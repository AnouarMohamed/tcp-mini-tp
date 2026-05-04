package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"tcp-mini-tp/internal/protocol"
)

const (
	maxOutputSize = 64 * 1024
	heartbeatPing = "ping"
	heartbeatPong = "pong"
)

var (
	defaultAllowedCommands = []string{"pwd", "ls", "whoami", "uname", "date", "echo", "cat", "id", "cd"}
	errAuthRejected        = errors.New("authentication rejected")
	errServerBusy          = errors.New("server busy")
	connectAndServeFn      = connectAndServe
	runClientSessionFn     = runClientSession
	sleepFn                = time.Sleep
)

var logger = slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("component", "client")

func connectAndServe(serverAddr, token string, certPEM []byte, allowed map[string]struct{}, maxRetries int) error {
	delay := time.Second
	attempt := 0

	for {
		err := runClientSessionFn(serverAddr, token, certPEM, allowed)
		if err == nil {
			return nil
		}
		if errors.Is(err, errAuthRejected) {
			return err
		}
		if maxRetries >= 0 && attempt >= maxRetries {
			return fmt.Errorf("max retries reached after %d attempts: %w", attempt, err)
		}

		attempt++
		logger.Warn("session ended, reconnecting", "remote_addr", serverAddr, "event", "reconnect", "attempt", attempt, "delay", delay.String(), "error", err)
		sleepFn(delay)
		delay *= 2
		if delay > 30*time.Second {
			delay = 30 * time.Second
		}
	}
}

func runClientSession(serverAddr, token string, certPEM []byte, allowed map[string]struct{}) error {
	tlsConfig, err := buildTLSConfig(serverAddr, certPEM)
	if err != nil {
		return err
	}

	conn, err := tls.Dial("tcp", serverAddr, tlsConfig)
	if err != nil {
		return err
	}
	defer conn.Close()

	logger.Info("connected to server", "remote_addr", serverAddr, "event", "connected")
	if err := authenticate(conn, token); err != nil {
		return err
	}
	logger.Info("authentication completed", "remote_addr", serverAddr, "event", "authenticated")

	writeMu := &sync.Mutex{}
	sessionErr := make(chan error, 1)
	shellMgr := newShellManager()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go clientReadLoop(ctx, cancel, conn, writeMu, allowed, shellMgr, sessionErr)
	go clientStdinLoop(ctx, cancel, conn, writeMu, sessionErr)

	if err := waitForSessionEnd(ctx, sessionErr); err != nil {
		return err
	}
	return nil
}

func buildTLSConfig(serverAddr string, certPEM []byte) (*tls.Config, error) {
	host := serverAddr
	if parsedHost, _, err := net.SplitHostPort(serverAddr); err == nil {
		host = parsedHost
	}

	config := &tls.Config{MinVersion: tls.VersionTLS12}
	if len(certPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(certPEM) {
			return nil, errors.New("failed to parse certificate")
		}
		config.RootCAs = pool
		config.ServerName = host
		return config, nil
	}

	config.InsecureSkipVerify = true
	return config, nil
}

func authenticate(conn net.Conn, token string) error {
	if token == "" {
		return errors.New("token cannot be empty")
	}

	if err := protocol.WriteFrame(conn, "auth "+token); err != nil {
		return err
	}

	status, err := protocol.ReadFrame(conn)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("server closed during authentication")
		}
		return err
	}

	switch status {
	case "auth_ok":
		return nil
	case "server_busy":
		return errServerBusy
	default:
		return errAuthRejected
	}
}

func clientStdinLoop(ctx context.Context, cancel context.CancelFunc, conn net.Conn, writeMu *sync.Mutex, sessionErr chan<- error) {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print("client> ")
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return
		default:
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			fmt.Print("client> ")
			continue
		}

		if err := clientWriteFrame(writeMu, conn, line); err != nil {
			select {
			case sessionErr <- err:
			default:
			}
			cancel()
			return
		}

		if line == "exit" {
			cancel()
			select {
			case sessionErr <- nil:
			default:
			}
			return
		}

		fmt.Print("client> ")
	}

	if err := scanner.Err(); err != nil {
		select {
		case sessionErr <- err:
		default:
		}
		cancel()
	}
}

func clientReadLoop(ctx context.Context, cancel context.CancelFunc, conn net.Conn, writeMu *sync.Mutex, allowed map[string]struct{}, shellMgr *shellManager, sessionErr chan<- error) {
	for {
		msg, err := protocol.ReadFrame(conn)
		if err != nil {
			select {
			case sessionErr <- err:
			default:
			}
			cancel()
			return
		}

		trimmed := strings.TrimSpace(msg)
		logger.Info("received command", "remote_addr", conn.RemoteAddr().String(), "event", "command_received", "command", msg)

		switch trimmed {
		case heartbeatPing:
			if err := clientWriteFrame(writeMu, conn, heartbeatPong); err != nil {
				select {
				case sessionErr <- err:
				default:
				}
				cancel()
				return
			}
		case "shell":
			if err := shellMgr.Start(); err != nil {
				if writeErr := clientWriteFrame(writeMu, conn, "shell_error:"+err.Error()); writeErr != nil {
					select {
					case sessionErr <- writeErr:
					default:
					}
					cancel()
					return
				}
				continue
			}
			if err := clientWriteFrame(writeMu, conn, "shell_ready"); err != nil {
				select {
				case sessionErr <- err:
				default:
				}
				cancel()
				return
			}
		case "shell exit":
			if err := shellMgr.Stop(); err != nil {
				if writeErr := clientWriteFrame(writeMu, conn, "shell_error:"+err.Error()); writeErr != nil {
					select {
					case sessionErr <- writeErr:
					default:
					}
					cancel()
					return
				}
				continue
			}
			if err := clientWriteFrame(writeMu, conn, "shell_closed"); err != nil {
				select {
				case sessionErr <- err:
				default:
				}
				cancel()
				return
			}
		case "exit":
			logger.Info("server requested exit", "remote_addr", conn.RemoteAddr().String(), "event", "exit")
			cancel()
			select {
			case sessionErr <- nil:
			default:
			}
			return
		default:
			if shellMgr.Active() {
				go func(command string) {
					outputs, exitCode, runErr := shellMgr.Run(command)
					if runErr != nil {
						if writeErr := clientWriteFrame(writeMu, conn, "shell_error:"+runErr.Error()); writeErr != nil {
							select {
							case sessionErr <- writeErr:
							default:
							}
							cancel()
						}
						return
					}

					for _, outputLine := range outputs {
						if writeErr := clientWriteFrame(writeMu, conn, "shell_output:"+outputLine); writeErr != nil {
							select {
							case sessionErr <- writeErr:
							default:
							}
							cancel()
							return
						}
					}

					if writeErr := clientWriteFrame(writeMu, conn, fmt.Sprintf("shell_done:%d", exitCode)); writeErr != nil {
						select {
						case sessionErr <- writeErr:
						default:
						}
						cancel()
					}
				}(trimmed)
				continue
			}

			if strings.HasPrefix(trimmed, "command ") || strings.HasPrefix(trimmed, "info ") {
				go func(command string) {
					response := execute(command, allowed)
					if err := clientWriteFrame(writeMu, conn, response); err != nil {
						select {
						case sessionErr <- err:
						default:
						}
						cancel()
					}
				}(msg)
				continue
			}

			if trimmed == "exit" {
				logger.Info("server requested exit", "remote_addr", conn.RemoteAddr().String(), "event", "exit")
				cancel()
				select {
				case sessionErr <- nil:
				default:
				}
				return
			}

			fmt.Printf("\nserver: %s\nclient> ", msg)
		}
	}
}

func waitForSessionEnd(ctx context.Context, sessionErr <-chan error) error {
	select {
	case err := <-sessionErr:
		if err == nil || errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	case <-ctx.Done():
		select {
		case err := <-sessionErr:
			if err == nil || errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		default:
		}
		return ctx.Err()
	}
}

func clientWriteFrame(writeMu *sync.Mutex, conn net.Conn, payload string) error {
	writeMu.Lock()
	defer writeMu.Unlock()
	return protocol.WriteFrame(conn, payload)
}

func execute(raw string, allowed map[string]struct{}) string {
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return "empty command"
	}

	if fields[0] == "info" {
		return handleInfo(fields)
	}

	if fields[0] != "command" {
		return "unknown instruction: expected prefix 'command'"
	}

	if len(fields) < 2 {
		return "empty command after 'command'"
	}

	if fields[1] == "cd" {
		if len(fields) < 3 {
			return "missing directory path"
		}
		path := strings.Join(fields[2:], " ")
		if err := os.Chdir(path); err != nil {
			return fmt.Sprintf("cd error: %v", err)
		}
		return fmt.Sprintf("changed directory to %s", path)
	}

	resolvedPath, err := exec.LookPath(fields[1])
	if err != nil {
		return fmt.Sprintf("command not found: %s", fields[1])
	}

	base := filepath.Base(resolvedPath)
	if _, ok := allowed[base]; !ok {
		return fmt.Sprintf("blocked command: %s (not in whitelist)", base)
	}

	cmd := exec.Command(resolvedPath, fields[2:]...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("command error: %v\n%s", err, string(output))
	}

	limitedOutput := io.LimitedReader{R: bytes.NewReader(output), N: maxOutputSize}
	cappedOutput, _ := io.ReadAll(&limitedOutput)

	if len(cappedOutput) == 0 {
		return "(no output)"
	}

	return string(cappedOutput)
}

func parseAllowlist(raw string) map[string]struct{} {
	allowed := make(map[string]struct{})

	if strings.TrimSpace(raw) == "" {
		for _, cmd := range defaultAllowedCommands {
			allowed[cmd] = struct{}{}
		}
		return allowed
	}

	for _, entry := range strings.Split(raw, ",") {
		cmd := strings.TrimSpace(entry)
		if cmd == "" {
			continue
		}
		allowed[cmd] = struct{}{}
	}

	allowed["cd"] = struct{}{}
	return allowed
}

func main() {
	serverAddr := flag.String("server", "localhost:9898", "TCP server address")
	token := flag.String("token", "tp-secret", "shared authentication token")
	certFile := flag.String("cert", "", "path to TLS certificate file (optional, uses InsecureSkipVerify if not provided)")
	allowlist := flag.String("allow", "pwd,ls,whoami,uname,date,echo,cat,id,cd", "comma-separated whitelist for allowed commands")
	maxRetries := flag.Int("max-retries", 5, "maximum reconnect attempts after a dropped session")
	flag.Parse()

	allowed := parseAllowlist(*allowlist)

	var certPEM []byte
	if *certFile != "" {
		var err error
		certPEM, err = os.ReadFile(*certFile)
		if err != nil {
			logger.Error("failed to read certificate file", "remote_addr", *serverAddr, "event", "cert_read_error", "error", err)
			os.Exit(1)
		}
	}

	if err := connectAndServeFn(*serverAddr, *token, certPEM, allowed, *maxRetries); err != nil {
		logger.Error("fatal error", "remote_addr", *serverAddr, "event", "fatal", "error", err)
		os.Exit(1)
	}
}
