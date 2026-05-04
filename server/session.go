package main

import (
	"bufio"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"tcp-mini-tp/internal/protocol"
)

const (
	serverHeartbeatInterval = 30 * time.Second
	serverHeartbeatTimeout  = 5 * time.Second
)

var logger = slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("component", "server")

type sessionMode string

const (
	normalMode sessionMode = "normal"
	shellMode  sessionMode = "shell"
)

type sessionManager struct {
	mu     sync.Mutex
	active net.Conn
}

func (m *sessionManager) tryAcquire(conn net.Conn) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.active != nil {
		return false
	}

	m.active = conn
	return true
}

func (m *sessionManager) release(conn net.Conn) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.active == conn {
		m.active = nil
	}
}

func (m *sessionManager) closeActive() {
	m.mu.Lock()
	active := m.active
	m.mu.Unlock()

	if active != nil {
		_ = active.Close()
	}
}

func startServer(ctx context.Context, listenAddr, token, certFile, keyFile string) error {
	if err := GenerateSelfSignedCert(certFile, keyFile); err != nil {
		return fmt.Errorf("cert generation failed: %w", err)
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("failed to load TLS cert: %w", err)
	}

	listener, err := tls.Listen("tcp", listenAddr, &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		return err
	}
	defer listener.Close()

	manager := &sessionManager{}
	go func() {
		<-ctx.Done()
		_ = listener.Close()
		manager.closeActive()
	}()

	logger.Info("server listening", "remote_addr", listenAddr, "event", "listener_started")

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			logger.Error("accept error", "remote_addr", "", "event", "accept_error", "error", err)
			continue
		}

		if !manager.tryAcquire(conn) {
			logger.Warn("session rejected", "remote_addr", conn.RemoteAddr().String(), "event", "session_busy")
			_ = protocol.WriteFrame(conn, "server_busy")
			_ = conn.Close()
			continue
		}

		go func(c net.Conn) {
			defer manager.release(c)
			handleSession(ctx, c, token)
		}(conn)
	}
}

func handleSession(parentCtx context.Context, conn net.Conn, token string) {
	defer conn.Close()

	sessionCtx, cancel := context.WithCancel(parentCtx)
	defer cancel()

	remoteAddr := conn.RemoteAddr().String()

	if err := authenticateClient(conn, token); err != nil {
		logger.Warn("authentication failed", "remote_addr", remoteAddr, "event", "authentication_failed", "error", err)
		_ = protocol.WriteFrame(conn, "auth_fail")
		return
	}

	if err := protocol.WriteFrame(conn, "auth_ok"); err != nil {
		logger.Error("failed to send auth confirmation", "remote_addr", remoteAddr, "event", "auth_confirmation_failed", "error", err)
		return
	}

	logger.Info("authenticated client", "remote_addr", remoteAddr, "event", "authenticated")

	writeMu := &sync.Mutex{}
	responses := make(chan string, 8)
	pongs := make(chan struct{}, 4)
	errCh := make(chan error, 1)

	go serverReadLoop(sessionCtx, cancel, conn, responses, pongs, errCh)
	go serverHeartbeatLoop(sessionCtx, cancel, conn, writeMu, pongs, errCh)

	mode := normalMode
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Printf("%s@%s> ", modePrompt(mode), remoteAddr)
	for scanner.Scan() {
		select {
		case <-sessionCtx.Done():
			return
		default:
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			fmt.Printf("%s@%s> ", modePrompt(mode), remoteAddr)
			continue
		}

		if err := appendCommandHistory(commandHistoryEntry{
			Timestamp:  time.Now().UTC(),
			Component:  "server",
			RemoteAddr: remoteAddr,
			Event:      "repl_command",
			Mode:       string(mode),
			Command:    line,
		}); err != nil {
			logger.Warn("history append failed", "remote_addr", remoteAddr, "event", "history_append_failed", "error", err)
		}

		if line == "history" {
			showCommandHistory(remoteAddr)
			fmt.Printf("%s@%s> ", modePrompt(mode), remoteAddr)
			continue
		}

		switch mode {
		case normalMode:
			if line == "shell" {
				if err := serverWriteFrame(writeMu, conn, line); err != nil {
					logger.Error("send error", "remote_addr", remoteAddr, "event", "send_error", "error", err)
					return
				}

				reply, err := waitForServerResponse(sessionCtx, responses, errCh)
				if err != nil {
					logger.Error("receive error", "remote_addr", remoteAddr, "event", "receive_error", "error", err)
					return
				}
				if reply == "shell_ready" {
					mode = shellMode
					fmt.Printf("shell@%s> ", remoteAddr)
					continue
				}
				fmt.Printf("client output:\n%s\n", reply)
				fmt.Printf("%s@%s> ", modePrompt(mode), remoteAddr)
				continue
			}

			if err := serverWriteFrame(writeMu, conn, line); err != nil {
				logger.Error("send error", "remote_addr", remoteAddr, "event", "send_error", "error", err)
				return
			}

			if line == "exit" {
				logger.Info("closing session", "remote_addr", remoteAddr, "event", "session_closed")
				return
			}

			reply, err := waitForServerResponse(sessionCtx, responses, errCh)
			if err != nil {
				logger.Error("receive error", "remote_addr", remoteAddr, "event", "receive_error", "error", err)
				return
			}

			fmt.Printf("client output:\n%s\n", reply)
			fmt.Printf("%s@%s> ", modePrompt(mode), remoteAddr)

		case shellMode:
			if err := serverWriteFrame(writeMu, conn, line); err != nil {
				logger.Error("send error", "remote_addr", remoteAddr, "event", "send_error", "error", err)
				return
			}

			for {
				msg, err := waitForServerResponse(sessionCtx, responses, errCh)
				if err != nil {
					logger.Error("receive error", "remote_addr", remoteAddr, "event", "receive_error", "error", err)
					return
				}

				switch {
				case strings.HasPrefix(msg, "shell_output:"):
					fmt.Println(strings.TrimPrefix(msg, "shell_output:"))
				case strings.HasPrefix(msg, "shell_done:"):
					fmt.Printf("shell exit code: %s\n", strings.TrimPrefix(msg, "shell_done:"))
					fmt.Printf("shell@%s> ", remoteAddr)
					goto nextInput
				case msg == "shell_closed":
					mode = normalMode
					fmt.Printf("%s@%s> ", modePrompt(mode), remoteAddr)
					goto nextInput
				default:
					fmt.Printf("client output:\n%s\n", msg)
				}
			}
		}

	nextInput:
	}

	if err := scanner.Err(); err != nil {
		logger.Error("stdin error", "remote_addr", remoteAddr, "event", "stdin_error", "error", err)
	}
}

func modePrompt(mode sessionMode) string {
	if mode == shellMode {
		return "shell"
	}
	return "server"
}

func showCommandHistory(remoteAddr string) {
	history, err := tailCommandHistory(20)
	if err != nil {
		logger.Error("history read error", "remote_addr", remoteAddr, "event", "history_read_error", "error", err)
		return
	}

	if len(history) == 0 {
		fmt.Println("no command history")
		return
	}

	for _, line := range history {
		fmt.Println(line)
	}
}

func authenticateClient(conn net.Conn, expectedToken string) error {
	if expectedToken == "" {
		return errors.New("empty expected token")
	}

	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	authMsg, err := protocol.ReadFrame(conn)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("client closed before auth")
		}
		return err
	}

	parts := strings.Fields(authMsg)
	if len(parts) != 2 || parts[0] != "auth" {
		return fmt.Errorf("invalid auth message")
	}

	if subtle.ConstantTimeCompare([]byte(parts[1]), []byte(expectedToken)) != 1 {
		return errors.New("invalid token")
	}

	return nil
}

func serverReadLoop(ctx context.Context, cancel context.CancelFunc, conn net.Conn, responses chan<- string, pongs chan<- struct{}, errCh chan<- error) {
	for {
		msg, err := protocol.ReadFrame(conn)
		if err != nil {
			select {
			case errCh <- err:
			default:
			}
			cancel()
			return
		}

		switch msg {
		case "pong":
			select {
			case pongs <- struct{}{}:
			default:
			}
		default:
			select {
			case responses <- msg:
			case <-ctx.Done():
				return
			}
		}
	}
}

func serverHeartbeatLoop(ctx context.Context, cancel context.CancelFunc, conn net.Conn, writeMu *sync.Mutex, pongs <-chan struct{}, errCh chan<- error) {
	ticker := time.NewTicker(serverHeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := serverWriteFrame(writeMu, conn, "ping"); err != nil {
				select {
				case errCh <- err:
				default:
				}
				cancel()
				return
			}

			timeout := time.NewTimer(serverHeartbeatTimeout)
			select {
			case <-pongs:
				if !timeout.Stop() {
					<-timeout.C
				}
			case <-timeout.C:
				select {
				case errCh <- fmt.Errorf("heartbeat timeout waiting for pong"):
				default:
				}
				cancel()
				_ = conn.Close()
				return
			case <-ctx.Done():
				if !timeout.Stop() {
					<-timeout.C
				}
				return
			}
		}
	}
}

func serverWriteFrame(writeMu *sync.Mutex, conn net.Conn, payload string) error {
	writeMu.Lock()
	defer writeMu.Unlock()
	return protocol.WriteFrame(conn, payload)
}

func waitForServerResponse(ctx context.Context, responses <-chan string, errCh <-chan error) (string, error) {
	select {
	case resp := <-responses:
		return resp, nil
	case err := <-errCh:
		if err == nil {
			return "", errors.New("session closed")
		}
		return "", err
	case <-ctx.Done():
		return "", ctx.Err()
	}
}
