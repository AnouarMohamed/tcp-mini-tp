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

type sessionMode string

const (
	normalMode sessionMode = "normal"
	shellMode  sessionMode = "shell"
	chatMode   sessionMode = "chat"
	execMode   sessionMode = "exec"
)

var logger = slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("component", "server")

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

	stdinScanner := bufio.NewScanner(os.Stdin)
	mode := selectSessionMode(stdinScanner, listenAddr)

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
			handleSession(ctx, c, token, stdinScanner, mode)
		}(conn)
	}
}

func handleSession(parentCtx context.Context, conn net.Conn, token string, scanner *bufio.Scanner, mode sessionMode) {
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
	pongs := make(chan struct{}, 4)
	errCh := make(chan error, 1)
	if mode == shellMode {
		if err := serverWriteFrame(writeMu, conn, "shell"); err != nil {
			logger.Error("failed to start shell mode", "remote_addr", remoteAddr, "event", "shell_start_failed", "error", err)
			return
		}
	}

	go serverReadLoop(sessionCtx, cancel, conn, remoteAddr, pongs, errCh)
	go serverHeartbeatLoop(sessionCtx, cancel, conn, writeMu, pongs, errCh)
	go serverInputLoop(scanner, sessionCtx, cancel, conn, writeMu, remoteAddr, mode, errCh)

	if err := waitForSessionEnd(sessionCtx, errCh); err != nil {
		logger.Error("session ended", "remote_addr", remoteAddr, "event", "session_ended", "error", err)
	}
}

func modePrompt(mode sessionMode) string {
	if mode == shellMode {
		return "shell"
	}
	if mode == execMode {
		return "exec"
	}
	if mode == chatMode {
		return "chat"
	}
	return "server"
}

func selectSessionMode(scanner *bufio.Scanner, target string) sessionMode {
	fmt.Println("+------------------------------------------------+")
	fmt.Println("|      __  __ _       _   _ _                    |")
	fmt.Println("|     |  \\/  (_)_ __ | |_| (_)_ __   ___        |")
	fmt.Println("|     | |\\/| | | '_ \\| __| | '_ \\ / _ \\      |")
	fmt.Println("|     | |  | | | | | | |_| | | | | |  __/       |")
	fmt.Println("|     |_|  |_|_|_| |_|\\__|_|_| |_|\\___|    |")
	fmt.Println("+------------------------------------------------+")
	fmt.Printf("choose mode for %s\n", target)
	fmt.Println("  1) chat mode   - type free-form messages")
	fmt.Println("  2) exec mode   - auto-run typed commands")
	fmt.Println("  3) shell mode  - open a remote shell session")
	fmt.Print("select [1/3]: ")

	for scanner.Scan() {
		choice := strings.ToLower(strings.TrimSpace(scanner.Text()))
		switch choice {
		case "1", "chat", "c":
			fmt.Println("chat mode selected")
			return chatMode
		case "2", "exec", "command", "e":
			fmt.Println("exec mode selected")
			return execMode
		case "3", "shell", "s":
			fmt.Println("shell mode selected")
			return shellMode
		default:
			fmt.Print("select [1/3]: ")
		}
	}

	if err := scanner.Err(); err != nil {
		logger.Error("mode selection failed", "remote_addr", target, "event", "mode_selection_failed", "error", err)
	}
	return chatMode
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

func serverInputLoop(scanner *bufio.Scanner, ctx context.Context, cancel context.CancelFunc, conn net.Conn, writeMu *sync.Mutex, remoteAddr string, mode sessionMode, errCh chan<- error) {
	fmt.Printf("%s@%s> ", modePrompt(mode), remoteAddr)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return
		default:
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			fmt.Printf("%s@%s> ", modePrompt(mode), remoteAddr)
			continue
		}

		if line == "history" {
			showCommandHistory(remoteAddr)
			fmt.Printf("%s@%s> ", modePrompt(mode), remoteAddr)
			continue
		}

		sendLine := line
		if mode == execMode &&
			!strings.HasPrefix(line, "command ") &&
			!strings.HasPrefix(line, "info ") &&
			line != "exit" &&
			line != "history" {
			sendLine = "command " + line
		}

		if line == "exit" {
			logger.Info("closing session", "remote_addr", remoteAddr, "event", "session_closed")
			cancel()
			return
		}

		if err := serverWriteFrame(writeMu, conn, sendLine); err != nil {
			select {
			case errCh <- err:
			default:
			}
			cancel()
			return
		}

		fmt.Printf("%s@%s> ", modePrompt(mode), remoteAddr)
	}

	if err := scanner.Err(); err != nil {
		select {
		case errCh <- err:
		default:
		}
		cancel()
	}
}

func serverReadLoop(ctx context.Context, cancel context.CancelFunc, conn net.Conn, remoteAddr string, pongs chan<- struct{}, errCh chan<- error) {
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
			fmt.Printf("\nclient@%s: %s\nserver@%s> ", remoteAddr, msg, remoteAddr)
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

func waitForSessionEnd(ctx context.Context, errCh <-chan error) error {
	select {
	case err := <-errCh:
		if err == nil || errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	case <-ctx.Done():
		select {
		case err := <-errCh:
			if err == nil || errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		default:
		}
		return ctx.Err()
	}
}

func serverWriteFrame(writeMu *sync.Mutex, conn net.Conn, payload string) error {
	writeMu.Lock()
	defer writeMu.Unlock()
	return protocol.WriteFrame(conn, payload)
}
