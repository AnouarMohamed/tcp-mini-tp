package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"tcp-mini-tp/internal/protocol"
)

func startServer(listenAddr, token string) error {
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}
	defer listener.Close()

	log.Printf("server listening on %s", listenAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go handleSession(conn, token)
	}
}

func handleSession(conn net.Conn, token string) {
	defer conn.Close()
	log.Printf("new connection from %s", conn.RemoteAddr())

	if err := authenticateClient(conn, token); err != nil {
		log.Printf("authentication failed for %s: %v", conn.RemoteAddr(), err)
		_ = protocol.WriteFrame(conn, "auth_fail")
		return
	}

	if err := protocol.WriteFrame(conn, "auth_ok"); err != nil {
		log.Printf("failed to send auth confirmation to %s: %v", conn.RemoteAddr(), err)
		return
	}

	log.Printf("authenticated client %s", conn.RemoteAddr())

	scanner := bufio.NewScanner(os.Stdin)
	fmt.Printf("server@%s> ", conn.RemoteAddr())
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			fmt.Printf("server@%s> ", conn.RemoteAddr())
			continue
		}

		if err := protocol.WriteFrame(conn, line); err != nil {
			log.Printf("send error: %v", err)
			return
		}

		if line == "exit" {
			log.Printf("closing session with %s", conn.RemoteAddr())
			return
		}

		reply, err := protocol.ReadFrame(conn)
		if err != nil {
			log.Printf("receive error: %v", err)
			return
		}

		fmt.Printf("client output:\n%s\n", reply)
		fmt.Printf("server@%s> ", conn.RemoteAddr())
	}

	if err := scanner.Err(); err != nil {
		log.Printf("stdin error: %v", err)
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

	if parts[1] != expectedToken {
		return errors.New("invalid token")
	}

	return nil
}

func main() {
	listenAddr := flag.String("listen", ":9898", "TCP address to listen on")
	token := flag.String("token", "tp-secret", "shared authentication token")
	flag.Parse()

	if err := startServer(*listenAddr, *token); err != nil {
		log.Fatal(err)
	}
}
