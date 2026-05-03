package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"tcp-mini-tp/internal/protocol"
)

func startServer(listenAddr string) error {
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
		go handleSession(conn)
	}
}

func handleSession(conn net.Conn) {
	defer conn.Close()
	log.Printf("new connection from %s", conn.RemoteAddr())

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

func main() {
	listenAddr := flag.String("listen", ":9898", "TCP address to listen on")
	flag.Parse()

	if err := startServer(*listenAddr); err != nil {
		log.Fatal(err)
	}
}
