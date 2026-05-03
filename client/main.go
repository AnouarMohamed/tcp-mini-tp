package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"

	"tcp-mini-tp/internal/protocol"
)

func connectAndServe(serverAddr string) error {
	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	log.Printf("connected to server %s", serverAddr)

	for {
		msg, err := protocol.ReadFrame(conn)
		if err != nil {
			return err
		}

		log.Printf("received command: %s", msg)

		if strings.TrimSpace(msg) == "exit" {
			log.Print("server requested exit")
			return nil
		}

		resp := execute(msg)
		if err := protocol.WriteFrame(conn, resp); err != nil {
			return err
		}
	}
}

func execute(raw string) string {
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return "empty command"
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

	commandLine := strings.Join(fields[1:], " ")
	cmd := exec.Command("bash", "-c", commandLine)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("command error: %v\n%s", err, string(output))
	}

	if len(output) == 0 {
		return "(no output)"
	}

	return string(output)
}

func main() {
	serverAddr := flag.String("server", "localhost:9898", "TCP server address")
	flag.Parse()

	if err := connectAndServe(*serverAddr); err != nil {
		log.Fatal(err)
	}
}
