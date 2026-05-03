package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"tcp-mini-tp/internal/protocol"
)

var defaultAllowedCommands = []string{"pwd", "ls", "whoami", "uname", "date", "echo", "cat", "id", "cd"}

func connectAndServe(serverAddr, token string, allowed map[string]struct{}) error {
	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	log.Printf("connected to server %s", serverAddr)
	if err := authenticate(conn, token); err != nil {
		return err
	}
	log.Print("authentication completed")

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

		resp := execute(msg, allowed)
		if err := protocol.WriteFrame(conn, resp); err != nil {
			return err
		}
	}
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

	if status != "auth_ok" {
		return fmt.Errorf("authentication rejected by server: %s", status)
	}

	return nil
}

func execute(raw string, allowed map[string]struct{}) string {
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return "empty command"
	}

	if fields[0] == "info" {
		if len(fields) == 2 && fields[1] == "cwd" {
			cwd, err := os.Getwd()
			if err != nil {
				return fmt.Sprintf("cwd error: %v", err)
			}
			return cwd
		}
		return "unknown info instruction"
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

	base := filepath.Base(fields[1])
	if _, ok := allowed[base]; !ok {
		return fmt.Sprintf("blocked command: %s (not in whitelist)", base)
	}

	cmd := exec.Command(fields[1], fields[2:]...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("command error: %v\n%s", err, string(output))
	}

	if len(output) == 0 {
		return "(no output)"
	}

	return string(output)
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
	allowlist := flag.String("allow", "pwd,ls,whoami,uname,date,echo,cat,id,cd", "comma-separated whitelist for allowed commands")
	flag.Parse()

	allowed := parseAllowlist(*allowlist)

	if err := connectAndServe(*serverAddr, *token, allowed); err != nil {
		log.Fatal(err)
	}
}
