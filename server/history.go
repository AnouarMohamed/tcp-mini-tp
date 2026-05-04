package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

var commandHistoryPath = "commands.log"

type commandHistoryEntry struct {
	Timestamp  time.Time `json:"timestamp"`
	Component  string    `json:"component"`
	RemoteAddr string    `json:"remote_addr"`
	Event      string    `json:"event"`
	Mode       string    `json:"mode"`
	Command    string    `json:"command"`
}

func appendCommandHistory(entry commandHistoryEntry) error {
	file, err := os.OpenFile(commandHistoryPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()

	payload, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	if _, err := file.Write(append(payload, '\n')); err != nil {
		return err
	}
	return nil
}

func tailCommandHistory(limit int) ([]string, error) {
	file, err := os.Open(commandHistoryPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer file.Close()

	lines := make([]string, 0, limit)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if len(lines) == limit {
			lines = append(lines[1:], line)
			continue
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan history: %w", err)
	}
	return lines, nil
}
