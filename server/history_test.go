package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAppendAndTailCommandHistory(t *testing.T) {
	oldPath := commandHistoryPath
	commandHistoryPath = filepath.Join(t.TempDir(), "commands.log")
	t.Cleanup(func() {
		commandHistoryPath = oldPath
	})

	entries := []commandHistoryEntry{
		{Timestamp: time.Now().UTC(), Component: "server", RemoteAddr: "127.0.0.1:1", Event: "repl_command", Mode: "normal", Command: "pwd"},
		{Timestamp: time.Now().UTC(), Component: "server", RemoteAddr: "127.0.0.1:1", Event: "repl_command", Mode: "shell", Command: "echo hi"},
	}
	for _, entry := range entries {
		if err := appendCommandHistory(entry); err != nil {
			t.Fatalf("appendCommandHistory failed: %v", err)
		}
	}

	lines, err := tailCommandHistory(20)
	if err != nil {
		t.Fatalf("tailCommandHistory failed: %v", err)
	}
	if len(lines) != len(entries) {
		t.Fatalf("tailCommandHistory returned %d lines, want %d", len(lines), len(entries))
	}

	for i, line := range lines {
		var decoded commandHistoryEntry
		if err := json.Unmarshal([]byte(line), &decoded); err != nil {
			t.Fatalf("invalid json line %q: %v", line, err)
		}
		if decoded.Command != entries[i].Command {
			t.Fatalf("history command %q, want %q", decoded.Command, entries[i].Command)
		}
	}
}

func TestTailCommandHistoryMissingFile(t *testing.T) {
	oldPath := commandHistoryPath
	commandHistoryPath = filepath.Join(t.TempDir(), "missing.log")
	t.Cleanup(func() {
		commandHistoryPath = oldPath
	})

	lines, err := tailCommandHistory(20)
	if err != nil {
		t.Fatalf("tailCommandHistory returned error: %v", err)
	}
	if len(lines) != 0 {
		t.Fatalf("expected no history lines, got %d", len(lines))
	}
}

func TestModePrompt(t *testing.T) {
	if got := modePrompt(normalMode); got != "server" {
		t.Fatalf("modePrompt(normalMode) = %q", got)
	}
	if got := modePrompt(shellMode); got != "shell" {
		t.Fatalf("modePrompt(shellMode) = %q", got)
	}
}

func TestShowCommandHistoryNoPanic(t *testing.T) {
	oldPath := commandHistoryPath
	commandHistoryPath = filepath.Join(t.TempDir(), "commands.log")
	t.Cleanup(func() {
		commandHistoryPath = oldPath
	})

	showCommandHistory("127.0.0.1:1")
	if _, err := os.Stat(commandHistoryPath); err != nil && !os.IsNotExist(err) {
		t.Fatalf("unexpected stat error: %v", err)
	}
}
