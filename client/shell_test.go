package main

import (
	"strings"
	"testing"
)

func TestShellSessionRunAndClose(t *testing.T) {
	session, err := newShellSession()
	if err != nil {
		t.Fatalf("newShellSession failed: %v", err)
	}
	defer func() {
		_ = session.Close()
	}()

	outputs, exitCode, err := session.Run("echo shell-ready")
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}
	joined := strings.Join(outputs, "\n")
	if !strings.Contains(joined, "shell-ready") {
		t.Fatalf("expected output to contain shell-ready, got %q", joined)
	}

	if err := session.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
}
