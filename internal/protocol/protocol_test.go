package protocol

import (
	"errors"
	"io"
	"net"
	"strings"
	"testing"
)

func TestWriteReadFrameRoundTrip(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	want := "hello over tcp"
	errCh := make(chan error, 1)

	go func() {
		errCh <- WriteFrame(client, want)
	}()

	got, err := ReadFrame(server)
	if err != nil {
		t.Fatalf("ReadFrame returned error: %v", err)
	}
	if got != want {
		t.Fatalf("ReadFrame returned %q, want %q", got, want)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("WriteFrame returned error: %v", err)
	}
}

func TestReadFrameEOF(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	// Close client to signal EOF to server
	client.Close()

	_, err := ReadFrame(server)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected io.EOF, got %v", err)
	}
}

func TestWriteFrameTooLarge(t *testing.T) {
	var sink strings.Builder
	tooLarge := strings.Repeat("a", maxFrameSize+1)

	err := WriteFrame(&sink, tooLarge)
	if err == nil {
		t.Fatal("expected error for oversized frame")
	}
}
