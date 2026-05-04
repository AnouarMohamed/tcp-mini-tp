package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

type shellSession struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	marker string
	mu     sync.Mutex
	closed bool
}

func newShellSession() (*shellSession, error) {
	cmd := exec.Command("bash")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	session := &shellSession{
		cmd:    cmd,
		stdin:  stdin,
		stdout: bufio.NewReader(stdoutPipe),
		marker: fmt.Sprintf("__TCP_TP_SHELL_DONE_%d__", time.Now().UnixNano()),
	}

	if _, err := io.WriteString(session.stdin, "exec 2>&1\n"); err != nil {
		_ = session.Close()
		return nil, err
	}

	return session, nil
}

func (s *shellSession) Run(command string) ([]string, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, 0, errors.New("shell session closed")
	}

	if _, err := io.WriteString(s.stdin, command+"\n"); err != nil {
		return nil, 0, err
	}
	if _, err := io.WriteString(s.stdin, fmt.Sprintf("printf '%s:%%s\\n' \"$?\"\n", s.marker)); err != nil {
		return nil, 0, err
	}

	outputs := make([]string, 0, 4)
	for {
		line, err := s.stdout.ReadString('\n')
		if err != nil {
			return outputs, 0, err
		}

		line = strings.TrimRight(line, "\r\n")
		if strings.HasPrefix(line, s.marker+":") {
			statusText := strings.TrimPrefix(line, s.marker+":")
			status, err := strconv.Atoi(statusText)
			if err != nil {
				status = 0
			}
			return outputs, status, nil
		}

		outputs = append(outputs, line)
	}
}

func (s *shellSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}
	s.closed = true

	if _, err := io.WriteString(s.stdin, "exit\n"); err != nil {
		return err
	}
	return s.cmd.Wait()
}

type shellManager struct {
	mu      sync.Mutex
	session *shellSession
}

func newShellManager() *shellManager {
	return &shellManager{}
}

func (m *shellManager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.session != nil {
		return errors.New("shell already active")
	}

	session, err := newShellSession()
	if err != nil {
		return err
	}
	m.session = session
	return nil
}

func (m *shellManager) Run(command string) ([]string, int, error) {
	m.mu.Lock()
	session := m.session
	m.mu.Unlock()

	if session == nil {
		return nil, 0, errors.New("shell not active")
	}
	return session.Run(command)
}

func (m *shellManager) Stop() error {
	m.mu.Lock()
	session := m.session
	m.session = nil
	m.mu.Unlock()

	if session == nil {
		return nil
	}
	return session.Close()
}

func (m *shellManager) Active() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.session != nil
}
