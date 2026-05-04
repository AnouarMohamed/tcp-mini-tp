package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"tcp-mini-tp/internal/protocol"
)

func TestParseAllowlist(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []string
	}{
		{name: "default allowlist", raw: "", want: []string{"pwd", "ls", "whoami", "uname", "date", "echo", "cat", "id", "cd"}},
		{name: "custom allowlist trims values", raw: " pwd , false , , echo ", want: []string{"pwd", "false", "echo", "cd"}},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			allowed := parseAllowlist(test.raw)
			for _, command := range test.want {
				if _, ok := allowed[command]; !ok {
					t.Fatalf("expected %q to be allowed", command)
				}
			}
		})
	}
}

func TestExecuteBranches(t *testing.T) {
	currentDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd failed: %v", err)
	}

	burstScript := createExecutable(t, "burst-output", "#!/bin/sh\nhead -c 70000 /dev/zero | tr '\\0' a\n")
	falsePath, err := exec.LookPath("false")
	if err != nil {
		t.Fatalf("LookPath false failed: %v", err)
	}
	truePath, err := exec.LookPath("true")
	if err != nil {
		t.Fatalf("LookPath true failed: %v", err)
	}
	pwdPath, err := exec.LookPath("pwd")
	if err != nil {
		t.Fatalf("LookPath pwd failed: %v", err)
	}

	tests := []struct {
		name       string
		run        func(t *testing.T) string
		want       string
		wantPrefix string
		wantLen    int
	}{
		{name: "empty command", run: func(t *testing.T) string { return execute("", map[string]struct{}{}) }, want: "empty command"},
		{name: "unknown info instruction", run: func(t *testing.T) string { return execute("info version", map[string]struct{}{}) }, want: "unknown info instruction"},
		{name: "cwd info command", run: func(t *testing.T) string { return execute("info cwd", map[string]struct{}{}) }, want: currentDir},
		{name: "unknown prefix", run: func(t *testing.T) string { return execute("noop", map[string]struct{}{}) }, want: "unknown instruction: expected prefix 'command'"},
		{name: "empty command after prefix", run: func(t *testing.T) string { return execute("command", map[string]struct{}{}) }, want: "empty command after 'command'"},
		{name: "cd missing path", run: func(t *testing.T) string { return execute("command cd", map[string]struct{}{"cd": {}}) }, want: "missing directory path"},
		{name: "cd success", run: func(t *testing.T) string {
			cdDir := t.TempDir()
			oldDir, err := os.Getwd()
			if err != nil {
				t.Fatalf("Getwd failed: %v", err)
			}
			if err := os.Chdir(cdDir); err != nil {
				t.Fatalf("Chdir setup failed: %v", err)
			}
			t.Cleanup(func() {
				if err := os.Chdir(oldDir); err != nil {
					t.Fatalf("restore cwd failed: %v", err)
				}
			})
			return execute("command cd "+cdDir, map[string]struct{}{"cd": {}})
		}, wantPrefix: "changed directory to "},
		{name: "command not found", run: func(t *testing.T) string {
			return execute("command definitely-not-a-real-command-12345", map[string]struct{}{"definitely-not-a-real-command-12345": {}})
		}, want: "command not found: definitely-not-a-real-command-12345"},
		{name: "blocked command", run: func(t *testing.T) string { return execute("command "+pwdPath, map[string]struct{}{"whoami": {}}) }, want: "blocked command: pwd (not in whitelist)"},
		{name: "command error", run: func(t *testing.T) string { return execute("command "+falsePath, map[string]struct{}{"false": {}}) }, wantPrefix: "command error:"},
		{name: "command no output", run: func(t *testing.T) string { return execute("command "+truePath, map[string]struct{}{"true": {}}) }, want: "(no output)"},
		{name: "command output capped", run: func(t *testing.T) string {
			return execute("command "+burstScript, map[string]struct{}{"burst-output": {}})
		}, wantLen: maxOutputSize},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			got := test.run(t)
			switch {
			case test.wantLen > 0:
				if len(got) != test.wantLen {
					t.Fatalf("execute returned length %d, want %d", len(got), test.wantLen)
				}
				if strings.Trim(got, "a") != "" {
					t.Fatalf("expected capped output to contain only a's, got prefix %q", got[:16])
				}
			case test.wantPrefix != "":
				if !strings.HasPrefix(got, test.wantPrefix) {
					t.Fatalf("execute returned %q, want prefix %q", got, test.wantPrefix)
				}
			default:
				if got != test.want {
					t.Fatalf("execute returned %q, want %q", got, test.want)
				}
			}
		})
	}
}

func TestBuildTLSConfig(t *testing.T) {
	t.Run("without cert uses insecure skip verify", func(t *testing.T) {
		config, err := buildTLSConfig("localhost:9898", nil)
		if err != nil {
			t.Fatalf("buildTLSConfig returned error: %v", err)
		}
		if !config.InsecureSkipVerify {
			t.Fatal("expected InsecureSkipVerify to be true")
		}
	})

	t.Run("with cert uses root ca", func(t *testing.T) {
		certPEM := createSelfSignedCertPEM(t)
		config, err := buildTLSConfig("localhost:9898", certPEM)
		if err != nil {
			t.Fatalf("buildTLSConfig returned error: %v", err)
		}
		if config.RootCAs == nil {
			t.Fatal("expected RootCAs to be populated")
		}
		if config.InsecureSkipVerify {
			t.Fatal("expected InsecureSkipVerify to be false")
		}
	})
}

func TestAuthenticate(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		server, client := net.Pipe()
		defer server.Close()
		defer client.Close()

		done := make(chan error, 1)
		go func() {
			msg, err := protocol.ReadFrame(server)
			if err != nil {
				done <- err
				return
			}
			if msg != "auth secret" {
				done <- errors.New("unexpected auth message")
				return
			}
			done <- protocol.WriteFrame(server, "auth_ok")
		}()

		if err := authenticate(client, "secret"); err != nil {
			t.Fatalf("authenticate returned error: %v", err)
		}
		if err := <-done; err != nil {
			t.Fatalf("server side error: %v", err)
		}
	})

	t.Run("server busy", func(t *testing.T) {
		server, client := net.Pipe()
		defer server.Close()
		defer client.Close()

		go func() {
			_, _ = protocol.ReadFrame(server)
			_ = protocol.WriteFrame(server, "server_busy")
		}()

		if err := authenticate(client, "secret"); !errors.Is(err, errServerBusy) {
			t.Fatalf("authenticate returned %v, want server busy", err)
		}
	})
}

func TestAuthenticateErrors(t *testing.T) {
	t.Run("empty token", func(t *testing.T) {
		if err := authenticate(nil, ""); err == nil || !strings.Contains(err.Error(), "token cannot be empty") {
			t.Fatalf("authenticate returned %v, want empty token error", err)
		}
	})

	t.Run("server closed before auth", func(t *testing.T) {
		server, client := net.Pipe()
		server.Close()
		defer client.Close()

		if err := authenticate(client, "secret"); err == nil {
			t.Fatal("expected authenticate to fail when the server closes the pipe")
		}
	})

	t.Run("invalid auth message", func(t *testing.T) {
		server, client := net.Pipe()
		defer server.Close()
		defer client.Close()

		go func() {
			_, _ = protocol.ReadFrame(server)
			_ = protocol.WriteFrame(server, "not-auth")
		}()

		if err := authenticate(client, "secret"); err == nil || !strings.Contains(err.Error(), "authentication rejected") {
			t.Fatalf("authenticate returned %v, want authentication rejected", err)
		}
	})
}

func TestWaitForSessionEnd(t *testing.T) {
	t.Run("returns session error", func(t *testing.T) {
		want := errors.New("boom")
		ch := make(chan error, 1)
		ch <- want
		if err := waitForSessionEnd(context.Background(), ch); !errors.Is(err, want) {
			t.Fatalf("waitForSessionEnd returned %v, want %v", err, want)
		}
	})

	t.Run("returns context error", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := waitForSessionEnd(ctx, nil); !errors.Is(err, context.Canceled) {
			t.Fatalf("waitForSessionEnd returned %v, want context canceled", err)
		}
	})
}

func TestClientReadLoopHandlesReadError(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sessionErr := make(chan error, 1)
	go clientReadLoop(ctx, cancel, client, &sync.Mutex{}, map[string]struct{}{}, sessionErr)

	server.Close()
	if err := <-sessionErr; err == nil {
		t.Fatal("expected read error from clientReadLoop")
	}
}

func TestMainUsesInjectedRunner(t *testing.T) {
	originalRunner := connectAndServeFn
	originalCommandLine := flag.CommandLine
	originalArgs := os.Args
	t.Cleanup(func() {
		connectAndServeFn = originalRunner
		flag.CommandLine = originalCommandLine
		os.Args = originalArgs
	})

	var gotServerAddr, gotToken string
	var gotMaxRetries int
	connectAndServeFn = func(serverAddr, token string, certPEM []byte, allowed map[string]struct{}, maxRetries int) error {
		gotServerAddr = serverAddr
		gotToken = token
		gotMaxRetries = maxRetries
		return nil
	}

	os.Args = []string{"client", "-server", "example:1234", "-token", "abc", "-max-retries", "7"}
	flag.CommandLine = flag.NewFlagSet("client", flag.ContinueOnError)

	main()

	if gotServerAddr != "example:1234" || gotToken != "abc" || gotMaxRetries != 7 {
		t.Fatalf("main passed %q, %q, %d", gotServerAddr, gotToken, gotMaxRetries)
	}
}

func TestConnectAndServeRetries(t *testing.T) {
	originalRunClientSession := runClientSessionFn
	originalSleep := sleepFn
	t.Cleanup(func() {
		runClientSessionFn = originalRunClientSession
		sleepFn = originalSleep
	})

	tests := []struct {
		name               string
		responses          []error
		maxRetries         int
		wantErrContains    string
		wantCalls          int
		wantSleepDurations []time.Duration
	}{
		{
			name:       "success without retry",
			responses:  []error{nil},
			maxRetries: 5,
			wantCalls:  1,
		},
		{
			name:            "authentication rejected stops immediately",
			responses:       []error{errAuthRejected},
			maxRetries:      5,
			wantErrContains: "authentication rejected",
			wantCalls:       1,
		},
		{
			name:               "retries until success",
			responses:          []error{errors.New("temporary 1"), errors.New("temporary 2"), nil},
			maxRetries:         5,
			wantCalls:          3,
			wantSleepDurations: []time.Duration{time.Second, 2 * time.Second},
		},
		{
			name:               "max retries reached",
			responses:          []error{errors.New("temporary 1"), errors.New("temporary 2"), errors.New("temporary 3")},
			maxRetries:         1,
			wantErrContains:    "max retries reached",
			wantCalls:          2,
			wantSleepDurations: []time.Duration{time.Second},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			sleeps := make([]time.Duration, 0, len(test.wantSleepDurations))
			runClientSessionFn = func(string, string, []byte, map[string]struct{}) error {
				if calls >= len(test.responses) {
					return errors.New("unexpected call")
				}
				err := test.responses[calls]
				calls++
				return err
			}
			sleepFn = func(delay time.Duration) {
				sleeps = append(sleeps, delay)
			}

			err := connectAndServe("localhost:9999", "secret", nil, map[string]struct{}{}, test.maxRetries)
			if test.wantErrContains == "" {
				if err != nil {
					t.Fatalf("connectAndServe returned unexpected error: %v", err)
				}
			} else {
				if err == nil || !strings.Contains(err.Error(), test.wantErrContains) {
					t.Fatalf("connectAndServe returned %v, want error containing %q", err, test.wantErrContains)
				}
			}

			if calls != test.wantCalls {
				t.Fatalf("runClientSession called %d times, want %d", calls, test.wantCalls)
			}
			if len(sleeps) != len(test.wantSleepDurations) {
				t.Fatalf("sleep called %d times, want %d", len(sleeps), len(test.wantSleepDurations))
			}
			for i, want := range test.wantSleepDurations {
				if sleeps[i] != want {
					t.Fatalf("sleep[%d] = %s, want %s", i, sleeps[i], want)
				}
			}
		})
	}
}

func TestRunClientSessionIntegration(t *testing.T) {
	serverCert, certPEM := createSelfSignedTLSCertificate(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{serverCert}})
	if err != nil {
		t.Fatalf("tls.Listen failed: %v", err)
	}
	defer listener.Close()

	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()

		msg, err := protocol.ReadFrame(conn)
		if err != nil {
			serverDone <- err
			return
		}
		if msg != "auth secret" {
			serverDone <- errors.New("unexpected auth payload")
			return
		}
		if err := protocol.WriteFrame(conn, "auth_ok"); err != nil {
			serverDone <- err
			return
		}

		if err := protocol.WriteFrame(conn, heartbeatPing); err != nil {
			serverDone <- err
			return
		}
		msg, err = protocol.ReadFrame(conn)
		if err != nil {
			serverDone <- err
			return
		}
		if msg != heartbeatPong {
			serverDone <- errors.New("expected pong response")
			return
		}

		if err := protocol.WriteFrame(conn, "command true"); err != nil {
			serverDone <- err
			return
		}
		msg, err = protocol.ReadFrame(conn)
		if err != nil {
			serverDone <- err
			return
		}
		if msg != "(no output)" {
			serverDone <- errors.New("expected no output response")
			return
		}

		if err := protocol.WriteFrame(conn, "exit"); err != nil {
			serverDone <- err
			return
		}
		serverDone <- nil
	}()

	allowed := map[string]struct{}{"true": {}}
	if err := runClientSession(listener.Addr().String(), "secret", certPEM, allowed); err != nil {
		t.Fatalf("runClientSession returned error: %v", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("server side error: %v", err)
	}
}

func createExecutable(t *testing.T, name, content string) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	return path
}

func createSelfSignedCertPEM(t *testing.T) []byte {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("CreateCertificate failed: %v", err)
	}

	var certPEM strings.Builder
	if err := pem.Encode(&certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		t.Fatalf("pem.Encode failed: %v", err)
	}
	return []byte(certPEM.String())
}

func createSelfSignedTLSCertificate(t *testing.T) (tls.Certificate, []byte) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("CreateCertificate failed: %v", err)
	}

	certPEM := new(strings.Builder)
	if err := pem.Encode(certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		t.Fatalf("pem.Encode failed: %v", err)
	}

	keyPEM := new(strings.Builder)
	if err := pem.Encode(keyPEM, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}); err != nil {
		t.Fatalf("pem.Encode key failed: %v", err)
	}

	cert, err := tls.X509KeyPair([]byte(certPEM.String()), []byte(keyPEM.String()))
	if err != nil {
		t.Fatalf("X509KeyPair failed: %v", err)
	}

	return cert, []byte(certPEM.String())
}
