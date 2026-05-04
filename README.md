# Mini TP: TCP Command Channel in Go

This repository is a mini practical work (TP) to understand:
- TCP client/server communication
- framing messages over a stream (length-prefix protocol)
- basic remote command execution flow
- clean code organization in Go

TP2 hardening has been added:
- shared-token authentication at connection start
- command whitelist on the client side

## Security Improvements (TP2 & TP3)

**TP2:**
- Shared-token authentication
- Command whitelist enforcement

**TP3 (Latest):**
1. **TLS Encryption** - All traffic encrypted, self-signed certificate auto-generated on first run
   - Server: `cert.pem` and `key.pem` generated automatically
   - Client: Accepts optional `-cert` flag for certificate verification
   
2. **Timing Attack Prevention** - Token comparison using `crypto/subtle.ConstantTimeCompare`
   - Prevents timing-based token disclosure
   
3. **Path Traversal Prevention** - `exec.LookPath` validates command before whitelist check
   - Blocks commands like `../../bin/dangerous`
   - Only resolved binary path is checked against whitelist
   
4. **Output Size Capping** - Command output limited to 64KB
   - Prevents memory exhaustion from large command outputs
   - Uses `io.LimitedReader`

## Architectural Improvements

- Single active session enforced by a server-side mutex
- Graceful shutdown on `SIGINT` and `SIGTERM`
- Client reconnects with exponential backoff up to 30s
- Heartbeat ping/pong every 30s with 5s timeout

## Project Structure

- `server/main.go`: server executable (listens, sends commands, prints client output)
- `server/tls.go`: TLS certificate generation utility
- `client/main.go`: client executable (receives commands, executes, sends output)
- `client/main_test.go`: client-side tests
- `internal/protocol/protocol.go`: shared framing logic
- `internal/protocol/protocol_test.go`: protocol tests

## Protocol (Application Layer)

Each message is sent as:
1. 4 bytes unsigned integer (big-endian) representing payload size
2. payload bytes (UTF-8 string)

This avoids partial-read issues and allows clean request/response exchanges.
All traffic is encrypted with TLS.

## Prerequisites

- Go 1.22+
- Linux or macOS (client uses `bash -c` for command execution)

## Build

```bash
go build -o bin/server ./server
go build -o bin/client ./client
```

## Run (2 terminals)

Terminal 1 (server):

```bash
go run ./server -listen :9898 -token tp-secret
```

The first run will auto-generate `cert.pem` and `key.pem`.

Terminal 2 (client):

```bash
go run ./client -server localhost:9898 -token tp-secret -max-retries 5
```

Optional: Use explicit certificate (for production verification):

```bash
go run ./client -server localhost:9898 -token tp-secret -cert cert.pem
```

Optional: customize allowed commands on the client:

```bash
go run ./client -server localhost:9898 -token tp-secret -allow "pwd,ls,whoami,cd"
```

Optional: adjust reconnect behavior:

```bash
go run ./client -server localhost:9898 -token tp-secret -max-retries 10
```

## Usage

Type commands in the server terminal.

The reverse command channel is still present: the server sends commands, the client executes them, and returns output.

The server now keeps one active session at a time. If a second client connects while a session is active, it is refused with `server_busy`.

The server also sends `ping` every 30 seconds. The client answers with `pong` and the session is closed if no pong arrives within 5 seconds.

- To execute a shell command on the client:

```text
command pwd
command ls -la
command whoami
```

- To change directory on the client process:

```text
command cd /tmp
command pwd
```

- Non-shell info request:

```text
info cwd
```

- To close session:

```text
exit
```

## Mini TP Tasks

1. Verify framing:
- Run `go test ./...`
- Explain why a 4-byte header is needed over raw TCP streams.

2. Observe command flow:
- Send `command pwd`
- Describe each step from server input to client output response.

3. Error handling:
- Send `command cd /path/that/does/not/exist`
- Explain where the error is produced and how it is returned.

4. TP2 security validation:
- Start client/server with same token and validate normal behavior.
- Restart client with wrong token and observe authentication failure.
- Send a blocked command (not in whitelist), then validate the rejection message.

5. TP3 security validation:
- Verify TLS handshake by checking certificate files are created
- Test timing attack resistance by attempting token bypass
- Try path traversal: `command ../../bin/touch` should be blocked
- Verify large outputs are capped at 64KB

6. Security discussion:
- Explain risks of executing arbitrary shell commands.
- Propose two mitigations for production use.
- Discuss certificate pinning vs. InsecureSkipVerify tradeoffs

## CI/CD

GitHub Actions runs on every push and PR to `main`:
- Format check with `gofmt`
- Vet with `go vet`
- Tests with `go test -race`
- Build validation for both server and client
- Tests run on Go 1.22 and 1.23

## Notes

This project is intentionally educational and minimal. Do not expose it on untrusted networks.

For production use, consider:
- Implementing proper certificate management
- Using mTLS for mutual authentication
- Adding audit logging
- Implementing rate limiting
- Using sandboxing/containers for command execution
