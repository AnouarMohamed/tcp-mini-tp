# TCP Mini-TP

A production-grade TCP command channel written in Go. The server operator sends instructions to a connected client over a custom length-prefixed framing protocol. Every connection is encrypted with TLS, every command is authenticated, every action is audited.

```
┌─────────────────────────────────────────────────────────────┐
│                        OPERATOR                             │
│                   (server terminal)                         │
└───────────────────────────┬─────────────────────────────────┘
                            │  TLS 1.3 · token auth · framed protocol
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                         SERVER                              │
│   session manager · allowlist enforcement · audit log       │
└───────────────────────────┬─────────────────────────────────┘
                            │  length-prefixed frames (uint32 BE)
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                         CLIENT                              │
│   exec.LookPath · output cap · reconnect backoff · info API │
└─────────────────────────────────────────────────────────────┘
```

---

## Features

| Feature | Detail |
|---|---|
| Transport encryption | TLS with auto-generated RSA-2048 cert on first run |
| Authentication | Pre-shared token, verified with `subtle.ConstantTimeCompare` |
| Command allowlist | Resolved via `exec.LookPath` — path traversal bypasses blocked |
| Output cap | All command output capped at 64 KB via `io.LimitedReader` |
| Native info API | `info os/memory/uptime/env` — no subprocess, no shell |
| Session management | Mutex-guarded single active session, concurrent connections rejected |
| Reconnect backoff | Exponential retry 1s → 2s → 4s … capped at 30s, configurable max attempts |
| Heartbeat | Server pings every 30s, session closes if no pong within 5s |
| Audit log | Every command written to `commands.log` as newline-delimited JSON |
| Structured logging | `log/slog` JSON output throughout — component, event, remote_addr fields |
| Graceful shutdown | `SIGINT`/`SIGTERM` handling, clean session drain before exit |
| Test suite | Table-driven tests across all packages, race detector enabled |

---

## Architecture

### Protocol

All messages use a simple length-prefixed framing layer: a 4-byte big-endian `uint32` header followed by the payload. The max frame size is 1 MiB. This makes the protocol self-delimiting — no newline scanning, no ambiguity.

```
┌────────────────┬──────────────────────────────┐
│  uint32 (BE)   │         payload bytes         │
│   4 bytes      │       up to 1,048,576 B       │
└────────────────┴──────────────────────────────┘
```

### Instruction set

| Prefix | Example | Handled by |
|---|---|---|
| `command` | `command whoami` | `exec.LookPath` + allowlist |
| `info` | `info os` | Native Go, no subprocess |
| `cd` | `cd /tmp` | `os.Chdir` |
| `history` | `history` | In-memory ring buffer |

---

## Quickstart

### Requirements

- Go 1.21+
- Make

### Build

```bash
git clone https://github.com/you/tcp-mini-tp
cd tcp-mini-tp
make build
```

Binaries are placed in `bin/`.

### Run

**Terminal 1 — start the server:**
```bash
go run ./server -listen :9898 -token s3cr3t
```

On first run, `cert.pem` and `key.pem` are auto-generated. The server is ready when you see `listener_started`.

**Terminal 2 — connect the client:**
```bash
go run ./client -server localhost:9898 -token s3cr3t
```

---

## Demo

### 1. Server starts with structured JSON logging

![Server start](ssc/Screenshot%20From%202026-05-04%2022-29-16.png)

On first boot the server generates `cert.pem` and `key.pem`, binds to `:9898`, and emits a structured JSON log line confirming it is listening. All subsequent logs follow the same format with `time`, `level`, `msg`, `component`, `remote_addr`, and `event` fields.

---

### 2. Client connects and authenticates

![Client connect](ssc/Screenshot%20From%202026-05-04%2022-30-12.png)

The client performs a TLS handshake using the server's certificate, then sends the pre-shared token. The server verifies it with `subtle.ConstantTimeCompare` — immune to timing side-channel attacks. Both sides log `connected` and `authenticated` as separate structured events.

---

### 3. Unknown instructions are rejected cleanly

![Unknown instruction](ssc/Screenshot%20From%202026-05-04%2022-30-49.png)

Any input without a recognised prefix is rejected by the client with a clear error message. The session stays alive — no crash, no hang.

---

### 4. Allowed commands execute over the encrypted channel

![command whoami](ssc/Screenshot%20From%202026-05-04%2022-41-02.png)

![command pwd](ssc/Screenshot%20From%202026-05-04%2022-42-05.png)

![command ls](ssc/Screenshot%20From%202026-05-04%2022-46-34.png)

`command whoami`, `command pwd`, and `command ls` all execute on the client machine and return output over the TLS channel. Note `cert.pem` and `key.pem` visible in the `ls` output — proof the encryption layer is active.

---

### 5. Allowlist blocks unauthorised commands

![curl blocked](ssc/Screenshot%20From%202026-05-04%2022-50-21.png)

![curl blocked then whoami allowed](ssc/Screenshot%20From%202026-05-04%2022-51-28.png)

`command curl https://example.com` is blocked — `curl` is not in the allowlist. The immediately following `command whoami` succeeds. The allowlist is selective, not a killswitch. The binary is resolved with `exec.LookPath` before the check, so path traversal attempts like `command /usr/bin/../bin/curl` are also caught.

---

### 6. Native info instructions — no subprocess required

![info os, memory, uptime](ssc/Screenshot%20From%202026-05-04%2022-53-16.png)

`info os`, `info memory`, and `info uptime` are handled entirely in Go using `runtime.GOOS`/`GOARCH`, `runtime.ReadMemStats`, and `time.Since`. No shell is spawned, no allowlist is consulted. `info env` is also available and automatically strips any environment variable whose key contains `TOKEN`, `SECRET`, `KEY`, or `PASS`.

---

### 7. Full command history in the REPL

![history](ssc/Screenshot%20From%202026-05-04%2022-56-29.png)

`history` prints the last 20 commands from the in-memory ring buffer, each entry including timestamp, remote address, command string, and event type. Every session's commands are also written to `commands.log` as newline-delimited JSON for persistent auditing.

---

### 8. Reconnect with exponential backoff

![reconnect backoff](ssc/Screenshot%20From%202026-05-04%2022-57-48.png)

When the server drops, the client retries automatically — 1s, 2s, 4s, 8s, 16s — doubling each attempt up to a configurable cap. After max retries are exhausted it exits with a clear fatal log line. When the server comes back before the cap, the client reconnects and re-authenticates without any manual intervention.

---

### 9. Server restarts cleanly

![server restart](ssc/Screenshot%20From%202026-05-04%2022-59-18.png)

The server can be stopped and restarted at any time. It re-reads the existing `cert.pem` and `key.pem` — no new cert generated, no disruption to clients that have the cert pinned.

---

### 10. Wrong token is rejected at authentication

![wrong token client](ssc/Screenshot%20From%202026-05-04%2022-59-41.png)

![wrong token server](ssc/Screenshot%20From%202026-05-04%2023-00-03.png)

A client presenting the wrong token connects at the TCP level, completes the TLS handshake, but is rejected immediately at the application authentication layer. The server logs `authentication_failed` with the remote address. The client exits with `authentication rejected`. No commands are ever reachable.

---

### 11. Wireshark / tcpdump confirms traffic is encrypted

![tcpdump encrypted](ssc/Screenshot%20From%202026-05-04%2023-11-40.png)

![command sent during capture](ssc/Screenshot%20From%202026-05-04%2023-12-06.png)

`sudo tcpdump -i lo -A port 9898` captures live traffic while a `command whoami` is sent. The output is binary noise — no readable token, no readable command, no readable response. This is TLS doing real work.

---

### 12. Test suite passes with race detector

![make test](ssc/Screenshot%20From%202026-05-04%2023-15-22.png)

All three packages pass: `client`, `internal/protocol`, and `server`. The `-race` flag is enabled, confirming the session manager mutex eliminates the multi-client stdin race that existed in the original implementation.

---

### 13. Coverage report

![coverage terminal](ssc/Screenshot%20From%202026-05-04%2023-16-40.png)

![coverage browser](ssc/Screenshot%20From%202026-05-04%2023-17-20.png)

`go test -coverprofile=coverage.out ./...` followed by `go tool cover -html=coverage.out` opens a line-by-line HTML report. The protocol package sits at 78.9% coverage. Green lines are covered, red lines are not — every uncovered branch is visible and addressable.

---

### 14. Auto-generated TLS certificate

![openssl cert](ssc/Screenshot%20From%202026-05-04%2023-18-39.png)

`openssl x509 -in cert.pem -text -noout` confirms the auto-generated certificate is a real X.509 v3 certificate — RSA-2048 key, SHA-256 signature, issued to `CN=localhost` under `O=TCP-Mini-TP`, valid for one year from first run.

---

### 15. Certificate validation enforced at the transport layer

![wrong cert](ssc/Screenshot%20From%202026-05-04%2023-19-06.png)

Passing a non-existent or wrong certificate file via `-cert wrongcert.pem` fails before the TLS handshake completes. The error surfaces at `cert_read_error` — no application data is ever exchanged. TLS enforcement is at the transport layer, not application logic.

---

## Makefile

```bash
make build       # compile server and client to bin/
make test        # go test -race -cover ./...
make lint        # golangci-lint run
make run-server  # go run ./server -listen :9898 -token s3cr3t
make run-client  # go run ./client -server localhost:9898 -token s3cr3t
make clean       # remove bin/ and coverage artifacts
```

---

## Flags

### Server

| Flag | Default | Description |
|---|---|---|
| `-listen` | `:9898` | Address to bind |
| `-token` | *(required)* | Pre-shared authentication token |
| `-allowlist` | `whoami,ls,pwd,id,uname,hostname,date,uptime,ps` | Comma-separated allowed commands |

### Client

| Flag | Default | Description |
|---|---|---|
| `-server` | `localhost:9898` | Server address |
| `-token` | *(required)* | Pre-shared authentication token |
| `-cert` | *(optional)* | Path to server's `cert.pem` for pinning |
| `-max-retries` | `5` | Max reconnect attempts before exit |

---

## Security notes

- The token is compared with `crypto/subtle.ConstantTimeCompare` — not vulnerable to timing attacks.
- All commands are resolved with `exec.LookPath` before the allowlist check — path traversal bypasses (`/usr/bin/../bin/curl`) are blocked.
- Command output is capped at 64 KB — `cat /dev/zero` cannot hang the server.
- `info env` strips sensitive keys automatically — tokens and secrets are never returned.
- The TLS certificate is self-signed. For production use, replace `cert.pem`/`key.pem` with a CA-issued certificate.
- This project is for educational and authorised lab use only.

---

## Project structure

```
.
├── server/
│   └── main.go          # listener, session manager, REPL, audit log
├── client/
│   ├── main.go          # connection, auth, execute(), reconnect loop
│   └── main_test.go     # table-driven tests for execute()
├── internal/
│   └── protocol/
│       ├── protocol.go       # ReadFrame / WriteFrame
│       └── protocol_test.go  # framing edge cases
├── commands.log         # generated at runtime
├── cert.pem             # generated on first server run
├── key.pem              # generated on first server run
├── Makefile
└── go.mod
```

---

## License

MIT
