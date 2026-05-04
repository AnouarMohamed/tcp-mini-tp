# Mini TP: TCP Command Channel in Go

This repository is a small practical work for learning TCP client/server communication, framed protocols, remote command execution, and Go project structure.

## Architecture

```text
Server REPL
    |
    | length-prefixed TLS frames
    v
Client listener  <--- heartbeat ping/pong --->  Server heartbeat loop
    |
    +--> normal commands: allowlisted process execution
    +--> info commands: native OS/env/uptime/memory inspection
    +--> shell mode: long-lived bash session
    +--> history log: commands.log (NDJSON)
```

## Features

| Feature | Description |
| --- | --- |
| TLS transport | All traffic is encrypted; the server auto-generates `cert.pem` and `key.pem` on first run. |
| Shared-token auth | The client authenticates before any commands are accepted. |
| Single active session | A second client is refused while one session is active. |
| Heartbeat | `ping`/`pong` keeps the session healthy and closes dead connections quickly. |
| Reconnect | The client retries with exponential backoff. |
| Normal command mode | `command <name> ...` executes allowlisted commands. |
| Persistent shell mode | `shell` starts a long-lived bash process; `shell exit` stops it. |
| Native info commands | `info os`, `info env`, `info uptime`, and `info memory` are handled locally on the client. |
| Command history | Every REPL command is appended to `commands.log` as newline-delimited JSON; `history` prints the last 20 entries. |
| Output cap | Command output is limited to 64 KB. |

## Protocol

Each message is sent as a 4-byte big-endian length header followed by the UTF-8 payload. That framing avoids partial-read issues on raw TCP streams and keeps request/response handling simple.

## Usage

Run the server in one terminal:

```bash
go run ./server -listen :9898 -token tp-secret
```

Run the client in another terminal:

```bash
go run ./client -server localhost:9898 -token tp-secret -max-retries 5
```

Useful REPL commands:

```text
command pwd
command ls -la
info os
info env
info uptime
info memory
shell
shell exit
history
exit
```

## Project Structure

- `server/main.go`: server entrypoint and shutdown handling
- `server/session.go`: server REPL, session control, and command routing
- `server/history.go`: command history persistence helpers
- `server/tls.go`: self-signed certificate generation
- `client/main.go`: client entrypoint, command execution, and reconnect logic
- `client/info.go`: native `info` command handlers
- `client/shell.go`: persistent shell session manager
- `internal/protocol/protocol.go`: shared frame read/write helpers

## Security Considerations

This project is educational and should not be exposed to untrusted networks.

- Remote command execution is inherently risky; keep the allowlist narrow and treat the shell mode as privileged.
- `info env` redacts common secret-like keys, but environment inspection can still leak operational metadata.
- The default TLS setup uses a self-signed certificate; use `-cert` to verify the server instead of trusting any certificate.
- Command history is written locally to `commands.log`; protect that file if the client runs on a sensitive system.
- For production use, prefer mTLS, stronger authorization, sandboxing, and central audit logging.

## Build and Test

```bash
go build ./server ./client
go test ./...
```
