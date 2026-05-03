# Mini TP: TCP Command Channel in Go

This repository is a mini practical work (TP) to understand:
- TCP client/server communication
- framing messages over a stream (length-prefix protocol)
- basic remote command execution flow
- clean code organization in Go

## Project Structure

- `server/main.go`: server executable (listens, sends commands, prints client output)
- `client/main.go`: client executable (receives commands, executes, sends output)
- `internal/protocol/protocol.go`: shared framing logic
- `internal/protocol/protocol_test.go`: protocol tests

## Protocol (Application Layer)

Each message is sent as:
1. 4 bytes unsigned integer (big-endian) representing payload size
2. payload bytes (UTF-8 string)

This avoids partial-read issues and allows clean request/response exchanges.

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
go run ./server -listen :9898
```

Terminal 2 (client):

```bash
go run ./client -server localhost:9898
```

## Usage

Type commands in the server terminal.

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

4. Extension task:
- Add support for a new instruction prefix `info` on client side.
- Example expected behavior: `info cwd` returns current directory without calling shell.

5. Security discussion:
- Explain risks of executing arbitrary shell commands.
- Propose two mitigations for production use.

## Notes

This project is intentionally educational and minimal. Do not expose it on untrusted networks.
