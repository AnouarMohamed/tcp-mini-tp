#!/usr/bin/env bash
set -euo pipefail

# Lightweight demo script for local testing.
# Usage: PORT=:9898 TOKEN=s3cr3t MODE=2 ./scripts/demo.sh

PORT="${PORT:-:9898}"
TOKEN="${TOKEN:-s3cr3t}"
MODE="${MODE:-2}"

mkdir -p logs
echo "Starting server (mode $MODE) -> logs/server.log"

# Start server and feed the menu choice via stdin, keep logs in background.
printf "%s\n" "$MODE" | nohup go run ./server -listen "$PORT" -token "$TOKEN" > logs/server.log 2>&1 &
SERVER_PID=$!

sleep 1
echo "Running client demo -> logs/client_demo.log"

# Send a couple of commands to the client and exit.
printf "command whoami\nexit\n" | go run ./client -server localhost${PORT} -token "$TOKEN" > logs/client_demo.log 2>&1 || true

sleep 1
echo "Stopping server (pid $SERVER_PID)"
kill "$SERVER_PID" 2>/dev/null || true

echo "Demo complete. See logs/server.log and logs/client_demo.log"
