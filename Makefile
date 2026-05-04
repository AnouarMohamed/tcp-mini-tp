BIN_DIR := bin
SERVER_BIN := $(BIN_DIR)/server
CLIENT_BIN := $(BIN_DIR)/client

.PHONY: build test lint run-server run-client clean

build:
	mkdir -p $(BIN_DIR)
	go build -o $(SERVER_BIN) ./server
	go build -o $(CLIENT_BIN) ./client

test:
	go test ./...

lint:
	golangci-lint run --config .golangci.yml

run-server:
	go run ./server -listen :9898 -token tp-secret

run-client:
	go run ./client -server localhost:9898 -token tp-secret -max-retries 5

clean:
	rm -rf $(BIN_DIR) cert.pem key.pem
