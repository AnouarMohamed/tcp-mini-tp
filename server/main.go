package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	listenAddr := flag.String("listen", ":9898", "TCP address to listen on")
	token := flag.String("token", "tp-secret", "shared authentication token")
	certFile := flag.String("cert", "cert.pem", "path to TLS certificate file")
	keyFile := flag.String("key", "key.pem", "path to TLS private key file")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := startServer(ctx, *listenAddr, *token, *certFile, *keyFile); err != nil {
		log.Fatal(err)
	}
}
