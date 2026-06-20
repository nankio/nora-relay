// Command relay is the hosted hub for Nora. Devices self-enroll by proving
// control of their Nano accounts (challenge/signature), so there are no device
// tokens or config files. External callers authenticate with an API key minted
// in-app by the account owner; the relay routes each request to the device that
// proved control of that account. The relay never sees a private key.
//
// State (API key hashes, encrypted policy blobs) lives in a Store: SQLite when
// SQLITE_PATH is set, otherwise an in-memory store for local development.
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	loadDotEnv() // pick up .env.local / .env before reading the environment

	var (
		listen  = flag.String("listen", envOr("LISTEN", ":8080"), "address to listen on")
		timeout = flag.Int("timeout", 45, "seconds to wait for a device to answer a request")
	)
	flag.Parse()

	cfg := &Config{
		Listen:                *listen,
		RequestTimeoutSeconds: *timeout,
		SQLitePath:            os.Getenv("SQLITE_PATH"),
	}

	store, err := openStore(cfg)
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	defer store.Close()

	srv := newServer(cfg, store)
	httpServer := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("relay listening on %s", cfg.Listen)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Println("shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(ctx)
}

// openStore uses SQLite when SQLITE_PATH is set, else an in-memory store for
// local development.
func openStore(cfg *Config) (Store, error) {
	if cfg.SQLitePath == "" {
		log.Println("using in-memory store (set SQLITE_PATH to persist)")
		return newMemStore(), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	log.Printf("using SQLite store at %s", cfg.SQLitePath)
	return newSQLiteStore(ctx, cfg.SQLitePath)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
