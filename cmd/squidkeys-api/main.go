package main

import (
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/LynnColeArt/squidkeys-go"
)

func main() {
	dbPath := os.Getenv("KEY_STORE_DB_PATH")
	if dbPath == "" {
		dbPath = "./keystore.duckdb"
	}

	store, err := squidkeys.NewKeyStore(dbPath, squidkeys.KeyStoreConfig{})
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			log.Printf("close store: %v", err)
		}
	}()

	host := os.Getenv("KEY_STORE_API_HOST")
	if host == "" {
		host = "127.0.0.1"
	}

	port := os.Getenv("KEY_STORE_API_PORT")
	if port == "" {
		port = "8080"
	}

	server := &http.Server{
		Addr:              net.JoinHostPort(host, port),
		Handler:           squidkeys.NewHTTPHandler(store),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	log.Printf("SquidKeys API listening on %q", server.Addr)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
