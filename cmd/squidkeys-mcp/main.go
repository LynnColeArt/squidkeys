package main

import (
	"context"
	"log"
	"os"

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

	transport := os.Getenv("KEY_STORE_MCP_TRANSPORT")
	if transport == "" {
		transport = "stdio"
	}

	if err := squidkeys.RunMCPServer(context.Background(), store, transport); err != nil {
		log.Fatal(err)
	}
}
