package main

import (
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/LynnColeArt/squidkeys-go"
)

func main() {
	dbPath := os.Getenv("KEY_STORE_DB_PATH")
	if dbPath == "" {
		dbPath = "./keystore.duckdb"
	}

	host := os.Getenv("KEY_STORE_API_HOST")
	if host == "" {
		host = "127.0.0.1"
	}
	policyPath := os.Getenv("KEY_STORE_ORG_AUTH_POLICY_PATH")
	certFile := os.Getenv("KEY_STORE_TLS_CERT_FILE")
	keyFile := os.Getenv("KEY_STORE_TLS_KEY_FILE")
	if err := validateServeConfig(host, policyPath, certFile, keyFile, os.Getenv("KEY_STORE_BEARER_TOKEN")); err != nil {
		log.Fatal(err)
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

	port := os.Getenv("KEY_STORE_API_PORT")
	if port == "" {
		port = "8080"
	}

	handler := squidkeys.NewHTTPHandler(store)
	if policyPath != "" {
		policy, err := squidkeys.LoadOrganizationPolicy(policyPath)
		if err != nil {
			log.Fatal(err)
		}
		handler = squidkeys.NewOrganizationHTTPHandler(store, policy)
	}

	server := &http.Server{
		Addr:              net.JoinHostPort(host, port),
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	log.Printf("SquidKeys API listening on %q", server.Addr)
	if certFile != "" {
		err = server.ListenAndServeTLS(certFile, keyFile)
	} else {
		err = server.ListenAndServe()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func validateServeConfig(host, policyPath, certFile, keyFile, legacyBearer string) error {
	if (certFile == "") != (keyFile == "") {
		return errors.New("KEY_STORE_TLS_CERT_FILE and KEY_STORE_TLS_KEY_FILE must be set together")
	}
	if policyPath != "" && legacyBearer != "" {
		return errors.New("organization policy and legacy bearer token cannot be combined")
	}
	if strings.EqualFold(host, "localhost") || net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback() {
		return nil
	}
	if policyPath == "" || certFile == "" {
		return errors.New("non-loopback API binding requires an organization policy and TLS certificate/key")
	}
	return nil
}
