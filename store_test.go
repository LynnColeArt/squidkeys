package squidkeys

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testKEKs() map[string]string {
	return map[string]string{
		"v1": GenerateKey(),
		"v2": GenerateKey(),
	}
}

func TestRequiresKeyConfiguration(t *testing.T) {
	t.Setenv(keksEnv, "")
	t.Setenv(legacyMasterKeyEnv, "")

	dbPath := filepath.Join(t.TempDir(), "no-key.duckdb")
	_, err := NewKeyStore(dbPath, KeyStoreConfig{})
	if err == nil {
		t.Fatal("expected configuration error")
	}

	var configErr *KeyStoreConfigError
	if !errors.As(err, &configErr) {
		t.Fatalf("expected KeyStoreConfigError, got %T", err)
	}
}

func TestAuthorizationRoundTrip(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "auth.duckdb")
	store, err := NewKeyStore(dbPath, KeyStoreConfig{
		KEKsB64:          testKEKs(),
		ActiveKEKVersion: "v1",
	})
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	defer store.Close()

	accountID := "user-123"
	refreshToken := "refresh-xyz"
	tokenType := "Bearer"
	expires := time.Date(2026, 2, 9, 10, 0, 0, 0, time.UTC)

	err = store.SaveAuthorization(AuthorizationUpsertInput{
		AgentID:      "agent-a",
		Provider:     "discord",
		AccountID:    &accountID,
		Scopes:       []string{"identify", "guilds"},
		AccessToken:  "access-abc",
		RefreshToken: &refreshToken,
		TokenType:    &tokenType,
		ExpiresAt:    &expires,
		Metadata:     map[string]any{"workspace": "primary"},
	})
	if err != nil {
		t.Fatalf("save authorization: %v", err)
	}

	record, err := store.GetAuthorization("agent-a", "discord", &accountID, "")
	if err != nil {
		t.Fatalf("get authorization: %v", err)
	}
	if record == nil {
		t.Fatal("expected authorization record")
	}
	if record.AccessToken != "access-abc" {
		t.Fatalf("access token mismatch: %q", record.AccessToken)
	}
	if record.RefreshToken == nil || *record.RefreshToken != "refresh-xyz" {
		t.Fatalf("refresh token mismatch: %#v", record.RefreshToken)
	}
	if len(record.Scopes) != 2 || record.Scopes[0] != "identify" || record.Scopes[1] != "guilds" {
		t.Fatalf("scopes mismatch: %#v", record.Scopes)
	}
	if record.ExpiresAt == nil || !record.ExpiresAt.Equal(expires) {
		t.Fatalf("expires_at mismatch: %#v", record.ExpiresAt)
	}
	if got := record.Metadata["workspace"]; got != "primary" {
		t.Fatalf("metadata mismatch: %#v", record.Metadata)
	}
	if record.KEKVersion != "v1" {
		t.Fatalf("kek version mismatch: %q", record.KEKVersion)
	}

	deleted, err := store.DeleteAuthorization("agent-a", "discord", &accountID, "")
	if err != nil {
		t.Fatalf("delete authorization: %v", err)
	}
	if !deleted {
		t.Fatal("expected authorization delete to report deleted=true")
	}

	record, err = store.GetAuthorization("agent-a", "discord", &accountID, "")
	if err != nil {
		t.Fatalf("get missing authorization: %v", err)
	}
	if record != nil {
		t.Fatalf("expected missing authorization, got %#v", record)
	}
}

func TestPasswordRoundTrip(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "pwd.duckdb")
	store, err := NewKeyStore(dbPath, KeyStoreConfig{
		KEKsB64:          testKEKs(),
		ActiveKEKVersion: "v1",
	})
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	defer store.Close()

	username := "svc-agent"
	url := "https://api.example.com"

	err = store.SavePassword(PasswordUpsertInput{
		AgentID:  "agent-a",
		Name:     "openai-api",
		Username: &username,
		Password: "super-secret",
		URL:      &url,
		Metadata: map[string]any{"team": "ops"},
	})
	if err != nil {
		t.Fatalf("save password: %v", err)
	}

	record, err := store.GetPassword("agent-a", "openai-api", "")
	if err != nil {
		t.Fatalf("get password: %v", err)
	}
	if record == nil {
		t.Fatal("expected password record")
	}
	if record.Username == nil || *record.Username != "svc-agent" {
		t.Fatalf("username mismatch: %#v", record.Username)
	}
	if record.Password != "super-secret" {
		t.Fatalf("password mismatch: %q", record.Password)
	}
	if record.URL == nil || *record.URL != "https://api.example.com" {
		t.Fatalf("url mismatch: %#v", record.URL)
	}
	if got := record.Metadata["team"]; got != "ops" {
		t.Fatalf("metadata mismatch: %#v", record.Metadata)
	}
	if record.KEKVersion != "v1" {
		t.Fatalf("kek version mismatch: %q", record.KEKVersion)
	}

	deleted, err := store.DeletePassword("agent-a", "openai-api", "")
	if err != nil {
		t.Fatalf("delete password: %v", err)
	}
	if !deleted {
		t.Fatal("expected password delete to report deleted=true")
	}

	record, err = store.GetPassword("agent-a", "openai-api", "")
	if err != nil {
		t.Fatalf("get missing password: %v", err)
	}
	if record != nil {
		t.Fatalf("expected missing password, got %#v", record)
	}
}

func TestValuesAreEncryptedAtRest(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "encrypted.duckdb")
	store, err := NewKeyStore(dbPath, KeyStoreConfig{
		KEKsB64:          testKEKs(),
		ActiveKEKVersion: "v1",
	})
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	if err := store.SavePassword(PasswordUpsertInput{
		AgentID:  "agent-z",
		Name:     "db",
		Password: "plain-visible-check",
	}); err != nil {
		t.Fatalf("save password: %v", err)
	}

	if err := store.SaveAuthorization(AuthorizationUpsertInput{
		AgentID:     "agent-z",
		Provider:    "app",
		AccessToken: "visible-access-token",
	}); err != nil {
		t.Fatalf("save authorization: %v", err)
	}

	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	raw, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatalf("read db file: %v", err)
	}
	if bytes.Contains(raw, []byte("plain-visible-check")) {
		t.Fatal("password appeared in plaintext at rest")
	}
	if bytes.Contains(raw, []byte("visible-access-token")) {
		t.Fatal("access token appeared in plaintext at rest")
	}
}

func TestRewrapRecords(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "rewrap.duckdb")
	keys := testKEKs()
	store, err := NewKeyStore(dbPath, KeyStoreConfig{
		KEKsB64:          keys,
		ActiveKEKVersion: "v1",
	})
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	defer store.Close()

	if err := store.SavePassword(PasswordUpsertInput{
		AgentID:  "agent-r",
		Name:     "db",
		Password: "rotate-me",
	}); err != nil {
		t.Fatalf("save password: %v", err)
	}

	if err := store.SaveAuthorization(AuthorizationUpsertInput{
		AgentID:     "agent-r",
		Provider:    "discord",
		AccessToken: "rotate-token",
	}); err != nil {
		t.Fatalf("save authorization: %v", err)
	}

	result, err := store.RewrapAllRecords("v2", "")
	if err != nil {
		t.Fatalf("rewrap: %v", err)
	}
	if result.TargetKEKVersion != "v2" {
		t.Fatalf("target_kek_version mismatch: %q", result.TargetKEKVersion)
	}
	if result.AuthorizationsRewrapped != 1 {
		t.Fatalf("expected 1 authorization rewrap, got %d", result.AuthorizationsRewrapped)
	}
	if result.PasswordsRewrapped != 1 {
		t.Fatalf("expected 1 password rewrap, got %d", result.PasswordsRewrapped)
	}

	pwd, err := store.GetPassword("agent-r", "db", "")
	if err != nil {
		t.Fatalf("get password: %v", err)
	}
	auth, err := store.GetAuthorization("agent-r", "discord", nil, "")
	if err != nil {
		t.Fatalf("get authorization: %v", err)
	}
	if pwd == nil || pwd.KEKVersion != "v2" {
		t.Fatalf("password kek version mismatch: %#v", pwd)
	}
	if auth == nil || auth.KEKVersion != "v2" {
		t.Fatalf("authorization kek version mismatch: %#v", auth)
	}
}

func TestConcurrentSaveAndRewrapDoesNotCorruptRecords(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "concurrent-rewrap.duckdb")
	keys := testKEKs()
	store, err := NewKeyStore(dbPath, KeyStoreConfig{
		KEKsB64:          keys,
		ActiveKEKVersion: "v1",
	})
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	defer store.Close()

	var (
		stop  = make(chan struct{})
		errCh = make(chan error, 1)
		wg    sync.WaitGroup
		saves atomic.Uint64
	)

	sendErr := func(err error) {
		select {
		case errCh <- err:
		default:
		}
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			target := "v1"
			if i%2 == 1 {
				target = "v2"
			}
			if _, err := store.RewrapAllRecords(target, "test"); err != nil {
				sendErr(fmt.Errorf("rewrap: %w", err))
				break
			}
		}
		close(stop)
	}()

	workers := max(4, runtime.NumCPU()/2)
	for workerID := 0; workerID < workers; workerID++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			n := 0
			for {
				select {
				case <-stop:
					return
				default:
				}

				name := fmt.Sprintf("svc-%d-%d", workerID, n)
				if err := store.SavePassword(PasswordUpsertInput{
					AgentID:  "agent",
					Name:     name,
					Password: name,
					Actor:    "test",
				}); err != nil {
					sendErr(fmt.Errorf("save %s: %w", name, err))
					return
				}

				record, err := store.GetPassword("agent", name, "test")
				if err != nil {
					sendErr(fmt.Errorf("get %s: %w", name, err))
					return
				}
				if record == nil || record.Password != name {
					sendErr(fmt.Errorf("password mismatch for %s: %#v", name, record))
					return
				}

				saves.Add(1)
				n++
			}
		}(workerID)
	}

	wg.Wait()

	select {
	case err := <-errCh:
		t.Fatal(err)
	default:
	}

	if saves.Load() == 0 {
		t.Fatal("expected at least one concurrent save")
	}
}

func TestStoreUsesRestrictiveFilesystemPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits are not portable on Windows")
	}

	dbDir := filepath.Join(t.TempDir(), "keystore")
	dbPath := filepath.Join(dbDir, "store.duckdb")
	store, err := NewKeyStore(dbPath, KeyStoreConfig{
		KEKsB64:          map[string]string{"v1": GenerateKey()},
		ActiveKEKVersion: "v1",
	})
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	defer store.Close()

	dirInfo, err := os.Stat(dbDir)
	if err != nil {
		t.Fatalf("stat db dir: %v", err)
	}
	if dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("expected db dir mode 0700, got %#o", dirInfo.Mode().Perm())
	}

	fileInfo, err := os.Stat(dbPath)
	if err != nil {
		t.Fatalf("stat db file: %v", err)
	}
	if fileInfo.Mode().Perm() != 0o600 {
		t.Fatalf("expected db file mode 0600, got %#o", fileInfo.Mode().Perm())
	}
}
