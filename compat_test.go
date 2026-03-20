package squidkeys

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

type pythonCompatFixture struct {
	Auth *AuthorizationRecord `json:"auth"`
	Pwd  *PasswordRecord      `json:"pwd"`
}

type pythonCompatStore struct {
	PythonBin string
	SourceDir string
}

func TestPythonWritesGoReads(t *testing.T) {
	compat := requirePythonCompat(t)
	keys := compatKEKs()
	dbPath := filepath.Join(t.TempDir(), "python-writes-go-reads.duckdb")

	runPythonCompat(t, compat, pythonSeedFixtures, map[string]string{
		"TEST_DB_PATH":            dbPath,
		"TEST_KEKS_JSON":          mustJSON(t, keys),
		"TEST_ACTIVE_KEK_VERSION": "v1",
	})

	store, err := NewKeyStore(dbPath, KeyStoreConfig{
		KEKsB64:          keys,
		ActiveKEKVersion: "v1",
	})
	if err != nil {
		t.Fatalf("open go store: %v", err)
	}
	defer store.Close()

	accountID := "user-123"
	auth, err := store.GetAuthorization("agent-python", "discord", &accountID, "compat-go")
	if err != nil {
		t.Fatalf("read python authorization: %v", err)
	}
	if auth == nil {
		t.Fatal("expected authorization record")
	}
	if auth.AccessToken != "python-access-token" {
		t.Fatalf("access token mismatch: %q", auth.AccessToken)
	}
	if auth.RefreshToken == nil || *auth.RefreshToken != "python-refresh-token" {
		t.Fatalf("refresh token mismatch: %#v", auth.RefreshToken)
	}
	if len(auth.Scopes) != 2 || auth.Scopes[0] != "identify" || auth.Scopes[1] != "guilds" {
		t.Fatalf("scopes mismatch: %#v", auth.Scopes)
	}
	wantExpiry := time.Date(2026, 2, 9, 10, 0, 0, 0, time.UTC)
	if auth.ExpiresAt == nil || !auth.ExpiresAt.Equal(wantExpiry) {
		t.Fatalf("expires_at mismatch: got %#v want %s", auth.ExpiresAt, wantExpiry.Format(time.RFC3339))
	}
	if auth.Metadata["workspace"] != "python-primary" {
		t.Fatalf("auth metadata mismatch: %#v", auth.Metadata)
	}
	if auth.KEKVersion != "v1" {
		t.Fatalf("auth kek version mismatch: %q", auth.KEKVersion)
	}

	pwd, err := store.GetPassword("agent-python", "openai-api", "compat-go")
	if err != nil {
		t.Fatalf("read python password: %v", err)
	}
	if pwd == nil {
		t.Fatal("expected password record")
	}
	if pwd.Username == nil || *pwd.Username != "svc-python" {
		t.Fatalf("username mismatch: %#v", pwd.Username)
	}
	if pwd.Password != "python-super-secret" {
		t.Fatalf("password mismatch: %q", pwd.Password)
	}
	if pwd.URL == nil || *pwd.URL != "https://api.example.com/python" {
		t.Fatalf("url mismatch: %#v", pwd.URL)
	}
	if pwd.Metadata["team"] != "python-ops" {
		t.Fatalf("password metadata mismatch: %#v", pwd.Metadata)
	}
	if pwd.KEKVersion != "v1" {
		t.Fatalf("password kek version mismatch: %q", pwd.KEKVersion)
	}
}

func TestGoWritesPythonReads(t *testing.T) {
	compat := requirePythonCompat(t)
	keys := compatKEKs()
	dbPath := filepath.Join(t.TempDir(), "go-writes-python-reads.duckdb")

	store, err := NewKeyStore(dbPath, KeyStoreConfig{
		KEKsB64:          keys,
		ActiveKEKVersion: "v1",
	})
	if err != nil {
		t.Fatalf("new go store: %v", err)
	}

	accountID := "user-go"
	refreshToken := "go-refresh-token"
	tokenType := "Bearer"
	offset := time.FixedZone("UTC-6", -6*60*60)
	expires := time.Date(2026, 2, 9, 4, 0, 0, 0, offset)
	username := "svc-go"
	url := "https://api.example.com/go"

	if err := store.SaveAuthorization(AuthorizationUpsertInput{
		AgentID:      "agent-go",
		Provider:     "discord",
		AccountID:    &accountID,
		Scopes:       []string{"identify", "email"},
		AccessToken:  "go-access-token",
		RefreshToken: &refreshToken,
		TokenType:    &tokenType,
		ExpiresAt:    &expires,
		Metadata:     map[string]any{"workspace": "go-primary"},
		Actor:        "compat-go",
	}); err != nil {
		t.Fatalf("save authorization: %v", err)
	}

	if err := store.SavePassword(PasswordUpsertInput{
		AgentID:  "agent-go",
		Name:     "openai-api",
		Username: &username,
		Password: "go-super-secret",
		URL:      &url,
		Metadata: map[string]any{"team": "go-ops"},
		Actor:    "compat-go",
	}); err != nil {
		t.Fatalf("save password: %v", err)
	}

	if err := store.Close(); err != nil {
		t.Fatalf("close go store: %v", err)
	}

	var fixture pythonCompatFixture
	runPythonCompatJSON(t, compat, pythonReadFixtures, map[string]string{
		"TEST_DB_PATH":            dbPath,
		"TEST_KEKS_JSON":          mustJSON(t, keys),
		"TEST_ACTIVE_KEK_VERSION": "v1",
		"TEST_AGENT_ID":           "agent-go",
		"TEST_PROVIDER":           "discord",
		"TEST_ACCOUNT_ID":         accountID,
		"TEST_PASSWORD_NAME":      "openai-api",
	}, &fixture)

	if fixture.Auth == nil {
		t.Fatal("expected python auth fixture")
	}
	if fixture.Auth.AccessToken != "go-access-token" {
		t.Fatalf("auth access token mismatch: %q", fixture.Auth.AccessToken)
	}
	if fixture.Auth.RefreshToken == nil || *fixture.Auth.RefreshToken != "go-refresh-token" {
		t.Fatalf("auth refresh token mismatch: %#v", fixture.Auth.RefreshToken)
	}
	if fixture.Auth.ExpiresAt == nil || !fixture.Auth.ExpiresAt.Equal(time.Date(2026, 2, 9, 10, 0, 0, 0, time.UTC)) {
		t.Fatalf("auth expires_at mismatch: %#v", fixture.Auth.ExpiresAt)
	}
	if fixture.Auth.Metadata["workspace"] != "go-primary" {
		t.Fatalf("auth metadata mismatch: %#v", fixture.Auth.Metadata)
	}
	if fixture.Auth.KEKVersion != "v1" {
		t.Fatalf("auth kek version mismatch: %q", fixture.Auth.KEKVersion)
	}

	if fixture.Pwd == nil {
		t.Fatal("expected python password fixture")
	}
	if fixture.Pwd.Password != "go-super-secret" {
		t.Fatalf("password mismatch: %q", fixture.Pwd.Password)
	}
	if fixture.Pwd.Username == nil || *fixture.Pwd.Username != "svc-go" {
		t.Fatalf("username mismatch: %#v", fixture.Pwd.Username)
	}
	if fixture.Pwd.URL == nil || *fixture.Pwd.URL != "https://api.example.com/go" {
		t.Fatalf("url mismatch: %#v", fixture.Pwd.URL)
	}
	if fixture.Pwd.Metadata["team"] != "go-ops" {
		t.Fatalf("password metadata mismatch: %#v", fixture.Pwd.Metadata)
	}
	if fixture.Pwd.KEKVersion != "v1" {
		t.Fatalf("password kek version mismatch: %q", fixture.Pwd.KEKVersion)
	}
}

func TestPythonRewrapsGoReads(t *testing.T) {
	compat := requirePythonCompat(t)
	keys := compatKEKs()
	dbPath := filepath.Join(t.TempDir(), "python-rewraps-go-reads.duckdb")

	store, err := NewKeyStore(dbPath, KeyStoreConfig{
		KEKsB64:          keys,
		ActiveKEKVersion: "v1",
	})
	if err != nil {
		t.Fatalf("new go store: %v", err)
	}

	if err := store.SavePassword(PasswordUpsertInput{
		AgentID:  "agent-rewrap",
		Name:     "db",
		Password: "rotate-me-go",
		Actor:    "compat-go",
	}); err != nil {
		t.Fatalf("save password: %v", err)
	}

	if err := store.SaveAuthorization(AuthorizationUpsertInput{
		AgentID:     "agent-rewrap",
		Provider:    "discord",
		AccessToken: "rotate-token-go",
		Actor:       "compat-go",
	}); err != nil {
		t.Fatalf("save authorization: %v", err)
	}

	if err := store.Close(); err != nil {
		t.Fatalf("close go store: %v", err)
	}

	runPythonCompat(t, compat, pythonRewrapFixtures, map[string]string{
		"TEST_DB_PATH":                 dbPath,
		"TEST_KEKS_JSON":               mustJSON(t, keys),
		"TEST_ACTIVE_KEK_VERSION":      "v1",
		"TEST_TARGET_KEK_VERSION":      "v2",
		"TEST_EXPECTED_AUTH_COUNT":     "1",
		"TEST_EXPECTED_PASSWORD_COUNT": "1",
	})

	reopened, err := NewKeyStore(dbPath, KeyStoreConfig{
		KEKsB64:          keys,
		ActiveKEKVersion: "v1",
	})
	if err != nil {
		t.Fatalf("reopen go store: %v", err)
	}
	defer reopened.Close()

	auth, err := reopened.GetAuthorization("agent-rewrap", "discord", nil, "compat-go")
	if err != nil {
		t.Fatalf("read rewrapped auth: %v", err)
	}
	if auth == nil || auth.KEKVersion != "v2" || auth.AccessToken != "rotate-token-go" {
		t.Fatalf("unexpected auth after python rewrap: %#v", auth)
	}

	pwd, err := reopened.GetPassword("agent-rewrap", "db", "compat-go")
	if err != nil {
		t.Fatalf("read rewrapped password: %v", err)
	}
	if pwd == nil || pwd.KEKVersion != "v2" || pwd.Password != "rotate-me-go" {
		t.Fatalf("unexpected password after python rewrap: %#v", pwd)
	}
}

func TestGoRewrapsPythonReads(t *testing.T) {
	compat := requirePythonCompat(t)
	keys := compatKEKs()
	dbPath := filepath.Join(t.TempDir(), "go-rewraps-python-reads.duckdb")

	runPythonCompat(t, compat, pythonSeedFixtures, map[string]string{
		"TEST_DB_PATH":            dbPath,
		"TEST_KEKS_JSON":          mustJSON(t, keys),
		"TEST_ACTIVE_KEK_VERSION": "v1",
	})

	store, err := NewKeyStore(dbPath, KeyStoreConfig{
		KEKsB64:          keys,
		ActiveKEKVersion: "v1",
	})
	if err != nil {
		t.Fatalf("open go store: %v", err)
	}

	result, err := store.RewrapAllRecords("v2", "compat-go")
	if err != nil {
		t.Fatalf("go rewrap: %v", err)
	}
	if result.AuthorizationsRewrapped != 1 || result.PasswordsRewrapped != 1 {
		t.Fatalf("unexpected rewrap result: %#v", result)
	}

	if err := store.Close(); err != nil {
		t.Fatalf("close go store: %v", err)
	}

	var fixture pythonCompatFixture
	runPythonCompatJSON(t, compat, pythonReadFixtures, map[string]string{
		"TEST_DB_PATH":            dbPath,
		"TEST_KEKS_JSON":          mustJSON(t, keys),
		"TEST_ACTIVE_KEK_VERSION": "v2",
		"TEST_AGENT_ID":           "agent-python",
		"TEST_PROVIDER":           "discord",
		"TEST_ACCOUNT_ID":         "user-123",
		"TEST_PASSWORD_NAME":      "openai-api",
	}, &fixture)

	if fixture.Auth == nil || fixture.Auth.KEKVersion != "v2" || fixture.Auth.AccessToken != "python-access-token" {
		t.Fatalf("unexpected auth after go rewrap: %#v", fixture.Auth)
	}
	if fixture.Pwd == nil || fixture.Pwd.KEKVersion != "v2" || fixture.Pwd.Password != "python-super-secret" {
		t.Fatalf("unexpected password after go rewrap: %#v", fixture.Pwd)
	}
}

func requirePythonCompat(t *testing.T) pythonCompatStore {
	t.Helper()

	sourceDir := os.Getenv("SQUIDKEYS_PYTHON_SOURCE")
	if sourceDir == "" {
		t.Skip("set SQUIDKEYS_PYTHON_SOURCE to the original SquidKeys src directory to run compatibility tests")
	}

	if _, err := os.Stat(filepath.Join(sourceDir, "key_store", "store.py")); err != nil {
		t.Skipf("python reference source not found at %s: %v", sourceDir, err)
	}

	pythonBin := os.Getenv("SQUIDKEYS_PYTHON_BIN")
	if pythonBin == "" {
		pythonBin = "python3"
	}

	check := exec.Command(pythonBin, "-c", "import cryptography, duckdb")
	if output, err := check.CombinedOutput(); err != nil {
		t.Skipf("python compatibility dependencies are unavailable for %s: %v\n%s", pythonBin, err, output)
	}

	return pythonCompatStore{
		PythonBin: pythonBin,
		SourceDir: sourceDir,
	}
}

func runPythonCompat(t *testing.T, compat pythonCompatStore, code string, env map[string]string) {
	t.Helper()

	cmd := exec.Command(compat.PythonBin, "-c", code)
	cmd.Dir = filepath.Dir(compat.SourceDir)
	cmd.Env = append(os.Environ(),
		"SQUIDKEYS_PYTHON_SOURCE="+compat.SourceDir,
	)
	for key, value := range env {
		cmd.Env = append(cmd.Env, key+"="+value)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("python compat command failed: %v\n%s", err, output)
	}
}

func runPythonCompatJSON(t *testing.T, compat pythonCompatStore, code string, env map[string]string, dst any) {
	t.Helper()

	cmd := exec.Command(compat.PythonBin, "-c", code)
	cmd.Dir = filepath.Dir(compat.SourceDir)
	cmd.Env = append(os.Environ(),
		"SQUIDKEYS_PYTHON_SOURCE="+compat.SourceDir,
	)
	for key, value := range env {
		cmd.Env = append(cmd.Env, key+"="+value)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("python compat JSON command failed: %v\n%s", err, output)
	}

	if err := json.NewDecoder(bytes.NewReader(output)).Decode(dst); err != nil {
		t.Fatalf("decode python JSON output: %v\n%s", err, output)
	}
}

func compatKEKs() map[string]string {
	return map[string]string{
		"v1": GenerateKey(),
		"v2": GenerateKey(),
	}
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal JSON: %v", err)
	}
	return string(data)
}

const pythonCompatPrelude = `
import json
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.environ["SQUIDKEYS_PYTHON_SOURCE"])

from key_store import KeyStore

store = KeyStore(
    db_path=os.environ["TEST_DB_PATH"],
    keks_b64=json.loads(os.environ["TEST_KEKS_JSON"]),
    active_kek_version=os.environ.get("TEST_ACTIVE_KEK_VERSION") or None,
)
`

const pythonSeedFixtures = pythonCompatPrelude + `
try:
    expires = datetime(2026, 2, 9, 4, 0, 0, tzinfo=timezone(timedelta(hours=-6)))
    store.save_authorization(
        agent_id="agent-python",
        provider="discord",
        account_id="user-123",
        scopes=["identify", "guilds"],
        access_token="python-access-token",
        refresh_token="python-refresh-token",
        token_type="Bearer",
        expires_at=expires,
        metadata={"workspace": "python-primary"},
        actor="compat-python",
    )
    store.save_password(
        agent_id="agent-python",
        name="openai-api",
        username="svc-python",
        password="python-super-secret",
        url="https://api.example.com/python",
        metadata={"team": "python-ops"},
        actor="compat-python",
    )
finally:
    store.close()
`

const pythonReadFixtures = pythonCompatPrelude + `
try:
    account_id = os.environ.get("TEST_ACCOUNT_ID") or None
    auth = store.get_authorization(
        agent_id=os.environ["TEST_AGENT_ID"],
        provider=os.environ["TEST_PROVIDER"],
        account_id=account_id,
        actor="compat-python",
    )
    pwd = store.get_password(
        agent_id=os.environ["TEST_AGENT_ID"],
        name=os.environ["TEST_PASSWORD_NAME"],
        actor="compat-python",
    )
    payload = {
        "auth": {
            "agent_id": auth.agent_id,
            "provider": auth.provider,
            "account_id": auth.account_id,
            "scopes": auth.scopes,
            "access_token": auth.access_token,
            "refresh_token": auth.refresh_token,
            "token_type": auth.token_type,
            "expires_at": auth.expires_at.isoformat() if auth.expires_at else None,
            "metadata": auth.metadata,
            "kek_version": auth.kek_version,
        } if auth else None,
        "pwd": {
            "agent_id": pwd.agent_id,
            "name": pwd.name,
            "username": pwd.username,
            "password": pwd.password,
            "url": pwd.url,
            "metadata": pwd.metadata,
            "kek_version": pwd.kek_version,
        } if pwd else None,
    }
    print(json.dumps(payload, separators=(",", ":")))
finally:
    store.close()
`

const pythonRewrapFixtures = pythonCompatPrelude + `
try:
    result = store.rewrap_all_records(
        target_kek_version=os.environ["TEST_TARGET_KEK_VERSION"],
        actor="compat-python",
    )
    expected_auth = int(os.environ["TEST_EXPECTED_AUTH_COUNT"])
    expected_pwd = int(os.environ["TEST_EXPECTED_PASSWORD_COUNT"])
    if result["authorizations_rewrapped"] != expected_auth:
        raise SystemExit(
            f"unexpected authorization rewrap count: {result['authorizations_rewrapped']} != {expected_auth}"
        )
    if result["passwords_rewrapped"] != expected_pwd:
        raise SystemExit(
            f"unexpected password rewrap count: {result['passwords_rewrapped']} != {expected_pwd}"
        )
finally:
    store.close()
`
