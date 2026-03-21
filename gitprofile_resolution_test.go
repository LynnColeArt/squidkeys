package squidkeys

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type gitProfileConsumerFixture struct {
	AgentID       string                   `json:"agent_id"`
	Profile       GitProfileUpsertInput    `json:"profile"`
	Authorization AuthorizationUpsertInput `json:"authorization"`
	Password      PasswordUpsertInput      `json:"password"`
	Certificate   struct {
		Name string `json:"name"`
	} `json:"certificate"`
}

func TestResolveGitProfileConsumerFixture(t *testing.T) {
	store, fixture := newGitProfileResolutionStore(t)
	defer store.Close()

	bundle := makeTestCertificateBundle(t)
	if err := seedGitProfileResolutionFixture(store, fixture, bundle); err != nil {
		t.Fatalf("seed resolution fixture: %v", err)
	}

	resolved, err := store.ResolveGitProfile(fixture.AgentID, fixture.Profile.Name, "switcher")
	if err != nil {
		t.Fatalf("resolve git profile: %v", err)
	}
	if resolved == nil {
		t.Fatal("expected resolved git profile")
	}

	if resolved.Profile.Name != fixture.Profile.Name {
		t.Fatalf("profile name mismatch: %q", resolved.Profile.Name)
	}
	if resolved.Profile.Host == nil || *resolved.Profile.Host != "github.com" {
		t.Fatalf("profile host mismatch: %#v", resolved.Profile.Host)
	}
	if resolved.HTTPSAuthorization == nil || resolved.HTTPSAuthorization.AccessToken != fixture.Authorization.AccessToken {
		t.Fatalf("https authorization mismatch: %#v", resolved.HTTPSAuthorization)
	}
	if resolved.SSHPassword == nil || resolved.SSHPassword.Password != fixture.Password.Password {
		t.Fatalf("ssh password mismatch: %#v", resolved.SSHPassword)
	}
	if resolved.SigningCertificate == nil {
		t.Fatal("expected signing certificate")
	}
	if resolved.SigningCertificate.Name != fixture.Certificate.Name {
		t.Fatalf("certificate name mismatch: %q", resolved.SigningCertificate.Name)
	}
	if resolved.SigningCertificate.PrivateKeyPEM == nil || *resolved.SigningCertificate.PrivateKeyPEM != bundle.PrivateKeyPEM {
		t.Fatalf("private key mismatch: %#v", resolved.SigningCertificate.PrivateKeyPEM)
	}
	if resolved.SigningCertificate.PrivateKeyPassphrase == nil || *resolved.SigningCertificate.PrivateKeyPassphrase != bundle.PrivateKeyPassphrase {
		t.Fatalf("private key passphrase mismatch: %#v", resolved.SigningCertificate.PrivateKeyPassphrase)
	}
}

func TestResolveGitProfileRejectsDanglingSecretRef(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "gitprofile-resolution-missing.duckdb")
	store, err := NewKeyStore(dbPath, KeyStoreConfig{
		KEKsB64:          testKEKs(),
		ActiveKEKVersion: "v1",
	})
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	defer store.Close()

	passwordName := "github-work-ssh"
	if err := store.SavePassword(PasswordUpsertInput{
		AgentID:  "agent-a",
		Name:     passwordName,
		Password: "ssh-private-key",
	}); err != nil {
		t.Fatalf("save password: %v", err)
	}

	if err := store.SaveGitProfile(GitProfileUpsertInput{
		AgentID:     "agent-a",
		Name:        "work",
		Platform:    "github",
		GitUsername: "workuser",
		GitEmail:    "work@example.com",
		SSHIdentityRef: &SecretRef{
			RecordType: "password",
			Name:       &passwordName,
		},
	}); err != nil {
		t.Fatalf("save git profile: %v", err)
	}

	deleted, err := store.DeletePassword("agent-a", passwordName, "")
	if err != nil {
		t.Fatalf("delete password: %v", err)
	}
	if !deleted {
		t.Fatal("expected password to be deleted")
	}

	_, err = store.ResolveGitProfile("agent-a", "work", "switcher")
	if err == nil {
		t.Fatal("expected dangling ref error")
	}

	var validationErr *ValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("expected ValidationError, got %T", err)
	}
	if !strings.Contains(err.Error(), "ssh_identity_ref references a missing password record") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveGitProfileMissingProfile(t *testing.T) {
	store := newTestStore(t)
	defer store.Close()

	resolved, err := store.ResolveGitProfile("agent-a", "missing", "switcher")
	if err != nil {
		t.Fatalf("resolve missing git profile: %v", err)
	}
	if resolved != nil {
		t.Fatalf("expected nil resolved profile, got %#v", resolved)
	}
}

func newGitProfileResolutionStore(t *testing.T) (*KeyStore, gitProfileConsumerFixture) {
	t.Helper()

	payload, err := os.ReadFile("testdata/git_profile_consumer_fixture.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	var fixture gitProfileConsumerFixture
	if err := json.Unmarshal(payload, &fixture); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}

	store, err := NewKeyStore(filepath.Join(t.TempDir(), "gitprofile-resolution.duckdb"), KeyStoreConfig{
		KEKsB64:          testKEKs(),
		ActiveKEKVersion: "v1",
	})
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	return store, fixture
}

func seedGitProfileResolutionFixture(store *KeyStore, fixture gitProfileConsumerFixture, bundle testCertificateBundle) error {
	fixture.Authorization.AgentID = fixture.AgentID
	if err := store.SaveAuthorization(fixture.Authorization); err != nil {
		return err
	}

	fixture.Password.AgentID = fixture.AgentID
	if err := store.SavePassword(fixture.Password); err != nil {
		return err
	}

	if err := store.SaveCertificate(CertificateUpsertInput{
		AgentID:              fixture.AgentID,
		Name:                 fixture.Certificate.Name,
		CertificateChainPEM:  bundle.CertificateChainPEM,
		PrivateKeyPEM:        &bundle.PrivateKeyPEM,
		PrivateKeyPassphrase: &bundle.PrivateKeyPassphrase,
	}); err != nil {
		return err
	}

	fixture.Profile.AgentID = fixture.AgentID
	return store.SaveGitProfile(fixture.Profile)
}
