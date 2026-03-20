package squidkeys

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestGitProfileRoundTrip(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "gitprofiles.duckdb")
	store, err := NewKeyStore(dbPath, KeyStoreConfig{
		KEKsB64:          testKEKs(),
		ActiveKEKVersion: "v1",
	})
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	defer store.Close()

	bundle := makeTestCertificateBundle(t)
	accountID := "user-123"
	sshPrivateKey := "-----BEGIN OPENSSH PRIVATE KEY-----\nlocal-test-key\n-----END OPENSSH PRIVATE KEY-----"

	if err := store.SaveAuthorization(AuthorizationUpsertInput{
		AgentID:     "agent-a",
		Provider:    "github",
		AccountID:   &accountID,
		AccessToken: "oauth-token",
	}); err != nil {
		t.Fatalf("save authorization: %v", err)
	}

	if err := store.SavePassword(PasswordUpsertInput{
		AgentID:  "agent-a",
		Name:     "github-work-ssh",
		Password: sshPrivateKey,
	}); err != nil {
		t.Fatalf("save password: %v", err)
	}

	if err := store.SaveCertificate(CertificateUpsertInput{
		AgentID:              "agent-a",
		Name:                 "github-work-signing",
		CertificateChainPEM:  bundle.CertificateChainPEM,
		PrivateKeyPEM:        &bundle.PrivateKeyPEM,
		PrivateKeyPassphrase: &bundle.PrivateKeyPassphrase,
	}); err != nil {
		t.Fatalf("save certificate: %v", err)
	}

	provider := "github"
	passwordName := "github-work-ssh"
	certName := "github-work-signing"
	transport := "ssh"
	signingFormat := "x509"
	err = store.SaveGitProfile(GitProfileUpsertInput{
		AgentID:            "agent-a",
		Name:               "work",
		Platform:           "GitHub",
		GitUsername:        "workuser",
		GitEmail:           "work@example.com",
		PreferredTransport: &transport,
		HTTPSCredentialRef: &SecretRef{
			RecordType: "authorization",
			Provider:   &provider,
			AccountID:  &accountID,
		},
		SSHIdentityRef: &SecretRef{
			RecordType: "password",
			Name:       &passwordName,
		},
		SigningIdentityRef: &SecretRef{
			RecordType: "certificate",
			Name:       &certName,
		},
		SigningFormat: &signingFormat,
		RepoMatchers:  []string{"github.com/work/*", "github.com/org/*"},
		Metadata:      map[string]any{"owner": "ops"},
	})
	if err != nil {
		t.Fatalf("save git profile: %v", err)
	}

	record, err := store.GetGitProfile("agent-a", "work", "")
	if err != nil {
		t.Fatalf("get git profile: %v", err)
	}
	if record == nil {
		t.Fatal("expected git profile record")
	}
	if record.Platform != "github" {
		t.Fatalf("platform mismatch: %q", record.Platform)
	}
	if record.GitUsername != "workuser" {
		t.Fatalf("git_username mismatch: %q", record.GitUsername)
	}
	if record.GitEmail != "work@example.com" {
		t.Fatalf("git_email mismatch: %q", record.GitEmail)
	}
	if record.PreferredTransport == nil || *record.PreferredTransport != "ssh" {
		t.Fatalf("preferred_transport mismatch: %#v", record.PreferredTransport)
	}
	if record.SigningFormat == nil || *record.SigningFormat != "x509" {
		t.Fatalf("signing_format mismatch: %#v", record.SigningFormat)
	}
	if !equalStrings(record.RepoMatchers, []string{"github.com/work/*", "github.com/org/*"}) {
		t.Fatalf("repo_matchers mismatch: %#v", record.RepoMatchers)
	}
	if !equalSecretRefs(record.HTTPSCredentialRef, &SecretRef{
		RecordType: "authorization",
		Provider:   &provider,
		AccountID:  &accountID,
	}) {
		t.Fatalf("https credential ref mismatch: %#v", record.HTTPSCredentialRef)
	}
	if !equalSecretRefs(record.SSHIdentityRef, &SecretRef{
		RecordType: "password",
		Name:       &passwordName,
	}) {
		t.Fatalf("ssh identity ref mismatch: %#v", record.SSHIdentityRef)
	}
	if !equalSecretRefs(record.SigningIdentityRef, &SecretRef{
		RecordType: "certificate",
		Name:       &certName,
	}) {
		t.Fatalf("signing identity ref mismatch: %#v", record.SigningIdentityRef)
	}
	if record.Metadata["owner"] != "ops" {
		t.Fatalf("metadata mismatch: %#v", record.Metadata)
	}

	list, err := store.ListGitProfiles(strPtr("agent-a"), strPtr("github"), "")
	if err != nil {
		t.Fatalf("list git profiles: %v", err)
	}
	if len(list) != 1 || list[0].Name != "work" {
		t.Fatalf("unexpected list result: %#v", list)
	}

	deleted, err := store.DeleteGitProfile("agent-a", "work", "")
	if err != nil {
		t.Fatalf("delete git profile: %v", err)
	}
	if !deleted {
		t.Fatal("expected deleted=true")
	}
}

func TestSaveGitProfileRejectsMissingSecretRefs(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "missing-ref.duckdb")
	store, err := NewKeyStore(dbPath, KeyStoreConfig{
		KEKsB64:          testKEKs(),
		ActiveKEKVersion: "v1",
	})
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	defer store.Close()

	passwordName := "missing"
	err = store.SaveGitProfile(GitProfileUpsertInput{
		AgentID:     "agent-a",
		Name:        "work",
		Platform:    "github",
		GitUsername: "workuser",
		GitEmail:    "work@example.com",
		SSHIdentityRef: &SecretRef{
			RecordType: "password",
			Name:       &passwordName,
		},
	})
	if err == nil {
		t.Fatal("expected missing ref validation error")
	}

	var validationErr *ValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("expected ValidationError, got %T", err)
	}
}

func equalSecretRefs(got, want *SecretRef) bool {
	if got == nil || want == nil {
		return got == want
	}
	if got.RecordType != want.RecordType {
		return false
	}
	return stringPtrEqual(got.Name, want.Name) &&
		stringPtrEqual(got.Provider, want.Provider) &&
		stringPtrEqual(got.AccountID, want.AccountID)
}

func stringPtrEqual(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func strPtr(value string) *string {
	return &value
}
