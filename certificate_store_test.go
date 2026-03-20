package squidkeys

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCertificateRoundTrip(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "cert.duckdb")
	store, err := NewKeyStore(dbPath, KeyStoreConfig{
		KEKsB64:          testKEKs(),
		ActiveKEKVersion: "v1",
	})
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	defer store.Close()

	bundle := makeTestCertificateBundle(t)
	err = store.SaveCertificate(CertificateUpsertInput{
		AgentID:              "agent-a",
		Name:                 "mtls-client",
		CertificateChainPEM:  bundle.CertificateChainPEM,
		PrivateKeyPEM:        &bundle.PrivateKeyPEM,
		PrivateKeyPassphrase: &bundle.PrivateKeyPassphrase,
		Metadata:             map[string]any{"env": "prod"},
	})
	if err != nil {
		t.Fatalf("save certificate: %v", err)
	}

	record, err := store.GetCertificate("agent-a", "mtls-client", "")
	if err != nil {
		t.Fatalf("get certificate: %v", err)
	}
	if record == nil {
		t.Fatal("expected certificate record")
	}
	if record.CertificateChainPEM != bundle.CertificateChainPEM {
		t.Fatalf("certificate chain mismatch")
	}
	if record.PrivateKeyPEM == nil || *record.PrivateKeyPEM != bundle.PrivateKeyPEM {
		t.Fatalf("private key mismatch: %#v", record.PrivateKeyPEM)
	}
	if record.PrivateKeyPassphrase == nil || *record.PrivateKeyPassphrase != bundle.PrivateKeyPassphrase {
		t.Fatalf("private key passphrase mismatch: %#v", record.PrivateKeyPassphrase)
	}
	if record.Subject != bundle.Subject {
		t.Fatalf("subject mismatch: %q", record.Subject)
	}
	if record.SubjectCommonName == nil || *record.SubjectCommonName != bundle.SubjectCommonName {
		t.Fatalf("subject CN mismatch: %#v", record.SubjectCommonName)
	}
	if record.Issuer != bundle.Issuer {
		t.Fatalf("issuer mismatch: %q", record.Issuer)
	}
	if record.IssuerCommonName == nil || *record.IssuerCommonName != bundle.IssuerCommonName {
		t.Fatalf("issuer CN mismatch: %#v", record.IssuerCommonName)
	}
	if record.SerialNumber != bundle.SerialNumber {
		t.Fatalf("serial number mismatch: %q", record.SerialNumber)
	}
	if record.FingerprintSHA256 != bundle.FingerprintSHA256 {
		t.Fatalf("fingerprint mismatch: %q", record.FingerprintSHA256)
	}
	if !record.NotBefore.Equal(bundle.NotBefore) {
		t.Fatalf("not_before mismatch: %s", record.NotBefore)
	}
	if !record.NotAfter.Equal(bundle.NotAfter) {
		t.Fatalf("not_after mismatch: %s", record.NotAfter)
	}
	if !equalStrings(record.DNSNames, bundle.DNSNames) {
		t.Fatalf("dns names mismatch: %#v", record.DNSNames)
	}
	if !equalStrings(record.EmailAddresses, bundle.EmailAddresses) {
		t.Fatalf("email addresses mismatch: %#v", record.EmailAddresses)
	}
	if !equalStrings(record.IPAddresses, bundle.IPAddresses) {
		t.Fatalf("ip addresses mismatch: %#v", record.IPAddresses)
	}
	if !equalStrings(record.URIs, bundle.URIs) {
		t.Fatalf("uris mismatch: %#v", record.URIs)
	}
	if !equalStrings(record.KeyUsages, bundle.KeyUsages) {
		t.Fatalf("key usages mismatch: %#v", record.KeyUsages)
	}
	if !equalStrings(record.ExtKeyUsages, bundle.ExtKeyUsages) {
		t.Fatalf("ext key usages mismatch: %#v", record.ExtKeyUsages)
	}
	if record.PublicKeyAlgorithm != bundle.PublicKeyAlgorithm {
		t.Fatalf("public key algorithm mismatch: %q", record.PublicKeyAlgorithm)
	}
	if record.PrivateKeyAlgorithm == nil || *record.PrivateKeyAlgorithm != bundle.PrivateKeyAlgorithm {
		t.Fatalf("private key algorithm mismatch: %#v", record.PrivateKeyAlgorithm)
	}
	if record.SignatureAlgorithm != bundle.SignatureAlgorithm {
		t.Fatalf("signature algorithm mismatch: %q", record.SignatureAlgorithm)
	}
	if record.Metadata["env"] != "prod" {
		t.Fatalf("metadata mismatch: %#v", record.Metadata)
	}
	if record.KEKVersion != "v1" {
		t.Fatalf("kek version mismatch: %q", record.KEKVersion)
	}

	deleted, err := store.DeleteCertificate("agent-a", "mtls-client", "")
	if err != nil {
		t.Fatalf("delete certificate: %v", err)
	}
	if !deleted {
		t.Fatal("expected deleted=true")
	}

	record, err = store.GetCertificate("agent-a", "mtls-client", "")
	if err != nil {
		t.Fatalf("get missing certificate: %v", err)
	}
	if record != nil {
		t.Fatalf("expected missing certificate, got %#v", record)
	}
}

func TestSaveCertificateRejectsMismatchedPrivateKey(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "mismatch.duckdb")
	store, err := NewKeyStore(dbPath, KeyStoreConfig{
		KEKsB64:          testKEKs(),
		ActiveKEKVersion: "v1",
	})
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	defer store.Close()

	leaf := makeTestCertificateBundle(t)
	other := makeTestCertificateBundle(t)
	err = store.SaveCertificate(CertificateUpsertInput{
		AgentID:              "agent-a",
		Name:                 "mtls-client",
		CertificateChainPEM:  leaf.CertificateChainPEM,
		PrivateKeyPEM:        &other.PrivateKeyPEM,
		PrivateKeyPassphrase: &other.PrivateKeyPassphrase,
	})
	if err == nil {
		t.Fatal("expected mismatch error")
	}

	var validationErr *ValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("expected ValidationError, got %T", err)
	}
}

func TestCertificateValuesAreEncryptedAtRest(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "cert-encrypted.duckdb")
	store, err := NewKeyStore(dbPath, KeyStoreConfig{
		KEKsB64:          testKEKs(),
		ActiveKEKVersion: "v1",
	})
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	bundle := makeTestCertificateBundle(t)
	if err := store.SaveCertificate(CertificateUpsertInput{
		AgentID:              "agent-z",
		Name:                 "mtls-client",
		CertificateChainPEM:  bundle.CertificateChainPEM,
		PrivateKeyPEM:        &bundle.PrivateKeyPEM,
		PrivateKeyPassphrase: &bundle.PrivateKeyPassphrase,
	}); err != nil {
		t.Fatalf("save certificate: %v", err)
	}

	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	raw, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatalf("read db file: %v", err)
	}
	if bytes.Contains(raw, []byte("BEGIN CERTIFICATE")) {
		t.Fatal("certificate chain appeared in plaintext at rest")
	}
	if bytes.Contains(raw, []byte("BEGIN RSA PRIVATE KEY")) {
		t.Fatal("private key appeared in plaintext at rest")
	}
	if bytes.Contains(raw, []byte(bundle.PrivateKeyPassphrase)) {
		t.Fatal("private key passphrase appeared in plaintext at rest")
	}
}

func TestCertificateRewrapRecords(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "cert-rewrap.duckdb")
	keys := testKEKs()
	store, err := NewKeyStore(dbPath, KeyStoreConfig{
		KEKsB64:          keys,
		ActiveKEKVersion: "v1",
	})
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	defer store.Close()

	bundle := makeTestCertificateBundle(t)
	if err := store.SaveCertificate(CertificateUpsertInput{
		AgentID:              "agent-r",
		Name:                 "mtls-client",
		CertificateChainPEM:  bundle.CertificateChainPEM,
		PrivateKeyPEM:        &bundle.PrivateKeyPEM,
		PrivateKeyPassphrase: &bundle.PrivateKeyPassphrase,
	}); err != nil {
		t.Fatalf("save certificate: %v", err)
	}

	result, err := store.RewrapAllRecords("v2", "")
	if err != nil {
		t.Fatalf("rewrap: %v", err)
	}
	if result.CertificatesRewrapped != 1 {
		t.Fatalf("expected 1 certificate rewrap, got %d", result.CertificatesRewrapped)
	}

	record, err := store.GetCertificate("agent-r", "mtls-client", "")
	if err != nil {
		t.Fatalf("get certificate: %v", err)
	}
	if record == nil || record.KEKVersion != "v2" {
		t.Fatalf("certificate kek version mismatch: %#v", record)
	}
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
