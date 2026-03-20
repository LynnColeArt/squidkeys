package squidkeys

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

func (s *KeyStore) SaveCertificate(input CertificateUpsertInput) error {
	if err := validateNonEmpty(input.AgentID, "agent_id"); err != nil {
		return err
	}
	if err := validateNonEmpty(input.Name, "name"); err != nil {
		return err
	}
	if err := validateNonEmpty(input.CertificateChainPEM, "certificate_chain_pem"); err != nil {
		return err
	}

	parsed, err := parseCertificateMaterial(input)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	activeVersion := s.activeKEKVersion
	dek, err := randomBytes(32)
	if err != nil {
		return err
	}

	wrappedDEKNonce, wrappedDEK, err := s.wrapDEK(
		dek,
		activeVersion,
		"crt",
		input.AgentID,
		input.Name,
	)
	if err != nil {
		return err
	}

	chainNonce, chainCiphertext, err := encryptWithDEK(
		dek,
		input.CertificateChainPEM,
		aad("crt", input.AgentID, input.Name, "certificate_chain"),
	)
	if err != nil {
		return err
	}

	var privateKeyNonce []byte
	var privateKeyCiphertext []byte
	if input.PrivateKeyPEM != nil {
		privateKeyNonce, privateKeyCiphertext, err = encryptWithDEK(
			dek,
			*input.PrivateKeyPEM,
			aad("crt", input.AgentID, input.Name, "private_key"),
		)
		if err != nil {
			return err
		}
	}

	var privateKeyPassphraseNonce []byte
	var privateKeyPassphraseCiphertext []byte
	if input.PrivateKeyPassphrase != nil {
		privateKeyPassphraseNonce, privateKeyPassphraseCiphertext, err = encryptWithDEK(
			dek,
			*input.PrivateKeyPassphrase,
			aad("crt", input.AgentID, input.Name, "private_key_passphrase"),
		)
		if err != nil {
			return err
		}
	}

	dnsNamesJSON, err := json.Marshal(defaultStringSlice(parsed.DNSNames))
	if err != nil {
		return fmt.Errorf("marshal dns_names: %w", err)
	}
	emailAddressesJSON, err := json.Marshal(defaultStringSlice(parsed.EmailAddresses))
	if err != nil {
		return fmt.Errorf("marshal email_addresses: %w", err)
	}
	ipAddressesJSON, err := json.Marshal(defaultStringSlice(parsed.IPAddresses))
	if err != nil {
		return fmt.Errorf("marshal ip_addresses: %w", err)
	}
	urisJSON, err := json.Marshal(defaultStringSlice(parsed.URIs))
	if err != nil {
		return fmt.Errorf("marshal uris: %w", err)
	}
	keyUsagesJSON, err := json.Marshal(defaultStringSlice(parsed.KeyUsages))
	if err != nil {
		return fmt.Errorf("marshal key_usages: %w", err)
	}
	extKeyUsagesJSON, err := json.Marshal(defaultStringSlice(parsed.ExtKeyUsages))
	if err != nil {
		return fmt.Errorf("marshal ext_key_usages: %w", err)
	}
	metadataJSON, err := json.Marshal(defaultMetadata(input.Metadata))
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}

	now := time.Now().Unix()
	_, err = s.db.ExecContext(
		context.Background(),
		`
		INSERT INTO certificate_secrets (
			agent_id,
			name,
			subject,
			subject_common_name,
			issuer,
			issuer_common_name,
			serial_number,
			fingerprint_sha256,
			not_before,
			not_after,
			dns_names,
			email_addresses,
			ip_addresses,
			uris,
			key_usages,
			ext_key_usages,
			is_ca,
			public_key_algorithm,
			private_key_algorithm,
			signature_algorithm,
			metadata,
			wrapped_dek_nonce,
			wrapped_dek,
			certificate_chain_nonce,
			certificate_chain_ciphertext,
			private_key_nonce,
			private_key_ciphertext,
			private_key_passphrase_nonce,
			private_key_passphrase_ciphertext,
			kek_version,
			created_at,
			updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (agent_id, name) DO UPDATE SET
			subject = excluded.subject,
			subject_common_name = excluded.subject_common_name,
			issuer = excluded.issuer,
			issuer_common_name = excluded.issuer_common_name,
			serial_number = excluded.serial_number,
			fingerprint_sha256 = excluded.fingerprint_sha256,
			not_before = excluded.not_before,
			not_after = excluded.not_after,
			dns_names = excluded.dns_names,
			email_addresses = excluded.email_addresses,
			ip_addresses = excluded.ip_addresses,
			uris = excluded.uris,
			key_usages = excluded.key_usages,
			ext_key_usages = excluded.ext_key_usages,
			is_ca = excluded.is_ca,
			public_key_algorithm = excluded.public_key_algorithm,
			private_key_algorithm = excluded.private_key_algorithm,
			signature_algorithm = excluded.signature_algorithm,
			metadata = excluded.metadata,
			wrapped_dek_nonce = excluded.wrapped_dek_nonce,
			wrapped_dek = excluded.wrapped_dek,
			certificate_chain_nonce = excluded.certificate_chain_nonce,
			certificate_chain_ciphertext = excluded.certificate_chain_ciphertext,
			private_key_nonce = excluded.private_key_nonce,
			private_key_ciphertext = excluded.private_key_ciphertext,
			private_key_passphrase_nonce = excluded.private_key_passphrase_nonce,
			private_key_passphrase_ciphertext = excluded.private_key_passphrase_ciphertext,
			kek_version = excluded.kek_version,
			updated_at = excluded.updated_at
		`,
		input.AgentID,
		input.Name,
		parsed.Subject,
		nullIfBlank(parsed.SubjectCommonName),
		parsed.Issuer,
		nullIfBlank(parsed.IssuerCommonName),
		parsed.SerialNumber,
		parsed.FingerprintSHA256,
		parsed.NotBefore.Unix(),
		parsed.NotAfter.Unix(),
		string(dnsNamesJSON),
		string(emailAddressesJSON),
		string(ipAddressesJSON),
		string(urisJSON),
		string(keyUsagesJSON),
		string(extKeyUsagesJSON),
		parsed.IsCA,
		parsed.PublicKeyAlgorithm,
		derefString(parsed.PrivateKeyAlgorithm),
		parsed.SignatureAlgorithm,
		string(metadataJSON),
		wrappedDEKNonce,
		wrappedDEK,
		chainNonce,
		chainCiphertext,
		nilIfEmpty(privateKeyNonce),
		nilIfEmpty(privateKeyCiphertext),
		nilIfEmpty(privateKeyPassphraseNonce),
		nilIfEmpty(privateKeyPassphraseCiphertext),
		activeVersion,
		now,
		now,
	)
	if err != nil {
		auditErr := s.auditLocked(auditEvent{
			Operation:  "save",
			RecordType: "certificate",
			Actor:      defaultActor(input.Actor, "system"),
			Status:     "error",
			AgentID:    input.AgentID,
			Name:       input.Name,
			Error:      err.Error(),
		})
		if auditErr != nil {
			return auditErr
		}
		return err
	}

	return s.auditLocked(auditEvent{
		Operation:  "save",
		RecordType: "certificate",
		Actor:      defaultActor(input.Actor, "system"),
		Status:     "ok",
		AgentID:    input.AgentID,
		Name:       input.Name,
	})
}

func (s *KeyStore) GetCertificate(agentID, name, actor string) (*CertificateRecord, error) {
	if err := validateNonEmpty(agentID, "agent_id"); err != nil {
		return nil, err
	}
	if err := validateNonEmpty(name, "name"); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var (
		subject                        string
		subjectCommonName              sql.NullString
		issuer                         string
		issuerCommonName               sql.NullString
		serialNumber                   string
		fingerprintSHA256              string
		notBefore                      int64
		notAfter                       int64
		dnsNamesJSON                   string
		emailAddressesJSON             string
		ipAddressesJSON                string
		urisJSON                       string
		keyUsagesJSON                  string
		extKeyUsagesJSON               string
		isCA                           bool
		publicKeyAlgorithm             string
		privateKeyAlgorithm            sql.NullString
		signatureAlgorithm             string
		metadataJSON                   string
		wrappedDEKNonce                []byte
		wrappedDEK                     []byte
		certificateChainNonce          []byte
		certificateChainCiphertext     []byte
		privateKeyNonce                []byte
		privateKeyCiphertext           []byte
		privateKeyPassphraseNonce      []byte
		privateKeyPassphraseCiphertext []byte
		kekVersion                     string
	)

	err := s.db.QueryRowContext(
		context.Background(),
		`
		SELECT
			subject,
			subject_common_name,
			issuer,
			issuer_common_name,
			serial_number,
			fingerprint_sha256,
			not_before,
			not_after,
			dns_names,
			email_addresses,
			ip_addresses,
			uris,
			key_usages,
			ext_key_usages,
			is_ca,
			public_key_algorithm,
			private_key_algorithm,
			signature_algorithm,
			metadata,
			wrapped_dek_nonce,
			wrapped_dek,
			certificate_chain_nonce,
			certificate_chain_ciphertext,
			private_key_nonce,
			private_key_ciphertext,
			private_key_passphrase_nonce,
			private_key_passphrase_ciphertext,
			kek_version
		FROM certificate_secrets
		WHERE agent_id = ? AND name = ?
		`,
		agentID,
		name,
	).Scan(
		&subject,
		&subjectCommonName,
		&issuer,
		&issuerCommonName,
		&serialNumber,
		&fingerprintSHA256,
		&notBefore,
		&notAfter,
		&dnsNamesJSON,
		&emailAddressesJSON,
		&ipAddressesJSON,
		&urisJSON,
		&keyUsagesJSON,
		&extKeyUsagesJSON,
		&isCA,
		&publicKeyAlgorithm,
		&privateKeyAlgorithm,
		&signatureAlgorithm,
		&metadataJSON,
		&wrappedDEKNonce,
		&wrappedDEK,
		&certificateChainNonce,
		&certificateChainCiphertext,
		&privateKeyNonce,
		&privateKeyCiphertext,
		&privateKeyPassphraseNonce,
		&privateKeyPassphraseCiphertext,
		&kekVersion,
	)
	if err == sql.ErrNoRows {
		if auditErr := s.auditLocked(auditEvent{
			Operation:  "get",
			RecordType: "certificate",
			Actor:      defaultActor(actor, "system"),
			Status:     "miss",
			AgentID:    agentID,
			Name:       name,
		}); auditErr != nil {
			return nil, auditErr
		}
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	dek, err := s.unwrapDEK(
		wrappedDEKNonce,
		wrappedDEK,
		kekVersion,
		"crt",
		agentID,
		name,
	)
	if err != nil {
		if auditErr := s.auditLocked(auditEvent{
			Operation:  "get",
			RecordType: "certificate",
			Actor:      defaultActor(actor, "system"),
			Status:     "error",
			AgentID:    agentID,
			Name:       name,
			Error:      err.Error(),
		}); auditErr != nil {
			return nil, auditErr
		}
		return nil, err
	}

	certificateChainPEM, err := decryptWithDEK(
		dek,
		certificateChainNonce,
		certificateChainCiphertext,
		aad("crt", agentID, name, "certificate_chain"),
	)
	if err != nil {
		if auditErr := s.auditLocked(auditEvent{
			Operation:  "get",
			RecordType: "certificate",
			Actor:      defaultActor(actor, "system"),
			Status:     "error",
			AgentID:    agentID,
			Name:       name,
			Error:      err.Error(),
		}); auditErr != nil {
			return nil, auditErr
		}
		return nil, err
	}

	var privateKeyPEM *string
	if len(privateKeyNonce) > 0 && len(privateKeyCiphertext) > 0 {
		value, err := decryptWithDEK(
			dek,
			privateKeyNonce,
			privateKeyCiphertext,
			aad("crt", agentID, name, "private_key"),
		)
		if err != nil {
			if auditErr := s.auditLocked(auditEvent{
				Operation:  "get",
				RecordType: "certificate",
				Actor:      defaultActor(actor, "system"),
				Status:     "error",
				AgentID:    agentID,
				Name:       name,
				Error:      err.Error(),
			}); auditErr != nil {
				return nil, auditErr
			}
			return nil, err
		}
		privateKeyPEM = &value
	}

	var privateKeyPassphrase *string
	if len(privateKeyPassphraseNonce) > 0 && len(privateKeyPassphraseCiphertext) > 0 {
		value, err := decryptWithDEK(
			dek,
			privateKeyPassphraseNonce,
			privateKeyPassphraseCiphertext,
			aad("crt", agentID, name, "private_key_passphrase"),
		)
		if err != nil {
			if auditErr := s.auditLocked(auditEvent{
				Operation:  "get",
				RecordType: "certificate",
				Actor:      defaultActor(actor, "system"),
				Status:     "error",
				AgentID:    agentID,
				Name:       name,
				Error:      err.Error(),
			}); auditErr != nil {
				return nil, auditErr
			}
			return nil, err
		}
		privateKeyPassphrase = &value
	}

	dnsNames, err := decodeStringSliceJSON(dnsNamesJSON)
	if err != nil {
		return nil, fmt.Errorf("unmarshal dns_names: %w", err)
	}
	emailAddresses, err := decodeStringSliceJSON(emailAddressesJSON)
	if err != nil {
		return nil, fmt.Errorf("unmarshal email_addresses: %w", err)
	}
	ipAddresses, err := decodeStringSliceJSON(ipAddressesJSON)
	if err != nil {
		return nil, fmt.Errorf("unmarshal ip_addresses: %w", err)
	}
	uris, err := decodeStringSliceJSON(urisJSON)
	if err != nil {
		return nil, fmt.Errorf("unmarshal uris: %w", err)
	}
	keyUsages, err := decodeStringSliceJSON(keyUsagesJSON)
	if err != nil {
		return nil, fmt.Errorf("unmarshal key_usages: %w", err)
	}
	extKeyUsages, err := decodeStringSliceJSON(extKeyUsagesJSON)
	if err != nil {
		return nil, fmt.Errorf("unmarshal ext_key_usages: %w", err)
	}

	var metadata map[string]any
	if err := json.Unmarshal([]byte(metadataJSON), &metadata); err != nil {
		return nil, fmt.Errorf("unmarshal metadata: %w", err)
	}
	if metadata == nil {
		metadata = map[string]any{}
	}

	record := &CertificateRecord{
		AgentID:              agentID,
		Name:                 name,
		CertificateChainPEM:  certificateChainPEM,
		PrivateKeyPEM:        privateKeyPEM,
		PrivateKeyPassphrase: privateKeyPassphrase,
		Subject:              subject,
		SubjectCommonName:    nullStringPtr(subjectCommonName),
		Issuer:               issuer,
		IssuerCommonName:     nullStringPtr(issuerCommonName),
		SerialNumber:         serialNumber,
		FingerprintSHA256:    fingerprintSHA256,
		NotBefore:            time.Unix(notBefore, 0).UTC(),
		NotAfter:             time.Unix(notAfter, 0).UTC(),
		DNSNames:             dnsNames,
		EmailAddresses:       emailAddresses,
		IPAddresses:          ipAddresses,
		URIs:                 uris,
		KeyUsages:            keyUsages,
		ExtKeyUsages:         extKeyUsages,
		IsCA:                 isCA,
		PublicKeyAlgorithm:   publicKeyAlgorithm,
		PrivateKeyAlgorithm:  nullStringPtr(privateKeyAlgorithm),
		SignatureAlgorithm:   signatureAlgorithm,
		Metadata:             metadata,
		KEKVersion:           kekVersion,
	}

	if err := s.auditLocked(auditEvent{
		Operation:  "get",
		RecordType: "certificate",
		Actor:      defaultActor(actor, "system"),
		Status:     "ok",
		AgentID:    agentID,
		Name:       name,
	}); err != nil {
		return nil, err
	}

	return record, nil
}

func (s *KeyStore) DeleteCertificate(agentID, name, actor string) (bool, error) {
	if err := validateNonEmpty(agentID, "agent_id"); err != nil {
		return false, err
	}
	if err := validateNonEmpty(name, "name"); err != nil {
		return false, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	res, err := s.db.ExecContext(
		context.Background(),
		`
		DELETE FROM certificate_secrets
		WHERE agent_id = ? AND name = ?
		`,
		agentID,
		name,
	)
	if err != nil {
		return false, err
	}

	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	deleted := rowsAffected > 0

	if err := s.auditLocked(auditEvent{
		Operation:  "delete",
		RecordType: "certificate",
		Actor:      defaultActor(actor, "system"),
		Status:     ternaryStatus(deleted),
		AgentID:    agentID,
		Name:       name,
	}); err != nil {
		return false, err
	}

	return deleted, nil
}

type parsedCertificateRecord struct {
	Subject             string
	SubjectCommonName   string
	Issuer              string
	IssuerCommonName    string
	SerialNumber        string
	FingerprintSHA256   string
	NotBefore           time.Time
	NotAfter            time.Time
	DNSNames            []string
	EmailAddresses      []string
	IPAddresses         []string
	URIs                []string
	KeyUsages           []string
	ExtKeyUsages        []string
	IsCA                bool
	PublicKeyAlgorithm  string
	PrivateKeyAlgorithm *string
	SignatureAlgorithm  string
}

func parseCertificateMaterial(input CertificateUpsertInput) (parsedCertificateRecord, error) {
	certs, err := parseCertificateChainPEM(input.CertificateChainPEM)
	if err != nil {
		return parsedCertificateRecord{}, err
	}

	signer, privateKeyAlgorithm, err := parsePrivateKeyPEM(input.PrivateKeyPEM, input.PrivateKeyPassphrase)
	if err != nil {
		return parsedCertificateRecord{}, err
	}

	leaf, err := selectLeafCertificate(certs, signer)
	if err != nil {
		return parsedCertificateRecord{}, err
	}

	if signer != nil && !publicKeysEqual(leaf.PublicKey, signer.Public()) {
		return parsedCertificateRecord{}, &ValidationError{Message: "private_key_pem does not match the certificate public key"}
	}

	fingerprint := sha256.Sum256(leaf.Raw)
	return parsedCertificateRecord{
		Subject:             leaf.Subject.String(),
		SubjectCommonName:   leaf.Subject.CommonName,
		Issuer:              leaf.Issuer.String(),
		IssuerCommonName:    leaf.Issuer.CommonName,
		SerialNumber:        strings.ToUpper(leaf.SerialNumber.Text(16)),
		FingerprintSHA256:   hex.EncodeToString(fingerprint[:]),
		NotBefore:           leaf.NotBefore.UTC(),
		NotAfter:            leaf.NotAfter.UTC(),
		DNSNames:            append([]string(nil), leaf.DNSNames...),
		EmailAddresses:      append([]string(nil), leaf.EmailAddresses...),
		IPAddresses:         stringifyIPs(leaf.IPAddresses),
		URIs:                stringifyURIs(leaf.URIs),
		KeyUsages:           certificateKeyUsages(leaf.KeyUsage),
		ExtKeyUsages:        certificateExtKeyUsages(leaf.ExtKeyUsage),
		IsCA:                leaf.IsCA,
		PublicKeyAlgorithm:  leaf.PublicKeyAlgorithm.String(),
		PrivateKeyAlgorithm: privateKeyAlgorithm,
		SignatureAlgorithm:  leaf.SignatureAlgorithm.String(),
	}, nil
}

func parseCertificateChainPEM(value string) ([]*x509.Certificate, error) {
	rest := []byte(strings.TrimSpace(value))
	if len(rest) == 0 {
		return nil, &ValidationError{Message: "certificate_chain_pem must be a non-empty string"}
	}

	var certs []*x509.Certificate
	for len(rest) > 0 {
		block, remaining := pem.Decode(rest)
		if block == nil {
			return nil, &ValidationError{Message: "certificate_chain_pem must contain PEM-encoded CERTIFICATE blocks"}
		}
		if block.Type != "CERTIFICATE" {
			return nil, &ValidationError{Message: fmt.Sprintf("certificate_chain_pem contains unsupported PEM block %q", block.Type)}
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, &ValidationError{Message: fmt.Sprintf("certificate_chain_pem contains an invalid certificate: %v", err)}
		}
		certs = append(certs, cert)
		rest = []byte(strings.TrimSpace(string(remaining)))
	}

	if len(certs) == 0 {
		return nil, &ValidationError{Message: "certificate_chain_pem must contain at least one certificate"}
	}

	return certs, nil
}

func parsePrivateKeyPEM(value, passphrase *string) (crypto.Signer, *string, error) {
	if value == nil {
		if passphrase != nil {
			return nil, nil, &ValidationError{Message: "private_key_passphrase requires private_key_pem"}
		}
		return nil, nil, nil
	}
	if err := validateNonEmpty(*value, "private_key_pem"); err != nil {
		return nil, nil, err
	}

	block, rest := pem.Decode([]byte(strings.TrimSpace(*value)))
	if block == nil {
		return nil, nil, &ValidationError{Message: "private_key_pem must contain a PEM-encoded private key"}
	}
	if len(strings.TrimSpace(string(rest))) > 0 {
		return nil, nil, &ValidationError{Message: "private_key_pem must contain exactly one PEM block"}
	}

	if block.Type == "ENCRYPTED PRIVATE KEY" {
		return nil, nil, &ValidationError{Message: "private_key_pem uses unsupported PKCS#8 encryption; provide an unencrypted PEM or legacy PEM-encrypted key"}
	}

	der := block.Bytes
	if x509.IsEncryptedPEMBlock(block) {
		if passphrase == nil {
			return nil, nil, &ValidationError{Message: "private_key_pem is encrypted and requires private_key_passphrase"}
		}
		decryptedDER, err := x509.DecryptPEMBlock(block, []byte(*passphrase))
		if err != nil {
			return nil, nil, &ValidationError{Message: fmt.Sprintf("private_key_passphrase could not decrypt private_key_pem: %v", err)}
		}
		der = decryptedDER
	} else if passphrase != nil {
		return nil, nil, &ValidationError{Message: "private_key_passphrase was provided but private_key_pem is not encrypted"}
	}

	signer, algorithm, err := parsePrivateKeyDER(der)
	if err != nil {
		return nil, nil, &ValidationError{Message: fmt.Sprintf("private_key_pem is not a supported private key: %v", err)}
	}
	return signer, &algorithm, nil
}

func parsePrivateKeyDER(der []byte) (crypto.Signer, string, error) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return signerWithAlgorithm(key)
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, "RSA", nil
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, "ECDSA", nil
	}
	return nil, "", fmt.Errorf("expected RSA, ECDSA, Ed25519, or PKCS#8 private key")
}

func signerWithAlgorithm(value any) (crypto.Signer, string, error) {
	switch key := value.(type) {
	case *rsa.PrivateKey:
		return key, "RSA", nil
	case *ecdsa.PrivateKey:
		return key, "ECDSA", nil
	case ed25519.PrivateKey:
		return key, "Ed25519", nil
	default:
		return nil, "", fmt.Errorf("unsupported private key type %T", value)
	}
}

func selectLeafCertificate(certs []*x509.Certificate, signer crypto.Signer) (*x509.Certificate, error) {
	if len(certs) == 0 {
		return nil, &ValidationError{Message: "certificate_chain_pem must contain at least one certificate"}
	}
	if signer == nil {
		return certs[0], nil
	}
	for _, cert := range certs {
		if publicKeysEqual(cert.PublicKey, signer.Public()) {
			return cert, nil
		}
	}
	return nil, &ValidationError{Message: "private_key_pem does not match any certificate in certificate_chain_pem"}
}

func publicKeysEqual(a, b any) bool {
	aDER, err := x509.MarshalPKIXPublicKey(a)
	if err != nil {
		return false
	}
	bDER, err := x509.MarshalPKIXPublicKey(b)
	if err != nil {
		return false
	}
	return string(aDER) == string(bDER)
}

func stringifyIPs(values []net.IP) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value.String())
	}
	return result
}

func stringifyURIs(values []*url.URL) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == nil {
			continue
		}
		result = append(result, value.String())
	}
	return result
}

func certificateKeyUsages(usage x509.KeyUsage) []string {
	var values []string
	flags := []struct {
		mask  x509.KeyUsage
		label string
	}{
		{x509.KeyUsageDigitalSignature, "digital_signature"},
		{x509.KeyUsageContentCommitment, "content_commitment"},
		{x509.KeyUsageKeyEncipherment, "key_encipherment"},
		{x509.KeyUsageDataEncipherment, "data_encipherment"},
		{x509.KeyUsageKeyAgreement, "key_agreement"},
		{x509.KeyUsageCertSign, "cert_sign"},
		{x509.KeyUsageCRLSign, "crl_sign"},
		{x509.KeyUsageEncipherOnly, "encipher_only"},
		{x509.KeyUsageDecipherOnly, "decipher_only"},
	}
	for _, flag := range flags {
		if usage&flag.mask != 0 {
			values = append(values, flag.label)
		}
	}
	return values
}

func certificateExtKeyUsages(values []x509.ExtKeyUsage) []string {
	if len(values) == 0 {
		return []string{}
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		switch value {
		case x509.ExtKeyUsageAny:
			result = append(result, "any")
		case x509.ExtKeyUsageServerAuth:
			result = append(result, "server_auth")
		case x509.ExtKeyUsageClientAuth:
			result = append(result, "client_auth")
		case x509.ExtKeyUsageCodeSigning:
			result = append(result, "code_signing")
		case x509.ExtKeyUsageEmailProtection:
			result = append(result, "email_protection")
		case x509.ExtKeyUsageIPSECEndSystem:
			result = append(result, "ipsec_end_system")
		case x509.ExtKeyUsageIPSECTunnel:
			result = append(result, "ipsec_tunnel")
		case x509.ExtKeyUsageIPSECUser:
			result = append(result, "ipsec_user")
		case x509.ExtKeyUsageTimeStamping:
			result = append(result, "time_stamping")
		case x509.ExtKeyUsageOCSPSigning:
			result = append(result, "ocsp_signing")
		case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
			result = append(result, "microsoft_server_gated_crypto")
		case x509.ExtKeyUsageNetscapeServerGatedCrypto:
			result = append(result, "netscape_server_gated_crypto")
		case x509.ExtKeyUsageMicrosoftCommercialCodeSigning:
			result = append(result, "microsoft_commercial_code_signing")
		case x509.ExtKeyUsageMicrosoftKernelCodeSigning:
			result = append(result, "microsoft_kernel_code_signing")
		default:
			result = append(result, fmt.Sprintf("unknown_%d", value))
		}
	}
	return result
}

func decodeStringSliceJSON(value string) ([]string, error) {
	var values []string
	if err := json.Unmarshal([]byte(value), &values); err != nil {
		return nil, err
	}
	if values == nil {
		return []string{}, nil
	}
	return values, nil
}
