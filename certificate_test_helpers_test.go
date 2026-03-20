package squidkeys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"
)

type testCertificateBundle struct {
	CertificateChainPEM  string
	PrivateKeyPEM        string
	PrivateKeyPassphrase string
	Subject              string
	SubjectCommonName    string
	Issuer               string
	IssuerCommonName     string
	SerialNumber         string
	FingerprintSHA256    string
	NotBefore            time.Time
	NotAfter             time.Time
	DNSNames             []string
	EmailAddresses       []string
	IPAddresses          []string
	URIs                 []string
	KeyUsages            []string
	ExtKeyUsages         []string
	PublicKeyAlgorithm   string
	PrivateKeyAlgorithm  string
	SignatureAlgorithm   string
}

func makeTestCertificateBundle(t *testing.T) testCertificateBundle {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}

	notBefore := time.Date(2026, 3, 20, 12, 0, 0, 0, time.UTC)
	notAfter := time.Date(2027, 3, 20, 12, 0, 0, 0, time.UTC)
	spiffeURI, err := url.Parse("spiffe://example.internal/agent-a")
	if err != nil {
		t.Fatalf("parse uri: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(0x1234ABCD),
		Subject: pkix.Name{
			CommonName:   "agent.example.internal",
			Organization: []string{"SquidKeys Test"},
		},
		Issuer: pkix.Name{
			CommonName:   "agent.example.internal",
			Organization: []string{"SquidKeys Test"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"agent.example.internal", "localhost"},
		EmailAddresses:        []string{"agent@example.internal"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		URIs:                  []*url.URL{spiffeURI},
		SignatureAlgorithm:    x509.SHA256WithRSA,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	certificatePEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	privateKeyDER := x509.MarshalPKCS1PrivateKey(privateKey)
	passphrase := "hunter2"
	encryptedKeyBlock, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", privateKeyDER, []byte(passphrase), x509.PEMCipherAES256)
	if err != nil {
		t.Fatalf("encrypt private key: %v", err)
	}
	privateKeyPEM := string(pem.EncodeToMemory(encryptedKeyBlock))

	fingerprint := sha256.Sum256(certDER)
	return testCertificateBundle{
		CertificateChainPEM:  certificatePEM,
		PrivateKeyPEM:        privateKeyPEM,
		PrivateKeyPassphrase: passphrase,
		Subject:              template.Subject.String(),
		SubjectCommonName:    template.Subject.CommonName,
		Issuer:               template.Issuer.String(),
		IssuerCommonName:     template.Issuer.CommonName,
		SerialNumber:         "1234ABCD",
		FingerprintSHA256:    hex.EncodeToString(fingerprint[:]),
		NotBefore:            notBefore,
		NotAfter:             notAfter,
		DNSNames:             []string{"agent.example.internal", "localhost"},
		EmailAddresses:       []string{"agent@example.internal"},
		IPAddresses:          []string{"127.0.0.1"},
		URIs:                 []string{"spiffe://example.internal/agent-a"},
		KeyUsages:            []string{"digital_signature", "key_encipherment"},
		ExtKeyUsages:         []string{"client_auth", "server_auth"},
		PublicKeyAlgorithm:   "RSA",
		PrivateKeyAlgorithm:  "RSA",
		SignatureAlgorithm:   "SHA256-RSA",
	}
}
