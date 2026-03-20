package squidkeys

import "time"

type AuthorizationRecord struct {
	AgentID      string         `json:"agent_id"`
	Provider     string         `json:"provider"`
	AccountID    *string        `json:"account_id"`
	Scopes       []string       `json:"scopes"`
	AccessToken  string         `json:"access_token"`
	RefreshToken *string        `json:"refresh_token"`
	TokenType    *string        `json:"token_type"`
	ExpiresAt    *time.Time     `json:"expires_at"`
	Metadata     map[string]any `json:"metadata"`
	KEKVersion   string         `json:"kek_version"`
}

type PasswordRecord struct {
	AgentID    string         `json:"agent_id"`
	Name       string         `json:"name"`
	Username   *string        `json:"username"`
	Password   string         `json:"password"`
	URL        *string        `json:"url"`
	Metadata   map[string]any `json:"metadata"`
	KEKVersion string         `json:"kek_version"`
}

type CertificateRecord struct {
	AgentID              string         `json:"agent_id"`
	Name                 string         `json:"name"`
	CertificateChainPEM  string         `json:"certificate_chain_pem"`
	PrivateKeyPEM        *string        `json:"private_key_pem"`
	PrivateKeyPassphrase *string        `json:"private_key_passphrase"`
	Subject              string         `json:"subject"`
	SubjectCommonName    *string        `json:"subject_common_name"`
	Issuer               string         `json:"issuer"`
	IssuerCommonName     *string        `json:"issuer_common_name"`
	SerialNumber         string         `json:"serial_number"`
	FingerprintSHA256    string         `json:"fingerprint_sha256"`
	NotBefore            time.Time      `json:"not_before"`
	NotAfter             time.Time      `json:"not_after"`
	DNSNames             []string       `json:"dns_names"`
	EmailAddresses       []string       `json:"email_addresses"`
	IPAddresses          []string       `json:"ip_addresses"`
	URIs                 []string       `json:"uris"`
	KeyUsages            []string       `json:"key_usages"`
	ExtKeyUsages         []string       `json:"ext_key_usages"`
	IsCA                 bool           `json:"is_ca"`
	PublicKeyAlgorithm   string         `json:"public_key_algorithm"`
	PrivateKeyAlgorithm  *string        `json:"private_key_algorithm"`
	SignatureAlgorithm   string         `json:"signature_algorithm"`
	Metadata             map[string]any `json:"metadata"`
	KEKVersion           string         `json:"kek_version"`
}

type SecretRef struct {
	RecordType string  `json:"record_type"`
	Name       *string `json:"name,omitempty"`
	Provider   *string `json:"provider,omitempty"`
	AccountID  *string `json:"account_id,omitempty"`
}

type GitProfileRecord struct {
	AgentID            string         `json:"agent_id"`
	Name               string         `json:"name"`
	Platform           string         `json:"platform"`
	Host               *string        `json:"host"`
	GitUsername        string         `json:"git_username"`
	GitEmail           string         `json:"git_email"`
	PreferredTransport *string        `json:"preferred_transport"`
	HTTPSCredentialRef *SecretRef     `json:"https_credential_ref"`
	SSHIdentityRef     *SecretRef     `json:"ssh_identity_ref"`
	SigningIdentityRef *SecretRef     `json:"signing_identity_ref"`
	SigningFormat      *string        `json:"signing_format"`
	RepoMatchers       []string       `json:"repo_matchers"`
	Metadata           map[string]any `json:"metadata"`
	CreatedAt          time.Time      `json:"created_at"`
	UpdatedAt          time.Time      `json:"updated_at"`
}

type KeyVersionStatus struct {
	KEKVersion string    `json:"kek_version"`
	IsActive   bool      `json:"is_active"`
	CreatedAt  time.Time `json:"created_at"`
}

type KeyStatus struct {
	ActiveKEKVersion      string             `json:"active_kek_version"`
	LoadedKEKVersions     []string           `json:"loaded_kek_versions"`
	RegisteredKEKVersions []KeyVersionStatus `json:"registered_kek_versions"`
}

type DeleteResponse struct {
	Deleted bool `json:"deleted"`
}

type RewrapResult struct {
	TargetKEKVersion        string `json:"target_kek_version"`
	AuthorizationsRewrapped int    `json:"authorizations_rewrapped"`
	PasswordsRewrapped      int    `json:"passwords_rewrapped"`
	CertificatesRewrapped   int    `json:"certificates_rewrapped"`
}

type AuthorizationUpsertInput struct {
	AgentID      string         `json:"agent_id"`
	Provider     string         `json:"provider"`
	AccessToken  string         `json:"access_token"`
	AccountID    *string        `json:"account_id,omitempty"`
	RefreshToken *string        `json:"refresh_token,omitempty"`
	TokenType    *string        `json:"token_type,omitempty"`
	Scopes       []string       `json:"scopes,omitempty"`
	ExpiresAt    *time.Time     `json:"expires_at,omitempty"`
	Metadata     map[string]any `json:"metadata,omitempty"`
	Actor        string         `json:"actor,omitempty"`
}

type PasswordUpsertInput struct {
	AgentID  string         `json:"agent_id"`
	Name     string         `json:"name"`
	Password string         `json:"password"`
	Username *string        `json:"username,omitempty"`
	URL      *string        `json:"url,omitempty"`
	Metadata map[string]any `json:"metadata,omitempty"`
	Actor    string         `json:"actor,omitempty"`
}

type CertificateUpsertInput struct {
	AgentID              string         `json:"agent_id"`
	Name                 string         `json:"name"`
	CertificateChainPEM  string         `json:"certificate_chain_pem"`
	PrivateKeyPEM        *string        `json:"private_key_pem,omitempty"`
	PrivateKeyPassphrase *string        `json:"private_key_passphrase,omitempty"`
	Metadata             map[string]any `json:"metadata,omitempty"`
	Actor                string         `json:"actor,omitempty"`
}

type GitProfileUpsertInput struct {
	AgentID            string         `json:"agent_id"`
	Name               string         `json:"name"`
	Platform           string         `json:"platform"`
	Host               *string        `json:"host,omitempty"`
	GitUsername        string         `json:"git_username"`
	GitEmail           string         `json:"git_email"`
	PreferredTransport *string        `json:"preferred_transport,omitempty"`
	HTTPSCredentialRef *SecretRef     `json:"https_credential_ref,omitempty"`
	SSHIdentityRef     *SecretRef     `json:"ssh_identity_ref,omitempty"`
	SigningIdentityRef *SecretRef     `json:"signing_identity_ref,omitempty"`
	SigningFormat      *string        `json:"signing_format,omitempty"`
	RepoMatchers       []string       `json:"repo_matchers,omitempty"`
	Metadata           map[string]any `json:"metadata,omitempty"`
	Actor              string         `json:"actor,omitempty"`
}

type RewrapInput struct {
	TargetKEKVersion string `json:"target_kek_version,omitempty"`
	Actor            string `json:"actor,omitempty"`
}
