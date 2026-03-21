package squidkeys

import "fmt"

type ResolvedGitProfile struct {
	Profile            GitProfileRecord     `json:"profile"`
	HTTPSAuthorization *AuthorizationRecord `json:"https_authorization,omitempty"`
	SSHPassword        *PasswordRecord      `json:"ssh_password,omitempty"`
	SigningCertificate *CertificateRecord   `json:"signing_certificate,omitempty"`
}

func (s *KeyStore) ResolveGitProfile(agentID, name, actor string) (*ResolvedGitProfile, error) {
	profile, err := s.GetGitProfile(agentID, name, actor)
	if err != nil || profile == nil {
		return nil, err
	}

	resolved := &ResolvedGitProfile{
		Profile: *profile,
	}

	if resolved.HTTPSAuthorization, err = s.resolveAuthorizationSecretRef(agentID, profile.HTTPSCredentialRef, actor, "https_credential_ref"); err != nil {
		return nil, err
	}
	if resolved.SSHPassword, err = s.resolvePasswordSecretRef(agentID, profile.SSHIdentityRef, actor, "ssh_identity_ref"); err != nil {
		return nil, err
	}
	if resolved.SigningCertificate, err = s.resolveCertificateSecretRef(agentID, profile.SigningIdentityRef, actor, "signing_identity_ref"); err != nil {
		return nil, err
	}

	return resolved, nil
}

func (s *KeyStore) resolveAuthorizationSecretRef(agentID string, ref *SecretRef, actor, fieldName string) (*AuthorizationRecord, error) {
	if ref == nil {
		return nil, nil
	}
	if ref.RecordType != "authorization" {
		return nil, &ValidationError{Message: fmt.Sprintf("%s must reference an authorization record", fieldName)}
	}
	if ref.Provider == nil {
		return nil, &ValidationError{Message: fmt.Sprintf("%s requires provider", fieldName)}
	}

	record, err := s.GetAuthorization(agentID, *ref.Provider, ref.AccountID, actor)
	if err != nil {
		return nil, err
	}
	if record == nil {
		return nil, &ValidationError{Message: fmt.Sprintf("%s references a missing authorization record", fieldName)}
	}
	return record, nil
}

func (s *KeyStore) resolvePasswordSecretRef(agentID string, ref *SecretRef, actor, fieldName string) (*PasswordRecord, error) {
	if ref == nil {
		return nil, nil
	}
	if ref.RecordType != "password" {
		return nil, &ValidationError{Message: fmt.Sprintf("%s must reference a password record", fieldName)}
	}
	if ref.Name == nil {
		return nil, &ValidationError{Message: fmt.Sprintf("%s requires name", fieldName)}
	}

	record, err := s.GetPassword(agentID, *ref.Name, actor)
	if err != nil {
		return nil, err
	}
	if record == nil {
		return nil, &ValidationError{Message: fmt.Sprintf("%s references a missing password record", fieldName)}
	}
	return record, nil
}

func (s *KeyStore) resolveCertificateSecretRef(agentID string, ref *SecretRef, actor, fieldName string) (*CertificateRecord, error) {
	if ref == nil {
		return nil, nil
	}
	if ref.RecordType != "certificate" {
		return nil, &ValidationError{Message: fmt.Sprintf("%s must reference a certificate record", fieldName)}
	}
	if ref.Name == nil {
		return nil, &ValidationError{Message: fmt.Sprintf("%s requires name", fieldName)}
	}

	record, err := s.GetCertificate(agentID, *ref.Name, actor)
	if err != nil {
		return nil, err
	}
	if record == nil {
		return nil, &ValidationError{Message: fmt.Sprintf("%s references a missing certificate record", fieldName)}
	}
	return record, nil
}
