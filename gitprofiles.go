package squidkeys

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"
)

func (s *KeyStore) SaveGitProfile(input GitProfileUpsertInput) error {
	if err := validateNonEmpty(input.AgentID, "agent_id"); err != nil {
		return err
	}
	if err := validateNonEmpty(input.Name, "name"); err != nil {
		return err
	}
	if err := validateNonEmpty(input.Platform, "platform"); err != nil {
		return err
	}
	if err := validateNonEmpty(input.GitUsername, "git_username"); err != nil {
		return err
	}

	platform := strings.ToLower(strings.TrimSpace(input.Platform))
	gitUsername := strings.TrimSpace(input.GitUsername)
	gitEmail, err := normalizeGitEmail(input.GitEmail)
	if err != nil {
		return err
	}
	host := normalizedOptionalString(input.Host)
	preferredTransport, err := normalizeOptionalTransport(input.PreferredTransport)
	if err != nil {
		return err
	}
	signingFormat, err := normalizeOptionalSigningFormat(input.SigningFormat)
	if err != nil {
		return err
	}
	httpsCredentialRef, err := normalizeSecretRef(input.HTTPSCredentialRef)
	if err != nil {
		return err
	}
	sshIdentityRef, err := normalizeSecretRef(input.SSHIdentityRef)
	if err != nil {
		return err
	}
	signingIdentityRef, err := normalizeSecretRef(input.SigningIdentityRef)
	if err != nil {
		return err
	}
	repoMatchers, err := normalizeMatchers(input.RepoMatchers)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.validateSecretRefLocked(input.AgentID, httpsCredentialRef, "https_credential_ref"); err != nil {
		return err
	}
	if err := s.validateSecretRefLocked(input.AgentID, sshIdentityRef, "ssh_identity_ref"); err != nil {
		return err
	}
	if err := s.validateSecretRefLocked(input.AgentID, signingIdentityRef, "signing_identity_ref"); err != nil {
		return err
	}

	httpsCredentialRefJSON, err := marshalSecretRef(httpsCredentialRef)
	if err != nil {
		return err
	}
	sshIdentityRefJSON, err := marshalSecretRef(sshIdentityRef)
	if err != nil {
		return err
	}
	signingIdentityRefJSON, err := marshalSecretRef(signingIdentityRef)
	if err != nil {
		return err
	}
	repoMatchersJSON, err := json.Marshal(defaultStringSlice(repoMatchers))
	if err != nil {
		return fmt.Errorf("marshal repo_matchers: %w", err)
	}
	metadataJSON, err := json.Marshal(defaultMetadata(input.Metadata))
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}

	now := time.Now().Unix()
	_, err = s.db.ExecContext(
		context.Background(),
		`
		INSERT INTO git_profiles (
			agent_id,
			name,
			platform,
			host,
			git_username,
			git_email,
			preferred_transport,
			https_credential_ref,
			ssh_identity_ref,
			signing_identity_ref,
			signing_format,
			repo_matchers,
			metadata,
			created_at,
			updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (agent_id, name) DO UPDATE SET
			platform = excluded.platform,
			host = excluded.host,
			git_username = excluded.git_username,
			git_email = excluded.git_email,
			preferred_transport = excluded.preferred_transport,
			https_credential_ref = excluded.https_credential_ref,
			ssh_identity_ref = excluded.ssh_identity_ref,
			signing_identity_ref = excluded.signing_identity_ref,
			signing_format = excluded.signing_format,
			repo_matchers = excluded.repo_matchers,
			metadata = excluded.metadata,
			updated_at = excluded.updated_at
		`,
		input.AgentID,
		input.Name,
		platform,
		derefString(host),
		gitUsername,
		gitEmail,
		derefString(preferredTransport),
		stringOrNil(httpsCredentialRefJSON),
		stringOrNil(sshIdentityRefJSON),
		stringOrNil(signingIdentityRefJSON),
		derefString(signingFormat),
		string(repoMatchersJSON),
		string(metadataJSON),
		now,
		now,
	)
	if err != nil {
		auditErr := s.auditLocked(auditEvent{
			Operation:  "save",
			RecordType: "git_profile",
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
		RecordType: "git_profile",
		Actor:      defaultActor(input.Actor, "system"),
		Status:     "ok",
		AgentID:    input.AgentID,
		Name:       input.Name,
	})
}

func (s *KeyStore) GetGitProfile(agentID, name, actor string) (*GitProfileRecord, error) {
	if err := validateNonEmpty(agentID, "agent_id"); err != nil {
		return nil, err
	}
	if err := validateNonEmpty(name, "name"); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	record, err := s.getGitProfileLocked(agentID, name)
	if errors.Is(err, sql.ErrNoRows) {
		if auditErr := s.auditLocked(auditEvent{
			Operation:  "get",
			RecordType: "git_profile",
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
		if auditErr := s.auditLocked(auditEvent{
			Operation:  "get",
			RecordType: "git_profile",
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

	if err := s.auditLocked(auditEvent{
		Operation:  "get",
		RecordType: "git_profile",
		Actor:      defaultActor(actor, "system"),
		Status:     "ok",
		AgentID:    agentID,
		Name:       name,
	}); err != nil {
		return nil, err
	}

	return record, nil
}

func (s *KeyStore) ListGitProfiles(agentID, platform *string, actor string) ([]GitProfileRecord, error) {
	if agentID != nil {
		if err := validateNonEmpty(*agentID, "agent_id"); err != nil {
			return nil, err
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	query := `
		SELECT
			agent_id,
			name,
			platform,
			host,
			git_username,
			git_email,
			preferred_transport,
			https_credential_ref,
			ssh_identity_ref,
			signing_identity_ref,
			signing_format,
			repo_matchers,
			metadata,
			created_at,
			updated_at
		FROM git_profiles
	`
	var (
		clauses []string
		args    []any
	)
	if agentID != nil {
		clauses = append(clauses, "agent_id = ?")
		args = append(args, strings.TrimSpace(*agentID))
	}
	if platform != nil {
		trimmedPlatform := strings.ToLower(strings.TrimSpace(*platform))
		if trimmedPlatform == "" {
			return nil, &ValidationError{Message: "platform must be a non-empty string"}
		}
		clauses = append(clauses, "platform = ?")
		args = append(args, trimmedPlatform)
	}
	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ")
	}
	query += " ORDER BY agent_id, name"

	rows, err := s.db.QueryContext(context.Background(), query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []GitProfileRecord
	for rows.Next() {
		record, err := scanGitProfile(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, *record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if err := s.auditLocked(auditEvent{
		Operation:  "list",
		RecordType: "git_profile",
		Actor:      defaultActor(actor, "system"),
		Status:     "ok",
		AgentID:    optionalStringValue(agentID),
	}); err != nil {
		return nil, err
	}

	return records, nil
}

func (s *KeyStore) DeleteGitProfile(agentID, name, actor string) (bool, error) {
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
		DELETE FROM git_profiles
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
		RecordType: "git_profile",
		Actor:      defaultActor(actor, "system"),
		Status:     ternaryStatus(deleted),
		AgentID:    agentID,
		Name:       name,
	}); err != nil {
		return false, err
	}

	return deleted, nil
}

func (s *KeyStore) getGitProfileLocked(agentID, name string) (*GitProfileRecord, error) {
	rows, err := s.db.QueryContext(
		context.Background(),
		`
		SELECT
			agent_id,
			name,
			platform,
			host,
			git_username,
			git_email,
			preferred_transport,
			https_credential_ref,
			ssh_identity_ref,
			signing_identity_ref,
			signing_format,
			repo_matchers,
			metadata,
			created_at,
			updated_at
		FROM git_profiles
		WHERE agent_id = ? AND name = ?
		`,
		agentID,
		name,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, err
		}
		return nil, sql.ErrNoRows
	}

	record, err := scanGitProfile(rows)
	if err != nil {
		return nil, err
	}
	if rows.Next() {
		return nil, fmt.Errorf("unexpected duplicate git profile rows for %s/%s", agentID, name)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return record, nil
}

func scanGitProfile(scanner interface{ Scan(dest ...any) error }) (*GitProfileRecord, error) {
	var (
		agentID            string
		name               string
		platform           string
		host               sql.NullString
		gitUsername        string
		gitEmail           string
		preferredTransport sql.NullString
		httpsCredentialRef sql.NullString
		sshIdentityRef     sql.NullString
		signingIdentityRef sql.NullString
		signingFormat      sql.NullString
		repoMatchersJSON   string
		metadataJSON       string
		createdAt          int64
		updatedAt          int64
	)

	if err := scanner.Scan(
		&agentID,
		&name,
		&platform,
		&host,
		&gitUsername,
		&gitEmail,
		&preferredTransport,
		&httpsCredentialRef,
		&sshIdentityRef,
		&signingIdentityRef,
		&signingFormat,
		&repoMatchersJSON,
		&metadataJSON,
		&createdAt,
		&updatedAt,
	); err != nil {
		return nil, err
	}

	repoMatchers, err := decodeStringSliceJSON(repoMatchersJSON)
	if err != nil {
		return nil, fmt.Errorf("unmarshal repo_matchers: %w", err)
	}

	var metadata map[string]any
	if err := json.Unmarshal([]byte(metadataJSON), &metadata); err != nil {
		return nil, fmt.Errorf("unmarshal metadata: %w", err)
	}
	if metadata == nil {
		metadata = map[string]any{}
	}

	record := &GitProfileRecord{
		AgentID:            agentID,
		Name:               name,
		Platform:           platform,
		Host:               nullStringPtr(host),
		GitUsername:        gitUsername,
		GitEmail:           gitEmail,
		PreferredTransport: nullStringPtr(preferredTransport),
		SigningFormat:      nullStringPtr(signingFormat),
		RepoMatchers:       repoMatchers,
		Metadata:           metadata,
		CreatedAt:          time.Unix(createdAt, 0).UTC(),
		UpdatedAt:          time.Unix(updatedAt, 0).UTC(),
	}

	if record.HTTPSCredentialRef, err = parseSecretRef(httpsCredentialRef); err != nil {
		return nil, fmt.Errorf("unmarshal https_credential_ref: %w", err)
	}
	if record.SSHIdentityRef, err = parseSecretRef(sshIdentityRef); err != nil {
		return nil, fmt.Errorf("unmarshal ssh_identity_ref: %w", err)
	}
	if record.SigningIdentityRef, err = parseSecretRef(signingIdentityRef); err != nil {
		return nil, fmt.Errorf("unmarshal signing_identity_ref: %w", err)
	}

	return record, nil
}

func normalizeGitEmail(value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", &ValidationError{Message: "git_email must be a non-empty string"}
	}
	parsed, err := mail.ParseAddress(trimmed)
	if err != nil || parsed.Address != trimmed {
		return "", &ValidationError{Message: "git_email must be a valid email address"}
	}
	return trimmed, nil
}

func normalizeOptionalTransport(value *string) (*string, error) {
	return normalizeOptionalChoice(value, "preferred_transport", "ssh", "https")
}

func normalizeOptionalSigningFormat(value *string) (*string, error) {
	return normalizeOptionalChoice(value, "signing_format", "ssh", "gpg", "x509")
}

func normalizeOptionalChoice(value *string, field string, allowed ...string) (*string, error) {
	trimmed := normalizedOptionalString(value)
	if trimmed == nil {
		return nil, nil
	}
	lowered := strings.ToLower(*trimmed)
	for _, candidate := range allowed {
		if lowered == candidate {
			return &lowered, nil
		}
	}
	return nil, &ValidationError{Message: fmt.Sprintf("%s must be one of: %s", field, strings.Join(allowed, ", "))}
}

func normalizeSecretRef(ref *SecretRef) (*SecretRef, error) {
	if ref == nil {
		return nil, nil
	}

	normalized := &SecretRef{
		RecordType: strings.ToLower(strings.TrimSpace(ref.RecordType)),
		Name:       normalizedOptionalString(ref.Name),
		Provider:   normalizedOptionalString(ref.Provider),
		AccountID:  normalizedOptionalString(ref.AccountID),
	}

	switch normalized.RecordType {
	case "authorization":
		if normalized.Provider == nil {
			return nil, &ValidationError{Message: "authorization secret refs require provider"}
		}
		if normalized.Name != nil {
			return nil, &ValidationError{Message: "authorization secret refs do not use name"}
		}
	case "password", "certificate":
		if normalized.Name == nil {
			return nil, &ValidationError{Message: fmt.Sprintf("%s secret refs require name", normalized.RecordType)}
		}
		if normalized.Provider != nil || normalized.AccountID != nil {
			return nil, &ValidationError{Message: fmt.Sprintf("%s secret refs only support name", normalized.RecordType)}
		}
	default:
		return nil, &ValidationError{Message: "record_type must be one of: authorization, password, certificate"}
	}

	return normalized, nil
}

func normalizeMatchers(values []string) ([]string, error) {
	if values == nil {
		return []string{}, nil
	}
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			return nil, &ValidationError{Message: "repo_matchers cannot contain blank values"}
		}
		normalized = append(normalized, trimmed)
	}
	return normalized, nil
}

func normalizedOptionalString(value *string) *string {
	if value == nil {
		return nil
	}
	trimmed := strings.TrimSpace(*value)
	if trimmed == "" {
		return nil
	}
	return &trimmed
}

func marshalSecretRef(ref *SecretRef) ([]byte, error) {
	if ref == nil {
		return nil, nil
	}
	payload, err := json.Marshal(ref)
	if err != nil {
		return nil, fmt.Errorf("marshal secret ref: %w", err)
	}
	return payload, nil
}

func parseSecretRef(value sql.NullString) (*SecretRef, error) {
	if !value.Valid || strings.TrimSpace(value.String) == "" {
		return nil, nil
	}
	var ref SecretRef
	if err := json.Unmarshal([]byte(value.String), &ref); err != nil {
		return nil, err
	}
	return normalizeSecretRef(&ref)
}

func (s *KeyStore) validateSecretRefLocked(agentID string, ref *SecretRef, fieldName string) error {
	if ref == nil {
		return nil
	}

	var probe int
	switch ref.RecordType {
	case "authorization":
		err := s.db.QueryRowContext(
			context.Background(),
			`
			SELECT 1
			FROM auth_secrets
			WHERE agent_id = ? AND provider = ? AND account_id_key = ?
			`,
			agentID,
			*ref.Provider,
			accountIDKey(ref.AccountID),
		).Scan(&probe)
		if errors.Is(err, sql.ErrNoRows) {
			return &ValidationError{Message: fmt.Sprintf("%s references a missing authorization record", fieldName)}
		}
		return err
	case "password":
		err := s.db.QueryRowContext(
			context.Background(),
			`
			SELECT 1
			FROM password_secrets
			WHERE agent_id = ? AND name = ?
			`,
			agentID,
			*ref.Name,
		).Scan(&probe)
		if errors.Is(err, sql.ErrNoRows) {
			return &ValidationError{Message: fmt.Sprintf("%s references a missing password record", fieldName)}
		}
		return err
	case "certificate":
		err := s.db.QueryRowContext(
			context.Background(),
			`
			SELECT 1
			FROM certificate_secrets
			WHERE agent_id = ? AND name = ?
			`,
			agentID,
			*ref.Name,
		).Scan(&probe)
		if errors.Is(err, sql.ErrNoRows) {
			return &ValidationError{Message: fmt.Sprintf("%s references a missing certificate record", fieldName)}
		}
		return err
	default:
		return &ValidationError{Message: fmt.Sprintf("%s has unsupported record_type", fieldName)}
	}
}

func stringOrNil(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return string(value)
}

func optionalStringValue(value *string) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(*value)
}
