package squidkeys

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	_ "github.com/duckdb/duckdb-go/v2"
	"github.com/google/uuid"
)

const (
	keksEnv             = "KEY_STORE_KEKS_JSON"
	activeKEKVersionEnv = "KEY_STORE_ACTIVE_KEK_VERSION"
	legacyMasterKeyEnv  = "KEY_STORE_MASTER_KEY"
)

type KeyStoreError struct {
	Message string
}

func (e *KeyStoreError) Error() string {
	return e.Message
}

type KeyStoreConfigError struct {
	Message string
}

func (e *KeyStoreConfigError) Error() string {
	return e.Message
}

type ValidationError struct {
	Message string
}

func (e *ValidationError) Error() string {
	return e.Message
}

type KeyStoreConfig struct {
	KEKsB64          map[string]string
	ActiveKEKVersion string
}

type KeyStore struct {
	dbPath           string
	db               *sql.DB
	mu               sync.Mutex
	keks             map[string][]byte
	activeKEKVersion string
}

func NewKeyStore(dbPath string, config KeyStoreConfig) (*KeyStore, error) {
	dbPath = strings.TrimSpace(dbPath)
	if dbPath == "" {
		return nil, &ValidationError{Message: "db_path must be a non-empty string"}
	}

	filePath := localDBFilePath(dbPath)
	dirPath := filepath.Dir(filePath)

	keks, activeVersion, err := loadKEKs(config.KEKsB64, config.ActiveKEKVersion)
	if err != nil {
		return nil, err
	}

	if err := ensurePrivateDirectory(dirPath); err != nil {
		return nil, err
	}

	db, err := sql.Open("duckdb", duckDBDSN(dbPath))
	if err != nil {
		return nil, fmt.Errorf("open duckdb: %w", err)
	}

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping duckdb: %w", err)
	}

	if err := ensurePrivateFile(filePath); err != nil {
		_ = db.Close()
		return nil, err
	}

	store := &KeyStore{
		dbPath:           dbPath,
		db:               db,
		keks:             keks,
		activeKEKVersion: activeVersion,
	}

	if err := store.initialize(); err != nil {
		_ = db.Close()
		return nil, err
	}

	if err := store.syncKeyVersions(); err != nil {
		_ = db.Close()
		return nil, err
	}

	return store, nil
}

func GenerateKey() string {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(fmt.Sprintf("generate key: %v", err))
	}
	return base64.URLEncoding.EncodeToString(key)
}

func GenerateMasterKey() string {
	return GenerateKey()
}

func (s *KeyStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.db.Close()
}

func (s *KeyStore) KeyStatus() (KeyStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.QueryContext(
		context.Background(),
		`
		SELECT kek_version, is_active, created_at
		FROM key_versions
		ORDER BY kek_version
		`,
	)
	if err != nil {
		return KeyStatus{}, fmt.Errorf("query key status: %w", err)
	}
	defer rows.Close()

	status := KeyStatus{
		ActiveKEKVersion:  s.activeKEKVersion,
		LoadedKEKVersions: sortedKeys(s.keks),
	}

	for rows.Next() {
		var version string
		var active bool
		var createdAt int64
		if err := rows.Scan(&version, &active, &createdAt); err != nil {
			return KeyStatus{}, fmt.Errorf("scan key status: %w", err)
		}
		status.RegisteredKEKVersions = append(status.RegisteredKEKVersions, KeyVersionStatus{
			KEKVersion: version,
			IsActive:   active,
			CreatedAt:  time.Unix(createdAt, 0).UTC(),
		})
	}

	if err := rows.Err(); err != nil {
		return KeyStatus{}, fmt.Errorf("iterate key status: %w", err)
	}

	return status, nil
}

func (s *KeyStore) SaveAuthorization(input AuthorizationUpsertInput) error {
	if err := validateNonEmpty(input.AgentID, "agent_id"); err != nil {
		return err
	}
	if err := validateNonEmpty(input.Provider, "provider"); err != nil {
		return err
	}
	if err := validateNonEmpty(input.AccessToken, "access_token"); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	accountIDKey := accountIDKey(input.AccountID)
	activeVersion := s.activeKEKVersion
	dek, err := randomBytes(32)
	if err != nil {
		return err
	}

	wrappedDEKNonce, wrappedDEK, err := s.wrapDEK(
		dek,
		activeVersion,
		"auth",
		input.AgentID,
		fmt.Sprintf("%s|%s", input.Provider, accountIDKey),
	)
	if err != nil {
		return err
	}

	accessNonce, accessCiphertext, err := encryptWithDEK(
		dek,
		input.AccessToken,
		aad("auth", input.AgentID, input.Provider, accountIDKey, "access"),
	)
	if err != nil {
		return err
	}

	var refreshNonce []byte
	var refreshCiphertext []byte
	if input.RefreshToken != nil {
		refreshNonce, refreshCiphertext, err = encryptWithDEK(
			dek,
			*input.RefreshToken,
			aad("auth", input.AgentID, input.Provider, accountIDKey, "refresh"),
		)
		if err != nil {
			return err
		}
	}

	scopesJSON, err := json.Marshal(defaultStringSlice(input.Scopes))
	if err != nil {
		return fmt.Errorf("marshal scopes: %w", err)
	}
	metadataJSON, err := json.Marshal(defaultMetadata(input.Metadata))
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}

	now := time.Now().Unix()
	var expiresAt any
	if input.ExpiresAt != nil {
		expiresAt = input.ExpiresAt.Unix()
	}

	_, err = s.db.ExecContext(
		context.Background(),
		`
		INSERT INTO auth_secrets (
			agent_id,
			provider,
			account_id,
			account_id_key,
			scopes,
			access_nonce,
			access_ciphertext,
			refresh_nonce,
			refresh_ciphertext,
			token_type,
			expires_at,
			metadata,
			wrapped_dek_nonce,
			wrapped_dek,
			kek_version,
			created_at,
			updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (agent_id, provider, account_id_key) DO UPDATE SET
			account_id = excluded.account_id,
			scopes = excluded.scopes,
			access_nonce = excluded.access_nonce,
			access_ciphertext = excluded.access_ciphertext,
			refresh_nonce = excluded.refresh_nonce,
			refresh_ciphertext = excluded.refresh_ciphertext,
			token_type = excluded.token_type,
			expires_at = excluded.expires_at,
			metadata = excluded.metadata,
			wrapped_dek_nonce = excluded.wrapped_dek_nonce,
			wrapped_dek = excluded.wrapped_dek,
			kek_version = excluded.kek_version,
			updated_at = excluded.updated_at
		`,
		input.AgentID,
		input.Provider,
		derefString(input.AccountID),
		accountIDKey,
		string(scopesJSON),
		accessNonce,
		accessCiphertext,
		nilIfEmpty(refreshNonce),
		nilIfEmpty(refreshCiphertext),
		derefString(input.TokenType),
		expiresAt,
		string(metadataJSON),
		wrappedDEKNonce,
		wrappedDEK,
		activeVersion,
		now,
		now,
	)
	if err != nil {
		auditErr := s.auditLocked(auditEvent{
			Operation:    "save",
			RecordType:   "authorization",
			Actor:        defaultActor(input.Actor, "system"),
			Status:       "error",
			AgentID:      input.AgentID,
			Provider:     input.Provider,
			AccountIDKey: accountIDKey,
			Error:        err.Error(),
		})
		if auditErr != nil {
			return auditErr
		}
		return err
	}

	return s.auditLocked(auditEvent{
		Operation:    "save",
		RecordType:   "authorization",
		Actor:        defaultActor(input.Actor, "system"),
		Status:       "ok",
		AgentID:      input.AgentID,
		Provider:     input.Provider,
		AccountIDKey: accountIDKey,
	})
}

func (s *KeyStore) GetAuthorization(agentID, provider string, accountID *string, actor string) (*AuthorizationRecord, error) {
	if err := validateNonEmpty(agentID, "agent_id"); err != nil {
		return nil, err
	}
	if err := validateNonEmpty(provider, "provider"); err != nil {
		return nil, err
	}

	accountIDKey := accountIDKey(accountID)

	s.mu.Lock()
	defer s.mu.Unlock()

	var (
		storedAccountID   sql.NullString
		scopesJSON        string
		accessNonce       []byte
		accessCiphertext  []byte
		refreshNonce      []byte
		refreshCiphertext []byte
		tokenType         sql.NullString
		expiresAt         sql.NullInt64
		metadataJSON      string
		wrappedDEKNonce   []byte
		wrappedDEK        []byte
		kekVersion        string
	)

	err := s.db.QueryRowContext(
		context.Background(),
		`
		SELECT
			account_id,
			scopes,
			access_nonce,
			access_ciphertext,
			refresh_nonce,
			refresh_ciphertext,
			token_type,
			expires_at,
			metadata,
			wrapped_dek_nonce,
			wrapped_dek,
			kek_version
		FROM auth_secrets
		WHERE agent_id = ? AND provider = ? AND account_id_key = ?
		`,
		agentID,
		provider,
		accountIDKey,
	).Scan(
		&storedAccountID,
		&scopesJSON,
		&accessNonce,
		&accessCiphertext,
		&refreshNonce,
		&refreshCiphertext,
		&tokenType,
		&expiresAt,
		&metadataJSON,
		&wrappedDEKNonce,
		&wrappedDEK,
		&kekVersion,
	)
	if errors.Is(err, sql.ErrNoRows) {
		if auditErr := s.auditLocked(auditEvent{
			Operation:    "get",
			RecordType:   "authorization",
			Actor:        defaultActor(actor, "system"),
			Status:       "miss",
			AgentID:      agentID,
			Provider:     provider,
			AccountIDKey: accountIDKey,
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
		"auth",
		agentID,
		fmt.Sprintf("%s|%s", provider, accountIDKey),
	)
	if err != nil {
		if auditErr := s.auditLocked(auditEvent{
			Operation:    "get",
			RecordType:   "authorization",
			Actor:        defaultActor(actor, "system"),
			Status:       "error",
			AgentID:      agentID,
			Provider:     provider,
			AccountIDKey: accountIDKey,
			Error:        err.Error(),
		}); auditErr != nil {
			return nil, auditErr
		}
		return nil, err
	}

	accessToken, err := decryptWithDEK(
		dek,
		accessNonce,
		accessCiphertext,
		aad("auth", agentID, provider, accountIDKey, "access"),
	)
	if err != nil {
		if auditErr := s.auditLocked(auditEvent{
			Operation:    "get",
			RecordType:   "authorization",
			Actor:        defaultActor(actor, "system"),
			Status:       "error",
			AgentID:      agentID,
			Provider:     provider,
			AccountIDKey: accountIDKey,
			Error:        err.Error(),
		}); auditErr != nil {
			return nil, auditErr
		}
		return nil, err
	}

	var refreshToken *string
	if len(refreshNonce) > 0 && len(refreshCiphertext) > 0 {
		value, err := decryptWithDEK(
			dek,
			refreshNonce,
			refreshCiphertext,
			aad("auth", agentID, provider, accountIDKey, "refresh"),
		)
		if err != nil {
			if auditErr := s.auditLocked(auditEvent{
				Operation:    "get",
				RecordType:   "authorization",
				Actor:        defaultActor(actor, "system"),
				Status:       "error",
				AgentID:      agentID,
				Provider:     provider,
				AccountIDKey: accountIDKey,
				Error:        err.Error(),
			}); auditErr != nil {
				return nil, auditErr
			}
			return nil, err
		}
		refreshToken = &value
	}

	var scopes []string
	if err := json.Unmarshal([]byte(scopesJSON), &scopes); err != nil {
		return nil, fmt.Errorf("unmarshal scopes: %w", err)
	}
	if scopes == nil {
		scopes = []string{}
	}

	var metadata map[string]any
	if err := json.Unmarshal([]byte(metadataJSON), &metadata); err != nil {
		return nil, fmt.Errorf("unmarshal metadata: %w", err)
	}
	if metadata == nil {
		metadata = map[string]any{}
	}

	record := &AuthorizationRecord{
		AgentID:      agentID,
		Provider:     provider,
		AccountID:    nullStringPtr(storedAccountID),
		Scopes:       scopes,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    nullStringPtr(tokenType),
		Metadata:     metadata,
		KEKVersion:   kekVersion,
	}
	if expiresAt.Valid {
		value := time.Unix(expiresAt.Int64, 0).UTC()
		record.ExpiresAt = &value
	}

	if err := s.auditLocked(auditEvent{
		Operation:    "get",
		RecordType:   "authorization",
		Actor:        defaultActor(actor, "system"),
		Status:       "ok",
		AgentID:      agentID,
		Provider:     provider,
		AccountIDKey: accountIDKey,
	}); err != nil {
		return nil, err
	}

	return record, nil
}

func (s *KeyStore) DeleteAuthorization(agentID, provider string, accountID *string, actor string) (bool, error) {
	if err := validateNonEmpty(agentID, "agent_id"); err != nil {
		return false, err
	}
	if err := validateNonEmpty(provider, "provider"); err != nil {
		return false, err
	}

	accountIDKey := accountIDKey(accountID)

	s.mu.Lock()
	defer s.mu.Unlock()

	res, err := s.db.ExecContext(
		context.Background(),
		`
		DELETE FROM auth_secrets
		WHERE agent_id = ? AND provider = ? AND account_id_key = ?
		`,
		agentID,
		provider,
		accountIDKey,
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
		Operation:    "delete",
		RecordType:   "authorization",
		Actor:        defaultActor(actor, "system"),
		Status:       ternaryStatus(deleted),
		AgentID:      agentID,
		Provider:     provider,
		AccountIDKey: accountIDKey,
	}); err != nil {
		return false, err
	}

	return deleted, nil
}

func (s *KeyStore) SavePassword(input PasswordUpsertInput) error {
	if err := validateNonEmpty(input.AgentID, "agent_id"); err != nil {
		return err
	}
	if err := validateNonEmpty(input.Name, "name"); err != nil {
		return err
	}
	if err := validateNonEmpty(input.Password, "password"); err != nil {
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
		"pwd",
		input.AgentID,
		input.Name,
	)
	if err != nil {
		return err
	}

	passwordNonce, passwordCiphertext, err := encryptWithDEK(
		dek,
		input.Password,
		aad("pwd", input.AgentID, input.Name, "password"),
	)
	if err != nil {
		return err
	}

	metadataJSON, err := json.Marshal(defaultMetadata(input.Metadata))
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}

	now := time.Now().Unix()

	_, err = s.db.ExecContext(
		context.Background(),
		`
		INSERT INTO password_secrets (
			agent_id,
			name,
			username,
			url,
			metadata,
			wrapped_dek_nonce,
			wrapped_dek,
			password_nonce,
			password_ciphertext,
			kek_version,
			created_at,
			updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (agent_id, name) DO UPDATE SET
			username = excluded.username,
			url = excluded.url,
			metadata = excluded.metadata,
			wrapped_dek_nonce = excluded.wrapped_dek_nonce,
			wrapped_dek = excluded.wrapped_dek,
			password_nonce = excluded.password_nonce,
			password_ciphertext = excluded.password_ciphertext,
			kek_version = excluded.kek_version,
			updated_at = excluded.updated_at
		`,
		input.AgentID,
		input.Name,
		derefString(input.Username),
		derefString(input.URL),
		string(metadataJSON),
		wrappedDEKNonce,
		wrappedDEK,
		passwordNonce,
		passwordCiphertext,
		activeVersion,
		now,
		now,
	)
	if err != nil {
		auditErr := s.auditLocked(auditEvent{
			Operation:  "save",
			RecordType: "password",
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
		RecordType: "password",
		Actor:      defaultActor(input.Actor, "system"),
		Status:     "ok",
		AgentID:    input.AgentID,
		Name:       input.Name,
	})
}

func (s *KeyStore) GetPassword(agentID, name, actor string) (*PasswordRecord, error) {
	if err := validateNonEmpty(agentID, "agent_id"); err != nil {
		return nil, err
	}
	if err := validateNonEmpty(name, "name"); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var (
		username        sql.NullString
		url             sql.NullString
		metadataJSON    string
		wrappedDEKNonce []byte
		wrappedDEK      []byte
		passwordNonce   []byte
		passwordCipher  []byte
		kekVersion      string
	)

	err := s.db.QueryRowContext(
		context.Background(),
		`
		SELECT
			username,
			url,
			metadata,
			wrapped_dek_nonce,
			wrapped_dek,
			password_nonce,
			password_ciphertext,
			kek_version
		FROM password_secrets
		WHERE agent_id = ? AND name = ?
		`,
		agentID,
		name,
	).Scan(
		&username,
		&url,
		&metadataJSON,
		&wrappedDEKNonce,
		&wrappedDEK,
		&passwordNonce,
		&passwordCipher,
		&kekVersion,
	)
	if errors.Is(err, sql.ErrNoRows) {
		if auditErr := s.auditLocked(auditEvent{
			Operation:  "get",
			RecordType: "password",
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
		"pwd",
		agentID,
		name,
	)
	if err != nil {
		if auditErr := s.auditLocked(auditEvent{
			Operation:  "get",
			RecordType: "password",
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

	password, err := decryptWithDEK(
		dek,
		passwordNonce,
		passwordCipher,
		aad("pwd", agentID, name, "password"),
	)
	if err != nil {
		if auditErr := s.auditLocked(auditEvent{
			Operation:  "get",
			RecordType: "password",
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

	var metadata map[string]any
	if err := json.Unmarshal([]byte(metadataJSON), &metadata); err != nil {
		return nil, fmt.Errorf("unmarshal metadata: %w", err)
	}
	if metadata == nil {
		metadata = map[string]any{}
	}

	record := &PasswordRecord{
		AgentID:    agentID,
		Name:       name,
		Username:   nullStringPtr(username),
		Password:   password,
		URL:        nullStringPtr(url),
		Metadata:   metadata,
		KEKVersion: kekVersion,
	}

	if err := s.auditLocked(auditEvent{
		Operation:  "get",
		RecordType: "password",
		Actor:      defaultActor(actor, "system"),
		Status:     "ok",
		AgentID:    agentID,
		Name:       name,
	}); err != nil {
		return nil, err
	}

	return record, nil
}

func (s *KeyStore) DeletePassword(agentID, name, actor string) (bool, error) {
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
		DELETE FROM password_secrets
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
		RecordType: "password",
		Actor:      defaultActor(actor, "system"),
		Status:     ternaryStatus(deleted),
		AgentID:    agentID,
		Name:       name,
	}); err != nil {
		return false, err
	}

	return deleted, nil
}

func (s *KeyStore) RewrapAllRecords(targetKEKVersion, actor string) (RewrapResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	target := strings.TrimSpace(targetKEKVersion)
	if target == "" {
		target = s.activeKEKVersion
	}

	if _, ok := s.keks[target]; !ok {
		return RewrapResult{}, &KeyStoreConfigError{
			Message: fmt.Sprintf("Unknown target_kek_version: %s", target),
		}
	}

	authRows, err := s.db.QueryContext(
		context.Background(),
		`
		SELECT agent_id, provider, account_id_key, wrapped_dek_nonce, wrapped_dek, kek_version
		FROM auth_secrets
		WHERE kek_version <> ?
		`,
		target,
	)
	if err != nil {
		return RewrapResult{}, err
	}
	var authEntries []struct {
		agentID      string
		provider     string
		accountIDKey string
		wrappedNonce []byte
		wrappedDEK   []byte
		kekVersion   string
	}
	for authRows.Next() {
		var row struct {
			agentID      string
			provider     string
			accountIDKey string
			wrappedNonce []byte
			wrappedDEK   []byte
			kekVersion   string
		}
		if err := authRows.Scan(
			&row.agentID,
			&row.provider,
			&row.accountIDKey,
			&row.wrappedNonce,
			&row.wrappedDEK,
			&row.kekVersion,
		); err != nil {
			if closeErr := authRows.Close(); closeErr != nil {
				return RewrapResult{}, closeErr
			}
			return RewrapResult{}, err
		}
		authEntries = append(authEntries, row)
	}
	if err := authRows.Err(); err != nil {
		if closeErr := authRows.Close(); closeErr != nil {
			return RewrapResult{}, closeErr
		}
		return RewrapResult{}, err
	}
	if err := authRows.Close(); err != nil {
		return RewrapResult{}, err
	}

	pwdRows, err := s.db.QueryContext(
		context.Background(),
		`
		SELECT agent_id, name, wrapped_dek_nonce, wrapped_dek, kek_version
		FROM password_secrets
		WHERE kek_version <> ?
		`,
		target,
	)
	if err != nil {
		return RewrapResult{}, err
	}
	var passwordEntries []struct {
		agentID      string
		name         string
		wrappedNonce []byte
		wrappedDEK   []byte
		kekVersion   string
	}
	for pwdRows.Next() {
		var row struct {
			agentID      string
			name         string
			wrappedNonce []byte
			wrappedDEK   []byte
			kekVersion   string
		}
		if err := pwdRows.Scan(
			&row.agentID,
			&row.name,
			&row.wrappedNonce,
			&row.wrappedDEK,
			&row.kekVersion,
		); err != nil {
			if closeErr := pwdRows.Close(); closeErr != nil {
				return RewrapResult{}, closeErr
			}
			return RewrapResult{}, err
		}
		passwordEntries = append(passwordEntries, row)
	}
	if err := pwdRows.Err(); err != nil {
		if closeErr := pwdRows.Close(); closeErr != nil {
			return RewrapResult{}, closeErr
		}
		return RewrapResult{}, err
	}
	if err := pwdRows.Close(); err != nil {
		return RewrapResult{}, err
	}

	certRows, err := s.db.QueryContext(
		context.Background(),
		`
		SELECT agent_id, name, wrapped_dek_nonce, wrapped_dek, kek_version
		FROM certificate_secrets
		WHERE kek_version <> ?
		`,
		target,
	)
	if err != nil {
		return RewrapResult{}, err
	}
	var certificateEntries []struct {
		agentID      string
		name         string
		wrappedNonce []byte
		wrappedDEK   []byte
		kekVersion   string
	}
	for certRows.Next() {
		var row struct {
			agentID      string
			name         string
			wrappedNonce []byte
			wrappedDEK   []byte
			kekVersion   string
		}
		if err := certRows.Scan(
			&row.agentID,
			&row.name,
			&row.wrappedNonce,
			&row.wrappedDEK,
			&row.kekVersion,
		); err != nil {
			if closeErr := certRows.Close(); closeErr != nil {
				return RewrapResult{}, closeErr
			}
			return RewrapResult{}, err
		}
		certificateEntries = append(certificateEntries, row)
	}
	if err := certRows.Err(); err != nil {
		if closeErr := certRows.Close(); closeErr != nil {
			return RewrapResult{}, closeErr
		}
		return RewrapResult{}, err
	}
	if err := certRows.Close(); err != nil {
		return RewrapResult{}, err
	}

	now := time.Now().Unix()

	authRewrapped := 0
	for _, row := range authEntries {
		dek, err := s.unwrapDEK(
			row.wrappedNonce,
			row.wrappedDEK,
			row.kekVersion,
			"auth",
			row.agentID,
			fmt.Sprintf("%s|%s", row.provider, row.accountIDKey),
		)
		if err != nil {
			return RewrapResult{}, err
		}

		newNonce, newWrapped, err := s.wrapDEK(
			dek,
			target,
			"auth",
			row.agentID,
			fmt.Sprintf("%s|%s", row.provider, row.accountIDKey),
		)
		if err != nil {
			return RewrapResult{}, err
		}

		if _, err := s.db.ExecContext(
			context.Background(),
			`
			UPDATE auth_secrets
			SET wrapped_dek_nonce = ?, wrapped_dek = ?, kek_version = ?, updated_at = ?
			WHERE agent_id = ? AND provider = ? AND account_id_key = ?
			`,
			newNonce,
			newWrapped,
			target,
			now,
			row.agentID,
			row.provider,
			row.accountIDKey,
		); err != nil {
			return RewrapResult{}, err
		}
		authRewrapped++
	}

	passwordRewrapped := 0
	for _, row := range passwordEntries {
		dek, err := s.unwrapDEK(
			row.wrappedNonce,
			row.wrappedDEK,
			row.kekVersion,
			"pwd",
			row.agentID,
			row.name,
		)
		if err != nil {
			return RewrapResult{}, err
		}

		newNonce, newWrapped, err := s.wrapDEK(
			dek,
			target,
			"pwd",
			row.agentID,
			row.name,
		)
		if err != nil {
			return RewrapResult{}, err
		}

		if _, err := s.db.ExecContext(
			context.Background(),
			`
			UPDATE password_secrets
			SET wrapped_dek_nonce = ?, wrapped_dek = ?, kek_version = ?, updated_at = ?
			WHERE agent_id = ? AND name = ?
			`,
			newNonce,
			newWrapped,
			target,
			now,
			row.agentID,
			row.name,
		); err != nil {
			return RewrapResult{}, err
		}
		passwordRewrapped++
	}

	certificateRewrapped := 0
	for _, row := range certificateEntries {
		dek, err := s.unwrapDEK(
			row.wrappedNonce,
			row.wrappedDEK,
			row.kekVersion,
			"crt",
			row.agentID,
			row.name,
		)
		if err != nil {
			return RewrapResult{}, err
		}

		newNonce, newWrapped, err := s.wrapDEK(
			dek,
			target,
			"crt",
			row.agentID,
			row.name,
		)
		if err != nil {
			return RewrapResult{}, err
		}

		if _, err := s.db.ExecContext(
			context.Background(),
			`
			UPDATE certificate_secrets
			SET wrapped_dek_nonce = ?, wrapped_dek = ?, kek_version = ?, updated_at = ?
			WHERE agent_id = ? AND name = ?
			`,
			newNonce,
			newWrapped,
			target,
			now,
			row.agentID,
			row.name,
		); err != nil {
			return RewrapResult{}, err
		}
		certificateRewrapped++
	}

	s.activeKEKVersion = target
	if err := s.syncKeyVersionsLocked(); err != nil {
		return RewrapResult{}, err
	}

	if err := s.auditLocked(auditEvent{
		Operation:  "rewrap",
		RecordType: "all",
		Actor:      defaultActor(actor, "system"),
		Status:     "ok",
	}); err != nil {
		return RewrapResult{}, err
	}

	return RewrapResult{
		TargetKEKVersion:        target,
		AuthorizationsRewrapped: authRewrapped,
		PasswordsRewrapped:      passwordRewrapped,
		CertificatesRewrapped:   certificateRewrapped,
	}, nil
}

type auditEvent struct {
	Operation    string
	RecordType   string
	Actor        string
	Status       string
	AgentID      string
	Provider     string
	AccountIDKey string
	Name         string
	Error        string
}

func (s *KeyStore) initialize() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	stmts := []string{
		`
		CREATE TABLE IF NOT EXISTS auth_secrets (
			agent_id TEXT NOT NULL,
			provider TEXT NOT NULL,
			account_id TEXT,
			account_id_key TEXT NOT NULL,
			scopes TEXT NOT NULL,
			access_nonce BLOB NOT NULL,
			access_ciphertext BLOB NOT NULL,
			refresh_nonce BLOB,
			refresh_ciphertext BLOB,
			token_type TEXT,
			expires_at BIGINT,
			metadata TEXT NOT NULL,
			wrapped_dek_nonce BLOB NOT NULL,
			wrapped_dek BLOB NOT NULL,
			kek_version TEXT NOT NULL,
			created_at BIGINT NOT NULL,
			updated_at BIGINT NOT NULL,
			UNIQUE(agent_id, provider, account_id_key)
		)
		`,
		`
		CREATE TABLE IF NOT EXISTS password_secrets (
			agent_id TEXT NOT NULL,
			name TEXT NOT NULL,
			username TEXT,
			url TEXT,
			metadata TEXT NOT NULL,
			wrapped_dek_nonce BLOB NOT NULL,
			wrapped_dek BLOB NOT NULL,
			password_nonce BLOB NOT NULL,
			password_ciphertext BLOB NOT NULL,
			kek_version TEXT NOT NULL,
			created_at BIGINT NOT NULL,
			updated_at BIGINT NOT NULL,
			UNIQUE(agent_id, name)
		)
		`,
		`
		CREATE TABLE IF NOT EXISTS certificate_secrets (
			agent_id TEXT NOT NULL,
			name TEXT NOT NULL,
			subject TEXT NOT NULL,
			subject_common_name TEXT,
			issuer TEXT NOT NULL,
			issuer_common_name TEXT,
			serial_number TEXT NOT NULL,
			fingerprint_sha256 TEXT NOT NULL,
			not_before BIGINT NOT NULL,
			not_after BIGINT NOT NULL,
			dns_names TEXT NOT NULL,
			email_addresses TEXT NOT NULL,
			ip_addresses TEXT NOT NULL,
			uris TEXT NOT NULL,
			key_usages TEXT NOT NULL,
			ext_key_usages TEXT NOT NULL,
			is_ca BOOLEAN NOT NULL,
			public_key_algorithm TEXT NOT NULL,
			private_key_algorithm TEXT,
			signature_algorithm TEXT NOT NULL,
			metadata TEXT NOT NULL,
			wrapped_dek_nonce BLOB NOT NULL,
			wrapped_dek BLOB NOT NULL,
			certificate_chain_nonce BLOB NOT NULL,
			certificate_chain_ciphertext BLOB NOT NULL,
			private_key_nonce BLOB,
			private_key_ciphertext BLOB,
			private_key_passphrase_nonce BLOB,
			private_key_passphrase_ciphertext BLOB,
			kek_version TEXT NOT NULL,
			created_at BIGINT NOT NULL,
			updated_at BIGINT NOT NULL,
			UNIQUE(agent_id, name)
		)
		`,
		`
		CREATE TABLE IF NOT EXISTS git_profiles (
			agent_id TEXT NOT NULL,
			name TEXT NOT NULL,
			platform TEXT NOT NULL,
			host TEXT,
			git_username TEXT NOT NULL,
			git_email TEXT NOT NULL,
			preferred_transport TEXT,
			https_credential_ref TEXT,
			ssh_identity_ref TEXT,
			signing_identity_ref TEXT,
			signing_format TEXT,
			repo_matchers TEXT NOT NULL,
			metadata TEXT NOT NULL,
			created_at BIGINT NOT NULL,
			updated_at BIGINT NOT NULL,
			UNIQUE(agent_id, name)
		)
		`,
		`
		CREATE TABLE IF NOT EXISTS key_versions (
			kek_version TEXT PRIMARY KEY,
			is_active BOOLEAN NOT NULL,
			created_at BIGINT NOT NULL
		)
		`,
		`
		CREATE TABLE IF NOT EXISTS audit_log (
			event_id TEXT PRIMARY KEY,
			operation TEXT NOT NULL,
			record_type TEXT NOT NULL,
			actor TEXT NOT NULL,
			status TEXT NOT NULL,
			agent_id TEXT,
			provider TEXT,
			account_id_key TEXT,
			name TEXT,
			error TEXT,
			created_at BIGINT NOT NULL
		)
		`,
		`
		CREATE INDEX IF NOT EXISTS idx_auth_lookup
		ON auth_secrets (agent_id, provider, account_id_key)
		`,
		`
		CREATE INDEX IF NOT EXISTS idx_pwd_lookup
		ON password_secrets (agent_id, name)
		`,
		`
		CREATE INDEX IF NOT EXISTS idx_cert_lookup
		ON certificate_secrets (agent_id, name)
		`,
		`
		CREATE INDEX IF NOT EXISTS idx_git_profile_lookup
		ON git_profiles (agent_id, name)
		`,
	}

	for _, stmt := range stmts {
		if _, err := s.db.ExecContext(context.Background(), stmt); err != nil {
			return fmt.Errorf("initialize schema: %w", err)
		}
	}

	return nil
}

func (s *KeyStore) syncKeyVersions() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.syncKeyVersionsLocked()
}

func (s *KeyStore) syncKeyVersionsLocked() error {
	now := time.Now().Unix()
	for _, version := range sortedKeys(s.keks) {
		if _, err := s.db.ExecContext(
			context.Background(),
			`
			INSERT INTO key_versions (kek_version, is_active, created_at)
			VALUES (?, ?, ?)
			ON CONFLICT (kek_version) DO UPDATE SET
				is_active = excluded.is_active
			`,
			version,
			version == s.activeKEKVersion,
			now,
		); err != nil {
			return fmt.Errorf("sync key version %s: %w", version, err)
		}
	}

	if _, err := s.db.ExecContext(
		context.Background(),
		`
		UPDATE key_versions
		SET is_active = FALSE
		WHERE kek_version <> ?
		`,
		s.activeKEKVersion,
	); err != nil {
		return fmt.Errorf("deactivate old key versions: %w", err)
	}

	return nil
}

func (s *KeyStore) auditLocked(event auditEvent) error {
	_, err := s.db.ExecContext(
		context.Background(),
		`
		INSERT INTO audit_log (
			event_id,
			operation,
			record_type,
			actor,
			status,
			agent_id,
			provider,
			account_id_key,
			name,
			error,
			created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`,
		uuid.NewString(),
		event.Operation,
		event.RecordType,
		event.Actor,
		event.Status,
		nullIfBlank(event.AgentID),
		nullIfBlank(event.Provider),
		nullIfBlank(event.AccountIDKey),
		nullIfBlank(event.Name),
		nullIfBlank(event.Error),
		time.Now().Unix(),
	)
	if err != nil {
		return fmt.Errorf("write audit log: %w", err)
	}
	return nil
}

func loadKEKs(overrideKEKs map[string]string, overrideActiveVersion string) (map[string][]byte, string, error) {
	var raw map[string]string

	if len(overrideKEKs) > 0 {
		raw = overrideKEKs
	} else {
		envJSON := strings.TrimSpace(os.Getenv(keksEnv))
		if envJSON != "" {
			if err := json.Unmarshal([]byte(envJSON), &raw); err != nil {
				return nil, "", &KeyStoreConfigError{Message: fmt.Sprintf("%s is not valid JSON", keksEnv)}
			}
			if len(raw) == 0 {
				return nil, "", &KeyStoreConfigError{Message: fmt.Sprintf("%s must be a non-empty JSON object", keksEnv)}
			}
		} else {
			legacyKey := strings.TrimSpace(os.Getenv(legacyMasterKeyEnv))
			if legacyKey == "" {
				return nil, "", &KeyStoreConfigError{
					Message: fmt.Sprintf("Set %s (JSON map) or legacy %s.", keksEnv, legacyMasterKeyEnv),
				}
			}
			raw = map[string]string{"v1": legacyKey}
		}
	}

	decoded := make(map[string][]byte, len(raw))
	for version, keyB64 := range raw {
		key, err := decodeKey(keyB64, version)
		if err != nil {
			return nil, "", err
		}
		decoded[version] = key
	}

	activeVersion := strings.TrimSpace(overrideActiveVersion)
	if activeVersion == "" {
		activeVersion = strings.TrimSpace(os.Getenv(activeKEKVersionEnv))
	}
	if activeVersion == "" {
		versions := sortedKeys(decoded)
		activeVersion = versions[len(versions)-1]
	}

	if _, ok := decoded[activeVersion]; !ok {
		return nil, "", &KeyStoreConfigError{
			Message: fmt.Sprintf("Active KEK version '%s' is not available in configured keys", activeVersion),
		}
	}

	return decoded, activeVersion, nil
}

func decodeKey(keyB64, version string) ([]byte, error) {
	key, err := base64.URLEncoding.DecodeString(keyB64)
	if err != nil {
		key, err = base64.RawURLEncoding.DecodeString(keyB64)
		if err != nil {
			return nil, &KeyStoreConfigError{
				Message: fmt.Sprintf("KEK '%s' is not valid URL-safe base64", version),
			}
		}
	}
	if len(key) != 32 {
		return nil, &KeyStoreConfigError{
			Message: fmt.Sprintf("KEK '%s' must decode to 32 bytes", version),
		}
	}
	return key, nil
}

func aad(parts ...string) []byte {
	return []byte(strings.Join(parts, "|"))
}

func accountIDKey(accountID *string) string {
	if accountID == nil {
		return ""
	}
	return strings.TrimSpace(*accountID)
}

func (s *KeyStore) wrapDEK(dek []byte, kekVersion, recordType, agentID, recordIdentity string) ([]byte, []byte, error) {
	kek, ok := s.keks[kekVersion]
	if !ok {
		return nil, nil, &KeyStoreConfigError{
			Message: fmt.Sprintf("Cannot encrypt record with missing KEK '%s'", kekVersion),
		}
	}
	nonce, err := randomBytes(12)
	if err != nil {
		return nil, nil, err
	}
	ciphertext, err := encryptAESGCM(kek, nonce, dek, aad("wrap", recordType, agentID, recordIdentity, kekVersion))
	if err != nil {
		return nil, nil, err
	}
	return nonce, ciphertext, nil
}

func (s *KeyStore) unwrapDEK(wrappedDEKNonce, wrappedDEK []byte, kekVersion, recordType, agentID, recordIdentity string) ([]byte, error) {
	kek, ok := s.keks[kekVersion]
	if !ok {
		return nil, &KeyStoreConfigError{
			Message: fmt.Sprintf("Cannot decrypt record wrapped with KEK '%s' because that key is not loaded", kekVersion),
		}
	}
	return decryptAESGCM(kek, wrappedDEKNonce, wrappedDEK, aad("wrap", recordType, agentID, recordIdentity, kekVersion))
}

func encryptWithDEK(dek []byte, plaintext string, associatedData []byte) ([]byte, []byte, error) {
	nonce, err := randomBytes(12)
	if err != nil {
		return nil, nil, err
	}
	ciphertext, err := encryptAESGCM(dek, nonce, []byte(plaintext), associatedData)
	if err != nil {
		return nil, nil, err
	}
	return nonce, ciphertext, nil
}

func decryptWithDEK(dek, nonce, ciphertext, associatedData []byte) (string, error) {
	plaintext, err := decryptAESGCM(dek, nonce, ciphertext, associatedData)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func encryptAESGCM(key, nonce, plaintext, associatedData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}
	return aead.Seal(nil, nonce, plaintext, associatedData), nil
}

func decryptAESGCM(key, nonce, ciphertext, associatedData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, associatedData)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func validateNonEmpty(value, name string) error {
	if strings.TrimSpace(value) == "" {
		return &ValidationError{Message: fmt.Sprintf("%s must be a non-empty string", name)}
	}
	return nil
}

func duckDBDSN(dbPath string) string {
	if strings.Contains(dbPath, "?") {
		return dbPath + "&access_mode=READ_WRITE"
	}
	return dbPath + "?access_mode=READ_WRITE"
}

func localDBFilePath(dbPath string) string {
	filePath, _, _ := strings.Cut(dbPath, "?")
	return filePath
}

func ensurePrivateDirectory(dirPath string) error {
	if dirPath == "" || dirPath == "." {
		return nil
	}
	if err := os.MkdirAll(dirPath, 0o700); err != nil {
		return fmt.Errorf("create db directory: %w", err)
	}
	if err := os.Chmod(dirPath, 0o700); err != nil {
		return fmt.Errorf("chmod db directory: %w", err)
	}
	return nil
}

func ensurePrivateFile(filePath string) error {
	if filePath == "" {
		return nil
	}
	info, err := os.Stat(filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("stat db file: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("db path is a directory: %s", filePath)
	}
	if err := os.Chmod(filePath, 0o600); err != nil {
		return fmt.Errorf("chmod db file: %w", err)
	}
	return nil
}

func defaultMetadata(metadata map[string]any) map[string]any {
	if metadata == nil {
		return map[string]any{}
	}
	return metadata
}

func defaultStringSlice(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func nilIfEmpty(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return value
}

func nullIfBlank(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}

func randomBytes(size int) ([]byte, error) {
	buf := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return nil, fmt.Errorf("read random bytes: %w", err)
	}
	return buf, nil
}

func nullStringPtr(value sql.NullString) *string {
	if !value.Valid {
		return nil
	}
	v := value.String
	return &v
}

func derefString(value *string) any {
	if value == nil {
		return nil
	}
	return *value
}

func defaultActor(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func sortedKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func ternaryStatus(deleted bool) string {
	if deleted {
		return "ok"
	}
	return "miss"
}

func bearerTokenMatches(presented, expected string) bool {
	return subtle.ConstantTimeCompare([]byte(presented), []byte(expected)) == 1
}
