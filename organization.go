package squidkeys

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// OrganizationPolicy is an immutable, opt-in authorization boundary for the
// HTTP API. Tokens are held by installations; only SHA-256 digests are stored
// in the policy file. Policy rotation requires an API restart.
type OrganizationPolicy struct {
	principals []organizationPrincipal
}

type organizationPrincipal struct {
	id     string
	digest [sha256.Size]byte
	admin  bool
	reads  map[organizationGrant]struct{}
}

type organizationGrant struct {
	typeName  string
	agentID   string
	name      string
	accountID string
}

type organizationPrincipalContextKey struct{}

type organizationPolicyJSON struct {
	Version    int                         `json:"version"`
	Principals []organizationPrincipalJSON `json:"principals"`
}

type organizationPrincipalJSON struct {
	ID          string                  `json:"id"`
	TokenSHA256 string                  `json:"token_sha256"`
	Admin       bool                    `json:"admin"`
	Read        []organizationGrantJSON `json:"read"`
}

type organizationGrantJSON struct {
	RecordType string `json:"record_type"`
	AgentID    string `json:"agent_id"`
	Name       string `json:"name"`
	Provider   string `json:"provider"`
	AccountID  string `json:"account_id"`
}

// LoadOrganizationPolicy reads a strictly validated policy from a local file.
func LoadOrganizationPolicy(path string) (*OrganizationPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read organization policy: %w", err)
	}
	return ParseOrganizationPolicy(data)
}

// ParseOrganizationPolicy rejects ambiguous or overbroad grants. Each
// non-admin principal can read only named records; it cannot list or mutate.
func ParseOrganizationPolicy(data []byte) (*OrganizationPolicy, error) {
	var input organizationPolicyJSON
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return nil, fmt.Errorf("decode organization policy: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("organization policy contains trailing data")
	}
	if input.Version != 1 || len(input.Principals) == 0 {
		return nil, errors.New("organization policy requires version 1 and at least one principal")
	}
	policy := &OrganizationPolicy{}
	ids := map[string]bool{}
	digests := map[[sha256.Size]byte]bool{}
	adminCount := 0
	for _, raw := range input.Principals {
		if !validPolicyComponent(raw.ID) || ids[raw.ID] {
			return nil, errors.New("organization principal IDs must be unique and nonempty")
		}
		if len(raw.TokenSHA256) != sha256.Size*2 || strings.ToLower(raw.TokenSHA256) != raw.TokenSHA256 {
			return nil, fmt.Errorf("principal %q requires a lowercase SHA-256 token digest", raw.ID)
		}
		decoded, err := hex.DecodeString(raw.TokenSHA256)
		if err != nil {
			return nil, fmt.Errorf("principal %q has invalid token digest", raw.ID)
		}
		var digest [sha256.Size]byte
		copy(digest[:], decoded)
		if digests[digest] {
			return nil, errors.New("organization principals must not share tokens")
		}
		if raw.Admin && len(raw.Read) != 0 {
			return nil, fmt.Errorf("admin principal %q must not have read grants", raw.ID)
		}
		if !raw.Admin && len(raw.Read) == 0 {
			return nil, fmt.Errorf("reader principal %q requires at least one read grant", raw.ID)
		}
		principal := organizationPrincipal{id: raw.ID, digest: digest, admin: raw.Admin, reads: map[organizationGrant]struct{}{}}
		if raw.Admin {
			adminCount++
		}
		for _, read := range raw.Read {
			if !validPolicyComponent(read.AgentID) {
				return nil, fmt.Errorf("principal %q has empty agent_id", raw.ID)
			}
			grant := organizationGrant{typeName: read.RecordType, agentID: read.AgentID}
			switch read.RecordType {
			case "authorization":
				if read.Provider == "" || read.Name != "" {
					return nil, fmt.Errorf("principal %q has invalid authorization grant", raw.ID)
				}
				grant.name, grant.accountID = read.Provider, read.AccountID
			case "password", "certificate", "git_profile":
				if read.Name == "" || read.Provider != "" || read.AccountID != "" {
					return nil, fmt.Errorf("principal %q has invalid named-record grant", raw.ID)
				}
				grant.name = read.Name
			default:
				return nil, fmt.Errorf("principal %q has unknown record type", raw.ID)
			}
			if !validPolicyComponent(grant.name) || grant.accountID != "" && !validPolicyComponent(grant.accountID) {
				return nil, fmt.Errorf("principal %q has untrimmed grant value", raw.ID)
			}
			if _, exists := principal.reads[grant]; exists {
				return nil, fmt.Errorf("principal %q has duplicate read grant", raw.ID)
			}
			principal.reads[grant] = struct{}{}
		}
		ids[raw.ID], digests[digest] = true, true
		policy.principals = append(policy.principals, principal)
	}
	if adminCount == 0 {
		return nil, errors.New("organization policy requires an admin principal")
	}
	return policy, nil
}

func validPolicyComponent(value string) bool {
	return value != "" && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "*\r\n\t")
}

func (p *OrganizationPolicy) guard(kind string, next http.HandlerFunc) http.HandlerFunc {
	if kind == "health" {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, "Bearer ") || len(header) <= len("Bearer ") {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		digest := sha256.Sum256([]byte(strings.TrimPrefix(header, "Bearer ")))
		var matched *organizationPrincipal
		for i := range p.principals {
			if subtle.ConstantTimeCompare(digest[:], p.principals[i].digest[:]) == 1 {
				matched = &p.principals[i]
			}
		}
		if matched == nil {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeError(w, http.StatusUnauthorized, "invalid bearer token")
			return
		}
		if !matched.admin {
			grant := organizationGrant{typeName: kind, agentID: r.PathValue("agent_id"), name: r.PathValue("name")}
			if kind == "authorization" {
				grant.name = r.PathValue("provider")
				values, exists := r.URL.Query()["account_id"]
				if !exists || len(values) != 1 {
					writeError(w, http.StatusForbidden, "exact account_id is required")
					return
				}
				grant.accountID = values[0]
			}
			if _, allowed := matched.reads[grant]; !allowed {
				writeError(w, http.StatusForbidden, "record access denied")
				return
			}
		}
		r = r.WithContext(context.WithValue(r.Context(), organizationPrincipalContextKey{}, matched.id))
		next(w, r)
	}
}

func requestActor(r *http.Request, supplied string) string {
	if principalID, ok := r.Context().Value(organizationPrincipalContextKey{}).(string); ok {
		return "organization:" + principalID
	}
	return defaultActor(supplied, "api")
}
