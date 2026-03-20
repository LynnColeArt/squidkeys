package squidkeys

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type authorizationToolInput struct {
	AgentID      string         `json:"agent_id" jsonschema:"agent identifier"`
	Provider     string         `json:"provider" jsonschema:"authorization provider"`
	AccessToken  string         `json:"access_token" jsonschema:"access token to store"`
	AccountID    *string        `json:"account_id,omitempty" jsonschema:"optional account identifier"`
	RefreshToken *string        `json:"refresh_token,omitempty" jsonschema:"optional refresh token"`
	TokenType    *string        `json:"token_type,omitempty" jsonschema:"optional token type"`
	Scopes       []string       `json:"scopes,omitempty" jsonschema:"optional authorization scopes"`
	ExpiresAtISO *string        `json:"expires_at_iso,omitempty" jsonschema:"optional RFC3339 expiration timestamp"`
	Metadata     map[string]any `json:"metadata,omitempty" jsonschema:"optional metadata object"`
	Actor        string         `json:"actor,omitempty" jsonschema:"actor performing the operation"`
}

type authorizationLookupInput struct {
	AgentID   string  `json:"agent_id" jsonschema:"agent identifier"`
	Provider  string  `json:"provider" jsonschema:"authorization provider"`
	AccountID *string `json:"account_id,omitempty" jsonschema:"optional account identifier"`
	Actor     string  `json:"actor,omitempty" jsonschema:"actor performing the operation"`
}

type passwordToolInput struct {
	AgentID  string         `json:"agent_id" jsonschema:"agent identifier"`
	Name     string         `json:"name" jsonschema:"password record name"`
	Password string         `json:"password" jsonschema:"password value"`
	Username *string        `json:"username,omitempty" jsonschema:"optional username"`
	URL      *string        `json:"url,omitempty" jsonschema:"optional URL"`
	Metadata map[string]any `json:"metadata,omitempty" jsonschema:"optional metadata object"`
	Actor    string         `json:"actor,omitempty" jsonschema:"actor performing the operation"`
}

type passwordLookupInput struct {
	AgentID string `json:"agent_id" jsonschema:"agent identifier"`
	Name    string `json:"name" jsonschema:"password record name"`
	Actor   string `json:"actor,omitempty" jsonschema:"actor performing the operation"`
}

type certificateToolInput struct {
	AgentID              string         `json:"agent_id" jsonschema:"agent identifier"`
	Name                 string         `json:"name" jsonschema:"certificate record name"`
	CertificateChainPEM  string         `json:"certificate_chain_pem" jsonschema:"PEM-encoded certificate chain"`
	PrivateKeyPEM        *string        `json:"private_key_pem,omitempty" jsonschema:"optional PEM-encoded private key"`
	PrivateKeyPassphrase *string        `json:"private_key_passphrase,omitempty" jsonschema:"optional private key passphrase"`
	Metadata             map[string]any `json:"metadata,omitempty" jsonschema:"optional metadata object"`
	Actor                string         `json:"actor,omitempty" jsonschema:"actor performing the operation"`
}

type certificateLookupInput struct {
	AgentID string `json:"agent_id" jsonschema:"agent identifier"`
	Name    string `json:"name" jsonschema:"certificate record name"`
	Actor   string `json:"actor,omitempty" jsonschema:"actor performing the operation"`
}

type gitProfileToolInput struct {
	AgentID            string         `json:"agent_id" jsonschema:"agent identifier"`
	Name               string         `json:"name" jsonschema:"git profile name"`
	Platform           string         `json:"platform" jsonschema:"git platform identifier"`
	Host               *string        `json:"host,omitempty" jsonschema:"optional host override"`
	GitUsername        string         `json:"git_username" jsonschema:"git username for this profile"`
	GitEmail           string         `json:"git_email" jsonschema:"git email for this profile"`
	PreferredTransport *string        `json:"preferred_transport,omitempty" jsonschema:"optional preferred transport: ssh or https"`
	HTTPSCredentialRef *SecretRef     `json:"https_credential_ref,omitempty" jsonschema:"optional ref to a stored HTTPS credential"`
	SSHIdentityRef     *SecretRef     `json:"ssh_identity_ref,omitempty" jsonschema:"optional ref to a stored SSH identity secret"`
	SigningIdentityRef *SecretRef     `json:"signing_identity_ref,omitempty" jsonschema:"optional ref to a stored signing identity secret"`
	SigningFormat      *string        `json:"signing_format,omitempty" jsonschema:"optional signing format: ssh, gpg, or x509"`
	RepoMatchers       []string       `json:"repo_matchers,omitempty" jsonschema:"optional repository matcher list"`
	Metadata           map[string]any `json:"metadata,omitempty" jsonschema:"optional metadata object"`
	Actor              string         `json:"actor,omitempty" jsonschema:"actor performing the operation"`
}

type gitProfileLookupInput struct {
	AgentID string `json:"agent_id" jsonschema:"agent identifier"`
	Name    string `json:"name" jsonschema:"git profile name"`
	Actor   string `json:"actor,omitempty" jsonschema:"actor performing the operation"`
}

type gitProfileListInput struct {
	AgentID  *string `json:"agent_id,omitempty" jsonschema:"optional agent filter"`
	Platform *string `json:"platform,omitempty" jsonschema:"optional platform filter"`
	Actor    string  `json:"actor,omitempty" jsonschema:"actor performing the operation"`
}

type rewrapToolInput struct {
	TargetKEKVersion string `json:"target_kek_version,omitempty" jsonschema:"target KEK version"`
	Actor            string `json:"actor,omitempty" jsonschema:"actor performing the operation"`
}

func NewMCPServer(store *KeyStore) *mcp.Server {
	if store == nil {
		panic("squidkeys: nil store")
	}

	server := mcp.NewServer(&mcp.Implementation{
		Name:    "SquidKeys",
		Version: Version,
	}, nil)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "save_authorization",
		Description: "Store or update an authorization token record",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in authorizationToolInput) (*mcp.CallToolResult, any, error) {
		var expiresAt *time.Time
		if in.ExpiresAtISO != nil {
			parsed, err := parseStrictRFC3339UTC(*in.ExpiresAtISO)
			if err != nil {
				return nil, nil, err
			}
			expiresAt = &parsed
		}

		input := AuthorizationUpsertInput{
			AgentID:      in.AgentID,
			Provider:     in.Provider,
			AccessToken:  in.AccessToken,
			AccountID:    in.AccountID,
			RefreshToken: in.RefreshToken,
			TokenType:    in.TokenType,
			Scopes:       in.Scopes,
			Metadata:     in.Metadata,
			Actor:        defaultActor(in.Actor, "mcp"),
		}
		if expiresAt != nil {
			t := *expiresAt
			input.ExpiresAt = &t
		}

		if err := store.SaveAuthorization(input); err != nil {
			return nil, nil, err
		}
		record, err := store.GetAuthorization(in.AgentID, in.Provider, in.AccountID, input.Actor)
		return nil, record, err
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_authorization",
		Description: "Fetch a stored authorization token record",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in authorizationLookupInput) (*mcp.CallToolResult, any, error) {
		record, err := store.GetAuthorization(in.AgentID, in.Provider, in.AccountID, defaultActor(in.Actor, "mcp"))
		return nil, record, err
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "delete_authorization",
		Description: "Delete an authorization token record",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in authorizationLookupInput) (*mcp.CallToolResult, any, error) {
		deleted, err := store.DeleteAuthorization(in.AgentID, in.Provider, in.AccountID, defaultActor(in.Actor, "mcp"))
		if err != nil {
			return nil, nil, err
		}
		return nil, DeleteResponse{Deleted: deleted}, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "save_password",
		Description: "Store or update a password secret",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in passwordToolInput) (*mcp.CallToolResult, any, error) {
		input := PasswordUpsertInput{
			AgentID:  in.AgentID,
			Name:     in.Name,
			Password: in.Password,
			Username: in.Username,
			URL:      in.URL,
			Metadata: in.Metadata,
			Actor:    defaultActor(in.Actor, "mcp"),
		}
		if err := store.SavePassword(input); err != nil {
			return nil, nil, err
		}
		record, err := store.GetPassword(in.AgentID, in.Name, input.Actor)
		return nil, record, err
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_password",
		Description: "Fetch a stored password secret",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in passwordLookupInput) (*mcp.CallToolResult, any, error) {
		record, err := store.GetPassword(in.AgentID, in.Name, defaultActor(in.Actor, "mcp"))
		return nil, record, err
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "delete_password",
		Description: "Delete a stored password secret",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in passwordLookupInput) (*mcp.CallToolResult, any, error) {
		deleted, err := store.DeletePassword(in.AgentID, in.Name, defaultActor(in.Actor, "mcp"))
		if err != nil {
			return nil, nil, err
		}
		return nil, DeleteResponse{Deleted: deleted}, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "save_certificate",
		Description: "Store or update a certificate bundle with derived X.509 metadata",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in certificateToolInput) (*mcp.CallToolResult, any, error) {
		input := CertificateUpsertInput{
			AgentID:              in.AgentID,
			Name:                 in.Name,
			CertificateChainPEM:  in.CertificateChainPEM,
			PrivateKeyPEM:        in.PrivateKeyPEM,
			PrivateKeyPassphrase: in.PrivateKeyPassphrase,
			Metadata:             in.Metadata,
			Actor:                defaultActor(in.Actor, "mcp"),
		}
		if err := store.SaveCertificate(input); err != nil {
			return nil, nil, err
		}
		record, err := store.GetCertificate(in.AgentID, in.Name, input.Actor)
		return nil, record, err
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_certificate",
		Description: "Fetch a stored certificate bundle",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in certificateLookupInput) (*mcp.CallToolResult, any, error) {
		record, err := store.GetCertificate(in.AgentID, in.Name, defaultActor(in.Actor, "mcp"))
		return nil, record, err
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "delete_certificate",
		Description: "Delete a stored certificate bundle",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in certificateLookupInput) (*mcp.CallToolResult, any, error) {
		deleted, err := store.DeleteCertificate(in.AgentID, in.Name, defaultActor(in.Actor, "mcp"))
		if err != nil {
			return nil, nil, err
		}
		return nil, DeleteResponse{Deleted: deleted}, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "save_git_profile",
		Description: "Store or update a Git profile manifest that references other stored secrets",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in gitProfileToolInput) (*mcp.CallToolResult, any, error) {
		input := GitProfileUpsertInput{
			AgentID:            in.AgentID,
			Name:               in.Name,
			Platform:           in.Platform,
			Host:               in.Host,
			GitUsername:        in.GitUsername,
			GitEmail:           in.GitEmail,
			PreferredTransport: in.PreferredTransport,
			HTTPSCredentialRef: in.HTTPSCredentialRef,
			SSHIdentityRef:     in.SSHIdentityRef,
			SigningIdentityRef: in.SigningIdentityRef,
			SigningFormat:      in.SigningFormat,
			RepoMatchers:       in.RepoMatchers,
			Metadata:           in.Metadata,
			Actor:              defaultActor(in.Actor, "mcp"),
		}
		if err := store.SaveGitProfile(input); err != nil {
			return nil, nil, err
		}
		record, err := store.GetGitProfile(in.AgentID, in.Name, input.Actor)
		return nil, record, err
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_git_profile",
		Description: "Fetch a stored Git profile manifest",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in gitProfileLookupInput) (*mcp.CallToolResult, any, error) {
		record, err := store.GetGitProfile(in.AgentID, in.Name, defaultActor(in.Actor, "mcp"))
		return nil, record, err
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_git_profiles",
		Description: "List stored Git profile manifests",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in gitProfileListInput) (*mcp.CallToolResult, any, error) {
		records, err := store.ListGitProfiles(in.AgentID, in.Platform, defaultActor(in.Actor, "mcp"))
		return nil, records, err
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "delete_git_profile",
		Description: "Delete a stored Git profile manifest",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in gitProfileLookupInput) (*mcp.CallToolResult, any, error) {
		deleted, err := store.DeleteGitProfile(in.AgentID, in.Name, defaultActor(in.Actor, "mcp"))
		if err != nil {
			return nil, nil, err
		}
		return nil, DeleteResponse{Deleted: deleted}, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "key_status",
		Description: "Show loaded and active KEK versions",
	}, func(_ context.Context, _ *mcp.CallToolRequest, _ map[string]any) (*mcp.CallToolResult, any, error) {
		status, err := store.KeyStatus()
		return nil, status, err
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "rewrap_all_records",
		Description: "Re-wrap all records to the target or active KEK version",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in rewrapToolInput) (*mcp.CallToolResult, any, error) {
		result, err := store.RewrapAllRecords(in.TargetKEKVersion, defaultActor(in.Actor, "mcp"))
		return nil, result, err
	})

	return server
}

func RunMCPServer(ctx context.Context, store *KeyStore, transport string) error {
	mode := strings.TrimSpace(strings.ToLower(transport))
	if mode == "" {
		mode = "stdio"
	}
	if mode != "stdio" {
		return fmt.Errorf("unsupported KEY_STORE_MCP_TRANSPORT: %s", transport)
	}
	return NewMCPServer(store).Run(ctx, &mcp.StdioTransport{})
}

// parseStrictRFC3339UTC requires an explicit offset or Z suffix so we never
// accept naive local timestamps for secret expiry handling.
func parseStrictRFC3339UTC(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, err
	}
	return parsed.UTC(), nil
}
