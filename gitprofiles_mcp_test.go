package squidkeys

import (
	"context"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestMCPGitProfileTools(t *testing.T) {
	store := newTestStore(t)
	defer store.Close()

	bundle := makeTestCertificateBundle(t)
	if err := seedGitProfileSecrets(store, bundle); err != nil {
		t.Fatalf("seed git profile secrets: %v", err)
	}

	ctx := context.Background()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	server := NewMCPServer(store)

	serverSession, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatalf("connect server: %v", err)
	}
	defer serverSession.Close()

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "v0.0.1"}, nil)
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("connect client: %v", err)
	}
	defer clientSession.Close()

	saveResult, err := clientSession.CallTool(ctx, &mcp.CallToolParams{
		Name: "save_git_profile",
		Arguments: map[string]any{
			"agent_id":            "agent-1",
			"name":                "work",
			"platform":            "github",
			"git_username":        "workuser",
			"git_email":           "work@example.com",
			"preferred_transport": "ssh",
			"https_credential_ref": map[string]any{
				"record_type": "authorization",
				"provider":    "github",
				"account_id":  "user-1",
			},
			"ssh_identity_ref": map[string]any{
				"record_type": "password",
				"name":        "github-work-ssh",
			},
			"signing_identity_ref": map[string]any{
				"record_type": "certificate",
				"name":        "github-work-signing",
			},
			"signing_format": "x509",
		},
	})
	if err != nil {
		t.Fatalf("save_git_profile: %v", err)
	}
	if got := structuredMap(t, saveResult)["git_email"]; got != "work@example.com" {
		t.Fatalf("git email mismatch: %#v", got)
	}

	getResult, err := clientSession.CallTool(ctx, &mcp.CallToolParams{
		Name: "get_git_profile",
		Arguments: map[string]any{
			"agent_id": "agent-1",
			"name":     "work",
		},
	})
	if err != nil {
		t.Fatalf("get_git_profile: %v", err)
	}
	if got := structuredMap(t, getResult)["platform"]; got != "github" {
		t.Fatalf("platform mismatch: %#v", got)
	}

	listResult, err := clientSession.CallTool(ctx, &mcp.CallToolParams{
		Name: "list_git_profiles",
		Arguments: map[string]any{
			"agent_id": "agent-1",
		},
	})
	if err != nil {
		t.Fatalf("list_git_profiles: %v", err)
	}
	listed, ok := listResult.StructuredContent.([]any)
	if !ok {
		t.Fatalf("expected list result, got %#v", listResult.StructuredContent)
	}
	if len(listed) != 1 {
		t.Fatalf("unexpected list length: %d", len(listed))
	}

	deleteResult, err := clientSession.CallTool(ctx, &mcp.CallToolParams{
		Name: "delete_git_profile",
		Arguments: map[string]any{
			"agent_id": "agent-1",
			"name":     "work",
		},
	})
	if err != nil {
		t.Fatalf("delete_git_profile: %v", err)
	}
	if got := structuredMap(t, deleteResult)["deleted"]; got != true {
		t.Fatalf("delete mismatch: %#v", got)
	}
}
