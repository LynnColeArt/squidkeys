package squidkeys

import (
	"context"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestMCPToolFunctions(t *testing.T) {
	store := newTestStore(t)
	defer store.Close()

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

	savePwd, err := clientSession.CallTool(ctx, &mcp.CallToolParams{
		Name: "save_password",
		Arguments: map[string]any{
			"agent_id": "agent-1",
			"name":     "service",
			"password": "mcp-secret",
		},
	})
	if err != nil {
		t.Fatalf("save_password: %v", err)
	}
	if got := structuredMap(t, savePwd)["password"]; got != "mcp-secret" {
		t.Fatalf("password mismatch: %#v", got)
	}

	getPwd, err := clientSession.CallTool(ctx, &mcp.CallToolParams{
		Name: "get_password",
		Arguments: map[string]any{
			"agent_id": "agent-1",
			"name":     "service",
		},
	})
	if err != nil {
		t.Fatalf("get_password: %v", err)
	}
	if got := structuredMap(t, getPwd)["password"]; got != "mcp-secret" {
		t.Fatalf("password mismatch: %#v", got)
	}

	saveAuth, err := clientSession.CallTool(ctx, &mcp.CallToolParams{
		Name: "save_authorization",
		Arguments: map[string]any{
			"agent_id":     "agent-1",
			"provider":     "discord",
			"access_token": "mcp-token",
		},
	})
	if err != nil {
		t.Fatalf("save_authorization: %v", err)
	}
	if got := structuredMap(t, saveAuth)["access_token"]; got != "mcp-token" {
		t.Fatalf("access token mismatch: %#v", got)
	}

	getAuth, err := clientSession.CallTool(ctx, &mcp.CallToolParams{
		Name: "get_authorization",
		Arguments: map[string]any{
			"agent_id": "agent-1",
			"provider": "discord",
		},
	})
	if err != nil {
		t.Fatalf("get_authorization: %v", err)
	}
	if got := structuredMap(t, getAuth)["access_token"]; got != "mcp-token" {
		t.Fatalf("access token mismatch: %#v", got)
	}

	status, err := clientSession.CallTool(ctx, &mcp.CallToolParams{
		Name:      "key_status",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatalf("key_status: %v", err)
	}
	if got := structuredMap(t, status)["active_kek_version"]; got != "v1" {
		t.Fatalf("active key mismatch: %#v", got)
	}

	delPwd, err := clientSession.CallTool(ctx, &mcp.CallToolParams{
		Name: "delete_password",
		Arguments: map[string]any{
			"agent_id": "agent-1",
			"name":     "service",
		},
	})
	if err != nil {
		t.Fatalf("delete_password: %v", err)
	}
	if got := structuredMap(t, delPwd)["deleted"]; got != true {
		t.Fatalf("delete password mismatch: %#v", got)
	}

	delAuth, err := clientSession.CallTool(ctx, &mcp.CallToolParams{
		Name: "delete_authorization",
		Arguments: map[string]any{
			"agent_id": "agent-1",
			"provider": "discord",
		},
	})
	if err != nil {
		t.Fatalf("delete_authorization: %v", err)
	}
	if got := structuredMap(t, delAuth)["deleted"]; got != true {
		t.Fatalf("delete authorization mismatch: %#v", got)
	}
}

func structuredMap(t *testing.T, result *mcp.CallToolResult) map[string]any {
	t.Helper()
	value, ok := result.StructuredContent.(map[string]any)
	if !ok {
		t.Fatalf("expected structured object, got %#v", result.StructuredContent)
	}
	return value
}

func TestParseStrictRFC3339UTCRejectsNaiveTimestamp(t *testing.T) {
	if _, err := parseStrictRFC3339UTC("2026-02-09T10:00:00"); err == nil {
		t.Fatal("expected naive timestamp to be rejected")
	}
}

func TestParseStrictRFC3339UTCNormalizesOffsetToUTC(t *testing.T) {
	got, err := parseStrictRFC3339UTC("2026-02-09T04:00:00-06:00")
	if err != nil {
		t.Fatalf("parse strict timestamp: %v", err)
	}

	want := time.Date(2026, 2, 9, 10, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("got %s, want %s", got.Format(time.RFC3339), want.Format(time.RFC3339))
	}
	if got.Location() != time.UTC {
		t.Fatalf("expected UTC location, got %s", got.Location())
	}
}
