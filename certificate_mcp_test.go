package squidkeys

import (
	"context"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestMCPCertificateTools(t *testing.T) {
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

	bundle := makeTestCertificateBundle(t)
	saveResult, err := clientSession.CallTool(ctx, &mcp.CallToolParams{
		Name: "save_certificate",
		Arguments: map[string]any{
			"agent_id":               "agent-1",
			"name":                   "mtls-client",
			"certificate_chain_pem":  bundle.CertificateChainPEM,
			"private_key_pem":        bundle.PrivateKeyPEM,
			"private_key_passphrase": bundle.PrivateKeyPassphrase,
		},
	})
	if err != nil {
		t.Fatalf("save_certificate: %v", err)
	}
	if got := structuredMap(t, saveResult)["fingerprint_sha256"]; got != bundle.FingerprintSHA256 {
		t.Fatalf("fingerprint mismatch: %#v", got)
	}

	getResult, err := clientSession.CallTool(ctx, &mcp.CallToolParams{
		Name: "get_certificate",
		Arguments: map[string]any{
			"agent_id": "agent-1",
			"name":     "mtls-client",
		},
	})
	if err != nil {
		t.Fatalf("get_certificate: %v", err)
	}
	if got := structuredMap(t, getResult)["subject_common_name"]; got != bundle.SubjectCommonName {
		t.Fatalf("subject common name mismatch: %#v", got)
	}

	deleteResult, err := clientSession.CallTool(ctx, &mcp.CallToolParams{
		Name: "delete_certificate",
		Arguments: map[string]any{
			"agent_id": "agent-1",
			"name":     "mtls-client",
		},
	})
	if err != nil {
		t.Fatalf("delete_certificate: %v", err)
	}
	if got := structuredMap(t, deleteResult)["deleted"]; got != true {
		t.Fatalf("delete mismatch: %#v", got)
	}
}
