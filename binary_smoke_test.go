package squidkeys

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestAPIBinarySmoke(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping binary smoke test in short mode")
	}

	binaryPath := buildBinary(t, "squidkeys-api", "./cmd/squidkeys-api")
	dbPath := filepath.Join(t.TempDir(), "api-binary.duckdb")
	port := freeTCPPort(t)
	baseURL := fmt.Sprintf("http://127.0.0.1:%s", port)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, binaryPath)
	cmd.Env = append(os.Environ(),
		"KEY_STORE_MASTER_KEY="+GenerateKey(),
		"KEY_STORE_DB_PATH="+dbPath,
		"KEY_STORE_API_HOST=127.0.0.1",
		"KEY_STORE_API_PORT="+port,
	)

	var logs bytes.Buffer
	cmd.Stdout = &logs
	cmd.Stderr = &logs

	if err := cmd.Start(); err != nil {
		t.Fatalf("start api binary: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	})

	waitForHTTPReady(t, baseURL+"/health", &logs, done)

	saveResp := doJSONRequest(t, http.MethodPut, baseURL+"/v1/passwords", map[string]any{
		"agent_id": "binary-agent",
		"name":     "service-token",
		"password": "super-secret",
	})
	if saveResp.StatusCode != http.StatusOK {
		t.Fatalf("save status = %d", saveResp.StatusCode)
	}

	var saved PasswordRecord
	decodeJSON(t, saveResp, &saved)
	if saved.Password != "super-secret" {
		t.Fatalf("saved password mismatch: %q", saved.Password)
	}

	getResp, err := http.Get(baseURL + "/v1/passwords/binary-agent/service-token")
	if err != nil {
		t.Fatalf("get password: %v", err)
	}
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("get status = %d", getResp.StatusCode)
	}

	var got PasswordRecord
	decodeJSON(t, getResp, &got)
	if got.Password != "super-secret" {
		t.Fatalf("retrieved password mismatch: %q", got.Password)
	}
}

func TestMCPBinarySmoke(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping binary smoke test in short mode")
	}

	binaryPath := buildBinary(t, "squidkeys-mcp", "./cmd/squidkeys-mcp")
	dbPath := filepath.Join(t.TempDir(), "mcp-binary.duckdb")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, binaryPath)
	cmd.Env = append(os.Environ(),
		"KEY_STORE_MASTER_KEY="+GenerateKey(),
		"KEY_STORE_DB_PATH="+dbPath,
		"KEY_STORE_MCP_TRANSPORT=stdio",
	)

	client := mcp.NewClient(&mcp.Implementation{Name: "binary-smoke-client", Version: "v0.0.1"}, nil)
	session, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatalf("connect mcp command transport: %v", err)
	}
	defer session.Close()

	saveResult, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "save_password",
		Arguments: map[string]any{
			"agent_id": "binary-agent",
			"name":     "service-token",
			"password": "super-secret",
		},
	})
	if err != nil {
		t.Fatalf("save_password via binary: %v", err)
	}
	if got := structuredMap(t, saveResult)["password"]; got != "super-secret" {
		t.Fatalf("save_password mismatch: %#v", got)
	}

	getResult, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "get_password",
		Arguments: map[string]any{
			"agent_id": "binary-agent",
			"name":     "service-token",
		},
	})
	if err != nil {
		t.Fatalf("get_password via binary: %v", err)
	}
	if got := structuredMap(t, getResult)["password"]; got != "super-secret" {
		t.Fatalf("get_password mismatch: %#v", got)
	}
}

func buildBinary(t *testing.T, name, pkg string) string {
	t.Helper()

	binaryPath := filepath.Join(t.TempDir(), name)
	cmd := exec.Command("go", "build", "-o", binaryPath, pkg)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build %s: %v\n%s", name, err, output)
	}
	return binaryPath
}

func freeTCPPort(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate tcp port: %v", err)
	}
	defer listener.Close()

	return fmt.Sprintf("%d", listener.Addr().(*net.TCPAddr).Port)
}

func waitForHTTPReady(t *testing.T, url string, logs *bytes.Buffer, done <-chan error) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			t.Fatalf("new health request: %v", err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				var payload map[string]string
				if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
					t.Fatalf("decode health response: %v", err)
				}
				if payload["status"] == "ok" {
					return
				}
			}
		}

		select {
		case err := <-done:
			t.Fatalf("api binary exited before ready: %v\nlogs:\n%s", err, logs.String())
		default:
		}

		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf("timed out waiting for api binary readiness\nlogs:\n%s", logs.String())
}
