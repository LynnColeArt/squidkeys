package squidkeys

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func newTestStore(t *testing.T) *KeyStore {
	t.Helper()
	store, err := NewKeyStore(filepath.Join(t.TempDir(), "test.duckdb"), KeyStoreConfig{
		KEKsB64:          map[string]string{"v1": GenerateKey()},
		ActiveKEKVersion: "v1",
	})
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	return store
}

func TestPasswordEndpoints(t *testing.T) {
	store := newTestStore(t)
	defer store.Close()

	server := httptest.NewServer(NewHTTPHandler(store))
	defer server.Close()

	saveResp := doJSONRequest(t, http.MethodPut, server.URL+"/v1/passwords", map[string]any{
		"agent_id": "agent-1",
		"name":     "github",
		"username": "svc",
		"password": "secret-123",
		"url":      "https://github.com",
	})
	if saveResp.StatusCode != http.StatusOK {
		t.Fatalf("save status = %d", saveResp.StatusCode)
	}
	var saved PasswordRecord
	decodeJSON(t, saveResp, &saved)
	if saved.Password != "secret-123" {
		t.Fatalf("saved password mismatch: %q", saved.Password)
	}

	getResp, err := http.Get(server.URL + "/v1/passwords/agent-1/github")
	if err != nil {
		t.Fatalf("get password: %v", err)
	}
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("get status = %d", getResp.StatusCode)
	}
	var got PasswordRecord
	decodeJSON(t, getResp, &got)
	if got.Username == nil || *got.Username != "svc" {
		t.Fatalf("username mismatch: %#v", got.Username)
	}

	req, err := http.NewRequest(http.MethodDelete, server.URL+"/v1/passwords/agent-1/github", nil)
	if err != nil {
		t.Fatalf("new delete request: %v", err)
	}
	delResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete password: %v", err)
	}
	if delResp.StatusCode != http.StatusOK {
		t.Fatalf("delete status = %d", delResp.StatusCode)
	}
	var deleted DeleteResponse
	decodeJSON(t, delResp, &deleted)
	if !deleted.Deleted {
		t.Fatal("expected deleted=true")
	}

	missingResp, err := http.Get(server.URL + "/v1/passwords/agent-1/github")
	if err != nil {
		t.Fatalf("get missing password: %v", err)
	}
	if missingResp.StatusCode != http.StatusNotFound {
		t.Fatalf("missing status = %d", missingResp.StatusCode)
	}
}

func TestAuthorizationEndpoints(t *testing.T) {
	store := newTestStore(t)
	defer store.Close()

	server := httptest.NewServer(NewHTTPHandler(store))
	defer server.Close()

	saveResp := doJSONRequest(t, http.MethodPut, server.URL+"/v1/authorizations", map[string]any{
		"agent_id":      "agent-1",
		"provider":      "discord",
		"account_id":    "user-1",
		"access_token":  "token-a",
		"refresh_token": "token-r",
		"scopes":        []string{"identify"},
	})
	if saveResp.StatusCode != http.StatusOK {
		t.Fatalf("save status = %d", saveResp.StatusCode)
	}
	var saved AuthorizationRecord
	decodeJSON(t, saveResp, &saved)
	if saved.AccessToken != "token-a" {
		t.Fatalf("access token mismatch: %q", saved.AccessToken)
	}

	getResp, err := http.Get(server.URL + "/v1/authorizations/agent-1/discord?account_id=user-1")
	if err != nil {
		t.Fatalf("get authorization: %v", err)
	}
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("get status = %d", getResp.StatusCode)
	}
	var got AuthorizationRecord
	decodeJSON(t, getResp, &got)
	if got.RefreshToken == nil || *got.RefreshToken != "token-r" {
		t.Fatalf("refresh token mismatch: %#v", got.RefreshToken)
	}

	req, err := http.NewRequest(http.MethodDelete, server.URL+"/v1/authorizations/agent-1/discord?account_id=user-1", nil)
	if err != nil {
		t.Fatalf("new delete request: %v", err)
	}
	delResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete authorization: %v", err)
	}
	if delResp.StatusCode != http.StatusOK {
		t.Fatalf("delete status = %d", delResp.StatusCode)
	}
	var deleted DeleteResponse
	decodeJSON(t, delResp, &deleted)
	if !deleted.Deleted {
		t.Fatal("expected deleted=true")
	}
}

func TestAuthorizationEndpointRejectsNaiveExpiry(t *testing.T) {
	store := newTestStore(t)
	defer store.Close()

	server := httptest.NewServer(NewHTTPHandler(store))
	defer server.Close()

	resp := doJSONRequest(t, http.MethodPut, server.URL+"/v1/authorizations", map[string]any{
		"agent_id":     "agent-1",
		"provider":     "discord",
		"access_token": "token-a",
		"expires_at":   "2026-02-09T10:00:00",
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}

	var apiErr apiError
	if err := json.NewDecoder(resp.Body).Decode(&apiErr); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if apiErr.Detail == "" {
		t.Fatal("expected validation detail for naive timestamp")
	}
}

func TestKeyEndpoints(t *testing.T) {
	store := newTestStore(t)
	defer store.Close()

	server := httptest.NewServer(NewHTTPHandler(store))
	defer server.Close()

	statusResp, err := http.Get(server.URL + "/v1/keys/status")
	if err != nil {
		t.Fatalf("get key status: %v", err)
	}
	if statusResp.StatusCode != http.StatusOK {
		t.Fatalf("status code = %d", statusResp.StatusCode)
	}
	var status KeyStatus
	decodeJSON(t, statusResp, &status)
	if status.ActiveKEKVersion != "v1" {
		t.Fatalf("active key mismatch: %q", status.ActiveKEKVersion)
	}

	rewrapResp := doJSONRequest(t, http.MethodPost, server.URL+"/v1/keys/rewrap", map[string]any{})
	if rewrapResp.StatusCode != http.StatusOK {
		t.Fatalf("rewrap status = %d", rewrapResp.StatusCode)
	}
	var rewrap RewrapResult
	decodeJSON(t, rewrapResp, &rewrap)
	if rewrap.TargetKEKVersion != "v1" {
		t.Fatalf("target key mismatch: %q", rewrap.TargetKEKVersion)
	}
}

func TestBearerAuthWhenConfigured(t *testing.T) {
	t.Setenv("KEY_STORE_BEARER_TOKEN", "test-token")
	store := newTestStore(t)
	defer store.Close()

	server := httptest.NewServer(NewHTTPHandler(store))
	defer server.Close()

	missingResp, err := http.Get(server.URL + "/v1/keys/status")
	if err != nil {
		t.Fatalf("missing auth request: %v", err)
	}
	if missingResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing auth status = %d", missingResp.StatusCode)
	}

	wrongReq, err := http.NewRequest(http.MethodGet, server.URL+"/v1/keys/status", nil)
	if err != nil {
		t.Fatalf("new wrong auth request: %v", err)
	}
	wrongReq.Header.Set("Authorization", "Bearer wrong-token")
	wrongResp, err := http.DefaultClient.Do(wrongReq)
	if err != nil {
		t.Fatalf("wrong auth request: %v", err)
	}
	if wrongResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong auth status = %d", wrongResp.StatusCode)
	}

	okReq, err := http.NewRequest(http.MethodGet, server.URL+"/v1/keys/status", nil)
	if err != nil {
		t.Fatalf("new ok auth request: %v", err)
	}
	okReq.Header.Set("Authorization", "Bearer test-token")
	okResp, err := http.DefaultClient.Do(okReq)
	if err != nil {
		t.Fatalf("ok auth request: %v", err)
	}
	if okResp.StatusCode != http.StatusOK {
		t.Fatalf("ok auth status = %d", okResp.StatusCode)
	}
	var status KeyStatus
	decodeJSON(t, okResp, &status)
	if status.ActiveKEKVersion != "v1" {
		t.Fatalf("active key mismatch: %q", status.ActiveKEKVersion)
	}
}

func TestPasswordEndpointRejectsOversizedBody(t *testing.T) {
	store := newTestStore(t)
	defer store.Close()

	server := httptest.NewServer(NewHTTPHandler(store))
	defer server.Close()

	resp := doJSONRequest(t, http.MethodPut, server.URL+"/v1/passwords", map[string]any{
		"agent_id": "agent-1",
		"name":     "oversized",
		"password": "secret-123",
		"metadata": map[string]any{
			"blob": strings.Repeat("x", int(maxJSONBodyBytes)),
		},
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusRequestEntityTooLarge)
	}

	var apiErr apiError
	if err := json.NewDecoder(resp.Body).Decode(&apiErr); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if apiErr.Detail != "request body too large" {
		t.Fatalf("unexpected detail: %q", apiErr.Detail)
	}
}

func doJSONRequest(t *testing.T, method, url string, payload any) *http.Response {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return resp
}

func decodeJSON(t *testing.T, resp *http.Response, dst any) {
	t.Helper()
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
		t.Fatalf("decode response: %v", err)
	}
}
