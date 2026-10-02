package squidkeys

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testOrganizationPolicy(t *testing.T) *OrganizationPolicy {
	t.Helper()
	digest := func(token string) string {
		sum := sha256.Sum256([]byte(token))
		return hex.EncodeToString(sum[:])
	}
	policy, err := ParseOrganizationPolicy([]byte(fmt.Sprintf(`{
		"version":1,
		"principals":[
			{"id":"owner","token_sha256":%q,"admin":true},
			{"id":"site-a","token_sha256":%q,"read":[
				{"record_type":"password","agent_id":"site-a","name":"git"},
				{"record_type":"authorization","agent_id":"site-a","provider":"ollama","account_id":"prod"},
				{"record_type":"git_profile","agent_id":"site-a","name":"source"}
			]},
			{"id":"site-b","token_sha256":%q,"read":[{"record_type":"password","agent_id":"site-b","name":"git"}]}
		]
	}`, digest("owner-secret"), digest("site-a-secret"), digest("site-b-secret"))))
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func organizationRequest(t *testing.T, client *http.Client, method, url, token, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestOrganizationHTTPBoundary(t *testing.T) {
	store := newTestStore(t)
	defer store.Close()
	server := httptest.NewServer(NewOrganizationHTTPHandler(store, testOrganizationPolicy(t)))
	defer server.Close()
	client := server.Client()
	for _, agentID := range []string{"site-a", "site-b"} {
		body := fmt.Sprintf(`{"agent_id":%q,"name":"git","password":"secret-%s","actor":"forged"}`, agentID, agentID)
		resp := organizationRequest(t, client, http.MethodPut, server.URL+"/v1/passwords", "owner-secret", body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("admin save %s: %d", agentID, resp.StatusCode)
		}
		resp.Body.Close()
	}
	resp := organizationRequest(t, client, http.MethodPut, server.URL+"/v1/authorizations", "owner-secret", `{"agent_id":"site-a","provider":"ollama","account_id":"prod","access_token":"ollama-secret"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin authorization save: %d", resp.StatusCode)
	}
	resp.Body.Close()

	cases := []struct {
		name, method, path, token, body string
		want                            int
	}{
		{"own exact read", "GET", "/v1/passwords/site-a/git?actor=forged", "site-a-secret", "", http.StatusOK},
		{"cross-installation read", "GET", "/v1/passwords/site-b/git", "site-a-secret", "", http.StatusForbidden},
		{"wrong name", "GET", "/v1/passwords/site-a/other", "site-a-secret", "", http.StatusForbidden},
		{"unknown bearer", "GET", "/v1/passwords/site-a/git", "wrong", "", http.StatusUnauthorized},
		{"missing bearer", "GET", "/v1/passwords/site-a/git", "", "", http.StatusUnauthorized},
		{"reader write", "PUT", "/v1/passwords", "site-a-secret", `{"agent_id":"site-a","name":"other","password":"new"}`, http.StatusForbidden},
		{"reader delete", "DELETE", "/v1/passwords/site-a/git", "site-a-secret", "", http.StatusForbidden},
		{"reader list", "GET", "/v1/git-profiles", "site-a-secret", "", http.StatusForbidden},
		{"reader key status", "GET", "/v1/keys/status", "site-a-secret", "", http.StatusForbidden},
		{"reader rewrap", "POST", "/v1/keys/rewrap", "site-a-secret", `{}`, http.StatusForbidden},
		{"auth exact account required", "GET", "/v1/authorizations/site-a/ollama", "site-a-secret", "", http.StatusForbidden},
		{"auth other account", "GET", "/v1/authorizations/site-a/ollama?account_id=other", "site-a-secret", "", http.StatusForbidden},
		{"auth granted exact account", "GET", "/v1/authorizations/site-a/ollama?account_id=prod", "site-a-secret", "", http.StatusOK},
		{"auth duplicate account query", "GET", "/v1/authorizations/site-a/ollama?account_id=prod&account_id=other", "site-a-secret", "", http.StatusForbidden},
		{"health public", "GET", "/health", "", "", http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := organizationRequest(t, client, tc.method, server.URL+tc.path, tc.token, tc.body)
			defer resp.Body.Close()
			if resp.StatusCode != tc.want {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.want)
			}
		})
	}
	var count int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE operation = 'get' AND record_type = 'password' AND agent_id = 'site-a' AND actor = 'organization:site-a'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count == 0 {
		t.Fatal("reader audit entry must use verified identity, not query actor")
	}
}

func TestOrganizationPolicyRejectsInvalidConfiguration(t *testing.T) {
	good := testOrganizationPolicy(t)
	if len(good.principals) != 3 {
		t.Fatal("expected three principals")
	}
	cases := []string{
		`{"version":2,"principals":[{"id":"a","token_sha256":"bad","admin":true}]}`,
		`{"version":1,"principals":[{"id":"a","token_sha256":"bad","admin":true}]}`,
		`{"version":1,"principals":[],"unexpected":true}`,
		`{"version":1,"principals":[]} {}`,
	}
	for _, raw := range cases {
		if _, err := ParseOrganizationPolicy([]byte(raw)); err == nil {
			t.Errorf("accepted invalid policy %s", raw)
		}
	}
	// A duplicate token or overbroad wildcard cannot silently collapse grants.
	sum := sha256.Sum256([]byte("same-token"))
	digest := hex.EncodeToString(sum[:])
	input := map[string]any{"version": 1, "principals": []any{
		map[string]any{"id": "admin", "token_sha256": digest, "admin": true},
		map[string]any{"id": "reader", "token_sha256": digest, "read": []any{map[string]any{"record_type": "password", "agent_id": "*", "name": "*"}}},
	}}
	data, _ := json.Marshal(input)
	if _, err := ParseOrganizationPolicy(data); err == nil {
		t.Fatal("accepted duplicate token")
	}
	other := sha256.Sum256([]byte("other-token"))
	input["principals"].([]any)[1].(map[string]any)["token_sha256"] = hex.EncodeToString(other[:])
	data, _ = json.Marshal(input)
	if _, err := ParseOrganizationPolicy(data); err == nil {
		t.Fatal("accepted wildcard grant")
	}
}
