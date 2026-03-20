package squidkeys

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGitProfileEndpoints(t *testing.T) {
	store := newTestStore(t)
	defer store.Close()

	bundle := makeTestCertificateBundle(t)
	if err := seedGitProfileSecrets(store, bundle); err != nil {
		t.Fatalf("seed git profile secrets: %v", err)
	}

	server := httptest.NewServer(NewHTTPHandler(store))
	defer server.Close()

	saveResp := doJSONRequest(t, http.MethodPut, server.URL+"/v1/git-profiles", map[string]any{
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
		"repo_matchers":  []string{"github.com/work/*"},
	})
	if saveResp.StatusCode != http.StatusOK {
		t.Fatalf("save status = %d", saveResp.StatusCode)
	}

	var saved GitProfileRecord
	decodeJSON(t, saveResp, &saved)
	if saved.GitEmail != "work@example.com" {
		t.Fatalf("git email mismatch: %q", saved.GitEmail)
	}

	getResp, err := http.Get(server.URL + "/v1/git-profiles/agent-1/work")
	if err != nil {
		t.Fatalf("get git profile: %v", err)
	}
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("get status = %d", getResp.StatusCode)
	}

	var got GitProfileRecord
	decodeJSON(t, getResp, &got)
	if got.SSHIdentityRef == nil || got.SSHIdentityRef.RecordType != "password" {
		t.Fatalf("ssh identity ref mismatch: %#v", got.SSHIdentityRef)
	}

	listResp, err := http.Get(server.URL + "/v1/git-profiles?agent_id=agent-1")
	if err != nil {
		t.Fatalf("list git profiles: %v", err)
	}
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list status = %d", listResp.StatusCode)
	}
	var listed []GitProfileRecord
	decodeJSON(t, listResp, &listed)
	if len(listed) != 1 || listed[0].Name != "work" {
		t.Fatalf("unexpected list result: %#v", listed)
	}

	req, err := http.NewRequest(http.MethodDelete, server.URL+"/v1/git-profiles/agent-1/work", nil)
	if err != nil {
		t.Fatalf("new delete request: %v", err)
	}
	delResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete git profile: %v", err)
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

func seedGitProfileSecrets(store *KeyStore, bundle testCertificateBundle) error {
	accountID := "user-1"
	if err := store.SaveAuthorization(AuthorizationUpsertInput{
		AgentID:     "agent-1",
		Provider:    "github",
		AccountID:   &accountID,
		AccessToken: "oauth-token",
	}); err != nil {
		return err
	}
	if err := store.SavePassword(PasswordUpsertInput{
		AgentID:  "agent-1",
		Name:     "github-work-ssh",
		Password: "ssh-private-key-material",
	}); err != nil {
		return err
	}
	return store.SaveCertificate(CertificateUpsertInput{
		AgentID:              "agent-1",
		Name:                 "github-work-signing",
		CertificateChainPEM:  bundle.CertificateChainPEM,
		PrivateKeyPEM:        &bundle.PrivateKeyPEM,
		PrivateKeyPassphrase: &bundle.PrivateKeyPassphrase,
	})
}
