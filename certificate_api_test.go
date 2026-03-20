package squidkeys

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCertificateEndpoints(t *testing.T) {
	store := newTestStore(t)
	defer store.Close()

	server := httptest.NewServer(NewHTTPHandler(store))
	defer server.Close()

	bundle := makeTestCertificateBundle(t)
	saveResp := doJSONRequest(t, http.MethodPut, server.URL+"/v1/certificates", map[string]any{
		"agent_id":               "agent-1",
		"name":                   "mtls-client",
		"certificate_chain_pem":  bundle.CertificateChainPEM,
		"private_key_pem":        bundle.PrivateKeyPEM,
		"private_key_passphrase": bundle.PrivateKeyPassphrase,
		"metadata":               map[string]any{"scope": "local-agent"},
	})
	if saveResp.StatusCode != http.StatusOK {
		t.Fatalf("save status = %d", saveResp.StatusCode)
	}

	var saved CertificateRecord
	decodeJSON(t, saveResp, &saved)
	if saved.FingerprintSHA256 != bundle.FingerprintSHA256 {
		t.Fatalf("fingerprint mismatch: %q", saved.FingerprintSHA256)
	}
	if saved.PrivateKeyPEM == nil || *saved.PrivateKeyPEM != bundle.PrivateKeyPEM {
		t.Fatalf("private key mismatch: %#v", saved.PrivateKeyPEM)
	}

	getResp, err := http.Get(server.URL + "/v1/certificates/agent-1/mtls-client")
	if err != nil {
		t.Fatalf("get certificate: %v", err)
	}
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("get status = %d", getResp.StatusCode)
	}

	var got CertificateRecord
	decodeJSON(t, getResp, &got)
	if got.SubjectCommonName == nil || *got.SubjectCommonName != bundle.SubjectCommonName {
		t.Fatalf("subject common name mismatch: %#v", got.SubjectCommonName)
	}
	if got.Metadata["scope"] != "local-agent" {
		t.Fatalf("metadata mismatch: %#v", got.Metadata)
	}

	req, err := http.NewRequest(http.MethodDelete, server.URL+"/v1/certificates/agent-1/mtls-client", nil)
	if err != nil {
		t.Fatalf("new delete request: %v", err)
	}
	delResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete certificate: %v", err)
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
