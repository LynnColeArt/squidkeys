package squidkeys

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
)

type apiError struct {
	Detail string `json:"detail"`
}

const maxJSONBodyBytes int64 = 1 << 20

func NewHTTPHandler(store *KeyStore) http.Handler {
	return newHTTPHandler(store, nil)
}

// NewOrganizationHTTPHandler enables the opt-in, per-installation HTTP boundary.
// Policy must have been validated by ParseOrganizationPolicy.
func NewOrganizationHTTPHandler(store *KeyStore, policy *OrganizationPolicy) http.Handler {
	if policy == nil {
		panic("squidkeys: nil organization policy")
	}
	return newHTTPHandler(store, policy)
}

func newHTTPHandler(store *KeyStore, policy *OrganizationPolicy) http.Handler {
	if store == nil {
		panic("squidkeys: nil store")
	}

	api := &httpAPI{store: store}
	mux := http.NewServeMux()
	register := func(pattern string, kind string, handler http.HandlerFunc) {
		if policy != nil {
			handler = policy.guard(kind, handler)
		}
		mux.HandleFunc(pattern, handler)
	}
	register("GET /health", "health", api.health)
	register("PUT /v1/authorizations", "admin", api.saveAuthorization)
	register("GET /v1/authorizations/{agent_id}/{provider}", "authorization", api.getAuthorization)
	register("DELETE /v1/authorizations/{agent_id}/{provider}", "admin", api.deleteAuthorization)
	register("PUT /v1/passwords", "admin", api.savePassword)
	register("GET /v1/passwords/{agent_id}/{name}", "password", api.getPassword)
	register("DELETE /v1/passwords/{agent_id}/{name}", "admin", api.deletePassword)
	register("PUT /v1/certificates", "admin", api.saveCertificate)
	register("GET /v1/certificates/{agent_id}/{name}", "certificate", api.getCertificate)
	register("DELETE /v1/certificates/{agent_id}/{name}", "admin", api.deleteCertificate)
	register("PUT /v1/git-profiles", "admin", api.saveGitProfile)
	register("GET /v1/git-profiles", "admin", api.listGitProfiles)
	register("GET /v1/git-profiles/{agent_id}/{name}", "git_profile", api.getGitProfile)
	register("DELETE /v1/git-profiles/{agent_id}/{name}", "admin", api.deleteGitProfile)
	register("GET /v1/keys/status", "admin", api.keyStatus)
	register("POST /v1/keys/rewrap", "admin", api.rewrap)
	return mux
}

type httpAPI struct {
	store *KeyStore
}

func (a *httpAPI) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *httpAPI) saveAuthorization(w http.ResponseWriter, r *http.Request) {
	if !requireBearer(w, r) {
		return
	}

	var payload AuthorizationUpsertInput
	if err := decodeJSONBody(w, r, &payload); err != nil {
		writeDecodeError(w, err)
		return
	}
	payload.Actor = requestActor(r, payload.Actor)

	if err := a.store.SaveAuthorization(payload); err != nil {
		var validationErr *ValidationError
		var configErr *KeyStoreConfigError
		switch {
		case errors.As(err, &validationErr):
			writeError(w, http.StatusBadRequest, validationErr.Error())
		case errors.As(err, &configErr):
			writeError(w, http.StatusInternalServerError, configErr.Error())
		default:
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	record, err := a.store.GetAuthorization(payload.AgentID, payload.Provider, payload.AccountID, payload.Actor)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if record == nil {
		writeError(w, http.StatusInternalServerError, "record not found after save")
		return
	}
	writeJSON(w, http.StatusOK, record)
}

func (a *httpAPI) getAuthorization(w http.ResponseWriter, r *http.Request) {
	if !requireBearer(w, r) {
		return
	}

	agentID := r.PathValue("agent_id")
	provider := r.PathValue("provider")
	accountID := queryStringPtr(r, "account_id")
	actor := requestActor(r, r.URL.Query().Get("actor"))

	record, err := a.store.GetAuthorization(agentID, provider, accountID, actor)
	if err != nil {
		var validationErr *ValidationError
		if errors.As(err, &validationErr) {
			writeError(w, http.StatusBadRequest, validationErr.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if record == nil {
		writeError(w, http.StatusNotFound, "authorization not found")
		return
	}
	writeJSON(w, http.StatusOK, record)
}

func (a *httpAPI) deleteAuthorization(w http.ResponseWriter, r *http.Request) {
	if !requireBearer(w, r) {
		return
	}

	agentID := r.PathValue("agent_id")
	provider := r.PathValue("provider")
	accountID := queryStringPtr(r, "account_id")
	actor := requestActor(r, r.URL.Query().Get("actor"))

	deleted, err := a.store.DeleteAuthorization(agentID, provider, accountID, actor)
	if err != nil {
		var validationErr *ValidationError
		if errors.As(err, &validationErr) {
			writeError(w, http.StatusBadRequest, validationErr.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, DeleteResponse{Deleted: deleted})
}

func (a *httpAPI) savePassword(w http.ResponseWriter, r *http.Request) {
	if !requireBearer(w, r) {
		return
	}

	var payload PasswordUpsertInput
	if err := decodeJSONBody(w, r, &payload); err != nil {
		writeDecodeError(w, err)
		return
	}
	payload.Actor = requestActor(r, payload.Actor)

	if err := a.store.SavePassword(payload); err != nil {
		var validationErr *ValidationError
		var configErr *KeyStoreConfigError
		switch {
		case errors.As(err, &validationErr):
			writeError(w, http.StatusBadRequest, validationErr.Error())
		case errors.As(err, &configErr):
			writeError(w, http.StatusInternalServerError, configErr.Error())
		default:
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	record, err := a.store.GetPassword(payload.AgentID, payload.Name, payload.Actor)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if record == nil {
		writeError(w, http.StatusInternalServerError, "record not found after save")
		return
	}
	writeJSON(w, http.StatusOK, record)
}

func (a *httpAPI) getPassword(w http.ResponseWriter, r *http.Request) {
	if !requireBearer(w, r) {
		return
	}

	actor := requestActor(r, r.URL.Query().Get("actor"))
	record, err := a.store.GetPassword(r.PathValue("agent_id"), r.PathValue("name"), actor)
	if err != nil {
		var validationErr *ValidationError
		if errors.As(err, &validationErr) {
			writeError(w, http.StatusBadRequest, validationErr.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if record == nil {
		writeError(w, http.StatusNotFound, "password not found")
		return
	}
	writeJSON(w, http.StatusOK, record)
}

func (a *httpAPI) deletePassword(w http.ResponseWriter, r *http.Request) {
	if !requireBearer(w, r) {
		return
	}

	actor := requestActor(r, r.URL.Query().Get("actor"))
	deleted, err := a.store.DeletePassword(r.PathValue("agent_id"), r.PathValue("name"), actor)
	if err != nil {
		var validationErr *ValidationError
		if errors.As(err, &validationErr) {
			writeError(w, http.StatusBadRequest, validationErr.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, DeleteResponse{Deleted: deleted})
}

func (a *httpAPI) saveCertificate(w http.ResponseWriter, r *http.Request) {
	if !requireBearer(w, r) {
		return
	}

	var payload CertificateUpsertInput
	if err := decodeJSONBody(w, r, &payload); err != nil {
		writeDecodeError(w, err)
		return
	}
	payload.Actor = requestActor(r, payload.Actor)

	if err := a.store.SaveCertificate(payload); err != nil {
		var validationErr *ValidationError
		var configErr *KeyStoreConfigError
		switch {
		case errors.As(err, &validationErr):
			writeError(w, http.StatusBadRequest, validationErr.Error())
		case errors.As(err, &configErr):
			writeError(w, http.StatusInternalServerError, configErr.Error())
		default:
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	record, err := a.store.GetCertificate(payload.AgentID, payload.Name, payload.Actor)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if record == nil {
		writeError(w, http.StatusInternalServerError, "record not found after save")
		return
	}
	writeJSON(w, http.StatusOK, record)
}

func (a *httpAPI) getCertificate(w http.ResponseWriter, r *http.Request) {
	if !requireBearer(w, r) {
		return
	}

	actor := requestActor(r, r.URL.Query().Get("actor"))
	record, err := a.store.GetCertificate(r.PathValue("agent_id"), r.PathValue("name"), actor)
	if err != nil {
		var validationErr *ValidationError
		if errors.As(err, &validationErr) {
			writeError(w, http.StatusBadRequest, validationErr.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if record == nil {
		writeError(w, http.StatusNotFound, "certificate not found")
		return
	}
	writeJSON(w, http.StatusOK, record)
}

func (a *httpAPI) deleteCertificate(w http.ResponseWriter, r *http.Request) {
	if !requireBearer(w, r) {
		return
	}

	actor := requestActor(r, r.URL.Query().Get("actor"))
	deleted, err := a.store.DeleteCertificate(r.PathValue("agent_id"), r.PathValue("name"), actor)
	if err != nil {
		var validationErr *ValidationError
		if errors.As(err, &validationErr) {
			writeError(w, http.StatusBadRequest, validationErr.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, DeleteResponse{Deleted: deleted})
}

func (a *httpAPI) saveGitProfile(w http.ResponseWriter, r *http.Request) {
	if !requireBearer(w, r) {
		return
	}

	var payload GitProfileUpsertInput
	if err := decodeJSONBody(w, r, &payload); err != nil {
		writeDecodeError(w, err)
		return
	}
	payload.Actor = requestActor(r, payload.Actor)

	if err := a.store.SaveGitProfile(payload); err != nil {
		var validationErr *ValidationError
		switch {
		case errors.As(err, &validationErr):
			writeError(w, http.StatusBadRequest, validationErr.Error())
		default:
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	record, err := a.store.GetGitProfile(payload.AgentID, payload.Name, payload.Actor)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if record == nil {
		writeError(w, http.StatusInternalServerError, "record not found after save")
		return
	}
	writeJSON(w, http.StatusOK, record)
}

func (a *httpAPI) listGitProfiles(w http.ResponseWriter, r *http.Request) {
	if !requireBearer(w, r) {
		return
	}

	records, err := a.store.ListGitProfiles(queryStringPtr(r, "agent_id"), queryStringPtr(r, "platform"), requestActor(r, r.URL.Query().Get("actor")))
	if err != nil {
		var validationErr *ValidationError
		if errors.As(err, &validationErr) {
			writeError(w, http.StatusBadRequest, validationErr.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, records)
}

func (a *httpAPI) getGitProfile(w http.ResponseWriter, r *http.Request) {
	if !requireBearer(w, r) {
		return
	}

	actor := requestActor(r, r.URL.Query().Get("actor"))
	record, err := a.store.GetGitProfile(r.PathValue("agent_id"), r.PathValue("name"), actor)
	if err != nil {
		var validationErr *ValidationError
		if errors.As(err, &validationErr) {
			writeError(w, http.StatusBadRequest, validationErr.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if record == nil {
		writeError(w, http.StatusNotFound, "git profile not found")
		return
	}
	writeJSON(w, http.StatusOK, record)
}

func (a *httpAPI) deleteGitProfile(w http.ResponseWriter, r *http.Request) {
	if !requireBearer(w, r) {
		return
	}

	actor := requestActor(r, r.URL.Query().Get("actor"))
	deleted, err := a.store.DeleteGitProfile(r.PathValue("agent_id"), r.PathValue("name"), actor)
	if err != nil {
		var validationErr *ValidationError
		if errors.As(err, &validationErr) {
			writeError(w, http.StatusBadRequest, validationErr.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, DeleteResponse{Deleted: deleted})
}

func (a *httpAPI) keyStatus(w http.ResponseWriter, r *http.Request) {
	if !requireBearer(w, r) {
		return
	}

	status, err := a.store.KeyStatus()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (a *httpAPI) rewrap(w http.ResponseWriter, r *http.Request) {
	if !requireBearer(w, r) {
		return
	}

	var payload RewrapInput
	if err := decodeJSONBody(w, r, &payload); err != nil {
		writeDecodeError(w, err)
		return
	}
	payload.Actor = requestActor(r, payload.Actor)

	result, err := a.store.RewrapAllRecords(payload.TargetKEKVersion, payload.Actor)
	if err != nil {
		var configErr *KeyStoreConfigError
		if errors.As(err, &configErr) {
			writeError(w, http.StatusBadRequest, configErr.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, result)
}

func requireBearer(w http.ResponseWriter, r *http.Request) bool {
	if _, ok := r.Context().Value(organizationPrincipalContextKey{}).(string); ok {
		return true
	}
	expected := os.Getenv("KEY_STORE_BEARER_TOKEN")
	if expected == "" {
		return true
	}

	authHeader := r.Header.Get("Authorization")
	if len(authHeader) < len("Bearer ")+1 || authHeader[:7] != "Bearer " {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeError(w, http.StatusUnauthorized, "missing bearer token")
		return false
	}

	presented := authHeader[7:]
	if !bearerTokenMatches(presented, expected) {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeError(w, http.StatusUnauthorized, "invalid bearer token")
		return false
	}

	return true
}

func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst any) error {
	if r.Body == nil {
		return nil
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodyBytes)
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(dst); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}

	var trailing any
	if err := decoder.Decode(&trailing); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return fmt.Errorf("decode json: %w", err)
	}
	return fmt.Errorf("decode json: trailing data")
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, detail string) {
	writeJSON(w, status, apiError{Detail: detail})
}

func writeDecodeError(w http.ResponseWriter, err error) {
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return
	}
	writeError(w, http.StatusBadRequest, fmt.Sprintf("decode json: %v", err))
}

func queryStringPtr(r *http.Request, key string) *string {
	value := r.URL.Query().Get(key)
	if value == "" {
		return nil
	}
	return &value
}
