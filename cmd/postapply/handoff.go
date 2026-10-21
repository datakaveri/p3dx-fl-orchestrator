package main

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"

	"github.com/s4r4v4n04/p3dx-fl-orchestrator/internal/vmcred"
)

// handoff mirrors the orchestrator's POST /p3dx/internal/vm-credentials.
func handoff(key string, creds *vmcred.Store, got chan<- string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost ||
			subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Internal-Key")), []byte(key)) != 1 {
			http.Error(w, `{"status":"FAILED","error":"UNAUTHORIZED"}`, http.StatusUnauthorized)
			return
		}
		var in struct {
			CredentialID string `json:"credential_id"`
			SubmissionID string `json:"submission_id"`
			ContractID   string `json:"contract_id"`
			Username     string `json:"username"`
			UserID       string `json:"user_id"`
			OfflineToken string `json:"offline_token"`
			ExpiresAt    string `json:"expires_at"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
			http.Error(w, `{"status":"FAILED","error":"INVALID_JSON"}`, http.StatusBadRequest)
			return
		}
		token := []byte(in.OfflineToken)
		in.OfflineToken = ""
		if err := creds.Put(vmcred.Credential{ID: in.CredentialID, SubmissionID: in.SubmissionID, ContractID: in.ContractID,
			Username: in.Username, UserID: in.UserID, ExpiresAt: in.ExpiresAt}, token); err != nil {
			http.Error(w, `{"status":"FAILED","error":"INVALID_CREDENTIAL"}`, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"SUCCESS"}`))
		select {
		case got <- in.CredentialID:
		default:
		}
	}
}
