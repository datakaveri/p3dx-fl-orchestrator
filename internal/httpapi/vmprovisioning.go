package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/s4r4v4n04/p3dx-fl-orchestrator/internal/provisioning"
	"github.com/s4r4v4n04/p3dx-fl-orchestrator/internal/vmcred"
	"github.com/s4r4v4n04/p3dx-fl-orchestrator/internal/vmsession"
)

type autoCreateInput struct {
	Role         string `json:"role"`
	VMName       string `json:"vmName"`
	RunKey       string `json:"runKey"`
	SubmissionID string `json:"submissionId"`
	// CredentialID names the VM credential the controlplane handed over after the
	// provider authorized this VM; required for a data-provider VM.
	CredentialID string `json:"credentialId"`
	// An "outputOwnerUsername" body field is no longer read: the owner comes
	// from the session's contract.
}

func normalizeRole(role string) string {
	if role == "data-provider" {
		return "data-provider"
	}
	return "user"
}

// POST /p3dx/vm-provisioning/auto-create — kicks off fully automated VM
// creation on the backend (device-code Azure login + Terraform). Responds
// immediately with a token identifying this run; progress streams over
// GET /vm-provisioning/stream.
func (s *Server) postAutoCreate(w http.ResponseWriter, r *http.Request) {
	username := usernameFromCtx(r)
	if username == "" {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "MISSING_USERNAME"})
		return
	}
	var in autoCreateInput
	if !readBody(w, r, &in) {
		return
	}
	role := normalizeRole(in.Role)
	vmName := strings.TrimSpace(in.VMName)
	// A submission's VM is named after the submission (provisioning.VMName),
	// so only a run without one needs a client-chosen name.
	if vmName == "" && in.SubmissionID == "" {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "MISSING_VM_NAME"})
		return
	}
	// runKey identifies this specific caller/panel instance (falls back to
	// username for older callers) — it's what guards against a duplicate
	// spawn of the *same* run, not against different concurrent runs.
	runKey := in.RunKey
	if runKey == "" {
		runKey = username
	}

	// Only the session's own parties may provision for it: the output owner
	// the server VM, a contract data provider a client VM.
	outputOwner := ""
	if in.SubmissionID != "" {
		parties := s.sessionParties(w, r, in.SubmissionID)
		if parties == nil {
			return
		}
		if role == "user" {
			if !parties.IsOwner(username) && !isOperator(r) {
				writeJSON(w, http.StatusForbidden, j{"status": "FAILED", "error": "NOT_SESSION_OWNER"})
				return
			}
			outputOwner = parties.UserName
		} else if !parties.IsDataProvider(username) {
			writeJSON(w, http.StatusForbidden, j{"status": "FAILED", "error": "NOT_A_CONTRACT_PARTY"})
			return
		}
	} else if role == "user" {
		// A server VM exists to run one submission's session.
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "MISSING_SUBMISSION_ID"})
		return
	}

	if s.prov.IsProvisioning(runKey) {
		writeJSON(w, http.StatusAccepted, j{"status": "SUCCESS", "already_running": true})
		return
	}

	// A client VM can only join an FL session with its provider's VM
	// credential: claim it now, bound to this provider and submission.
	if role == "data-provider" && in.SubmissionID != "" {
		if in.CredentialID == "" {
			writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "MISSING_CREDENTIAL",
				"message": "authorize this VM first (credentialId missing)"})
			return
		}
		if _, err := s.creds.Claim(in.CredentialID, username, in.SubmissionID); err != nil {
			writeJSON(w, http.StatusForbidden, j{"status": "FAILED", "error": "CREDENTIAL_NOT_CLAIMABLE", "message": err.Error()})
			return
		}
	}

	// "Start Again" reuses the submission id: a new server VM run must not
	// inherit the finished earlier session's FL state.
	if role == "user" && in.SubmissionID != "" {
		s.flow.PrepareOwnerRun(in.SubmissionID)
	}

	token := s.store.CreateRun(vmsession.RunInfo{
		Username: username, Role: role, SubmissionID: in.SubmissionID,
		VMName: provisioning.VMName(in.SubmissionID, vmName, username), OutputOwner: outputOwner,
	})
	writeJSON(w, http.StatusAccepted, j{"status": "SUCCESS", "token": token})

	go s.prov.RunAutoProvision(provisioning.RunAutoProvisionInput{
		Token: token, Username: username, Role: role, VMName: vmName,
		RunKey: runKey, SubmissionID: in.SubmissionID, CredentialID: in.CredentialID,
	})
}

// GET /p3dx/vm-provisioning/private-key — one-time download of the SSH
// private key generated for one specific auto-created VM run.
func (s *Server) getPrivateKey(w http.ResponseWriter, r *http.Request) {
	runToken := strings.TrimSpace(r.URL.Query().Get("token"))
	// The run token is a capability, but also require it to be the caller's
	// own run (or a server-VM run they own the output of).
	if runToken == "" || !s.store.CanAccess(runToken, usernameFromCtx(r)) {
		writeJSON(w, http.StatusNotFound, j{"status": "FAILED", "error": "NOT_FOUND_OR_ALREADY_DOWNLOADED"})
		return
	}
	key, ok := s.prov.TakePrivateKey(runToken)
	if !ok {
		writeJSON(w, http.StatusNotFound, j{"status": "FAILED", "error": "NOT_FOUND_OR_ALREADY_DOWNLOADED"})
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="p3dx_flo_vm_key.pem"`)
	_, _ = w.Write([]byte(key))
}

type tokenInput struct {
	Role string `json:"role"`
}

// POST /p3dx/vm-provisioning/token — mint a short-lived token identifying the
// caller, so their local terraform/participant-vm/deploy.sh run can report
// progress back to their own FL dashboard.
func (s *Server) postToken(w http.ResponseWriter, r *http.Request) {
	username := usernameFromCtx(r)
	if username == "" {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "MISSING_USERNAME"})
		return
	}
	var in tokenInput
	if !readBody(w, r, &in) {
		return
	}
	token := s.store.CreateToken(username, normalizeRole(in.Role))
	writeJSON(w, http.StatusCreated, j{"status": "SUCCESS", "token": token})
}

type eventsInput struct {
	Token   string `json:"token"`
	Step    string `json:"step"`
	Command string `json:"command"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

// POST /p3dx/vm-provisioning/events — deploy.sh posts one event per step
// here. Token-authenticated rather than JWT-authenticated: the caller is a
// local shell script with no browser session, just the token minted above.
func (s *Server) postEvents(w http.ResponseWriter, r *http.Request) {
	var in eventsInput
	if !readBody(w, r, &in) {
		return
	}
	if in.Token == "" || in.Step == "" || in.Status == "" {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "MISSING_FIELDS"})
		return
	}
	if !s.store.AppendEvent(in.Token, in.Step, in.Command, in.Status, in.Message) {
		writeJSON(w, http.StatusNotFound, j{"status": "FAILED", "error": "UNKNOWN_OR_EXPIRED_TOKEN"})
		return
	}
	writeJSON(w, http.StatusOK, j{"status": "SUCCESS"})
}

// GET /p3dx/vm-provisioning/runs?submissionId= — the caller's runs, newest
// first, so a panel can be reopened later (their own runs, plus server VM
// runs whose output owner they are). Optionally narrowed to one submission.
func (s *Server) getRuns(w http.ResponseWriter, r *http.Request) {
	username := usernameFromCtx(r)
	if username == "" {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "MISSING_USERNAME"})
		return
	}
	submissionID := strings.TrimSpace(r.URL.Query().Get("submissionId"))
	writeJSON(w, http.StatusOK, j{"runs": s.store.ListRuns(username, submissionID)})
}

// GET /p3dx/vm-provisioning/stream?token= — SSE push of one run's VM
// provisioning events. EventSource can't set an Authorization header, so the
// run token (an unguessable capability, listed only to its owner by
// /vm-provisioning/runs) identifies the run instead of a JWT. The old
// ?username=&role= lookup is gone: it let anyone watch anyone's latest run.
// Sends the full event log each time the run changes — traffic is tiny, so
// no need to diff.
func (s *Server) getStream(w http.ResponseWriter, r *http.Request) {
	runToken := strings.TrimSpace(r.URL.Query().Get("token"))
	if runToken == "" {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "MISSING_TOKEN"})
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "\n")
	flusher.Flush()

	// Rev, not len(Events): a "Training round" event is replaced in place.
	sent, lastRev := false, uint64(0)
	poll := func() {
		snap, ok := s.store.Get(runToken)
		status := snap.Status
		if !ok || status == "" {
			status = "idle"
		}
		if !sent || snap.Rev != lastRev {
			payload := j{"status": status, "vmReady": snap.VMReady, "events": snap.Events}
			data, _ := json.Marshal(payload)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
			sent, lastRev = true, snap.Rev
		}
	}

	poll()
	pollTicker := time.NewTicker(2 * time.Second)
	heartbeat := time.NewTicker(15 * time.Second)
	defer pollTicker.Stop()
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-pollTicker.C:
			poll()
		case <-heartbeat.C:
			fmt.Fprint(w, ": heartbeat\n\n")
			flusher.Flush()
		}
	}
}

type registerExpectedInput struct {
	SubmissionID string `json:"submissionId"`
	Count        int    `json:"count"`
}

// POST /p3dx/internal/register-expected-providers — called by p3dx-aaa's
// /gov/start-fl-session once it knows the full participating_providers list
// for a submission, so flauto knows how many clients to wait for before
// auto-starting the FL session.
func (s *Server) postRegisterExpectedProviders(w http.ResponseWriter, r *http.Request) {
	var in registerExpectedInput
	if !readBody(w, r, &in) {
		return
	}
	if in.SubmissionID == "" || in.Count <= 0 {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "MISSING_FIELDS"})
		return
	}
	s.flow.RegisterExpectedProviders(in.SubmissionID, in.Count)
	writeJSON(w, http.StatusOK, j{"status": "SUCCESS"})
}

type vmCredentialInput struct {
	CredentialID string `json:"credential_id"`
	SubmissionID string `json:"submission_id"`
	ContractID   string `json:"contract_id"`
	Username     string `json:"username"`
	UserID       string `json:"user_id"`
	OfflineToken string `json:"offline_token"`
	ExpiresAt    string `json:"expires_at"`
}

// POST /p3dx/internal/vm-credentials — the controlplane hands over a freshly issued
// VM credential (X-Internal-Key). Held in memory only until the provider's
// provisioning run claims and delivers it; never logged.
func (s *Server) postVMCredential(w http.ResponseWriter, r *http.Request) {
	var in vmCredentialInput
	if !readBody(w, r, &in) {
		return
	}
	token := []byte(in.OfflineToken)
	in.OfflineToken = ""
	err := s.creds.Put(vmcred.Credential{ID: in.CredentialID, SubmissionID: in.SubmissionID, ContractID: in.ContractID,
		Username: in.Username, UserID: in.UserID, ExpiresAt: in.ExpiresAt}, token)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "INVALID_CREDENTIAL", "message": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, j{"status": "SUCCESS"})
}
