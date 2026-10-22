package httpapi

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

// POST /p3dx/fl-output/{submissionId}/collect — (re)collect a finished FL
// session's output (final model + metrics) from its server VM into
// gov_layer. Runs in the background; progress shows as "Collecting output"
// events on the submission's provisioning panels. Returns no output data:
// reading it stays gated by gov_layer's owner check.
func (s *Server) postCollectFLOutput(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(chi.URLParam(r, "submissionId"))
	if id == "" || len(id) > 200 {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "INVALID_SUBMISSION_ID"})
		return
	}
	if !s.flow.StartCollectOutput(id) {
		writeJSON(w, http.StatusAccepted, j{"status": "already_collecting"})
		return
	}
	writeJSON(w, http.StatusAccepted, j{"status": "collecting"})
}
