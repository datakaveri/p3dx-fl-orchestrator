package flauto

import (
	"context"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"github.com/s4r4v4n04/p3dx-fl-orchestrator/internal/vmsession"
)

const defaultRoundPollInterval = 15 * time.Second

// roundFileRe matches flo_server's global-model download name,
// global_model_round_<N>.<ext>.
var roundFileRe = regexp.MustCompile(`global_model_round_(\d+)\.`)

// latestRound reports how many rounds the running session has completed.
//
// We can't change Flotilla (flo_server.py) to expose round progress, and its
// /get_status says only "running". GET /get_latest_gm, though, answers a
// running session with the current global model as an attachment named
// global_model_round_<last_round_number>.<ext>, and last_round_number
// increments after each aggregation — so the round comes from that filename.
// Only the headers are read: the body (the whole model) is closed unread so
// no poll downloads it. ok is false for every "no round yet" answer — 200
// JSON idle/not_found, 404 "Global model not available yet", any error.
func (m *Manager) latestRound(ctx context.Context, client *http.Client, ownerIP, sessionID string) (round int, ok bool) {
	u := fmt.Sprintf("https://%s:%d/get_latest_gm?session_id=%s", ownerIP, m.restPort, url.QueryEscape(sessionID))
	req, err := m.gatewayRequest(http.MethodGet, u, nil)
	if err != nil {
		return 0, false
	}
	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return 0, false
	}
	// Closing without draining drops the connection rather than reading the
	// model to reuse it — exactly what we want.
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, false
	}
	return roundFromDisposition(resp.Header.Get("Content-Disposition"))
}

// roundFromDisposition extracts N from a Content-Disposition naming
// global_model_round_<N>.<ext>, in filename= or RFC 5987 filename*= form.
func roundFromDisposition(cd string) (int, bool) {
	if cd == "" {
		return 0, false
	}
	name := ""
	if _, params, err := mime.ParseMediaType(cd); err == nil {
		name = params["filename"] // ParseMediaType decodes filename* into this key too
	}
	if name == "" {
		name = cd // malformed header: match the raw text
	}
	match := roundFileRe.FindStringSubmatch(name)
	if match == nil {
		return 0, false
	}
	n, err := strconv.Atoi(match[1])
	if err != nil {
		return 0, false
	}
	return n, true
}

// startRoundPoller polls the round of a running session every
// roundPollInterval and reports each new one as a single "Training round"
// event, replaced in place. The returned stop cancels any in-flight request
// and waits for the poller to exit, so no round event can land after the
// session's final event.
func (m *Manager) startRoundPoller(s *submissionState, ownerIP, sessionID string, maxRounds int) (stop func()) {
	interval := m.roundPollInterval
	if interval <= 0 {
		interval = defaultRoundPollInterval
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		client := m.client(s, interval)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		last := 0
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			n, ok := m.latestRound(ctx, client, ownerIP, sessionID)
			if !ok || n <= last || ctx.Err() != nil {
				continue // round 0 = nothing aggregated yet
			}
			last = n
			msg := fmt.Sprintf("Round %d of %d complete", n, maxRounds)
			if maxRounds <= 0 {
				msg = fmt.Sprintf("Round %d complete", n)
			}
			m.emitReplace(s, vmsession.Event{Step: "Training round", Status: "running", Message: msg, Round: n, MaxRounds: maxRounds})
		}
	}()
	return func() {
		cancel()
		<-done
	}
}

// emitReplace is emit for progress that replaces its previous event.
func (m *Manager) emitReplace(s *submissionState, ev vmsession.Event) {
	s.mu.Lock()
	tokens := make([]string, 0, len(s.tokens))
	for t := range s.tokens {
		tokens = append(tokens, t)
	}
	s.mu.Unlock()
	for _, token := range tokens {
		m.store.ReplaceEvent(token, ev)
	}
}

// quicksetupMaxRounds is the round count the quicksetup config would run.
func quicksetupMaxRounds() int {
	session, _ := flotillaQuicksetupConfig["session_config"].(map[string]any)
	args, _ := session["termination_condition_args"].(map[string]any)
	n, _ := args["max_rounds"].(int)
	return n
}
