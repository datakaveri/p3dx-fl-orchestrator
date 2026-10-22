// Package flauto automatically starts the actual FL training session once
// the output-owner's server VM is up AND every provider selected for that
// submission has connected their client — this is "the post flow" that runs
// after the fl-orchestrator operator clicks "Sign in with Azure & Start
// Session": nothing else in this platform ever calls flo_server.py's
// POST /execute_command otherwise.
//
// Ported from p3dx-aaa/src/services/flSessionAuto.service.js. Readiness is
// judged by *count* (connected clients >= selected providers), not identity —
// flo_server's /client_status keys clients by whatever CLIENT_NAME each
// provider's VM was given, which is an arbitrary name they typed, not their
// platform username.
//
// Progress is surfaced by piggybacking on the existing VM-provisioning SSE
// plumbing (vmsession.Store.AppendEvent) rather than a new stream: every
// provisioning token associated with this submission (the owner's VM run,
// plus each provider's VM run) gets the same "Waiting for clients"/"Starting
// FL session" events appended.
package flauto

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/s4r4v4n04/p3dx-fl-orchestrator/internal/postapply"
	"github.com/s4r4v4n04/p3dx-fl-orchestrator/internal/vmsession"
)

// TokenFunc returns the orchestrator's service-account access token; the
// session gateway's REST API accepts only that token, over TLS.
type TokenFunc func() (string, error)

const (
	pollInterval = 5 * time.Second
	maxWait      = 2 * time.Hour // give up after 2h of not everyone connecting
)

var nonAlnum = regexp.MustCompile(`[^a-zA-Z0-9_-]`)

type submissionState struct {
	mu                    sync.Mutex
	expectedProviderCount int
	ownerIP               string
	tokens                map[string]struct{}
	gatewayCA             *x509.CertPool // the session gateway's CA (gov_layer's governance CA)
	gatewayCAPEM          string
	ownerReady            chan struct{}  // closed once ownerIP is set
	lastConnectedCount    int
	started               bool
	polling               bool
	pollStartedAt         time.Time
}

// Manager tracks FL auto-start state per submission.
type Manager struct {
	store    *vmsession.Store
	token    TokenFunc
	restPort int

	mu          sync.Mutex
	submissions map[string]*submissionState

	// output collection (output.go)
	out               OutputConfig
	collectMu         sync.Mutex
	collecting        map[string]bool
	newSSH            func(postapply.SSHTarget) sshRunner // tests: stub SSH
	uploadClient      *http.Client                        // tests: nil = default client
	queryPastAttempts int
	queryPastWait     time.Duration
}

func NewManager(store *vmsession.Store, token TokenFunc, restPort int) *Manager {
	return &Manager{
		store:       store,
		token:       token,
		restPort:    restPort,
		submissions: make(map[string]*submissionState),
	}
}

// client returns an HTTPS client that trusts only this session gateway's CA.
// The gateway certificate names the server VM's IP, so the URL uses the IP.
func (m *Manager) client(s *submissionState, timeout time.Duration) *http.Client {
	s.mu.Lock()
	pool := s.gatewayCA
	s.mu.Unlock()
	return httpsClient(pool, timeout)
}

func httpsClient(pool *x509.CertPool, timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	}}
}

// gatewayRequest builds an authenticated request to the session gateway.
func (m *Manager) gatewayRequest(method, url string, body []byte) (*http.Request, error) {
	tok, err := m.token()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

// SetGatewayCA records the CA the session gateway's certificate chains to
// (from gov_layer's /gateway-certs response); flauto will not talk to the
// gateway before it is set.
func (m *Manager) SetGatewayCA(submissionID, caPEM string) error {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(caPEM)) {
		return fmt.Errorf("invalid gateway CA PEM")
	}
	s := m.getOrCreate(submissionID)
	s.mu.Lock()
	s.gatewayCA, s.gatewayCAPEM = pool, caPEM
	s.mu.Unlock()
	return nil
}

// WaitOwnerIP blocks until this submission's server VM is up (its gateway
// secured) and returns its IP — so each client VM is pointed at its OWN
// session's gateway, not "the latest output-owner VM" overall.
func (m *Manager) WaitOwnerIP(submissionID string, timeout time.Duration) (string, string, error) {
	s := m.getOrCreate(submissionID)
	select {
	case <-s.ownerReady:
	case <-time.After(timeout):
		return "", "", fmt.Errorf("server VM for submission %s not ready after %s", submissionID, timeout)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ownerIP, s.gatewayCAPEM, nil
}

func (m *Manager) getOrCreate(submissionID string) *submissionState {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.submissions[submissionID]
	if !ok {
		s = &submissionState{
			tokens:             make(map[string]struct{}),
			ownerReady:         make(chan struct{}),
			lastConnectedCount: -1,
		}
		m.submissions[submissionID] = s
	}
	return s
}

func (m *Manager) emit(s *submissionState, step, status, message string) {
	s.mu.Lock()
	tokens := make([]string, 0, len(s.tokens))
	for t := range s.tokens {
		tokens = append(tokens, t)
	}
	s.mu.Unlock()
	for _, token := range tokens {
		m.store.AppendEvent(token, step, "", status, message)
	}
}

// RegisterExpectedProviders is called once POST /internal/register-expected-providers
// (from p3dx-aaa's /gov/start-fl-session, which already knows the full
// participating_providers list) arrives for this submission.
func (m *Manager) RegisterExpectedProviders(submissionID string, count int) {
	if submissionID == "" || count == 0 {
		return
	}
	s := m.getOrCreate(submissionID)
	s.mu.Lock()
	s.expectedProviderCount = count
	s.mu.Unlock()
	m.maybeStartPolling(submissionID, s)
}

// RegisterProviderToken is called once a provider's own VM auto-create run
// has a token, so they get the fan-out events on their panel too.
func (m *Manager) RegisterProviderToken(submissionID, token string) {
	if submissionID == "" || token == "" {
		return
	}
	s := m.getOrCreate(submissionID)
	s.mu.Lock()
	s.tokens[token] = struct{}{}
	s.mu.Unlock()
}

// RegisterOwnerVM is called once the owner's ("user" role) VM run succeeds
// and its public IP is known — that VM is the one running flo_server.py.
func (m *Manager) RegisterOwnerVM(submissionID, ip, token string) {
	if submissionID == "" || ip == "" {
		return
	}
	s := m.getOrCreate(submissionID)
	s.mu.Lock()
	first := s.ownerIP == ""
	s.ownerIP = ip
	if token != "" {
		s.tokens[token] = struct{}{}
	}
	s.mu.Unlock()
	if first {
		close(s.ownerReady)
	}
	m.maybeStartPolling(submissionID, s)
}

func (m *Manager) maybeStartPolling(submissionID string, s *submissionState) {
	s.mu.Lock()
	if s.polling || s.started || s.ownerIP == "" || s.expectedProviderCount == 0 {
		s.mu.Unlock()
		return
	}
	s.polling = true
	s.pollStartedAt = time.Now()
	expected := s.expectedProviderCount
	s.mu.Unlock()

	m.emit(s, "Waiting for clients", "running", fmt.Sprintf("0/%d providers connected", expected))

	go m.pollLoop(submissionID, s)
}

func (m *Manager) pollLoop(submissionID string, s *submissionState) {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	m.pollOnce(submissionID, s)
	for range ticker.C {
		if m.pollOnce(submissionID, s) {
			return
		}
	}
}

// pollOnce returns true once polling should stop (started or gave up).
func (m *Manager) pollOnce(submissionID string, s *submissionState) bool {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return true
	}
	if time.Since(s.pollStartedAt) > maxWait {
		expected := s.expectedProviderCount
		s.mu.Unlock()
		m.emit(s, "Waiting for clients", "error",
			fmt.Sprintf("Gave up after 2h — not all %d provider(s) connected. Start the session manually over SSH once they do.", expected))
		return true
	}
	ownerIP := s.ownerIP
	expected := s.expectedProviderCount
	lastCount := s.lastConnectedCount
	s.mu.Unlock()

	count, err := m.clientCount(s, ownerIP)
	if err != nil {
		// server VM likely still booting/pulling images - not worth surfacing every 5s
		return false
	}

	if count != lastCount {
		s.mu.Lock()
		s.lastConnectedCount = count
		s.mu.Unlock()
		m.emit(s, "Waiting for clients", "running", fmt.Sprintf("%d/%d providers connected", count, expected))
	}

	if count >= expected {
		s.mu.Lock()
		s.started = true
		s.mu.Unlock()
		m.startSession(submissionID, s)
		return true
	}
	return false
}

func (m *Manager) clientCount(s *submissionState, ownerIP string) (int, error) {
	req, err := m.gatewayRequest(http.MethodGet, fmt.Sprintf("https://%s:%d/client_status", ownerIP, m.restPort), nil)
	if err != nil {
		return 0, err
	}
	resp, err := m.client(s, 10*time.Second).Do(req)
	if err != nil {
		return 0, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return 0, fmt.Errorf("gateway returned %d", resp.StatusCode)
	}
	defer resp.Body.Close()
	var body struct {
		Clients map[string]any `json:"clients"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return 0, err
	}
	return len(body.Clients), nil
}

func (m *Manager) startSession(submissionID string, s *submissionState) {
	m.emit(s, "Starting FL session", "running", "All expected providers connected — starting training")

	sessionID := nonAlnum.ReplaceAllString(submissionID, "_")
	body := map[string]any{
		"federated_learning_config": flotillaQuicksetupConfig,
		"session_id":                sessionID,
		"file":                      false,
		"restore":                   false,
		"revive":                    false,
	}
	payload, _ := json.Marshal(body)

	s.mu.Lock()
	ownerIP := s.ownerIP
	s.mu.Unlock()

	// POST /execute_command blocks server-side until the whole training run
	// finishes (could be a long time) - fire it and move on instead of
	// blocking this goroutine on it; its eventual resolution/rejection
	// becomes one more event for whoever's still watching this submission's
	// panels.
	go func() {
		req, err := m.gatewayRequest(http.MethodPost, fmt.Sprintf("https://%s:%d/execute_command", ownerIP, m.restPort), payload)
		if err != nil {
			m.emit(s, "FL session", "error", err.Error())
			return
		}
		// no timeout — mirrors the Node version's timeout: 0
		resp, err := m.client(s, 0).Do(req)
		if err != nil {
			m.emit(s, "FL session", "error", err.Error())
			return
		}
		defer resp.Body.Close()
		var out struct {
			Message string `json:"message"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&out)
		if resp.StatusCode >= 300 {
			msg := out.Message
			if msg == "" {
				msg = fmt.Sprintf("flo_server returned status %d", resp.StatusCode)
			}
			m.emit(s, "FL session", "error", msg)
			return
		}
		msg := out.Message
		if msg == "" {
			msg = fmt.Sprintf("Session %s finished", sessionID)
		}
		m.emit(s, "FL session", "done", msg)
		// Pull the final model + metrics into gov_layer straight away; the
		// output owner can re-trigger it (POST /p3dx/fl-output/{id}/collect).
		go func() {
			if err := m.collectOutput(submissionID); err != nil {
				log.Printf("[flauto] submission %s: output collection: %v", submissionID, err)
			}
		}()
	}()

	m.emit(s, "Starting FL session", "ok", fmt.Sprintf("Session %s started — training is now running on the server VM", sessionID))
	log.Printf("[flauto] submission %s: FL session %s started on %s", submissionID, sessionID, ownerIP)
}
