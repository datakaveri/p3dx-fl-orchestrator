package flauto

// FL session output collection: once a session finishes (or when the output
// owner asks for it), pull the final global model and the per-round metrics
// off the server VM and push them to gov_layer, which stores and serves them.
//
//   - metrics: GET /query_past on the session gateway (service token, TLS
//     pinned to the governance CA);
//   - model:   the highest-round model_<sid>_round_<N>.<ext> in the VM's
//     deployment/checkpoints, read over SSH;
//   - upload:  POST {GovLayerURL}/fl-output/{submissionID}, multipart
//     (metrics, round, model), streamed — the model is never held in memory.
//
// The orchestrator keeps no copy of the output. To reach the server VM after
// a restart, SaveOwnerAccess keeps that VM's SSH key, known_hosts and IP
// under OutputConfig.StateDir (only for the output-owner VM).

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/s4r4v4n04/p3dx-fl-orchestrator/internal/postapply"
)

// OutputConfig is what output collection needs beyond the Manager's own
// gateway settings. A zero StateDir disables keeping the owner VM's SSH key.
type OutputConfig struct {
	GovLayerURL     string // e.g. http://localhost:8083/api/v1
	VMFlotillaDir   string // VM_FLOTILLA_DIR (relative to the VM user's home, or absolute)
	SSHUser         string
	SSHPort         string
	StateDir        string // per-submission owner-VM access: <StateDir>/<sid>/{id_ed25519,known_hosts,owner.json}
	VMRegistryToken string // X-VM-Registry-Token for gov_layer's /vm-registry (empty: not sent)
}

// sshRunner is the part of postapply.SSHTarget collection uses (stubbed in tests).
type sshRunner interface {
	Run(remote string, stdin []byte) (string, error)
	Stream(remote string, w io.Writer) error
}

// ErrCollectInFlight is returned when a collection for the submission is
// already running.
var ErrCollectInFlight = errors.New("output collection already in progress")

const (
	ownerKeyFile        = "id_ed25519"
	ownerKnownHostsFile = "known_hosts"
	ownerInfoFile       = "owner.json"
)

// ConfigureOutput sets what output collection needs; call once at startup.
func (m *Manager) ConfigureOutput(cfg OutputConfig) {
	cfg.GovLayerURL = strings.TrimRight(cfg.GovLayerURL, "/")
	m.out = cfg
}

func fileSID(submissionID string) string { return nonAlnum.ReplaceAllString(submissionID, "_") }

// SaveOwnerAccess keeps a copy of the output-owner VM's SSH private key
// (0600), its known_hosts and its IP, so output can still be collected after
// the provisioning run's temp dir is gone or the orchestrator restarts.
func (m *Manager) SaveOwnerAccess(submissionID, ip, keyPath, knownHostsPath string) error {
	if m.out.StateDir == "" || submissionID == "" {
		return nil
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("read SSH key: %w", err)
	}
	if err := os.MkdirAll(m.out.StateDir, 0o700); err != nil {
		return err
	}
	// The state dir may sit inside the repo checkout: keep it out of git.
	ignore := filepath.Join(m.out.StateDir, ".gitignore")
	if _, err := os.Stat(ignore); os.IsNotExist(err) {
		_ = os.WriteFile(ignore, []byte("*\n"), 0o600)
	}
	dir := filepath.Join(m.out.StateDir, fileSID(submissionID))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(dir, ownerKeyFile), key, 0o600); err != nil {
		return err
	}
	if kh, err := os.ReadFile(knownHostsPath); err == nil {
		_ = writeFileAtomic(filepath.Join(dir, ownerKnownHostsFile), kh, 0o600)
	}
	info, _ := json.Marshal(map[string]string{"submission_id": submissionID, "ip": ip})
	return writeFileAtomic(filepath.Join(dir, ownerInfoFile), info, 0o600)
}

func writeFileAtomic(dst string, b []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dst)
}

// StartCollectOutput runs collectOutput in the background. It returns false
// (and starts nothing) if a collection for this submission is in flight.
func (m *Manager) StartCollectOutput(submissionID string) bool {
	if !m.beginCollect(submissionID) {
		return false
	}
	go func() {
		defer m.endCollect(submissionID)
		if err := m.doCollect(submissionID); err != nil {
			log.Printf("[flauto] submission %s: output collection failed: %v", submissionID, err)
		}
	}()
	return true
}

// collectOutput pulls the session's metrics and final model off the server
// VM and uploads them to gov_layer. Idempotent; one run per submission at a
// time (ErrCollectInFlight otherwise).
func (m *Manager) collectOutput(submissionID string) error {
	if !m.beginCollect(submissionID) {
		return ErrCollectInFlight
	}
	defer m.endCollect(submissionID)
	return m.doCollect(submissionID)
}

func (m *Manager) beginCollect(id string) bool {
	m.collectMu.Lock()
	defer m.collectMu.Unlock()
	if m.collecting == nil {
		m.collecting = make(map[string]bool)
	}
	if m.collecting[id] {
		return false
	}
	m.collecting[id] = true
	return true
}

func (m *Manager) endCollect(id string) {
	m.collectMu.Lock()
	delete(m.collecting, id)
	m.collectMu.Unlock()
}

func (m *Manager) lookup(submissionID string) *submissionState {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.submissions[submissionID]
}

func (m *Manager) doCollect(submissionID string) error {
	s := m.lookup(submissionID)
	emit := func(status, msg string) {
		if s != nil {
			m.emit(s, "Collecting output", status, msg)
		}
	}
	emit("running", "Collecting the session's metrics and final model from the server VM")
	msg, err := m.collect(submissionID, s)
	if err != nil {
		emit("error", "Could not collect the session output: "+err.Error())
		return err
	}
	emit("ok", msg)
	log.Printf("[flauto] submission %s: %s", submissionID, msg)
	return nil
}

func (m *Manager) collect(submissionID string, s *submissionState) (string, error) {
	if m.out.GovLayerURL == "" {
		return "", fmt.Errorf("output collection is not configured (no gov_layer URL)")
	}
	sid := fileSID(submissionID)

	ip, pool, err := m.resolveOwner(submissionID, s)
	if err != nil {
		return "", err
	}
	target, err := m.ownerSSHTarget(submissionID, ip)
	if err != nil {
		return "", err
	}

	metrics, err := m.queryPast(ip, pool, sid)
	if err != nil {
		return "", err
	}

	file, round, size, err := m.latestModel(target, sid)
	if err != nil {
		return "", err
	}

	if err := m.uploadOutput(submissionID, metrics, round, file, size, target); err != nil {
		return "", err
	}
	return fmt.Sprintf("Round %d model (%s) and metrics delivered to the governance layer", round, humanBytes(size)), nil
}

// resolveOwner returns the server VM's IP and the gateway CA pool, from
// memory or — after a restart — from the saved owner info / gov_layer.
func (m *Manager) resolveOwner(submissionID string, s *submissionState) (string, *x509.CertPool, error) {
	var ip string
	var pool *x509.CertPool
	if s != nil {
		s.mu.Lock()
		ip, pool = s.ownerIP, s.gatewayCA
		s.mu.Unlock()
	}
	if ip == "" {
		ip = m.savedOwnerIP(submissionID)
	}
	if ip == "" {
		var err error
		if ip, err = m.registryOwnerIP(); err != nil {
			return "", nil, fmt.Errorf("server VM address unknown: %w", err)
		}
	}
	if pool == nil {
		var err error
		if pool, err = m.governanceCA(); err != nil {
			return "", nil, fmt.Errorf("gateway CA unknown: %w", err)
		}
	}
	return ip, pool, nil
}

func (m *Manager) savedOwnerIP(submissionID string) string {
	if m.out.StateDir == "" {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(m.out.StateDir, fileSID(submissionID), ownerInfoFile))
	if err != nil {
		return ""
	}
	var info struct {
		IP string `json:"ip"`
	}
	_ = json.Unmarshal(b, &info)
	return info.IP
}

func (m *Manager) govGet(rel string, hdr map[string]string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, m.out.GovLayerURL+rel, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gov_layer %s returned %d", rel, resp.StatusCode)
	}
	return body, nil
}

// registryOwnerIP asks gov_layer for the most recently registered
// output-owner VM. That registry is not per-submission, so it is only a last
// resort when neither memory nor the saved owner info has the IP.
func (m *Manager) registryOwnerIP() (string, error) {
	hdr := map[string]string{}
	if m.out.VMRegistryToken != "" {
		hdr["X-VM-Registry-Token"] = m.out.VMRegistryToken
	}
	body, err := m.govGet("/vm-registry/output-owner", hdr)
	if err != nil {
		return "", err
	}
	var out struct {
		VM struct {
			IPAddress string `json:"ip_address"`
		} `json:"vm"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.VM.IPAddress == "" {
		return "", fmt.Errorf("gov_layer /vm-registry/output-owner returned no IP")
	}
	return out.VM.IPAddress, nil
}

// governanceCA fetches the governance CA, which signs every session gateway's
// certificate.
func (m *Manager) governanceCA() (*x509.CertPool, error) {
	body, err := m.govGet("/governance/ca-cert", nil)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(body) {
		return nil, fmt.Errorf("gov_layer /governance/ca-cert returned no certificate")
	}
	return pool, nil
}

func (m *Manager) ownerSSHTarget(submissionID, ip string) (sshRunner, error) {
	if m.out.StateDir == "" {
		return nil, fmt.Errorf("no saved SSH access to the server VM (state dir not configured)")
	}
	dir := filepath.Join(m.out.StateDir, fileSID(submissionID))
	key := filepath.Join(dir, ownerKeyFile)
	if _, err := os.Stat(key); err != nil {
		return nil, fmt.Errorf("no saved SSH key for this session's server VM (%s)", key)
	}
	t := postapply.SSHTarget{Host: ip, User: m.out.SSHUser, Port: m.out.SSHPort,
		KeyPath: key, KnownHosts: filepath.Join(dir, ownerKnownHostsFile)}
	if m.newSSH != nil {
		return m.newSSH(t), nil
	}
	return t, nil
}

// pastSession is flo_server's /query_past response (the parts forwarded).
type pastSession struct {
	Status                  string          `json:"status"`
	StartTimestamp          json.RawMessage `json:"start_timestamp"`
	EndTimestamp            json.RawMessage `json:"end_timestamp"`
	LastCheckpointRound     json.RawMessage `json:"last_checkpoint_round"`
	GlobalValidationMetrics json.RawMessage `json:"global_validation_metrics"`
	SessionConfig           json.RawMessage `json:"session_config"`
}

// queryPast reads the finished session's state from flo_server, retrying a
// few times: right after /execute_command returns, Redis may not be final
// yet (/query_past answers 400 "running" or 404 "not_found").
func (m *Manager) queryPast(ip string, pool *x509.CertPool, sid string) (*pastSession, error) {
	attempts, wait := m.queryPastAttempts, m.queryPastWait
	if attempts <= 0 {
		attempts = 5
	}
	if wait <= 0 {
		wait = 5 * time.Second
	}
	u := fmt.Sprintf("https://%s:%d/query_past?session_id=%s", ip, m.restPort, url.QueryEscape(sid))
	var lastErr error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			time.Sleep(wait)
		}
		req, err := m.gatewayRequest(http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		resp, err := httpsClient(pool, 30*time.Second).Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("query_past returned %d: %s", resp.StatusCode, truncate(string(body), 200))
			continue
		}
		var ps pastSession
		if err := json.Unmarshal(body, &ps); err != nil {
			return nil, fmt.Errorf("query_past: %w", err)
		}
		if ps.Status != "completed" {
			lastErr = fmt.Errorf("query_past status %q", ps.Status)
			continue
		}
		return &ps, nil
	}
	return nil, fmt.Errorf("session metrics: %w", lastErr)
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n]
	}
	return s
}

func (m *Manager) checkpointDir() string {
	dir := m.out.VMFlotillaDir
	if dir == "" {
		dir = "flotilla"
	}
	p := path.Join(dir, "deployment", "checkpoints")
	if strings.HasPrefix(dir, "/") {
		return shellQuote(p)
	}
	return "~/" + shellQuote(p) // ~ must stay unquoted to expand
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// latestModel finds the highest-round model file for sid on the VM and its size.
func (m *Manager) latestModel(t sshRunner, sid string) (string, int, int64, error) {
	dir := m.checkpointDir()
	out, err := t.Run("sudo ls -1 "+dir, nil)
	if err != nil {
		return "", 0, 0, fmt.Errorf("list checkpoints: %w", err)
	}
	file, round, ok := pickLatestModel(strings.Split(out, "\n"), sid)
	if !ok {
		return "", 0, 0, fmt.Errorf("no model_%s_round_<N> checkpoint on the server VM", sid)
	}
	st, err := t.Run("sudo stat -c %s "+dir+"/"+shellQuote(file), nil)
	if err != nil {
		return "", 0, 0, fmt.Errorf("stat %s: %w", file, err)
	}
	size, err := strconv.ParseInt(strings.TrimSpace(st), 10, 64)
	if err != nil {
		return "", 0, 0, fmt.Errorf("stat %s: unexpected output %q", file, truncate(st, 80))
	}
	return file, round, size, nil
}

// pickLatestModel returns the model_<sid>_round_<N>.<ext> entry with the
// largest N (numerically: round_10 beats round_9).
func pickLatestModel(names []string, sid string) (string, int, bool) {
	re := regexp.MustCompile(`^model_` + regexp.QuoteMeta(sid) + `_round_(\d+)\.[A-Za-z0-9]+$`)
	best, bestRound := "", -1
	for _, n := range names {
		n = strings.TrimSpace(n)
		mm := re.FindStringSubmatch(n)
		if mm == nil {
			continue
		}
		r, err := strconv.Atoi(mm[1])
		if err != nil {
			continue
		}
		if r > bestRound {
			best, bestRound = n, r
		}
	}
	return best, bestRound, bestRound >= 0
}

// metricsDoc is the `metrics` part of the upload (contract with gov_layer).
type metricsDoc struct {
	GlobalValidationMetrics json.RawMessage `json:"global_validation_metrics"`
	SessionConfig           json.RawMessage `json:"session_config"`
	StartTimestamp          json.RawMessage `json:"start_timestamp"`
	EndTimestamp            json.RawMessage `json:"end_timestamp"`
	LastCheckpointRound     json.RawMessage `json:"last_checkpoint_round"`
	RoundsTotal             *int            `json:"rounds_total"`
}

func orNull(r json.RawMessage) json.RawMessage {
	if len(r) == 0 {
		return json.RawMessage("null")
	}
	return r
}

func buildMetrics(ps *pastSession) ([]byte, error) {
	return json.Marshal(metricsDoc{
		GlobalValidationMetrics: orNull(ps.GlobalValidationMetrics),
		SessionConfig:           orNull(ps.SessionConfig),
		StartTimestamp:          orNull(ps.StartTimestamp),
		EndTimestamp:            orNull(ps.EndTimestamp),
		LastCheckpointRound:     orNull(ps.LastCheckpointRound),
		RoundsTotal:             roundsTotal(ps.SessionConfig),
	})
}

var roundsKeys = []string{"max_rounds", "num_rounds", "total_rounds", "rounds"}

// roundsTotal looks for a rounds count in session_config (e.g.
// termination_condition_args.max_rounds), searching a few levels deep.
func roundsTotal(raw json.RawMessage) *int {
	var v any
	if len(raw) == 0 || json.Unmarshal(raw, &v) != nil {
		return nil
	}
	return findRounds(v, 0)
}

func findRounds(v any, depth int) *int {
	obj, ok := v.(map[string]any)
	if !ok || depth > 3 {
		return nil
	}
	for _, k := range roundsKeys {
		if n, ok := obj[k].(float64); ok && n > 0 && n == float64(int(n)) {
			i := int(n)
			return &i
		}
	}
	for _, child := range obj {
		if r := findRounds(child, depth+1); r != nil {
			return r
		}
	}
	return nil
}

// countingWriter counts bytes written through it.
type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// uploadOutput streams metrics + the model straight from SSH stdout into a
// multipart request to gov_layer (parts in order: metrics, round, model).
func (m *Manager) uploadOutput(submissionID string, ps *pastSession, round int, file string, size int64, t sshRunner) error {
	metrics, err := buildMetrics(ps)
	if err != nil {
		return err
	}
	tok, err := m.token()
	if err != nil {
		return err
	}

	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	writeErr := make(chan error, 1)
	go func() {
		err := func() error {
			if err := mw.WriteField("metrics", string(metrics)); err != nil {
				return err
			}
			if err := mw.WriteField("round", strconv.Itoa(round)); err != nil {
				return err
			}
			part, err := mw.CreateFormFile("model", file)
			if err != nil {
				return err
			}
			cw := &countingWriter{w: part}
			if err := t.Stream("sudo cat "+m.checkpointDir()+"/"+shellQuote(file), cw); err != nil {
				return fmt.Errorf("read model: %w", err)
			}
			if cw.n != size {
				return fmt.Errorf("read model: got %d bytes, expected %d", cw.n, size)
			}
			return mw.Close()
		}()
		// An error here aborts the request body, so gov_layer never sees a
		// complete (closing-boundary) upload.
		pw.CloseWithError(err)
		writeErr <- err
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		m.out.GovLayerURL+"/fl-output/"+url.PathEscape(submissionID), pr)
	if err != nil {
		pr.CloseWithError(err)
		<-writeErr
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", mw.FormDataContentType())

	client := m.uploadClient
	if client == nil {
		client = &http.Client{} // no overall timeout: the model may be large
	}
	resp, doErr := client.Do(req)
	var status int
	var body []byte
	if doErr == nil {
		status = resp.StatusCode
		body, _ = io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
	}
	pr.CloseWithError(errors.New("upload finished")) // unblock the writer if gov_layer stopped reading
	wErr := <-writeErr
	if doErr == nil && status != http.StatusCreated {
		return fmt.Errorf("upload to gov_layer returned %d: %s", status, truncate(string(body), 200))
	}
	if wErr != nil {
		return wErr
	}
	if doErr != nil {
		return fmt.Errorf("upload to gov_layer: %w", doErr)
	}
	return nil
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}
