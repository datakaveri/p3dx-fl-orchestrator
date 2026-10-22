package flauto

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/s4r4v4n04/p3dx-fl-orchestrator/internal/postapply"
	"github.com/s4r4v4n04/p3dx-fl-orchestrator/internal/vmsession"
)

func TestPickLatestModel(t *testing.T) {
	names := []string{
		"model_sub_1_round_9.pt",
		"model_sub_1_round_10.pt", // numerically highest, lexically lower than round_9
		"model_sub_1_round_2.weights",
		"model_sub_10_round_99.pt", // different session
		"model_sub_1_round_x.pt",
		"notes.txt", "",
	}
	file, round, ok := pickLatestModel(names, "sub_1")
	if !ok || file != "model_sub_1_round_10.pt" || round != 10 {
		t.Fatalf("pickLatestModel = %q %d %v", file, round, ok)
	}
	if _, _, ok := pickLatestModel([]string{"model_other_round_3.pt"}, "sub_1"); ok {
		t.Fatal("matched another session's checkpoint")
	}
}

func TestRoundsTotal(t *testing.T) {
	got := roundsTotal(json.RawMessage(`{"session_id":"x","termination_condition_args":{"max_rounds":100}}`))
	if got == nil || *got != 100 {
		t.Fatalf("nested max_rounds: %v", got)
	}
	if got := roundsTotal(json.RawMessage(`{"aggregator":"fedavg"}`)); got != nil {
		t.Fatalf("no rounds key: %v", *got)
	}
	if got := roundsTotal(nil); got != nil {
		t.Fatal("nil config")
	}
}

// fakeSSH emulates the server VM's checkpoint dir.
type fakeSSH struct {
	mu      sync.Mutex
	host    string
	files   map[string][]byte
	short   bool // Stream sends one byte less than stat reports
	remotes []string
}

func (f *fakeSSH) Run(remote string, _ []byte) (string, error) {
	f.mu.Lock()
	f.remotes = append(f.remotes, remote)
	f.mu.Unlock()
	switch {
	case strings.HasPrefix(remote, "sudo ls -1 "):
		var b strings.Builder
		for n := range f.files {
			b.WriteString(n + "\n")
		}
		return b.String(), nil
	case strings.HasPrefix(remote, "sudo stat -c %s "):
		for n, c := range f.files {
			if strings.HasSuffix(remote, "/'"+n+"'") {
				return fmt.Sprintf("%d\n", len(c)), nil
			}
		}
	}
	return "", fmt.Errorf("unexpected remote %q", remote)
}

func (f *fakeSSH) Stream(remote string, w io.Writer) error {
	f.mu.Lock()
	f.remotes = append(f.remotes, remote)
	f.mu.Unlock()
	for n, c := range f.files {
		if strings.HasPrefix(remote, "sudo cat ") && strings.HasSuffix(remote, "/'"+n+"'") {
			if f.short {
				c = c[:len(c)-1]
			}
			// write in chunks, like ssh stdout
			for len(c) > 0 {
				k := min(len(c), 1000)
				if _, err := w.Write(c[:k]); err != nil {
					return err
				}
				c = c[k:]
			}
			return nil
		}
	}
	return fmt.Errorf("unexpected remote %q", remote)
}

type upload struct {
	auth, path string
	parts      []string // form names in order
	metrics    map[string]any
	round      string
	filename   string
	model      []byte
	err        error
}

type govFake struct {
	srv      *httptest.Server
	caPEM    string
	ownerIP  string
	mu       sync.Mutex
	uploads  []upload
	caCalls  int
	regCalls int
	regToken string
}

func newGovFake(t *testing.T) *govFake {
	g := &govFake{}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/governance/ca-cert", func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		g.caCalls++
		g.mu.Unlock()
		_, _ = w.Write([]byte(g.caPEM))
	})
	mux.HandleFunc("/api/v1/vm-registry/output-owner", func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		g.regCalls++
		g.regToken = r.Header.Get("X-VM-Registry-Token")
		g.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "SUCCESS", "vm": map[string]string{"ip_address": g.ownerIP}})
	})
	mux.HandleFunc("/api/v1/fl-output/", func(w http.ResponseWriter, r *http.Request) {
		u := upload{auth: r.Header.Get("Authorization"), path: r.URL.EscapedPath()}
		u.err = func() error {
			mr, err := r.MultipartReader()
			if err != nil {
				return err
			}
			for {
				p, err := mr.NextPart()
				if err == io.EOF {
					return nil
				}
				if err != nil {
					return err
				}
				b, err := io.ReadAll(p)
				if err != nil {
					return err
				}
				u.parts = append(u.parts, p.FormName())
				switch p.FormName() {
				case "metrics":
					if err := json.Unmarshal(b, &u.metrics); err != nil {
						return err
					}
				case "round":
					u.round = string(b)
				case "model":
					u.filename, u.model = p.FileName(), b
				}
			}
		}()
		g.mu.Lock()
		g.uploads = append(g.uploads, u)
		g.mu.Unlock()
		if u.err != nil {
			http.Error(w, u.err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusCreated)
	})
	g.srv = httptest.NewServer(mux)
	t.Cleanup(g.srv.Close)
	return g
}

// queryPastGateway serves /query_past, failing the first `fails` calls with
// 404 (Redis not final yet).
func queryPastGateway(t *testing.T, fails int) (*gateway, *[]string) {
	g := newGateway(t)
	var mu sync.Mutex
	var seen []string
	calls := 0
	g.srv.Config.Handler.(*http.ServeMux).HandleFunc("/query_past", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		n := calls
		seen = append(seen, r.Header.Get("Authorization")+" "+r.URL.Query().Get("session_id"))
		mu.Unlock()
		if n <= fails {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"status":"not_found"}`))
			return
		}
		_, _ = w.Write([]byte(`{"session_id":"sub_1","status":"completed","start_timestamp":1700000000.5,
			"end_timestamp":1700000900.25,"last_checkpoint_round":10,
			"global_validation_metrics":{"accuracy":[0.1,0.5,0.8],"loss":[2.0,1.0,0.5]},
			"session_config":{"session_id":"sub_1","termination_condition_args":{"max_rounds":100}}}`))
	})
	return g, &seen
}

func modelBytes() []byte {
	b := make([]byte, 50_000)
	for i := range b {
		b[i] = byte(i * 7)
	}
	return b
}

func setupOutputManager(t *testing.T, gw *gateway, gov *govFake, ssh *fakeSSH) (*Manager, string) {
	t.Helper()
	m := NewManager(vmsession.NewStore(), staticToken("svc-token"), gw.port)
	m.ConfigureOutput(OutputConfig{
		GovLayerURL: gov.srv.URL + "/api/v1/", VMFlotillaDir: "flotilla",
		SSHUser: "azureuser", SSHPort: "22", StateDir: t.TempDir(), VMRegistryToken: "reg-secret",
	})
	m.queryPastAttempts, m.queryPastWait = 3, time.Millisecond
	m.newSSH = func(tg postapply.SSHTarget) sshRunner {
		ssh.mu.Lock()
		ssh.host = tg.Host
		ssh.mu.Unlock()
		return ssh
	}
	// The provisioning run's key + known_hosts, saved for the owner VM.
	runDir := t.TempDir()
	key, kh := filepath.Join(runDir, "id_ed25519"), filepath.Join(runDir, "known_hosts")
	_ = os.WriteFile(key, []byte("PRIVATE KEY"), 0o600)
	_ = os.WriteFile(kh, []byte("host-key"), 0o600)
	if err := m.SaveOwnerAccess("sub/1", "127.0.0.1", key, kh); err != nil {
		t.Fatal(err)
	}
	return m, runDir
}

func TestCollectOutputUploadsLatestModelAndMetrics(t *testing.T) {
	gw, seen := queryPastGateway(t, 1)
	gov := newGovFake(t)
	model := modelBytes()
	ssh := &fakeSSH{files: map[string][]byte{
		"model_sub_1_round_9.pt":  []byte("old"),
		"model_sub_1_round_10.pt": model,
		"model_sub_2_round_50.pt": []byte("other"),
	}}
	m, _ := setupOutputManager(t, gw, gov, ssh)

	// Live state: owner VM registered, CA known, a panel watching.
	runTok := m.store.CreateToken("owner", "user")
	if err := m.SetGatewayCA("sub/1", gw.caPEM()); err != nil {
		t.Fatal(err)
	}
	m.RegisterOwnerVM("sub/1", "127.0.0.1", runTok)

	if err := m.collectOutput("sub/1"); err != nil {
		t.Fatalf("collectOutput: %v", err)
	}

	if len(*seen) != 2 || (*seen)[1] != "Bearer svc-token sub_1" {
		t.Fatalf("query_past calls = %v (want a retry after 404)", *seen)
	}
	if len(gov.uploads) != 1 {
		t.Fatalf("uploads = %d", len(gov.uploads))
	}
	u := gov.uploads[0]
	if u.err != nil {
		t.Fatalf("multipart: %v", u.err)
	}
	if u.auth != "Bearer svc-token" || u.path != "/api/v1/fl-output/sub%2F1" {
		t.Fatalf("auth/path = %q %q", u.auth, u.path)
	}
	if strings.Join(u.parts, ",") != "metrics,round,model" {
		t.Fatalf("part order = %v", u.parts)
	}
	if u.round != "10" || u.filename != "model_sub_1_round_10.pt" || !bytes.Equal(u.model, model) {
		t.Fatalf("round=%q file=%q model bytes equal=%v", u.round, u.filename, bytes.Equal(u.model, model))
	}
	md := u.metrics
	for _, k := range []string{"global_validation_metrics", "session_config", "start_timestamp", "end_timestamp", "last_checkpoint_round", "rounds_total"} {
		if _, ok := md[k]; !ok {
			t.Errorf("metrics missing %q", k)
		}
	}
	if md["rounds_total"] != float64(100) || md["last_checkpoint_round"] != float64(10) {
		t.Fatalf("metrics = %v", md)
	}
	if acc := md["global_validation_metrics"].(map[string]any)["accuracy"].([]any); len(acc) != 3 {
		t.Fatalf("accuracy = %v", acc)
	}
	// In-memory state was enough: no gov_layer fallbacks.
	if gov.caCalls != 0 || gov.regCalls != 0 {
		t.Fatalf("unexpected fallbacks: ca=%d reg=%d", gov.caCalls, gov.regCalls)
	}
	for _, r := range ssh.remotes {
		if !strings.Contains(r, "~/'flotilla/deployment/checkpoints'") {
			t.Errorf("remote outside checkpoint dir: %q", r)
		}
	}

	snap, _ := m.store.Get(runTok)
	var statuses []string
	for _, e := range snap.Events {
		if e.Step == "Collecting output" {
			statuses = append(statuses, e.Status)
		}
	}
	if strings.Join(statuses, ",") != "running,ok" {
		t.Fatalf("Collecting output events = %v", statuses)
	}
}

func TestCollectOutputAfterRestartUsesSavedAccessAndGovCA(t *testing.T) {
	gw, _ := queryPastGateway(t, 0)
	gov := newGovFake(t)
	gov.caPEM = gw.caPEM()
	ssh := &fakeSSH{files: map[string][]byte{"model_sub_1_round_3.pt": []byte("weights")}}
	m, _ := setupOutputManager(t, gw, gov, ssh)

	// No submissionState at all (fresh process): IP from the saved owner
	// info, CA from gov_layer.
	if err := m.collectOutput("sub/1"); err != nil {
		t.Fatalf("collectOutput: %v", err)
	}
	if gov.caCalls != 1 || gov.regCalls != 0 || ssh.host != "127.0.0.1" {
		t.Fatalf("ca=%d reg=%d host=%q", gov.caCalls, gov.regCalls, ssh.host)
	}
	if len(gov.uploads) != 1 || gov.uploads[0].round != "3" || string(gov.uploads[0].model) != "weights" {
		t.Fatalf("uploads = %+v", gov.uploads)
	}

	// Saved owner info gone: last resort is gov_layer's vm-registry.
	_ = os.Remove(filepath.Join(m.out.StateDir, "sub_1", ownerInfoFile))
	gov.ownerIP = "127.0.0.1"
	if err := m.collectOutput("sub/1"); err != nil {
		t.Fatalf("collectOutput via registry: %v", err)
	}
	if gov.regCalls != 1 || gov.regToken != "reg-secret" {
		t.Fatalf("registry calls=%d token=%q", gov.regCalls, gov.regToken)
	}
}

func TestSaveOwnerAccessPermissions(t *testing.T) {
	gw, _ := queryPastGateway(t, 0)
	m, _ := setupOutputManager(t, gw, newGovFake(t), &fakeSSH{})
	dir := filepath.Join(m.out.StateDir, "sub_1")
	for _, f := range []string{ownerKeyFile, ownerKnownHostsFile, ownerInfoFile} {
		st, err := os.Stat(filepath.Join(dir, f))
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %v", f, st.Mode().Perm())
		}
	}
	if b, _ := os.ReadFile(filepath.Join(dir, ownerKeyFile)); string(b) != "PRIVATE KEY" {
		t.Fatalf("key = %q", b)
	}
	if m.savedOwnerIP("sub/1") != "127.0.0.1" {
		t.Fatal("owner IP not saved")
	}
}

func TestCollectOutputNoSavedKey(t *testing.T) {
	gw, _ := queryPastGateway(t, 0)
	gov := newGovFake(t)
	m := NewManager(vmsession.NewStore(), staticToken("svc-token"), gw.port)
	m.ConfigureOutput(OutputConfig{GovLayerURL: gov.srv.URL + "/api/v1", StateDir: t.TempDir()})
	_ = m.SetGatewayCA("sub-1", gw.caPEM())
	m.RegisterOwnerVM("sub-1", "127.0.0.1", "")
	err := m.collectOutput("sub-1")
	if err == nil || !strings.Contains(err.Error(), "no saved SSH key") {
		t.Fatalf("want missing-key error, got %v", err)
	}
	if len(gov.uploads) != 0 {
		t.Fatal("uploaded without a model")
	}
}

func TestCollectOutputShortStreamAbortsUpload(t *testing.T) {
	gw, _ := queryPastGateway(t, 0)
	gov := newGovFake(t)
	gov.caPEM = gw.caPEM()
	ssh := &fakeSSH{files: map[string][]byte{"model_sub_1_round_1.pt": modelBytes()}, short: true}
	m, _ := setupOutputManager(t, gw, gov, ssh)
	err := m.collectOutput("sub/1")
	if err == nil || !strings.Contains(err.Error(), "expected") {
		t.Fatalf("want size-mismatch error, got %v", err)
	}
	gov.srv.Close() // waits for the aborted upload's handler to finish
	gov.mu.Lock()
	defer gov.mu.Unlock()
	for _, u := range gov.uploads {
		if u.err == nil {
			t.Fatal("gov_layer received a complete upload despite the short read")
		}
	}
}

func TestCollectOutputInFlightGuard(t *testing.T) {
	m := NewManager(vmsession.NewStore(), staticToken("x"), 1)
	if !m.beginCollect("a") {
		t.Fatal("first begin refused")
	}
	if err := m.collectOutput("a"); !errors.Is(err, ErrCollectInFlight) {
		t.Fatalf("want ErrCollectInFlight, got %v", err)
	}
	if m.StartCollectOutput("a") {
		t.Fatal("StartCollectOutput ran while in flight")
	}
	if !m.beginCollect("b") {
		t.Fatal("guard is not per submission")
	}
	m.endCollect("a")
	if !m.beginCollect("a") {
		t.Fatal("guard not released")
	}
}
