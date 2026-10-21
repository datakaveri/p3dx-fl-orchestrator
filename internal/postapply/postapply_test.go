package postapply

import (
	"bufio"
	"encoding/json"
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

	"github.com/s4r4v4n04/p3dx-fl-orchestrator/internal/config"
	"github.com/s4r4v4n04/p3dx-fl-orchestrator/internal/keycloak"
)

// The test binary doubles as a fake ssh: when FAKE_SSH_DIR is set it records
// its argv/stdin and emulates the handful of remote commands postapply runs.
const fakeSSHEnv = "FAKE_SSH_DIR"

func TestMain(m *testing.M) {
	if dir := os.Getenv(fakeSSHEnv); dir != "" {
		os.Exit(fakeSSH(dir, os.Args[1:]))
	}
	os.Exit(m.Run())
}

type sshCall struct {
	Argv   []string `json:"argv"`
	Remote string   `json:"remote"`
	Stdin  string   `json:"stdin"`
}

type installRec struct {
	Mode, Owner, Group, Dst, Content string
}

const fakeCSR = "-----BEGIN CERTIFICATE REQUEST-----\nMIIBfake\n-----END CERTIFICATE REQUEST-----\n"

func fakeSSH(dir string, args []string) int {
	stdin, _ := io.ReadAll(os.Stdin)
	remote := ""
	if len(args) > 0 {
		remote = args[len(args)-1]
	}
	rec, _ := json.Marshal(sshCall{Argv: args, Remote: remote, Stdin: string(stdin)})
	f, err := os.OpenFile(filepath.Join(dir, "calls.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return 255
	}
	fmt.Fprintf(f, "%s\n", rec)
	f.Close()

	if _, err := os.Stat(filepath.Join(dir, "fail")); err == nil {
		fmt.Fprintln(os.Stderr, "remote command failed")
		return 1
	}
	switch {
	case strings.HasPrefix(remote, "sudo cat ") && strings.Contains(remote, "tls.csr"):
		fmt.Print(fakeCSR)
	case strings.HasPrefix(remote, "sudo install "):
		// sudo install -m MODE -o UID -g GID /dev/stdin 'DST'
		fs := strings.Fields(remote)
		if len(fs) != 10 || fs[8] != "/dev/stdin" {
			fmt.Fprintln(os.Stderr, "bad install command")
			return 2
		}
		r := installRec{Mode: fs[3], Owner: fs[5], Group: fs[7], Dst: strings.Trim(fs[9], "'"), Content: string(stdin)}
		b, _ := json.Marshal(r)
		g, _ := os.OpenFile(filepath.Join(dir, "installs.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		fmt.Fprintf(g, "%s\n", b)
		g.Close()
	case strings.Contains(remote, "docker inspect"):
		fmt.Println("healthy")
	case strings.Contains(remote, "docker compose"):
	default:
		fmt.Fprintln(os.Stderr, "unexpected remote command")
		return 3
	}
	return 0
}

func readJSONL[T any](t *testing.T, path string) []T {
	t.Helper()
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []T
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var v T
		if err := json.Unmarshal(sc.Bytes(), &v); err != nil {
			t.Fatal(err)
		}
		out = append(out, v)
	}
	return out
}

// setupFakeSSH points sshBinary at the test binary in fake mode.
func setupFakeSSH(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv(fakeSSHEnv, dir)
	old := sshBinary
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	sshBinary = exe
	t.Cleanup(func() { sshBinary = old })
	return dir
}

func installs(t *testing.T, dir string) map[string]installRec {
	m := map[string]installRec{}
	for _, r := range readJSONL[installRec](t, filepath.Join(dir, "installs.jsonl")) {
		m[r.Dst] = r
	}
	return m
}

// backend fakes Keycloak, gov_layer and p3dx-aaa on one server.
type backend struct {
	srv *httptest.Server

	mu        sync.Mutex
	govStatus int
	govAuth   string
	govBody   map[string]string
	aaaStatus int
	aaaAuth   string
	aaaPath   string
	aaaCalls  int
}

const govResp = `{"serial":"ab","certificate_pem":"-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----\n","ca_certificate_pem":"CA","fingerprint_sha256":"ff","not_after":"2027-01-01T00:00:00Z","contract_id":"c1","project_id":"p1","job_id":"j1","submission_id":"s1","valid_until":"2027-01-01T00:00:00Z","parties":[{"id":"u1","name":"prov-a"}]}`

func newBackend(t *testing.T) *backend {
	b := &backend{govStatus: 200, aaaStatus: 200}
	mux := http.NewServeMux()
	mux.HandleFunc("/realms/master/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"svc-token","expires_in":300}`))
	})
	mux.HandleFunc("/gov/gateway-certs", func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		defer b.mu.Unlock()
		b.govAuth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&b.govBody)
		if r.Method != http.MethodPost {
			w.WriteHeader(405)
			return
		}
		w.WriteHeader(b.govStatus)
		if b.govStatus == 200 {
			_, _ = w.Write([]byte(govResp))
		} else {
			_, _ = w.Write([]byte(`{"error":"CONFLICT","message":"already issued"}`))
		}
	})
	mux.HandleFunc("/aaa/p3dx/internal/fl/vm-credentials/", func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		defer b.mu.Unlock()
		b.aaaCalls++
		b.aaaAuth = r.Header.Get("Authorization")
		b.aaaPath = r.Method + " " + r.URL.Path
		w.WriteHeader(b.aaaStatus)
	})
	b.srv = httptest.NewServer(mux)
	t.Cleanup(b.srv.Close)
	return b
}

func (b *backend) runner() *Runner {
	cfg := &config.Config{
		KeycloakBaseURL: b.srv.URL, KeycloakRealm: "master",
		KeycloakClientID: "orch", KeycloakClientSecret: "secret",
		GovLayerURL: b.srv.URL + "/gov", AAAURL: b.srv.URL + "/aaa", AAAPublicURL: "https://aaa.example",
		GatewayDir: "/etc/flotilla-gateway", SidecarDir: "/etc/flotilla-sidecar", VMFlotillaDir: "flotilla",
		GatewayUID: "10001", GatewayReadyTimeout: 2 * time.Second,
	}
	return New(cfg, keycloak.NewTokenSource(cfg.KeycloakBaseURL, cfg.KeycloakRealm, cfg.KeycloakClientID, cfg.KeycloakClientSecret))
}

var target = SSHTarget{Host: "10.0.0.5", User: "azureuser", Port: "22", KeyPath: "/k/id", KnownHosts: "/k/kh"}

func noEmit(step, status, msg string) {}

func TestSecureGateway(t *testing.T) {
	dir := setupFakeSSH(t)
	b := newBackend(t)
	cert, err := b.runner().SecureGateway(target, "20.1.2.3", "s1", noEmit)
	if err != nil {
		t.Fatalf("SecureGateway: %v", err)
	}
	if cert.Serial != "ab" || cert.CAPEM != "CA" || cert.ContractID != "c1" {
		t.Fatalf("unexpected cert: %+v", cert)
	}
	if b.govAuth != "Bearer svc-token" {
		t.Fatalf("gov Authorization = %q", b.govAuth)
	}
	if b.govBody["csr_pem"] != fakeCSR || b.govBody["server_ip"] != "20.1.2.3" || b.govBody["submission_id"] != "s1" {
		t.Fatalf("gov body = %v", b.govBody)
	}
	ins := installs(t, dir)
	for _, name := range []string{"tls.crt", "ca.crt", "parties.json"} {
		r, ok := ins["/etc/flotilla-gateway/"+name]
		if !ok {
			t.Fatalf("%s not installed; got %v", name, ins)
		}
		if r.Mode != "0644" || r.Owner != "10001" || r.Group != "10001" {
			t.Errorf("%s: mode/owner %s %s:%s", name, r.Mode, r.Owner, r.Group)
		}
	}
	if !strings.Contains(ins["/etc/flotilla-gateway/tls.crt"].Content, "BEGIN CERTIFICATE") ||
		ins["/etc/flotilla-gateway/ca.crt"].Content != "CA" {
		t.Errorf("cert contents wrong")
	}
	var parties struct {
		ContractID string            `json:"contract_id"`
		ValidUntil string            `json:"valid_until"`
		Parties    []json.RawMessage `json:"parties"`
	}
	if err := json.Unmarshal([]byte(ins["/etc/flotilla-gateway/parties.json"].Content), &parties); err != nil {
		t.Fatal(err)
	}
	if parties.ContractID != "c1" || parties.ValidUntil != "2027-01-01T00:00:00Z" || len(parties.Parties) != 1 ||
		!strings.Contains(string(parties.Parties[0]), "prov-a") {
		t.Errorf("parties.json = %+v", parties)
	}
	var started bool
	for _, c := range readJSONL[sshCall](t, filepath.Join(dir, "calls.jsonl")) {
		if strings.Contains(c.Remote, "docker compose up -d --force-recreate gateway") && strings.Contains(c.Remote, "~/flotilla/deployment") {
			started = true
		}
	}
	if !started {
		t.Errorf("gateway was not started")
	}
}

func TestSecureGatewayGovConflict(t *testing.T) {
	dir := setupFakeSSH(t)
	b := newBackend(t)
	b.govStatus = http.StatusConflict
	if _, err := b.runner().SecureGateway(target, "20.1.2.3", "s1", noEmit); err == nil || !strings.Contains(err.Error(), "409") {
		t.Fatalf("want 409 error, got %v", err)
	}
	if ins := installs(t, dir); len(ins) != 0 {
		t.Fatalf("files installed despite gov failure: %v", ins)
	}
}

const offlineToken = "eyJ-OFFLINE-TOKEN-very-secret"

func TestDeliverClient(t *testing.T) {
	dir := setupFakeSSH(t)
	b := newBackend(t)
	tok := []byte(offlineToken)
	var msgs []string
	err := b.runner().DeliverClient(target, ClientInput{
		SubmissionID: "s1", CredentialID: "cred-1", Token: tok,
		SelfIP: "20.9.9.9", GatewayHost: "20.1.2.3", CAPEM: "CA",
	}, func(step, status, msg string) { msgs = append(msgs, step+"|"+status+"|"+msg) })
	if err != nil {
		t.Fatalf("DeliverClient: %v", err)
	}
	for i, c := range tok {
		if c != 0 {
			t.Fatalf("caller's token not wiped at byte %d", i)
		}
	}

	ins := installs(t, dir)
	cr, ok := ins["/etc/flotilla-sidecar/credential"]
	if !ok {
		t.Fatalf("credential not installed: %v", ins)
	}
	if cr.Mode != "0600" || cr.Owner != "10001" || cr.Group != "10001" {
		t.Errorf("credential mode/owner %s %s:%s", cr.Mode, cr.Owner, cr.Group)
	}
	var credJSON map[string]string
	if err := json.Unmarshal([]byte(cr.Content), &credJSON); err != nil {
		t.Fatal(err)
	}
	if credJSON["credential_id"] != "cred-1" || credJSON["offline_token"] != offlineToken || credJSON["aaa_url"] != "https://aaa.example" {
		t.Errorf("credential content = %v", credJSON)
	}

	env := ins["/etc/flotilla-sidecar/sidecar.env"]
	for _, want := range []string{"GATEWAY_HOST=20.1.2.3\n", "SIDECAR_ADVERTISE_HOST=20.9.9.9\n", "AAA_URL=https://aaa.example\n"} {
		if !strings.Contains(env.Content, want) {
			t.Errorf("sidecar.env missing %q: %q", want, env.Content)
		}
	}
	if env.Mode != "0644" || ins["/etc/flotilla-sidecar/ca.crt"].Content != "CA" {
		t.Errorf("sidecar.env/ca.crt wrong: %+v", ins)
	}

	calls := readJSONL[sshCall](t, filepath.Join(dir, "calls.jsonl"))
	var started bool
	for _, c := range calls {
		for _, a := range c.Argv {
			if strings.Contains(a, offlineToken) {
				t.Fatalf("offline token appears in ssh argv: %q", c.Argv)
			}
		}
		if strings.Contains(c.Remote, "client-compose.yaml up -d") {
			started = true
		}
	}
	if !started {
		t.Errorf("client not started")
	}
	for _, m := range msgs {
		if strings.Contains(m, offlineToken) {
			t.Fatalf("offline token in emitted event: %q", m)
		}
	}
	if b.aaaCalls != 1 || b.aaaAuth != "Bearer svc-token" ||
		b.aaaPath != "POST /aaa/p3dx/internal/fl/vm-credentials/cred-1/delivered" {
		t.Errorf("aaa callback: calls=%d auth=%q path=%q", b.aaaCalls, b.aaaAuth, b.aaaPath)
	}
}

func TestDeliverClientAAAFailureNotFatal(t *testing.T) {
	setupFakeSSH(t)
	b := newBackend(t)
	b.aaaStatus = http.StatusInternalServerError
	var last string
	err := b.runner().DeliverClient(target, ClientInput{SubmissionID: "s1", CredentialID: "cred-1",
		Token: []byte(offlineToken), SelfIP: "1.1.1.1", GatewayHost: "2.2.2.2", CAPEM: "CA"},
		func(step, status, msg string) { last = status })
	if err != nil {
		t.Fatalf("aaa failure failed delivery: %v", err)
	}
	if b.aaaCalls != 1 || last != "ok" {
		t.Errorf("aaa calls=%d last status=%q", b.aaaCalls, last)
	}
}

func TestDeliverClientSSHFailureWipesAndHidesToken(t *testing.T) {
	dir := setupFakeSSH(t)
	if err := os.WriteFile(filepath.Join(dir, "fail"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	b := newBackend(t)
	tok := []byte(offlineToken)
	err := b.runner().DeliverClient(target, ClientInput{CredentialID: "cred-1", Token: tok}, noEmit)
	if err == nil {
		t.Fatal("want error")
	}
	if strings.Contains(err.Error(), offlineToken) {
		t.Fatalf("error leaks token: %v", err)
	}
	if string(tok) == offlineToken {
		t.Fatal("token not wiped on failure")
	}
}

func TestRunErrorOmitsStdin(t *testing.T) {
	dir := setupFakeSSH(t)
	if err := os.WriteFile(filepath.Join(dir, "fail"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := target.Run("sudo install -m 0600 -o 1 -g 1 /dev/stdin '/x'", []byte("STDIN-SECRET-xyz"))
	if err == nil {
		t.Fatal("want error")
	}
	if strings.Contains(err.Error(), "STDIN-SECRET-xyz") {
		t.Fatalf("error contains stdin: %v", err)
	}
	if !strings.Contains(err.Error(), "remote command failed") {
		t.Fatalf("error should carry remote output: %v", err)
	}
	calls := readJSONL[sshCall](t, filepath.Join(dir, "calls.jsonl"))
	if len(calls) != 1 || calls[0].Stdin != "STDIN-SECRET-xyz" {
		t.Fatalf("stdin not delivered via stdin: %+v", calls)
	}
}

func TestSSHArgs(t *testing.T) {
	got := strings.Join(target.args("echo hi"), " ")
	for _, want := range []string{"BatchMode=yes", "UserKnownHostsFile=/k/kh", "-i /k/id", "IdentitiesOnly=yes", "-p 22", "azureuser@10.0.0.5 echo hi"} {
		if !strings.Contains(got, want) {
			t.Errorf("args %q missing %q", got, want)
		}
	}
	bare := strings.Join(SSHTarget{Host: "h", User: "u"}.args("x"), " ")
	if strings.Contains(bare, "-i ") || strings.Contains(bare, "-p ") || strings.Contains(bare, "UserKnownHostsFile") {
		t.Errorf("unexpected options: %q", bare)
	}
}

func TestShellQuote(t *testing.T) {
	if got := shellQuote("a'b c"); got != `'a'\''b c'` {
		t.Fatalf("shellQuote = %s", got)
	}
}

func TestHome(t *testing.T) {
	r := &Runner{cfg: &config.Config{VMFlotillaDir: "flotilla"}}
	if r.home("deployment") != "~/flotilla/deployment" {
		t.Fatal(r.home("deployment"))
	}
	r.cfg.VMFlotillaDir = "/opt/flotilla"
	if r.home("") != "/opt/flotilla" {
		t.Fatal(r.home(""))
	}
}
