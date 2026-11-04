package postapply

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
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

	"github.com/s4r4v4n04/p3dx-fl-orchestrator/internal/config"
	"github.com/s4r4v4n04/p3dx-fl-orchestrator/internal/gatewayca"
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

// fakeCSR is what the fake ssh prints for the gateway's tls.csr: a real P-256
// CSR (each process makes its own), so the CA can sign it.
var fakeCSR = func() string {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "gw"}}, key)
	if err != nil {
		panic(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}()

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
	case remote == "stream-test":
		os.Stdout.Write([]byte("streamed\x00bytes"))
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

// backend fakes Keycloak and the controlplane on one server, plus gov_layer's
// contract check (gate) and a real gateway CA.
type backend struct {
	srv *httptest.Server

	mu        sync.Mutex
	aaaStatus int
	aaaAuth   string
	aaaPath   string
	aaaCalls  int

	gate  *stubGate
	ca    *gatewayca.CA
	caDir string
}

// stubGate stands in for gov_layer's contract check.
type stubGate struct {
	err     error
	gotSID  string
	gotCall int
}

var testValidUntil = time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)

func (g *stubGate) GatewayAuthorization(_ context.Context, submissionID string, _ time.Time) (*gatewayca.Authorization, error) {
	g.gotSID, g.gotCall = submissionID, g.gotCall+1
	if g.err != nil {
		return nil, g.err
	}
	return &gatewayca.Authorization{ContractID: "c1", ProjectID: "p1", JobID: "j1", SubmissionID: submissionID,
		ValidUntil: testValidUntil, Parties: []gatewayca.Party{{ID: "u1", Name: "prov-a"}}}, nil
}

func newBackend(t *testing.T) *backend {
	b := &backend{aaaStatus: 200, gate: &stubGate{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/realms/master/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"svc-token","expires_in":300}`))
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
	b.caDir = t.TempDir()
	ca, err := gatewayca.LoadOrCreate(filepath.Join(b.caDir, "ca.key"), filepath.Join(b.caDir, "ca.pem"), filepath.Join(b.caDir, "records"))
	if err != nil {
		t.Fatal(err)
	}
	b.ca = ca
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
	return New(cfg, keycloak.NewTokenSource(cfg.KeycloakBaseURL, cfg.KeycloakRealm, cfg.KeycloakClientID, cfg.KeycloakClientSecret), b.ca, b.gate)
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
	if cert.Serial == "" || cert.CAPEM != string(b.ca.CAPEM()) || cert.ContractID != "c1" || cert.NotAfter != "2099-01-01T00:00:00Z" {
		t.Fatalf("unexpected cert: %+v", cert)
	}
	if b.gate.gotCall != 1 || b.gate.gotSID != "s1" {
		t.Fatalf("contract gate calls = %d (sid %q)", b.gate.gotCall, b.gate.gotSID)
	}
	block, _ := pem.Decode([]byte(cert.CertPEM))
	if block == nil {
		t.Fatal("no certificate PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(b.ca.CAPEM())
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "20.1.2.3", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("issued certificate does not verify against the CA: %v", err)
	}
	if _, err := os.Stat(filepath.Join(b.caDir, "records", cert.Serial+".json")); err != nil {
		t.Fatalf("issued certificate not recorded: %v", err)
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
		ins["/etc/flotilla-gateway/ca.crt"].Content != string(b.ca.CAPEM()) {
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
	if parties.ContractID != "c1" || parties.ValidUntil != "2099-01-01T00:00:00Z" || len(parties.Parties) != 1 ||
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

func TestSecureGatewayContractRejected(t *testing.T) {
	dir := setupFakeSSH(t)
	b := newBackend(t)
	notSigned := errors.New("contract is not signed")
	b.gate.err = notSigned
	if _, err := b.runner().SecureGateway(target, "20.1.2.3", "s1", noEmit); !errors.Is(err, notSigned) {
		t.Fatalf("want the gate's error, got %v", err)
	}
	if ins := installs(t, dir); len(ins) != 0 {
		t.Fatalf("files installed despite the contract check failing: %v", ins)
	}
	if entries, _ := os.ReadDir(filepath.Join(b.caDir, "records")); len(entries) != 0 {
		t.Fatalf("certificate issued despite the contract check failing: %v", entries)
	}
}

func TestSecureGatewayBadIP(t *testing.T) {
	setupFakeSSH(t)
	b := newBackend(t)
	if _, err := b.runner().SecureGateway(target, "gateway.local", "s1", noEmit); err == nil || b.gate.gotCall != 0 {
		t.Fatalf("want an IP error before the contract check, got %v (gate calls %d)", err, b.gate.gotCall)
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
	for _, want := range []string{"BatchMode=yes", "ConnectTimeout=15", "ServerAliveInterval=15", "ServerAliveCountMax=4", "UserKnownHostsFile=/k/kh", "-i /k/id", "IdentitiesOnly=yes", "-p 22", "azureuser@10.0.0.5 echo hi"} {
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

func TestSSHStream(t *testing.T) {
	dir := setupFakeSSH(t)
	tg := SSHTarget{Host: "10.0.0.5", User: "azureuser", KeyPath: "/k/id", KnownHosts: "/k/kh"}
	var buf strings.Builder
	if err := tg.Stream("stream-test", &buf); err != nil {
		t.Fatalf("Stream: %v", err)
	}
	if buf.String() != "streamed\x00bytes" {
		t.Fatalf("stdout = %q", buf.String())
	}
	calls := readJSONL[sshCall](t, filepath.Join(dir, "calls.jsonl"))
	if len(calls) != 1 || !strings.Contains(strings.Join(calls[0].Argv, " "), "-i /k/id -o IdentitiesOnly=yes") {
		t.Fatalf("argv = %v", calls)
	}

	_ = os.WriteFile(filepath.Join(dir, "fail"), nil, 0o600)
	err := tg.Stream("stream-test", io.Discard)
	if err == nil || !strings.Contains(err.Error(), "remote command failed") {
		t.Fatalf("want stderr in error, got %v", err)
	}
}
