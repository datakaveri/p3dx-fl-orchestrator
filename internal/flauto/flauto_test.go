package flauto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/s4r4v4n04/p3dx-fl-orchestrator/internal/vmsession"
)

type gateway struct {
	srv  *httptest.Server
	port int

	mu       sync.Mutex
	auths    []string
	execBody map[string]any
	execDone chan struct{}
}

func newGateway(t *testing.T) *gateway {
	g := &gateway{execDone: make(chan struct{})}
	mux := http.NewServeMux()
	mux.HandleFunc("/client_status", func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		g.auths = append(g.auths, r.Header.Get("Authorization"))
		g.mu.Unlock()
		_, _ = w.Write([]byte(`{"clients":{"a":{},"b":{}}}`))
	})
	mux.HandleFunc("/execute_command", func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		g.auths = append(g.auths, r.Header.Get("Authorization"))
		_ = json.NewDecoder(r.Body).Decode(&g.execBody)
		g.mu.Unlock()
		_, _ = w.Write([]byte(`{"message":"done"}`))
		close(g.execDone)
	})
	g.srv = httptest.NewTLSServer(mux)
	t.Cleanup(g.srv.Close)
	u, _ := url.Parse(g.srv.URL)
	g.port, _ = strconv.Atoi(u.Port())
	return g
}

func (g *gateway) caPEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: g.srv.Certificate().Raw}))
}

func otherCAPEM(t *testing.T) string {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "other CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func staticToken(tok string) TokenFunc { return func() (string, error) { return tok, nil } }

func TestClientCountOverTLSWithBearer(t *testing.T) {
	g := newGateway(t)
	m := NewManager(vmsession.NewStore(), staticToken("svc-token"), g.port)
	if err := m.SetGatewayCA("sub-1", g.caPEM()); err != nil {
		t.Fatal(err)
	}
	m.RegisterOwnerVM("sub-1", "127.0.0.1", "")
	n, err := m.clientCount(m.getOrCreate("sub-1"), "127.0.0.1")
	if err != nil {
		t.Fatalf("clientCount: %v", err)
	}
	if n != 2 {
		t.Fatalf("clientCount = %d, want 2", n)
	}
	if len(g.auths) != 1 || g.auths[0] != "Bearer svc-token" {
		t.Fatalf("Authorization headers = %v", g.auths)
	}
}

func TestClientCountRejectsUntrustedGateway(t *testing.T) {
	g := newGateway(t)
	for name, ca := range map[string]string{"no CA": "", "wrong CA": otherCAPEM(t)} {
		t.Run(name, func(t *testing.T) {
			m := NewManager(vmsession.NewStore(), staticToken("svc-token"), g.port)
			if ca != "" {
				if err := m.SetGatewayCA("sub-1", ca); err != nil {
					t.Fatal(err)
				}
			}
			_, err := m.clientCount(m.getOrCreate("sub-1"), "127.0.0.1")
			if err == nil {
				t.Fatal("expected TLS verification failure")
			}
			if !strings.Contains(err.Error(), "certificate") {
				t.Fatalf("expected a certificate error, got %v", err)
			}
		})
	}
	if len(g.auths) != 0 {
		t.Fatalf("untrusted client reached the handler: %v", g.auths)
	}
}

func TestClientCountTokenError(t *testing.T) {
	g := newGateway(t)
	m := NewManager(vmsession.NewStore(), func() (string, error) { return "", errTest }, g.port)
	_ = m.SetGatewayCA("sub-1", g.caPEM())
	if _, err := m.clientCount(m.getOrCreate("sub-1"), "127.0.0.1"); err != errTest {
		t.Fatalf("want token error, got %v", err)
	}
	if len(g.auths) != 0 {
		t.Fatal("request sent without a token")
	}
}

type testErr string

func (e testErr) Error() string { return string(e) }

const errTest = testErr("no token")

func TestSetGatewayCAInvalid(t *testing.T) {
	m := NewManager(vmsession.NewStore(), staticToken("x"), 1)
	if err := m.SetGatewayCA("s", "not a pem"); err == nil {
		t.Fatal("want error for invalid PEM")
	}
}

func TestStartSessionPostsExecuteCommand(t *testing.T) {
	g := newGateway(t)
	store := vmsession.NewStore()
	runTok := store.CreateToken("owner", "user")
	m := NewManager(store, staticToken("svc-token"), g.port)
	_ = m.SetGatewayCA("sub/1", g.caPEM())
	m.RegisterOwnerVM("sub/1", "127.0.0.1", runTok) // no expected count: no poller
	s := m.getOrCreate("sub/1")
	m.startSession("sub/1", s)
	select {
	case <-g.execDone:
	case <-time.After(5 * time.Second):
		t.Fatal("execute_command not called")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.auths[len(g.auths)-1] != "Bearer svc-token" {
		t.Fatalf("execute_command auth = %v", g.auths)
	}
	if g.execBody["session_id"] != "sub_1" {
		t.Fatalf("session_id = %v", g.execBody["session_id"])
	}
	// The final "FL session done" event arrives asynchronously.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		snap, _ := store.Get(runTok)
		for _, e := range snap.Events {
			if e.Step == "FL session" && e.Status == "done" && e.Message == "done" {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("no FL session done event")
}

func TestWaitOwnerIP(t *testing.T) {
	m := NewManager(vmsession.NewStore(), staticToken("x"), 1)
	start := time.Now()
	if _, _, err := m.WaitOwnerIP("sub-1", 50*time.Millisecond); err == nil {
		t.Fatal("want timeout before owner registered")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("timeout not honoured")
	}

	ca := otherCAPEM(t)
	if err := m.SetGatewayCA("sub-1", ca); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var ip, gotCA string
	var err error
	go func() {
		ip, gotCA, err = m.WaitOwnerIP("sub-1", 5*time.Second)
		close(done)
	}()
	m.RegisterOwnerVM("sub-1", "10.1.2.3", "")
	m.RegisterOwnerVM("sub-1", "10.1.2.3", "") // second registration must not panic (double close)
	<-done
	if err != nil || ip != "10.1.2.3" || gotCA != ca {
		t.Fatalf("WaitOwnerIP = %q, %q, %v", ip, gotCA, err)
	}
	// Other submissions are independent.
	if _, _, err := m.WaitOwnerIP("sub-2", 10*time.Millisecond); err == nil {
		t.Fatal("sub-2 should not be ready")
	}
}

func TestGetOrCreateIsPerSubmission(t *testing.T) {
	m := NewManager(vmsession.NewStore(), staticToken("x"), 1)
	a := m.getOrCreate("a")
	if m.getOrCreate("a") != a || m.getOrCreate("b") == a {
		t.Fatal("getOrCreate not keyed by submission")
	}
	if a.lastConnectedCount != -1 || a.tokens == nil || a.ownerReady == nil {
		t.Fatalf("bad initial state: %+v", a)
	}
}
