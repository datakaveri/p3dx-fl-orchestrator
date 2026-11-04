package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/s4r4v4n04/p3dx-fl-orchestrator/internal/config"
	"github.com/s4r4v4n04/p3dx-fl-orchestrator/internal/govclient"
	"github.com/s4r4v4n04/p3dx-fl-orchestrator/internal/vmcred"
	"github.com/s4r4v4n04/p3dx-fl-orchestrator/internal/vmsession"
)

const (
	internalKey  = "internal-key-123"
	offlineToken = "OFFLINE-TOKEN-must-not-leak"
	realm        = "p3dx"
)

var signingKey *rsa.PrivateKey

func init() {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	signingKey = k
}

// jwksServer serves the realm's JWKS with signingKey under kid "k1".
func jwksServer(t *testing.T) *httptest.Server {
	pub := signingKey.PublicKey
	jwks := map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig",
		"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/realms/"+realm+"/protocol/openid-connect/certs" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func mint(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = time.Now().Add(time.Hour).Unix()
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "k1"
	s, err := tok.SignedString(signingKey)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func newTestServer(t *testing.T, key string) *Server {
	kc := jwksServer(t)
	cfg := &config.Config{
		KeycloakBaseURL: kc.URL, KeycloakRealm: realm,
		InternalServiceKey: key, FlotillaVMClientID: "flotilla-vm",
		KeycloakClientID: "p3dx-fl-orchestrator", GatewayRESTPort: 12345,
		ServiceRoot: t.TempDir(), TerraformDir: t.TempDir(), FLOutputStateDir: t.TempDir(),
		VMCredentialClaimTTL: time.Hour, OwnerWaitTimeout: time.Second, GatewayReadyTimeout: time.Second,
	}
	srv := New(cfg)
	srv.gov = &stubGov{parties: map[string]*govclient.Parties{
		"sub-1": {UserName: "alice", DataProviders: []string{"alice", "bob"}},
		"sub-2": {UserName: "carol", DataProviders: []string{"dave"}},
	}}
	return srv
}

// stubGov is a canned gov_layer contract source.
type stubGov struct {
	parties map[string]*govclient.Parties
	err     error // returned for every lookup when set
}

func (g *stubGov) ContractParties(_ context.Context, id string) (*govclient.Parties, error) {
	if g.err != nil {
		return nil, g.err
	}
	if p, ok := g.parties[id]; ok {
		return p, nil
	}
	return nil, govclient.ErrNoContract
}

func do(t *testing.T, h http.Handler, method, path string, hdr map[string]string, body any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

func credBody() map[string]string {
	return map[string]string{
		"credential_id": "cred-1", "submission_id": "sub-1", "contract_id": "c1",
		"username": "alice", "user_id": "u1", "offline_token": offlineToken, "expires_at": "2027-01-01T00:00:00Z",
	}
}

func TestVMCredentialRequiresInternalKey(t *testing.T) {
	s := newTestServer(t, internalKey)
	h := s.Handler()
	for name, hdr := range map[string]map[string]string{
		"missing": nil,
		"wrong":   {"X-Internal-Key": "nope"},
		"prefix":  {"X-Internal-Key": internalKey[:5]},
	} {
		rec, out := do(t, h, http.MethodPost, "/p3dx/internal/vm-credentials", hdr, credBody())
		if rec.Code != http.StatusUnauthorized || out["error"] != "UNAUTHORIZED" {
			t.Errorf("%s key: got %d %v", name, rec.Code, out)
		}
	}
	if _, err := s.creds.Claim("cred-1", "alice", "sub-1"); !errors.Is(err, vmcred.ErrUnknown) {
		t.Fatalf("credential stored without a valid key: %v", err)
	}
}

func TestVMCredentialEmptyInternalKeyIsClosed(t *testing.T) {
	s := newTestServer(t, "")
	h := s.Handler()
	for _, hdr := range []map[string]string{nil, {"X-Internal-Key": ""}, {"X-Internal-Key": "anything"}} {
		rec, _ := do(t, h, http.MethodPost, "/p3dx/internal/vm-credentials", hdr, credBody())
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("empty INTERNAL_SERVICE_KEY must refuse; got %d", rec.Code)
		}
	}
	rec, _ := do(t, h, http.MethodPost, "/p3dx/internal/register-expected-providers", nil, map[string]any{"submissionId": "s", "count": 1})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("register-expected-providers open with empty key: %d", rec.Code)
	}
}

func TestVMCredentialStoredAndNotEchoed(t *testing.T) {
	s := newTestServer(t, internalKey)
	h := s.Handler()
	rec, out := do(t, h, http.MethodPost, "/p3dx/internal/vm-credentials", map[string]string{"X-Internal-Key": internalKey}, credBody())
	if rec.Code != http.StatusOK || out["status"] != "SUCCESS" {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), offlineToken) {
		t.Fatalf("response echoes token: %s", rec.Body)
	}
	// Duplicate: rejected, still no echo.
	rec, _ = do(t, h, http.MethodPost, "/p3dx/internal/vm-credentials", map[string]string{"X-Internal-Key": internalKey}, credBody())
	if rec.Code != http.StatusBadRequest || strings.Contains(rec.Body.String(), offlineToken) {
		t.Fatalf("duplicate: got %d %s", rec.Code, rec.Body)
	}
	meta, err := s.creds.Claim("cred-1", "alice", "sub-1")
	if err != nil || meta.ContractID != "c1" || meta.UserID != "u1" {
		t.Fatalf("Claim: %+v %v", meta, err)
	}
	tok, err := s.creds.Take("cred-1")
	if err != nil || string(tok) != offlineToken {
		t.Fatalf("Take: %q %v", tok, err)
	}
}

func TestVMCredentialInvalidNotEchoed(t *testing.T) {
	s := newTestServer(t, internalKey)
	b := credBody()
	delete(b, "username")
	rec, out := do(t, s.Handler(), http.MethodPost, "/p3dx/internal/vm-credentials", map[string]string{"X-Internal-Key": internalKey}, b)
	if rec.Code != http.StatusBadRequest || out["error"] != "INVALID_CREDENTIAL" {
		t.Fatalf("got %d %v", rec.Code, out)
	}
	if strings.Contains(rec.Body.String(), offlineToken) {
		t.Fatalf("error echoes token: %s", rec.Body)
	}
}

func TestRequireJWT(t *testing.T) {
	s := newTestServer(t, internalKey)
	h := s.Handler()
	body := map[string]string{"role": "user"}

	rec, out := do(t, h, http.MethodPost, "/p3dx/vm-provisioning/token", nil, body)
	if rec.Code != http.StatusUnauthorized || out["error"] != "MISSING_AUTH_TOKEN" {
		t.Errorf("no token: %d %v", rec.Code, out)
	}
	rec, out = do(t, h, http.MethodPost, "/p3dx/vm-provisioning/token", map[string]string{"Authorization": "Bearer garbage"}, body)
	if rec.Code != http.StatusUnauthorized || out["error"] != "INVALID_OR_EXPIRED_TOKEN" {
		t.Errorf("bad token: %d %v", rec.Code, out)
	}
	expired := mint(t, jwt.MapClaims{"preferred_username": "alice", "exp": time.Now().Add(-time.Hour).Unix()})
	rec, _ = do(t, h, http.MethodPost, "/p3dx/vm-provisioning/token", map[string]string{"Authorization": "Bearer " + expired}, body)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expired token: %d", rec.Code)
	}

	vm := mint(t, jwt.MapClaims{"preferred_username": "alice", "azp": "flotilla-vm"})
	for _, path := range []string{"/p3dx/vm-provisioning/token", "/p3dx/vm-provisioning/auto-create"} {
		rec, out = do(t, h, http.MethodPost, path, map[string]string{"Authorization": "Bearer " + vm}, body)
		if rec.Code != http.StatusForbidden || out["error"] != "VM_TOKEN_NOT_ALLOWED" {
			t.Errorf("%s with VM token: %d %v", path, rec.Code, out)
		}
	}

	user := mint(t, jwt.MapClaims{"preferred_username": "alice", "azp": "p3dx-auth-ui"})
	rec, out = do(t, h, http.MethodPost, "/p3dx/vm-provisioning/token", map[string]string{"Authorization": "Bearer " + user}, body)
	if rec.Code != http.StatusCreated || out["token"] == "" {
		t.Errorf("user token: %d %v", rec.Code, out)
	}
}

func TestAutoCreateCredentialChecks(t *testing.T) {
	s := newTestServer(t, internalKey)
	h := s.Handler()
	auth := map[string]string{"Authorization": "Bearer " + mint(t, jwt.MapClaims{"preferred_username": "alice", "azp": "p3dx-auth-ui"})}

	rec, out := do(t, h, http.MethodPost, "/p3dx/vm-provisioning/auto-create", auth,
		map[string]string{"role": "data-provider", "vmName": "vm1", "submissionId": "sub-1"})
	if rec.Code != http.StatusBadRequest || out["error"] != "MISSING_CREDENTIAL" {
		t.Fatalf("no credentialId: %d %v", rec.Code, out)
	}

	// A credential handed over for bob: alice cannot claim it, and the
	// attempt drops it.
	bob := credBody()
	bob["username"] = "bob"
	if rec, _ := do(t, h, http.MethodPost, "/p3dx/internal/vm-credentials", map[string]string{"X-Internal-Key": internalKey}, bob); rec.Code != http.StatusOK {
		t.Fatalf("put: %d", rec.Code)
	}
	rec, out = do(t, h, http.MethodPost, "/p3dx/vm-provisioning/auto-create", auth,
		map[string]string{"role": "data-provider", "vmName": "vm1", "submissionId": "sub-1", "credentialId": "cred-1"})
	if rec.Code != http.StatusForbidden || out["error"] != "CREDENTIAL_NOT_CLAIMABLE" {
		t.Fatalf("other user's credential: %d %v", rec.Code, out)
	}
	if strings.Contains(rec.Body.String(), offlineToken) {
		t.Fatalf("response leaks token")
	}
	if _, err := s.creds.Claim("cred-1", "bob", "sub-1"); !errors.Is(err, vmcred.ErrUnknown) {
		t.Fatalf("mismatched claim should drop the credential, got %v", err)
	}

	// Unknown credential id is refused too.
	rec, out = do(t, h, http.MethodPost, "/p3dx/vm-provisioning/auto-create", auth,
		map[string]string{"role": "data-provider", "vmName": "vm1", "submissionId": "sub-1", "credentialId": "nope"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("unknown credential: %d %v", rec.Code, out)
	}

	rec, out = do(t, h, http.MethodPost, "/p3dx/vm-provisioning/auto-create", auth, map[string]string{"role": "data-provider"})
	if rec.Code != http.StatusBadRequest || out["error"] != "MISSING_VM_NAME" {
		t.Fatalf("missing vm name: %d %v", rec.Code, out)
	}
	// A submission's VM is named after the submission: no vmName needed
	// (this one then stops at the credential check).
	rec, out = do(t, h, http.MethodPost, "/p3dx/vm-provisioning/auto-create", auth,
		map[string]string{"role": "data-provider", "submissionId": "sub-1"})
	if rec.Code != http.StatusBadRequest || out["error"] != "MISSING_CREDENTIAL" {
		t.Fatalf("submission without vm name: %d %v", rec.Code, out)
	}
}

func TestRunsRoute(t *testing.T) {
	s := newTestServer(t, internalKey)
	h := s.Handler()
	if rec, _ := do(t, h, http.MethodGet, "/p3dx/vm-provisioning/runs", nil, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no JWT: %d", rec.Code)
	}
	mine := s.store.CreateRun(vmsession.RunInfo{Username: "alice", Role: "data-provider", SubmissionID: "gov-1", VMName: "p3dx-fl-1"})
	time.Sleep(2 * time.Millisecond)
	owned := s.store.CreateRun(vmsession.RunInfo{Username: "op", Role: "user", SubmissionID: "gov-1", VMName: "p3dx-fl-1", OutputOwner: "alice"})
	s.store.CreateRun(vmsession.RunInfo{Username: "bob", Role: "data-provider", SubmissionID: "gov-1"})
	s.store.CreateRun(vmsession.RunInfo{Username: "alice", Role: "user", SubmissionID: "gov-2"})

	auth := map[string]string{"Authorization": "Bearer " + mint(t, jwt.MapClaims{"preferred_username": "alice", "azp": "p3dx-auth-ui"})}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/p3dx/vm-provisioning/runs?submissionId=gov-1", nil)
	req.Header.Set("Authorization", auth["Authorization"])
	h.ServeHTTP(rec, req)
	var out struct {
		Runs []map[string]any `json:"runs"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("runs: %d %s", rec.Code, rec.Body.String())
	}
	if len(out.Runs) != 2 || out.Runs[0]["token"] != owned || out.Runs[1]["token"] != mine {
		t.Fatalf("runs = %v", out.Runs)
	}
	for _, k := range []string{"token", "role", "submissionId", "vmName", "status", "vmReady", "createdAt", "updatedAt"} {
		if _, ok := out.Runs[0][k]; !ok {
			t.Errorf("run lacks %q: %v", k, out.Runs[0])
		}
	}
	if len(out.Runs[0]) != 8 {
		t.Errorf("run has extra fields: %v", out.Runs[0])
	}
}

func TestStreamNeedsToken(t *testing.T) {
	s := newTestServer(t, internalKey)
	h := s.Handler()
	for _, q := range []string{"", "?username=alice&role=user"} {
		rec, out := do(t, h, http.MethodGet, "/p3dx/vm-provisioning/stream"+q, nil, nil)
		if rec.Code != http.StatusBadRequest || out["error"] != "MISSING_TOKEN" {
			t.Errorf("stream%s: %d %v", q, rec.Code, out)
		}
	}
}

func TestCollectFLOutputRoute(t *testing.T) {
	s := newTestServer(t, internalKey)
	h := s.Handler()
	path := "/p3dx/fl-output/sub-1/collect"

	rec, out := do(t, h, http.MethodPost, path, nil, nil)
	if rec.Code != http.StatusUnauthorized || out["error"] != "MISSING_AUTH_TOKEN" {
		t.Fatalf("no token: %d %v", rec.Code, out)
	}
	vm := mint(t, jwt.MapClaims{"preferred_username": "alice", "azp": "flotilla-vm"})
	rec, _ = do(t, h, http.MethodPost, path, map[string]string{"Authorization": "Bearer " + vm}, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("VM token: %d", rec.Code)
	}

	user := mint(t, jwt.MapClaims{"preferred_username": "alice", "azp": "p3dx-auth-ui"})
	rec, out = do(t, h, http.MethodPost, path, map[string]string{"Authorization": "Bearer " + user, "Origin": "http://ui"}, nil)
	if rec.Code != http.StatusAccepted || (out["status"] != "collecting" && out["status"] != "already_collecting") {
		t.Fatalf("user: %d %v", rec.Code, out)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "http://ui" {
		t.Fatalf("CORS header = %q", rec.Header().Get("Access-Control-Allow-Origin"))
	}
}

func userAuth(t *testing.T, name string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + mint(t, jwt.MapClaims{"preferred_username": name, "azp": "p3dx-auth-ui"})}
}

func TestCollectFLOutputOwnership(t *testing.T) {
	s := newTestServer(t, internalKey)
	h := s.Handler()
	path := func(id string) string { return "/p3dx/fl-output/" + id + "/collect" }

	// bob is a data provider of sub-1, not its owner.
	rec, out := do(t, h, http.MethodPost, path("sub-1"), userAuth(t, "bob"), nil)
	if rec.Code != http.StatusForbidden || out["error"] != "NOT_SESSION_OWNER" {
		t.Fatalf("non-owner: %d %v", rec.Code, out)
	}
	if rec, _ := do(t, h, http.MethodPost, path("sub-2"), userAuth(t, "alice"), nil); rec.Code != http.StatusForbidden {
		t.Fatalf("other session: %d", rec.Code)
	}
	if rec, _ := do(t, h, http.MethodPost, path("nope"), userAuth(t, "alice"), nil); rec.Code != http.StatusNotFound {
		t.Fatalf("no contract: %d", rec.Code)
	}
	s.gov = &stubGov{err: errors.New("down")}
	if rec, _ := do(t, h, http.MethodPost, path("sub-1"), userAuth(t, "alice"), nil); rec.Code != http.StatusBadGateway {
		t.Fatalf("gov down: %d", rec.Code)
	}
}

func TestAutoCreateSessionChecks(t *testing.T) {
	s := newTestServer(t, internalKey)
	h := s.Handler()
	const p = "/p3dx/vm-provisioning/auto-create"

	rec, out := do(t, h, http.MethodPost, p, userAuth(t, "bob"), map[string]string{"role": "user", "submissionId": "sub-1"})
	if rec.Code != http.StatusForbidden || out["error"] != "NOT_SESSION_OWNER" {
		t.Fatalf("non-owner server VM: %d %v", rec.Code, out)
	}
	rec, out = do(t, h, http.MethodPost, p, userAuth(t, "carol"), map[string]string{"role": "data-provider", "submissionId": "sub-2", "credentialId": "c"})
	if rec.Code != http.StatusForbidden || out["error"] != "NOT_A_CONTRACT_PARTY" {
		t.Fatalf("non-party client VM: %d %v", rec.Code, out)
	}
	rec, out = do(t, h, http.MethodPost, p, userAuth(t, "alice"), map[string]string{"role": "user", "vmName": "vm1"})
	if rec.Code != http.StatusBadRequest || out["error"] != "MISSING_SUBMISSION_ID" {
		t.Fatalf("server VM without submission: %d %v", rec.Code, out)
	}
	if rec, _ := do(t, h, http.MethodPost, p, userAuth(t, "alice"), map[string]string{"role": "user", "submissionId": "nope"}); rec.Code != http.StatusNotFound {
		t.Fatalf("no contract: %d", rec.Code)
	}
	s.gov = &stubGov{err: errors.New("down")}
	if rec, _ := do(t, h, http.MethodPost, p, userAuth(t, "alice"), map[string]string{"role": "user", "submissionId": "sub-1"}); rec.Code != http.StatusBadGateway {
		t.Fatalf("gov down: %d", rec.Code)
	}
}

func TestAutoCreateOperatorMayStartServerVM(t *testing.T) {
	s := newTestServer(t, internalKey)
	h := s.Handler()
	op := map[string]string{"Authorization": "Bearer " + mint(t, jwt.MapClaims{
		"preferred_username": "operator", "azp": "p3dx-auth-ui",
		"realm_access": map[string]any{"roles": []any{"fl-orchestrator"}},
	})}
	// requireJWT must expose the operator role to the handlers (calling
	// auto-create for real would start a provisioning run in the background).
	var sawOperator bool
	probe := s.requireJWT(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { sawOperator = isOperator(r) }))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", op["Authorization"])
	probe.ServeHTTP(httptest.NewRecorder(), req)
	if !sawOperator {
		t.Fatal("fl-orchestrator role not recognised as operator")
	}
	// The role only covers the server VM, not a provider's client VM.
	rec, out := do(t, h, http.MethodPost, "/p3dx/vm-provisioning/auto-create", op, map[string]string{"role": "data-provider", "submissionId": "sub-1", "credentialId": "c"})
	if rec.Code != http.StatusForbidden || out["error"] != "NOT_A_CONTRACT_PARTY" {
		t.Fatalf("operator client VM: %d %v", rec.Code, out)
	}
}

func TestPrivateKeyOnlyForRunUser(t *testing.T) {
	s := newTestServer(t, internalKey)
	h := s.Handler()
	tok := s.store.CreateRun(vmsession.RunInfo{Username: "alice", Role: "user", SubmissionID: "sub-1"})
	rec, out := do(t, h, http.MethodGet, "/p3dx/vm-provisioning/private-key?token="+tok, userAuth(t, "bob"), nil)
	if rec.Code != http.StatusNotFound || out["error"] != "NOT_FOUND_OR_ALREADY_DOWNLOADED" {
		t.Fatalf("other user: %d %v", rec.Code, out)
	}
}
