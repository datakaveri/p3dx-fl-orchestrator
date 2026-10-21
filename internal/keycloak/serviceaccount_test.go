package keycloak

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func tokenServer(t *testing.T, status int, expiresIn int) (*httptest.Server, *int32) {
	t.Helper()
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		if r.URL.Path != "/realms/master/protocol/openid-connect/token" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		_ = r.ParseForm()
		if r.PostForm.Get("grant_type") != "client_credentials" || r.PostForm.Get("client_id") != "orch" ||
			r.PostForm.Get("client_secret") != "s3cret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "tok-" + string(rune('0'+n)), "expires_in": expiresIn})
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func TestTokenCachedUntilNearExpiry(t *testing.T) {
	srv, hits := tokenServer(t, http.StatusOK, 300)
	ts := NewTokenSource(srv.URL+"/", "master", "orch", "s3cret")
	a, err := ts.Token()
	if err != nil {
		t.Fatal(err)
	}
	b, err := ts.Token()
	if err != nil {
		t.Fatal(err)
	}
	if a != "tok-1" || b != a || atomic.LoadInt32(hits) != 1 {
		t.Fatalf("expected one cached fetch, got %q %q hits=%d", a, b, *hits)
	}
}

func TestTokenRefetchedWithinSkew(t *testing.T) {
	// expires_in <= 30s skew: cached lifetime is zero, so every call refetches.
	srv, hits := tokenServer(t, http.StatusOK, 30)
	ts := NewTokenSource(srv.URL, "master", "orch", "s3cret")
	a, _ := ts.Token()
	b, err := ts.Token()
	if err != nil {
		t.Fatal(err)
	}
	if a == b || atomic.LoadInt32(hits) != 2 {
		t.Fatalf("expected refetch, got %q %q hits=%d", a, b, *hits)
	}
}

func TestTokenNon200(t *testing.T) {
	srv, _ := tokenServer(t, http.StatusUnauthorized, 300)
	ts := NewTokenSource(srv.URL, "master", "orch", "s3cret")
	if _, err := ts.Token(); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("want 401 error, got %v", err)
	}
}

func TestTokenBadBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"expires_in":300}`))
	}))
	defer srv.Close()
	if _, err := NewTokenSource(srv.URL, "master", "orch", "s3cret").Token(); err == nil {
		t.Fatal("want error for missing access_token")
	}
}

func TestTokenEmptySecret(t *testing.T) {
	srv, hits := tokenServer(t, http.StatusOK, 300)
	if _, err := NewTokenSource(srv.URL, "master", "orch", "").Token(); err == nil {
		t.Fatal("want error with empty secret")
	}
	if _, err := NewTokenSource(srv.URL, "master", "", "s3cret").Token(); err == nil {
		t.Fatal("want error with empty client id")
	}
	if atomic.LoadInt32(hits) != 0 {
		t.Fatalf("Keycloak contacted without credentials")
	}
}

func TestAzp(t *testing.T) {
	if Azp(map[string]any{"azp": "flotilla-vm"}) != "flotilla-vm" || Azp(map[string]any{}) != "" || Azp(map[string]any{"azp": 1}) != "" {
		t.Fatal("Azp mismatch")
	}
}
