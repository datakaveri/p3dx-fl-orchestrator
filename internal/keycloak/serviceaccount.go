package keycloak

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// expirySkew refreshes a cached service token this long before it expires.
const expirySkew = 30 * time.Second

// TokenSource hands out this service's own Keycloak access token
// (client-credentials grant), cached until shortly before it expires —
// same pattern as p3dx_gov_layer/internal/keycloak/keycloak.go. It is what
// gov_layer (/gateway-certs), p3dx-aaa (VM-credential callbacks) and the
// session gateways' REST API accept from the orchestrator.
type TokenSource struct {
	tokenURL, clientID, secret string
	http                       *http.Client

	mu        sync.Mutex
	token     string
	expiresAt time.Time
}

// NewTokenSource builds a source for baseURL/realms/realm.
func NewTokenSource(baseURL, realm, clientID, secret string) *TokenSource {
	return &TokenSource{
		tokenURL: strings.TrimRight(baseURL, "/") + "/realms/" + realm + "/protocol/openid-connect/token",
		clientID: clientID,
		secret:   secret,
		http:     &http.Client{Timeout: 15 * time.Second},
	}
}

// Token returns a valid access token, fetching a new one when needed.
func (s *TokenSource) Token() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token != "" && time.Now().Before(s.expiresAt) {
		return s.token, nil
	}
	if s.clientID == "" || s.secret == "" {
		return "", fmt.Errorf("KEYCLOAK_CLIENT_ID/KEYCLOAK_CLIENT_SECRET not configured")
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {s.clientID}, "client_secret": {s.secret}}
	resp, err := s.http.PostForm(s.tokenURL, form)
	if err != nil {
		return "", fmt.Errorf("service token request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("service token request: Keycloak returned %d", resp.StatusCode)
	}
	var body struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil || body.AccessToken == "" {
		return "", fmt.Errorf("service token response could not be read")
	}
	ttl := time.Duration(body.ExpiresIn)*time.Second - expirySkew
	if ttl < 0 {
		ttl = 0
	}
	s.token, s.expiresAt = body.AccessToken, time.Now().Add(ttl)
	return s.token, nil
}

// Azp extracts the "azp" claim (the client the token was issued to).
func Azp(claims map[string]any) string {
	azp, _ := claims["azp"].(string)
	return azp
}
