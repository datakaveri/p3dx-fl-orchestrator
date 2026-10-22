// Package httpapi is the fl-orchestrator REST API: VM auto-provisioning
// (Azure device-code login + terraform apply), the SSE progress stream, and
// the internal register-expected-providers hook p3dx-aaa's
// /gov/start-fl-session calls into. Mounted under /p3dx, matching the paths
// these endpoints had when they lived inside p3dx-aaa, so only the host in
// p3dx-auth-ui's config needs to change.
package httpapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"

	"github.com/s4r4v4n04/p3dx-fl-orchestrator/internal/config"
	"github.com/s4r4v4n04/p3dx-fl-orchestrator/internal/flauto"
	"github.com/s4r4v4n04/p3dx-fl-orchestrator/internal/keycloak"
	"github.com/s4r4v4n04/p3dx-fl-orchestrator/internal/postapply"
	"github.com/s4r4v4n04/p3dx-fl-orchestrator/internal/provisioning"
	"github.com/s4r4v4n04/p3dx-fl-orchestrator/internal/vmcred"
	"github.com/s4r4v4n04/p3dx-fl-orchestrator/internal/vmsession"
)

const maxBodyBytes = 5 * 1024 * 1024

// Server bundles the dependencies shared by every handler.
type Server struct {
	cfg   *config.Config
	store *vmsession.Store
	flow  *flauto.Manager
	prov  *provisioning.Provisioner
	creds *vmcred.Store
}

func New(cfg *config.Config) *Server {
	store := vmsession.NewStore()
	tokens := keycloak.NewTokenSource(cfg.KeycloakBaseURL, cfg.KeycloakRealm, cfg.KeycloakClientID, cfg.KeycloakClientSecret)
	flow := flauto.NewManager(store, tokens.Token, cfg.GatewayRESTPort)
	flow.ConfigureOutput(flauto.OutputConfig{
		GovLayerURL: cfg.GovLayerURL, VMFlotillaDir: cfg.VMFlotillaDir,
		SSHUser: cfg.SSHUser, SSHPort: cfg.SSHPort,
		StateDir: cfg.FLOutputStateDir, VMRegistryToken: cfg.VMRegistryToken,
	})
	creds := vmcred.NewStore(cfg.VMCredentialClaimTTL)
	prov := provisioning.New(cfg, store, flow, creds, postapply.New(cfg, tokens))
	return &Server{cfg: cfg, store: store, flow: flow, prov: prov, creds: creds}
}

// Handler returns the root http.Handler.
func (s *Server) Handler() http.Handler {
	root := chi.NewRouter()
	root.Use(s.corsMiddleware)
	root.Route("/p3dx", s.registerRoutes)
	return root
}

func (s *Server) registerRoutes(r chi.Router) {
	r.Group(func(r chi.Router) {
		r.Use(s.requireJWT)
		r.Post("/vm-provisioning/auto-create", s.postAutoCreate)
		r.Get("/vm-provisioning/private-key", s.getPrivateKey)
		r.Post("/vm-provisioning/token", s.postToken)
		r.Post("/fl-output/{submissionId}/collect", s.postCollectFLOutput)
	})
	// Token-authenticated (deploy.sh has no browser session / JWT) or
	// unauthenticated by nature (SSE — EventSource can't set headers).
	r.Post("/vm-provisioning/events", s.postEvents)
	r.Get("/vm-provisioning/stream", s.getStream)

	r.Group(func(r chi.Router) {
		r.Use(s.requireInternalKey)
		r.Post("/internal/register-expected-providers", s.postRegisterExpectedProviders)
		r.Post("/internal/vm-credentials", s.postVMCredential)
	})
}

// corsMiddleware reflects the request Origin, matching the other Go services
// in this workspace (p3dx_gov_layer's server.go).
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		} else {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Add("Vary", "Origin")
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization,X-Internal-Key")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type usernameCtxKey struct{}

// requireJWT verifies the caller's Keycloak access token and stashes their
// preferred_username on the request context, mirroring p3dx-aaa's
// verifyJWT middleware (auth.middleware.js) minus the immudb audit-log call —
// this service's only runtime dependencies are Keycloak + the az/terraform
// CLIs, not immudb.
func (s *Server) requireJWT(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			writeJSON(w, http.StatusUnauthorized, j{"status": "FAILED", "error": "MISSING_AUTH_TOKEN"})
			return
		}
		tokenStr := strings.TrimPrefix(auth, "Bearer ")
		tok, err := keycloak.ValidateAccessToken(s.cfg.KeycloakBaseURL, s.cfg.KeycloakRealm, tokenStr)
		if err != nil || !tok.Valid {
			log.Println("[fl-orchestrator] JWT verify error:", err)
			writeJSON(w, http.StatusUnauthorized, j{"status": "FAILED", "error": "INVALID_OR_EXPIRED_TOKEN"})
			return
		}
		// Flotilla VM tokens only let a VM rejoin its FL session at the
		// gateway; they never pass as a user here.
		if claims, ok := tok.Claims.(jwt.MapClaims); ok && keycloak.Azp(claims) == s.cfg.FlotillaVMClientID {
			writeJSON(w, http.StatusForbidden, j{"status": "FAILED", "error": "VM_TOKEN_NOT_ALLOWED"})
			return
		}
		username := keycloak.PreferredUsername(tok)
		ctx := context.WithValue(r.Context(), usernameCtxKey{}, username)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func usernameFromCtx(r *http.Request) string {
	username, _ := r.Context().Value(usernameCtxKey{}).(string)
	return username
}

// requireInternalKey guards the service-to-service endpoints p3dx-aaa calls
// (register-expected-providers, vm-credentials). INTERNAL_SERVICE_KEY is
// required: VM credentials arrive on this route, so it is never left open.
func (s *Server) requireInternalKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.InternalServiceKey == "" ||
			subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Internal-Key")), []byte(s.cfg.InternalServiceKey)) != 1 {
			writeJSON(w, http.StatusUnauthorized, j{"status": "FAILED", "error": "UNAUTHORIZED"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

type j = map[string]any

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// readBody decodes a JSON request body into dst. An empty body is treated as
// an empty object.
func readBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	err := json.NewDecoder(r.Body).Decode(dst)
	if err != nil && !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "INVALID_JSON", "message": "Invalid JSON in request body"})
		return false
	}
	return true
}
