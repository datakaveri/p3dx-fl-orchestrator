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
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"

	"github.com/s4r4v4n04/p3dx-fl-orchestrator/internal/config"
	"github.com/s4r4v4n04/p3dx-fl-orchestrator/internal/flauto"
	"github.com/s4r4v4n04/p3dx-fl-orchestrator/internal/gatewayca"
	"github.com/s4r4v4n04/p3dx-fl-orchestrator/internal/govclient"
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
	gov   ContractSource
	ca    *gatewayca.CA
}

// ContractSource reads a submission's contract parties from gov_layer
// (*govclient.Client); a stub in tests.
type ContractSource interface {
	ContractParties(ctx context.Context, submissionID string) (*govclient.Parties, error)
}

func New(cfg *config.Config) *Server {
	// Runs live on disk so their panels can be reopened after a restart.
	store := vmsession.NewStore()
	if cfg.FLOutputStateDir != "" {
		var err error
		store, err = vmsession.NewPersistentStore(filepath.Join(cfg.FLOutputStateDir, "runs"), cfg.RunRetention)
		if err != nil {
			log.Fatalf("[fl-orchestrator] provisioning run store: %v", err)
		}
		keepOutOfGit(cfg.FLOutputStateDir)
	}
	// The orchestrator is the CA for session gateways.
	ca, err := LoadGatewayCA(cfg)
	if err != nil {
		log.Fatalf("[fl-orchestrator] gateway CA: %v", err)
	}
	tokens := keycloak.NewTokenSource(cfg.KeycloakBaseURL, cfg.KeycloakRealm, cfg.KeycloakClientID, cfg.KeycloakClientSecret)
	flow := flauto.NewManager(store, tokens.Token, cfg.GatewayRESTPort)
	flow.ConfigureOutput(flauto.OutputConfig{
		GovLayerURL: cfg.GovLayerURL, VMFlotillaDir: cfg.VMFlotillaDir,
		SSHUser: cfg.SSHUser, SSHPort: cfg.SSHPort,
		StateDir: cfg.FLOutputStateDir, VMRegistryToken: cfg.VMRegistryToken,
		GatewayCAPEM: ca.CAPEM(),
	})
	// Sessions run with their contract's fl_config; an unreadable contract or
	// a missing/out-of-range fl_config blocks the session.
	gov := govclient.New(cfg.GovLayerURL, tokens.Token)
	flow.SetFLConfigSource(gov)
	// Runs reloaded from disk keep receiving their submission's FL events
	// (training rounds, session finished, output collected).
	for token, submissionID := range store.Resumable() {
		flow.RegisterProviderToken(submissionID, token)
	}
	creds := vmcred.NewStore(cfg.VMCredentialClaimTTL)
	prov := provisioning.New(cfg, store, flow, creds, postapply.New(cfg, tokens, ca, gov))
	return &Server{cfg: cfg, store: store, flow: flow, prov: prov, creds: creds, gov: gov, ca: ca}
}

// LoadGatewayCA loads (or, on first start, creates) the orchestrator's
// gateway CA from cfg, keeping its key and records out of git.
func LoadGatewayCA(cfg *config.Config) (*gatewayca.CA, error) {
	ca, err := gatewayca.LoadOrCreate(cfg.GatewayCAKeyPath, cfg.GatewayCACertPath, cfg.GatewayCertRecordsDir)
	if err != nil {
		return nil, err
	}
	keepOutOfGit(filepath.Dir(cfg.GatewayCAKeyPath))
	log.Printf("[fl-orchestrator] gateway CA certificate: %s (expires %s)", cfg.GatewayCACertPath,
		ca.Certificate().NotAfter.UTC().Format("2006-01-02"))
	return ca, nil
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
		r.Get("/vm-provisioning/runs", s.getRuns)
		r.Post("/fl-output/{submissionId}/collect", s.postCollectFLOutput)
	})
	// Token-authenticated (deploy.sh has no browser session / JWT) or
	// unauthenticated by nature (SSE — EventSource can't set headers).
	r.Post("/vm-provisioning/events", s.postEvents)
	r.Get("/vm-provisioning/stream", s.getStream)
	// The gateway CA certificate, public: FL clients pin it to trust session
	// gateways.
	r.Get("/gateway-ca-cert", s.getGatewayCACert)

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
		if claims, ok := tok.Claims.(jwt.MapClaims); ok {
			ctx = context.WithValue(ctx, rolesCtxKey{}, realmRoles(claims))
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type rolesCtxKey struct{}

// operatorRole is the realm role of the FL operator, who starts a session's
// server VM from the FL Orchestrator page on the output owner's behalf.
const operatorRole = "fl-orchestrator"

func realmRoles(claims jwt.MapClaims) []string {
	ra, _ := claims["realm_access"].(map[string]any)
	list, _ := ra["roles"].([]any)
	roles := make([]string, 0, len(list))
	for _, v := range list {
		if s, ok := v.(string); ok {
			roles = append(roles, s)
		}
	}
	return roles
}

func isOperator(r *http.Request) bool {
	roles, _ := r.Context().Value(rolesCtxKey{}).([]string)
	return slices.Contains(roles, operatorRole)
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

// keepOutOfGit drops a "*" .gitignore into dir (the state dir may sit inside
// the repo checkout), as flauto does for the owner-VM keys it keeps there.
func keepOutOfGit(dir string) {
	ignore := filepath.Join(dir, ".gitignore")
	if _, err := os.Stat(ignore); os.IsNotExist(err) {
		_ = os.WriteFile(ignore, []byte("*\n"), 0o600)
	}
}

type j = map[string]any

// GET /gateway-ca-cert — the orchestrator's gateway CA certificate, PEM.
func (s *Server) getGatewayCACert(w http.ResponseWriter, r *http.Request) {
	if s.ca == nil {
		writeJSON(w, http.StatusServiceUnavailable, j{"status": "FAILED", "error": "CA_NOT_LOADED"})
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(s.ca.CAPEM())
}

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

// sessionParties loads the submission's contract parties for an
// authorization check, writing the error response itself (404 no contract,
// 502 gov_layer unreachable) and returning nil in that case.
func (s *Server) sessionParties(w http.ResponseWriter, r *http.Request, submissionID string) *govclient.Parties {
	parties, err := s.gov.ContractParties(r.Context(), submissionID)
	if err == nil {
		return parties
	}
	if errors.Is(err, govclient.ErrNoContract) {
		writeJSON(w, http.StatusNotFound, j{"status": "FAILED", "error": "NO_CONTRACT"})
		return nil
	}
	log.Printf("[fl-orchestrator] contract lookup for %s: %v", submissionID, err)
	writeJSON(w, http.StatusBadGateway, j{"status": "FAILED", "error": "GOV_LAYER_UNAVAILABLE"})
	return nil
}
