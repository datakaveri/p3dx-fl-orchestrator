// Package config loads runtime configuration for the fl-orchestrator service
// from environment variables (and the service's own .env, loaded with
// override semantics — see LoadEnv), mirroring p3dx_gov_layer's config
// package.
package config

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

// Config holds every tunable used by the service.
type Config struct {
	Port    string // PORT (default 3002)
	CORSRaw string // CORS_ORIGINS

	KeycloakBaseURL string // KEYCLOAK_BASE_URL
	KeycloakRealm   string // KEYCLOAK_REALM

	// InternalServiceKey guards POST /p3dx/internal/register-expected-providers
	// (X-Internal-Key header). An empty value disables the check, same
	// "empty disables it" convention as gov_layer's VM_REGISTRY_TOKEN.
	InternalServiceKey string

	// GHCR pull creds, forwarded to terraform as TF_VAR_ghcr_namespace /
	// TF_VAR_ghcr_token (see internal/provisioning) — lets provisioned VMs
	// `docker login ghcr.io` instead of building from source.
	GHCRNamespace string
	GHCRPullToken string

	// AzureTenantID (AZURE_TENANT_ID), when set, pins the device-code login to
	// this Microsoft Entra tenant (`az login --tenant`), so a personal Microsoft
	// account sharing the same email can't be picked instead of the work one.
	AzureTenantID string

	// TerraformDir is the participant-vm terraform root, local to this
	// service now (moved in from the workspace-root terraform/ directory).
	TerraformDir string

	// ServiceRoot is this service's own directory (p3dx-fl-orchestrator/),
	// used to resolve TerraformDir, the provisioning log dir, and the
	// terraform plugin cache — all local to this service, not the outer
	// workspace.
	ServiceRoot string

	// --- Flotilla join gateway ---

	// The orchestrator's own Keycloak identity (client-credentials grant,
	// realm role fl-orchestrator): used to request gateway certificates from
	// gov_layer, to call the gateway's REST API, and for p3dx-aaa callbacks.
	KeycloakClientID     string // KEYCLOAK_CLIENT_ID (default p3dx-fl-orchestrator)
	KeycloakClientSecret string // KEYCLOAK_CLIENT_SECRET
	// FlotillaVMClientID is the Keycloak client VM credentials are minted
	// for; its tokens are refused on this service's own endpoints.
	FlotillaVMClientID string // FLOTILLA_VM_CLIENT_ID (default flotilla-vm)

	GovLayerURL  string // GOV_LAYER_URL (default http://localhost:8083/api/v1)
	AAAURL       string // AAA_URL — p3dx-aaa as this service reaches it
	AAAPublicURL string // AAA_PUBLIC_URL — p3dx-aaa as client VMs reach it (sidecar token refresh)

	// Paths on the session VMs (cloud-init.sh.tftpl creates them).
	GatewayDir      string // GATEWAY_DIR (default /etc/flotilla-gateway)
	SidecarDir      string // SIDECAR_DIR (default /etc/flotilla-sidecar)
	VMFlotillaDir   string // VM_FLOTILLA_DIR (default flotilla, relative to the VM user's home)
	GatewayUID      string // GATEWAY_UID — uid the gateway image runs as (default 10001)
	GatewayRESTPort int    // GATEWAY_REST_PORT (default 12345)
	SSHUser         string // VM_SSH_USER (default azureuser — participant-vm's admin_username)
	SSHPort         string // VM_SSH_PORT (default 22)

	// DryRunVMs (DRY_RUN_VMS, "role=host,role=host") is a test-only mode: runs
	// use these existing VMs per role instead of signing in to Azure and
	// creating one. Empty = normal runs.
	DryRunVMs map[string]string

	VMCredentialClaimTTL time.Duration // VM_CREDENTIAL_CLAIM_TTL (default 30m)
	OwnerWaitTimeout     time.Duration // OWNER_WAIT_TIMEOUT (default 45m)
	GatewayReadyTimeout  time.Duration // GATEWAY_READY_TIMEOUT (default 5m)
}

// LoadEnv loads the service's own .env with OVERRIDE semantics, matching
// gov_layer's config.LoadEnv. A missing .env is non-fatal.
func LoadEnv() {
	_ = godotenv.Overload(".env")
}

// Load reads configuration from the environment.
func Load() *Config {
	root := serviceRoot()

	dryRunVMs, err := ParseDryRunVMs(os.Getenv("DRY_RUN_VMS"))
	if err != nil {
		log.Fatalf("[config] DRY_RUN_VMS: %v", err)
	}

	return &Config{
		Port:    getEnv("PORT", "3002"),
		CORSRaw: os.Getenv("CORS_ORIGINS"),

		KeycloakBaseURL: os.Getenv("KEYCLOAK_BASE_URL"),
		KeycloakRealm:   os.Getenv("KEYCLOAK_REALM"),

		InternalServiceKey: os.Getenv("INTERNAL_SERVICE_KEY"),

		GHCRNamespace: os.Getenv("GHCR_NAMESPACE"),
		GHCRPullToken: os.Getenv("GHCR_PULL_TOKEN"),

		AzureTenantID: strings.TrimSpace(os.Getenv("AZURE_TENANT_ID")),

		TerraformDir: getEnv("TERRAFORM_DIR", filepath.Join(root, "terraform", "participant-vm")),
		ServiceRoot:  root,

		KeycloakClientID:     getEnv("KEYCLOAK_CLIENT_ID", "p3dx-fl-orchestrator"),
		KeycloakClientSecret: os.Getenv("KEYCLOAK_CLIENT_SECRET"),
		FlotillaVMClientID:   getEnv("FLOTILLA_VM_CLIENT_ID", "flotilla-vm"),

		GovLayerURL:  strings.TrimRight(getEnv("GOV_LAYER_URL", "http://localhost:8083/api/v1"), "/"),
		AAAURL:       strings.TrimRight(getEnv("AAA_URL", "http://localhost:3001"), "/"),
		AAAPublicURL: strings.TrimRight(os.Getenv("AAA_PUBLIC_URL"), "/"),

		GatewayDir:      getEnv("GATEWAY_DIR", "/etc/flotilla-gateway"),
		SidecarDir:      getEnv("SIDECAR_DIR", "/etc/flotilla-sidecar"),
		VMFlotillaDir:   getEnv("VM_FLOTILLA_DIR", "flotilla"),
		GatewayUID:      getEnv("GATEWAY_UID", "10001"),
		GatewayRESTPort: getEnvInt("GATEWAY_REST_PORT", 12345),
		SSHUser:         getEnv("VM_SSH_USER", "azureuser"),
		SSHPort:         getEnv("VM_SSH_PORT", "22"),

		DryRunVMs: dryRunVMs,

		VMCredentialClaimTTL: getEnvDuration("VM_CREDENTIAL_CLAIM_TTL", 30*time.Minute),
		OwnerWaitTimeout:     getEnvDuration("OWNER_WAIT_TIMEOUT", 45*time.Minute),
		GatewayReadyTimeout:  getEnvDuration("GATEWAY_READY_TIMEOUT", 5*time.Minute),
	}
}

// ParseDryRunVMs parses DRY_RUN_VMS ("user=<host>,data-provider=<host>") into a
// role -> host map. Empty input means dry-run is off.
func ParseDryRunVMs(raw string) (map[string]string, error) {
	out := map[string]string{}
	if strings.TrimSpace(raw) == "" {
		return out, nil
	}
	for _, entry := range strings.Split(raw, ",") {
		role, host, ok := strings.Cut(entry, "=")
		role, host = strings.TrimSpace(role), strings.TrimSpace(host)
		if !ok || role == "" || host == "" {
			return nil, fmt.Errorf("malformed entry %q (want role=host)", strings.TrimSpace(entry))
		}
		if role != "user" && role != "data-provider" {
			return nil, fmt.Errorf("unknown role %q (want user or data-provider)", role)
		}
		out[role] = host
	}
	return out, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if v, err := strconv.Atoi(os.Getenv(key)); err == nil && v > 0 {
		return v
	}
	return fallback
}

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		log.Printf("[config] %s=%q is not a positive duration — using %s", key, raw, fallback)
		return fallback
	}
	return d
}

// serviceRoot returns this process's working directory (start-all.sh launches
// it from p3dx-fl-orchestrator/, same as every other service here).
func serviceRoot() string {
	cwd, err := os.Getwd()
	if err != nil {
		return "."
	}
	abs, err := filepath.Abs(cwd)
	if err != nil {
		return cwd
	}
	return abs
}
