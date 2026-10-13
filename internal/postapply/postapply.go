package postapply

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/s4r4v4n04/p3dx-fl-orchestrator/internal/config"
	"github.com/s4r4v4n04/p3dx-fl-orchestrator/internal/keycloak"
)

// Emit reports one provisioning step (the same events the SSE stream shows).
type Emit func(step, status, message string)

// Runner holds what the post-apply steps need.
type Runner struct {
	cfg    *config.Config
	tokens *keycloak.TokenSource
	http   *http.Client
}

func New(cfg *config.Config, tokens *keycloak.TokenSource) *Runner {
	return &Runner{cfg: cfg, tokens: tokens, http: &http.Client{Timeout: 30 * time.Second}}
}

// GatewayCert is gov_layer's POST /gateway-certs response (the parts we use).
type GatewayCert struct {
	Serial       string            `json:"serial"`
	CertPEM      string            `json:"certificate_pem"`
	CAPEM        string            `json:"ca_certificate_pem"`
	Fingerprint  string            `json:"fingerprint_sha256"`
	NotAfter     string            `json:"not_after"`
	ContractID   string            `json:"contract_id"`
	ProjectID    string            `json:"project_id"`
	JobID        string            `json:"job_id"`
	SubmissionID string            `json:"submission_id"`
	ValidUntil   string            `json:"valid_until"`
	Parties      []json.RawMessage `json:"parties"`
}

// serviceCall POSTs JSON to url with the orchestrator's service token.
func (r *Runner) serviceCall(url string, body any, out any) error {
	tok, err := r.tokens.Token()
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := r.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		var e struct{ Error, Message string }
		_ = json.Unmarshal(raw, &e)
		return fmt.Errorf("%s returned %d %s %s", url, resp.StatusCode, e.Error, e.Message)
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

func (r *Runner) home(rel string) string {
	if strings.HasPrefix(r.cfg.VMFlotillaDir, "/") {
		return path.Join(r.cfg.VMFlotillaDir, rel)
	}
	return "~/" + path.Join(r.cfg.VMFlotillaDir, rel)
}

// install writes content to dst on the VM as the gateway uid, via stdin.
func (r *Runner) install(t SSHTarget, dst, mode string, content []byte) error {
	uid := r.cfg.GatewayUID
	_, err := t.Run(fmt.Sprintf("sudo install -m %s -o %s -g %s /dev/stdin %s", mode, uid, uid, shellQuote(dst)), content)
	return err
}

// SecureGateway runs "Securing gateway" on a new server VM and returns the
// issued certificate (whose CA and fingerprint flauto needs).
func (r *Runner) SecureGateway(t SSHTarget, serverIP, submissionID string, emit Emit) (*GatewayCert, error) {
	emit("Securing gateway", "running", "Reading the gateway's certificate request")
	csr, err := t.RunRetry("sudo cat "+shellQuote(path.Join(r.cfg.GatewayDir, "tls.csr")), nil, 10, 6*time.Second)
	if err != nil || !strings.Contains(csr, "CERTIFICATE REQUEST") {
		return nil, fmt.Errorf("read gateway CSR: %v", err)
	}

	emit("Securing gateway", "running", "Requesting the gateway certificate from the governance layer")
	var cert GatewayCert
	if err := r.serviceCall(r.cfg.GovLayerURL+"/gateway-certs",
		map[string]string{"csr_pem": csr, "server_ip": serverIP, "submission_id": submissionID}, &cert); err != nil {
		return nil, fmt.Errorf("gateway certificate: %w", err)
	}

	parties, _ := json.MarshalIndent(map[string]any{
		"submission_id": cert.SubmissionID, "project_id": cert.ProjectID, "contract_id": cert.ContractID,
		"job_id": cert.JobID, "valid_until": cert.ValidUntil, "parties": cert.Parties,
	}, "", "  ")
	for _, f := range []struct {
		name    string
		content []byte
	}{{"tls.crt", []byte(cert.CertPEM)}, {"ca.crt", []byte(cert.CAPEM)}, {"parties.json", parties}} {
		if err := r.install(t, path.Join(r.cfg.GatewayDir, f.name), "0644", f.content); err != nil {
			return nil, fmt.Errorf("write %s: %w", f.name, err)
		}
	}

	emit("Securing gateway", "running", "Starting the gateway")
	if _, err := t.Run("cd "+r.home("deployment")+" && sudo docker compose up -d --force-recreate gateway", nil); err != nil {
		return nil, fmt.Errorf("start gateway: %w", err)
	}
	if err := waitHealthy(t, "flotilla-gateway", r.cfg.GatewayReadyTimeout); err != nil {
		return nil, err
	}
	emit("Securing gateway", "ok", fmt.Sprintf("Gateway certificate %s issued for contract %s, valid until %s",
		cert.Serial, cert.ContractID, cert.NotAfter))
	return &cert, nil
}

func waitHealthy(t SSHTarget, container string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		out, err := t.Run("sudo docker inspect -f '{{.State.Health.Status}}' "+container, nil)
		if err == nil && strings.TrimSpace(out) == "healthy" {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s not healthy after %s (last: %q %v)", container, timeout, strings.TrimSpace(out), err)
		}
		time.Sleep(5 * time.Second)
	}
}

// ClientInput is what "Connecting to the session" needs for one client VM.
type ClientInput struct {
	SubmissionID string
	CredentialID string
	Token        []byte // the provider's VM offline token — wiped by DeliverClient
	SelfIP       string // this client VM's public IP (the sidecar's advertised address)
	GatewayHost  string // this submission's server VM IP
	CAPEM        string
}

// DeliverClient configures the sidecar on a new client VM, writes the VM
// credential, starts client + sidecar, and tells p3dx-aaa it was delivered.
func (r *Runner) DeliverClient(t SSHTarget, in ClientInput, emit Emit) error {
	defer wipe(in.Token)
	emit("Connecting to the session", "running", "Configuring the client's gateway sidecar")
	env := fmt.Sprintf("GATEWAY_HOST=%s\nSIDECAR_ADVERTISE_HOST=%s\nAAA_URL=%s\n", in.GatewayHost, in.SelfIP, r.cfg.AAAPublicURL)
	if err := r.install(t, path.Join(r.cfg.SidecarDir, "sidecar.env"), "0644", []byte(env)); err != nil {
		return fmt.Errorf("write sidecar.env: %w", err)
	}
	if err := r.install(t, path.Join(r.cfg.SidecarDir, "ca.crt"), "0644", []byte(in.CAPEM)); err != nil {
		return fmt.Errorf("write ca.crt: %w", err)
	}

	emit("Connecting to the session", "running", "Writing the VM credential")
	credential, err := json.Marshal(map[string]string{
		"credential_id": in.CredentialID, "offline_token": string(in.Token), "aaa_url": r.cfg.AAAPublicURL,
	})
	if err != nil {
		return err
	}
	err = r.install(t, path.Join(r.cfg.SidecarDir, "credential"), "0600", credential)
	wipe(credential)
	if err != nil {
		return fmt.Errorf("write VM credential: %w", err)
	}

	emit("Connecting to the session", "running", "Starting the client and its sidecar")
	if _, err := t.Run("cd "+r.home("")+" && sudo docker compose -f client-compose.yaml up -d", nil); err != nil {
		return fmt.Errorf("start client: %w", err)
	}
	if err := r.serviceCall(r.cfg.AAAURL+"/p3dx/internal/fl/vm-credentials/"+in.CredentialID+"/delivered",
		map[string]string{}, nil); err != nil {
		// Delivery itself succeeded; the bookkeeping call failing is not fatal.
		emit("Connecting to the session", "running", "Note: could not record delivery with p3dx-aaa")
	}
	emit("Connecting to the session", "ok", "Client and sidecar started; joining through the session gateway")
	return nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
