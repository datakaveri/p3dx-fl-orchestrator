// Package provisioning does fully automated VM creation: it runs
// `az login --use-device-code` in an isolated Azure CLI config (so concurrent
// participants never collide), then runs the same terraform/participant-vm
// config deploy.sh uses — but as a child process here, driven by that
// participant's own freshly-authenticated Azure CLI session, so the VM lands
// in *their* Azure subscription without them running anything locally.
//
// This deliberately does NOT use the browser's MSAL access token: Terraform's
// azurerm provider has no supported "hand me a bearer token" auth mode (its
// options are Azure CLI, a Service Principal, Managed Identity, or OIDC
// federation) — Azure CLI is the one that actually works here, so the device
// code is a second, separate Azure sign-in from the MSAL identity check the
// participant already did.
//
// Ported from p3dx-aaa/src/services/vmAutoProvision.service.js.
package provisioning

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/s4r4v4n04/p3dx-fl-orchestrator/internal/config"
	"github.com/s4r4v4n04/p3dx-fl-orchestrator/internal/flauto"
	"github.com/s4r4v4n04/p3dx-fl-orchestrator/internal/postapply"
	"github.com/s4r4v4n04/p3dx-fl-orchestrator/internal/vmcred"
	"github.com/s4r4v4n04/p3dx-fl-orchestrator/internal/vmsession"
)

// Provisioner runs Azure/Terraform provisioning and reports progress through
// a vmsession.Store (the same one the SSE stream and /events endpoint read
// from) and a flauto.Manager (so the owner/provider VM registration chains
// into the post-provisioning FL auto-start).
type Provisioner struct {
	cfg   *config.Config
	store *vmsession.Store
	flow  *flauto.Manager
	creds *vmcred.Store
	post  *postapply.Runner

	// tfDir is the participant-vm terraform root, now local to this service
	// (see config.TerraformDir).
	tfDir string
	// repoRoot is the workspace root — one level above this service's own
	// directory — where Flotilla_Deployment still lives (see the plan: only
	// the terraform config moved into this service, not Flotilla_Deployment).
	repoRoot string
	// provisioningLogDir holds full `terraform apply` output on failure, so a
	// failure can be diagnosed after the fact without SSHing into the VM.
	provisioningLogDir string
	// pluginCacheDir is a shared, persistent cache of downloaded provider
	// plugins (azurerm is large) so concurrent runs' `terraform init` calls
	// reuse one download instead of each fetching it again.
	pluginCacheDir string

	activeRunKeys sync.Map // runKey -> struct{}

	mu          sync.Mutex
	privateKeys map[string]string // provisioning token -> PEM text, cleared on first download
}

func New(cfg *config.Config, store *vmsession.Store, flow *flauto.Manager, creds *vmcred.Store, post *postapply.Runner) *Provisioner {
	return &Provisioner{
		cfg:                 cfg,
		store:               store,
		flow:                flow,
		creds:               creds,
		post:                post,
		tfDir:               cfg.TerraformDir,
		repoRoot:            filepath.Dir(cfg.ServiceRoot),
		provisioningLogDir:  filepath.Join(cfg.ServiceRoot, "logs", "vm-provisioning"),
		pluginCacheDir:      filepath.Join(cfg.TerraformDir, ".terraform-plugin-cache"),
		privateKeys:         make(map[string]string),
	}
}

// IsProvisioning reports whether a run for this runKey is already in flight.
func (p *Provisioner) IsProvisioning(runKey string) bool {
	_, ok := p.activeRunKeys.Load(runKey)
	return ok
}

var slugRe = regexp.MustCompile(`[^a-z0-9]+`)
var trimDashRe = regexp.MustCompile(`^-+|-+$`)

func slugify(name string) string {
	slug := strings.ToLower(strings.TrimSpace(name))
	slug = slugRe.ReplaceAllString(slug, "-")
	slug = trimDashRe.ReplaceAllString(slug, "")
	if len(slug) > 22 {
		slug = slug[:22]
	}
	if slug == "" {
		return "participant"
	}
	return slug
}

// Event mirrors vmAutoProvision.service.js's `event()` calls: appended to the
// session store and logged, so a run can be traced without inspecting
// processes directly.
type eventLogger struct {
	p        *Provisioner
	token    string
	username string
}

func (e *eventLogger) emit(step, command, status, message string) {
	e.p.store.AppendEvent(e.token, step, command, status, message)
	extra := ""
	if message != "" {
		extra = fmt.Sprintf(" (%s)", message)
	}
	fmt.Printf("[vm-auto-provision] %s: %s — %s%s\n", e.username, step, status, extra)
}

var deviceCodeLineRe = regexp.MustCompile(`(?i)devicelogin|enter the code`)

// deviceCodeLogin runs the device-code login, streaming the code/URL out as a
// provisioning event the moment Azure CLI prints it.
func (p *Provisioner) deviceCodeLogin(env []string, ev *eventLogger) error {
	announced := false
	_, _, err := runCommand("az", []string{"login", "--use-device-code"}, "", env, func(line string) {
		if !announced && deviceCodeLineRe.MatchString(line) {
			announced = true
			ev.emit("Azure device login", "", "running", line)
		}
	})
	return err
}

// copyTerraformSource copies just the terraform *source* (not state, not
// .terraform/) plus the Flotilla_Deployment files main.tf's dataset-
// generation script reaches for, into an isolated per-run directory mirroring
// this service's own layout two levels deep
// (<serviceRoot-name>/terraform/participant-vm, with Flotilla_Deployment as
// its sibling) — the same depth main.tf's
// `${path.module}/../../../Flotilla_Deployment/...` reference expects, so it
// resolves correctly inside the isolated copy too. State still lands in the
// one persistent, shared location per participant it always has.
func (p *Provisioner) copyTerraformSource(runRoot string) (string, error) {
	serviceDirName := filepath.Base(p.cfg.ServiceRoot)
	destDir := filepath.Join(runRoot, serviceDirName, "terraform", "participant-vm")
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return "", err
	}
	entries := []string{"main.tf", "variables.tf", "outputs.tf", "versions.tf", "templates", ".terraform.lock.hcl"}
	for _, entry := range entries {
		src := filepath.Join(p.tfDir, entry)
		if _, err := os.Stat(src); os.IsNotExist(err) {
			continue
		}
		if err := runCp(src, filepath.Join(destDir, entry)); err != nil {
			return "", err
		}
	}

	externalFiles := []string{
		filepath.Join("Flotilla_Deployment", "generate_dataset.py"),
	}
	for _, rel := range externalFiles {
		destPath := filepath.Join(runRoot, rel)
		if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
			return "", err
		}
		if err := runCp(filepath.Join(p.repoRoot, rel), destPath); err != nil {
			return "", err
		}
	}
	return destDir, nil
}

func runCp(src, dst string) error {
	return exec.Command("cp", "-r", src, dst).Run()
}

// RunAutoProvisionInput bundles the parameters of one provisioning run.
type RunAutoProvisionInput struct {
	Token        string
	Username     string
	Role         string // "user" | "data-provider"
	VMName       string
	RunKey       string // identifies this caller's own instance; guards against a duplicate spawn of the *same* run
	SubmissionID string // ties this VM run to an FL submission, if any
	CredentialID string // data-provider: the claimed VM credential to deliver
}

// RunAutoProvision runs the full device-code-login + terraform-apply flow.
// Meant to be called in a goroutine — it blocks until the run finishes or
// fails, emitting events throughout to p.store.
func (p *Provisioner) RunAutoProvision(in RunAutoProvisionInput) {
	if _, loaded := p.activeRunKeys.LoadOrStore(in.RunKey, struct{}{}); loaded {
		p.store.AppendEvent(in.Token, "Starting", "", "error",
			"A provisioning run for you is already in progress — check for an earlier device code rather than starting a new one.")
		return
	}
	defer p.activeRunKeys.Delete(in.RunKey)
	// Whatever happens below, a VM credential claimed for this run never
	// outlives it in memory (Drop is a no-op once it has been delivered).
	if in.CredentialID != "" {
		defer p.creds.Drop(in.CredentialID)
	}

	if in.Role == "data-provider" && in.SubmissionID != "" {
		p.flow.RegisterProviderToken(in.SubmissionID, in.Token)
	}

	ev := &eventLogger{p: p, token: in.Token, username: in.Username}
	// The VM (and its RG/vnet/NSG/disk/workspace) is named after the
	// participant-chosen vmName, not their username/id.
	participantName := slugify(in.VMName)

	var workDir string
	var applyOutputLines []string
	var keyPath string

	cleanup := func() {
		p.activeRunKeys.Delete(in.RunKey)
		if workDir == "" {
			return
		}
		// On a failed run the VM may already exist (terraform apply can fail
		// partway through) with this run's public key installed as its only
		// admin_ssh_key — losing the matching private key here would make
		// that VM permanently unreachable. Stash it before wiping the temp
		// dir if it wasn't already stashed on the success path.
		p.mu.Lock()
		_, has := p.privateKeys[in.Token]
		p.mu.Unlock()
		if !has && keyPath != "" {
			if key, err := os.ReadFile(keyPath); err == nil {
				p.mu.Lock()
				p.privateKeys[in.Token] = string(key)
				p.mu.Unlock()
			}
		}
		_ = os.RemoveAll(workDir)
	}
	defer cleanup()

	ev.emit("Starting", "", "running",
		fmt.Sprintf(`Provisioning VM "%s" for %s (%s) — this needs one more Azure sign-in for Terraform itself.`, in.VMName, in.Username, in.Role))

	var err error
	workDir, err = os.MkdirTemp("", "p3dx-vm-")
	if err != nil {
		ev.emit("Provisioning failed", "", "error", err.Error())
		return
	}

	env := mergeEnv(mergeMaps(baseEnvOverrides(), map[string]string{
		"AZURE_CONFIG_DIR": filepath.Join(workDir, "azure-config"),
		"TF_IN_AUTOMATION": "1",
	}))

	ev.emit("Azure device login", "az login --use-device-code", "running", "Waiting for you to sign in via the code above...")
	if err := p.deviceCodeLogin(env, ev); err != nil {
		p.fail(ev, participantName, applyOutputLines, err)
		return
	}
	ev.emit("Azure device login", "", "ok", "Signed in")

	accountJSON, _, err := runCommand("az", []string{"account", "show", "-o", "json"}, "", env, nil)
	if err != nil {
		p.fail(ev, participantName, applyOutputLines, err)
		return
	}
	var account struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		User struct {
			Name string `json:"name"`
		} `json:"user"`
	}
	if err := json.Unmarshal([]byte(accountJSON), &account); err != nil {
		p.fail(ev, participantName, applyOutputLines, err)
		return
	}
	ev.emit("Azure account", "", "ok", fmt.Sprintf(`Using subscription "%s" (%s)`, account.Name, account.ID))

	keyPath = filepath.Join(workDir, "id_ed25519")
	ev.emit("SSH key", "", "running", "Generating a fresh SSH keypair for this VM")
	if _, _, err := runCommand("ssh-keygen", []string{"-t", "ed25519", "-N", "", "-f", keyPath, "-C", "p3dx-flo-" + participantName}, "", env, nil); err != nil {
		p.fail(ev, participantName, applyOutputLines, err)
		return
	}
	ev.emit("SSH key", "", "ok", "")

	tfOverrides := map[string]string{
		"TF_VAR_role":                 in.Role,
		"TF_VAR_participant_name":     participantName,
		"TF_VAR_created_by":           orDefault(account.User.Name, account.ID),
		"TF_VAR_ssh_public_key_path":  keyPath + ".pub",
		"TF_VAR_ssh_private_key_path": keyPath,
	}
	// Lets the VM `docker login ghcr.io` and pull the pre-built
	// flotilla-server/client/session images instead of git-cloning and
	// building from source. Falls back to variables.tf's own defaults if
	// unset here.
	if p.cfg.GHCRNamespace != "" {
		tfOverrides["TF_VAR_ghcr_namespace"] = p.cfg.GHCRNamespace
	}
	if p.cfg.GHCRPullToken != "" {
		tfOverrides["TF_VAR_ghcr_token"] = p.cfg.GHCRPullToken
	}
	// Flotilla join gateway: the server VM's gateway verifies tokens from
	// this P3DX Keycloak realm. No secret is passed to terraform.
	tfOverrides["TF_VAR_keycloak_issuer"] = strings.TrimRight(p.cfg.KeycloakBaseURL, "/") + "/realms/" + p.cfg.KeycloakRealm
	if v := os.Getenv("GATEWAY_KEYCLOAK_JWKS_URL"); v != "" {
		tfOverrides["TF_VAR_keycloak_jwks_url"] = v
	}
	if v := os.Getenv("GATEWAY_IMAGE"); v != "" {
		tfOverrides["TF_VAR_gateway_image"] = v
	}

	// Runs in a private copy of the terraform config so this run's
	// `.terraform/` never collides with another concurrent run's.
	// `-backend-config` points this private copy at the SAME persistent
	// state file this participant's workspace has always used
	// (terraform.tfstate.d/<name>/terraform.tfstate under tfDir), so nothing
	// about where state lives actually changes.
	statePath := filepath.Join(p.tfDir, "terraform.tfstate.d", participantName, "terraform.tfstate")
	if err := os.MkdirAll(p.pluginCacheDir, 0o755); err != nil {
		p.fail(ev, participantName, applyOutputLines, err)
		return
	}
	if err := os.MkdirAll(filepath.Dir(statePath), 0o755); err != nil {
		p.fail(ev, participantName, applyOutputLines, err)
		return
	}
	tfOverrides["TF_PLUGIN_CACHE_DIR"] = p.pluginCacheDir
	tfEnv := mergeEnv(mergeMaps(baseEnvOverrides(), mergeMaps(tfOverrides, map[string]string{
		"AZURE_CONFIG_DIR": filepath.Join(workDir, "azure-config"),
		"TF_IN_AUTOMATION": "1",
	})))

	ev.emit("Preparing Terraform config", "", "running", "Setting up an isolated working directory for this run")
	runTfDir, err := p.copyTerraformSource(workDir)
	if err != nil {
		p.fail(ev, participantName, applyOutputLines, err)
		return
	}
	ev.emit("Preparing Terraform config", "", "ok", "")

	ev.emit("Terraform init", "terraform init -input=false", "running", "")
	if _, _, err := runCommand("terraform", []string{"init", "-input=false", "-no-color", "-backend-config=path=" + statePath}, runTfDir, tfEnv, nil); err != nil {
		p.fail(ev, participantName, applyOutputLines, err)
		return
	}
	ev.emit("Terraform init", "", "ok", "")

	ev.emit("Creating VM", "terraform apply -auto-approve -input=false", "running", "")
	// Once the VM exists, two provisioners stream progress as "STAGE: ..." /
	// "WARNING: ..." lines: wait_for_combine_fl SSHes into the VM itself
	// (tagged "(remote-exec):" by terraform) and configure_broker runs
	// locally right after (tagged "(local-exec):"). Surface each one as its
	// own event instead of one opaque "Creating VM" spinner for the whole
	// apply.
	remoteStageLineRe := regexp.MustCompile(`\(remote-exec\):\s*(?:STAGE|WARNING):\s*(.+)$`)
	localStageLineRe := regexp.MustCompile(`\(local-exec\):\s*(?:STAGE|WARNING):\s*(.+)$`)
	_, _, err = runCommand("terraform", []string{"apply", "-auto-approve", "-input=false", "-no-color"}, runTfDir, tfEnv, func(line string) {
		applyOutputLines = append(applyOutputLines, line)
		if m := remoteStageLineRe.FindStringSubmatch(line); m != nil {
			ev.emit("VM setup", "", "running", strings.TrimSpace(m[1]))
			return
		}
		if m := localStageLineRe.FindStringSubmatch(line); m != nil {
			ev.emit("Broker config", "", "running", strings.TrimSpace(m[1]))
		}
	})
	if err != nil {
		p.fail(ev, participantName, applyOutputLines, err)
		return
	}

	outputsJSON, _, err := runCommand("terraform", []string{"output", "-json"}, runTfDir, tfEnv, nil)
	if err != nil {
		p.fail(ev, participantName, applyOutputLines, err)
		return
	}
	var outputs struct {
		SSHCommand    struct{ Value string `json:"value"` } `json:"ssh_command"`
		VMName        struct{ Value string `json:"value"` } `json:"vm_name"`
		PublicIP      struct{ Value string `json:"value"` } `json:"public_ip_address"`
	}
	_ = json.Unmarshal([]byte(outputsJSON), &outputs)

	// Flotilla join gateway: secure the server VM's gateway / connect the
	// client VM to its own session's gateway. Secrets travel over SSH stdin
	// only (see internal/postapply), never through terraform.
	if in.SubmissionID != "" && outputs.PublicIP.Value != "" {
		target := postapply.SSHTarget{Host: outputs.PublicIP.Value, User: p.cfg.SSHUser, Port: p.cfg.SSHPort,
			KeyPath: keyPath, KnownHosts: filepath.Join(workDir, "known_hosts")}
		if err := p.runPostApply(in, target, outputs.PublicIP.Value, ev); err != nil {
			p.fail(ev, participantName, nil, err)
			return
		}
	}

	if key, err := os.ReadFile(keyPath); err == nil {
		p.mu.Lock()
		p.privateKeys[in.Token] = string(key)
		p.mu.Unlock()
	}

	createdVMName := orDefault(outputs.VMName.Value, participantName)
	msg := fmt.Sprintf(`VM "%s" created.`, createdVMName)
	if outputs.SSHCommand.Value != "" {
		msg += fmt.Sprintf(" Connect: %s", outputs.SSHCommand.Value)
	}
	msg += " Download your SSH key below."
	ev.emit("Creating VM", "", "done", msg)
}

// runPostApply runs the gateway steps that follow terraform apply for an FL
// submission's VM. For the server VM it secures the gateway and only then
// announces the VM to flauto; for a client VM it waits for this submission's
// own server VM and delivers the provider's VM credential.
func (p *Provisioner) runPostApply(in RunAutoProvisionInput, target postapply.SSHTarget, ip string, ev *eventLogger) error {
	emit := func(step, status, msg string) { ev.emit(step, "", status, msg) }
	switch in.Role {
	case "user":
		cert, err := p.post.SecureGateway(target, ip, in.SubmissionID, emit)
		if err != nil {
			return err
		}
		if err := p.flow.SetGatewayCA(in.SubmissionID, cert.CAPEM); err != nil {
			return err
		}
		p.flow.RegisterOwnerVM(in.SubmissionID, ip, in.Token)
		return nil
	case "data-provider":
		if in.CredentialID == "" {
			return fmt.Errorf("no VM credential for this client VM — authorize the VM first")
		}
		emit("Waiting for server VM", "running", "Waiting for this session's server VM and gateway")
		ownerIP, caPEM, err := p.flow.WaitOwnerIP(in.SubmissionID, p.cfg.OwnerWaitTimeout)
		if err != nil {
			p.creds.Drop(in.CredentialID)
			return err
		}
		emit("Waiting for server VM", "ok", "Session gateway at "+ownerIP)
		token, err := p.creds.Take(in.CredentialID)
		if err != nil {
			return err
		}
		return p.post.DeliverClient(target, postapply.ClientInput{
			SubmissionID: in.SubmissionID, CredentialID: in.CredentialID, Token: token,
			SelfIP: ip, GatewayHost: ownerIP, CAPEM: caPEM,
		}, emit)
	}
	return nil
}

func (p *Provisioner) fail(ev *eventLogger, participantName string, applyOutputLines []string, cause error) {
	message := cause.Error()
	if len(applyOutputLines) > 0 {
		if err := os.MkdirAll(p.provisioningLogDir, 0o755); err == nil {
			logPath := filepath.Join(p.provisioningLogDir, fmt.Sprintf("%s-%d.log", participantName, time.Now().UnixMilli()))
			if err := os.WriteFile(logPath, []byte(strings.Join(applyOutputLines, "\n")), 0o644); err == nil {
				// (remote-exec)/(local-exec) lines are the provisioner
				// scripts' own output; "Error:" lines are terraform's own
				// diagnostics - together these are what actually explains an
				// apply failure, unlike the generic "Process exited with
				// status 1" terraform reports on its own.
				var relevant []string
				for _, l := range applyOutputLines {
					if strings.Contains(l, "(remote-exec):") || strings.Contains(l, "(local-exec):") || strings.HasPrefix(l, "Error:") {
						relevant = append(relevant, l)
					}
				}
				tail := ""
				if len(relevant) > 0 {
					start := 0
					if len(relevant) > 15 {
						start = len(relevant) - 15
					}
					tail = "\n\nLast relevant lines:\n" + strings.Join(relevant[start:], "\n")
				}
				message = fmt.Sprintf("%s\n\nFull apply output saved to %s%s", message, logPath, tail)
			}
		}
	}
	ev.emit("Provisioning failed", "", "error", message)
}

// TakePrivateKey is a one-time retrieval of the SSH private key generated for
// one auto-created VM run, identified by its provisioning token — cleared
// from memory as soon as it's downloaded.
func (p *Provisioner) TakePrivateKey(token string) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	key, ok := p.privateKeys[token]
	if ok {
		delete(p.privateKeys, token)
	}
	return key, ok
}

func mergeMaps(a, b map[string]string) map[string]string {
	out := make(map[string]string, len(a)+len(b))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

func orDefault(v, fallback string) string {
	if v != "" {
		return v
	}
	return fallback
}
