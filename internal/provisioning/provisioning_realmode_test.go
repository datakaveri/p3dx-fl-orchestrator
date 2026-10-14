package provisioning

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/s4r4v4n04/p3dx-fl-orchestrator/internal/config"
	"github.com/s4r4v4n04/p3dx-fl-orchestrator/internal/vmsession"
)

type rmFixture struct {
	p      *Provisioner
	store  *vmsession.Store
	log    string
	tfDir  string
	tmp    string
	runDir string
}

// newRMFixture builds a fake HOME with fake az/terraform/ssh-keygen in
// ~/.local/bin (found first via baseEnvOverrides) plus a stub terraform tree.
func newRMFixture(t *testing.T, dry map[string]string) *rmFixture {
	t.Helper()
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	bin := filepath.Join(home, ".local", "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	// exec.Command resolves the binary via the *process* PATH (cmd.Env only
	// affects the child), so the fake dir must be on the test process's PATH.
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	for _, k := range []string{"TF_VAR_existing_vm_ip", "TF_VAR_admin_username", "TF_VAR_created_by",
		"GATEWAY_KEYCLOAK_JWKS_URL", "GATEWAY_IMAGE", "AZURE_CONFIG_DIR"} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
	logf := filepath.Join(tmp, "calls.log")

	prelude := `#!/bin/bash
LOG='` + logf + `'
{ echo "CMD $(basename "$0") $*"
  echo "ENV AZURE_CONFIG_DIR=${AZURE_CONFIG_DIR-<unset>}"
  echo "ENV TF_VAR_created_by=${TF_VAR_created_by-<unset>}"
  echo "ENV TF_VAR_existing_vm_ip=${TF_VAR_existing_vm_ip-<unset>}"
  echo "ENV TF_VAR_admin_username=${TF_VAR_admin_username-<unset>}"
} >> "$LOG"
`
	script := func(name, body string) {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(prelude+body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	script("az", `
if [ "$1" = login ]; then echo "To sign in, open https://microsoft.com/devicelogin and enter the code ABC123"; exit 0; fi
if [ "$1" = account ]; then echo '{"id":"sub-123","name":"Test Sub","user":{"name":"tester@example.com"}}'; exit 0; fi
exit 1
`)
	script("ssh-keygen", `
while [ $# -gt 0 ]; do [ "$1" = -f ] && f="$2"; shift; done
echo priv > "$f"; echo pub > "$f.pub"
`)
	script("terraform", `
echo "TFCWD main.tf=$(head -1 main.tf)" >> "$LOG"
if [ "$1" = output ]; then
  echo '{"ssh_command":{"value":"ssh x@192.0.2.99"},"vm_name":{"value":"vm-out"},"public_ip_address":{"value":"192.0.2.99"}}'
fi
exit 0
`)

	repoRoot := filepath.Join(tmp, "repo")
	svcRoot := filepath.Join(repoRoot, "svc")
	tfDir := filepath.Join(svcRoot, "terraform", "participant-vm")
	write := func(path, content string) {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"main.tf", "variables.tf", "outputs.tf", "versions.tf"} {
		write(filepath.Join(tfDir, f), "REAL "+f+"\n")
	}
	for _, f := range []string{"main.tf", "outputs.tf", "versions.tf"} {
		write(filepath.Join(tfDir, "dry-run", f), "DRYRUN "+f+"\n")
	}
	write(filepath.Join(repoRoot, "Flotilla_Deployment", "generate_dataset.py"), "py")

	store := vmsession.NewStore()
	cfg := &config.Config{ServiceRoot: svcRoot, TerraformDir: tfDir, SSHUser: "azureuser", SSHPort: "22", DryRunVMs: dry}
	p := &Provisioner{
		cfg: cfg, store: store, tfDir: tfDir, repoRoot: repoRoot,
		provisioningLogDir: filepath.Join(svcRoot, "logs"),
		pluginCacheDir:     filepath.Join(tfDir, ".terraform-plugin-cache"),
		privateKeys:        map[string]string{},
	}
	return &rmFixture{p: p, store: store, log: logf, tfDir: tfDir, tmp: tmp}
}

func (f *rmFixture) run(t *testing.T, role string) (string, []vmsession.Event) {
	t.Helper()
	tok := f.store.CreateToken("alice", role)
	f.p.RunAutoProvision(RunAutoProvisionInput{Token: tok, Username: "alice", Role: role, VMName: "My VM", RunKey: "rk"})
	snap, ok := f.store.Get(tok)
	if !ok {
		t.Fatal("no session")
	}
	b, _ := os.ReadFile(f.log)
	return string(b), snap.Events
}

func hasEvent(evs []vmsession.Event, step, status string) bool {
	for _, e := range evs {
		if e.Step == step && e.Status == status {
			return true
		}
	}
	return false
}

func TestRunAutoProvisionRealModeUnchanged(t *testing.T) {
	f := newRMFixture(t, nil)
	log, evs := f.run(t, "user")

	for _, want := range []string{
		"CMD az login --use-device-code",
		"CMD az account show -o json",
		"CMD ssh-keygen -t ed25519",
		"CMD terraform init -input=false -no-color -backend-config=path=" + filepath.Join(f.tfDir, "terraform.tfstate.d", "my-vm", "terraform.tfstate") + "\n",
		"CMD terraform apply -auto-approve -input=false -no-color",
		"CMD terraform output -json",
		"ENV TF_VAR_created_by=tester@example.com",
		"ENV TF_VAR_existing_vm_ip=<unset>",
		"ENV TF_VAR_admin_username=<unset>",
	} {
		if !strings.Contains(log, want) {
			t.Errorf("log missing %q\n%s", want, log)
		}
	}
	if strings.Contains(log, "dry-run") {
		t.Errorf("dry-run path leaked into real run:\n%s", log)
	}
	if strings.Contains(log, "TFCWD main.tf=DRYRUN") || !strings.Contains(log, "TFCWD main.tf=REAL main.tf") {
		t.Errorf("terraform did not see the real main.tf:\n%s", log)
	}
	if strings.Contains(log, "TF_VAR_created_by=dry-run") {
		t.Errorf("created_by is dry-run")
	}
	if !hasEvent(evs, "Azure device login", "running") || !hasEvent(evs, "Azure device login", "ok") || !hasEvent(evs, "Azure account", "ok") {
		t.Errorf("missing azure events: %+v", evs)
	}
	if hasEvent(evs, "Starting", "error") {
		t.Errorf("unexpected error: %+v", evs)
	}
	last := evs[len(evs)-1]
	if last.Step != "Creating VM" || last.Status != "done" || !strings.Contains(last.Message, "vm-out") {
		t.Errorf("last event = %+v", last)
	}
	if first := evs[0]; first.Step != "Starting" || !strings.Contains(first.Message, "one more Azure sign-in") {
		t.Errorf("first event = %+v", first)
	}
}

func TestRunAutoProvisionDryRunMode(t *testing.T) {
	f := newRMFixture(t, map[string]string{"user": "192.0.2.10"})
	log, evs := f.run(t, "user")

	if strings.Contains(log, "CMD az ") {
		t.Errorf("az must not run in dry-run:\n%s", log)
	}
	for _, want := range []string{
		"TFCWD main.tf=DRYRUN main.tf",
		"ENV TF_VAR_existing_vm_ip=192.0.2.10",
		"ENV TF_VAR_admin_username=azureuser",
		"ENV TF_VAR_created_by=dry-run",
		"-backend-config=path=" + filepath.Join(f.tfDir, "terraform.tfstate.d", "dry-run", "my-vm", "terraform.tfstate"),
	} {
		if !strings.Contains(log, want) {
			t.Errorf("log missing %q\n%s", want, log)
		}
	}
	if strings.Contains(log, "TFCWD main.tf=REAL") {
		t.Errorf("real main.tf seen in dry-run:\n%s", log)
	}
	last := evs[len(evs)-1]
	if last.Step != "Creating VM" || last.Status != "done" {
		t.Errorf("last event = %+v", last)
	}
}

func TestRunAutoProvisionDryRunMissingRole(t *testing.T) {
	f := newRMFixture(t, map[string]string{"data-provider": "192.0.2.20"})
	log, evs := f.run(t, "user")

	if log != "" {
		t.Errorf("no external command should run, got:\n%s", log)
	}
	if len(evs) == 0 || evs[len(evs)-1].Status != "error" {
		t.Errorf("want trailing error event, got %+v", evs)
	}
	if !hasEvent(evs, "Provisioning failed", "error") && !hasAnyError(evs) {
		t.Errorf("no error event: %+v", evs)
	}
}

func hasAnyError(evs []vmsession.Event) bool {
	for _, e := range evs {
		if e.Status == "error" {
			return true
		}
	}
	return false
}
