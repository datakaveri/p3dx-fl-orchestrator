package provisioning

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/s4r4v4n04/p3dx-fl-orchestrator/internal/config"
)

func TestCopyTerraformSourceDryRunOverlay(t *testing.T) {
	repoRoot := t.TempDir()
	svcRoot := filepath.Join(repoRoot, "svc")
	tfDir := filepath.Join(svcRoot, "terraform", "participant-vm")
	write := func(path, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"main.tf", "outputs.tf", "versions.tf", "variables.tf"} {
		write(filepath.Join(tfDir, f), "real "+f)
	}
	write(filepath.Join(tfDir, "templates", "t.tftpl"), "tpl")
	for _, f := range []string{"main.tf", "outputs.tf", "versions.tf"} {
		write(filepath.Join(tfDir, "dry-run", f), "dry "+f)
	}
	write(filepath.Join(repoRoot, "Flotilla_Deployment", "generate_dataset.py"), "py")

	p := &Provisioner{cfg: &config.Config{ServiceRoot: svcRoot}, tfDir: tfDir, repoRoot: repoRoot}
	cases := []struct {
		dryRun bool
		prefix string
	}{{false, "real "}, {true, "dry "}}
	for _, c := range cases {
		dest, err := p.copyTerraformSource(t.TempDir(), c.dryRun)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range []string{"main.tf", "outputs.tf", "versions.tf"} {
			got, _ := os.ReadFile(filepath.Join(dest, f))
			if string(got) != c.prefix+f {
				t.Errorf("dryRun=%v %s = %q, want %q", c.dryRun, f, got, c.prefix+f)
			}
		}
		if got, _ := os.ReadFile(filepath.Join(dest, "variables.tf")); string(got) != "real variables.tf" {
			t.Errorf("variables.tf = %q, want real copy", got)
		}
		if _, err := os.Stat(filepath.Join(dest, "templates", "t.tftpl")); err != nil {
			t.Errorf("templates not copied: %v", err)
		}
	}
}
