// Package postapply runs the Flotilla join-gateway steps that follow
// `terraform apply` on a freshly created session VM:
//
//   - server VM ("Securing gateway"): read the gateway's CSR (its key was
//     generated on the VM and never leaves it), get it signed by gov_layer,
//     write the certificate + authorized parties, start the gateway;
//   - client VM ("Connecting to the session"): point the sidecar at this
//     submission's gateway and write the provider's VM credential.
//
// Everything reaches the VM over SSH. Secrets go ONLY through the SSH
// session's stdin — never on a command line (visible in ps), in terraform
// variables/state, in logs or in provisioning events.
package postapply

import (
	"bytes"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"
)

// SSHTarget is one VM reachable over SSH.
type SSHTarget struct {
	Host       string
	User       string
	Port       string
	KeyPath    string // empty: the default identity (manual/test runs)
	KnownHosts string // per-run known_hosts file (trust on first use, like terraform's own connection)
}

func (t SSHTarget) args(remote string) []string {
	a := []string{"-o", "BatchMode=yes", "-o", "ConnectTimeout=20", "-o", "StrictHostKeyChecking=accept-new"}
	if t.KnownHosts != "" {
		a = append(a, "-o", "UserKnownHostsFile="+t.KnownHosts)
	}
	if t.KeyPath != "" {
		a = append(a, "-i", t.KeyPath, "-o", "IdentitiesOnly=yes")
	}
	if t.Port != "" {
		a = append(a, "-p", t.Port)
	}
	return append(a, t.User+"@"+t.Host, remote)
}

// sshBinary is overridable in tests.
var sshBinary = "ssh"

// Run executes remote on the VM, feeding stdin (may be nil). The returned
// error carries the command's own output, never stdin.
func (t SSHTarget) Run(remote string, stdin []byte) (string, error) {
	cmd := exec.Command(sshBinary, t.args(remote)...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if err != nil {
		msg := strings.TrimSpace(errb.String() + "\n" + out.String())
		if len(msg) > 600 {
			msg = msg[len(msg)-600:]
		}
		return out.String(), fmt.Errorf("ssh %s@%s %q: %w: %s", t.User, t.Host, remote, err, msg)
	}
	return out.String(), nil
}

// Stream executes remote on the VM and copies its stdout to w as it arrives
// (for large files: nothing is buffered here). The returned error carries the
// command's stderr.
func (t SSHTarget) Stream(remote string, w io.Writer) error {
	cmd := exec.Command(sshBinary, t.args(remote)...)
	var errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = w, &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if len(msg) > 600 {
			msg = msg[len(msg)-600:]
		}
		return fmt.Errorf("ssh %s@%s %q: %w: %s", t.User, t.Host, remote, err, msg)
	}
	return nil
}

// RunRetry retries Run while the VM is still coming up (sshd not ready yet).
func (t SSHTarget) RunRetry(remote string, stdin []byte, attempts int, wait time.Duration) (string, error) {
	var out string
	var err error
	for i := 0; i < attempts; i++ {
		if out, err = t.Run(remote, stdin); err == nil {
			return out, nil
		}
		time.Sleep(wait)
	}
	return out, err
}

// shellQuote single-quotes s for a POSIX shell.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
