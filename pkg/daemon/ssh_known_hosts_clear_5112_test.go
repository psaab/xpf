package daemon

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"golang.org/x/crypto/ssh"
)

// withTempSSHKnownHostsPath points sshKnownHostsPath at a temp file for the
// duration of a test and restores it afterward.
func withTempSSHKnownHostsPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "ssh_known_hosts")
	orig := sshKnownHostsPath
	sshKnownHostsPath = path
	t.Cleanup(func() { sshKnownHostsPath = orig })
	return path
}

// trustKey14692 is a real ssh-ed25519 blob (generated key, fixed test
// vector) so the #14692 parser validation accepts it. The legacy
// synthetic "...AAAAtestkey" marker no longer parses and is skipped.
func trustKey14692() string {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	pub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		panic(err)
	}
	return strings.Fields(string(ssh.MarshalAuthorizedKey(pub)))[1]
}

// cachedTrustKey14692 memoises one generated blob so want-line assertions
// compare against exactly what newTrustCfg rendered.
var cachedTrustKey14692 = trustKey14692()

func newTrustCfg() *config.Config {
	cfg := &config.Config{}
	cfg.Security.SSHKnownHosts = map[string][]config.SSHKnownHostKey{
		"192.168.0.253": {{Type: "ssh-ed25519-key", Key: cachedTrustKey14692}},
	}
	return cfg
}

// TestApplySSHKnownHostsClearRemovesManagedFile is the #5112 guard: once the
// operator clears security ssh-known-hosts, the xpf-owned file must be removed
// so a revoked host key does not stay trusted for outbound SSH. This is the
// test that goes RED when the production removal path is reverted.
func TestApplySSHKnownHostsClearRemovesManagedFile(t *testing.T) {
	path := withTempSSHKnownHostsPath(t)
	d := &Daemon{}

	// Seed a managed file by applying non-empty desired state.
	d.applySSHKnownHosts(newTrustCfg())
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("expected managed file written, read err: %v", err)
	}
	if !strings.HasPrefix(string(data), sshKnownHostsHeader) {
		t.Fatalf("managed file missing header: %q", string(data))
	}

	// Clear desired state → managed file must be removed.
	d.applySSHKnownHosts(&config.Config{})
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("managed ssh_known_hosts not removed on empty desired state (stat err=%v)", err)
	}
}

// TestApplySSHKnownHostsClearLeavesForeignFile verifies the ownership guard: a
// file WITHOUT the xpf managed header (hand-maintained / foreign) must never be
// deleted, even when desired state is empty.
func TestApplySSHKnownHostsClearLeavesForeignFile(t *testing.T) {
	path := withTempSSHKnownHostsPath(t)
	foreign := "10.0.0.1 ssh-ed25519 AAAAhandmaintained\n"
	if err := os.WriteFile(path, []byte(foreign), 0644); err != nil {
		t.Fatalf("seed foreign file: %v", err)
	}

	d := &Daemon{}
	d.applySSHKnownHosts(&config.Config{})

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("foreign ssh_known_hosts must be preserved, read err: %v", err)
	}
	if string(got) != foreign {
		t.Fatalf("foreign file mutated: got %q want %q", string(got), foreign)
	}
}

// TestApplySSHKnownHostsWritesNonEmpty verifies the existing write path is
// preserved: non-empty desired state renders the managed header plus a host
// key line with the Junos→OpenSSH type mapping applied.
func TestApplySSHKnownHostsWritesNonEmpty(t *testing.T) {
	path := withTempSSHKnownHostsPath(t)
	d := &Daemon{}
	d.applySSHKnownHosts(newTrustCfg())

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read written file: %v", err)
	}
	content := string(data)
	if !strings.HasPrefix(content, sshKnownHostsHeader) {
		t.Fatalf("missing managed header: %q", content)
	}
	// ssh-ed25519-key must map to OpenSSH ssh-ed25519.
	wantLine := "192.168.0.253 ssh-ed25519 " + cachedTrustKey14692 + "\n"
	if !strings.Contains(content, wantLine) {
		t.Fatalf("expected host line %q in %q", wantLine, content)
	}
}

// TestApplySSHKnownHostsClearAbsentFileNoError verifies that clearing desired
// state when no file exists is a clean no-op (no panic, no file created).
func TestApplySSHKnownHostsClearAbsentFileNoError(t *testing.T) {
	path := withTempSSHKnownHostsPath(t)
	d := &Daemon{}

	d.applySSHKnownHosts(&config.Config{})

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("no file should exist after clear-on-absent (stat err=%v)", err)
	}
}
