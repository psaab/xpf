package daemon

// sshd_dropin_dir_seam_7609_test.go — #7609.
//
// sshdConfPath is a package var for one reason: so a test can point the
// xpf-managed sshd drop-in at a throwaway tree instead of writing to the real
// /etc/ssh/sshd_config.d. applySSHConfig then created its directory from a
// HARD-CODED literal, so relocating the var produced a file path whose parent
// did not exist and the write failed with ENOENT.
//
// The failure mode is worse than an inconvenient fixture. The write error
// surfaces as whatever the test was actually asserting, so a cell checking only
// "an error was returned" passes for the wrong reason — it observes the
// fixture's own broken seam rather than the condition it injected. That is how
// the #6790 credential cells first went green-then-red: their healthy control
// caught it, but only because it asserted nil rather than "some error".

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// sshCfg7609 is the smallest config that makes applySSHConfig WRITE rather
// than take its remove-or-no-op branches: one recognised ssh leaf, so
// buildSSHDConfig returns a non-empty body.
func sshCfg7609() *config.Config {
	cfg := &config.Config{}
	cfg.System.Services = &config.SystemServicesConfig{
		SSH: &config.SSHServiceConfig{RootLogin: "deny"},
	}
	return cfg
}

// stubSSHDCmds7609 makes the validate/reload seams succeed so the only thing
// that can fail is the filesystem work under test.
func stubSSHDCmds7609(t *testing.T) {
	t.Helper()
	origV, origR := sshdValidateCmd, sshdReloadCmd
	sshdValidateCmd = func() ([]byte, error) { return nil, nil }
	sshdReloadCmd = func() ([]byte, error) { return nil, nil }
	t.Cleanup(func() { sshdValidateCmd, sshdReloadCmd = origV, origR })
}

// TestRelocatingSSHDConfPathRelocatesItsDirectory7609 is the property: ONE var
// moves the whole drop-in.
//
// The parent is deliberately NOT pre-created — creating it is exactly the
// workaround this change removes, and a fixture that creates it cannot observe
// the defect.
//
// FAIL-ON-REVERT: restore the hard-coded "/etc/ssh/sshd_config.d" and the
// relocated write fails with ENOENT, so the drop-in is absent and this reds.
func TestRelocatingSSHDConfPathRelocatesItsDirectory7609(t *testing.T) {
	stubSSHDCmds7609(t)
	orig := sshdConfPath
	// Nested, so the derivation has to create more than a single component —
	// a fix that only ever worked for an existing grandparent still fails.
	sshdConfPath = filepath.Join(t.TempDir(), "etc", "ssh", "sshd_config.d", "xpf.conf")
	t.Cleanup(func() { sshdConfPath = orig })

	d := &Daemon{}
	if err := d.applySSHConfig(sshCfg7609()); err != nil {
		t.Fatalf("applySSHConfig returned %v — with sshdConfPath relocated and its "+
			"parent NOT pre-created, the drop-in directory must be derived from "+
			"the same var (#7609)", err)
	}

	got, err := os.ReadFile(sshdConfPath)
	if err != nil {
		t.Fatalf("the relocated drop-in was not written: %v", err)
	}
	if !strings.Contains(string(got), "PermitRootLogin no") {
		t.Fatalf("the drop-in does not carry the configured setting:\n%s", got)
	}
}

// TestProductionDropInDirIsUnchanged7609 is the PAIRED control, and it is the
// one that keeps this from being a behaviour change.
//
// The whole justification is "byte-identical in production": filepath.Dir of
// the production path IS the literal it replaced. Without this cell, the
// derivation could be wrong in production and every relocated test would still
// pass, because no test uses the production path.
func TestProductionDropInDirIsUnchanged7609(t *testing.T) {
	const wantPath = "/etc/ssh/sshd_config.d/00-xpf.conf"
	const wantDir = "/etc/ssh/sshd_config.d"
	if sshdConfPath != wantPath {
		t.Fatalf("sshdConfPath = %q, want %q — the production location is part of "+
			"the operator contract, not an implementation detail", sshdConfPath, wantPath)
	}
	if got := filepath.Dir(sshdConfPath); got != wantDir {
		t.Fatalf("filepath.Dir(sshdConfPath) = %q, want %q — the derivation must "+
			"reproduce the literal it replaced, or #7609 silently moved where a "+
			"real box writes its sshd drop-in", got, wantDir)
	}
}

// TestDropInDirectoryFailureIsStillReported7609 pins that deriving the path did
// not swallow the error the mkdir already reported.
//
// The pre-existing comment at that site says the mkdir error is surfaced
// because it is "the real cause (e.g. a read-only /etc)" and the write's error
// would be opaque. That reasoning is unchanged by #7609 and is worth holding:
// a derivation that quietly dropped the error would leave an operator with only
// the downstream write failure.
//
// Induced with a parent that is a FILE, so MkdirAll fails with ENOTDIR — a
// refusal no privilege level can bypass, so the cell behaves the same for a
// root and a non-root runner.
func TestDropInDirectoryFailureIsStillReported7609(t *testing.T) {
	stubSSHDCmds7609(t)
	root := t.TempDir()
	blocked := filepath.Join(root, "blocked")
	if err := os.WriteFile(blocked, []byte("not a directory\n"), 0o644); err != nil {
		t.Fatalf("seed the blocking file: %v", err)
	}
	orig := sshdConfPath
	sshdConfPath = filepath.Join(blocked, "sshd_config.d", "xpf.conf")
	t.Cleanup(func() { sshdConfPath = orig })

	d := &Daemon{}
	err := d.applySSHConfig(sshCfg7609())
	if err == nil {
		t.Fatal("applySSHConfig returned nil although the drop-in directory could " +
			"not be created — the commit reports success over an sshd posture that " +
			"was never written (#6790 joins this error into the commit result)")
	}
	if !strings.Contains(err.Error(), "create sshd config drop-in directory") {
		t.Fatalf("the error does not name the directory failure, so an operator sees "+
			"only the opaque downstream write error: %v", err)
	}
}
