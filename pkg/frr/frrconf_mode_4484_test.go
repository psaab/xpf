// frrconf_mode_4484_test.go — #4484 L-6 / #16046: frr.conf must not be written
// world-readable. The xpf-managed section carries routing-authentication
// secrets (BGP TCP-MD5, OSPF/IS-IS/RIP keys), so a fresh frr.conf is written
// 0640 (was 0644) and owned root:<frr-group> so the unprivileged frr daemons
// can still read it, while an existing operator file keeps a stricter-or-equal
// mode+ownership but is capped at 0640 when wider (a legacy 0644 file is
// tightened to 0640, never kept world-readable — #16046).
package frr

import (
	"os"
	"path/filepath"
	"testing"
)

// TestFRRConfFreshWriteMode0640 pins the mode of a freshly created frr.conf to
// 0640. RED-on-revert: restoring 0644 at the writeManagedSection
// atomicWriteFile call site makes this fail.
func TestFRRConfFreshWriteMode0640(t *testing.T) {
	// Force the "frr group absent" path so the write does not attempt a
	// (non-root) fchown to the frr gid — that would fail with EPERM and mask
	// the mode assertion. The 0640 mode is enforced regardless of the owner
	// override, so this still exercises the security-relevant change.
	restore := resolveFRRGroup
	resolveFRRGroup = func() (int, bool) { return 0, false }
	t.Cleanup(func() { resolveFRRGroup = restore })

	dir := t.TempDir()
	conf := filepath.Join(dir, "frr.conf")
	m := &Manager{frrConf: conf}
	if err := m.writeManagedSection("router bgp 65000\n"); err != nil {
		t.Fatalf("writeManagedSection: %v", err)
	}
	fi, err := os.Stat(conf)
	if err != nil {
		t.Fatalf("stat frr.conf: %v", err)
	}
	if got := fi.Mode().Perm(); got != 0o640 {
		t.Fatalf("fresh frr.conf mode = %04o, want 0640 (0644 is world-readable "+
			"and leaks routing-auth secrets, #4484 L-6)", got)
	}
}

// TestFRRConfPreservesOperatorMode confirms an existing operator frr.conf keeps
// its own (stricter) mode across a managed-section write — WithPreserveExisting
// is not overridden by the fresh-create hardening.
func TestFRRConfPreservesOperatorMode(t *testing.T) {
	restore := resolveFRRGroup
	resolveFRRGroup = func() (int, bool) { return 0, false }
	t.Cleanup(func() { resolveFRRGroup = restore })

	dir := t.TempDir()
	conf := filepath.Join(dir, "frr.conf")
	// Operator's pre-existing file at 0600 with no managed markers.
	if err := os.WriteFile(conf, []byte("hostname r1\nlog syslog informational\n"), 0o600); err != nil {
		t.Fatalf("seed operator frr.conf: %v", err)
	}
	m := &Manager{frrConf: conf}
	if err := m.writeManagedSection("router bgp 65000\n"); err != nil {
		t.Fatalf("writeManagedSection: %v", err)
	}
	fi, err := os.Stat(conf)
	if err != nil {
		t.Fatalf("stat frr.conf: %v", err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Fatalf("existing operator frr.conf mode = %04o, want 0600 preserved "+
			"(fresh-create hardening must not restamp an operator file)", got)
	}
}

// TestFRRConfLegacy0644TightenedTo0640 is the decisive #16046 regression:
// seed a pre-existing 0644 frr.conf carrying a routing-auth leaf, run the
// next managed-section apply, and require the file to land at 0640
// (0644 & 0640) — group read kept, world read stripped. RED-on-revert:
// restoring wholesale preserve in fsatomic leaves it 0644 and fails here.
func TestFRRConfLegacy0644TightenedTo0640(t *testing.T) {
	restore := resolveFRRGroup
	resolveFRRGroup = func() (int, bool) { return 0, false }
	t.Cleanup(func() { resolveFRRGroup = restore })

	dir := t.TempDir()
	conf := filepath.Join(dir, "frr.conf")
	seed := "hostname r1\nrouter bgp 65000\n neighbor 192.0.2.1 password route-secret\n"
	if err := os.WriteFile(conf, []byte(seed), 0o644); err != nil {
		t.Fatalf("seed legacy frr.conf: %v", err)
	}
	if err := os.Chmod(conf, 0o644); err != nil {
		t.Fatalf("chmod seed frr.conf: %v", err)
	}
	m := &Manager{frrConf: conf}
	if err := m.writeManagedSection("router bgp 65000\n"); err != nil {
		t.Fatalf("writeManagedSection: %v", err)
	}
	fi, err := os.Stat(conf)
	if err != nil {
		t.Fatalf("stat frr.conf: %v", err)
	}
	if got := fi.Mode().Perm(); got != 0o640 {
		t.Fatalf("legacy 0644 frr.conf mode = %04o after apply, want 0640 "+
			"(world-readable routing-auth secrets must not survive, #16046/#4484)", got)
	}
}

// TestAtomicWriteOwnerOptDecision pins the owner-override decision matrix:
// apply owner ONLY on a fresh create when the frr group resolves; never on an
// existing file (preserve operator ownership); never when the group is absent
// (best-effort, keep 0640 root:root). RED-on-revert: dropping the exists-gate
// makes the existing-file case return ok=true; dropping the group-gate makes
// the absent-group case return ok=true.
func TestAtomicWriteOwnerOptDecision(t *testing.T) {
	dir := t.TempDir()
	fresh := filepath.Join(dir, "does-not-exist.conf")
	existing := filepath.Join(dir, "exists.conf")
	if err := os.WriteFile(existing, []byte("x\n"), 0o640); err != nil {
		t.Fatalf("seed existing: %v", err)
	}

	restore := resolveFRRGroup
	t.Cleanup(func() { resolveFRRGroup = restore })

	// Group resolves.
	resolveFRRGroup = func() (int, bool) { return 4242, true }
	if _, ok := atomicWriteOwnerOpt(fresh); !ok {
		t.Fatalf("fresh + group-resolves: want owner override applied, got none")
	}
	if _, ok := atomicWriteOwnerOpt(existing); ok {
		t.Fatalf("existing file: want NO owner override (preserve operator), got one")
	}

	// Group absent.
	resolveFRRGroup = func() (int, bool) { return 0, false }
	if _, ok := atomicWriteOwnerOpt(fresh); ok {
		t.Fatalf("fresh + group-absent: want NO owner override (best-effort), got one")
	}
}
