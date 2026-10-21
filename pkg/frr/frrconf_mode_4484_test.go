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
	"syscall"
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
// (0644 & 0640) — group read kept, world read stripped. The frr group is
// stubbed to the process gid, so the preserved group IS the service
// group and the cap alone is service-readable (no migration needed;
// the root:root migration/floor cells are in
// TestFRRConfRootRoot0644MigratesToServiceGroup). RED-on-revert:
// restoring wholesale preserve in fsatomic leaves it 0644 and fails here.
func TestFRRConfLegacy0644TightenedTo0640(t *testing.T) {
	restore := resolveFRRGroup
	resolveFRRGroup = func() (int, bool) { return os.Getegid(), true }
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

// frrServiceReadable reports whether the frr service account could read
// the file at fi via the group arm: group-read bit set and gid equal to
// the (injected) frr service gid, or other-read. The owner arm is not
// used here — production frr.conf is root-owned, so group/other decides.
func frrServiceReadable(fi os.FileInfo, serviceGID int) bool {
	perm := fi.Mode().Perm()
	if perm&0o004 != 0 {
		return true // world-readable (the pre-fix legacy state)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return int(st.Gid) == serviceGID && perm&0o040 != 0
}

// TestFRRConfRootRoot0644MigratesToServiceGroup is the #16046 fold cell:
// a legacy root:root 0644 frr.conf (the Debian-stock state — this host's
// /etc/frr/frr.conf is root:root 0644, and FRR daemons run as frr:frr)
// must NOT be tightened to 0640 root:root, which the frr group cannot
// read. When the frr group resolves, the apply migrates the group to
// the frr gid (uid preserved) and lands 0640 uid:frr — service-readable,
// not world-readable. When the group cannot be resolved, the mode is
// floored at 0644 (still service-readable via other-read) rather than
// tightened into an unreadable file. RED-on-revert: capping without
// migration lands 0640 with the process gid and fails the gid/readable
// assertions; tightening without the floor fails the absent-group case.
func TestFRRConfRootRoot0644MigratesToServiceGroup(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("group migration requires root to chown to the frr gid")
	}
	const frrGID = 4242
	restore := resolveFRRGroup
	t.Cleanup(func() { resolveFRRGroup = restore })

	seedLegacy := func(t *testing.T) string {
		t.Helper()
		dir := t.TempDir()
		conf := filepath.Join(dir, "frr.conf")
		seed := "hostname r1\nrouter bgp 65000\n neighbor 192.0.2.1 password route-secret\n"
		if err := os.WriteFile(conf, []byte(seed), 0o644); err != nil {
			t.Fatalf("seed legacy frr.conf: %v", err)
		}
		if err := os.Chmod(conf, 0o644); err != nil {
			t.Fatalf("chmod seed: %v", err)
		}
		return conf
	}

	// Case 1: frr group resolves → migrate group, tighten to 0640.
	resolveFRRGroup = func() (int, bool) { return frrGID, true }
	conf := seedLegacy(t)
	m := &Manager{frrConf: conf}
	if err := m.writeManagedSection("router bgp 65000\n"); err != nil {
		t.Fatalf("writeManagedSection (migrate): %v", err)
	}
	fi, err := os.Stat(conf)
	if err != nil {
		t.Fatalf("stat migrated frr.conf: %v", err)
	}
	if got := fi.Mode().Perm(); got != 0o640 {
		t.Fatalf("migrated frr.conf mode = %04o, want 0640", got)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("stat migrated frr.conf: no Stat_t")
	}
	if int(st.Gid) != frrGID {
		t.Fatalf("migrated frr.conf gid = %d, want frr gid %d (0640 root:root would deny the frr reader, #16046 fold)", st.Gid, frrGID)
	}
	if int(st.Uid) != os.Geteuid() {
		t.Fatalf("migrated frr.conf uid = %d, want preserved owner uid %d (only the group migrates)", st.Uid, os.Geteuid())
	}
	if !frrServiceReadable(fi, frrGID) {
		t.Fatalf("migrated frr.conf not readable by frr service group (mode %04o gid %d)", fi.Mode().Perm(), st.Gid)
	}

	// Case 2: frr group unresolvable → floor at 0644, do not tighten
	// into a file the service cannot read.
	resolveFRRGroup = func() (int, bool) { return 0, false }
	conf2 := seedLegacy(t)
	m2 := &Manager{frrConf: conf2}
	if err := m2.writeManagedSection("router bgp 65000\n"); err != nil {
		t.Fatalf("writeManagedSection (floor): %v", err)
	}
	fi2, err := os.Stat(conf2)
	if err != nil {
		t.Fatalf("stat floored frr.conf: %v", err)
	}
	if got := fi2.Mode().Perm(); got != 0o644 {
		t.Fatalf("floored frr.conf mode = %04o, want 0644 kept until the frr group resolves (tightening to 0640 without migration would strand FRR)", got)
	}
	if !frrServiceReadable(fi2, frrGID) {
		t.Fatalf("floored frr.conf must remain service-readable via other-read")
	}
}

// TestAtomicWriteOwnerOptDecision pins the owner-override decision matrix:
// fresh create applies WithOwner(0, frr-gid) only when the frr group
// resolves; an existing file at/below perm gets NO override (preserve
// operator ownership); an existing WIDER file (0644 > 0640) whose group
// is not the frr group gets a group-migration override (preserve uid,
// frr gid) so the #16046 tightening stays service-readable. RED-on-revert:
// dropping the fresh exists-gate makes the existing-file case return
// ok=true; dropping the group-gate makes the absent-group case return
// ok=true; dropping the migration arm makes the wide non-service-group
// case return ok=false.
func TestAtomicWriteOwnerOptDecision(t *testing.T) {
	dir := t.TempDir()
	fresh := filepath.Join(dir, "does-not-exist.conf")
	existing := filepath.Join(dir, "exists.conf")
	if err := os.WriteFile(existing, []byte("x\n"), 0o640); err != nil {
		t.Fatalf("seed existing: %v", err)
	}

	restore := resolveFRRGroup
	t.Cleanup(func() { resolveFRRGroup = restore })

	// Group resolves, file at perm: no override (preserve).
	resolveFRRGroup = func() (int, bool) { return 4242, true }
	if _, ok := atomicWriteOwnerOpt(fresh, 0o640); !ok {
		t.Fatalf("fresh + group-resolves: want owner override applied, got none")
	}
	if _, ok := atomicWriteOwnerOpt(existing, 0o640); ok {
		t.Fatalf("existing file at perm: want NO owner override (preserve operator), got one")
	}
	// Wide existing file (0644) owned by the test process (gid != 4242):
	// tightening would occur, so a group-migration override must apply.
	wide := filepath.Join(dir, "wide.conf")
	if err := os.WriteFile(wide, []byte("x\n"), 0o644); err != nil {
		t.Fatalf("seed wide: %v", err)
	}
	if err := os.Chmod(wide, 0o644); err != nil {
		t.Fatalf("chmod wide: %v", err)
	}
	if _, ok := atomicWriteOwnerOpt(wide, 0o640); !ok {
		t.Fatalf("wide existing + non-service group: want group-migration override, got none")
	}

	// Group absent: no override on fresh, and no migration on wide.
	resolveFRRGroup = func() (int, bool) { return 0, false }
	if _, ok := atomicWriteOwnerOpt(fresh, 0o640); ok {
		t.Fatalf("fresh + group-absent: want NO owner override (best-effort), got one")
	}
	if _, ok := atomicWriteOwnerOpt(wide, 0o640); ok {
		t.Fatalf("wide + group-absent: want NO migration override (floor keeps mode), got one")
	}
}
