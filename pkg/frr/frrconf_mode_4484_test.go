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
	"strings"
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

// frrServiceReadableForUID reports whether the frr service principal
// (given uid+gid) could read the file at fi through ANY arm: owner-read
// when the file uid matches, group-read when the gid matches with the
// group bit, or other-read. Production frr.conf is root-owned with the
// service as group/other reader; tests use the process uid as owner.
func frrServiceReadableForUID(fi os.FileInfo, uid, gid int) bool {
	perm := fi.Mode().Perm()
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	if int(st.Uid) == uid && perm&0o400 != 0 {
		return true
	}
	if int(st.Gid) == gid && perm&0o040 != 0 {
		return true
	}
	return perm&0o004 != 0
}

// frrServiceReadable is frrServiceReadableForUID with a distinct service
// uid (-1: never the owner), i.e. read must come via group or other.
func frrServiceReadable(fi os.FileInfo, serviceGID int) bool {
	return frrServiceReadableForUID(fi, -1, serviceGID)
}

// foldServiceGID returns a gid usable as the synthetic frr service group
// without root: a supplementary group of the test process that differs
// from its egid (chown to a member group is permitted for non-root).
func foldServiceGID(t *testing.T) int {
	t.Helper()
	groups, err := os.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	for _, gid := range groups {
		if gid != os.Getegid() {
			return gid
		}
	}
	t.Skip("no supplementary group available for non-root service-group fixture")
	return 0
}

// TestFRRConfRootRoot0644MigratesToServiceGroup is the #16046 fold-1 cell:
// a legacy root:root 0644 frr.conf (Debian-stock state; FRR daemons run
// as frr:frr) must NOT be tightened to 0640 root:root. When the frr
// group resolves, the apply migrates the group to the frr gid (uid
// preserved) and lands 0640 uid:frr. Fold-2: when the group cannot be
// resolved the write now FAILS before publication (no floored success
// publishing new secrets world-readable) and the old inode is untouched.
// RED-on-revert: capping without migration lands 0640 with the process
// gid; flooring succeeds at 0644 with new content — both fail here.
func TestFRRConfRootRoot0644MigratesToServiceGroup(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("group migration requires root to chown to the frr gid")
	}
	const frrGID = 4242
	restore := resolveFRRGroup
	t.Cleanup(func() { resolveFRRGroup = restore })

	seedLegacy := func(t *testing.T) (string, string) {
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
		return conf, seed
	}

	// Case 1: frr group resolves → migrate group, tighten to 0640.
	resolveFRRGroup = func() (int, bool) { return frrGID, true }
	conf, _ := seedLegacy(t)
	m := &Manager{frrConf: conf}
	if err := m.writeManagedSection("router bgp 65000\n neighbor 192.0.2.9 password new-secret\n"); err != nil {
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

	// Case 2 (fold-2 claim 2): group unresolvable → error before
	// publication; old inode (content+mode) untouched, new secret absent.
	resolveFRRGroup = func() (int, bool) { return 0, false }
	conf2, seed2 := seedLegacy(t)
	m2 := &Manager{frrConf: conf2}
	if err := m2.writeManagedSection("router bgp 65000\n neighbor 192.0.2.9 password new-secret\n"); err == nil {
		t.Fatalf("writeManagedSection (unresolved group) succeeded; want error before publishing new secrets world-readable (#16046 fold-2)")
	}
	got2, err := os.ReadFile(conf2)
	if err != nil {
		t.Fatalf("read rejected frr.conf: %v", err)
	}
	if string(got2) != seed2 {
		t.Fatalf("rejected write replaced the old inode:\n got %q\nwant seed %q", got2, seed2)
	}
	fi2, _ := os.Stat(conf2)
	if fi2.Mode().Perm() != 0o644 {
		t.Fatalf("rejected write changed mode to %04o, want untouched 0644", fi2.Mode().Perm())
	}
}

// TestFRRWritePlanDecision pins the single-decision table (fold-2 claim
// 4): one planFRRWrite call → one resolver invocation; fresh/at-perm/
// migrate/grant/error rows. RED-on-revert: restoring the two-function
// floor+owner pair fails compilation here (deleted symbols) and, in
// spirit, the unresolved-wide row (was floored success, now error).
func TestFRRWritePlanDecision(t *testing.T) {
	restore := resolveFRRGroup
	t.Cleanup(func() { resolveFRRGroup = restore })
	dir := t.TempDir()
	seed := func(name string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("x\n"), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	calls := 0
	wide := seed("wide.conf", 0o644)
	// Foreign-gid arms (gid 4242) are installable only as root: as root
	// assert the (0,4242) fresh owner and the wide migration owner; as
	// non-root the same resolution must fail closed / omit the owner
	// (annotated installability), asserted in the Wide+foreign row.
	if os.Geteuid() == 0 {
		calls = 0
		resolveFRRGroup = func() (int, bool) { calls++; return 4242, true }
		plan, err := planFRRWrite(filepath.Join(dir, "fresh.conf"), 0o640)
		if err != nil || plan.preserve || plan.writePerm != 0o640 || plan.owner == nil || plan.owner.uid != 0 || plan.owner.gid != 4242 {
			t.Fatalf("fresh+resolved(root) plan = %+v err=%v, want explicit owner (0,4242) perm 0640", plan, err)
		}
		if calls != 1 {
			t.Fatalf("fresh plan made %d resolver calls, want exactly 1", calls)
		}
		plan, err = planFRRWrite(wide, 0o640)
		if err != nil || plan.preserve || plan.writePerm != 0o640 || plan.owner == nil || plan.owner.gid != 4242 || plan.owner.uid != os.Geteuid() {
			t.Fatalf("wide+migrate(root) plan = %+v err=%v, want explicit 0640 owner (uid,4242)", plan, err)
		}
	}
	// Fresh + resolved to own egid (non-root): no owner pin — pinning
	// (0, egid) would force a uid-changing chown; the temp already
	// carries the process (uid, egid). Root pins (0,4242) above.
	if os.Geteuid() != 0 {
		calls = 0
		resolveFRRGroup = func() (int, bool) { calls++; return os.Getegid(), true }
		plan, err := planFRRWrite(filepath.Join(dir, "fresh-egid.conf"), 0o640)
		if err != nil || plan.preserve || plan.writePerm != 0o640 || plan.owner != nil {
			t.Fatalf("fresh+egid(non-root) plan = %+v err=%v, want plain 0640 no owner pin", plan, err)
		}
		if calls != 1 {
			t.Fatalf("fresh-egid plan made %d resolver calls, want exactly 1", calls)
		}
	}
	// Wide + foreign gid as non-root: cannot install → fail closed.
	if os.Geteuid() != 0 {
		resolveFRRGroup = func() (int, bool) { return 4242, true }
		if _, err := planFRRWrite(wide, 0o640); err == nil {
			t.Fatalf("wide+foreign-gid(non-root): want fail-closed error (gid not installable)")
		}
		// Fresh + foreign gid as non-root: plain 0640, no owner (no
		// chown attempted, write can still succeed process-owned).
		plan, err := planFRRWrite(filepath.Join(dir, "fresh-foreign.conf"), 0o640)
		if err != nil || plan.owner != nil || plan.writePerm != 0o640 {
			t.Fatalf("fresh+foreign(non-root) plan = %+v err=%v, want plain 0640 no owner", plan, err)
		}
	}
	// Fresh + unresolved: plain perm, no owner, still exactly 0640.
	resolveFRRGroup = func() (int, bool) { return 0, false }
	plan, err := planFRRWrite(filepath.Join(dir, "fresh2.conf"), 0o640)
	if err != nil || plan.preserve || plan.writePerm != 0o640 || plan.owner != nil {
		t.Fatalf("fresh+unresolved plan = %+v err=%v, want plain 0640 no owner", plan, err)
	}
	// At-perm existing: pure preserve regardless of resolution.
	atPerm := seed("atperm.conf", 0o640)
	plan, err = planFRRWrite(atPerm, 0o640)
	if err != nil || !plan.preserve || plan.owner != nil || plan.writePerm != 0o640 {
		t.Fatalf("at-perm plan = %+v err=%v, want preserve 0640", plan, err)
	}
	// Wide + unresolved: error (no floored success).
	resolveFRRGroup = func() (int, bool) { return 0, false }
	if _, err = planFRRWrite(wide, 0o640); err == nil {
		t.Fatalf("wide+unresolved: want error, got success (floored world-readable publish, fold-2 claim 2)")
	}
	// Wide 0604 + resolved as process egid (already service group):
	// grant group-read → explicit 0640-equivalent plan (0644&0640|0040
	// = 0640 here: 0604&0640=0600, |0040=0640), no owner needed.
	resolveFRRGroup = func() (int, bool) { return os.Getegid(), true }
	otherOnly := seed("otheronly.conf", 0o604)
	plan, err = planFRRWrite(otherOnly, 0o640)
	if err != nil || plan.preserve || plan.owner != nil || plan.writePerm != 0o640 {
		t.Fatalf("0604 service-group plan = %+v err=%v, want explicit granted 0640 no owner", plan, err)
	}
	// Wide + resolved as service gid == file gid (simulate by stubbing
	// to egid on a 0644 file): capped keeps group-read → preserve.
	resolveFRRGroup = func() (int, bool) { return os.Getegid(), true }
	plan, err = planFRRWrite(wide, 0o640)
	if err != nil || !plan.preserve || plan.owner != nil {
		t.Fatalf("wide service-group plan = %+v err=%v, want pure preserve", plan, err)
	}
}

// TestFRRConfOtherReadOnlyKeepsServiceReader is fold-2 claim 3 through
// the real writer: a 0604 file whose service access was other-read only
// must land non-world-readable AND service-readable (group migrated to
// the synthetic service gid + group-read granted: 0604→0640), via
// writeManagedSection. Non-root: the service gid is a supplementary
// group of the test process, so the migration chown is permitted.
// RED-on-revert: cap+migrate without the grant lands 0600 gid=service
// and frrServiceReadable is false.
func TestFRRConfOtherReadOnlyKeepsServiceReader(t *testing.T) {
	gid := foldServiceGID(t)
	dir := t.TempDir()
	conf := filepath.Join(dir, "frr.conf")
	if err := os.WriteFile(conf, []byte("hostname r1\n"), 0o604); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(conf, 0o604); err != nil {
		t.Fatal(err)
	}
	prior, _ := os.Stat(conf)
	if !frrServiceReadable(prior, gid) {
		t.Fatal("bad positive control: 0604 seed not readable via other")
	}
	restore := resolveFRRGroup
	resolveFRRGroup = func() (int, bool) { return gid, true }
	t.Cleanup(func() { resolveFRRGroup = restore })
	m := &Manager{frrConf: conf}
	if err := m.writeManagedSection("router bgp 65000\n neighbor 192.0.2.1 password new-secret\n"); err != nil {
		t.Fatalf("writeManagedSection 0604: %v", err)
	}
	fi, err := os.Stat(conf)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o004 != 0 {
		t.Fatalf("0604 apply left file world-readable: mode %04o", fi.Mode().Perm())
	}
	if fi.Mode().Perm() != 0o640 {
		t.Fatalf("0604 apply mode = %04o, want 0640 (0600 capped + group-read grant on migrated group)", fi.Mode().Perm())
	}
	if !frrServiceReadable(fi, gid) {
		st := fi.Sys().(*syscall.Stat_t)
		t.Fatalf("service lost read after 0604 apply: mode %04o uid=%d gid=%d serviceGID=%d", fi.Mode().Perm(), st.Uid, st.Gid, gid)
	}
}

// TestFRRConfResolverFlipConsistent is fold-2 claim 4 through the real
// writer in both flip directions. The resolver flips on the SECOND
// call; a correct single-resolution write consults it exactly once, so
// the flip is never observed: success-then-failure still migrates
// (0640, service gid, readable, not world-readable) and
// failure-then-success still fails closed (error, old inode untouched).
// RED-on-revert: the old two-lookup pair observes the flip and either
// publishes 0640 without migration or succeeds floored at 0644.
func TestFRRConfResolverFlipConsistent(t *testing.T) {
	gid := foldServiceGID(t)
	restore := resolveFRRGroup
	t.Cleanup(func() { resolveFRRGroup = restore })
	seedWide := func(t *testing.T) (string, string) {
		dir := t.TempDir()
		conf := filepath.Join(dir, "frr.conf")
		seed := "hostname r1\n"
		if err := os.WriteFile(conf, []byte(seed), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(conf, 0o644); err != nil {
			t.Fatal(err)
		}
		return conf, seed
	}
	// success → failure: exactly one (successful) resolution.
	calls := 0
	resolveFRRGroup = func() (int, bool) {
		calls++
		if calls == 1 {
			return gid, true
		}
		return 0, false
	}
	conf, _ := seedWide(t)
	m := &Manager{frrConf: conf}
	if err := m.writeManagedSection("router bgp 65000\n"); err != nil {
		t.Fatalf("flip success-first write: %v", err)
	}
	if calls != 1 {
		t.Fatalf("write consulted resolver %d times, want exactly 1 (single resolution, fold-2 claim 4)", calls)
	}
	fi, _ := os.Stat(conf)
	if fi.Mode().Perm()&0o007 != 0 || !frrServiceReadable(fi, gid) {
		st := fi.Sys().(*syscall.Stat_t)
		t.Fatalf("flip success-first published mode %04o uid=%d gid=%d (serviceGID %d): want non-world-readable + service-readable", fi.Mode().Perm(), st.Uid, st.Gid, gid)
	}
	// failure → success: exactly one (failed) resolution → fail closed.
	calls = 0
	resolveFRRGroup = func() (int, bool) {
		calls++
		if calls == 1 {
			return 0, false
		}
		return gid, true
	}
	conf2, seed2 := seedWide(t)
	m2 := &Manager{frrConf: conf2}
	if err := m2.writeManagedSection("router bgp 65000\n neighbor 192.0.2.1 password new-secret\n"); err == nil {
		t.Fatalf("flip failure-first write succeeded; want fail-closed error (old inode must stay)")
	}
	if calls != 1 {
		t.Fatalf("rejected write consulted resolver %d times, want exactly 1", calls)
	}
	got, _ := os.ReadFile(conf2)
	if string(got) != seed2 {
		t.Fatalf("rejected flip write replaced old inode: %q", got)
	}
}

// TestStripManagedSectionMode16046 covers the zeroize caller (fold-2
// claim 5): a marker-bearing 0644 file strips to a capped,
// service-readable inode when resolved, FAILS (file untouched, secrets
// not republished insecurely — strip is rejected, old file retained for
// a later retry) when unresolved, and a marker-less file is never
// rewritten at all.
func TestStripManagedSectionMode16046(t *testing.T) {
	gid := foldServiceGID(t)
	restore := resolveFRRGroup
	t.Cleanup(func() { resolveFRRGroup = restore })
	marked := "hostname r1\n" + markerBegin + "\nrouter bgp 65000\n neighbor 192.0.2.1 password strip-secret\n" + markerEnd + "\n"
	seedMarked := func(t *testing.T) string {
		dir := t.TempDir()
		conf := filepath.Join(dir, "frr.conf")
		if err := os.WriteFile(conf, []byte(marked), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(conf, 0o644); err != nil {
			t.Fatal(err)
		}
		return conf
	}
	// Resolved: strip succeeds, secrets gone, capped + readable.
	resolveFRRGroup = func() (int, bool) { return gid, true }
	conf := seedMarked(t)
	if err := StripManagedSectionFile(conf); err != nil {
		t.Fatalf("strip resolved: %v", err)
	}
	data, _ := os.ReadFile(conf)
	if strings.Contains(string(data), "strip-secret") || strings.Contains(string(data), markerBegin) {
		t.Fatalf("strip left managed secrets/markers: %q", data)
	}
	fi, _ := os.Stat(conf)
	if fi.Mode().Perm()&0o004 != 0 || !frrServiceReadable(fi, gid) {
		t.Fatalf("stripped file mode %04o: want non-world-readable + service-readable", fi.Mode().Perm())
	}
	// Unresolved: strip fails, marked file untouched (retryable).
	resolveFRRGroup = func() (int, bool) { return 0, false }
	conf2 := seedMarked(t)
	if err := StripManagedSectionFile(conf2); err == nil {
		t.Fatalf("strip unresolved succeeded; want fail-closed error")
	}
	data2, _ := os.ReadFile(conf2)
	if string(data2) != marked {
		t.Fatalf("rejected strip rewrote the file: %q", data2)
	}
	// No markers: never rewritten (byte-identical, mode untouched).
	dir := t.TempDir()
	plain := filepath.Join(dir, "frr.conf")
	if err := os.WriteFile(plain, []byte("hostname r1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(plain, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := StripManagedSectionFile(plain); err != nil {
		t.Fatalf("strip marker-less: %v", err)
	}
	data3, _ := os.ReadFile(plain)
	fi3, _ := os.Stat(plain)
	if string(data3) != "hostname r1\n" || fi3.Mode().Perm() != 0o644 {
		t.Fatalf("marker-less file rewritten: %q mode %04o", data3, fi3.Mode().Perm())
	}
}
