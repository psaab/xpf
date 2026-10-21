package dhcpserver

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/psaab/xpf/pkg/fsatomic"
)

// probeOptions determines the owner a list of fsatomic options installs
// by applying them to a probe file and reading back its ownership.
// WithOwner to a foreign gid fails unprivileged, so callers only probe
// when running as root; writeKeaConfig's own decision guarantees the
// owner is installable, so a probe failure here is a test bug.
func probeOptions(t *testing.T, dir string, opts []fsatomic.Option) (uid, gid int) {
	t.Helper()
	probe := filepath.Join(dir, ".owner-probe")
	if err := fsatomic.WriteFileAtomic(probe, []byte("probe"), 0o640, opts...); err != nil {
		t.Fatalf("probe write with caller options: %v", err)
	}
	fi, err := os.Stat(probe)
	if err != nil {
		t.Fatalf("stat probe: %v", err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("probe stat has no Stat_t")
	}
	_ = os.Remove(probe)
	return int(st.Uid), int(st.Gid)
}

// TestWriteKeaConfig_FreshAndPreExisting0644 pins the #16062 decisive
// regression: a fresh render and a re-render over a pre-existing 0644
// file both land 0640 (never world-readable), so a non-root account
// outside the Kea group cannot read the reservation inventory. Pre-fix
// (0644) both assertions fail.
//
// The test injects the Kea group as the process egid so the WithOwner
// fchown is installable unprivileged and fsatomic SKIPS it (temp inode
// already carries that owner) — the on-disk gid is then genuinely the
// "Kea group" of this test's world, and group-readability is real.
func TestWriteKeaConfig_FreshAndPreExisting0644(t *testing.T) {
	egid := os.Getegid()
	euid := os.Geteuid()

	dir := t.TempDir()
	conf := filepath.Join(dir, "kea", "kea-dhcp4.conf")

	m := New()
	m.SetKeaOwnerLookupForTesting(func() (int, int, bool) { return euid, egid, true })

	cfg := map[string]any{"Dhcp4": map[string]any{"valid-lifetime": 86400}}

	// Fresh render.
	if _, err := m.writeKeaConfig(conf, cfg); err != nil {
		t.Fatalf("fresh writeKeaConfig: %v", err)
	}
	assertKeaConfigLockedDown(t, conf, egid)

	// Pre-existing world-readable file (the pre-fix on-disk state) must
	// be tightened by the next render, not preserved.
	if err := os.WriteFile(conf, []byte(`{"Dhcp4":{"legacy":true}}`), 0o644); err != nil {
		t.Fatalf("seed legacy 0644: %v", err)
	}
	// WriteFile over an existing inode keeps its mode; force the legacy
	// world-readable state explicitly.
	if err := os.Chmod(conf, 0o644); err != nil {
		t.Fatalf("chmod legacy seed: %v", err)
	}
	if fi, _ := os.Stat(conf); fi.Mode().Perm() != 0o644 {
		t.Fatalf("seed mode = %04o, want 0644", fi.Mode().Perm())
	}
	if _, err := m.writeKeaConfig(conf, cfg); err != nil {
		t.Fatalf("re-render writeKeaConfig: %v", err)
	}
	assertKeaConfigLockedDown(t, conf, egid)

	// Content survived the tightening render.
	data, err := os.ReadFile(conf)
	if err != nil {
		t.Fatalf("read rendered config: %v", err)
	}
	if !strings.Contains(string(data), "valid-lifetime") {
		t.Fatalf("rendered config lost content after tightening: %s", data)
	}
}

func assertKeaConfigLockedDown(t *testing.T, path string, wantGID int) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := fi.Mode().Perm(); got != 0o640 {
		t.Fatalf("%s mode = %04o, want 0640 (#16062: reservation inventory must not be world-readable)", path, got)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("%s stat has no Stat_t", path)
	}
	if int(st.Gid) != wantGID {
		t.Fatalf("%s gid = %d, want Kea group %d", path, st.Gid, wantGID)
	}
	// Owner-read + group-read, no other-read: a non-owner, non-group
	// local account (the decisive #16062 check) gets EACCES. Asserted
	// via the mode bits — the test process owns the file, so an actual
	// cross-uid read cannot be performed unprivileged.
	if fi.Mode().Perm()&0o004 != 0 {
		t.Fatalf("%s is world-readable (mode %04o)", path, fi.Mode().Perm())
	}
}

// TestWriteKeaConfig_RequestsKeaGroup asserts the REQUESTED owner on the
// production write path: with a resolved Kea user (fake uid/gid), a fresh
// render must request WithOwner(0, kea-gid) at 0640 — root:_kea. The
// recorder performs the write without the foreign fchown so it runs
// unprivileged; fsatomic's WithOwner-before-rename is pinned by
// fsatomic's own tests. RED-on-revert: restoring the plain 0644 write
// makes perm=0644 with no owner option here.
func TestWriteKeaConfig_RequestsKeaGroup(t *testing.T) {
	const wantGID = 14243

	prev := writeKeaConfigFile
	var gotPerm os.FileMode
	var gotOpts []fsatomic.Option
	writeKeaConfigFile = func(path string, data []byte, perm os.FileMode, opts ...fsatomic.Option) error {
		gotPerm = perm
		gotOpts = append([]fsatomic.Option(nil), opts...)
		// Install without the (foreign-gid) fchown: mode only.
		return fsatomic.WriteFileAtomic(path, data, perm)
	}
	defer func() { writeKeaConfigFile = prev }()

	dir := t.TempDir()
	conf := filepath.Join(dir, "kea-dhcp4.conf")
	m := New()
	// Fake Kea user. As a non-root process the foreign gid is not
	// installable, so writeKeaConfig must NOT request it (that would
	// EPERM the apply); the root-only request is asserted below when
	// privileged. Unprivileged, the contract is: plain 0640.
	m.SetKeaOwnerLookupForTesting(func() (int, int, bool) { return 14242, wantGID, true })

	if _, err := m.writeKeaConfig(conf, map[string]any{"Dhcp4": map[string]any{}}); err != nil {
		t.Fatalf("writeKeaConfig: %v", err)
	}
	if gotPerm != 0o640 {
		t.Fatalf("requested perm = %04o, want 0640", gotPerm)
	}
	fi, err := os.Stat(conf)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != 0o640 {
		t.Fatalf("on-disk mode = %04o, want 0640", fi.Mode().Perm())
	}

	if os.Geteuid() != 0 {
		if len(gotOpts) != 0 {
			t.Fatalf("non-root with foreign Kea gid requested %d owner options, want 0 (un-installable pin would EPERM)", len(gotOpts))
		}
		return
	}
	// Root: exactly one option, and probing it installs (0, wantGID).
	if len(gotOpts) != 1 {
		t.Fatalf("root render requested %d options, want exactly 1 (WithOwner)", len(gotOpts))
	}
	uid, gid := probeOptions(t, dir, gotOpts)
	if uid != 0 || gid != wantGID {
		t.Fatalf("requested owner = %d:%d, want 0:%d (root:_kea)", uid, gid, wantGID)
	}
}

// TestWriteKeaConfig_NoKeaUser_StillLockedDown: with no _kea/kea user
// resolvable (dev host), the render still lands 0640 — never the old
// world-readable 0644 — and does not fail.
func TestWriteKeaConfig_NoKeaUser_StillLockedDown(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "kea-dhcp6.conf")
	m := New()
	m.SetKeaOwnerLookupForTesting(func() (int, int, bool) { return 0, 0, false })

	if _, err := m.writeKeaConfig(conf, map[string]any{"Dhcp6": map[string]any{}}); err != nil {
		t.Fatalf("writeKeaConfig without Kea user: %v", err)
	}
	fi, err := os.Stat(conf)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode without Kea user = %04o, want 0640", fi.Mode().Perm())
	}
}

// TestWriteKeaConfig_PreservesKeaOwnedFile: an existing file already
// owned by the Kea uid at a mode within 0640 keeps its ownership (pure
// preserve) — writeKeaConfig must not revert an operator's _kea uid to
// root. RED-on-revert to an unconditional WithOwner(0, gid): the uid
// assertion fails.
func TestWriteKeaConfig_PreservesKeaOwnedFile(t *testing.T) {
	euid, egid := os.Geteuid(), os.Getegid()

	dir := t.TempDir()
	conf := filepath.Join(dir, "kea-dhcp4.conf")
	if err := os.WriteFile(conf, []byte("{}"), 0o640); err != nil {
		t.Fatalf("seed: %v", err)
	}

	m := New()
	// The test process IS the "Kea user" in this world: existing file
	// uid == kea uid, gid == kea gid, mode within perm.
	m.SetKeaOwnerLookupForTesting(func() (int, int, bool) { return euid, egid, true })

	if _, err := m.writeKeaConfig(conf, map[string]any{"Dhcp4": map[string]any{}}); err != nil {
		t.Fatalf("writeKeaConfig: %v", err)
	}
	fi, err := os.Stat(conf)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	if int(st.Uid) != euid || int(st.Gid) != egid {
		t.Fatalf("owner after render = %d:%d, want preserved %d:%d", st.Uid, st.Gid, euid, egid)
	}
	if fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode after render = %04o, want 0640", fi.Mode().Perm())
	}
}
