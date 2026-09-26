package upgrade

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/configstore"
)

// fakeSystem is an in-memory System for state-machine tests. It records
// the call sequence and lets a test inject failures at any phase.
type fakeSystem struct {
	t *testing.T

	stagedVersion string

	// unitRunning models systemd state.
	unitRunning bool
	// dropinContent is the last drop-in written.
	dropinContent string
	// daemonReloaded counts daemon-reload calls.
	daemonReloaded int

	// free is the value FreeBytes returns.
	free uint64
	// verifyPass controls the verify-dataplane gate result.
	verifyPass bool
	verifyErr  error
	// verifyHook, if set, runs inside VerifyDataplane (used to simulate an
	// operator commit landing mid-VERIFY while the daemon is still live,
	// i.e. after the PREFLIGHT snapshot but before the STOP cut boundary).
	verifyHook func()
	// stopHook, if set, runs at StopUnit entry, while the old daemon is still
	// live. It models the final commit/confirmation race at the cut boundary.
	stopHook func()
	// readerVersion/readerErr model the target binary's pure envelope probe.
	readerVersion int
	readerErr     error
	// healthErr is returned by HelperHealthy (nil = healthy).
	healthErr error
	// healthFailVersions: versions for which health fails (overrides
	// healthErr when matched).
	healthFailVersions map[string]bool
	// healthHook, if set, runs at the start of HelperHealthy (used to
	// simulate the new daemon mutating the live config DB post-start).
	healthHook func()
	// healthProbe, if set, REPLACES the healthErr/healthFailVersions result of
	// HelperHealthy. #5286 wires the REAL HelperHealthProbe here so a cutover
	// integration test drives the production armed+forwarding+target-version
	// gate through a live Run().
	healthProbe func(ver string, deadline time.Duration) error
	// startFailOnce makes the NEXT StartUnit call fail once (to simulate a
	// post-flip start-exec failure that must trigger auto-rollback).
	startFailOnce bool
	// daemonReloadFailOnce makes the NEXT DaemonReload call fail once. Since
	// DaemonReload is flip()'s last substep, this injects a flip failure
	// AFTER STOP — exercising mechanism C's recoverFromFlipFailure (#1964).
	daemonReloadFailOnce bool

	// calls records the ordered call log for assertions.
	calls []string

	// failAt injects an error AFTER the named call (to simulate a crash
	// where the op succeeded but the journal write / next step did not —
	// the test drives idempotent re-runs).
	now time.Time
}

func newFakeSystem(t *testing.T, ver string) *fakeSystem {
	return &fakeSystem{
		t:                  t,
		stagedVersion:      ver,
		unitRunning:        true,
		free:               1 << 40, // 1 TiB
		readerVersion:      configstore.EnvelopeFormatVersion,
		verifyPass:         true,
		healthFailVersions: map[string]bool{},
		now:                time.Unix(1_700_000_000, 0),
	}
}

func (f *fakeSystem) log(s string) { f.calls = append(f.calls, s) }
func (f *fakeSystem) StopUnit(string) error {
	f.log("stop")
	if f.stopHook != nil {
		hook := f.stopHook
		f.stopHook = nil
		hook()
	}
	f.unitRunning = false
	return nil
}
func (f *fakeSystem) StartUnit(string) error {
	f.log("start")
	// startFailVersions: fail StartUnit while the target is the named
	// version (cleared once the unit is back on a non-failing version).
	if f.startFailOnce {
		f.startFailOnce = false
		return fmt.Errorf("synthetic start failure")
	}
	f.unitRunning = true
	return nil
}
func (f *fakeSystem) DaemonReload() error {
	f.log("daemon-reload")
	if f.daemonReloadFailOnce {
		f.daemonReloadFailOnce = false
		return fmt.Errorf("synthetic daemon-reload failure")
	}
	f.daemonReloaded++
	return nil
}
func (f *fakeSystem) FreeBytes(string) (uint64, error) {
	return f.free, nil
}
func (f *fakeSystem) WriteUnitDropin(_, _, content string) error {
	f.log("dropin")
	f.dropinContent = content
	return nil
}
func (f *fakeSystem) VerifyDataplane(string, []string) (bool, error) {
	f.log("verify")
	if f.verifyHook != nil {
		f.verifyHook()
	}
	return f.verifyPass, f.verifyErr
}
func (f *fakeSystem) BinaryVersion(string) (string, error) { return f.stagedVersion, nil }
func (f *fakeSystem) EnvelopeReaderVersion(string) (int, error) {
	if f.readerErr != nil {
		return 0, f.readerErr
	}
	return f.readerVersion, nil
}
func (f *fakeSystem) HelperHealthy(ver string, deadline time.Duration) error {
	f.log("health:" + ver)
	if f.healthHook != nil {
		f.healthHook()
	}
	if f.healthProbe != nil {
		return f.healthProbe(ver, deadline)
	}
	if f.healthFailVersions[ver] {
		return fmt.Errorf("health fail for %s", ver)
	}
	return f.healthErr
}
func (f *fakeSystem) Now() time.Time { return f.now }

// testEnv builds a populated staged tree + config DB, PUBLISHES a staged
// generation (mirroring the production postinst publish -> cut flow, #1981
// Option B — the cut reads staged-gen/<genid>/, not live staged/), and returns
// a Runner wired to the fake system.
func testEnv(t *testing.T, fs *fakeSystem) (*Runner, Config) {
	t.Helper()
	root := t.TempDir()
	staged := filepath.Join(root, "staged")
	for _, b := range managedBins {
		writeFakeBin(t, filepath.Join(staged, b), "binary-"+b+"-"+fs.stagedVersion)
	}
	cfgdb := filepath.Join(root, "etc", ".configdb")
	mkfile(t, filepath.Join(cfgdb, "active.json"), "#xpf-config-envelope v=1\n{}")

	cfg := Config{
		StagedDir:    staged,
		VersionsDir:  filepath.Join(root, "versions"),
		StagedGenDir: filepath.Join(root, "staged-gen"),
		SbinDir:      filepath.Join(root, "sbin"),
		ConfigDBDir:  cfgdb,
		JournalPath:  filepath.Join(root, "versions", "upgrade.state"),
		Unit:         "xpfd",
		// #5284: point the cluster-identity marker at a hermetic tempdir path
		// that does NOT exist, so every test defaults to STANDALONE (no
		// dependency on the build host's real /etc/xpf/node-id). A clustered
		// test writes a file at cfg.NodeIDPath to flip the node to a member;
		// the runner stats it at Run() time, so a post-testEnv write is seen.
		NodeIDPath:          filepath.Join(root, "etc", "node-id"),
		StartHealthDeadline: time.Second,
		Sys:                 fs,
		Logf:                func(format string, a ...any) { t.Logf("LOG "+format, a...) },
	}
	r, err := NewRunner(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Publish the initial generation so a fresh cut has a source (production
	// does this in the postinst before the cut).
	publishStagedGen(t, r)
	return r, cfg
}

// publishStagedGen publishes a generation from the runner's current StagedDir,
// returning the genid (mirrors the production postinst publish step).
func publishStagedGen(t *testing.T, r *Runner) string {
	t.Helper()
	genid, err := r.stagedGenConfig().Publish()
	if err != nil {
		t.Fatalf("publish staged generation: %v", err)
	}
	return genid
}

// fakeBinContent builds the bytes a fake managed binary carries: a minimal but
// genuinely PARSEABLE 64-bit little-endian ELF header (so it clears the #6409
// content gate in validateRestorableVersion, which parses restorable-rollback
// lockstep binaries as ELF images) followed by the caller's identifier tail (so
// each fake binary stays byte-distinct per name/version and copy-fidelity
// assertions still discriminate). The header declares no program/section
// headers, which debug/elf.Open accepts; the trailing identifier is ignored by
// the header parse. The machine matches the running architecture so the fake
// reads as a genuine native binary, though the #6409 gate parses the header
// without checking the machine.
func fakeBinContent(content string) []byte {
	var machine elf.Machine
	switch runtime.GOARCH {
	case "arm64":
		machine = elf.EM_AARCH64
	default:
		machine = elf.EM_X86_64
	}
	var b bytes.Buffer
	b.Write([]byte{0x7f, 'E', 'L', 'F'}) // ELFMAG
	b.WriteByte(byte(elf.ELFCLASS64))    // 64-bit
	b.WriteByte(byte(elf.ELFDATA2LSB))   // little-endian
	b.WriteByte(byte(elf.EV_CURRENT))    // ELF version
	b.WriteByte(byte(elf.ELFOSABI_NONE)) // ABI
	b.Write(make([]byte, 8))             // ABI version + padding -> 16-byte e_ident
	le := binary.LittleEndian
	w16 := func(v uint16) { var t [2]byte; le.PutUint16(t[:], v); b.Write(t[:]) }
	w32 := func(v uint32) { var t [4]byte; le.PutUint32(t[:], v); b.Write(t[:]) }
	w64 := func(v uint64) { var t [8]byte; le.PutUint64(t[:], v); b.Write(t[:]) }
	w16(uint16(elf.ET_EXEC))    // e_type
	w16(uint16(machine))        // e_machine
	w32(uint32(elf.EV_CURRENT)) // e_version
	w64(0)                      // e_entry
	w64(0)                      // e_phoff
	w64(0)                      // e_shoff
	w32(0)                      // e_flags
	w16(64)                     // e_ehsize
	w16(0)                      // e_phentsize
	w16(0)                      // e_phnum
	w16(0)                      // e_shentsize
	w16(0)                      // e_shnum
	w16(0)                      // e_shstrndx
	b.WriteString(content)
	return b.Bytes()
}

// writeFakeBin writes a regular, executable fake managed binary. Its content is
// a parseable ELF image (fakeBinContent) so it is a valid restorable-rollback
// target under the #6409 content gate; the identifier tail keeps it byte-
// distinct so copy-fidelity assertions compare against fakeBinContent(content).
func writeFakeBin(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, fakeBinContent(content), 0755); err != nil {
		t.Fatal(err)
	}
	// WriteFile applies the mode only when CREATING the file; overwriting an
	// existing file preserves its old mode. Force the exec bit so the helper
	// always yields a regular executable binary regardless of any prior file.
	if err := os.Chmod(path, 0755); err != nil {
		t.Fatal(err)
	}
}

func mkfile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestRun_FullFreshCutover(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)

	if err := r.Run(Options{AllowNoRollbackFirstCut: true}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// versions/2.0.0/ exists with all bins.
	for _, b := range managedBins {
		p := filepath.Join(cfg.VersionsDir, "2.0.0", b)
		if _, err := os.Stat(p); err != nil {
			t.Errorf("missing %s: %v", p, err)
		}
	}
	// current -> 2.0.0
	target, err := os.Readlink(filepath.Join(cfg.VersionsDir, "current"))
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(target) != "2.0.0" {
		t.Errorf("current points at %q, want 2.0.0", target)
	}
	// sbin links point through current.
	for _, b := range managedBins {
		l, err := os.Readlink(filepath.Join(cfg.SbinDir, b))
		if err != nil {
			t.Errorf("sbin link %s: %v", b, err)
			continue
		}
		if !strings.Contains(l, "current") {
			t.Errorf("sbin %s -> %q, want via current", b, l)
		}
	}
	// drop-in pins the CONCRETE version path (not the symlink).
	if !strings.Contains(fs.dropinContent, filepath.Join(cfg.VersionsDir, "2.0.0", "xpfd")) {
		t.Errorf("drop-in does not pin concrete version path:\n%s", fs.dropinContent)
	}
	// STOP happened before FLIP (dropin/daemon-reload) before START.
	assertOrder(t, fs.calls, "stop", "dropin")
	assertOrder(t, fs.calls, "dropin", "start")
	assertOrder(t, fs.calls, "verify", "stop")
	stamp, present := r.readCommittedStamp("2.0.0")
	if !present || stamp == nil || !stamp.Committed || stamp.Version != "2.0.0" || stamp.Predecessor != "" {
		t.Errorf("committed version record = (%+v,present=%v), want committed 2.0.0 with empty first-cut predecessor", stamp, present)
	}
	if stamp != nil && stamp.CommittedAtUnixNano <= 0 {
		t.Errorf("committed version record has invalid commit time %d", stamp.CommittedAtUnixNano)
	}
	// Journal cleared on success.
	if _, err := os.Stat(cfg.JournalPath); !os.IsNotExist(err) {
		t.Errorf("journal not cleared after commit")
	}
}

func TestRun_VerifyRejectLeavesLiveUntouched(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	fs.verifyPass = false
	r, cfg := testEnv(t, fs)
	// Post-#1964: an upgrade runs against a seeded host (current exists), so
	// the cut reaches VERIFY rather than the no-rollback-target INIT refuse.
	seedInitialCurrent(t, r, cfg, "1.0.0")

	err := r.Run(Options{})
	if err == nil {
		t.Fatal("expected verify reject error")
	}
	if !strings.Contains(err.Error(), "REJECT") {
		t.Errorf("error not a REJECT: %v", err)
	}
	// No stop, no flip, no start.
	for _, c := range fs.calls {
		if c == "stop" || c == "start" || c == "dropin" {
			t.Errorf("live mutation %q happened on a verify REJECT", c)
		}
	}
	// current must still point at the prior version (never flipped to 2.0.0).
	target, _ := os.Readlink(filepath.Join(cfg.VersionsDir, "current"))
	if filepath.Base(target) != "1.0.0" {
		t.Errorf("current moved off 1.0.0 despite verify reject: %q", target)
	}
}

func TestRun_DiskFullAbortsPreMutation(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	fs.free = 1 // 1 byte: nowhere near enough
	r, cfg := testEnv(t, fs)
	// Post-#1964: seeded host (current exists) so the cut reaches PREFLIGHT
	// rather than the no-rollback-target INIT refuse.
	seedInitialCurrent(t, r, cfg, "1.0.0")

	err := r.Run(Options{})
	if err == nil {
		t.Fatal("expected disk-full abort")
	}
	if !strings.Contains(err.Error(), "insufficient space") {
		t.Errorf("error not a disk-full abort: %v", err)
	}
	for _, c := range fs.calls {
		if c == "stop" || c == "start" || c == "dropin" || c == "verify" || c == "copy" {
			t.Errorf("phase %q ran despite disk-full preflight abort", c)
		}
	}
}

func TestRun_AutoRollbackOnUnhealthyStart(t *testing.T) {
	// First cut to 1.0.0 (establishes a previous version).
	fs := newFakeSystem(t, "1.0.0")
	r, cfg := testEnv(t, fs)
	if err := r.Run(Options{AllowNoRollbackFirstCut: true}); err != nil {
		t.Fatalf("first cut: %v", err)
	}

	// Now stage 2.0.0 but make it unhealthy -> must auto-rollback to 1.0.0.
	fs.stagedVersion = "2.0.0"
	writeFakeBin(t, filepath.Join(cfg.StagedDir, "xpfd"), "binary-xpfd-2.0.0")
	for _, b := range managedBins[1:] {
		writeFakeBin(t, filepath.Join(cfg.StagedDir, b), "binary-"+b+"-2.0.0")
	}
	fs.healthFailVersions["2.0.0"] = true

	err := r.Run(Options{})
	if err == nil {
		t.Fatal("expected unhealthy-start error with rollback")
	}
	if !strings.Contains(err.Error(), "rolled back to 1.0.0") {
		t.Errorf("error does not report rollback: %v", err)
	}
	// current must be back at 1.0.0.
	target, _ := os.Readlink(filepath.Join(cfg.VersionsDir, "current"))
	if filepath.Base(target) != "1.0.0" {
		t.Errorf("after rollback current=%q want 1.0.0", target)
	}
	// drop-in must pin 1.0.0 again.
	if !strings.Contains(fs.dropinContent, filepath.Join(cfg.VersionsDir, "1.0.0", "xpfd")) {
		t.Errorf("drop-in not re-pinned to 1.0.0 after rollback:\n%s", fs.dropinContent)
	}
}

// TestRun_RollbackClearsJournalNoResurrectFailedTarget proves Codex r1
// Critical#1 is fixed: after an auto-rollback, a re-run of Run does NOT
// resume the FAILED target and mark it committed. The previous version
// must remain live.
func TestRun_RollbackClearsJournalNoResurrectFailedTarget(t *testing.T) {
	fs := newFakeSystem(t, "1.0.0")
	r, cfg := testEnv(t, fs)
	if err := r.Run(Options{AllowNoRollbackFirstCut: true}); err != nil {
		t.Fatalf("first cut: %v", err)
	}

	// Stage 2.0.0, unhealthy -> auto-rollback to 1.0.0.
	fs.stagedVersion = "2.0.0"
	for _, b := range managedBins {
		writeFakeBin(t, filepath.Join(cfg.StagedDir, b), "binary-"+b+"-2.0.0")
	}
	fs.healthFailVersions["2.0.0"] = true
	_ = r.Run(Options{}) // rolls back to 1.0.0

	if _, err := os.Stat(cfg.JournalPath); !os.IsNotExist(err) {
		t.Fatalf("journal not cleared after rollback — a re-run could resurrect the failed target")
	}

	// A re-run: 2.0.0 is still staged and now "healthy" (operator fixed
	// it). The re-run must do a FRESH cut from 1.0.0 -> 2.0.0, NOT resume
	// the stale FLIPPED journal of the failed attempt.
	delete(fs.healthFailVersions, "2.0.0")
	if err := r.Run(Options{}); err != nil {
		t.Fatalf("re-run after rollback: %v", err)
	}
	target, _ := os.Readlink(filepath.Join(cfg.VersionsDir, "current"))
	if filepath.Base(target) != "2.0.0" {
		t.Errorf("re-run did not cleanly cut to 2.0.0: current=%q", target)
	}
}

// TestRun_StartUnitFailureTriggersRollback proves a post-flip StartUnit
// exec failure (not just an unhealthy helper) triggers auto-rollback to
// the previous version (AGY r3 Medium) — the binary is already flipped-in,
// so a failed start would otherwise leave the daemon offline.
func TestRun_StartUnitFailureTriggersRollback(t *testing.T) {
	fs := newFakeSystem(t, "1.0.0")
	r, cfg := testEnv(t, fs)
	if err := r.Run(Options{AllowNoRollbackFirstCut: true}); err != nil {
		t.Fatalf("first cut: %v", err)
	}
	// Stage 2.0.0; make its post-flip StartUnit fail once.
	fs.stagedVersion = "2.0.0"
	for _, b := range managedBins {
		writeFakeBin(t, filepath.Join(cfg.StagedDir, b), "binary-"+b+"-2.0.0")
	}
	fs.startFailOnce = true

	err := r.Run(Options{})
	if err == nil || !strings.Contains(err.Error(), "rolled back to 1.0.0") {
		t.Fatalf("expected start-failure rollback to 1.0.0, got %v", err)
	}
	target, _ := os.Readlink(filepath.Join(cfg.VersionsDir, "current"))
	if filepath.Base(target) != "1.0.0" {
		t.Errorf("after start-failure rollback current=%q want 1.0.0", target)
	}
}

// TestGC_SweepsOrphanDBSnapshot proves an orphan .<ver>.dbsnap (left by a
// PREFLIGHT abort before the version dir exists) is swept by gc (AGY r2).
func TestGC_SweepsOrphanDBSnapshot(t *testing.T) {
	fs := newFakeSystem(t, "1.0.0")
	r, cfg := testEnv(t, fs)
	if err := r.Run(Options{AllowNoRollbackFirstCut: true}); err != nil {
		t.Fatalf("first cut: %v", err)
	}
	// Plant an orphan dbsnap for a version with no version dir.
	orphan := filepath.Join(cfg.VersionsDir, ".9.9.9.dbsnap")
	mkfile(t, filepath.Join(orphan, "active.json"), "x")

	j := &Journal{TargetVersion: "1.0.0"}
	if err := r.gc(j); err != nil {
		t.Fatalf("gc: %v", err)
	}
	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Errorf("orphan dbsnap not swept by gc")
	}
}

// TestRollback_ResumeMidRollback proves a crash mid-rollback (journal at
// ROLLINGBACK) resumes the rollback to PreviousVersion, not the failed
// forward cut.
func TestRollback_ResumeMidRollback(t *testing.T) {
	fs := newFakeSystem(t, "1.0.0")
	r, cfg := testEnv(t, fs)
	if err := r.Run(Options{AllowNoRollbackFirstCut: true}); err != nil {
		t.Fatalf("first cut: %v", err)
	}
	// Stage + copy + flip 2.0.0 so the on-disk state matches a cut that
	// then crashed during rollback (journal=ROLLINGBACK, target=2.0.0,
	// prev=1.0.0).
	fs.stagedVersion = "2.0.0"
	for _, b := range managedBins {
		writeFakeBin(t, filepath.Join(cfg.StagedDir, b), "binary-"+b+"-2.0.0")
	}
	j := &Journal{
		State:           StateRollingBack,
		TargetVersion:   "2.0.0",
		PreviousVersion: "1.0.0",
	}
	must(t, r.copyStaged(j))  // create versions/2.0.0
	must(t, r.flip("2.0.0"))  // current -> 2.0.0 (the failed cut)
	must(t, r.saveJournal(j)) // journal = ROLLINGBACK

	if err := r.Run(Options{}); err != nil {
		t.Fatalf("resume rollback: %v", err)
	}
	target, _ := os.Readlink(filepath.Join(cfg.VersionsDir, "current"))
	if filepath.Base(target) != "1.0.0" {
		t.Errorf("resumed rollback did not land on 1.0.0: current=%q", target)
	}
	if _, err := os.Stat(cfg.JournalPath); !os.IsNotExist(err) {
		t.Errorf("journal not cleared after resumed rollback")
	}
}

// TestRun_RollbackRestoresDBBeforeReflip proves the binary+DB-atomic
// rollback restores the pre-upgrade config-DB snapshot (so an old binary
// never boots against a too-new envelope DB and fatal-rejects it). It
// mutates the live DB to simulate the N+1 daemon writing a new-format
// active.json, then asserts rollback restores the PRE-upgrade content.
func TestRun_RollbackRestoresDBBeforeReflip(t *testing.T) {
	fs := newFakeSystem(t, "1.0.0")
	r, cfg := testEnv(t, fs)
	if err := r.Run(Options{AllowNoRollbackFirstCut: true}); err != nil {
		t.Fatalf("first cut: %v", err)
	}

	// Record the pre-upgrade DB content (what PREFLIGHT will snapshot).
	dbFile := filepath.Join(cfg.ConfigDBDir, "active.json")
	preContent := "#xpf-config-envelope v=1\n{}"
	mkfile(t, dbFile, preContent)

	// Stage 2.0.0, unhealthy. The cut's PREFLIGHT snapshots preContent.
	fs.stagedVersion = "2.0.0"
	writeFakeBin(t, filepath.Join(cfg.StagedDir, "xpfd"), "binary-xpfd-2.0.0")
	for _, b := range managedBins[1:] {
		writeFakeBin(t, filepath.Join(cfg.StagedDir, b), "binary-"+b+"-2.0.0")
	}
	fs.healthFailVersions["2.0.0"] = true

	// Hook: corrupt the live DB to a too-new format AFTER the snapshot is
	// taken but before rollback. We approximate the N+1 daemon's write by
	// overwriting the live DB right after Run starts; simplest is to make
	// StartUnit (called post-flip, before the failing health check) mutate
	// the DB. We can't inject into the fake easily, so overwrite here is
	// done via a custom health probe that writes the new-format DB then
	// fails.
	newFormatContent := "#xpf-config-envelope v=1 min-reader=99\n{}"
	fs.healthHook = func() {
		mkfile(t, dbFile, newFormatContent)
	}

	_ = r.Run(Options{})

	// After rollback, the DB must be restored to the PRE-upgrade content,
	// not the too-new N+1 content.
	got, err := os.ReadFile(dbFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != preContent {
		t.Errorf("DB not restored to pre-upgrade content after rollback.\n got=%q\nwant=%q", got, preContent)
	}
}

func TestRun_CrashResumeIdempotent(t *testing.T) {
	// Drive the full flow once to get a reference final state.
	fsRef := newFakeSystem(t, "3.0.0")
	rRef, cfgRef := testEnv(t, fsRef)
	if err := rRef.Run(Options{AllowNoRollbackFirstCut: true}); err != nil {
		t.Fatalf("reference run: %v", err)
	}
	refTarget, _ := os.Readlink(filepath.Join(cfgRef.VersionsDir, "current"))

	// Now simulate a crash AFTER each journaled state by truncating the
	// journal to that state and re-running; assert idempotent completion.
	for _, crashAfter := range []State{StateStaged, StatePreflight, StateCopied, StateVerified, StateStopped, StateFlipped} {
		t.Run(string(crashAfter), func(t *testing.T) {
			fs := newFakeSystem(t, "3.0.0")
			r, cfg := testEnv(t, fs)

			// Run a partial flow by intercepting: we can't easily stop
			// mid-Run, so instead we craft a journal at crashAfter and the
			// matching on-disk side effects, then re-run.
			seedCrashState(t, r, cfg, fs, crashAfter)

			if err := r.Run(Options{AllowNoRollbackFirstCut: true}); err != nil {
				t.Fatalf("resume from %s: %v", crashAfter, err)
			}
			target, _ := os.Readlink(filepath.Join(cfg.VersionsDir, "current"))
			if filepath.Base(target) != "3.0.0" {
				t.Errorf("resume from %s: current=%q want 3.0.0", crashAfter, target)
			}
			if filepath.Base(refTarget) != "3.0.0" {
				t.Fatalf("reference target unexpected: %q", refTarget)
			}
			// No orphan partials.
			ents, _ := os.ReadDir(cfg.VersionsDir)
			for _, e := range ents {
				if strings.HasSuffix(e.Name(), partialSuffix) {
					t.Errorf("orphan partial after resume from %s: %s", crashAfter, e.Name())
				}
			}
		})
	}
}

// seedCrashState performs the phases up to and including crashAfter, then
// leaves the journal at that state (simulating a crash before the NEXT
// phase). It reuses the Runner's own phase methods so the on-disk state is
// authentic.
func seedCrashState(t *testing.T, r *Runner, cfg Config, fs *fakeSystem, crashAfter State) {
	t.Helper()
	j := &Journal{State: StateInit, TargetVersion: fs.stagedVersion}
	prev, _ := r.readCurrentVersion()
	j.PreviousVersion = prev
	j.StartedAtUnixNano = fs.Now().UnixNano()
	must(t, r.transition(j, StateStaged))
	if crashAfter.atLeast(StatePreflight) {
		must(t, r.preflight(j))
		must(t, r.transition(j, StatePreflight))
	}
	if crashAfter.atLeast(StateCopied) {
		must(t, r.copyStaged(j))
		must(t, r.transition(j, StateCopied))
	}
	if crashAfter.atLeast(StateVerified) {
		must(t, r.verify(j))
		must(t, r.transition(j, StateVerified))
	}
	if crashAfter.atLeast(StateStopped) {
		must(t, fs.StopUnit(cfg.Unit))
		must(t, r.transition(j, StateStopped))
	}
	if crashAfter.atLeast(StateFlipped) {
		must(t, r.flip(j.TargetVersion))
		must(t, r.transition(j, StateFlipped))
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func assertOrder(t *testing.T, calls []string, before, after string) {
	t.Helper()
	bi, ai := -1, -1
	for i, c := range calls {
		if c == before && bi == -1 {
			bi = i
		}
		if c == after {
			ai = i
		}
	}
	if bi == -1 {
		t.Errorf("call %q never happened (calls=%v)", before, calls)
		return
	}
	if ai == -1 {
		t.Errorf("call %q never happened (calls=%v)", after, calls)
		return
	}
	if bi >= ai {
		t.Errorf("%q (idx %d) did not happen before %q (idx %d); calls=%v", before, bi, after, ai, calls)
	}
}

// TestCopyTree_NestedDirsDurable exercises the copyTree directory-fsync path
// (AGY review-011 Part I): a NESTED source tree must copy completely, with
// every file and intermediate directory present and contents intact, and the
// content checksum must be deterministic. The .configdb/staged trees are flat
// today, so this is the only coverage of the nested branch (the new
// createdDirs fsync loop). A bug in that loop — e.g. erroring on a nested dir
// — fails here rather than silently shipping.
func TestCopyTree_NestedDirsDurable(t *testing.T) {
	src := t.TempDir()
	files := map[string]string{
		"top.txt":        "root file",
		"a/d.txt":        "mid file",
		"a/b/c.txt":      "deep file",
		"a/b/e/leaf.txt": "leaf file",
	}
	for rel, content := range files {
		full := filepath.Join(src, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatalf("mkdir src %s: %v", full, err)
		}
		if err := os.WriteFile(full, []byte(content), 0644); err != nil {
			t.Fatalf("write src %s: %v", full, err)
		}
	}

	dst := filepath.Join(t.TempDir(), "copy1")
	sum1, err := copyTree(src, dst)
	if err != nil {
		t.Fatalf("copyTree nested tree: %v", err)
	}
	if sum1 == "" {
		t.Fatal("copyTree returned empty checksum")
	}

	// Every file (and thus every intermediate dir) must be present + intact.
	for rel, want := range files {
		got, rerr := os.ReadFile(filepath.Join(dst, rel))
		if rerr != nil {
			t.Fatalf("nested entry %s not copied: %v", rel, rerr)
		}
		if string(got) != want {
			t.Errorf("nested entry %s = %q, want %q", rel, got, want)
		}
	}

	// Checksum is deterministic for the same source tree.
	dst2 := filepath.Join(t.TempDir(), "copy2")
	sum2, err := copyTree(src, dst2)
	if err != nil {
		t.Fatalf("copyTree second pass: %v", err)
	}
	if sum1 != sum2 {
		t.Errorf("copyTree checksum non-deterministic: %s != %s", sum1, sum2)
	}
}

// TestCopyTree_FsyncsEachDirDeepestFirst proves copyTree actually fsyncs every
// copied directory, deepest-first (Codex/Copilot r1: the durability test must
// fail if the fsync loop is removed). It substitutes the copyTreeSyncDir hook
// with a recorder and asserts every nested dir is synced and that depth is
// non-increasing across the recorded order.
func TestCopyTree_FsyncsEachDirDeepestFirst(t *testing.T) {
	src := t.TempDir()
	for _, rel := range []string{"top.txt", "a/d.txt", "a/b/c.txt", "a/b/e/leaf.txt"} {
		full := filepath.Join(src, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatalf("mkdir src: %v", err)
		}
		if err := os.WriteFile(full, []byte("x"), 0644); err != nil {
			t.Fatalf("write src: %v", err)
		}
	}

	var synced []string
	orig := copyTreeSyncDir
	copyTreeSyncDir = func(d string) error { synced = append(synced, d); return nil }
	defer func() { copyTreeSyncDir = orig }()

	dst := filepath.Join(t.TempDir(), "copy")
	if _, err := copyTree(src, dst); err != nil {
		t.Fatalf("copyTree: %v", err)
	}

	// Every created directory must have been fsynced (root + a + a/b + a/b/e).
	wantDirs := []string{dst, filepath.Join(dst, "a"), filepath.Join(dst, "a/b"), filepath.Join(dst, "a/b/e")}
	syncedSet := map[string]bool{}
	for _, d := range synced {
		syncedSet[d] = true
	}
	for _, d := range wantDirs {
		if !syncedSet[d] {
			t.Errorf("copied dir %s was not fsynced (synced=%v)", d, synced)
		}
	}
	if len(synced) == 0 {
		t.Fatal("copyTree fsynced no directories — the durability loop did not run")
	}

	// Depth (path-separator count) must be non-increasing across the order.
	prevDepth := strings.Count(synced[0], string(os.PathSeparator))
	for _, d := range synced[1:] {
		depth := strings.Count(d, string(os.PathSeparator))
		if depth > prevDepth {
			t.Errorf("fsync order not deepest-first: %s (depth %d) followed a shallower dir (depth %d): %v",
				d, depth, prevDepth, synced)
		}
		prevDepth = depth
	}
}

// TestCopyTree_FsyncDirErrorPropagates proves a directory-fsync failure aborts
// copyTree (so a non-durable copy never silently becomes a rollback target).
func TestCopyTree_FsyncDirErrorPropagates(t *testing.T) {
	src := t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, "a/b"), 0755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	if err := os.WriteFile(filepath.Join(src, "a/b/c.txt"), []byte("x"), 0644); err != nil {
		t.Fatalf("write src: %v", err)
	}

	orig := copyTreeSyncDir
	copyTreeSyncDir = func(d string) error { return fmt.Errorf("injected fsync failure") }
	defer func() { copyTreeSyncDir = orig }()

	dst := filepath.Join(t.TempDir(), "copy")
	if _, err := copyTree(src, dst); err == nil {
		t.Fatal("copyTree returned nil despite a directory-fsync failure")
	}
}
