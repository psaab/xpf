package upgrade

import (
	"errors"
	"fmt"
	"github.com/psaab/xpf/pkg/configstore"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// rollbackFixture models a node mid-life: versions/<cur>/ is live
// (current -> cur), versions/<prev>/ is the retained rollback target, and
// .<cur>.dbsnap/active.json is the PREFLIGHT snapshot of the live DB.
type rollbackFixture struct {
	r          *Runner
	cfg        Config
	fs         *fakeSystem
	cur        string
	snapActive string
	liveActive string
}

func setupRollback(t *testing.T, cur, prev, snapHeader string) *rollbackFixture {
	t.Helper()
	fs := newFakeSystem(t, cur)
	// The fake target binary reads the CURRENT envelope grammar unless a
	// test overrides readerVersion (skew) or readerErr (unprovable target).
	fs.readerVersion = configstore.EnvelopeFormatVersion
	r, cfg := testEnv(t, fs)
	writeCompleteVersionDir(t, cfg, cur)
	writeCompleteVersionDir(t, cfg, prev)
	if err := os.Symlink(cur, currentLinkPath(cfg)); err != nil {
		t.Fatal(err)
	}
	snapActive := filepath.Join(cfg.VersionsDir, "."+cur+".dbsnap", "active.json")
	mkfile(t, snapActive, snapHeader+"{\"rolled\":true}")
	liveActive := filepath.Join(cfg.ConfigDBDir, "active.json")
	mkfile(t, liveActive, snapHeader+"{\"live\":true}")
	return &rollbackFixture{r: r, cfg: cfg, fs: fs, cur: cur,
		snapActive: snapActive, liveActive: liveActive}
}

const rollbackV1Snap = "#xpf-config-envelope v=1 writer=1.0.0 ast=1 min-reader=1 rollback-fmt=1 committed=1\n"

var errFakeReaderProbe = errors.New("synthetic capability-check failure")

func rollbackCalls(fs *fakeSystem) []string { return append([]string(nil), fs.calls...) }

func assertNoDestructiveCalls(t *testing.T, fs *fakeSystem) {
	t.Helper()
	for _, c := range fs.calls {
		if c == "stop" || c == "dropin" || c == "verify" || c == "start" || c == "daemon-reload" {
			t.Errorf("destructive/live-mutation call %q ran on a pre-STOP refusal (calls=%v)", c, fs.calls)
		}
	}
}

func currentTarget(t *testing.T, cfg Config) string {
	t.Helper()
	raw, err := os.Readlink(currentLinkPath(cfg))
	if err != nil {
		t.Fatalf("read current: %v", err)
	}
	return raw
}

// TestRollbackTo_AdjacentHappyPath is the Cell-1 unit pin: an
// envelope-consistent rollback restores the PREFLIGHT snapshot, re-flips
// current/sbin/unit to the (default-resolved) previous version, health-gates
// the target, and clears the journal.
func TestRollbackTo_AdjacentHappyPath(t *testing.T) {
	fx := setupRollback(t, "2.0.0", "1.0.0", rollbackV1Snap)
	if err := fx.r.RollbackTo("", RollbackOptions{}); err != nil {
		t.Fatalf("RollbackTo: %v", err)
	}
	if got := currentTarget(t, fx.cfg); got != "1.0.0" {
		t.Errorf("current -> %q, want 1.0.0", got)
	}
	// Live DB now carries the byte-correct PREFLIGHT snapshot.
	snap, _ := os.ReadFile(fx.snapActive)
	live, _ := os.ReadFile(fx.liveActive)
	if string(live) != string(snap) {
		t.Errorf("live DB %q != snapshot %q", live, snap)
	}
	old, err := os.ReadFile(filepath.Join(fx.cfg.ConfigDBDir+".old", "active.json"))
	if err != nil {
		t.Fatalf("pre-rollback live DB was not retained at .old: %v", err)
	}
	if string(old) != rollbackV1Snap+`{"live":true}` {
		t.Errorf("retained .old DB = %q, want original live DB", old)
	}
	// Drop-in pins the CONCRETE target path (flip.go 6c), not the symlink.
	if !strings.Contains(fx.fs.dropinContent, filepath.Join(fx.cfg.VersionsDir, "1.0.0", "xpfd")) {
		t.Errorf("drop-in does not pin concrete 1.0.0 xpfd: %q", fx.fs.dropinContent)
	}
	// Ordering: stop -> ... -> start, then the target health gate.
	calls := rollbackCalls(fx.fs)
	ord := map[string]int{}
	for i, c := range calls {
		if _, ok := ord[c]; !ok {
			ord[c] = i
		}
	}
	for _, want := range []string{"stop", "dropin", "daemon-reload", "start", "health:1.0.0"} {
		if _, ok := ord[want]; !ok {
			t.Fatalf("missing call %q in %v", want, calls)
		}
	}
	if !(ord["stop"] < ord["dropin"] && ord["dropin"] < ord["daemon-reload"] && ord["daemon-reload"] < ord["start"] && ord["start"] < ord["health:1.0.0"]) {
		t.Errorf("call order wrong: %v", calls)
	}
	if _, err := os.Stat(fx.cfg.JournalPath); !os.IsNotExist(err) {
		t.Errorf("journal not cleared on terminal rollback success (err=%v)", err)
	}
}

// TestRollbackTo_SkewRefusesPreStop is the Cell-2 unit pin: a snapshot whose
// envelope major exceeds the target reader refuses BEFORE the first STOP
// with ZERO live-mutation calls and every no-destruction assert.
func TestRollbackTo_SkewRefusesPreStop(t *testing.T) {
	skew := "#xpf-config-envelope v=99 writer=9.9.9 ast=1 min-reader=99 rollback-fmt=1 committed=1\n"
	fx := setupRollback(t, "2.0.0", "1.0.0", skew)
	beforeLive, _ := os.ReadFile(fx.liveActive)
	err := fx.r.RollbackTo("", RollbackOptions{})
	if err == nil {
		t.Fatal("RollbackTo with v99/min-reader-99 snapshot vs v2-reader target succeeded; want envelope-skew refusal")
	}
	msg := err.Error()
	for _, want := range []string{"2.0.0", "1.0.0", "99", "roll"} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal %q missing %q (want current+target versions, skew majors, roll-forward guidance)", msg, want)
		}
	}
	assertNoDestructiveCalls(t, fx.fs)
	if got := currentTarget(t, fx.cfg); got != "2.0.0" {
		t.Errorf("current moved to %q on a pre-STOP refusal", got)
	}
	afterLive, _ := os.ReadFile(fx.liveActive)
	if string(afterLive) != string(beforeLive) {
		t.Error("live active.json changed on a pre-STOP refusal")
	}
	if _, err := os.Stat(fx.cfg.ConfigDBDir + ".old"); !os.IsNotExist(err) {
		t.Errorf(".configdb.old created on a pre-STOP refusal (err=%v)", err)
	}
	if _, err := os.Stat(fx.cfg.JournalPath); !os.IsNotExist(err) {
		t.Errorf("journal written on a pre-STOP refusal (err=%v)", err)
	}
}

func TestRollbackTo_ExplicitTargetHonored(t *testing.T) {
	fx := setupRollback(t, "2.0.0", "1.0.0", rollbackV1Snap)
	writeCompleteVersionDir(t, fx.cfg, "0.9.0")
	if err := fx.r.RollbackTo("0.9.0", RollbackOptions{}); err != nil {
		t.Fatalf("RollbackTo(0.9.0): %v", err)
	}
	if got := currentTarget(t, fx.cfg); got != "0.9.0" {
		t.Errorf("current -> %q, want 0.9.0", got)
	}
}

func stampCommittedForTest(t *testing.T, fx *rollbackFixture, ver, predecessor string, committedAt int64) {
	t.Helper()
	if err := fx.r.writeCommitStamp(committedStamp{
		Version:             ver,
		Predecessor:         predecessor,
		Committed:           true,
		CommittedAtUnixNano: committedAt,
	}); err != nil {
		t.Fatalf("write commit record for %s: %v", ver, err)
	}
}

func TestRollbackTo_DefaultIgnoresTouchedOldCommittedVersion(t *testing.T) {
	fx := setupRollback(t, "3.0.0", "1.0.0", rollbackV1Snap)
	writeCompleteVersionDir(t, fx.cfg, "2.0.0")
	stampCommittedForTest(t, fx, "3.0.0", "2.0.0", 300)
	stampCommittedForTest(t, fx, "2.0.0", "1.0.0", 200)
	stampCommittedForTest(t, fx, "1.0.0", "", 100)
	// The ancient version has the newest directory mtime, but the current
	// version's persisted predecessor is the genuine intermediate rollback.
	touched := time.Now().Add(time.Hour)
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(filepath.Join(fx.cfg.VersionsDir, "1.0.0"), touched, touched); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(filepath.Join(fx.cfg.VersionsDir, "2.0.0"), old, old); err != nil {
		t.Fatal(err)
	}
	if err := fx.r.RollbackTo("", RollbackOptions{}); err != nil {
		t.Fatalf("RollbackTo: %v", err)
	}
	if got := currentTarget(t, fx.cfg); got != "2.0.0" {
		t.Errorf("default target -> %q, want committed predecessor 2.0.0 despite touched-old mtime", got)
	}
}

func TestRollbackTo_DefaultExcludesActuallyFailedCutVersion(t *testing.T) {
	fs := newFakeSystem(t, "4.0.0")
	r, cfg := testEnv(t, fs)
	writeCompleteVersionDir(t, cfg, "0.9.0")
	seedInitialCurrent(t, r, cfg, "1.0.0")
	fx := &rollbackFixture{r: r, cfg: cfg, fs: fs}
	stampCommittedForTest(t, fx, "1.0.0", "0.9.0", 100)
	mkfile(t, filepath.Join(cfg.VersionsDir, ".1.0.0.dbsnap", "active.json"), rollbackV1Snap+"{}")

	// A real forward cut fails on START and auto-rolls back to 1.0.0. Its
	// complete version dir remains present with a durable non-committed stamp.
	fs.startFailOnce = true
	if err := r.Run(Options{}); err == nil {
		t.Fatal("Run succeeded despite synthetic failed start; want auto-rollback")
	}
	if got := currentTarget(t, cfg); got != "1.0.0" {
		t.Fatalf("current after auto-rollback -> %q, want 1.0.0", got)
	}
	if stamp, present := r.readCommittedStamp("4.0.0"); !present || stamp == nil || stamp.Committed {
		t.Fatalf("failed target commit record = (%+v,present=%v), want explicit non-committed", stamp, present)
	}

	// Bare operator rollback must resolve current's committed predecessor,
	// never the just-failed but still-restorable 4.0.0 directory.
	if err := r.RollbackTo("", RollbackOptions{}); err != nil {
		t.Fatalf("RollbackTo: %v", err)
	}
	if got := currentTarget(t, cfg); got != "0.9.0" {
		t.Errorf("default target -> %q, want committed predecessor 0.9.0 (not failed 4.0.0)", got)
	}
}

func TestGC_RanksCommittedVersionsBeforeDirectoryMtime(t *testing.T) {
	fs := newFakeSystem(t, "5.0.0")
	r, cfg := testEnv(t, fs)
	fx := &rollbackFixture{r: r, cfg: cfg}
	for i := 1; i <= 5; i++ {
		ver := fmt.Sprintf("%d.0.0", i)
		writeCompleteVersionDir(t, cfg, ver)
		predecessor := ""
		if i > 1 {
			predecessor = fmt.Sprintf("%d.0.0", i-1)
		}
		stampCommittedForTest(t, fx, ver, predecessor, int64(i*100))
	}
	if err := os.Symlink("5.0.0", currentLinkPath(cfg)); err != nil {
		t.Fatal(err)
	}
	// A copy/touch makes the oldest build's mtime newest. GC must still retain
	// the committed intermediate (3.0.0) inside the N=3 history window.
	touched := time.Now().Add(time.Hour)
	if err := os.Chtimes(filepath.Join(cfg.VersionsDir, "1.0.0"), touched, touched); err != nil {
		t.Fatal(err)
	}
	if err := r.gc(&Journal{TargetVersion: "5.0.0", PreviousVersion: "4.0.0"}); err != nil {
		t.Fatalf("gc: %v", err)
	}
	for _, ver := range []string{"3.0.0", "4.0.0", "5.0.0"} {
		if _, err := os.Stat(filepath.Join(cfg.VersionsDir, ver)); err != nil {
			t.Errorf("committed version %s was not retained: %v", ver, err)
		}
	}
	for _, ver := range []string{"1.0.0", "2.0.0"} {
		if _, err := os.Stat(filepath.Join(cfg.VersionsDir, ver)); !os.IsNotExist(err) {
			t.Errorf("old version %s survived committed-history GC (stat err=%v)", ver, err)
		}
	}
}
func TestRollbackTo_TargetEqualsCurrentRefuses(t *testing.T) {
	fx := setupRollback(t, "2.0.0", "1.0.0", rollbackV1Snap)
	if err := fx.r.RollbackTo("2.0.0", RollbackOptions{}); err == nil {
		t.Fatal("RollbackTo(live version) succeeded; want refusal")
	}
	assertNoDestructiveCalls(t, fx.fs)
}

func TestRollbackTo_MissingSnapshotRefusesPreStop(t *testing.T) {
	fx := setupRollback(t, "2.0.0", "1.0.0", rollbackV1Snap)
	if err := os.RemoveAll(filepath.Join(fx.cfg.VersionsDir, ".2.0.0.dbsnap")); err != nil {
		t.Fatal(err)
	}
	if err := fx.r.RollbackTo("", RollbackOptions{}); err == nil {
		t.Fatal("RollbackTo without a PREFLIGHT snapshot succeeded; want refusal")
	}
	assertNoDestructiveCalls(t, fx.fs)
	if got := currentTarget(t, fx.cfg); got != "2.0.0" {
		t.Errorf("current moved to %q on a pre-STOP refusal", got)
	}
}

func TestRollbackTo_TornCurrentRefusesWithReseedGuidance(t *testing.T) {
	fx := setupRollback(t, "2.0.0", "1.0.0", rollbackV1Snap)
	if err := os.RemoveAll(filepath.Join(fx.cfg.VersionsDir, "2.0.0")); err != nil {
		t.Fatal(err)
	}
	err := fx.r.RollbackTo("", RollbackOptions{})
	if err == nil {
		t.Fatal("RollbackTo with dangling current succeeded; want torn-layout refusal")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "re-seed") {
		t.Errorf("torn-layout refusal %q missing re-seed guidance", err)
	}
	assertNoDestructiveCalls(t, fx.fs)
}

func TestRollbackTo_ClusteredStandaloneRefuses(t *testing.T) {
	fx := setupRollback(t, "2.0.0", "1.0.0", rollbackV1Snap)
	mkfile(t, fx.cfg.NodeIDPath, "node-0")
	err := fx.r.RollbackTo("", RollbackOptions{})
	if err == nil {
		t.Fatal("standalone RollbackTo on a cluster member succeeded; want #5284-style refusal")
	}
	if !strings.Contains(err.Error(), "--rolling") {
		t.Errorf("clustered refusal %q missing --rolling guidance", err)
	}
	assertNoDestructiveCalls(t, fx.fs)
	// The coordinated (rolling-driver) path is sanctioned on a member.
	if err := fx.r.RollbackTo("", RollbackOptions{ClusterCoordinated: true, LockAlreadyHeld: true, SkipHealthCheck: true}); err != nil {
		t.Fatalf("coordinated RollbackTo on a member: %v", err)
	}
	if got := currentTarget(t, fx.cfg); got != "1.0.0" {
		t.Errorf("current -> %q, want 1.0.0", got)
	}
}

func TestRollbackTo_UnprovableTargetReaderRefusesPreStop(t *testing.T) {
	fx := setupRollback(t, "2.0.0", "1.0.0", rollbackV1Snap)
	fx.fs.readerErr = errFakeReaderProbe
	if err := fx.r.RollbackTo("", RollbackOptions{}); err == nil {
		t.Fatal("RollbackTo with an unprovable target reader succeeded; want fail-closed refusal")
	}
	assertNoDestructiveCalls(t, fx.fs)
	if got := currentTarget(t, fx.cfg); got != "2.0.0" {
		t.Errorf("current moved to %q on a pre-STOP refusal", got)
	}
}

func TestRollbackTo_ForwardJournalInFlightRefuses(t *testing.T) {
	fx := setupRollback(t, "2.0.0", "1.0.0", rollbackV1Snap)
	j := &Journal{TargetVersion: "3.0.0", PreviousVersion: "2.0.0", State: StateStopped}
	if err := fx.r.saveJournal(j); err != nil {
		t.Fatal(err)
	}
	err := fx.r.RollbackTo("", RollbackOptions{})
	if err == nil {
		t.Fatal("RollbackTo with a forward cut in flight succeeded; want refusal")
	}
	if !strings.Contains(err.Error(), "3.0.0") {
		t.Errorf("in-flight refusal %q does not name the journaled target", err)
	}
	assertNoDestructiveCalls(t, fx.fs)
	if got := currentTarget(t, fx.cfg); got != "2.0.0" {
		t.Errorf("current moved to %q on a pre-STOP refusal", got)
	}
}

func TestRollbackTo_ResumeAfterCrashCompletesStart(t *testing.T) {
	fx := setupRollback(t, "2.0.0", "1.0.0", rollbackV1Snap)
	// Crash landed after the flip to 1.0.0 but before the start: current
	// already points at the target, the unit is down, the journal records
	// the rollback intent.
	if err := os.Remove(currentLinkPath(fx.cfg)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("1.0.0", currentLinkPath(fx.cfg)); err != nil {
		t.Fatal(err)
	}
	fx.fs.unitRunning = false
	snapDir := filepath.Join(fx.cfg.VersionsDir, ".2.0.0.dbsnap")
	j := &Journal{TargetVersion: "2.0.0", PreviousVersion: "1.0.0",
		State: StateRollingBack, DBSnapshotPath: snapDir, AdvancedStateFloor: true,
		OperatorRollback: true}
	if err := fx.r.saveJournal(j); err != nil {
		t.Fatal(err)
	}
	fx.fs.calls = nil
	if err := fx.r.RollbackTo("1.0.0", RollbackOptions{}); err != nil {
		t.Fatalf("resumed RollbackTo: %v", err)
	}
	foundStart, foundHealth := false, false
	for _, c := range fx.fs.calls {
		if c == "start" {
			foundStart = true
		}
		if c == "health:1.0.0" {
			foundHealth = true
		}
	}
	if !foundStart || !foundHealth {
		t.Errorf("resume did not complete start+health (calls=%v)", fx.fs.calls)
	}
	if _, err := os.Stat(fx.cfg.JournalPath); !os.IsNotExist(err) {
		t.Errorf("journal not cleared after resumed rollback completed (err=%v)", err)
	}
}

// TestRollbackTo_ResumeAfterRestoreKeepsOld proves the crash window between
// the retained DB swap and FLIP is idempotent. A journaled retry must not
// rotate the already-restored live DB over the original .old copy.
func TestRollbackTo_ResumeAfterRestoreKeepsOld(t *testing.T) {
	fx := setupRollback(t, "2.0.0", "1.0.0", rollbackV1Snap)
	snapDir := filepath.Join(fx.cfg.VersionsDir, ".2.0.0.dbsnap")
	if err := fx.r.restoreDBSnapshotRetainOld(snapDir); err != nil {
		t.Fatalf("initial retained restore: %v", err)
	}
	j := &Journal{
		TargetVersion:      "2.0.0",
		PreviousVersion:    "1.0.0",
		State:              StateRollingBack,
		DBSnapshotPath:     snapDir,
		AdvancedStateFloor: true,
		OperatorRollback:   true,
		RollbackDBRestored: true,
	}
	if err := fx.r.saveJournal(j); err != nil {
		t.Fatal(err)
	}
	if err := fx.r.RollbackTo("1.0.0", RollbackOptions{}); err != nil {
		t.Fatalf("resumed RollbackTo after DB restore: %v", err)
	}
	old, err := os.ReadFile(filepath.Join(fx.cfg.ConfigDBDir+".old", "active.json"))
	if err != nil {
		t.Fatalf("retained .old missing after resume: %v", err)
	}
	if string(old) != rollbackV1Snap+`{"live":true}` {
		t.Errorf("retained .old changed during resume: %q", old)
	}
}

func TestRunnerResumeOperatorRollbackMissingOldRefusesPreStop(t *testing.T) {
	fx := setupRollback(t, "2.0.0", "1.0.0", rollbackV1Snap)
	j := &Journal{
		TargetVersion:      "2.0.0",
		PreviousVersion:    "1.0.0",
		State:              StateRollingBack,
		DBSnapshotPath:     filepath.Join(fx.cfg.VersionsDir, ".2.0.0.dbsnap"),
		AdvancedStateFloor: true,
		OperatorRollback:   true,
		RollbackDBRestored: true,
	}
	if err := fx.r.saveJournal(j); err != nil {
		t.Fatal(err)
	}
	if err := fx.r.Run(Options{}); err == nil {
		t.Fatal("Runner.Run resumed operator rollback with missing .old; want pre-STOP refusal")
	}
	assertNoDestructiveCalls(t, fx.fs)
	if got := currentTarget(t, fx.cfg); got != "2.0.0" {
		t.Errorf("current moved to %q on missing-.old pre-STOP refusal", got)
	}
}

func TestRollbackTo_UnhealthyTargetSurfacesErrorJournalPreserved(t *testing.T) {
	fx := setupRollback(t, "2.0.0", "1.0.0", rollbackV1Snap)
	fx.fs.healthFailVersions["1.0.0"] = true
	if err := fx.r.RollbackTo("", RollbackOptions{}); err == nil {
		t.Fatal("RollbackTo to an unhealthy target succeeded; want surfaced error")
	}
	// No auto-flip loop: the failure surfaces and the journal preserves the
	// rollback state for the operator.
	j, jerr := fx.r.loadJournal()
	if jerr != nil {
		t.Fatalf("loadJournal: %v", jerr)
	}
	if j.State != StateRollingBack || j.TargetVersion != "2.0.0" || j.PreviousVersion != "1.0.0" {
		t.Errorf("journal = %+v, want ROLLINGBACK from 2.0.0 to 1.0.0 preserved", j)
	}
}

// TestRollingRollback_HappyPath drives the HA per-node rollback through the
// drain/cut/rejoin driver: prechecks + ForceSecondary + strong drain, then
// the rollback cut, then sync re-establish + ResetFailover + per-RG rejoin
// confirm.
func TestRollingRollback_HappyPath(t *testing.T) {
	fx := setupRollback(t, "2.0.0", "1.0.0", rollbackV1Snap)
	cl := &fakeCluster{peerAlive: true, synced: true, compatible: true, peerReady: true}
	if err := runRollingRollbackWith(fx.r, cl, fastRC(), ""); err != nil {
		t.Fatalf("runRollingRollbackWith: %v", err)
	}
	if !cl.forced {
		t.Error("ForceSecondary not called")
	}
	if !cl.resetCalled {
		t.Error("ResetFailover not called")
	}
	if cl.rejoinChecks == 0 {
		t.Error("per-RG rejoin never confirmed")
	}
	if cl.syncWireChecks == 0 {
		t.Error("session-sync wire gate never consulted")
	}
	if got := currentTarget(t, fx.cfg); got != "1.0.0" {
		t.Errorf("current -> %q, want 1.0.0", got)
	}
}

// TestRollingRollback_DrainAbortNoMutation pins the abort-without-cutting
// direction: an unmet drain predicate fails back and leaves current, the DB,
// and the unit untouched.
func TestRollingRollback_DrainAbortNoMutation(t *testing.T) {
	fx := setupRollback(t, "2.0.0", "1.0.0", rollbackV1Snap)
	beforeLive, _ := os.ReadFile(fx.liveActive)
	cl := &fakeCluster{peerAlive: true, synced: true, compatible: true, peerReady: true,
		drainAfter: 1 << 30}
	rc := fastRC()
	rc.DrainDeadline = 20 * time.Millisecond
	if err := runRollingRollbackWith(fx.r, cl, rc, ""); err == nil {
		t.Fatal("rolling rollback with an unmet drain predicate succeeded; want abort")
	}
	if !cl.resetCalled {
		t.Error("failback ResetFailover not called on drain abort")
	}
	assertNoDestructiveCalls(t, fx.fs)
	if got := currentTarget(t, fx.cfg); got != "2.0.0" {
		t.Errorf("current moved to %q on a drain abort", got)
	}
	afterLive, _ := os.ReadFile(fx.liveActive)
	if string(afterLive) != string(beforeLive) {
		t.Error("live DB changed on a drain abort")
	}
}

// TestRollingRollback_SkewRefusesPreDrain pins the policy ordering on the HA
// path: envelope skew refuses before ForceSecondary, so the node never
// demotes for a rollback it cannot take.
func TestRollingRollback_SkewRefusesPreDrain(t *testing.T) {
	skew := "#xpf-config-envelope v=99 writer=9.9.9 ast=1 min-reader=99 rollback-fmt=1 committed=1\n"
	fx := setupRollback(t, "2.0.0", "1.0.0", skew)
	cl := &fakeCluster{peerAlive: true, synced: true, compatible: true, peerReady: true}
	if err := runRollingRollbackWith(fx.r, cl, fastRC(), ""); err == nil {
		t.Fatal("rolling rollback with envelope skew succeeded; want pre-drain refusal")
	}
	if cl.forced {
		t.Error("ForceSecondary ran before the envelope-skew refusal")
	}
	assertNoDestructiveCalls(t, fx.fs)
}
