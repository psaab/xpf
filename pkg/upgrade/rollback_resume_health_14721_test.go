package upgrade

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// seedAutoRollingBack14721 builds the exact interrupted auto-rollback state
// from #14721: an initial healthy 1.0.0 cut, versions/2.0.0 present as the
// failed target, current flipped to 2.0.0, and a non-operator StateRollingBack
// journal (Target=2.0.0, Previous=1.0.0). The helper-health failure for the
// rollback destination is armed by the caller via fs.healthFailVersions.
func seedAutoRollingBack14721(t *testing.T) (*Runner, Config, *fakeSystem) {
	t.Helper()
	fs := newFakeSystem(t, "1.0.0")
	r, cfg := testEnv(t, fs)
	if err := r.Run(Options{AllowNoRollbackFirstCut: true}); err != nil {
		t.Fatalf("first cut: %v", err)
	}
	// Stage + copy + flip 2.0.0 so on-disk state matches a cut that crashed
	// during its auto-rollback.
	fs.stagedVersion = "2.0.0"
	for _, b := range managedBins {
		writeFakeBin(t, filepath.Join(cfg.StagedDir, b), "binary-"+b+"-2.0.0")
	}
	j := &Journal{
		State:           StateRollingBack,
		TargetVersion:   "2.0.0",
		PreviousVersion: "1.0.0",
	}
	must(t, r.copyStaged(j))
	must(t, r.flip("2.0.0"))
	must(t, r.saveJournal(j))
	fs.calls = nil
	return r, cfg, fs
}

// #14721 arm 1+resume: a resumed auto-rollback whose destination starts but
// whose helper is unhealthy must fail and preserve the journal. Pre-fix,
// Runner.rollback never called HelperHealthy, cleared the journal, and Run
// returned nil.
func TestResumeAutoRollbackUnhealthyHelperPreservesJournal14721(t *testing.T) {
	r, cfg, fs := seedAutoRollingBack14721(t)
	fs.healthFailVersions["1.0.0"] = true

	err := r.Run(Options{})
	if err == nil {
		t.Fatal("resumed auto-rollback with unhealthy helper succeeded; want error")
	}
	if !strings.Contains(err.Error(), "helper health") {
		t.Errorf("error %q does not name helper health", err)
	}
	foundHealth := false
	for _, c := range fs.calls {
		if c == "health:1.0.0" {
			foundHealth = true
		}
	}
	if !foundHealth {
		t.Errorf("HelperHealthy was not consulted for rollback destination (calls=%v)", fs.calls)
	}
	j, jerr := r.loadJournal()
	if jerr != nil {
		t.Fatalf("journal must be preserved after unhealthy resumed rollback: %v", jerr)
	}
	if j.State != StateRollingBack || j.PreviousVersion != "1.0.0" || j.TargetVersion != "2.0.0" {
		t.Errorf("journal = %+v, want ROLLINGBACK 2.0.0 -> 1.0.0 preserved", j)
	}
	if cur, cerr := r.readCurrentVersion(); cerr != nil || cur != "1.0.0" {
		t.Errorf("current = %q err=%v; previous version should have been re-flipped before health check", cur, cerr)
	}
	_ = cfg
}

// Control: with the helper healthy, the resumed auto-rollback completes,
// lands on the previous version, records health:1.0.0, clears the journal,
// and Run reports the rollback outcome (non-nil) rather than cut success.
func TestResumeAutoRollbackHealthyCompletes14721(t *testing.T) {
	r, cfg, fs := seedAutoRollingBack14721(t)

	err := r.Run(Options{})
	if err == nil {
		t.Fatal("resumed auto-rollback returned nil; Run must not report a forward-cut success")
	}
	if !strings.Contains(err.Error(), "rolled back") {
		t.Errorf("error %q should describe the completed rollback", err)
	}
	foundHealth := false
	for _, c := range fs.calls {
		if c == "health:1.0.0" {
			foundHealth = true
		}
	}
	if !foundHealth {
		t.Errorf("healthy resume did not consult HelperHealthy (calls=%v)", fs.calls)
	}
	if _, serr := os.Stat(cfg.JournalPath); !os.IsNotExist(serr) {
		t.Errorf("journal not cleared after healthy resumed rollback (err=%v)", serr)
	}
	if cur, cerr := r.readCurrentVersion(); cerr != nil || cur != "1.0.0" {
		t.Errorf("current = %q err=%v; want 1.0.0", cur, cerr)
	}
	if proof := r.LastCommittedCut(); proof.healthConfirmed || proof.version != "" {
		t.Errorf("resumed rollback exposed committed-cut evidence %+v", proof)
	}
}

// #14721 arm 2: even a healthy resumed rollback reached via --rolling must
// not be reported as a completed cut: runRollingWith must error and must
// not ResetFailover / rejoin election.
func TestRollingResumeAutoRollbackHealthyDoesNotRejoin14721(t *testing.T) {
	r, _, _ := seedAutoRollingBack14721(t)
	cl := &fakeCluster{peerAlive: true, synced: true, compatible: true, peerReady: true, drainAfter: 1}
	err := runRollingWith(r, cl, fastRC())
	if err == nil {
		t.Fatal("runRollingWith reported success for a resumed rollback; want error")
	}
	if !strings.Contains(err.Error(), "rolled back") {
		t.Errorf("rolling error %q should describe the rollback, not a completed cut", err)
	}
	if cl.resetCalled {
		t.Error("ResetFailover ran for a resumed rollback; node must not rejoin election as if cut")
	}
	if cl.rejoinChecks != 0 {
		t.Errorf("rejoin was confirmed %d time(s) for a resumed rollback", cl.rejoinChecks)
	}
}

// Unhealthy twin under --rolling: same composition, helper dead. The error
// must surface, the journal must survive, and no rejoin may happen.
func TestRollingResumeAutoRollbackUnhealthyDoesNotRejoin14721(t *testing.T) {
	r, _, fs := seedAutoRollingBack14721(t)
	fs.healthFailVersions["1.0.0"] = true
	cl := &fakeCluster{peerAlive: true, synced: true, compatible: true, peerReady: true, drainAfter: 1}
	err := runRollingWith(r, cl, fastRC())
	if err == nil {
		t.Fatal("runRollingWith succeeded with an unhealthy rolled-back helper")
	}
	if cl.resetCalled {
		t.Error("ResetFailover ran after an unhealthy resumed rollback")
	}
	j, jerr := r.loadJournal()
	if jerr != nil || j.State != StateRollingBack {
		t.Errorf("journal after unhealthy rolling resume = %+v err=%v; want ROLLINGBACK preserved", j, jerr)
	}
}

// Direct rollback() gate: the uninterrupted auto-rollback path (forward cut
// health failure calls rollback directly) must also gate on helper health
// and preserve the journal when the old version's helper is dead.
func TestDirectRollbackUnhealthyHelperPreservesJournal14721(t *testing.T) {
	r, _, fs := seedAutoRollingBack14721(t)
	fs.healthFailVersions["1.0.0"] = true
	j, err := r.loadJournal()
	if err != nil {
		t.Fatal(err)
	}
	fs.calls = nil
	if rbErr := r.rollback(j); rbErr == nil {
		t.Fatal("rollback() succeeded with unhealthy previous-version helper")
	} else if !strings.Contains(rbErr.Error(), "helper health") {
		t.Errorf("rollback error %q does not name helper health", rbErr)
	}
	if _, serr := os.Stat(r.cfg.JournalPath); serr != nil {
		t.Errorf("journal must survive an unhealthy rollback: %v", serr)
	}
}
