package upgrade

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stagedDowngradeFixture12177 models a node mid-life on 3.0.0 with a retained
// restorable 2.0.0 and a compatible pre-upgrade DB snapshot.
func stagedDowngradeFixture12177(t *testing.T) (*Runner, Config, *fakeSystem) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	if err := r.Run(Options{AllowNoRollbackFirstCut: true}); err != nil {
		t.Fatalf("first cut: %v", err)
	}
	// Cut 2.0.0 -> 3.0.0 so 2.0.0 becomes the committed predecessor of live.
	fs.stagedVersion = "3.0.0"
	for _, b := range managedBins {
		writeFakeBin(t, filepath.Join(cfg.StagedDir, b), "binary-"+b+"-3.0.0")
	}
	if publishStagedGen(t, r) == "" {
		t.Fatal("publish staged generation returned empty generation")
	}
	if err := r.Run(Options{}); err != nil {
		t.Fatalf("second cut: %v", err)
	}
	if got := currentTarget(t, cfg); got != "3.0.0" {
		t.Fatalf("current -> %q, want 3.0.0", got)
	}
	return r, cfg, fs
}

// stageDowngradeTarget12177 stages the committed predecessor's version tag
// with a fresh generation. The staged binary and installed rollback binary
// can report different envelope readers, as in a same-tag restage.
func stageDowngradeTarget12177(t *testing.T, r *Runner, cfg Config, fs *fakeSystem, stagedReader int) {
	t.Helper()
	fs.stagedVersion = "2.0.0"
	for _, b := range managedBins {
		writeFakeBin(t, filepath.Join(cfg.StagedDir, b), "binary-"+b+"-2.0.0")
	}
	genid := publishStagedGen(t, r)
	if genid == "" {
		t.Fatal("publish staged generation returned empty generation")
	}
	if fs.readerVersionsByDir == nil {
		fs.readerVersionsByDir = make(map[string]int)
	}
	fs.readerVersionsByDir[genid] = stagedReader
	fs.readerVersionsByDir["2.0.0"] = 2
	// Model byte-identical staged content with this generation stamp so COPY
	// takes the same-generation resume path that exposed the pre-STOP demotion.
	mkfile(t, r.srcGenPath("2.0.0"), genid+"\n")
}

// stageFreshDowngradeGeneration12177 publishes the committed predecessor tag
// as a new generation without falsifying the installed .srcgen marker.
func stageFreshDowngradeGeneration12177(t *testing.T, r *Runner, cfg Config,
	fs *fakeSystem, stagedReader int, identical bool) string {
	t.Helper()
	fs.stagedVersion = "2.0.0"
	for _, b := range managedBins {
		dst := filepath.Join(cfg.StagedDir, b)
		if identical {
			data, err := os.ReadFile(filepath.Join(r.versionDir("2.0.0"), b))
			if err != nil {
				t.Fatalf("read installed predecessor binary %s: %v", b, err)
			}
			if err := os.WriteFile(dst, data, 0755); err != nil {
				t.Fatalf("write identical staged binary %s: %v", b, err)
			}
		} else {
			writeFakeBin(t, dst, "binary-"+b+"-2.0.0-rebuild")
		}
	}
	genid := publishStagedGen(t, r)
	if genid == "" {
		t.Fatal("publish staged generation returned empty generation")
	}
	if fs.readerVersionsByDir == nil {
		fs.readerVersionsByDir = make(map[string]int)
	}
	fs.readerVersionsByDir[genid] = stagedReader
	fs.readerVersionsByDir["2.0.0"] = 2
	return genid
}

const downgradeLiveDB12177 = "#xpf-config-envelope v=2 writer=3.0.0 ast=1 min-reader=2 rollback-fmt=1 committed=1\n{\"live\":true}"

// TestEnvelopeRefusal_DoesNotWedgeRollback12177 is the #12177 PREFLIGHT
// regression: a staged downgrade refused by the forward envelope gate must
// not leave an in-flight journal that blocks an independently compatible
// operator rollback, and a rerun must refuse cleanly at INIT rather than
// resume a wedged journal.
func TestEnvelopeRefusal_DoesNotWedgeRollback12177(t *testing.T) {
	for _, target := range []struct {
		name string
	}{
		{name: "explicit"},
		{name: "default"},
	} {
		t.Run(target.name, func(t *testing.T) {
			r, cfg, fs := stagedDowngradeFixture12177(t)
			mkfile(t, filepath.Join(cfg.ConfigDBDir, "active.json"), downgradeLiveDB12177)
			stageDowngradeTarget12177(t, r, cfg, fs, 1)
			fs.calls = nil

			err := r.Run(Options{})
			if err == nil || !strings.Contains(err.Error(), "refuse-before-PREFLIGHT") ||
				!strings.Contains(err.Error(), "min-reader=2") {
				t.Fatalf("Run error = %v, want preflight envelope refusal", err)
			}
			assertForwardEnvelopeRefusedBeforeStop(t, fs)

			// The refusal must not wedge the journal: no in-flight record.
			if _, serr := os.Stat(cfg.JournalPath); !os.IsNotExist(serr) {
				j, _ := r.loadJournal()
				t.Fatalf("journal left on disk after preflight envelope refusal (state=%v)", j)
			}

			// A stale journal from a pre-fix run must also be cleared when its
			// resumed PREFLIGHT gate refuses; operator rollback remains available.
			stale := &Journal{State: StateStaged, TargetVersion: "2.0.0", PreviousVersion: "3.0.0"}
			if err := r.saveJournal(stale); err != nil {
				t.Fatalf("seed stale STAGED journal: %v", err)
			}
			fs.calls = nil
			if rerr := r.Run(Options{}); rerr == nil || !strings.Contains(rerr.Error(), "refuse-before-PREFLIGHT") {
				t.Fatalf("rerun error = %v, want clean preflight refusal", rerr)
			}
			if _, serr := os.Stat(cfg.JournalPath); !os.IsNotExist(serr) {
				t.Fatalf("resumed envelope refusal left journal behind: %v", serr)
			}
			assertForwardEnvelopeRefusedBeforeStop(t, fs)

			// The independently compatible snapshot rollback still works.
			want := "2.0.0"
			rbTarget := want
			if target.name == "default" {
				rbTarget = ""
			}
			if err := r.RollbackTo(rbTarget, RollbackOptions{}); err != nil {
				t.Fatalf("RollbackTo(%q) after envelope refusal: %v", rbTarget, err)
			}
			if got := currentTarget(t, cfg); got != want {
				t.Fatalf("current -> %q, want %s", got, want)
			}
		})
	}
}

// TestEnvelopeRefusal_InitGateClearsStaleJournal12177 distinguishes the INIT
// gate from the later PREFLIGHT gate. The new staged target differs from a
// stale journal, so INIT must clear the stale record before refusing; a missing
// INIT gate instead reports a resumed PREFLIGHT refusal.
func TestEnvelopeRefusal_InitGateClearsStaleJournal12177(t *testing.T) {
	r, cfg, fs := stagedDowngradeFixture12177(t)
	mkfile(t, filepath.Join(cfg.ConfigDBDir, "active.json"), downgradeLiveDB12177)
	stageDowngradeTarget12177(t, r, cfg, fs, 1)
	stale := &Journal{
		State: StateVerified, TargetVersion: "1.9.0", PreviousVersion: "3.0.0",
	}
	if err := r.saveJournal(stale); err != nil {
		t.Fatalf("seed stale journal: %v", err)
	}
	fs.calls = nil

	err := r.Run(Options{})
	if err == nil || !strings.HasPrefix(err.Error(), "refuse-before-PREFLIGHT:") {
		t.Fatalf("Run error = %v, want INIT refusal before PREFLIGHT", err)
	}
	if !strings.Contains(err.Error(), "re-stage an envelope-compatible target") {
		t.Fatalf("refusal lacks recovery guidance: %v", err)
	}
	if _, err := os.Stat(cfg.JournalPath); !os.IsNotExist(err) {
		t.Fatalf("INIT refusal left stale journal: %v", err)
	}
	assertForwardEnvelopeRefusedBeforeStop(t, fs)
}

func TestForwardEnvelopeRefusalDetectionUsesErrorsAs12177(t *testing.T) {
	refusal := &forwardEnvelopeGateRefusal{phase: "PREFLIGHT", err: errors.New("incompatible")}
	wrapped := fmt.Errorf("resume: %w", refusal)
	if !isForwardEnvelopeGateRefusal(wrapped) {
		t.Fatal("wrapped forward-envelope refusal was not detected")
	}
	if isForwardEnvelopeGateRefusal(errors.New("unrelated preflight error")) {
		t.Fatal("unrelated preflight error was classified as an envelope refusal")
	}
}

func TestCommittedPredecessorStampRequiresCurrentLink12177(t *testing.T) {
	r, _, _ := stagedDowngradeFixture12177(t)
	current, present, err := r.readCommittedStamp("3.0.0")
	if err != nil || !present || current == nil || !current.Committed {
		t.Fatalf("current 3.0.0 stamp = (%+v,present=%v,err=%v), want committed", current, present, err)
	}
	current.Predecessor = "1.0.0"
	if err := r.writeCommitStamp(*current); err != nil {
		t.Fatalf("write mismatched current predecessor: %v", err)
	}
	if got, err := r.committedPredecessorStamp(
		&Journal{PreviousVersion: "3.0.0"}, "2.0.0"); err != nil || got != nil {
		t.Fatalf("unlinked target stamp = (%+v, err=%v), want nil", got, err)
	}
}

func TestEnvelopeRefusal_ReplacePathDemotesChangedBytes12177(t *testing.T) {
	r, cfg, fs := stagedDowngradeFixture12177(t)
	active := filepath.Join(cfg.ConfigDBDir, "active.json")
	mkfile(t, active, "#xpf-config-envelope v=1 writer=3.0.0 ast=1 min-reader=1 rollback-fmt=1 committed=1\n{}")
	genid := stageFreshDowngradeGeneration12177(t, r, cfg, fs, 2, false)
	const risen = "#xpf-config-envelope v=3 writer=3.0.0 ast=1 min-reader=3 rollback-fmt=1 committed=1\n{}"
	fs.verifyHook = func() { mkfile(t, active, risen) }
	fs.calls = nil

	err := r.Run(Options{})
	if err == nil || !strings.Contains(err.Error(), "refuse-before-STOP") {
		t.Fatalf("Run error = %v, want pre-STOP refusal", err)
	}
	assertForwardEnvelopeRefusedBeforeStop(t, fs)
	stamp, present, _ := r.readCommittedStamp("2.0.0")
	if !present || stamp == nil || stamp.Committed {
		t.Fatalf("replaced different-byte predecessor stamp = (%+v,present=%v), want non-committed", stamp, present)
	}
	if got, err := r.readSrcGen("2.0.0"); err != nil || got != genid {
		t.Fatalf("replacement generation = %q, err=%v; want %q", got, err, genid)
	}
	if err := r.verifyVersionDirMatchesStaged("2.0.0", r.sourceDir(&Journal{SourceGeneration: genid})); err != nil {
		t.Fatalf("replacement bytes do not match pinned source: %v", err)
	}
}

func TestEnvelopeRefusal_ReplacePathPreservesIdenticalBytes12177(t *testing.T) {
	r, cfg, fs := stagedDowngradeFixture12177(t)
	active := filepath.Join(cfg.ConfigDBDir, "active.json")
	mkfile(t, active, "#xpf-config-envelope v=1 writer=3.0.0 ast=1 min-reader=1 rollback-fmt=1 committed=1\n{}")
	before, present, _ := r.readCommittedStamp("2.0.0")
	if !present || before == nil || !before.Committed {
		t.Fatalf("precondition predecessor stamp = (%+v,present=%v), want committed", before, present)
	}
	genid := stageFreshDowngradeGeneration12177(t, r, cfg, fs, 2, true)
	const risen = "#xpf-config-envelope v=3 writer=3.0.0 ast=1 min-reader=3 rollback-fmt=1 committed=1\n{}"
	fs.verifyHook = func() { mkfile(t, active, risen) }
	fs.calls = nil

	err := r.Run(Options{})
	if err == nil || !strings.Contains(err.Error(), "refuse-before-STOP") {
		t.Fatalf("Run error = %v, want pre-STOP refusal", err)
	}
	stamp, present, _ := r.readCommittedStamp("2.0.0")
	if !present || stamp == nil || !stamp.Committed ||
		stamp.CommittedAtUnixNano != before.CommittedAtUnixNano {
		t.Fatalf("identical-byte replacement stamp = (%+v,present=%v), want preserved %+v", stamp, present, before)
	}
	if got, err := r.readSrcGen("2.0.0"); err != nil || got != genid {
		t.Fatalf("replacement generation = %q, err=%v; want %q", got, err, genid)
	}
}

// TestEnvelopeRefusal_UnverifiablePredecessorDoesNotWedge12177 covers a
// crash-resumed same-tag replace whose prior RemoveAll unlinked one managed
// binary but left the committed stamp behind. The predecessor cannot be
// proven identical, so the replacement must be demoted rather than stranding
// the PREFLIGHT journal on a hash error.
func TestEnvelopeRefusal_UnverifiablePredecessorDoesNotWedge12177(t *testing.T) {
	r, cfg, fs := stagedDowngradeFixture12177(t)
	active := filepath.Join(cfg.ConfigDBDir, "active.json")
	mkfile(t, active,
		"#xpf-config-envelope v=1 writer=3.0.0 ast=1 min-reader=1 rollback-fmt=1 committed=1\n{}")
	genid := stageFreshDowngradeGeneration12177(t, r, cfg, fs, 2, true)

	// Model a crash partway through removeStaleVersionDir: the old committed
	// stamp and source-generation marker survive, but one managed binary does
	// not. Resume at PREFLIGHT against the freshly published generation.
	if err := os.Remove(filepath.Join(r.versionDir("2.0.0"), "cli")); err != nil {
		t.Fatalf("unlink predecessor cli: %v", err)
	}
	j := &Journal{
		State: StatePreflight, TargetVersion: "2.0.0", PreviousVersion: "3.0.0",
		SourceGeneration: genid,
	}
	if err := r.saveJournal(j); err != nil {
		t.Fatalf("seed resumed PREFLIGHT journal: %v", err)
	}
	const risen = "#xpf-config-envelope v=3 writer=3.0.0 ast=1 min-reader=3 rollback-fmt=1 committed=1\n{}"
	fs.verifyHook = func() { mkfile(t, active, risen) }
	fs.calls = nil

	err := r.Run(Options{})
	if err == nil || !strings.Contains(err.Error(), "refuse-before-STOP") {
		t.Fatalf("resumed Run error = %v, want pre-STOP refusal after replacement", err)
	}
	assertForwardEnvelopeRefusedBeforeStop(t, fs)
	if _, serr := os.Stat(cfg.JournalPath); !os.IsNotExist(serr) {
		journal, _ := r.loadJournal()
		t.Fatalf("unverifiable predecessor left journal behind (state=%s): %v", journal.State, serr)
	}
	stamp, present, _ := r.readCommittedStamp("2.0.0")
	if !present || stamp == nil || stamp.Committed {
		t.Fatalf("unverifiable predecessor stamp = (%+v,present=%v), want non-committed", stamp, present)
	}
	if got, err := r.readSrcGen("2.0.0"); err != nil || got != genid {
		t.Fatalf("replacement generation = %q, err=%v; want %q", got, err, genid)
	}

	// With the refusal journal cleared, a rerun reports the current envelope
	// incompatibility at INIT rather than refusing behind a stuck PREFLIGHT.
	rerunErr := r.Run(Options{})
	if rerunErr == nil || !strings.HasPrefix(rerunErr.Error(), "refuse-before-PREFLIGHT:") {
		t.Fatalf("rerun error = %v, want a clean INIT envelope refusal", rerunErr)
	}
	if strings.Contains(rerunErr.Error(), "in-flight") {
		t.Fatalf("rerun was blocked by an in-flight journal: %v", rerunErr)
	}
}

func TestEnvelopeRefusal_PreStopDemotesFailedReplacement12177(t *testing.T) {
	r, cfg, fs := stagedDowngradeFixture12177(t)
	mkfile(t, filepath.Join(cfg.ConfigDBDir, "active.json"),
		"#xpf-config-envelope v=1 writer=3.0.0 ast=1 min-reader=1 rollback-fmt=1 committed=1\n{}")
	stageFreshDowngradeGeneration12177(t, r, cfg, fs, 2, true)
	fs.healthFailVersions["2.0.0"] = true

	err := r.Run(Options{})
	if err == nil || !strings.Contains(err.Error(), "rolled back to 3.0.0") {
		t.Fatalf("Run error = %v, want failed target auto-rollback", err)
	}
	if got := currentTarget(t, cfg); got != "3.0.0" {
		t.Fatalf("current -> %q after failed replacement, want 3.0.0", got)
	}
	stamp, present, _ := r.readCommittedStamp("2.0.0")
	if !present || stamp == nil || stamp.Committed {
		t.Fatalf("failed replacement stamp = (%+v,present=%v), want non-committed", stamp, present)
	}
	if got, err := r.defaultRollbackTarget("3.0.0"); err == nil && got == "2.0.0" {
		t.Fatalf("failed target 2.0.0 remains default rollback candidate")
	}
}

// TestEnvelopeRefusal_PreStopRisePreservesPredecessor12177 is the #12177
// pre-STOP control: when the DB reader floor rises between preflight and the
// pre-STOP recheck, the recheck refuses — and the committed predecessor's
// stamp must survive so it remains the default rollback target.
func TestEnvelopeRefusal_PreStopRisePreservesPredecessor12177(t *testing.T) {
	for _, tc := range []struct {
		name   string
		target string
	}{
		{name: "default rollback"},
		{name: "explicit rollback", target: "2.0.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, cfg, fs := stagedDowngradeFixture12177(t)
			const compatible = "#xpf-config-envelope v=1 writer=3.0.0 ast=1 min-reader=1 rollback-fmt=1 committed=1\n{}"
			const risen = "#xpf-config-envelope v=3 writer=3.0.0 ast=1 min-reader=3 rollback-fmt=1 committed=1\n{}"
			active := filepath.Join(cfg.ConfigDBDir, "active.json")
			mkfile(t, active, compatible)
			stageDowngradeTarget12177(t, r, cfg, fs, 2)
			fs.verifyHook = func() { mkfile(t, active, risen) }
			fs.calls = nil

			err := r.Run(Options{})
			if err == nil || !strings.Contains(err.Error(), "refuse-before-STOP") ||
				!strings.Contains(err.Error(), "min-reader=3") {
				t.Fatalf("Run error = %v, want pre-STOP envelope refusal", err)
			}
			assertForwardEnvelopeRefusedBeforeStop(t, fs)
			if !containsCall(fs.calls, "verify") {
				t.Fatalf("verification was not reached before the live DB changed: calls=%v", fs.calls)
			}
			if _, serr := os.Stat(cfg.JournalPath); !os.IsNotExist(serr) {
				t.Fatalf("pre-STOP refusal left journal behind: %v", serr)
			}

			// A rerun is a fresh refusal at INIT, not a resume that is stuck
			// behind RollbackTo's in-flight-journal guard.
			fs.calls = nil
			rerunErr := r.Run(Options{})
			if rerunErr == nil || !strings.HasPrefix(rerunErr.Error(), "refuse-before-PREFLIGHT:") {
				t.Fatalf("rerun error = %v, want clean INIT envelope refusal", rerunErr)
			}
			if !strings.Contains(rerunErr.Error(), "re-stage an envelope-compatible target") {
				t.Fatalf("rerun refusal lacks recovery guidance: %v", rerunErr)
			}
			if _, serr := os.Stat(cfg.JournalPath); !os.IsNotExist(serr) {
				t.Fatalf("INIT refusal after pre-STOP refusal left journal: %v", serr)
			}
			assertForwardEnvelopeRefusedBeforeStop(t, fs)

			// The same two operator rollback forms that were blocked before
			// #12177 are available after the pre-STOP refusal.
			if got, err := r.defaultRollbackTarget("3.0.0"); err != nil || got != "2.0.0" {
				t.Fatalf("default rollback target = %q, err=%v; want 2.0.0", got, err)
			}
			if err := r.RollbackTo(tc.target, RollbackOptions{}); err != nil {
				t.Fatalf("RollbackTo(%q) after pre-STOP refusal: %v", tc.target, err)
			}
			if got := currentTarget(t, cfg); got != "2.0.0" {
				t.Fatalf("current -> %q after rollback, want 2.0.0", got)
			}
		})
	}
}
