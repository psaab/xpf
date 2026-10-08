package upgrade

import (
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

// TestEnvelopeRefusal_PreStopRisePreservesPredecessor12177 is the #12177
// pre-STOP control: when the DB reader floor rises between preflight and the
// pre-STOP recheck, the recheck refuses — and the committed predecessor's
// stamp must survive so it remains the default rollback target.
func TestEnvelopeRefusal_PreStopRisePreservesPredecessor12177(t *testing.T) {
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

	// The committed predecessor's stamp and default-selection role must survive
	// the refused cut despite COPY taking its same-generation resume path.
	stamp, present := r.readCommittedStamp("2.0.0")
	if !present || stamp == nil || !stamp.Committed {
		t.Fatalf("predecessor 2.0.0 commit record = (%+v,present=%v), want committed", stamp, present)
	}
	if got, err := r.defaultRollbackTarget("3.0.0"); err != nil || got != "2.0.0" {
		t.Fatalf("default rollback target = %q, err=%v; want committed predecessor 2.0.0", got, err)
	}
}
