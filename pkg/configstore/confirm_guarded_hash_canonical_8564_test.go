package configstore

import (
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// #8564: `confirmRecord.GuardedHash` must be computed over the tree's CANONICAL
// text — the text it has after one JSON round trip — because the two ends of
// the binding never see the same tree.
//
// It is computed before writeActive from the staged candidate, and checked at
// boot over the active tree DECODED FROM DISK (`store_persist.go`
// recoverPendingConfirmLocked). The finalized record uses the same canonical
// basis. Any value the JSON encoding normalizes therefore makes the two differ,
// and recovery drops a LIVE record as stale: no timer, no rollback, and the
// UNCONFIRMED config stands permanently — the #4577 failure the record exists to prevent —
// while the log says "a later commit/confirm superseded it" and nothing did.
//
// The reachable instance: `hasControlChars` (pkg/config/freetext.go) rejects
// only C0/DEL, so a raw invalid-UTF-8 byte in a free-text leaf commits cleanly,
// and `json.MarshalIndent` (pkg/configstore/db.go, the persistence format)
// coerces it to U+FFFD.
//
// The three cells below are a matrix, not three views of one property:
//   - normalized: the defect. RED before the fix.
//   - clean: the positive control. If it ever fails, the fixture never restored
//     anything and the first cell's PASS means nothing.
//   - stale: the control that fails on the OVER-BROAD fix. A basis that
//     collapsed to a constant (or to "") would satisfy the first two cells
//     while disabling #5835's staleness guard entirely, resurrecting a rollback
//     of an already-confirmed generation.

// armWithDescription commits a baseline, then arms a commit-confirmed window
// whose active tree carries the supplied interface description.
func armWithDescription(t *testing.T, path, desc string) *Store {
	t.Helper()
	s := newTestStoreAt(t, path)
	commitBaseline(t, s)
	if err := s.SetFromInput("interfaces eth0 description \"" + desc + "\""); err != nil {
		t.Fatalf("SetFromInput(description %q): %v — the leaf must COMMIT for this cell "+
			"to be about the hash basis rather than about input validation", desc, err)
	}
	if _, err := s.CommitConfirmed(10); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	if !s.IsConfirmPending() {
		t.Fatal("PREMISE: the window must be armed before the restart")
	}
	return s
}

func TestGuardedHashSurvivesJSONNormalization_8564(t *testing.T) {
	for _, tc := range []struct {
		name string
		desc string
	}{
		// The SUBJECT: a raw 0xff byte, which json.MarshalIndent turns into
		// U+FFFD on the way to disk.
		{"normalized-leaf", "lan\xffside"},
		// POSITIVE CONTROL: byte-identical through the round trip. If this arm
		// ever fails, the fixture is not restoring windows at all and the
		// subject's PASS would be meaningless.
		{"clean-leaf", "lanside"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config")
			_ = armWithDescription(t, path, tc.desc)

			s2 := newTestStoreAt(t, path)
			if err := s2.Load(); err != nil {
				t.Fatalf("boot Load: %v", err)
			}
			if !s2.IsConfirmPending() {
				t.Fatal("#8564: the LIVE commit-confirmed window did not survive a restart. " +
					"Recovery hashed the reloaded tree against a record armed over the " +
					"in-memory one, they differed only by a value the JSON encoding " +
					"normalized, and the record was dropped as stale — so the UNCONFIRMED " +
					"config now stands permanently with no rollback (#4577).")
			}
			if rec, err := s2.db.ReadConfirm(); err != nil || rec == nil {
				t.Fatalf("#8564: the record must still be on disk after recovery re-arms it: rec=%v err=%v", rec, err)
			}
		})
	}
}

// TestGuardedHashStillCatchesAStaleRecord_8564 is the control that fails on the
// over-broad fix. #5835's binding must keep REJECTING a record whose active
// config has genuinely advanced.
func TestGuardedHashStillCatchesAStaleRecord_8564(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	var failUnlink atomic.Bool
	installConfirmDeleteSeams(t, &failUnlink, nil)

	s := newTestStoreAt(t, path)
	commitBaseline(t, s)
	s.SetPersistRetryBackoffForTesting(time.Hour, time.Hour)
	stagePendingConfirmed(t, s, "eth1", "untrust") // window B

	// Resolve B with a plain commit while the unlink fails: the active config
	// ADVANCES and the stale record lingers guarding B.
	failUnlink.Store(true)
	committed := commitPlainChange(t, s, "eth3", "dmz")
	if rec, err := s.db.ReadConfirm(); err != nil || rec == nil {
		t.Fatalf("PREMISE: the stale record must linger: rec=%v err=%v", rec, err)
	}

	forceConfirmDeadlinePast(t, path)
	failUnlink.Store(false)
	s2 := newTestStoreAt(t, path)
	if err := s2.Load(); err != nil {
		t.Fatalf("boot Load: %v", err)
	}
	if got := s2.ShowActiveSet(); got != committed {
		t.Fatalf("#5835 REGRESSION (#8564 control): the stale record resurrected a rollback of "+
			"the durably-committed generation. A guarded-hash basis that matches every config "+
			"— a constant, or \"\" — passes the normalization cells above and disables this "+
			"binding entirely.\nwant %s\ngot  %s", committed, got)
	}
}

// TestGuardedHashLegacyBasisStillMatches_8564 binds the cross-version claim in
// guardedConfigHash's doc comment: a record armed by a PRE-#8564 build carries
// the plain `journalConfigHash` basis, and for every config the JSON encoding
// does not normalize the two bases are equal, so no versioned basis is needed.
//
// Without this cell that sentence is an unfalsifiable claim in a comment: a
// change that made the canonical basis differ from the plain one on ordinary
// config would silently stale-drop every in-flight window across an upgrade,
// and the cells above — which arm and recover with the SAME build — could not
// see it.
func TestGuardedHashLegacyBasisStillMatches_8564(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	s := armWithDescription(t, path, "lanside")

	// Rewrite the persisted record with the PRE-#8564 (plain Format) basis,
	// exactly as an older build would have armed it.
	rec, err := s.db.ReadConfirm()
	if err != nil || rec == nil {
		t.Fatalf("ReadConfirm: rec=%v err=%v", rec, err)
	}
	legacy := journalConfigHash(s.ActiveTree())
	if legacy == "" {
		t.Fatal("PREMISE: the legacy basis must be computable over the active tree")
	}
	if legacy != rec.GuardedHash {
		t.Fatalf("#8564 CROSS-VERSION: the canonical basis differs from the plain one on a "+
			"config the JSON encoding does not normalize (%q vs %q). Every window armed by an "+
			"older build would be stale-dropped on upgrade — the very defect this change "+
			"fixes, inflicted on every operator instead of the ones using an odd byte.",
			legacy, rec.GuardedHash)
	}
	rec.GuardedHash = legacy
	if err := s.db.WriteConfirm(rec); err != nil {
		t.Fatalf("WriteConfirm: %v", err)
	}

	s2 := newTestStoreAt(t, path)
	if err := s2.Load(); err != nil {
		t.Fatalf("boot Load: %v", err)
	}
	if !s2.IsConfirmPending() {
		t.Fatal("#8564: a record carrying the legacy basis must still be recognized on boot")
	}
}
