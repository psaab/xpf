package configstore

import (
	"strings"
	"testing"
)

// #17215: the rollback slot error travels INSIDE RollbackCapture.
// The old getters returned it as a trailing positional value that all
// gate call sites hand-carried (and the REST compare arm dropped on
// its no-candidate path); a second-lock helper re-derived it in the
// show-rollback handlers. These cells pin the capture contract:
// a missing slot yields Err + nil arms with the capture's own Cfg, a
// resolved slot yields its tree (and candidate/active Other), and a
// resolved slot with no candidate yields Other=nil, Err=nil — the
// "not in configuration mode" distinction handlers make from Other.
func TestCaptureRollbackCarriesSlotErr17215(t *testing.T) {
	s := newTestStore(t)
	commit := func(text string) {
		t.Helper()
		if err := s.EnterConfigure(); err != nil {
			t.Fatal(err)
		}
		if err := s.LoadOverride(text); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Commit(); err != nil {
			t.Fatal(err)
		}
		s.ExitConfigure()
	}
	commit("system { host-name cap-a-17215; }")
	commit("system { host-name cap-b-17215; }")
	// History holds exactly slot 1; no candidate open.

	missing := s.CaptureRollback(40, false)
	if missing.Err == nil || !strings.Contains(missing.Err.Error(), "out of range") {
		t.Fatalf("CaptureRollback(40) Err = %v, want history out-of-range", missing.Err)
	}
	if missing.Slot != nil || missing.Other != nil {
		t.Errorf("missing slot arms = (%v, %v), want nil/nil", missing.Slot, missing.Other)
	}
	if missing.Cfg == nil {
		t.Error("missing slot Cfg = nil, want capture policy for pricing")
	}

	slotOnly := s.CaptureRollbackSlot(40)
	if slotOnly.Err == nil || slotOnly.Slot != nil {
		t.Errorf("CaptureRollbackSlot(40) = Err %v Slot %v, want err + nil slot", slotOnly.Err, slotOnly.Slot)
	}

	// Resolved slot, no candidate: Other nil but Err nil — distinct
	// from the missing-slot row above.
	resolved := s.CaptureRollback(1, false)
	if resolved.Err != nil {
		t.Fatalf("CaptureRollback(1) Err = %v", resolved.Err)
	}
	if resolved.Slot == nil {
		t.Fatal("CaptureRollback(1) Slot nil, want slot 1 tree")
	}
	if resolved.Other != nil {
		t.Errorf("CaptureRollback(1) no-candidate Other = %v, want nil", resolved.Other)
	}
	// Active-baseline twin needs no candidate.
	activeBase := s.CaptureRollback(1, true)
	if activeBase.Err != nil || activeBase.Other == nil {
		t.Errorf("CaptureRollback(1, active) = Err %v Other %v, want nil + active arm", activeBase.Err, activeBase.Other)
	}

	// Candidate open: Other is the candidate arm.
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	defer s.ExitConfigure()
	if err := s.SetFromInput("system host-name cap-cand-17215"); err != nil {
		t.Fatal(err)
	}
	withCand := s.CaptureRollback(1, false)
	if withCand.Err != nil || withCand.Other == nil {
		t.Errorf("CaptureRollback(1) with candidate = Err %v Other %v, want nil + candidate arm", withCand.Err, withCand.Other)
	}
	one := s.CaptureRollbackSlot(1)
	if one.Err != nil || one.Slot == nil || one.Other != nil {
		t.Errorf("CaptureRollbackSlot(1) = Err %v Slot %v Other %v, want nil + slot + nil", one.Err, one.Slot, one.Other)
	}
}
