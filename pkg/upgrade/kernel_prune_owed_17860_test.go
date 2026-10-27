package upgrade

import (
	"errors"
	"testing"
)

// #17860 settle tests (fold of Rev18063Opus B1/B2): the settle decides
// from the CURRENT slot selector — full prune only while the debt
// still owns the slot, purge-only when a later roll repurposed it,
// retain (collect nothing) whenever ownership is unprovable.

func seedOwed17860(t *testing.T, r *KernelRunner) {
	t.Helper()
	r.recordPruneOwed(&KernelJournal{
		InactiveSlot:     SlotB,
		CandidateVersion: "6.18.5-12-generic",
		KnownGoodVersion: "6.17.9-9-generic",
	})
	if !owedRecordExists(t, r) {
		t.Fatal("recordPruneOwed did not persist")
	}
}

func TestSettleOwedRepurposedPurgesOnly17860(t *testing.T) {
	f := newFakeKernelSystem()
	r := newKernelRunner(t, f)
	seedOwed17860(t, r)
	f.running = "6.17.9-9-generic"
	f.selectors[SlotB] = "6.19.0-1-generic" // later roll owns the slot
	if err := r.settlePruneOwed(); err != nil {
		t.Fatalf("settle: %v", err)
	}
	if n := countCalls(f.calls, "purge:6.18.5-12-generic"); n != 1 {
		t.Fatalf("purge calls = %d, want 1 (%v)", n, f.calls)
	}
	if n := countCalls(f.calls, "prune:"+SlotB); n != 0 {
		t.Fatalf("full prune ran on a repurposed slot (%v)", f.calls)
	}
	if got := f.selectors[SlotB]; got != "6.19.0-1-generic" {
		t.Fatalf("repurposed selector rewritten to %q", got)
	}
	if owedRecordExists(t, r) {
		t.Fatal("debt not discharged after purge")
	}
}

func TestSettleOwedStillOwnsFullPrune17860(t *testing.T) {
	f := newFakeKernelSystem()
	r := newKernelRunner(t, f)
	seedOwed17860(t, r)
	f.running = "6.17.9-9-generic"
	f.selectors[SlotB] = "6.17.9-9-generic" // deferral left known-good
	if err := r.settlePruneOwed(); err != nil {
		t.Fatalf("settle: %v", err)
	}
	if n := countCalls(f.calls, "prune:"+SlotB); n != 1 {
		t.Fatalf("full prune calls = %d, want 1 (%v)", n, f.calls)
	}
	if owedRecordExists(t, r) {
		t.Fatal("debt not discharged")
	}
	// Exactly once: a second settle is a no-op (no record remains).
	if err := r.settlePruneOwed(); err != nil {
		t.Fatalf("second settle: %v", err)
	}
	if n := countCalls(f.calls, "prune:"+SlotB); n != 1 {
		t.Fatalf("double-collected: prune calls = %d", n)
	}
}

func TestSettleOwedUnprovableRetains17860(t *testing.T) {
	// Unreadable selector (read error): retain, collect nothing.
	f := newFakeKernelSystem()
	r := newKernelRunner(t, f)
	seedOwed17860(t, r)
	f.running = "6.17.9-9-generic"
	f.readSelectorErr = errors.New("io error")
	if err := r.settlePruneOwed(); err != nil {
		t.Fatalf("settle: %v", err)
	}
	if len(f.calls) != 0 {
		t.Fatalf("collected on unreadable selector: %v", f.calls)
	}
	if !owedRecordExists(t, r) {
		t.Fatal("record discharged without collecting")
	}
	// Empty selector (missing/corrupt file): retain, never
	// discharged as "repurposed to ''" (Rev18063Opus B2).
	f2 := newFakeKernelSystem()
	r2 := newKernelRunner(t, f2)
	seedOwed17860(t, r2)
	f2.running = "6.17.9-9-generic"
	f2.selectors[SlotB] = ""
	if err := r2.settlePruneOwed(); err != nil {
		t.Fatalf("settle: %v", err)
	}
	if len(f2.calls) != 0 {
		t.Fatalf("collected on empty selector: %v", f2.calls)
	}
	if !owedRecordExists(t, r2) {
		t.Fatal("empty-selector debt discharged")
	}
}
