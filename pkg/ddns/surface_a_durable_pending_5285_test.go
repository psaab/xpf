package ddns

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// surface_a_durable_pending_5285_test.go: #5285 fail-on-revert proofs for the
// Surface A durable desired-vs-confirmed publish contract.
//
// ROOT CAUSE (#5285): pre-fix, publishLocked persisted the DESIRED address into
// the SOLE ownership row BEFORE the provider I/O with NO pending bit and NO
// retained prior value. An abrupt CRASH between state.save and the wire add
// (the in-process rollback never runs on a crash) therefore left the store
// falsely reporting the new address as published. On restart the unchanged-owned
// skip suppressed recovery: public DNS stayed at the OLD value while the appliance
// reported the NEW one, and the OLD value's value-specific cleanup key was
// destroyed.
//
// FIX: the write-ahead row now records the desired address as PublishPending and
// RETAINS the last-confirmed value (PriorAddrText) until the wire add confirms;
// the confirm-save AFTER the wire op clears the pending bit and releases the
// prior value. On restart a PENDING record is detected and does NOT take the
// unchanged-owned skip — the provider I/O is re-run and the prior value is kept
// as the replace/cleanup target. Mirrors the DHCP-lease PTRPending idiom;
// DISTINCT from #2662 (which closes the end-of-pass orphan window but writes the
// desired address as though confirmed).

// crashUpsertUpdater panics on UpsertLease to simulate the process being killed
// mid-wire — AFTER publishLocked has durably written-ahead the PENDING
// {desired, prior} row and BEFORE the wire add takes effect. A panic (not an
// error return) is the faithful crash: neither the confirm-save nor the
// in-process rollback runs, so the durable store is frozen at the pending
// write-ahead, exactly as a hard kill would leave it.
type crashUpsertUpdater struct{ called bool }

func (c *crashUpsertUpdater) UpsertLease(context.Context, LeaseDNSRecord) error {
	c.called = true
	panic("xpf-test: simulated crash between the durable pending save and the wire add")
}

func (c *crashUpsertUpdater) DeleteLease(context.Context, LeaseDNSRecord) error { return nil }

// onlyOwned5285 reads the durable ownership store and returns its single record,
// failing if the count is not exactly one (Surface A keys one record per scope).
func onlyOwned5285(t *testing.T, statePath string) ownedRecord {
	t.Helper()
	recs := readDurableOwnership(t, statePath)
	if len(recs) != 1 {
		t.Fatalf("want exactly one owned record on disk, got %d: %v", len(recs), recs)
	}
	for _, r := range recs {
		return r
	}
	return ownedRecord{}
}

// TestSurfaceADurablePendingCrashRecovery is the #5285 fail-on-revert proof. A
// renumber A->B is killed between the durable pending save and the wire add; a
// fresh manager loaded from the persisted store MUST detect the PENDING record,
// re-run the provider I/O for B, retain A as the value-specific cleanup key, and
// NOT report B as a confirmed publish (nor take the unchanged-owned skip).
//
// RED-on-revert: restore the no-pending-bit save-desired-first behavior and the
// crash leaves {AddrText=B} with no pending bit; on restart seedFromStore seeds B
// as lastAddr, the unchanged-owned skip fires, and the recovery reconcile
// publishes NOTHING (fu3.upserts == 0) — this test then fails at the "recovery
// must re-run the wire publish for B" assertion. A's cleanup key is also lost.
func TestSurfaceADurablePendingCrashRecovery(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "iface-ddns.json")
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }

	const fqdn = "wan.example.net"
	const addrA = "203.0.113.5"
	const addrB = "198.51.100.9"
	sc := surfaceAScope(fqdn, FamilyV4, 0)

	// Boot 1: publish A successfully -> CONFIRMED ownership on disk.
	fu1 := newFakeUpdater()
	m1 := newSurfaceAManagerForTesting(statePath, fu1, clock)
	if err := m1.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver(addrA), nil, nil); err != nil {
		t.Fatalf("boot1 publish A: %v", err)
	}
	if got := fu1.upsertNames(); len(got) != 1 || got[0] != fqdn+"="+addrA {
		t.Fatalf("boot1: want one publish of A, got %v", got)
	}
	if rec := onlyOwned5285(t, statePath); rec.PublishPending || rec.AddrText != addrA || rec.PriorAddrText != "" {
		t.Fatalf("boot1: confirmed record want {A, not pending, no prior}, got %+v", rec)
	}

	// Boot 2: renumber A->B, but CRASH mid-wire (panic on UpsertLease). The panic
	// strikes after the write-ahead save of {desired=B pending, prior=A} and before
	// the wire add — a faithful "process killed between state.save and the wire".
	now = now.Add(time.Hour)
	crash := &crashUpsertUpdater{}
	m2 := newSurfaceAManagerForTesting(statePath, crash, clock)
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expected the crash backend to panic during the wire add")
			}
		}()
		_ = m2.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver(addrB), nil, nil)
	}()
	if !crash.called {
		t.Fatal("the crash backend's UpsertLease was never reached (write-ahead did not precede the wire)")
	}

	// The crash left a RECOVERABLE PENDING record: desired=B pending, CONFIRMED
	// prior A retained as the cleanup key. It MUST NOT report B as confirmed.
	rec := onlyOwned5285(t, statePath)
	if !rec.PublishPending {
		t.Fatalf("crash-recovery: on-disk record must be PENDING after a save->wire crash, got %+v", rec)
	}
	if rec.AddrText != addrB {
		t.Fatalf("crash-recovery: pending desired AddrText = %q, want B (%s)", rec.AddrText, addrB)
	}
	if rec.PriorAddrText != addrA {
		t.Fatalf("crash-recovery: pending record must RETAIN prior A as its cleanup key, got PriorAddrText=%q", rec.PriorAddrText)
	}

	// Boot 3 (restart): a fresh manager from the persisted store must DETECT the
	// pending record, RE-RUN the provider I/O for B (NOT the unchanged-owned skip),
	// and thread the retained prior A as the value-specific replace target.
	fu3 := newFakeUpdater()
	m3 := newSurfaceAManagerForTesting(statePath, fu3, clock)
	if err := m3.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver(addrB), nil, nil); err != nil {
		t.Fatalf("boot3 recovery reconcile: %v", err)
	}
	if got := fu3.upserts; len(got) != 1 {
		t.Fatalf("recovery must re-run the wire publish for B; got %d upserts (%v) — "+
			"the unchanged-owned skip must NOT suppress a pending record", len(got), fu3.upsertNames())
	}
	if got := fu3.upserts[0]; got.FQDN != fqdn || got.Addr.String() != addrB {
		t.Fatalf("recovery published %s=%s, want %s=%s", got.FQDN, got.Addr, fqdn, addrB)
	}
	if got := fu3.upserts[0].PrevAddr; got.String() != addrA {
		t.Fatalf("recovery must thread the retained prior A as PrevAddr (value-specific "+
			"replace of xpf's real live value); got %q", got)
	}

	// After the confirmed recovery the record is SETTLED: pending cleared, desired
	// B is now confirmed, prior cleanup key released.
	rec = onlyOwned5285(t, statePath)
	if rec.PublishPending || rec.AddrText != addrB || rec.PriorAddrText != "" {
		t.Fatalf("post-recovery record want {B, not pending, no prior}, got %+v", rec)
	}
}

// TestSurfaceADurablePendingHappyPathConfirms proves the ordinary (no-crash)
// renumber A->B with a successful wire op ends CONFIRMED: the pending bit is
// cleared, B is the confirmed value, the retained prior A is released, and the
// wire add threaded A as the value-specific replace target. Reverting the
// confirm-save leaves the record PENDING on disk -> the "confirmed" assertions
// below go RED.
func TestSurfaceADurablePendingHappyPathConfirms(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "iface-ddns.json")
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }

	const fqdn = "wan.example.net"
	const addrA = "203.0.113.5"
	const addrB = "198.51.100.9"
	sc := surfaceAScope(fqdn, FamilyV4, 0)

	fu := newFakeUpdater()
	m := newSurfaceAManagerForTesting(statePath, fu, clock)

	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver(addrA), nil, nil); err != nil {
		t.Fatalf("publish A: %v", err)
	}
	if rec := onlyOwned5285(t, statePath); rec.PublishPending || rec.AddrText != addrA || rec.PriorAddrText != "" {
		t.Fatalf("after A: want {A, confirmed, no prior}, got %+v", rec)
	}

	now = now.Add(time.Hour)
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver(addrB), nil, nil); err != nil {
		t.Fatalf("renumber B: %v", err)
	}
	ups := fu.upserts
	if len(ups) != 2 {
		t.Fatalf("want A then B upserts, got %v", fu.upsertNames())
	}
	if ups[1].Addr.String() != addrB || ups[1].PrevAddr.String() != addrA {
		t.Fatalf("renumber upsert = %s (prev %s), want B with prev A (value-specific replace)",
			ups[1].Addr, ups[1].PrevAddr)
	}
	if rec := onlyOwned5285(t, statePath); rec.PublishPending || rec.AddrText != addrB || rec.PriorAddrText != "" {
		t.Fatalf("after B: want {B, confirmed, prior released}, got %+v", rec)
	}
}

// TestSurfaceADurablePendingInProcessRollbackRestoresPrev — UPDATED by
// #15225 A40-02: a bare wire failure is AMBIGUOUS (the UPDATE may have
// been applied before the error surfaced), so it no longer rolls back to
// the single confirmed prior. The durable row stays PENDING {B, prior A}
// retaining both cleanup candidates; only a DEFINITIVE rejection (e.g.
// errDDNSConflictRefused, covered in surface_a_ambiguous_15225_test.go)
// rolls back. This preserves the #5285 invariant that matters — B is
// never falsely CONFIRMED — while closing the A40-02 orphan.
func TestSurfaceADurablePendingInProcessRollbackRestoresPrev(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "iface-ddns.json")
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }

	const fqdn = "wan.example.net"
	const addrA = "203.0.113.5"
	const addrB = "198.51.100.9"
	sc := surfaceAScope(fqdn, FamilyV4, 0)

	fu := newFakeUpdater()
	m := newSurfaceAManagerForTesting(statePath, fu, clock)

	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver(addrA), nil, nil); err != nil {
		t.Fatalf("publish A: %v", err)
	}

	// Renumber A->B but the wire add FAILS ambiguously: the row must stay
	// pending with A retained, never confirmed-B and never rolled back
	// to A-only (which would orphan a possibly-live B).
	fu.failEvery = true
	now = now.Add(time.Hour)
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver(addrB), nil, nil); err == nil {
		t.Fatal("renumber with a failing wire op must surface an error")
	}

	rec := onlyOwned5285(t, statePath)
	if !rec.PublishPending || rec.AddrText != addrB || rec.PriorAddrText != addrA {
		t.Fatalf("ambiguous failure must retain pending {B, prior A}, got %+v", rec)
	}
	if st := m.Stats(); st.UpsertFail == 0 {
		t.Fatalf("failed wire add must count an upsertFail, stats=%+v", st)
	}
}
