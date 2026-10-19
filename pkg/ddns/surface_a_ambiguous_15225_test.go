package ddns

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

// surface_a_ambiguous_15225_test.go: #15225 A40-02 fail-on-revert proofs.
//
// An ambiguous publish (the wire UPDATE was applied but its reply was lost,
// so publishLocked sees an error) must NOT roll the durable row back to the
// single confirmed prior: the new value may already be live. The fix keeps
// every ambiguous candidate as a cleanup key (PrevAddrs on the wire record,
// AmbiguousPriorAddrText on the durable row) and the next renumber removes
// ALL candidates != the new value, so both probe sequences end wire=[C].
//
// RED-on-revert: restore the single-PrevAddr threading + unconditional
// rollback and boot3 below publishes C removing only B, leaving the
// actually-live A orphaned forever (wire ends [A C], never [C]).

// ambiguousUpdater simulates a provider whose UPDATE is applied to its
// wire set but whose reply is lost for the flagged addresses: UpsertLease
// mutates the wire set, then returns an error for those addresses.
type ambiguousUpdater struct {
	wire    map[string]bool // "fqdn=addr" values currently live at the provider
	loseFor map[string]bool // addr -> apply-then-report-error
	upserts []LeaseDNSRecord
}

func newAmbiguousUpdater() *ambiguousUpdater {
	return &ambiguousUpdater{wire: map[string]bool{}, loseFor: map[string]bool{}}
}

func (a *ambiguousUpdater) UpsertLease(_ context.Context, rec LeaseDNSRecord) error {
	a.upserts = append(a.upserts, rec)
	key := rec.FQDN + "=" + rec.Addr.Unmap().String()
	a.wire[key] = true
	for _, p := range rec.PrevAddrs {
		if p.IsValid() && p.Unmap() != rec.Addr.Unmap() {
			delete(a.wire, rec.FQDN+"="+p.Unmap().String())
		}
	}
	if rec.PrevAddr.IsValid() && rec.PrevAddr.Unmap() != rec.Addr.Unmap() {
		delete(a.wire, rec.FQDN+"="+rec.PrevAddr.Unmap().String())
	}
	if a.loseFor[rec.Addr.Unmap().String()] {
		return errors.New("fake: reply lost after UPDATE applied")
	}
	return nil
}

func (a *ambiguousUpdater) DeleteLease(_ context.Context, rec LeaseDNSRecord) error {
	delete(a.wire, rec.FQDN+"="+rec.Addr.Unmap().String())
	return nil
}

func (a *ambiguousUpdater) wireValues(fqdn string) []string {
	var out []string
	for k := range a.wire {
		out = append(out, k)
	}
	_ = fqdn
	return out
}

func TestSurfaceAAmbiguousPublishThenRenumberCleansAll15225(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "iface-ddns.json")
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }

	const fqdn = "wan.example.net"
	const addrA = "203.0.113.5"
	const addrB = "198.51.100.9"
	const addrC = "192.0.2.77"
	sc := surfaceAScope(fqdn, FamilyV4, 0)

	// Boot 1: publish A cleanly.
	up := newAmbiguousUpdater()
	m1 := newSurfaceAManagerForTesting(statePath, up, clock)
	if err := m1.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver(addrA), nil, nil); err != nil {
		t.Fatalf("boot1 publish A: %v", err)
	}
	if rec := onlyOwned5285(t, statePath); rec.PublishPending || rec.AddrText != addrA {
		t.Fatalf("boot1: want confirmed A, got %+v", rec)
	}

	// Boot 2: renumber A->B, but the B UPDATE is applied and its reply is
	// lost. publishLocked sees an error; the durable row must retain BOTH
	// candidates (A confirmed prior, B ambiguous desired) instead of
	// rolling back to A alone.
	up.loseFor[addrB] = true
	m2 := newSurfaceAManagerForTesting(statePath, up, clock)
	now = now.Add(time.Hour)
	if err := m2.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver(addrB), nil, nil); err == nil {
		t.Fatal("boot2: ambiguous publish must surface an error")
	}
	rec := onlyOwned5285(t, statePath)
	if !rec.PublishPending || rec.AddrText != addrB || rec.PriorAddrText != addrA {
		t.Fatalf("boot2: want pending {B, prior A} retaining both candidates, got %+v", rec)
	}

	// Boot 3: renumber to C. The publish must remove ALL candidates != C
	// (both A and B), ending with wire=[C] only.
	delete(up.loseFor, addrB)
	m3 := newSurfaceAManagerForTesting(statePath, up, clock)
	now = now.Add(time.Hour)
	if err := m3.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver(addrC), nil, nil); err != nil {
		t.Fatalf("boot3 renumber C: %v", err)
	}
	got := up.wireValues(fqdn)
	if len(got) != 1 || got[0] != fqdn+"="+addrC {
		t.Fatalf("wire must end [C] only after ambiguous renumber, got %v", got)
	}
	if rec := onlyOwned5285(t, statePath); rec.PublishPending || rec.AddrText != addrC || rec.PriorAddrText != "" {
		t.Fatalf("boot3: want confirmed C with priors released, got %+v", rec)
	}
	// The C upsert must have carried both cleanup candidates.
	last := up.upserts[len(up.upserts)-1]
	if last.Addr.String() != addrC {
		t.Fatalf("last upsert addr = %s, want C", last.Addr)
	}
	var prevs []string
	for _, p := range last.PrevAddrs {
		prevs = append(prevs, p.String())
	}
	if len(prevs) != 2 {
		t.Fatalf("C upsert must carry both ambiguous candidates as PrevAddrs, got %v (PrevAddr=%s)", prevs, last.PrevAddr)
	}
}

// Definitive rejection control: a conflict refusal (name owned by another
// party) is NOT ambiguous — nothing was applied — so the durable row rolls
// back to the confirmed prior exactly as before.
func TestSurfaceADefinitiveRejectionStillRollsBack15225(t *testing.T) {
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
	fu.failUpd[fqdn] = false
	// Definitive refusal via the conflict sentinel.
	refuser := &refusingUpdater{err: errDDNSConflictRefused}
	m2 := newSurfaceAManagerForTesting(statePath, refuser, clock)
	now = now.Add(time.Hour)
	if err := m2.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver(addrB), nil, nil); err == nil {
		t.Fatal("conflict refusal must surface an error")
	}
	rec := onlyOwned5285(t, statePath)
	if rec.PublishPending || rec.AddrText != addrA {
		t.Fatalf("definitive rejection must roll back to confirmed A, got %+v", rec)
	}
}

type refusingUpdater struct{ err error }

func (r *refusingUpdater) UpsertLease(context.Context, LeaseDNSRecord) error { return r.err }
func (r *refusingUpdater) DeleteLease(context.Context, LeaseDNSRecord) error { return nil }

var _ = netip.MustParseAddr
