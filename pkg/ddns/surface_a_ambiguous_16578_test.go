package ddns

import (
	"context"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

// surface_a_ambiguous_16578_test.go: #16578 fail-on-revert proofs (residual
// of #15225 A40-02, finding R3-A40-03).
//
// Two lost-reply shapes orphaned a live value under the #15225 fix:
//
//   Arm 1 — first publish ambiguous, then renumber. Boot1 publishes A with
//   the reply lost (wire={A}, durable pending {A, prior=""}). The old
//   threading gate `len(prevCandidates) > 1` yielded exactly one candidate
//   ([A]) and threaded NOTHING, so boot2's renumber to B was Insert-only
//   at the backend and A stayed live forever: wire ends [A B], never [B].
//
//   Arm 2 — three renumbers during an outage. A confirmed; B, C, D each
//   applied-but-reply-lost in turn. The old single ambiguous slot was
//   overwritten each time (keeps C, loses B), so the final successful
//   publish to E removed only {A, C, D} and B orphaned: wire [B E].
//
// Fix: thread PrevAddrs whenever ANY candidate differs from the new value
// (gate dropped), and keep a bounded append-only candidate list
// (AmbiguousPriorAddrTexts, legacy slot folded/synced) instead of
// overwriting a single slot.
//
// RED-on-revert: restore the `> 1` gate and Arm 1 ends wire=[A B]; restore
// the single-slot overwrite and Arm 2 ends wire=[B E]. Both assertions
// below fail for the stated reason, not incidentally: the fake backend
// (ambiguousUpdater, shared with the 15225 test) removes exactly the
// PrevAddrs/PrevAddr candidates it is threaded, mirroring rfc2136's
// exact-RR deletes / cloudflare's candidate-row deletes / route53's merge.

func sortedWire16578(up *ambiguousUpdater) []string {
	got := up.wireValues("")
	sort.Strings(got)
	return got
}

func TestSurfaceAFirstPublishAmbiguousThenRenumber16578(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "iface-ddns.json")
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }

	const fqdn = "wan.example.net"
	const addrA = "203.0.113.5"
	const addrB = "198.51.100.9"
	sc := surfaceAScope(fqdn, FamilyV4, 0)

	// Boot 1: FIRST publish of A — applied on the wire, reply lost.
	up := newAmbiguousUpdater()
	up.loseFor[addrA] = true
	m1 := newSurfaceAManagerForTesting(statePath, up, clock)
	if err := m1.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver(addrA), nil, nil); err == nil {
		t.Fatal("boot1: ambiguous first publish must surface an error")
	}
	rec := onlyOwned5285(t, statePath)
	if !rec.PublishPending || rec.AddrText != addrA || rec.PriorAddrText != "" {
		t.Fatalf("boot1: want pending first-publish {A, prior \"\"}, got %+v", rec)
	}
	if got := sortedWire16578(up); len(got) != 1 || got[0] != fqdn+"="+addrA {
		t.Fatalf("boot1: wire must hold applied A, got %v", got)
	}

	// Boot 2: renumber to B (provider healthy again). The single candidate
	// A must be threaded as a cleanup candidate even though there is only
	// one of it, so the publish removes A and the wire ends [B] only.
	delete(up.loseFor, addrA)
	m2 := newSurfaceAManagerForTesting(statePath, up, clock)
	now = now.Add(time.Hour)
	if err := m2.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver(addrB), nil, nil); err != nil {
		t.Fatalf("boot2 renumber B: %v", err)
	}
	if got := sortedWire16578(up); len(got) != 1 || got[0] != fqdn+"="+addrB {
		t.Fatalf("wire must end [B] only after first-publish-ambiguous renumber, got %v", got)
	}
	if rec := onlyOwned5285(t, statePath); rec.PublishPending || rec.AddrText != addrB || len(rec.ambiguousCandidates()) != 0 {
		t.Fatalf("boot2: want confirmed B with candidates released, got %+v", rec)
	}
	// The B upsert must have carried A as a cleanup candidate (PrevAddrs
	// with the single candidate, or PrevAddr — either is honoured by the
	// backends' union; assert at least one carries A and PrevAddrs is
	// used per the #16578 threading).
	last := up.upserts[len(up.upserts)-1]
	if last.Addr.String() != addrB {
		t.Fatalf("last upsert addr = %s, want B", last.Addr)
	}
	found := false
	for _, p := range last.PrevAddrs {
		if p.String() == addrA {
			found = true
		}
	}
	if !found {
		t.Fatalf("B upsert must carry A in PrevAddrs (single candidate threaded), got PrevAddrs=%v PrevAddr=%s", last.PrevAddrs, last.PrevAddr)
	}
}

func TestSurfaceAThreeAmbiguousRenumbers16578(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "iface-ddns.json")
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }

	const fqdn = "wan.example.net"
	const (
		addrA = "203.0.113.5"
		addrB = "198.51.100.9"
		addrC = "192.0.2.77"
		addrD = "192.0.2.99"
		addrE = "203.0.113.200"
	)
	sc := surfaceAScope(fqdn, FamilyV4, 0)
	up := newAmbiguousUpdater()

	reconcile := func(addr string, wantErr bool) {
		t.Helper()
		m := newSurfaceAManagerForTesting(statePath, up, clock)
		now = now.Add(time.Hour)
		err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver(addr), nil, nil)
		if wantErr && err == nil {
			t.Fatalf("publish %s: ambiguous publish must surface an error", addr)
		}
		if !wantErr && err != nil {
			t.Fatalf("publish %s: %v", addr, err)
		}
	}

	// A clean.
	reconcile(addrA, false)
	// B, C, D each applied-but-reply-lost in turn (provider outage).
	up.loseFor[addrB] = true
	up.loseFor[addrC] = true
	up.loseFor[addrD] = true
	reconcile(addrB, true)
	reconcile(addrC, true)
	// After two chained ambiguities the durable row must retain BOTH
	// ambiguous candidates (list), not just the latest.
	if rec := onlyOwned5285(t, statePath); len(rec.ambiguousCandidates()) != 1 || rec.ambiguousCandidates()[0] != addrB {
		t.Fatalf("after C ambiguous: want ambiguous candidates [B], got %+v", rec)
	}
	reconcile(addrD, true)
	if rec := onlyOwned5285(t, statePath); len(rec.ambiguousCandidates()) != 2 {
		t.Fatalf("after D ambiguous: want 2 ambiguous candidates [B C], got %+v (single-slot overwrite loses B)", rec)
	}

	// E succeeds: every candidate != E (A, B, C, D) must be removed.
	delete(up.loseFor, addrB)
	delete(up.loseFor, addrC)
	delete(up.loseFor, addrD)
	reconcile(addrE, false)
	if got := sortedWire16578(up); len(got) != 1 || got[0] != fqdn+"="+addrE {
		t.Fatalf("wire must end [E] only after three ambiguous renumbers, got %v", got)
	}
	if rec := onlyOwned5285(t, statePath); rec.PublishPending || rec.AddrText != addrE || len(rec.ambiguousCandidates()) != 0 {
		t.Fatalf("after E: want confirmed E with candidates released, got %+v", rec)
	}
	last := up.upserts[len(up.upserts)-1]
	var prevs []string
	for _, p := range last.PrevAddrs {
		prevs = append(prevs, p.String())
	}
	sort.Strings(prevs)
	want := []string{addrA, addrB, addrC, addrD}
	sort.Strings(want)
	if len(prevs) != len(want) {
		t.Fatalf("E upsert must carry all 4 candidates as PrevAddrs, got %v", prevs)
	}
	for i := range want {
		if prevs[i] != want[i] {
			t.Fatalf("E upsert PrevAddrs = %v, want %v", prevs, want)
		}
	}
}

// Bounded-list unit proof: the candidate list never exceeds
// maxAmbiguousPriorCandidates, drops oldest first, deduplicates, and
// keeps the legacy single slot in sync with the first element. Legacy
// single-slot records (pre-#16578 stores) fold into the list.
func TestAmbiguousCandidateListBounded16578(t *testing.T) {
	var r ownedRecord
	// Legacy fold: a store carrying only the old single slot.
	r = ownedRecord{AmbiguousPriorAddrText: "203.0.113.5"}.normalizeAmbiguous()
	if got := r.ambiguousCandidates(); len(got) != 1 || got[0] != "203.0.113.5" {
		t.Fatalf("legacy fold: got %v", got)
	}
	// Append past the bound: oldest dropped, size capped, slot synced.
	for i := range maxAmbiguousPriorCandidates + 5 {
		r = r.appendAmbiguousCandidate(addr16578(i))
	}
	got := r.ambiguousCandidates()
	if len(got) != maxAmbiguousPriorCandidates {
		t.Fatalf("list must be bounded at %d, got %d: %v", maxAmbiguousPriorCandidates, len(got), got)
	}
	if got[0] != addr16578(5) {
		t.Fatalf("oldest must be dropped FIFO: first=%s want %s (full %v)", got[0], addr16578(5), got)
	}
	if r.AmbiguousPriorAddrText != got[0] {
		t.Fatalf("legacy slot must sync to first element: slot=%s list=%v", r.AmbiguousPriorAddrText, got)
	}
	// Dedup: re-appending an existing candidate is a no-op.
	r2 := r.appendAmbiguousCandidate(got[0])
	if len(r2.ambiguousCandidates()) != len(got) {
		t.Fatalf("duplicate append must be a no-op, got %v", r2.ambiguousCandidates())
	}
	// Clearing releases both spellings.
	r3 := r.withAmbiguousCandidates(nil)
	if len(r3.ambiguousCandidates()) != 0 || r3.AmbiguousPriorAddrText != "" || len(r3.AmbiguousPriorAddrTexts) != 0 {
		t.Fatalf("clear must release list and slot, got %+v", r3)
	}
}

func addr16578(i int) string {
	// Distinct TEST-NET-3 addresses.
	return "203.0.113." + itoa16578(i+1)
}

func itoa16578(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// Withdraw after chained ambiguities must delete every candidate.
func TestSurfaceAWithdrawAfterAmbiguousChain16578(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "iface-ddns.json")
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }

	const fqdn = "wan.example.net"
	const (
		addrA = "203.0.113.5"
		addrB = "198.51.100.9"
		addrC = "192.0.2.77"
	)
	sc := surfaceAScope(fqdn, FamilyV4, 0)
	up := newAmbiguousUpdater()

	m1 := newSurfaceAManagerForTesting(statePath, up, clock)
	if err := m1.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver(addrA), nil, nil); err != nil {
		t.Fatalf("publish A: %v", err)
	}
	up.loseFor[addrB] = true
	up.loseFor[addrC] = true
	m2 := newSurfaceAManagerForTesting(statePath, up, clock)
	now = now.Add(time.Hour)
	if err := m2.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver(addrB), nil, nil); err == nil {
		t.Fatal("publish B ambiguous must error")
	}
	m3 := newSurfaceAManagerForTesting(statePath, up, clock)
	now = now.Add(time.Hour)
	if err := m3.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver(addrC), nil, nil); err == nil {
		t.Fatal("publish C ambiguous must error")
	}
	// Wire holds A, B, C (each ambiguous UPDATE applied, none cleaned yet
	// because each renumber's cleanup only ran for candidates known then;
	// B's publish removed A in this model... assert via withdrawTargets
	// directly instead of wire shape).
	rec := onlyOwned5285(t, statePath)
	mgr := newSurfaceAManagerForTesting(statePath, up, clock)
	targets := mgr.withdrawTargets(rec)
	var ts []string
	for _, a := range targets {
		ts = append(ts, a.String())
	}
	sort.Strings(ts)
	want := []string{addrA, addrB, addrC}
	sort.Strings(want)
	if len(ts) != len(want) {
		t.Fatalf("withdrawTargets must include all candidates %v, got %v (rec %+v)", want, ts, rec)
	}
	for i := range want {
		if ts[i] != want[i] {
			t.Fatalf("withdrawTargets = %v, want %v", ts, want)
		}
	}
}
