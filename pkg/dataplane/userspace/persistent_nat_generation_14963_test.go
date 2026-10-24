package userspace

import (
	"fmt"
	"math"
	"path/filepath"
	"testing"
	"time"
)

// #14963: ImportPersistentNatLeaseBatch enforced neither cap that the
// forwarded-clear path (ClearPersistentNATLeasesWithGeneration) already
// applied, so the batch path was a strictly weaker entry point to the same
// durable watermark state:
//
//   - Generation jump: one forged/corrupted batch at MaxUint64 for a KNOWN
//     peer advanced the durable watermark straight to MaxUint64. The import
//     cleared every local lease (PendingRemote barrier) and persisted the
//     poisoned high-water mark; every genuine batch below it was then
//     dropped as stale indefinitely, and the poison survived restart —
//     post-restart persistent-NAT bricking.
//   - Peer count: batch imports grew RemoteGenerations without bound. A
//     state file already holding more than maxPersistentNatGenerationPeers11486
//     peers then failed the loader peer-limit check on every restart,
//     bricking lease export/import.
//
// Fail-on-revert: remove the jump guard and the MaxUint64 batch is accepted,
// the watermark persists at MaxUint64, and the genuine generation-9 batch
// after restart is silently dropped as stale; remove the peer-cap guard and
// the 17th distinct origin is accepted (and the state file then fails to
// load after restart).
func TestPersistentNatBatchForgedGenerationJumpRefused14963(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nat-generation.json")
	m, helper := persistentNatGenerationManager11486(t, path)
	peerOrigin := "0123456789abcdef0123456789abcdef"

	// Establish watermark generation 8 via a genuine lease batch.
	batch := PersistentNatLeaseBatch{OriginID: peerOrigin, Generation: 8, Leases: []IdleLeaseWire{scopedLease10018()}}
	if err := m.ImportPersistentNatLeaseBatch(batch); err != nil {
		t.Fatalf("import generation 8: %v", err)
	}
	if got := (<-helper.requests).Type; got != "clear_persistent_nat_leases" {
		t.Fatalf("generation 8 helper request = %q, want clear", got)
	}
	if req := <-helper.requests; req.Type != "import_idle_leases" {
		t.Fatalf("generation 8 helper import = %q", req.Type)
	}

	// One forged batch at MaxUint64 must be refused with an error, counted,
	// and must NOT reach the helper (no local clear) or persist.
	jumpsBefore := PersistentNatGenerationJumpsRejected()
	forged := PersistentNatLeaseBatch{OriginID: peerOrigin, Generation: math.MaxUint64, Leases: []IdleLeaseWire{scopedLease10018()}}
	if err := m.ImportPersistentNatLeaseBatch(forged); err == nil {
		t.Fatal("forged MaxUint64 lease batch was accepted")
	}
	if got := PersistentNatGenerationJumpsRejected(); got != jumpsBefore+1 {
		t.Fatalf("jumps rejected = %d, want %d", got, jumpsBefore+1)
	}
	select {
	case req := <-helper.requests:
		t.Fatalf("forged batch reached helper as %q", req.Type)
	case <-time.After(25 * time.Millisecond):
	}

	// Watermark unpoisoned across restart: a genuine generation-9 batch is
	// still admitted (it would be silently dropped as stale had MaxUint64
	// persisted).
	restarted, restartHelper := persistentNatGenerationManager11486(t, path)
	batch.Generation = 9
	if err := restarted.ImportPersistentNatLeaseBatch(batch); err != nil {
		t.Fatalf("genuine generation 9 import after refused forgery: %v", err)
	}
	if got := (<-restartHelper.requests).Type; got != "clear_persistent_nat_leases" {
		t.Fatalf("generation 9 helper request = %q, want clear_persistent_nat_leases", got)
	}
	if req := <-restartHelper.requests; req.Type != "import_idle_leases" {
		t.Fatalf("generation 9 helper import = %q, want import_idle_leases", req.Type)
	}

	// Control: a jump exactly at the bound is admitted (genuine peers that
	// cleared many times while this node was partitioned), and one past the
	// bound is refused.
	batch.Generation = 9 + maxPersistentNatGenerationJump14580
	if err := restarted.ImportPersistentNatLeaseBatch(batch); err != nil {
		t.Fatalf("at-bound generation jump import: %v", err)
	}
	if got := (<-restartHelper.requests).Type; got != "clear_persistent_nat_leases" {
		t.Fatalf("at-bound helper request = %q, want clear_persistent_nat_leases", got)
	}
	if req := <-restartHelper.requests; req.Type != "import_idle_leases" {
		t.Fatalf("at-bound helper import = %q, want import_idle_leases", req.Type)
	}
	batch.Generation += maxPersistentNatGenerationJump14580 + 1
	if err := restarted.ImportPersistentNatLeaseBatch(batch); err == nil {
		t.Fatal("over-bound generation jump batch was accepted")
	}
	select {
	case req := <-restartHelper.requests:
		t.Fatalf("over-bound batch reached helper as %q", req.Type)
	case <-time.After(25 * time.Millisecond):
	}

	// Control: an UNSEEN origin's first batch is accepted at any generation
	// (no watermark to jump from; first contact with a long-lived peer).
	newOrigin := "fedcba9876543210fedcba9876543210"
	first := PersistentNatLeaseBatch{OriginID: newOrigin, Generation: math.MaxUint64, Leases: []IdleLeaseWire{scopedLease10018()}}
	if err := restarted.ImportPersistentNatLeaseBatch(first); err != nil {
		t.Fatalf("unseen origin first batch at MaxUint64: %v", err)
	}
	if got := (<-restartHelper.requests).Type; got != "clear_persistent_nat_leases" {
		t.Fatalf("unseen origin helper request = %q, want clear_persistent_nat_leases", got)
	}
	if req := <-restartHelper.requests; req.Type != "import_idle_leases" {
		t.Fatalf("unseen origin helper import = %q, want import_idle_leases", req.Type)
	}
}

func TestPersistentNatBatchPeerLimitEnforced14963(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nat-generation.json")
	m, helper := persistentNatGenerationManager11486(t, path)

	// Fill the peer table to the cap with distinct origins at generation 1.
	for i := range maxPersistentNatGenerationPeers11486 {
		origin := fmt.Sprintf("%032x", i+1)
		batch := PersistentNatLeaseBatch{OriginID: origin, Generation: 1, Leases: []IdleLeaseWire{scopedLease10018()}}
		if err := m.ImportPersistentNatLeaseBatch(batch); err != nil {
			t.Fatalf("import peer %d: %v", i, err)
		}
		if got := (<-helper.requests).Type; got != "clear_persistent_nat_leases" {
			t.Fatalf("peer %d helper request = %q, want clear_persistent_nat_leases", i, got)
		}
		if req := <-helper.requests; req.Type != "import_idle_leases" {
			t.Fatalf("peer %d helper import = %q", i, req.Type)
		}
	}

	// The next distinct origin must be refused with an error and must NOT
	// reach the helper or be persisted.
	over := PersistentNatLeaseBatch{
		OriginID:   fmt.Sprintf("%032x", maxPersistentNatGenerationPeers11486+1),
		Generation: 1, Leases: []IdleLeaseWire{scopedLease10018()},
	}
	if err := m.ImportPersistentNatLeaseBatch(over); err == nil {
		t.Fatal("batch from peer beyond the cap was accepted")
	}
	select {
	case req := <-helper.requests:
		t.Fatalf("over-cap batch reached helper as %q", req.Type)
	case <-time.After(25 * time.Millisecond):
	}

	// The state file still loads after restart (pre-fix it held 17 peers and
	// the loader rejected it on every restart), and a KNOWN peer at the cap
	// is still admitted — the cap bounds distinct origins, not traffic.
	restarted, restartHelper := persistentNatGenerationManager11486(t, path)
	known := PersistentNatLeaseBatch{
		OriginID:   fmt.Sprintf("%032x", maxPersistentNatGenerationPeers11486),
		Generation: 2, Leases: []IdleLeaseWire{scopedLease10018()},
	}
	if err := restarted.ImportPersistentNatLeaseBatch(known); err != nil {
		t.Fatalf("known peer import at cap after restart: %v", err)
	}
	if got := (<-restartHelper.requests).Type; got != "clear_persistent_nat_leases" {
		t.Fatalf("known peer helper request = %q, want clear_persistent_nat_leases", got)
	}
	if req := <-restartHelper.requests; req.Type != "import_idle_leases" {
		t.Fatalf("known peer helper import = %q", req.Type)
	}

	// Control: the over-cap origin is still refused after restart.
	if err := restarted.ImportPersistentNatLeaseBatch(over); err == nil {
		t.Fatal("batch from peer beyond the cap was accepted after restart")
	}
	select {
	case req := <-restartHelper.requests:
		t.Fatalf("over-cap batch after restart reached helper as %q", req.Type)
	case <-time.After(25 * time.Millisecond):
	}
}

// #16417: the gen-0 first-contact arm persisted a new RemoteGenerations key
// without the peer cap (the cap was guarded by batch.Generation > 0), so 17+
// distinct gen-0 origins wrote a state file the loader rejects on every
// restart. Fail-on-revert: restore the `batch.Generation > 0` condition and
// the 17th gen-0 origin is accepted (20/20 accepted pre-fix); the restarted
// manager then fails to load ("exceeds peer limit") and Export errors.
func TestPersistentNatBatchGen0PeerLimitEnforced16417(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nat-generation.json")
	m, helper := persistentNatGenerationManager11486(t, path)

	// A fresh state file starts with PendingLocalClear set, so the first
	// import completes exactly one local clear barrier; after that, gen-0
	// first contact itself issues no helper request (no clear barrier, no
	// protocol-gated lease import for an empty batch). Fill the peer table
	// to the cap with distinct origins at generation 0.
	for i := range maxPersistentNatGenerationPeers11486 {
		origin := fmt.Sprintf("%032x", i+1)
		batch := PersistentNatLeaseBatch{OriginID: origin, Generation: 0}
		if err := m.ImportPersistentNatLeaseBatch(batch); err != nil {
			t.Fatalf("import gen-0 peer %d: %v", i, err)
		}
		if i == 0 {
			if got := (<-helper.requests).Type; got != "clear_persistent_nat_leases" {
				t.Fatalf("first import helper request = %q, want one-time local clear barrier", got)
			}
		}
	}
	select {
	case req := <-helper.requests:
		t.Fatalf("gen-0 first contact reached helper as %q, want no further barrier", req.Type)
	case <-time.After(25 * time.Millisecond):
	}
	m.mu.Lock()
	gotOrigins := len(m.persistentNatLeaseGeneration.RemoteGenerations)
	m.mu.Unlock()
	if gotOrigins != maxPersistentNatGenerationPeers11486 {
		t.Fatalf("remote origins = %d, want cap %d", gotOrigins, maxPersistentNatGenerationPeers11486)
	}

	// The next distinct gen-0 origin must be refused with an error and must
	// NOT reach the helper, be persisted, or consume a peer slot.
	over := PersistentNatLeaseBatch{
		OriginID:   fmt.Sprintf("%032x", maxPersistentNatGenerationPeers11486+1),
		Generation: 0,
	}
	if err := m.ImportPersistentNatLeaseBatch(over); err == nil {
		t.Fatal("gen-0 batch from peer beyond the cap was accepted")
	}
	select {
	case req := <-helper.requests:
		t.Fatalf("over-cap gen-0 batch reached helper as %q", req.Type)
	case <-time.After(25 * time.Millisecond):
	}

	// The state file still loads after restart (pre-fix it held 17+ gen-0
	// peers and the loader rejected it on every restart). Prove the load
	// directly under the restarted manager's lock — the loader is the
	// function the peer limit bricks — then a KNOWN gen-0 peer's empty
	// generation-1 advance is still admitted through the clear barrier,
	// and the over-cap origin stays refused.
	restarted, restartHelper := persistentNatGenerationManager11486(t, path)
	restarted.mu.Lock()
	loadErr := restarted.loadPersistentNatLeaseGenerationLocked()
	loadedOrigins := len(restarted.persistentNatLeaseGeneration.RemoteGenerations)
	restarted.mu.Unlock()
	if loadErr != nil {
		t.Fatalf("restart load with capped gen-0 peers: %v", loadErr)
	}
	if loadedOrigins != maxPersistentNatGenerationPeers11486 {
		t.Fatalf("restart loaded origins = %d, want cap %d", loadedOrigins, maxPersistentNatGenerationPeers11486)
	}
	known := PersistentNatLeaseBatch{
		OriginID:   fmt.Sprintf("%032x", maxPersistentNatGenerationPeers11486),
		Generation: 1,
	}
	if err := restarted.ImportPersistentNatLeaseBatch(known); err != nil {
		t.Fatalf("known gen-0 peer generation-1 import at cap after restart: %v", err)
	}
	if got := (<-restartHelper.requests).Type; got != "clear_persistent_nat_leases" {
		t.Fatalf("known peer helper request = %q, want clear_persistent_nat_leases", got)
	}
	if got := len(restartHelper.requests); got != 0 {
		t.Fatalf("empty known-peer advance issued %d extra helper requests", got)
	}
	restarted.mu.Lock()
	knownGen := restarted.persistentNatLeaseGeneration.RemoteGenerations[known.OriginID]
	restartOrigins := len(restarted.persistentNatLeaseGeneration.RemoteGenerations)
	restarted.mu.Unlock()
	if knownGen != 1 || restartOrigins != maxPersistentNatGenerationPeers11486 {
		t.Fatalf("after known advance: generation=%d origins=%d, want 1/%d",
			knownGen, restartOrigins, maxPersistentNatGenerationPeers11486)
	}

	// Control: the over-cap gen-0 origin is still refused after restart.
	if err := restarted.ImportPersistentNatLeaseBatch(over); err == nil {
		t.Fatal("gen-0 batch from peer beyond the cap was accepted after restart")
	}
	select {
	case req := <-restartHelper.requests:
		t.Fatalf("over-cap gen-0 batch after restart reached helper as %q", req.Type)
	case <-time.After(25 * time.Millisecond):
	}
}
