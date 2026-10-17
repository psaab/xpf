package userspace

import (
	"math"
	"path/filepath"
	"testing"
	"time"
)

// #14580 manager half: a forwarded clear whose generation jumps implausibly
// far beyond the observed peer watermark is refused (error + counter), the
// watermark is NOT persisted, and the local clear does not run. A genuine
// +1 advance is accepted. A lease batch below the watermark is dropped and
// counted/logged rather than silently discarded.
//
// Fail-on-revert: remove the jump bound and the MaxUint64 clear persists
// RemoteGenerations[origin]=MaxUint64; remove the counter and the stale drop
// is invisible again.
func TestPersistentNatForgedGenerationJumpRefused14580(t *testing.T) {
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

	jumpsBefore := PersistentNatGenerationJumpsRejected()
	if _, _, _, err := m.ClearPersistentNATLeasesWithGeneration(peerOrigin, math.MaxUint64); err == nil {
		t.Fatal("forged MaxUint64 forwarded clear was accepted")
	}
	if got := PersistentNatGenerationJumpsRejected(); got != jumpsBefore+1 {
		t.Fatalf("jumps rejected = %d, want %d", got, jumpsBefore+1)
	}
	// Refused BEFORE the helper: no clear request was issued.
	select {
	case req := <-helper.requests:
		t.Fatalf("forged clear reached helper as %q", req.Type)
	case <-time.After(25 * time.Millisecond):
	}

	// Watermark unpoisoned across restart: a genuine generation-9 batch is
	// still admitted (it would be silently dropped had MaxUint64 persisted).
	restarted, restartHelper := persistentNatGenerationManager11486(t, path)
	batch.Generation = 9
	if err := restarted.ImportPersistentNatLeaseBatch(batch); err != nil {
		t.Fatalf("genuine generation 9 import after refused forgery: %v", err)
	}
	// A newer generation first completes the pending clear barrier, then imports.
	if got := (<-restartHelper.requests).Type; got != "clear_persistent_nat_leases" {
		t.Fatalf("generation 9 helper request = %q, want clear_persistent_nat_leases", got)
	}
	if req := <-restartHelper.requests; req.Type != "import_idle_leases" {
		t.Fatalf("generation 9 helper import = %q, want import_idle_leases", req.Type)
	}

	// A genuine +1 forwarded clear is accepted.
	if _, _, _, err := restarted.ClearPersistentNATLeasesWithGeneration(peerOrigin, 10); err != nil {
		t.Fatalf("genuine +1 forwarded clear: %v", err)
	}
	if got := (<-restartHelper.requests).Type; got != "clear_persistent_nat_leases" {
		t.Fatalf("genuine clear helper request = %q", got)
	}
}

func TestPersistentNatStaleBatchDropCounted14580(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nat-generation.json")
	m, helper := persistentNatGenerationManager11486(t, path)
	peerOrigin := "0123456789abcdef0123456789abcdef"
	batch := PersistentNatLeaseBatch{OriginID: peerOrigin, Generation: 8, Leases: []IdleLeaseWire{scopedLease10018()}}
	if err := m.ImportPersistentNatLeaseBatch(batch); err != nil {
		t.Fatalf("import generation 8: %v", err)
	}
	<-helper.requests // clear
	<-helper.requests // import

	dropsBefore := PersistentNatStaleBatchDrops()
	batch.Generation = 7
	if err := m.ImportPersistentNatLeaseBatch(batch); err != nil {
		t.Fatalf("stale import should drop without error: %v", err)
	}
	if got := PersistentNatStaleBatchDrops(); got != dropsBefore+1 {
		t.Fatalf("stale drops = %d, want %d (drop must be counted, not silent)", got, dropsBefore+1)
	}
	select {
	case req := <-helper.requests:
		t.Fatalf("stale batch reached helper as %q", req.Type)
	case <-time.After(25 * time.Millisecond):
	}
}
