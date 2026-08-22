package ddns

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// TestCorruptStateDegradedSurvivesRestart is the #4873 (A) fail-on-revert test.
//
// A corrupt ownership state file is quarantined (renamed to `.corrupt-<ts>`) and
// the manager fails closed in-process. But the fail-closed posture must ALSO be
// DURABLE: quarantine removes the only canonical file, so a naive reload on the
// next boot would find no file, load an EMPTY store with a nil error, and
// silently resume publish/withdraw with all prior ownership forgotten. A durable
// `.degraded` marker keeps a restarted manager degraded until an operator
// resolves it.
//
// fail-on-revert: without the durable marker the SECOND construction (simulating
// a restart over the same directory, canonical file already quarantined away)
// comes up NOT degraded, and its reconcile publishes the lease — the exact
// fail-open. Both assertions below then fail.
func TestCorruptStateDegradedSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	clock := func() time.Time { return time.Unix(1_700_000_000, 0) }

	// Boot 1: a corrupt store left behind by a crash / disk fault.
	writeCSV(t, statePath, "{ this is not valid json at all")
	m1 := newManagerForTesting(
		(&fakeLeaseSource{v4: laptopMacLease()}).parser(),
		newFakeUpdater(),
		statePath,
		filepath.Join(dir, "leases4.csv"),
		filepath.Join(dir, "leases6.csv"),
		"node0",
		clock,
	)
	if !m1.degraded {
		t.Fatal("boot 1: manager must be DEGRADED after loading a corrupt state file")
	}
	// The corrupt file must have been quarantined away.
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatalf("boot 1: corrupt state file must be quarantined (renamed away); stat err=%v", err)
	}
	// A DURABLE degraded marker must exist beside the store.
	if _, err := os.Stat(degradedMarkerPath(statePath)); err != nil {
		t.Fatalf("boot 1: durable degraded marker must be written; stat err=%v", err)
	}

	// Boot 2: a brand-new manager over the SAME directory (simulating a
	// restart). The canonical file is gone (quarantined), so ONLY the durable
	// marker can keep it fail-closed.
	up2 := newFakeUpdater()
	m2 := newManagerForTesting(
		(&fakeLeaseSource{v4: laptopMacLease()}).parser(),
		up2,
		statePath,
		filepath.Join(dir, "leases4.csv"),
		filepath.Join(dir, "leases6.csv"),
		"node0",
		clock,
	)
	if !m2.degraded {
		t.Fatal("boot 2 (restart): manager must STILL be degraded from the durable marker, " +
			"not resume clean-but-empty (fail-open)")
	}

	// The restarted manager must not proceed as owner/updated: an ENABLED
	// reconcile with a live lease must publish and withdraw NOTHING.
	cfg := &config.DHCPServerConfig{
		DynamicDNS: &config.DHCPDynamicDNSConfig{
			Enabled:    true,
			Domain:     "example.com",
			TTLSeconds: 300,
		},
	}
	if err := m2.Reconcile(context.Background(), cfg); err == nil {
		t.Fatal("boot 2: reconcile must return an error while degraded (fail closed)")
	}
	if names := up2.upsertNames(); len(names) != 0 {
		t.Fatalf("boot 2: degraded manager must NOT publish any record, got upserts %v", names)
	}
	if names := up2.deleteNames(); len(names) != 0 {
		t.Fatalf("boot 2: degraded manager must NOT withdraw any record, got deletes %v", names)
	}
	// The reconcile must NOT recreate a fresh (empty) canonical state file.
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatal("boot 2: degraded manager must not recreate the ownership state file")
	}
}

// TestDegradedMarkerGatesEvenWithValidState confirms the durable marker is
// authoritative: even if a syntactically VALID canonical state file is present,
// a lingering `.degraded` marker keeps the manager fail-closed until an operator
// removes it (explicit resolution). This guards against a partial "recovery"
// that restores state bytes but leaves the fail-closed signal in place.
func TestDegradedMarkerGatesEvenWithValidState(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	// A valid, empty-but-parseable state file.
	writeCSV(t, statePath, `{"version":1,"records":[]}`)
	// And a durable degraded marker from a prior corruption event.
	if err := writeDegradedMarker(statePath, "ddns: prior corruption not yet resolved"); err != nil {
		t.Fatalf("writeDegradedMarker: %v", err)
	}

	st, degraded, reason := loadStateOrDegrade(statePath, func() time.Time { return time.Unix(1, 0) })
	if !degraded {
		t.Fatal("a present degraded marker must fail closed even with a valid state file")
	}
	if reason == "" {
		t.Fatal("degraded reason must be surfaced from the marker")
	}
	if st == nil {
		t.Fatal("loadStateOrDegrade must still return a constructible store")
	}
	// The valid canonical file must NOT be quarantined (it was not corrupt) — a
	// marker gate is not a re-classification.
	if _, err := os.Stat(statePath); err != nil {
		t.Fatalf("valid state file must be left in place under a marker gate; stat err=%v", err)
	}
}

// TestQuarantineBadStateSameSecondCollisionDoesNotOverwrite pins #6218 item 6:
// two quarantine events landing in the same wall-clock SECOND (the stamp's
// resolution) must not let the second os.Rename silently overwrite the first
// quarantine file — that would destroy the only forensic copy of the FIRST
// corruption. Both corrupt files must survive as distinct paths.
//
// RED on revert: restoring the bare `os.Rename(path, dst)` with no collision
// probe makes the second quarantineBadState call rename over the first
// quarantine file, so the first quarantined file's content ("first-corrupt")
// is lost — the byte-content assertion below fails.
func TestQuarantineBadStateSameSecondCollisionDoesNotOverwrite(t *testing.T) {
	dir := t.TempDir()
	now := time.Unix(1_700_000_000, 0)

	path1 := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path1, []byte("first-corrupt"), 0o600); err != nil {
		t.Fatalf("write path1: %v", err)
	}
	q1, err := quarantineBadState(path1, now)
	if err != nil {
		t.Fatalf("quarantineBadState (first): %v", err)
	}

	// A second corrupt file at the SAME canonical path, quarantined at the
	// SAME `now` (same-second collision) — simulating a rapid restart loop
	// within one wall-clock second.
	path2 := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path2, []byte("second-corrupt"), 0o600); err != nil {
		t.Fatalf("write path2: %v", err)
	}
	q2, err := quarantineBadState(path2, now)
	if err != nil {
		t.Fatalf("quarantineBadState (second): %v", err)
	}

	if q1 == q2 {
		t.Fatalf("both quarantine calls resolved to the SAME path %q; second must not collide with first", q1)
	}
	b1, err := os.ReadFile(q1)
	if err != nil {
		t.Fatalf("read first quarantine file %q: %v", q1, err)
	}
	if string(b1) != "first-corrupt" {
		t.Fatalf("first quarantine file %q was overwritten; got %q, want %q", q1, b1, "first-corrupt")
	}
	b2, err := os.ReadFile(q2)
	if err != nil {
		t.Fatalf("read second quarantine file %q: %v", q2, err)
	}
	if string(b2) != "second-corrupt" {
		t.Fatalf("second quarantine file %q has wrong content; got %q, want %q", q2, b2, "second-corrupt")
	}
}
