package ddns

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// #2691 P2 Surface A engine tests. Everything is driven through a fakeUpdater
// (the spine's test seam) + a synthetic AddressObserver — no network, no DNS,
// no netlink. These are the fail-on-revert proofs for the engine discipline the
// plan requires: change-detection, forced-refresh, error backoff, replace (not
// withdraw-then-add) on address change, withdraw on config removal / address
// loss, and the per-RG HA gate (publish/never-withdraw).

func newSurfaceATestManager(t *testing.T, up DNSUpdater, now func() time.Time) *SurfaceAManager {
	t.Helper()
	dir := t.TempDir()
	return newSurfaceAManagerForTesting(filepath.Join(dir, "iface-ddns.json"), up, now)
}

func surfaceAScope(fqdn string, family Family, rg int) SurfaceAScope {
	return SurfaceAScope{
		Key: ScopeKey{
			Family:    family,
			Interface: "ge-0-0-2",
			Unit:      50,
			RGOwner:   rg,
			PolicyID:  "corp-2136",
			// The published name is part of the Surface A scope identity (#2903):
			// Key.FQDN must equal SurfaceAScope.FQDN so a hostname change is a new
			// scope (old withdrawn, new published), not an orphaning in-place rename.
			FQDN: fqdn,
		},
		FQDN:   fqdn,
		TTL:    300,
		Source: AddressSourceDHCP,
	}
}

// fixedObserver returns a single address for every scope.
func fixedObserver(addr string) AddressObserver {
	a := netip.MustParseAddr(addr)
	return func(context.Context, SurfaceAScope) (AddressObservation, bool) {
		return AddressObservation{Addr: a, Source: AddressSourceDHCP}, true
	}
}

func TestSurfaceAPublishesObservedAddress(t *testing.T) {
	fu := newFakeUpdater()
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceATestManager(t, fu, func() time.Time { return now })

	sc := surfaceAScope("wan.example.net", FamilyV4, 0)
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("203.0.113.5"), nil, nil); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	ups := fu.upsertNames()
	if len(ups) != 1 || ups[0] != "wan.example.net=203.0.113.5" {
		t.Fatalf("expected one publish of wan.example.net=203.0.113.5, got %v", ups)
	}
	if st := m.Stats(); st.UpsertOK != 1 || st.Scopes != 1 {
		t.Fatalf("stats: %+v", st)
	}
}

func TestSurfaceASkipsUnchangedWithinForcedRefresh(t *testing.T) {
	fu := newFakeUpdater()
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceATestManager(t, fu, func() time.Time { return now })
	sc := surfaceAScope("wan.example.net", FamilyV4, 0)
	obs := fixedObserver("203.0.113.5")

	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, obs, nil, nil); err != nil {
		t.Fatalf("Reconcile1: %v", err)
	}
	// Second pass, same address, still inside the forced-refresh floor: NO wire
	// update.
	now = now.Add(time.Minute)
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, obs, nil, nil); err != nil {
		t.Fatalf("Reconcile2: %v", err)
	}
	if got := len(fu.upserts); got != 1 {
		t.Fatalf("unchanged address inside forced-refresh must not republish; got %d upserts", got)
	}
	if st := m.Stats(); st.Skipped != 1 {
		t.Fatalf("expected 1 unchanged skip, got %+v", st)
	}
}

func TestSurfaceARepublishesAfterForcedRefresh(t *testing.T) {
	fu := newFakeUpdater()
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceATestManager(t, fu, func() time.Time { return now })
	sc := surfaceAScope("wan.example.net", FamilyV4, 0)
	sc.ForcedRefresh = time.Hour
	obs := fixedObserver("203.0.113.5")

	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, obs, nil, nil); err != nil {
		t.Fatalf("Reconcile1: %v", err)
	}
	// Past the forced-refresh floor: a wire re-assert fires even with no change.
	now = now.Add(2 * time.Hour)
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, obs, nil, nil); err != nil {
		t.Fatalf("Reconcile2: %v", err)
	}
	if got := len(fu.upserts); got != 2 {
		t.Fatalf("forced-refresh elapsed must re-assert; got %d upserts", got)
	}
}

// TestSurfaceAForceRefreshRepublishesUnchanged is the #3276 fail-on-revert
// proof for the operator force-now verb (`request system dynamic-dns update`).
// An owned scope whose address has NOT changed and is still inside the
// forced-refresh floor is normally a counted skip (no wire traffic). After
// ForceRefresh() the NEXT reconcile MUST re-assert the wire record exactly once,
// proving the force latch overrides the change-detection + forced-refresh skip.
// Revert the `force ||` wiring in reconcileScopeLocked (or ForceRefresh) and the
// forced pass skips → this test goes RED.
func TestSurfaceAForceRefreshRepublishesUnchanged(t *testing.T) {
	fu := newFakeUpdater()
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceATestManager(t, fu, func() time.Time { return now })
	sc := surfaceAScope("wan.example.net", FamilyV4, 0)
	sc.ForcedRefresh = time.Hour
	obs := fixedObserver("203.0.113.5")

	// First publish establishes ownership + last-published.
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, obs, nil, nil); err != nil {
		t.Fatalf("Reconcile1: %v", err)
	}
	// Inside the forced-refresh floor, unchanged address: normally a skip.
	now = now.Add(time.Minute)
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, obs, nil, nil); err != nil {
		t.Fatalf("Reconcile2: %v", err)
	}
	if got := len(fu.upserts); got != 1 {
		t.Fatalf("baseline: unchanged-in-floor must skip; got %d upserts", got)
	}

	// Force-now: the next pass must re-assert even though nothing changed and the
	// floor has not elapsed.
	m.ForceRefresh()
	now = now.Add(time.Minute)
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, obs, nil, nil); err != nil {
		t.Fatalf("Reconcile3 (forced): %v", err)
	}
	if got := len(fu.upserts); got != 2 {
		t.Fatalf("forced update must re-assert the wire record; got %d upserts", got)
	}

	// The latch is one-shot: a subsequent unchanged pass (still no force) skips
	// again rather than re-asserting forever.
	now = now.Add(time.Minute)
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, obs, nil, nil); err != nil {
		t.Fatalf("Reconcile4: %v", err)
	}
	if got := len(fu.upserts); got != 2 {
		t.Fatalf("force latch must be one-shot; got %d upserts after the forced pass", got)
	}
}

// TestSurfaceAForceRefreshRespectsGate proves the force-now latch never bypasses
// the per-RG HA writer gate (#2972): a forced reconcile on a scope this node may
// NOT write (gate closed) publishes NOTHING — only the RG owner writes, even
// under an operator force.
func TestSurfaceAForceRefreshRespectsGate(t *testing.T) {
	fu := newFakeUpdater()
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceATestManager(t, fu, func() time.Time { return now })
	sc := surfaceAScope("wan.example.net", FamilyV4, 1)
	obs := fixedObserver("203.0.113.5")
	gateClosed := func(ScopeKey) bool { return false }

	m.ForceRefresh()
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, obs, gateClosed, nil); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if got := len(fu.upserts); got != 0 {
		t.Fatalf("force must not bypass the per-RG gate; got %d upserts on a gated-out scope", got)
	}
}

// NOTE (#2691 P2 review): the replace-on-address-change, withdraw-on-config-
// removal, withdraw-on-address-loss, and per-RG-gate-withdraw proofs moved to
// surface_a_rfc2136_test.go — they MUST run through the REAL rfc2136 backend
// against the stateful fake DNS server, because the two production-path bugs the
// review found (the no-DHCID replace refusal + the no-op withdraw) are invisible
// to fakeUpdater (it appends on any UpsertLease and the old withdraw helper
// returned the injected static backend regardless of the production newBackend
// wiring). The fakeUpdater tests below stay only for backend-AGNOSTIC engine
// cadence (publish-once, skip-unchanged, forced-refresh fires, transient does
// not withdraw, backoff, status).

func TestSurfaceATransientObservationDoesNotWithdraw(t *testing.T) {
	fu := newFakeUpdater()
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceATestManager(t, fu, func() time.Time { return now })
	sc := surfaceAScope("wan.example.net", FamilyV4, 0)

	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("203.0.113.5"), nil, nil); err != nil {
		t.Fatalf("Reconcile1: %v", err)
	}
	// Transient observation failure (ok=false): NEVER withdraw (the
	// never-blackhole rule).
	transient := func(context.Context, SurfaceAScope) (AddressObservation, bool) {
		return AddressObservation{}, false
	}
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, transient, nil, nil); err != nil {
		t.Fatalf("Reconcile2: %v", err)
	}
	if got := len(fu.deletes); got != 0 {
		t.Fatalf("transient observation failure must NOT withdraw; got %d deletes", got)
	}
	if st := m.Stats(); st.Scopes != 1 {
		t.Fatalf("the record must stay owned across a transient; got %d scopes", st.Scopes)
	}
}

// TestSurfaceAPerRGGate moved to surface_a_rfc2136_test.go
// (TestSurfaceARealBackendPerRGGate) — it asserts the actual zone state through
// the real backend, not fakeUpdater call counts.

func TestSurfaceABackoffOnRepeatedFailure(t *testing.T) {
	fu := newFakeUpdater()
	fu.failEvery = true // every publish fails
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceATestManager(t, fu, func() time.Time { return now })
	sc := surfaceAScope("wan.example.net", FamilyV4, 0)
	obs := fixedObserver("203.0.113.5")

	// First pass: attempts a publish, fails, arms backoff.
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, obs, nil, nil); err == nil {
		t.Fatal("expected a publish error on first pass")
	}
	attemptsAfterFirst := len(fu.upserts) // the fakeUpdater records nothing on failure
	_ = attemptsAfterFirst
	failCalls1 := fu.failedCalls
	// Second pass immediately after (still inside the backoff window): the
	// scope is SKIPPED, so the backend is NOT hit again (ban-avoidance).
	now = now.Add(time.Second)
	_ = m.Reconcile(context.Background(), []SurfaceAScope{sc}, obs, nil, nil)
	if fu.failedCalls != failCalls1 {
		t.Fatalf("scope in backoff window must not hit the backend again; calls %d -> %d",
			failCalls1, fu.failedCalls)
	}
	if st := m.Stats(); st.BackedOff < 1 {
		t.Fatalf("expected a backed-off skip, got %+v", st)
	}
	// Well past the backoff window: the scope is eligible again and retries.
	now = now.Add(time.Hour)
	_ = m.Reconcile(context.Background(), []SurfaceAScope{sc}, obs, nil, nil)
	if fu.failedCalls <= failCalls1 {
		t.Fatalf("after backoff window the scope must retry; calls stayed at %d", fu.failedCalls)
	}
}

func TestSurfaceAStatusViews(t *testing.T) {
	fu := newFakeUpdater()
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceATestManager(t, fu, func() time.Time { return now })
	sc := surfaceAScope("wan.example.net", FamilyV4, 0)
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("203.0.113.5"), nil, nil); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	views := m.StatusViews([]SurfaceAScope{sc})
	if len(views) != 1 {
		t.Fatalf("expected one status view, got %d", len(views))
	}
	v := views[0]
	if v.FQDN != "wan.example.net" || v.Published != "203.0.113.5" ||
		v.Interface != "ge-0-0-2" || v.Family != 4 || v.Provider != "corp-2136" {
		t.Fatalf("status view mismatch: %+v", v)
	}
	if v.State != SurfaceAStatePublished {
		t.Fatalf("published scope must have state %q, got %q", SurfaceAStatePublished, v.State)
	}
	if v.LastPublished.IsZero() {
		t.Fatal("status view must carry a last-published time")
	}
}

// TestSurfaceAFQDNChangeDetectedAndPublished is the #2903 fail-on-revert proof
// for the change-detection half: changing ONLY the configured hostname for a
// scope (same interface/unit/family/RG/provider, SAME address) must be detected
// as a change and the NEW name published. Before #2903 the ScopeKey had no FQDN
// axis, so a FQDN-only edit kept the same scope key; change detection compared
// only the IP, so `owned && !changed && !refreshDue` skipped the pass and the
// new name was never published (RED: only the first publish would appear). The
// fix makes the published FQDN part of the scope identity so the renamed scope
// is a new, not-yet-owned scope whose publish is not skipped.
//
// FAIL-ON-REVERT: this goes RED when `scopePrefix()` drops the `/fqdn=` axis
// (state.go) — the load-bearing change. (Both these helper-built scopes set
// Key.FQDN, so this particular test does NOT isolate the effectiveKey fold;
// TestSurfaceAFQDNFoldFromScopeFQDN below covers the fold with an empty Key.FQDN.)
func TestSurfaceAFQDNChangeDetectedAndPublished(t *testing.T) {
	fu := newFakeUpdater()
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceATestManager(t, fu, func() time.Time { return now })

	old := surfaceAScope("old.example.net", FamilyV4, 0)
	obs := fixedObserver("203.0.113.5")
	if err := m.Reconcile(context.Background(), []SurfaceAScope{old}, obs, nil, nil); err != nil {
		t.Fatalf("Reconcile(old): %v", err)
	}

	// Operator renames the published hostname; the address is UNCHANGED and we
	// are well inside the forced-refresh floor (only a minute later).
	now = now.Add(time.Minute)
	renamed := surfaceAScope("new.example.net", FamilyV4, 0)
	if err := m.Reconcile(context.Background(), []SurfaceAScope{renamed}, obs, nil, nil); err != nil {
		t.Fatalf("Reconcile(renamed): %v", err)
	}

	ups := fu.upsertNames()
	if !contains(ups, "new.example.net=203.0.113.5") {
		t.Fatalf("FQDN-only change (same IP) must publish the NEW name; upserts=%v", ups)
	}
}

// TestSurfaceAFQDNChangeWithdrawsOldName is the #2903 fail-on-revert proof for
// the orphan half: when the configured hostname changes, the OLD name's RR must
// be withdrawn at the provider (a real DeleteLease), not left orphaned. Before
// #2903 the in-place ownership overwrite stored the new FQDN under the SAME
// scope key and never DeleteLease'd the old name (RED: zero deletes, the old
// record resolves forever). The fix makes the old FQDN its own scope key; once
// the binding is reconciled under the new name, the old scope is gone-from-
// config and Reconcile Pass 2 withdraws it through the same backend.
//
// FAIL-ON-REVERT: this goes RED when `scopePrefix()` drops the `/fqdn=` axis
// (state.go) — the load-bearing change.
func TestSurfaceAFQDNChangeWithdrawsOldName(t *testing.T) {
	fu := newFakeUpdater()
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceATestManager(t, fu, func() time.Time { return now })

	old := surfaceAScope("old.example.net", FamilyV4, 0)
	obs := fixedObserver("203.0.113.5")
	if err := m.Reconcile(context.Background(), []SurfaceAScope{old}, obs, nil, nil); err != nil {
		t.Fatalf("Reconcile(old): %v", err)
	}

	now = now.Add(time.Minute)
	renamed := surfaceAScope("new.example.net", FamilyV4, 0)
	if err := m.Reconcile(context.Background(), []SurfaceAScope{renamed}, obs, nil, nil); err != nil {
		t.Fatalf("Reconcile(renamed): %v", err)
	}

	dels := fu.deleteNames()
	if !contains(dels, "old.example.net=203.0.113.5") {
		t.Fatalf("a FQDN rename must withdraw the OLD name (no orphaned RR); deletes=%v", dels)
	}
	// And only ONE record is owned afterward (the new name); the old scope's
	// ownership entry must be dropped after the successful withdraw.
	if st := m.Stats(); st.Scopes != 1 {
		t.Fatalf("after a rename exactly one scope must remain owned (the new name); got %d", st.Scopes)
	}
	// Status must show the renamed scope as published, no stale withdraw-pending.
	views := m.StatusViews([]SurfaceAScope{renamed})
	if len(views) != 1 || views[0].FQDN != "new.example.net" || views[0].State != SurfaceAStatePublished {
		t.Fatalf("after a rename the only status row must be the published new name; got %+v", views)
	}
}

// TestSurfaceAFQDNFoldFromScopeFQDN is the focused fail-on-revert guard for the
// effectiveKey() FOLD specifically: the manager must derive the FQDN scope axis
// from SurfaceAScope.FQDN even when the caller did NOT pre-populate Key.FQDN.
// The daemon and the surfaceAScope helper both happen to set Key.FQDN, which
// makes the other rename tests insensitive to a no-op effectiveKey (return
// s.Key) — so this test deliberately leaves Key.FQDN EMPTY and only sets
// SurfaceAScope.FQDN. With the fold intact, renaming SurfaceAScope.FQDN (same
// interface/unit/family, same IP) is a new scope: the new name publishes and the
// old name is withdrawn. With effectiveKey reverted to a passthrough that
// ignores SurfaceAScope.FQDN, both scopes collapse to the SAME key — the rename
// is skipped (no new publish) and the old name is overwritten in place (no
// withdraw), so this test goes RED.
func TestSurfaceAFQDNFoldFromScopeFQDN(t *testing.T) {
	fu := newFakeUpdater()
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceATestManager(t, fu, func() time.Time { return now })

	// Key.FQDN intentionally EMPTY; only SurfaceAScope.FQDN carries the name.
	base := ScopeKey{Family: FamilyV4, Interface: "ge-0-0-2", Unit: 50, PolicyID: "corp-2136"}
	old := SurfaceAScope{Key: base, FQDN: "old.example.net", TTL: 300, Source: AddressSourceDHCP}
	obs := fixedObserver("203.0.113.5")
	if err := m.Reconcile(context.Background(), []SurfaceAScope{old}, obs, nil, nil); err != nil {
		t.Fatalf("Reconcile(old): %v", err)
	}

	now = now.Add(time.Minute)
	renamed := SurfaceAScope{Key: base, FQDN: "new.example.net", TTL: 300, Source: AddressSourceDHCP}
	if err := m.Reconcile(context.Background(), []SurfaceAScope{renamed}, obs, nil, nil); err != nil {
		t.Fatalf("Reconcile(renamed): %v", err)
	}

	if ups := fu.upsertNames(); !contains(ups, "new.example.net=203.0.113.5") {
		t.Fatalf("the manager must fold SurfaceAScope.FQDN into the scope key (publish the new name) even with an empty Key.FQDN; upserts=%v", ups)
	}
	if dels := fu.deleteNames(); !contains(dels, "old.example.net=203.0.113.5") {
		t.Fatalf("the manager must fold SurfaceAScope.FQDN into the scope key (withdraw the old name) even with an empty Key.FQDN; deletes=%v", dels)
	}
}

// TestSurfaceAFQDNMigrationAdoptsExistingRecord proves the #2903 on-disk
// upgrade path does NOT blackhole: a pre-#2903 ownership record was keyed under
// an FQDN-LESS scope prefix; after upgrade the configured scope keys under the
// FQDN-bearing prefix with the SAME name+address. Pass 1 (re)publishes under the
// new prefix; Pass 2 must adopt the stale old-prefix entry (drop it WITHOUT an
// exact-RR delete that would remove the just-published live RR). Net: the name
// stays published and no stale ownership lingers.
func TestSurfaceAFQDNMigrationAdoptsExistingRecord(t *testing.T) {
	fu := newFakeUpdater()
	now := time.Unix(1_700_000_000, 0)
	dir := t.TempDir()
	statePath := filepath.Join(dir, "iface-ddns.json")

	sc := surfaceAScope("wan.example.net", FamilyV4, 0)

	// Seed a PRE-#2903 ownership record: same scope, but FQDN NOT in the key
	// (the old on-disk shape). We build the manager, then inject the legacy entry
	// directly into the store under the FQDN-less scope key.
	m := newSurfaceAManagerForTesting(statePath, fu, func() time.Time { return now })
	// The pre-#2903 on-disk record was keyed WITHOUT the FQDN axis. The helper
	// pre-populates sc.Key.FQDN, so we MUST clear it here — otherwise legacyKey
	// would equal the configured scope's effectiveKey, only ONE record would
	// exist, and the adopt branch would never run (a vacuous test that stays
	// green even with the adopt block disabled).
	legacyKey := sc.Key
	legacyKey.FQDN = ""
	m.state.put(ownedRecord{
		Family:      4,
		Identity:    surfaceAIdentity,
		Address:     "",
		FQDN:        "wan.example.net",
		ForwardType: "A",
		TTL:         300,
		AddrText:    "203.0.113.5",
	}.withScope(legacyKey))
	if err := m.state.save(); err != nil {
		t.Fatalf("seed save: %v", err)
	}

	// First post-upgrade reconcile, same address.
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("203.0.113.5"), nil, nil); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	// The name must NOT have been withdrawn (no blackhole on upgrade).
	if dels := fu.deleteNames(); contains(dels, "wan.example.net=203.0.113.5") {
		t.Fatalf("upgrade migration must NOT delete the live RR; deletes=%v", dels)
	}
	// Exactly one scope owned (the new FQDN-bearing prefix); the stale legacy
	// entry must have been adopted/dropped.
	if st := m.Stats(); st.Scopes != 1 {
		t.Fatalf("after migration exactly one scope must remain owned; got %d", st.Scopes)
	}
	views := m.StatusViews([]SurfaceAScope{sc})
	if len(views) != 1 || views[0].State != SurfaceAStatePublished {
		t.Fatalf("migrated scope must be the single published row; got %+v", views)
	}
}

// contains reports whether s is present in xs.
func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// TestSurfaceACorruptStateFailsClosed is the #2971 fail-on-revert test: a
// corrupt Surface A ownership state file must put the manager into the DEGRADED
// (fail-closed) state — Reconcile refuses to publish AND to withdraw any record,
// never silently resetting to an empty store and reconciling-from-empty (which
// would re-publish EVERY scope, overwriting a peer/manual owner, and leak the
// records it can no longer withdraw). It also proves the bad file is quarantined
// (preserved, not overwritten) and the alarm is surfaced in Stats. Reverting
// NewSurfaceAManager/newSurfaceAManagerForTesting to the old fail-open path
// (loadDDNSState + log-and-continue with the empty store) makes this RED: the
// reconcile would publish the observed address and the no-op + degraded
// assertions fail.
func TestSurfaceACorruptStateFailsClosed(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "iface-ddns.json")
	// A corrupt store left behind by a crash / disk fault.
	if err := os.WriteFile(statePath, []byte("{ this is not valid json at all"), 0o600); err != nil {
		t.Fatalf("seed corrupt state: %v", err)
	}

	fu := newFakeUpdater()
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceAManagerForTesting(statePath, fu, func() time.Time { return now })

	// Degraded must be set at construction and surfaced in Stats.
	if !m.degraded {
		t.Fatal("manager must be DEGRADED after loading a corrupt Surface A state file")
	}
	if st := m.Stats(); !st.Degraded || st.DegradedReason == "" {
		t.Fatalf("Stats must report Degraded with a reason, got %+v", st)
	}

	// The corrupt file must be quarantined aside (preserved for inspection), not
	// left in place to be overwritten by a later save.
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatalf("corrupt state file must be quarantined (renamed away); stat err=%v", err)
	}
	matches, _ := filepath.Glob(statePath + ".corrupt-*")
	if len(matches) != 1 {
		t.Fatalf("expected exactly one quarantined copy, found %v", matches)
	}

	// A reconcile of a configured scope with a valid observed address must FAIL
	// CLOSED: no publish, no withdraw, an error returned, and the state file NOT
	// recreated. A standalone (nil gate) run is used deliberately — losing the
	// only ownership authority is no safer without a peer.
	sc := surfaceAScope("wan.example.net", FamilyV4, 0)
	err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("203.0.113.5"), nil, nil)
	if err == nil {
		t.Fatal("reconcile must return an error while degraded (fail closed)")
	}
	if got := len(fu.upserts); got != 0 {
		t.Fatalf("degraded manager must NOT publish any record, got %d upserts", got)
	}
	if got := len(fu.deletes); got != 0 {
		t.Fatalf("degraded manager must NOT withdraw any record, got %d deletes", got)
	}
	// The reconcile must NOT have written a fresh (empty) state file — that would
	// erase the only signal that ownership was lost.
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatal("degraded manager must not recreate the ownership state file")
	}
}

// TestSurfaceAUnsupportedVersionFailsClosed proves the unknown-future-version
// path also fails closed + quarantines (#2971, sibling of the corrupt path):
// the manager must not trust records from a format it cannot decode.
func TestSurfaceAUnsupportedVersionFailsClosed(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "iface-ddns.json")
	if err := os.WriteFile(statePath,
		[]byte(`{"version":99,"records":[{"family":4,"identity":"router-self","address":"","fqdn":"wan.example.net","forward_type":"A","ttl":300,"addr_text":"203.0.113.5"}]}`),
		0o600); err != nil {
		t.Fatalf("seed unsupported-version state: %v", err)
	}

	fu := newFakeUpdater()
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceAManagerForTesting(statePath, fu, func() time.Time { return now })

	if !m.degraded {
		t.Fatal("unsupported-version state must put the manager into the degraded state")
	}
	// No record from the future-version file leaked into the in-memory store.
	if len(m.state.records) != 0 {
		t.Fatalf("unsupported-version records must not load, got %d", len(m.state.records))
	}
	matches, _ := filepath.Glob(statePath + ".corrupt-*")
	if len(matches) != 1 {
		t.Fatalf("unsupported-version file must be quarantined, found %v", matches)
	}

	sc := surfaceAScope("wan.example.net", FamilyV4, 0)
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("203.0.113.5"), nil, nil); err == nil {
		t.Fatal("reconcile must return an error while degraded (fail closed)")
	}
	if got := len(fu.upserts); got != 0 {
		t.Fatalf("degraded manager must NOT publish, got %d upserts", got)
	}
}

// TestSurfaceAAbsentStateFirstBootStandaloneWrites pins the OTHER half of the
// #2971 contract: a MISSING state file (first boot) is a legitimately-empty
// store, NOT degraded, so a fresh standalone (nil gate) node still publishes its
// records. Distinguishing absent (fail-open OK) from corrupt (fail-closed) is
// the whole point — this proves the fix did not over-apply fail-closed into
// never-writing for a first-boot node.
func TestSurfaceAAbsentStateFirstBootStandaloneWrites(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "iface-ddns.json")
	// Deliberately do NOT create the file: first boot.
	if _, err := os.Stat(statePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("precondition: state file must be absent, stat err=%v", err)
	}

	fu := newFakeUpdater()
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceAManagerForTesting(statePath, fu, func() time.Time { return now })

	if m.degraded {
		t.Fatalf("an absent (first-boot) state file must NOT be degraded; reason=%q", m.degradedReason)
	}

	sc := surfaceAScope("wan.example.net", FamilyV4, 0)
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("203.0.113.5"), nil, nil); err != nil {
		t.Fatalf("first-boot standalone reconcile must succeed: %v", err)
	}
	if got := len(fu.upserts); got != 1 {
		t.Fatalf("first-boot standalone node must publish its record, got %d upserts", got)
	}
}

// TestSurfaceARestartSeedsFromAddrTextNoRepublishStorm is the #3734 (H04)
// fail-on-revert proof. On restart seedFromStore must rebuild the runtime cache
// from the durable ownership store's AddrText field — where a Surface A record's
// published rdata lives (Address is "" for a Surface A record, #2691 P2) — AND
// baseline lastPublished at the restart instant, so the FIRST post-restart
// reconcile of an UNCHANGED record is a counted SKIP, not a redundant wire
// republish. Reverting the fix (parse the empty Address, leave lastPublished
// zero) seeds NOTHING and makes refreshDue immediately true, so every owned
// scope republishes on the first pass — the restart write-storm proportional to
// the scope count (provider ban/rate-limit risk) — and this test goes RED. A
// genuinely CHANGED address must still republish (the seed must not
// over-suppress a real renumber).
func TestSurfaceARestartSeedsFromAddrTextNoRepublishStorm(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "iface-ddns.json")
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }
	sc := surfaceAScope("wan.example.net", FamilyV4, 0)

	// Pre-restart: publish 203.0.113.5 so the durable store records an owned
	// Surface A entry.
	fu1 := newFakeUpdater()
	m1 := newSurfaceAManagerForTesting(statePath, fu1, clock)
	if err := m1.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("203.0.113.5"), nil, nil); err != nil {
		t.Fatalf("pre-restart publish: %v", err)
	}
	if got := len(fu1.upserts); got != 1 {
		t.Fatalf("pre-restart must publish once, got %d", got)
	}
	// Prove the on-disk shape the seed must read: AddrText carries the rdata,
	// Address is empty. If this shape ever changes, the seed logic must too.
	owned, ok := m1.state.get(sc.effectiveKey(), surfaceAIdentity, "")
	if !ok || owned.AddrText != "203.0.113.5" || owned.Address != "" {
		t.Fatalf("stored record must carry rdata in AddrText with Address empty; got %+v (ok=%v)", owned, ok)
	}

	// Restart: a fresh manager loads the SAME durable store and seeds the runtime
	// cache. An UNCHANGED reconcile must NOT touch the wire.
	fu2 := newFakeUpdater()
	m2 := newSurfaceAManagerForTesting(statePath, fu2, clock)
	if err := m2.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("203.0.113.5"), nil, nil); err != nil {
		t.Fatalf("post-restart unchanged reconcile: %v", err)
	}
	if got := len(fu2.upserts); got != 0 {
		t.Fatalf("post-restart unchanged record must NOT republish (storm); got %d upserts", got)
	}
	if st := m2.Stats(); st.Skipped != 1 {
		t.Fatalf("post-restart unchanged record must be a counted skip; stats=%+v", st)
	}

	// A genuinely CHANGED address after restart must still republish.
	if err := m2.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("198.51.100.7"), nil, nil); err != nil {
		t.Fatalf("post-restart changed reconcile: %v", err)
	}
	if got := fu2.upsertNames(); len(got) != 1 || got[0] != "wan.example.net=198.51.100.7" {
		t.Fatalf("changed address after restart must republish; got %v", got)
	}
}

// TestSurfaceARenumberLogReadsAddrText is the #3734 (M02) fail-on-revert proof.
// On a WAN renumber (same FQDN, new address) publishLocked must log the
// "replaced record address" transition with the OLD address read from the
// previous owned record's AddrText. Reverting to prevOwned.Address (always "" for
// a Surface A record) makes prevAddr "" so the log never fires → this test goes
// RED (a renumber leaves no operational trace).
func TestSurfaceARenumberLogReadsAddrText(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "iface-ddns.json")
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }
	sc := surfaceAScope("wan.example.net", FamilyV4, 0)

	fu := newFakeUpdater()
	m := newSurfaceAManagerForTesting(statePath, fu, clock)

	// Establish ownership at the old address (logs "published record").
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("203.0.113.5"), nil, nil); err != nil {
		t.Fatalf("initial publish: %v", err)
	}

	// Capture the default slog output for the renumber pass only.
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	defer slog.SetDefault(prev)

	// Renumber: same FQDN, new address → replace in place.
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("198.51.100.7"), nil, nil); err != nil {
		t.Fatalf("renumber publish: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "replaced record address") {
		t.Fatalf("renumber must log the replacement transition; log=%q", out)
	}
	if !strings.Contains(out, "old=203.0.113.5") || !strings.Contains(out, "new=198.51.100.7") {
		t.Fatalf("renumber log must carry old (from AddrText) + new address; log=%q", out)
	}
}

// TestSurfaceAPublishBackoffDoesNotDelayWithdraw is the #4423 M03 fail-on-revert
// proof: a PUBLISH-failure backoff must NOT delay a newly-observed address-LOSS
// withdraw. Before the fix the error-backoff window was checked at the TOP of
// reconcileScopeLocked and gated BOTH wire ops, so a scope whose publish failed
// (armed backoff) would skip the whole pass on a later address loss — leaving
// the record live at a now-dead address for the whole backoff window (a
// blackhole). The fix observes first and gates the window PER wire op (a
// publish backoff no longer blocks a withdraw). RED-on-revert: restore the
// top-of-function unconditional backoff check and the withdraw below never fires.
func TestSurfaceAPublishBackoffDoesNotDelayWithdraw(t *testing.T) {
	fu := newFakeUpdater()
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceATestManager(t, fu, func() time.Time { return now })
	sc := surfaceAScope("wan.example.net", FamilyV4, 0)

	obsAddr := netip.MustParseAddr("203.0.113.5")
	obsOK := true
	observe := func(context.Context, SurfaceAScope) (AddressObservation, bool) {
		if !obsOK {
			return AddressObservation{}, false
		}
		return AddressObservation{Addr: obsAddr, Source: AddressSourceDHCP}, true
	}

	// 1. Publish the initial address (record owned at 203.0.113.5).
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, observe, nil, nil); err != nil {
		t.Fatalf("Reconcile(publish): %v", err)
	}

	// 2. A new address fails to publish → arms a PUBLISH-origin backoff. The
	//    record stays pending with both candidates retained (#15225).
	fu.failUpd["wan.example.net"] = true
	obsAddr = netip.MustParseAddr("203.0.113.9")
	now = now.Add(time.Second)
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, observe, nil, nil); err == nil {
		t.Fatal("expected the failed publish to return an error and arm backoff")
	}
	if len(fu.deletes) != 0 {
		t.Fatalf("no withdraw should have happened yet; got %d deletes", len(fu.deletes))
	}

	// 3. Address is LOST while still inside the (publish-origin) backoff window.
	//    The withdraw MUST proceed — it is a different intent than the failed
	//    publish, and leaving the record live at a dead address is a blackhole.
	//    #15225: the failed publish was ambiguous, so the pending row retains
	//    BOTH candidates and the withdraw deletes both (2 deletes).
	obsAddr = netip.Addr{} // definitive loss
	now = now.Add(time.Second)
	_ = m.Reconcile(context.Background(), []SurfaceAScope{sc}, observe, nil, nil)
	if len(fu.deletes) != 2 {
		t.Fatalf("a publish-origin backoff must NOT delay an address-loss withdraw (#4423 M03); "+
			"got %d deletes, want 2 (both ambiguous candidates)", len(fu.deletes))
	}
}

// TestSortSurfaceAStatusViewsTotalOrder is the #4423 M11 fail-on-revert proof:
// status rows must sort by a TOTAL key so the operator surface is byte-stable.
// The pre-fix comparator keyed only on {FQDN, Family}; rows that legitimately
// tie on both (same hostname from different interfaces/units, or a configured +
// withdraw-pending/orphaned row for the same name+family) were left in input
// order by the non-stable sort. Comparing the sorted output against the explicit
// total-order expectation goes RED if the comparator only breaks {FQDN, Family}.
func TestSortSurfaceAStatusViewsTotalOrder(t *testing.T) {
	mk := func(fqdn string, fam int, iface string, unit int, prov, state, pub string) SurfaceAStatusView {
		return SurfaceAStatusView{FQDN: fqdn, Family: fam, Interface: iface, Unit: unit, Provider: prov, State: state, Published: pub}
	}
	// Three rows tie on {wan.example.net, family 4}; they must order by
	// interface then unit. A second FQDN and a family-6 row round out the key.
	want := []SurfaceAStatusView{
		mk("a.example.net", 4, "ge-0-0-1", 0, "q", "pending", ""),
		mk("wan.example.net", 4, "ge-0-0-1", 0, "p", "published", "203.0.113.1"),
		mk("wan.example.net", 4, "ge-0-0-1", 5, "p", "published", "203.0.113.5"),
		mk("wan.example.net", 4, "ge-0-0-9", 0, "p", "published", "203.0.113.9"),
		mk("wan.example.net", 6, "ge-0-0-1", 0, "p", "published", "2001:db8::1"),
	}
	// Several permutations of the same rows must all sort to `want`.
	perms := [][]int{
		{3, 1, 4, 2, 0}, // interface/unit ties out of order
		{4, 3, 2, 1, 0}, // reversed
		{2, 0, 4, 1, 3}, // shuffled
	}
	for i, order := range perms {
		in := make([]SurfaceAStatusView, len(order))
		for j, idx := range order {
			in[j] = want[idx]
		}
		SortSurfaceAStatusViews(in)
		if !reflect.DeepEqual(in, want) {
			t.Fatalf("permutation %d did not sort to the total order (#4423 M11):\n got=%+v\nwant=%+v", i, in, want)
		}
	}
}

// #9067 (the second, backend-independent half): a TTL-only edit must republish
// PROMPTLY, not at the 24h forced-refresh floor.
//
// Change detection was `changed := addr != rt.lastAddr`, so a TTL change was not
// a change on ANY backend — including Route 53, whose backend comparison is
// correct. The Cloudflare early return made it permanent; this made it slow
// everywhere. Both defeat the same operator intent: a shorter TTL is bought
// precisely so the NEXT change propagates soon, and waiting a day for the TTL
// itself to land inverts that.
func TestSurfaceATTLOnlyChangeRepublishesPromptly9067(t *testing.T) {
	fu := newFakeUpdater()
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceATestManager(t, fu, func() time.Time { return now })
	obs := fixedObserver("203.0.113.5")

	sc := surfaceAScope("wan.example.net", FamilyV4, 0)
	sc.TTL = 3600
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, obs, nil, nil); err != nil {
		t.Fatalf("Reconcile1: %v", err)
	}
	if got := len(fu.upserts); got != 1 {
		t.Fatalf("fixture: first publish must write, got %d", got)
	}

	// SAME address, LOWER TTL, still deep inside the forced-refresh floor.
	now = now.Add(time.Minute)
	lower := surfaceAScope("wan.example.net", FamilyV4, 0)
	lower.TTL = 60
	if err := m.Reconcile(context.Background(), []SurfaceAScope{lower}, obs, nil, nil); err != nil {
		t.Fatalf("Reconcile2: %v", err)
	}
	if got := len(fu.upserts); got != 2 {
		t.Fatalf("#9067: a TTL-only change did not republish (%d upserts). Change "+
			"detection compared only the address, so nothing republished until the "+
			"24h forced-refresh floor — on EVERY backend, including the one whose "+
			"own comparison is correct", got)
	}
}

// CONTROL: with the TTL unchanged the skip must still fire. Without this, a
// "fix" that simply set changed=true unconditionally would satisfy the cell
// above while turning every reconcile into wire traffic — the exact cost the
// forced-refresh floor exists to avoid, and on a rate-limited provider a
// self-inflicted outage.
func TestSurfaceAUnchangedTTLStillSkips9067(t *testing.T) {
	fu := newFakeUpdater()
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceATestManager(t, fu, func() time.Time { return now })
	obs := fixedObserver("203.0.113.5")

	sc := surfaceAScope("wan.example.net", FamilyV4, 0)
	sc.TTL = 3600
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, obs, nil, nil); err != nil {
		t.Fatalf("Reconcile1: %v", err)
	}
	now = now.Add(time.Minute)
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, obs, nil, nil); err != nil {
		t.Fatalf("Reconcile2: %v", err)
	}
	if got := len(fu.upserts); got != 1 {
		t.Errorf("#9067: address AND TTL unchanged must still skip inside the "+
			"forced-refresh floor; got %d upserts", got)
	}
	if st := m.Stats(); st.Skipped != 1 {
		t.Errorf("#9067: expected the unchanged pass to be a COUNTED skip, got %+v", st)
	}
}

// The comparison must be on the NORMALISED TTL. `TTL <= 0` means "use
// defaultDDNSTTL", so an explicit-to-unset edit at that same value is NOT a
// change — and comparing the raw configured field would report one, republishing
// on a no-op edit. This is the "compared the wrong property" direction of the
// same defect.
func TestSurfaceATTLComparisonIsNormalized9067(t *testing.T) {
	fu := newFakeUpdater()
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceATestManager(t, fu, func() time.Time { return now })
	obs := fixedObserver("203.0.113.5")

	explicit := surfaceAScope("wan.example.net", FamilyV4, 0)
	explicit.TTL = defaultDDNSTTL
	if err := m.Reconcile(context.Background(), []SurfaceAScope{explicit}, obs, nil, nil); err != nil {
		t.Fatalf("Reconcile1: %v", err)
	}
	// The operator deletes the explicit `ttl` leaf: 0 means "default", which is
	// the value already published. Nothing changed.
	now = now.Add(time.Minute)
	unset := surfaceAScope("wan.example.net", FamilyV4, 0)
	unset.TTL = 0
	if err := m.Reconcile(context.Background(), []SurfaceAScope{unset}, obs, nil, nil); err != nil {
		t.Fatalf("Reconcile2: %v", err)
	}
	if got := len(fu.upserts); got != 1 {
		t.Errorf("#9067: unset resolves to defaultDDNSTTL (%d), which is what was "+
			"already published — comparing the RAW field reports a change that did "+
			"not happen and republishes on a no-op edit; got %d upserts",
			defaultDDNSTTL, got)
	}
}

// #9067: what is STORED must be the NORMALISED (published) TTL, not the raw
// configured field.
//
// This is the direction the other cells miss, and it is reachable by the most
// ordinary edit there is: a scope that never set a TTL, then does.
//
// `lastTTL == 0` means "not published in this process" and suppresses the
// comparison (so a scope re-adopted after restart, whose TTL the durable store
// does not record, is not republished spuriously). If the publish stores the RAW
// field, a scope first published with the TTL leaf UNSET stores 0 — which is
// indistinguishable from "never published" — and the comparison is then disabled
// FOREVER for that scope. The operator later sets `ttl 60` and nothing
// republishes until the 24h floor, which is the very defect #9067 is about,
// re-entered through the fix.
func TestSurfaceAUnsetThenExplicitTTLRepublishes9067(t *testing.T) {
	fu := newFakeUpdater()
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceATestManager(t, fu, func() time.Time { return now })
	obs := fixedObserver("203.0.113.5")

	// First publish with NO explicit TTL — the common starting configuration.
	unset := surfaceAScope("wan.example.net", FamilyV4, 0)
	unset.TTL = 0
	if err := m.Reconcile(context.Background(), []SurfaceAScope{unset}, obs, nil, nil); err != nil {
		t.Fatalf("Reconcile1: %v", err)
	}
	if got := len(fu.upserts); got != 1 {
		t.Fatalf("fixture: first publish must write, got %d", got)
	}

	// The operator now sets an explicit, DIFFERENT TTL.
	now = now.Add(time.Minute)
	explicit := surfaceAScope("wan.example.net", FamilyV4, 0)
	explicit.TTL = 60
	if explicit.TTL == defaultDDNSTTL {
		t.Fatalf("fixture: the explicit TTL must differ from the default (%d), or "+
			"this cell cannot observe a change", defaultDDNSTTL)
	}
	if err := m.Reconcile(context.Background(), []SurfaceAScope{explicit}, obs, nil, nil); err != nil {
		t.Fatalf("Reconcile2: %v", err)
	}
	if got := len(fu.upserts); got != 2 {
		t.Errorf("#9067: setting an explicit TTL on a scope first published with the "+
			"TTL leaf UNSET did not republish (%d upserts). The publish must store "+
			"the NORMALISED TTL: storing the raw 0 is indistinguishable from "+
			"\"never published\", which permanently disables the comparison for "+
			"that scope", got)
	}
}
