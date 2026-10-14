// #2049: tests proving dynamic-address feed prefixes are ENFORCED — they
// reach the published userspace snapshot's AddressBookSnapshot rows and the
// referencing policy routes them through SourceBookIDs/DestinationBookIDs
// (book references), not as no-match literals. Asserts against the published
// snapshot, NOT the retired eBPF compiler's result.AddrIDs.
package userspace

import (
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// feedPolicyCfg builds a config with a single from->to policy whose source
// (and optionally destination) reference a feed-backed address-name. The name
// is NOT in the static AddressBook — it is purely feed-backed, which is the
// case #2049 fixes (before the overlay the token was a no-match literal).
func feedPolicyCfg(srcName, dstName string) *config.Config {
	return &config.Config{
		Security: config.SecurityConfig{
			// AddressBook intentionally nil: the feed-backed name exists only
			// via the binding, exercising the "build from overlay alone" path.
			Zones: map[string]*config.ZoneConfig{
				"trust":   {Name: "trust"},
				"untrust": {Name: "untrust"},
			},
			Policies: []*config.ZonePairPolicies{
				{
					FromZone: "untrust",
					ToZone:   "trust",
					Policies: []*config.Policy{
						{
							Name: "block-threats",
							Match: config.PolicyMatch{
								SourceAddresses:      []string{srcName},
								DestinationAddresses: []string{dstName},
							},
							Action: config.PolicyDeny,
						},
					},
				},
			},
		},
	}
}

func findBookByName(books []AddressBookSnapshot, name string) *AddressBookSnapshot {
	for i := range books {
		if books[i].Name == name {
			return &books[i]
		}
	}
	return nil
}

func contains(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}

func containsID(ids []uint32, want uint32) bool {
	for _, v := range ids {
		if v == want {
			return true
		}
	}
	return false
}

// TestFeedOverlayEmitsBookRowAndPopulatesNameToID is the core enforcement
// proof: a feed-backed name with v4 AND v6 feed prefixes produces an
// AddressBookSnapshot row carrying those prefixes, and nameToID[name] is set
// (non-zero). NON-TAUTOLOGICAL: the same build WITHOUT the overlay must NOT
// emit the row and must NOT set nameToID — if the overlay merge is removed
// from buildAddressBookTableWithFeeds, this test fails.
func TestFeedOverlayEmitsBookRowAndPopulatesNameToID(t *testing.T) {
	cfg := feedPolicyCfg("bad-actors", "any")
	overlay := map[string][]string{
		"bad-actors": {"198.51.100.0/24", "2001:db8:bad::/48"},
	}

	books, nameToID, _ := buildAddressBookTableWithFeeds(cfg, overlay)

	row := findBookByName(books, "bad-actors")
	if row == nil {
		t.Fatalf("feed-backed name produced no AddressBookSnapshot row; books=%+v", books)
	}
	if !contains(row.PrefixesV4, "198.51.100.0/24") {
		t.Fatalf("v4 feed prefix not enforced; PrefixesV4=%v", row.PrefixesV4)
	}
	if !contains(row.PrefixesV6, "2001:db8:bad::/48") {
		t.Fatalf("v6 feed prefix not enforced; PrefixesV6=%v", row.PrefixesV6)
	}
	id, ok := nameToID["bad-actors"]
	if !ok || id == 0 {
		t.Fatalf("nameToID not populated for feed-backed name (ok=%v id=%d)", ok, id)
	}

	// NON-TAUTOLOGICAL guard: with no overlay the name is unknown — the table
	// is empty and nameToID has no entry. Proves the row/ID come from the
	// overlay, not from anywhere else.
	booksNoOverlay, nameToIDNoOverlay, _ := buildAddressBookTableWithFeeds(cfg, nil)
	if findBookByName(booksNoOverlay, "bad-actors") != nil {
		t.Fatalf("without the overlay, bad-actors must NOT emit a book row (tautology check)")
	}
	if _, ok := nameToIDNoOverlay["bad-actors"]; ok {
		t.Fatalf("without the overlay, nameToID must NOT contain bad-actors (tautology check)")
	}
}

// TestFeedBackedPolicyRoutesAsBookReference proves the policy snapshot routes
// the feed-backed token into SourceBookIDs (a book reference), not
// SourceLiterals (a no-match literal) — the actual enforcement behaviour.
func TestFeedBackedPolicyRoutesAsBookReference(t *testing.T) {
	cfg := feedPolicyCfg("bad-actors", "any")
	overlay := map[string][]string{
		"bad-actors": {"198.51.100.0/24"},
	}

	_, nameToID, _ := buildAddressBookTableWithFeeds(cfg, overlay)
	wantID := nameToID["bad-actors"]
	if wantID == 0 {
		t.Fatalf("precondition: feed name must have an ID")
	}

	snaps, _ := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, overlay)
	if len(snaps) != 1 {
		t.Fatalf("expected 1 policy rule, got %d", len(snaps))
	}
	rule := snaps[0]
	if !containsID(rule.SourceBookIDs, wantID) {
		t.Fatalf("feed-backed source must be a book reference; SourceBookIDs=%v want id %d", rule.SourceBookIDs, wantID)
	}
	if contains(rule.SourceLiterals, "bad-actors") {
		t.Fatalf("feed-backed source must NOT fall through to a no-match literal; SourceLiterals=%v", rule.SourceLiterals)
	}

	// NON-TAUTOLOGICAL: without the overlay the SAME token is unresolvable. This
	// proves the difference is the overlay. Pre-#2049 it silently became a
	// no-match literal — itself a deny fail-open. #3261 now makes an unresolvable
	// address fail CLOSED: the token routes to the __unsupported_address__
	// sentinel (no book reference), so the helper integrity preflight rejects the
	// whole snapshot rather than collapsing the side to a silent no-match.
	snapsNoOverlay, _ := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, nil)
	if len(snapsNoOverlay) != 1 {
		t.Fatalf("expected 1 rule without overlay, got %d", len(snapsNoOverlay))
	}
	if len(snapsNoOverlay[0].SourceBookIDs) != 0 {
		t.Fatalf("without overlay the feed name must NOT be a book reference; got %v", snapsNoOverlay[0].SourceBookIDs)
	}
	if contains(snapsNoOverlay[0].SourceLiterals, "bad-actors") {
		t.Fatalf("without overlay the unresolvable feed name must NOT be a silent no-match literal (pre-#2049 fail-open); got %v", snapsNoOverlay[0].SourceLiterals)
	}
	if !addressListHasSentinel(snapsNoOverlay[0].SourceLiterals) {
		t.Fatalf("without overlay the unresolvable feed name must route to the #3261 address sentinel (fail closed); got %v", snapsNoOverlay[0].SourceLiterals)
	}
}

// TestFeedBackedPolicyDestinationRoutesAsBookReference is the destination-side
// analogue (v4+v6 parity flows through expandBookNameToCIDRs automatically).
func TestFeedBackedPolicyDestinationRoutesAsBookReference(t *testing.T) {
	cfg := feedPolicyCfg("any", "blocklist")
	overlay := map[string][]string{
		"blocklist": {"203.0.113.0/24", "2001:db8:dead::/48"},
	}
	_, nameToID, _ := buildAddressBookTableWithFeeds(cfg, overlay)
	wantID := nameToID["blocklist"]
	if wantID == 0 {
		t.Fatalf("precondition: feed name must have an ID")
	}
	snaps, _ := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, overlay)
	if !containsID(snaps[0].DestinationBookIDs, wantID) {
		t.Fatalf("feed-backed destination must be a book reference; DestinationBookIDs=%v want %d", snaps[0].DestinationBookIDs, wantID)
	}
}

// TestEmptyFeedSnapshotYieldsNoPrefixes exercises the consumer's DEFENSIVE
// handling of an explicit present-but-empty overlay entry: it produces a row
// with no concrete prefixes (a match-none book reference) without panicking or
// erroring. NOTE (#5645): the daemon no longer PRODUCES this shape for an
// unready feed — feeds.Manager.SnapshotForBindings OMITS an unresolved feed
// name so the referencing policy fails CLOSED (see
// TestFeedBackedPolicyRoutesAsBookReference's no-overlay branch:
// absent name -> __unsupported_address__ sentinel). This test now only pins the
// consumer's no-panic behavior for a hand-supplied empty entry, NOT a reachable
// denylist fail-open.
func TestEmptyFeedSnapshotYieldsNoPrefixes(t *testing.T) {
	cfg := feedPolicyCfg("bad-actors", "any")
	overlay := map[string][]string{
		"bad-actors": {}, // bound but empty (no snapshot yet)
	}
	books, nameToID, _ := buildAddressBookTableWithFeeds(cfg, overlay)
	row := findBookByName(books, "bad-actors")
	if row != nil {
		if len(row.PrefixesV4) != 0 || len(row.PrefixesV6) != 0 {
			t.Fatalf("empty feed must yield no concrete prefixes, got v4=%v v6=%v", row.PrefixesV4, row.PrefixesV6)
		}
	}
	// The name is still classifiable (present in nameToID with an empty book)
	// so the policy snapshot builds without error.
	if _, ok := nameToID["bad-actors"]; !ok {
		t.Fatalf("empty feed-backed name must still be in nameToID (book reference to an empty set)")
	}
	snaps, _ := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, overlay)
	if len(snaps) != 1 {
		t.Fatalf("policy must still build with an empty feed; got %d rules", len(snaps))
	}
}

// TestFeedContentChangeReshapesPublishedSnapshot proves a feed content change
// reshapes the FULL published snapshot AND shifts its content hash, so
// Manager.Apply's duplicate-publish gate (snapshotContentHash) lets the
// refresh through. Both snapshots are built from the SAME *config.Config — the
// only difference is the overlay — which is exactly the feed onUpdate path
// (the typed config is byte-identical across a feed refresh).
func TestFeedContentChangeReshapesPublishedSnapshot(t *testing.T) {
	cfg := feedPolicyCfg("bad-actors", "any")
	ucfg := config.UserspaceConfig{}

	overlayP1 := map[string][]string{"bad-actors": {"198.51.100.0/24"}}
	overlayP2 := map[string][]string{"bad-actors": {"203.0.113.0/24"}}

	s1 := mustBuildSnapshotWithSchedulerState(t, cfg, ucfg, 1, 0, nil, nil, overlayP1)
	s2 := mustBuildSnapshotWithSchedulerState(t, cfg, ucfg, 1, 0, nil, nil, overlayP2)

	// The published address-book row follows the new content.
	row1 := findBookByName(s1.AddressBooks, "bad-actors")
	row2 := findBookByName(s2.AddressBooks, "bad-actors")
	if row1 == nil || row2 == nil {
		t.Fatalf("both snapshots must carry the feed-backed book row")
	}
	if !contains(row1.PrefixesV4, "198.51.100.0/24") {
		t.Fatalf("S1 must carry P1; got %v", row1.PrefixesV4)
	}
	if !contains(row2.PrefixesV4, "203.0.113.0/24") || contains(row2.PrefixesV4, "198.51.100.0/24") {
		t.Fatalf("S2 must carry P2 and not P1; got %v", row2.PrefixesV4)
	}

	// The content hash MUST differ so the duplicate-publish gate republishes.
	h1, ok1 := snapshotContentHash(s1)
	h2, ok2 := snapshotContentHash(s2)
	if !ok1 || !ok2 {
		t.Fatalf("content hash failed (ok1=%v ok2=%v)", ok1, ok2)
	}
	if h1 == h2 {
		t.Fatalf("feed content change must shift the snapshot content hash (else the refresh is silently dropped)")
	}

	// Conversely: identical overlay content yields an identical hash (the skip
	// is correct — no wasted round-trip).
	s1b := mustBuildSnapshotWithSchedulerState(t, cfg, ucfg, 9, 7, nil, nil, overlayP1)
	h1b, _ := snapshotContentHash(s1b)
	if h1 != h1b {
		t.Fatalf("identical feed content must yield identical content hash; %x != %x", h1, h1b)
	}
}

// TestFeedOverlayMergesWithStaticBook proves a feed-backed name that ALSO has
// static members merges both sets into one book row (the overlay is additive,
// not a replacement).
func TestFeedOverlayMergesWithStaticBook(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			AddressBook: &config.AddressBook{
				Addresses: map[string]*config.Address{
					"mixed": {Name: "mixed", Value: "10.0.0.0/8"},
				},
			},
		},
	}
	overlay := map[string][]string{"mixed": {"198.51.100.0/24"}}
	books, _, _ := buildAddressBookTableWithFeeds(cfg, overlay)
	row := findBookByName(books, "mixed")
	if row == nil {
		t.Fatalf("mixed book row missing")
	}
	if !contains(row.PrefixesV4, "10.0.0.0/8") || !contains(row.PrefixesV4, "198.51.100.0/24") {
		t.Fatalf("mixed row must carry BOTH static and feed prefixes; got %v", row.PrefixesV4)
	}
}

// TestLegacyAdapterForwardsFeedSnapshots proves the daemon hand-off reaches
// the runtime dataplane on the REAL path. The daemon asserts the runtime
// dataplane to feedSnapshotSetter and calls SetFeedSnapshots; on the default
// path the runtime dataplane is *LegacyDataPlaneAdapter (dpuserspace.Boot ->
// NewLegacyDataPlaneAdapter). Before the adapter forwarding method existed the
// assertion failed silently and m.feedOverlay stayed empty — feed enforcement
// was a no-op. This test drives the ADAPTER (not the Manager directly), which
// is the gap the prior #2049 tests missed: it FAILS to compile / leaves the
// overlay empty without LegacyDataPlaneAdapter.SetFeedSnapshots.
func TestLegacyAdapterForwardsFeedSnapshots(t *testing.T) {
	m := New()
	adapter := NewLegacyDataPlaneAdapter(m)

	overlay := map[string][]string{
		"bad-actors": {"198.51.100.0/24", "2001:db8:bad::/48"},
	}
	adapter.SetFeedSnapshots(overlay)

	got := m.feedSnapshotOverlay()
	if !contains(got["bad-actors"], "198.51.100.0/24") || !contains(got["bad-actors"], "2001:db8:bad::/48") {
		t.Fatalf("adapter SetFeedSnapshots did not reach Manager.feedOverlay; got %v", got)
	}

	// Prove enforcement actually follows: the full snapshot build under the
	// stored overlay emits the feed-backed book row. Mirrors the daemon path
	// where the next Compile/Apply consumes the cached overlay.
	cfg := feedPolicyCfg("bad-actors", "any")
	books, nameToID, _ := buildAddressBookTableWithFeeds(cfg, m.feedSnapshotOverlay())
	if findBookByName(books, "bad-actors") == nil {
		t.Fatalf("feed overlay forwarded through the adapter must enforce a book row")
	}
	if id, ok := nameToID["bad-actors"]; !ok || id == 0 {
		t.Fatalf("feed overlay forwarded through the adapter must populate nameToID (ok=%v id=%d)", ok, id)
	}

	// Nil-manager adapter must not panic (mirrors SetRouteOverlay's guard).
	(&LegacyDataPlaneAdapter{}).SetFeedSnapshots(overlay)
}

// TestSchedulerRepublishRetainsFeedEnforcement proves a CoS scheduler-state
// change (UpdatePolicyScheduleState) republishes a snapshot that STILL carries
// feed enforcement. Before the fix the scheduler-only republish rebuilt the
// policies/address-book with a nil overlay, dropping the feed-backed book rows
// until the next full apply. The test stands up a fake control socket, captures
// the published apply_snapshot, and asserts the feed-backed book row + ID
// survived. It FAILS against the nil-overlay republish.
func TestSchedulerRepublishRetainsFeedEnforcement(t *testing.T) {
	dir := t.TempDir()
	controlSock := filepath.Join(dir, "control.sock")
	ln, err := net.Listen("unix", controlSock)
	if err != nil {
		t.Fatalf("listen control socket: %v", err)
	}
	defer ln.Close()

	type captured struct {
		req ControlRequest
	}
	capCh := make(chan captured, 4)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			func() {
				defer conn.Close()
				var req ControlRequest
				if err := json.NewDecoder(conn).Decode(&req); err != nil {
					return
				}
				capCh <- captured{req: req}
				_ = json.NewEncoder(conn).Encode(ControlResponse{
					OK:     true,
					Status: &ProcessStatus{PID: 4321, Enabled: true},
				})
			}()
		}
	}()

	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("FindProcess: %v", err)
	}

	cfg := feedPolicyCfg("bad-actors", "any")
	overlay := map[string][]string{
		"bad-actors": {"198.51.100.0/24", "2001:db8:bad::/48"},
	}

	m := New()
	m.proc = &exec.Cmd{Process: proc}
	m.cfg.ControlSocket = controlSock
	// Seed the manager with the stored feed overlay (as SetFeedSnapshots does)
	// and a prior published snapshot for the scheduler republish to clone.
	m.SetFeedSnapshots(overlay)
	m.lastSnapshot = &ConfigSnapshot{Config: cfg, Generation: 5}

	// A CoS scheduler-state change with NO config change: must NOT drop the feed.
	m.UpdatePolicyScheduleState(cfg, map[string]bool{})

	var snap *ConfigSnapshot
	deadline := time.After(2 * time.Second)
	for snap == nil {
		select {
		case c := <-capCh:
			if c.req.Type == "apply_snapshot" && c.req.Snapshot != nil {
				snap = c.req.Snapshot
			}
		case <-deadline:
			t.Fatal("helper did not receive an apply_snapshot republish")
		}
	}

	row := findBookByName(snap.AddressBooks, "bad-actors")
	if row == nil {
		t.Fatalf("scheduler republish DROPPED the feed-backed book row; AddressBooks=%+v", snap.AddressBooks)
	}
	if !contains(row.PrefixesV4, "198.51.100.0/24") {
		t.Fatalf("scheduler republish lost the v4 feed prefix; PrefixesV4=%v", row.PrefixesV4)
	}
	if !contains(row.PrefixesV6, "2001:db8:bad::/48") {
		t.Fatalf("scheduler republish lost the v6 feed prefix; PrefixesV6=%v", row.PrefixesV6)
	}

	// And the policy still routes the feed token as a book reference, not a
	// no-match literal.
	if len(snap.Policies) != 1 {
		t.Fatalf("expected 1 republished policy rule, got %d", len(snap.Policies))
	}
	_, nameToID, _ := buildAddressBookTableWithFeeds(cfg, overlay)
	wantID := nameToID["bad-actors"]
	if wantID == 0 {
		t.Fatalf("precondition: feed name must have an ID")
	}
	if !containsID(snap.Policies[0].SourceBookIDs, wantID) {
		t.Fatalf("scheduler republish must keep the feed source as a book reference; SourceBookIDs=%v want %d",
			snap.Policies[0].SourceBookIDs, wantID)
	}
	if contains(snap.Policies[0].SourceLiterals, "bad-actors") {
		t.Fatalf("scheduler republish must NOT demote the feed source to a no-match literal; SourceLiterals=%v",
			snap.Policies[0].SourceLiterals)
	}
}
