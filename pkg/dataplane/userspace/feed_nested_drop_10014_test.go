// feed_nested_drop_10014_test.go: #10014 — a fail-mode drop binding as the SOLE
// member of a nested address-set rendered refuse instead of drop.
//
// Drop + all-hold-dropped publishes a PRESENT-but-empty overlay entry
// (SnapshotForBindings, #9689). A direct token lowers it to match-none via the
// addrRepresentable feedOverlay short-circuit, but a nested member routes
// through nameRepresentability, whose feed-bound branch gated the concrete bit
// on live prefix count (len(feeds) > 0). A sole-drop nested set was therefore
// (representable, NOT concrete) and the top-level r&&c gate refused it via the
// #3261 sentinel — a committed drop intent enforced as a whole-snapshot reject.
//
// The fix treats a present-but-empty overlay entry for a DECLARED fail-mode
// drop binding as concrete-drop (SnapshotForBindings publishes empty ONLY for
// drop + all-hold-dropped: a ready feed always holds >= 1 prefix, so all-ready
// can never publish empty, and retain/default/never-fetched/unknown are
// omitted, never present-empty). Genuinely unresolved bindings stay omitted,
// so the #5753 omission guard still refuses them.
package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// denyNestedSoleBindingCfg builds a config where the address-set "drop-set"
// has a SINGLE member "partners" — the #10014 shape. When withBinding is true,
// "partners" is also a declared feed-backed dynamic-address binding with the
// given fail-mode. A `deny` policy references the SET, routing the member
// through the NESTED nameRepresentability recursion rather than the top-level
// addrRepresentable guard.
func denyNestedSoleBindingCfg(withBinding bool, failMode string) *config.Config {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			AddressBook: &config.AddressBook{
				AddressSets: map[string]*config.AddressSet{
					"drop-set": {
						Name:      "drop-set",
						Addresses: []string{"partners"},
					},
				},
			},
			Policies: []*config.ZonePairPolicies{
				{
					FromZone: "untrust",
					ToZone:   "trust",
					Policies: []*config.Policy{
						{
							Name: "block-partners",
							Match: config.PolicyMatch{
								SourceAddresses:      []string{"drop-set"},
								DestinationAddresses: []string{"any"},
							},
							Action: config.PolicyDeny,
						},
					},
				},
			},
		},
	}
	if withBinding {
		cfg.Security.DynamicAddress = config.DynamicAddressConfig{
			AddressBindings: map[string]*config.AddressBinding{
				"partners": {Name: "partners", FeedNames: []string{"partner-feed"}, FailMode: failMode},
			},
		}
	}
	return cfg
}

// bookRowByID10014 returns the address-book row carrying id, or nil when no
// row carries it (a dangling book reference).
func bookRowByID10014(books []AddressBookSnapshot, id uint32) *AddressBookSnapshot {
	for i := range books {
		if books[i].ID == id {
			return &books[i]
		}
	}
	return nil
}

// TestSoleDropBindingInNestedSetPublishesDrop10014 is the #10014 fail-on-revert:
// a fail-mode drop binding as the SOLE member of a nested address-set, with
// the present-but-empty overlay row SnapshotForBindings emits for drop +
// all-hold-dropped, must publish the drop — a book reference to an empty row
// (match-none) — and NOT refuse via the #3261 sentinel. Neutralizing the fix
// (gating the concrete bit on len(feeds) > 0 again) makes the set
// (representable, NOT concrete), so the r&&c gate emits the sentinel and the
// first assertion turns RED.
func TestSoleDropBindingInNestedSetPublishesDrop10014(t *testing.T) {
	cfg := denyNestedSoleBindingCfg(true, "drop")
	// Exactly what SnapshotForBindings emits for drop + all-hold-dropped (#9689).
	overlay := map[string][]string{"partners": {}}

	books, nameToID, err := buildAddressBookTableWithFeeds(cfg, overlay)
	if err != nil {
		t.Fatalf("buildAddressBookTableWithFeeds error: %v", err)
	}
	if id, ok := nameToID["drop-set"]; !ok || id == 0 {
		t.Fatalf("precondition: the nesting address-set must create a name/ID; nameToID=%v", nameToID)
	}

	snaps, err := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, overlay)
	if err != nil {
		t.Fatalf("buildPolicySnapshots error: %v", err)
	}
	if len(snaps) != 1 {
		t.Fatalf("expected 1 policy rule, got %d", len(snaps))
	}
	rule := snaps[0]

	// The committed drop intent must NOT refuse the snapshot ...
	if addressListHasSentinel(rule.SourceLiterals) || addressListHasSentinel(rule.SourceAddresses) {
		t.Fatalf("a sole drop binding nested in an address-set must publish drop, not refuse via %s: "+
			"SourceLiterals=%v SourceAddresses=%v", unsupportedAddressSentinel, rule.SourceLiterals, rule.SourceAddresses)
	}
	// ... it routes as a book reference ...
	if len(rule.SourceBookIDs) == 0 {
		t.Fatal("a sole drop binding nested in an address-set must route as a book reference; SourceBookIDs empty")
	}
	// ... to an EMPTY row (match-none = the drop). A non-empty row would
	// enforce prefixes the operator dropped; a missing row is a dangling ref.
	row := bookRowByID10014(books, rule.SourceBookIDs[0])
	if row == nil {
		t.Fatalf("no address-book row for source book ID %d", rule.SourceBookIDs[0])
	}
	if len(row.PrefixesV4) != 0 || len(row.PrefixesV6) != 0 {
		t.Fatalf("sole-drop nested set row must be empty (match-none drop); got v4=%v v6=%v",
			row.PrefixesV4, row.PrefixesV6)
	}
}

// TestSoleUnreadyBindingInNestedSetStillRefuses10014 is the #10014 control: a
// genuinely unresolved binding (the overlay OMITS it — a never-fetched or
// unknown feed) nested as a sole set member must STILL refuse, EVEN when the
// declared binding says fail-mode drop (drop covers a hold-interval drop only,
// never a feed with no snapshot — #9689). The concrete-drop fix must not
// weaken this omission guard.
func TestSoleUnreadyBindingInNestedSetStillRefuses10014(t *testing.T) {
	for _, mode := range []string{"", "retain", "drop"} {
		name := mode
		if name == "" {
			name = "default"
		}
		t.Run("fail-mode-"+name, func(t *testing.T) {
			cfg := denyNestedSoleBindingCfg(true, mode)
			// Omitted: exactly what SnapshotForBindings emits for a
			// never-fetched or unknown feed, in every fail-mode.
			overlay := map[string][]string{}
			snaps, err := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, overlay)
			if err != nil {
				t.Fatalf("buildPolicySnapshots error: %v", err)
			}
			if len(snaps) != 1 {
				t.Fatalf("expected 1 policy rule, got %d", len(snaps))
			}
			rule := snaps[0]
			if len(rule.SourceBookIDs) != 0 {
				t.Fatalf("fail-open: a sole unresolved nested binding (fail-mode %q) routed as "+
					"a book reference; SourceBookIDs=%v", mode, rule.SourceBookIDs)
			}
			if !addressListHasSentinel(rule.SourceLiterals) {
				t.Fatalf("a sole unresolved nested binding (fail-mode %q) must fail CLOSED via "+
					"the __unsupported_address__ sentinel; SourceLiterals=%v", mode, rule.SourceLiterals)
			}
		})
	}
}

// TestNestedPresentEmptyNonDropBindingStillRefuses10014 pins the fix's
// discriminator: a PRESENT-but-empty overlay entry for a retain/default (or
// undeclared) binding still refuses. The daemon never emits that shape —
// SnapshotForBindings omits non-drop unready bindings — so it only arises from
// a hand-built overlay, and the concrete-drop treatment must apply ONLY to
// declared fail-mode drop bindings (never unconditionally, per the
// TestFeedOnlySetEnforcesUnderA/empty-feed control).
func TestNestedPresentEmptyNonDropBindingStillRefuses10014(t *testing.T) {
	cases := []struct {
		name        string
		withBinding bool
		failMode    string
	}{
		{name: "default", withBinding: true, failMode: ""},
		{name: "retain", withBinding: true, failMode: "retain"},
		{name: "undeclared", withBinding: false, failMode: ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := denyNestedSoleBindingCfg(c.withBinding, c.failMode)
			overlay := map[string][]string{"partners": {}}
			snaps, err := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, overlay)
			if err != nil {
				t.Fatalf("buildPolicySnapshots error: %v", err)
			}
			if len(snaps) != 1 {
				t.Fatalf("expected 1 policy rule, got %d", len(snaps))
			}
			rule := snaps[0]
			if len(rule.SourceBookIDs) != 0 {
				t.Fatalf("fail-open: a present-empty nested binding (%s) routed as "+
					"a book reference; SourceBookIDs=%v", c.name, rule.SourceBookIDs)
			}
			if !addressListHasSentinel(rule.SourceLiterals) {
				t.Fatalf("a present-empty nested binding (%s) must fail CLOSED via "+
					"the __unsupported_address__ sentinel; SourceLiterals=%v", c.name, rule.SourceLiterals)
			}
		})
	}
}
