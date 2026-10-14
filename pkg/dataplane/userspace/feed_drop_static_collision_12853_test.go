// feed_drop_static_collision_12853_test.go: #12853 (D4-06).
//
// addressBookExpansionResolver.expand merges feed values with a same-named
// static book entry unconditionally. With a declared fail-mode drop binding
// whose feed hold-drops (present-but-empty overlay []string{}) and a same-named
// static entry, the row becomes the static prefix instead of the explicit
// match-none drop, and a nested set member likewise resurrects the static
// prefix. An overlapping CollidingNames entry must also resolve to nothing,
// per nameRepresentability's rejection. These are fail-on-revert: removing
// the feed-precedence / collision gate in expand restores the static prefixes.
package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func cfg12853(books *config.AddressBook, policies []*config.Policy) *config.Config {
	cfg := &config.Config{}
	cfg.Security.AddressBook = books
	cfg.Security.DynamicAddress.AddressBindings = map[string]*config.AddressBinding{
		"denylist": {Name: "denylist", FeedNames: []string{"threat"}, FailMode: "drop"},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{{FromZone: "untrust", ToZone: "trust", Policies: policies}}
	return cfg
}

func TestDropHoldDroppedFeedWithStaticAliasPublishesEmpty12853(t *testing.T) {
	books := &config.AddressBook{Addresses: map[string]*config.Address{"denylist": {Name: "denylist", Value: "10.0.0.0/8"}}}
	pol := &config.Policy{Name: "p", Match: config.PolicyMatch{SourceAddresses: []string{"denylist"}, DestinationAddresses: []string{"any"}}, Action: config.PolicyDeny}
	cfg := cfg12853(books, []*config.Policy{pol})
	overlay := map[string][]string{"denylist": {}}

	booksRows, nameToID, err := buildAddressBookTableWithFeeds(cfg, overlay)
	if err != nil {
		t.Fatal(err)
	}
	id, ok := nameToID["denylist"]
	if !ok || id == 0 {
		t.Fatalf("precondition nameToID=%v", nameToID)
	}
	var row *AddressBookSnapshot
	for i := range booksRows {
		if booksRows[i].ID == id {
			row = &booksRows[i]
		}
	}
	if row == nil || len(row.PrefixesV4) != 0 || len(row.PrefixesV6) != 0 {
		t.Fatalf("hold-dropped fail-mode drop row must be empty, got %+v", row)
	}
	if v4, v6 := expandBookNameToCIDRs(cfg, overlay, "denylist"); len(v4) != 0 || len(v6) != 0 {
		t.Fatalf("expand must be empty, got %v %v", v4, v6)
	}
	snaps, err := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, overlay)
	if err != nil || len(snaps) != 1 {
		t.Fatalf("snaps=%d err=%v", len(snaps), err)
	}
	rule := snaps[0]
	if addressListHasSentinel(rule.SourceLiterals) || addressListHasSentinel(rule.SourceAddresses) || len(rule.SourceBookIDs) != 1 || rule.SourceBookIDs[0] != id {
		t.Fatalf("drop must publish book ref to empty row, got ids=%v lits=%v addrs=%v", rule.SourceBookIDs, rule.SourceLiterals, rule.SourceAddresses)
	}
	// Controls: non-empty feed unions with static; no overlay entry keeps static.
	if v4, _ := expandBookNameToCIDRs(cfg, map[string][]string{"denylist": {"198.51.100.0/24"}}, "denylist"); len(v4) != 2 {
		t.Fatalf("ready feed must union with static, got %v", v4)
	}
	if v4, _ := expandBookNameToCIDRs(cfg, map[string][]string{}, "denylist"); len(v4) != 1 {
		t.Fatalf("no overlay must keep static, got %v", v4)
	}
}

func TestDropHoldDroppedFeedNestedInSetPublishesEmpty12853(t *testing.T) {
	books := &config.AddressBook{
		Addresses:   map[string]*config.Address{"denylist": {Name: "denylist", Value: "10.0.0.0/8"}},
		AddressSets: map[string]*config.AddressSet{"grp": {Name: "grp", Addresses: []string{"denylist"}}},
	}
	pol := &config.Policy{Name: "p", Match: config.PolicyMatch{SourceAddresses: []string{"grp"}, DestinationAddresses: []string{"any"}}, Action: config.PolicyDeny}
	cfg := cfg12853(books, []*config.Policy{pol})
	overlay := map[string][]string{"denylist": {}}
	if v4, v6 := expandBookNameToCIDRs(cfg, overlay, "grp"); len(v4) != 0 || len(v6) != 0 {
		t.Fatalf("nested hold-dropped drop member must make set empty, got %v %v", v4, v6)
	}
	snaps, err := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, overlay)
	if err != nil || len(snaps) != 1 {
		t.Fatalf("snaps=%d err=%v", len(snaps), err)
	}
	rule := snaps[0]
	if addressListHasSentinel(rule.SourceLiterals) || len(rule.SourceBookIDs) != 1 {
		t.Fatalf("nested drop must publish empty book row, got ids=%v lits=%v", rule.SourceBookIDs, rule.SourceLiterals)
	}
}

func TestCollidingAddressBookNameExpandsToNothing12853(t *testing.T) {
	books := &config.AddressBook{
		Addresses:      map[string]*config.Address{"blocked": {Name: "blocked", Value: "10.0.0.0/8"}, "other": {Name: "other", Value: "192.0.2.1/32"}},
		AddressSets:    map[string]*config.AddressSet{"blocked": {Name: "blocked", Addresses: []string{"other"}}},
		CollidingNames: map[string]struct{}{"blocked": {}},
	}
	cfg := &config.Config{}
	cfg.Security.AddressBook = books
	// Policy is irrelevant to the expansion unit; nameRepresentability rejects.
	if v4, v6 := expandBookNameToCIDRs(cfg, nil, "blocked"); len(v4) != 0 || len(v6) != 0 {
		t.Fatalf("colliding name must expand to nothing, got %v %v", v4, v6)
	}
	books.AddressSets["grp"] = &config.AddressSet{Name: "grp", Addresses: []string{"blocked"}}
	if v4, v6 := expandBookNameToCIDRs(cfg, nil, "grp"); len(v4) != 0 || len(v6) != 0 {
		t.Fatalf("set containing colliding member must expand to nothing, got %v %v", v4, v6)
	}
	// Even a policy-unreferenced colliding row must not carry static content.
	rows, nameToID, err := buildAddressBookTableWithFeeds(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	id, ok := nameToID["blocked"]
	if !ok || id == 0 {
		t.Fatalf("colliding name must retain its empty book row, nameToID=%v", nameToID)
	}
	for _, r := range rows {
		if r.ID == id {
			if len(r.PrefixesV4) != 0 || len(r.PrefixesV6) != 0 {
				t.Fatalf("colliding row must be empty, got %+v", r)
			}
			return
		}
	}
	t.Fatalf("address-book row for colliding name ID %d not found", id)
}
