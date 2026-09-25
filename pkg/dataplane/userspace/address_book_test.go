// #1606: tests for the wire-protocol address-book deduplication.
// Covers ID stability, HA determinism across map insertion order,
// content-dedup, collision recovery, the v3-shaped predicate, and
// the "any" normalization at book-build time.
package userspace

import (
	"encoding/json"
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func newBookCfg(addresses map[string]string) *config.Config {
	addrs := make(map[string]*config.Address, len(addresses))
	for name, value := range addresses {
		addrs[name] = &config.Address{Name: name, Value: value}
	}
	return &config.Config{
		Security: config.SecurityConfig{
			AddressBook: &config.AddressBook{
				Addresses:   addrs,
				AddressSets: nil,
			},
		},
	}
}

func TestAddressBookIDStability(t *testing.T) {
	cfg := newBookCfg(map[string]string{
		"alpha": "10.0.0.0/24",
		"beta":  "192.168.0.0/16",
	})
	a, _, _ := buildAddressBookTable(cfg)
	b, _, _ := buildAddressBookTable(cfg)
	if len(a) != len(b) || len(a) != 2 {
		t.Fatalf("expected 2 books in each build, got %d / %d", len(a), len(b))
	}
	for i := range a {
		if a[i].ID != b[i].ID {
			t.Fatalf("book %d: id drifted across builds (%d vs %d)", i, a[i].ID, b[i].ID)
		}
	}
}

func TestAddressBookIDDeterministicAcrossMapOrder(t *testing.T) {
	// Same content, 5 different insertion orders. All must produce
	// identical wire output.
	contents := map[string]string{
		"book-a": "10.1.0.0/24",
		"book-b": "10.2.0.0/24",
		"book-c": "10.3.0.0/24",
		"book-d": "10.4.0.0/24",
		"book-e": "10.5.0.0/24",
	}
	// Run multiple times. Because Go map iteration is randomized,
	// repeated builds should still produce identical output thanks
	// to the sort-by-name gate.
	var first []AddressBookSnapshot
	for i := 0; i < 5; i++ {
		cfg := newBookCfg(contents)
		books, _, _ := buildAddressBookTable(cfg)
		if i == 0 {
			first = books
			continue
		}
		if len(books) != len(first) {
			t.Fatalf("iter %d: book count drifted (%d vs %d)", i, len(books), len(first))
		}
		for j := range books {
			if books[j].ID != first[j].ID {
				t.Fatalf("iter %d book %d: id drifted (%d vs %d)", i, j, books[j].ID, first[j].ID)
			}
			if books[j].Name != first[j].Name {
				t.Fatalf("iter %d book %d: diag-name drifted (%q vs %q)", i, j, books[j].Name, first[j].Name)
			}
		}
	}
}

func TestAddressBookContentDedup(t *testing.T) {
	// Two books with identical content collapse to ONE row with ONE
	// id. The diagnostic name is the lexicographically smallest.
	cfg := newBookCfg(map[string]string{
		"zeta":   "10.0.0.0/24",
		"alpha":  "10.0.0.0/24",
		"middle": "10.0.0.0/24",
		"unique": "192.168.0.0/16",
	})
	books, nameToID, _ := buildAddressBookTable(cfg)
	if len(books) != 2 {
		t.Fatalf("expected 2 unique rows (one for 10.0.0.0/24, one for 192.168), got %d", len(books))
	}
	if nameToID["alpha"] != nameToID["middle"] || nameToID["alpha"] != nameToID["zeta"] {
		t.Fatalf("three names with same content should share an id")
	}
	// Diagnostic name for the shared content is "alpha" (smallest).
	var sharedRow *AddressBookSnapshot
	for i := range books {
		if books[i].ID == nameToID["alpha"] {
			sharedRow = &books[i]
		}
	}
	if sharedRow == nil {
		t.Fatalf("could not find shared content row")
	}
	if sharedRow.Name != "alpha" {
		t.Fatalf("diag-name for shared row should be 'alpha' (smallest), got %q", sharedRow.Name)
	}
}

func TestAddressBookContainingBareIPNormalizesToSlash32Or128(t *testing.T) {
	// Junos `set security address-book global address host1 10.0.0.1`
	// produces a value of "10.0.0.1" (bare IP, NOT CIDR). The wire
	// row must normalize this to "10.0.0.1/32" so the Rust side
	// sees a concrete CIDR. (Codex code-review F1.)
	cfg := newBookCfg(map[string]string{
		"host1": "10.0.0.1",
		"host2": "2001:db8::1",
	})
	books, _, _ := buildAddressBookTable(cfg)
	if len(books) != 2 {
		t.Fatalf("expected 2 books, got %d", len(books))
	}
	for _, b := range books {
		if b.Name == "host1" {
			if len(b.PrefixesV4) != 1 || b.PrefixesV4[0] != "10.0.0.1/32" {
				t.Fatalf("host1 bare IP should normalize to 10.0.0.1/32, got %v", b.PrefixesV4)
			}
		}
		if b.Name == "host2" {
			if len(b.PrefixesV6) != 1 || b.PrefixesV6[0] != "2001:db8::1/128" {
				t.Fatalf("host2 bare IP should normalize to 2001:db8::1/128, got %v", b.PrefixesV6)
			}
		}
	}
}

func TestAddressBookDedupsCIDRSetByContent(t *testing.T) {
	// Two books with the SAME effective CIDR set but one has a
	// duplicate member entry — after dedup they should share an ID.
	// (Codex code-review F3.)
	cfg := &config.Config{
		Security: config.SecurityConfig{
			AddressBook: &config.AddressBook{
				Addresses: map[string]*config.Address{
					"plain": {Name: "plain", Value: "10.0.0.0/24"},
				},
				AddressSets: map[string]*config.AddressSet{
					"dup-set": {
						Name:      "dup-set",
						Addresses: []string{"plain", "plain"},
					},
				},
			},
		},
	}
	books, nameToID, _ := buildAddressBookTable(cfg)
	if len(books) != 1 {
		t.Fatalf("expected 1 deduped row, got %d (members: %+v)", len(books), books)
	}
	if nameToID["plain"] != nameToID["dup-set"] {
		t.Fatalf("plain and dup-set should share id; got %d vs %d", nameToID["plain"], nameToID["dup-set"])
	}
}

func TestAddressBookContainingAnyNormalizesToZeroSlash(t *testing.T) {
	cfg := newBookCfg(map[string]string{"world": "any"})
	books, _, _ := buildAddressBookTable(cfg)
	if len(books) != 1 {
		t.Fatalf("expected 1 book, got %d", len(books))
	}
	hasV4 := false
	hasV6 := false
	for _, p := range books[0].PrefixesV4 {
		if p == "0.0.0.0/0" {
			hasV4 = true
		}
	}
	for _, p := range books[0].PrefixesV6 {
		if p == "::/0" {
			hasV6 = true
		}
	}
	if !hasV4 || !hasV6 {
		t.Fatalf("'any' should normalize to (0.0.0.0/0, ::/0); got v4=%v v6=%v", books[0].PrefixesV4, books[0].PrefixesV6)
	}
}

func TestClassifyPolicyAddresses(t *testing.T) {
	cfg := newBookCfg(map[string]string{
		"corp-net": "10.0.0.0/8",
		"vpn-net":  "192.168.0.0/16",
	})
	_, nameToID, _ := buildAddressBookTable(cfg)
	// Mix: 2 named books + 1 literal CIDR + 1 "any" + 1 unknown name.
	bookIDs, literals := classifyPolicyAddresses(cfg, nameToID, []string{
		"corp-net", "192.168.5.5/32", "any", "vpn-net", "unknown-book",
	})
	if len(bookIDs) != 2 {
		t.Fatalf("expected 2 book IDs, got %d", len(bookIDs))
	}
	// bookIDs are sorted+deduped.
	if !(bookIDs[0] < bookIDs[1]) {
		t.Fatalf("bookIDs not sorted: %v", bookIDs)
	}
	// Literals include the explicit CIDR + "any" + the unknown
	// name (treated as free-form literal).
	wantLiterals := map[string]bool{
		"192.168.5.5/32": true,
		"any":            true,
		"unknown-book":   true,
	}
	for _, lit := range literals {
		if !wantLiterals[lit] {
			t.Fatalf("unexpected literal %q in %v", lit, literals)
		}
	}
	if len(literals) != 3 {
		t.Fatalf("expected 3 literals, got %d (%v)", len(literals), literals)
	}
}

func TestPolicyBuildEmitsBookIDsAndLiterals(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			AddressBook: &config.AddressBook{
				Addresses: map[string]*config.Address{
					"corp-net": {Name: "corp-net", Value: "10.0.0.0/8"},
				},
			},
			Policies: []*config.ZonePairPolicies{
				{
					FromZone: "trust",
					ToZone:   "untrust",
					Policies: []*config.Policy{
						{
							Name: "test-rule",
							Match: config.PolicyMatch{
								SourceAddresses:      []string{"corp-net"},
								DestinationAddresses: []string{"192.168.1.0/24"},
							},
							Action: config.PolicyPermit,
						},
					},
				},
			},
		},
	}
	books, nameToID, err := buildAddressBookTable(cfg)
	if err != nil {
		t.Fatalf("buildAddressBookTable: %v", err)
	}
	snaps, err := buildPolicySnapshotsWithAddressBook(cfg, nil, nil, nameToID)
	if err != nil {
		t.Fatalf("buildPolicySnapshotsWithAddressBook: %v", err)
	}
	if len(snaps) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(snaps))
	}
	if len(snaps[0].SourceBookIDs) != 1 {
		t.Fatalf("expected 1 source book id, got %v", snaps[0].SourceBookIDs)
	}
	if len(snaps[0].SourceLiterals) != 0 {
		t.Fatalf("source had a book ref, no literals expected, got %v", snaps[0].SourceLiterals)
	}
	if len(snaps[0].DestinationBookIDs) != 0 {
		t.Fatalf("destination was a literal CIDR, no book ids expected, got %v", snaps[0].DestinationBookIDs)
	}
	if len(snaps[0].DestinationLiterals) != 1 || snaps[0].DestinationLiterals[0] != "192.168.1.0/24" {
		t.Fatalf("expected destination literal=[192.168.1.0/24], got %v", snaps[0].DestinationLiterals)
	}
	// A v3 rule carries the book reference; the shared table owns the resolved
	// prefix payload instead of repeating it on every rule.
	if len(snaps[0].SourceAddresses) != 0 {
		t.Fatalf("book-backed v3 rule duplicated its legacy prefix payload: %v", snaps[0].SourceAddresses)
	}
	bookID := snaps[0].SourceBookIDs[0]
	if nameToID["corp-net"] != bookID {
		t.Fatalf("source book ID = %d, table ID = %d", bookID, nameToID["corp-net"])
	}
	for _, book := range books {
		if book.ID == bookID {
			if !slices.Contains(book.PrefixesV4, "10.0.0.0/8") {
				t.Fatalf("book row %d lost 10.0.0.0/8: %+v", bookID, book)
			}
			return
		}
	}
	t.Fatalf("source book ID %d has no address-book row", bookID)
}
func TestSnapshotBuildHashesEachAddressBookBucketOnce11005(t *testing.T) {
	cases := []struct {
		name        string
		addresses   map[string]string
		feedOverlay map[string][]string
		policyName  string
	}{
		{
			name: "static",
			addresses: map[string]string{
				"shared-a": "10.0.0.1/24",
				"shared-b": "10.0.0.0/24",
				"other":    "192.0.2.0/24",
			},
			policyName: "shared-a",
		},
		{
			name: "feed-backed",
			addresses: map[string]string{
				"static": "192.0.2.0/24",
			},
			feedOverlay: map[string][]string{
				"feed-book": {"198.51.100.0/24"},
			},
			policyName: "feed-book",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := newBookCfg(tc.addresses)
			cfg.Security.Policies = []*config.ZonePairPolicies{{
				FromZone: "trust",
				ToZone:   "untrust",
				Policies: []*config.Policy{{
					Name:   "rule",
					Match:  config.PolicyMatch{SourceAddresses: []string{tc.policyName}},
					Action: config.PolicyPermit,
				}},
			}}
			originalHash := addressBookContentHash64
			hashCalls := 0
			addressBookContentHash64 = func(canonical []byte) uint64 {
				hashCalls++
				return originalHash(canonical)
			}
			defer func() { addressBookContentHash64 = originalHash }()

			snapshot, err := buildSnapshotWithSchedulerStateAndNATCounters(
				cfg, config.UserspaceConfig{}, 1, 0, nil, nil, tc.feedOverlay, nil,
			)
			if err != nil {
				t.Fatalf("build snapshot: %v", err)
			}
			if hashCalls != len(snapshot.AddressBooks) {
				t.Fatalf("hashed %d canonical buckets for %d snapshot rows; want exactly one hash per row",
					hashCalls, len(snapshot.AddressBooks))
			}
			if len(snapshot.Policies) != 1 || len(snapshot.Policies[0].SourceBookIDs) != 1 {
				t.Fatalf("policy did not retain one v3 book reference: %+v", snapshot.Policies)
			}
		})
	}
}

func TestAddressBookTableParsesEachRawPrefixOnce11006(t *testing.T) {
	cfg := newBookCfg(map[string]string{
		"base": "10.0.0.1/24",
		"v6":   "2001:db8::1",
	})
	cfg.Security.AddressBook.AddressSets = map[string]*config.AddressSet{
		"nested": {
			Name:        "nested",
			Addresses:   []string{"base", "base", "v6"},
			AddressSets: []string{"leaf"},
		},
		"outer": {Name: "outer", AddressSets: []string{"nested"}},
		"leaf":  {Name: "leaf", Addresses: []string{"base"}},
	}
	overlay := map[string][]string{
		"nested": {"192.0.2.7/24", "192.0.2.7/24", "198.51.100.8/24"},
	}
	wantRaw := []string{
		"10.0.0.1/24",
		"2001:db8::1/128",
		"192.0.2.7/24",
		"198.51.100.8/24",
	}
	originalParser := parseAddressBookCIDR
	parseCalls := make(map[string]int)
	parseAddressBookCIDR = func(value string) (net.IP, *net.IPNet, error) {
		parseCalls[value]++
		return originalParser(value)
	}
	defer func() { parseAddressBookCIDR = originalParser }()

	build := func() ([]AddressBookSnapshot, map[string]uint32) {
		t.Helper()
		clear(parseCalls)
		books, nameToID, err := buildAddressBookTableWithFeeds(cfg, overlay)
		if err != nil {
			t.Fatalf("build address-book table: %v", err)
		}
		for _, raw := range wantRaw {
			if parseCalls[raw] != 1 {
				t.Errorf("CIDR %q parsed %d times in one table build; want once", raw, parseCalls[raw])
			}
		}
		return books, nameToID
	}
	first, firstIDs := build()
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatalf("marshal first table: %v", err)
	}
	second, secondIDs := build()
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatalf("marshal second table: %v", err)
	}
	if string(firstJSON) != string(secondJSON) {
		t.Fatalf("canonical address-book output changed between builds:\nfirst:  %s\nsecond: %s",
			firstJSON, secondJSON)
	}
	if firstIDs["nested"] != firstIDs["outer"] || secondIDs["nested"] != secondIDs["outer"] {
		t.Fatalf("nested and outer sets with identical resolved content received different IDs: first=%v second=%v",
			firstIDs, secondIDs)
	}

}

func TestSharedFeedBookSnapshotStoresPrefixesOnce11007(t *testing.T) {
	const ruleCount = 24
	const prefixCount = 512
	prefixes := make([]string, prefixCount)
	for i := range prefixes {
		prefixes[i] = fmt.Sprintf("10.%d.%d.0/24", i/256, i%256)
	}
	cfg := newBookCfg(nil)
	policies := make([]*config.Policy, ruleCount)
	for i := range policies {
		policies[i] = &config.Policy{
			Name:   fmt.Sprintf("rule-%02d", i),
			Match:  config.PolicyMatch{SourceAddresses: []string{"shared-feed"}},
			Action: config.PolicyPermit,
		}
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "trust",
		ToZone:   "untrust",
		Policies: policies,
	}}
	feedOverlay := map[string][]string{"shared-feed": prefixes}
	snapshot, err := buildSnapshotWithSchedulerStateAndNATCounters(
		cfg, config.UserspaceConfig{}, 1, 0, nil, nil, feedOverlay, nil,
	)
	if err != nil {
		t.Fatalf("build shared-feed snapshot: %v", err)
	}
	if len(snapshot.Policies) != ruleCount {
		t.Fatalf("snapshot contains %d policy rows; want %d", len(snapshot.Policies), ruleCount)
	}
	if len(snapshot.AddressBooks) != 1 {
		t.Fatalf("shared feed content produced %d address-book rows; want one", len(snapshot.AddressBooks))
	}
	if len(snapshot.AddressBooks[0].PrefixesV4) != prefixCount {
		t.Fatalf("shared feed book has %d prefixes; want %d", len(snapshot.AddressBooks[0].PrefixesV4), prefixCount)
	}
	bookID := snapshot.AddressBooks[0].ID
	for i, rule := range snapshot.Policies {
		if len(rule.SourceBookIDs) != 1 || rule.SourceBookIDs[0] != bookID {
			t.Errorf("rule %d lost shared book ID %d: %v", i, bookID, rule.SourceBookIDs)
		}
		if len(rule.SourceAddresses) != 0 {
			t.Errorf("v3 rule %d repeated %d legacy prefixes", i, len(rule.SourceAddresses))
		}
	}

	wire, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("marshal shared-feed snapshot: %v", err)
	}
	encoded := string(wire)
	if strings.Contains(encoded, `"source_addresses"`) {
		t.Fatal("v3 shared-book rules serialized legacy source address payloads")
	}
	for _, prefix := range prefixes {
		if count := strings.Count(encoded, prefix); count != 1 {
			t.Fatalf("snapshot contains shared feed prefix %q %d times; want once", prefix, count)
		}
	}

	smallOverlay := map[string][]string{"shared-feed": prefixes[:1]}
	nameToID := map[string]uint32{"shared-feed": bookID}
	measureAllocs := func(overlay map[string][]string) float64 {
		t.Helper()
		return testing.AllocsPerRun(5, func() {
			if _, err := buildPolicySnapshotsWithAddressBook(cfg, nil, overlay, nameToID); err != nil {
				panic(err)
			}
		})
	}
	smallAllocs := measureAllocs(smallOverlay)
	largeAllocs := measureAllocs(feedOverlay)
	if largeAllocs > smallAllocs+1 {
		t.Fatalf("policy lowering allocations grew with shared feed size: 1-prefix=%.1f, %d-prefix=%.1f",
			smallAllocs, prefixCount, largeAllocs)
	}
}
func TestPolicyResolvedFingerprintTracksAddressBookDefinition11007(t *testing.T) {
	cfg := newBookCfg(map[string]string{"host": "10.0.0.1/32"})
	cfg.Security.AddressBook.AddressSets = map[string]*config.AddressSet{
		"shared": {Name: "shared", Addresses: []string{"host"}},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "trust",
		ToZone:   "untrust",
		Policies: []*config.Policy{{
			Name:   "address-set-policy",
			Match:  config.PolicyMatch{SourceAddresses: []string{"shared"}},
			Action: config.PolicyPermit,
		}},
	}}
	before := PolicyResolvedFingerprints(cfg)
	if len(before) != 1 {
		t.Fatalf("fingerprints = %v, want one stable policy fingerprint", before)
	}
	var key string
	for key = range before {
	}
	cfg.Security.AddressBook.Addresses["host"].Value = "10.0.0.2/32"
	after := PolicyResolvedFingerprints(cfg)
	if after[key] == "" || after[key] == before[key] {
		t.Fatalf("changing a referenced address-set definition did not change fingerprint: before=%v after=%v",
			before, after)
	}
}
