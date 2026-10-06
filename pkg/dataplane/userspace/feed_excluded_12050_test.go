package userspace

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/feeds"
)

func excludedDropFeedConfig12050(addresses []string, nested, destinationExcluded bool) *config.Config {
	return excludedDropFeedConfigNamed12050("partners", addresses, nested, destinationExcluded)
}

func excludedDropFeedConfigNamed12050(binding string, addresses []string, nested, destinationExcluded bool) *config.Config {
	ab := &config.AddressBook{}
	if nested {
		ab.AddressSets = map[string]*config.AddressSet{
			"partners-set": {Name: "partners-set", Addresses: []string{binding}},
		}
		addresses = []string{"partners-set"}
	}
	match := config.PolicyMatch{
		SourceAddresses:       addresses,
		SourceAddressExcluded: !destinationExcluded,
		DestinationAddresses:  []string{"any"},
		Applications:          []string{"any"},
	}
	if destinationExcluded {
		match.SourceAddresses = []string{"any"}
		match.SourceAddressExcluded = false
		match.DestinationAddresses = addresses
		match.DestinationAddressExcluded = true
	}
	return &config.Config{
		Security: config.SecurityConfig{
			DefaultPolicy: config.PolicyPermit,
			Zones: map[string]*config.ZoneConfig{
				"trust":   {Name: "trust"},
				"untrust": {Name: "untrust"},
			},
			AddressBook: ab,
			DynamicAddress: config.DynamicAddressConfig{
				AddressBindings: map[string]*config.AddressBinding{
					binding: {Name: binding, FeedNames: []string{"partner-feed"}, FailMode: "drop"},
				},
			},
			Policies: []*config.ZonePairPolicies{{
				FromZone: "trust",
				ToZone:   "untrust",
				Policies: []*config.Policy{
					{
						Name:   "deny-except-partners",
						Match:  match,
						Action: config.PolicyDeny,
					},
					{
						Name: "later-permit",
						Match: config.PolicyMatch{
							SourceAddresses:      []string{"any"},
							DestinationAddresses: []string{"any"},
							Applications:         []string{"any"},
						},
						Action: config.PolicyPermit,
					},
				},
			}},
		},
	}
}

// A feed binding whose name parses as an IP address must still resolve by name
// before literal parsing. An empty fail-mode drop feed on an excluded DENY must
// refuse publication, for both CIDR and bare-IP spellings.
func TestExcludedDenyOverLiteralNamedDropFeedRefusesSnapshot12050(t *testing.T) {
	for _, binding := range []string{"10.0.1.0/24", "192.0.2.7"} {
		t.Run(binding, func(t *testing.T) {
			cfg := excludedDropFeedConfigNamed12050(binding, []string{binding}, false, false)
			overlay := map[string][]string{binding: {}}
			snaps, err := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, overlay)
			if err != nil {
				t.Fatalf("buildPolicySnapshots error: %v", err)
			}
			if len(snaps) != 2 {
				t.Fatalf("expected the deny and later permit rules, got %d", len(snaps))
			}
			first := snaps[0]
			if !addressListHasSentinel(first.SourceLiterals) || len(first.SourceBookIDs) != 0 {
				t.Fatalf("empty drop feed named like a literal must poison the excluded side; got literals=%v bookIDs=%v",
					first.SourceLiterals, first.SourceBookIDs)
			}
			if reasons := PolicyContentRejectionReasons(cfg, overlay); len(reasons) == 0 {
				t.Fatal("poisoned excluded-deny snapshot produced no whole-snapshot rejection reason")
			}
		})
	}
}

// A genuine literal sibling remains concrete even when another token is a
// literal-shaped feed name, preserving populated-sibling exclusion behavior.
func TestExcludedDenyLiteralNamedDropFeedWithLiteralSiblingPublishes12050(t *testing.T) {
	for _, binding := range []string{"10.0.1.0/24", "192.0.2.7"} {
		t.Run(binding, func(t *testing.T) {
			cfg := excludedDropFeedConfigNamed12050(binding,
				[]string{binding, "198.51.100.0/24"}, false, false)
			overlay := map[string][]string{binding: {}}
			snaps, err := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, overlay)
			if err != nil {
				t.Fatalf("buildPolicySnapshots error: %v", err)
			}
			if len(snaps) != 2 {
				t.Fatalf("expected the deny and later permit rules, got %d", len(snaps))
			}
			if addressListHasSentinel(snaps[0].SourceLiterals) || len(snaps[0].SourceBookIDs) == 0 {
				t.Fatalf("a genuine literal sibling must preserve normal exclusion behavior; got literals=%v bookIDs=%v",
					snaps[0].SourceLiterals, snaps[0].SourceBookIDs)
			}
			if reasons := PolicyContentRejectionReasons(cfg, overlay); len(reasons) != 0 {
				t.Fatalf("a genuine literal sibling must not reject the snapshot: %v", reasons)
			}
		})
	}
}

// An excluded deny over an all-hold-dropped fail-mode drop feed cannot be
// published as an empty book: the runtime's empty-excluded guard would skip it
// and let a later permit win. The whole snapshot must be refused instead.
func TestExcludedDenyOverEmptyDropFeedRefusesSnapshot12050(t *testing.T) {
	for _, tc := range []struct {
		name                string
		addresses           []string
		nested              bool
		destinationExcluded bool
		emptyDropOnly       bool
	}{
		{name: "source direct", addresses: []string{"partners"}, emptyDropOnly: true},
		{name: "source nested", nested: true, emptyDropOnly: true},
		{name: "destination direct", addresses: []string{"partners"}, destinationExcluded: true, emptyDropOnly: true},
		{name: "destination nested", nested: true, destinationExcluded: true, emptyDropOnly: true},
		{name: "populated sibling literal", addresses: []string{"partners", "192.0.2.0/24"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := excludedDropFeedConfig12050(tc.addresses, tc.nested, tc.destinationExcluded)
			overlay := map[string][]string{"partners": {}}
			snaps, err := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, overlay)
			if err != nil {
				t.Fatalf("buildPolicySnapshots error: %v", err)
			}
			if len(snaps) != 2 {
				t.Fatalf("expected the deny and later permit rules, got %d", len(snaps))
			}
			first := snaps[0]
			literals, bookIDs := first.SourceLiterals, first.SourceBookIDs
			if tc.destinationExcluded {
				literals, bookIDs = first.DestinationLiterals, first.DestinationBookIDs
			}
			hasSentinel := addressListHasSentinel(literals)
			if tc.emptyDropOnly {
				if !hasSentinel || len(bookIDs) != 0 {
					t.Fatalf("empty drop feed on an excluded deny must poison the side and reject the snapshot; got literals=%v bookIDs=%v",
						literals, bookIDs)
				}
				if reasons := PolicyContentRejectionReasons(cfg, overlay); len(reasons) == 0 {
					t.Fatal("poisoned excluded-deny snapshot produced no whole-snapshot rejection reason")
				}
				return
			}
			if hasSentinel || len(bookIDs) == 0 {
				t.Fatalf("a populated sibling literal must preserve normal exclusion behavior; got literals=%v bookIDs=%v",
					literals, bookIDs)
			}
			if reasons := PolicyContentRejectionReasons(cfg, overlay); len(reasons) != 0 {
				t.Fatalf("a populated sibling literal must not reject the snapshot: %v", reasons)
			}
		})
	}
}

func TestExcludedDenyOverPopulatedDropFeedStillPublishes12050(t *testing.T) {
	cfg := excludedDropFeedConfig12050([]string{"partners"}, false, false)
	overlay := map[string][]string{"partners": {"192.0.2.0/24"}}
	snaps, err := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, overlay)
	if err != nil {
		t.Fatalf("buildPolicySnapshots error: %v", err)
	}
	if len(snaps) != 2 {
		t.Fatalf("expected the deny and later permit rules, got %d", len(snaps))
	}
	if addressListHasSentinel(snaps[0].SourceLiterals) || len(snaps[0].SourceBookIDs) == 0 {
		t.Fatalf("a populated drop feed must remain a book-backed exclusion, got literals=%v bookIDs=%v",
			snaps[0].SourceLiterals, snaps[0].SourceBookIDs)
	}
	if reasons := PolicyContentRejectionReasons(cfg, overlay); len(reasons) != 0 {
		t.Fatalf("a populated drop feed must not reject the snapshot: %v", reasons)
	}
}

// This crosses the actual feed manager boundary: a successful first fetch is
// retained until subsequent failures pass the configured hold interval, then
// SnapshotForBindings feeds the resulting present-empty row into policy lowering.
func TestHoldDroppedExcludedFeedRefusesSnapshot12050(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if requests.Add(1) == 1 {
			_, _ = w.Write([]byte("192.0.2.0/24\n"))
			return
		}
		http.Error(w, "feed unavailable", http.StatusServiceUnavailable)
	}))

	m := feeds.New(nil)
	m.SetPrivateFeedAllowlist([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")})
	cfg := excludedDropFeedConfig12050([]string{"partners"}, false, false)
	cfg.Security.DynamicAddress.FeedServers = map[string]*config.FeedServer{
		"partner-server": {
			Name:           "partner-server",
			URL:            server.URL,
			FeedName:       "partner-feed",
			UpdateInterval: 1,
			HoldInterval:   1,
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.Apply(ctx, &cfg.Security.DynamicAddress)
	t.Cleanup(func() {
		cancel()
		m.StopAll()
		server.Close()
	})

	waitForOverlay := func(want func(map[string][]string) bool) map[string][]string {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			overlay := m.SnapshotForBindings(&cfg.Security.DynamicAddress)
			if want(overlay) {
				return overlay
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("timed out waiting for feed state; requests=%d overlay=%v", requests.Load(),
			m.SnapshotForBindings(&cfg.Security.DynamicAddress))
		return nil
	}
	waitForOverlay(func(overlay map[string][]string) bool {
		prefixes, ok := overlay["partners"]
		return ok && len(prefixes) == 1 && prefixes[0] == "192.0.2.0/24"
	})

	overlay := waitForOverlay(func(overlay map[string][]string) bool {
		prefixes, ok := overlay["partners"]
		return ok && len(prefixes) == 0
	})
	if requests.Load() < 3 {
		t.Fatalf("feed was not driven through the hold interval: requests=%d", requests.Load())
	}
	snaps, err := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, overlay)
	if err != nil {
		t.Fatalf("buildPolicySnapshots error: %v", err)
	}
	if len(snaps) != 2 {
		t.Fatalf("expected the deny and later permit rules, got %d", len(snaps))
	}
	reasons := PolicyContentRejectionReasons(cfg, overlay)
	if len(reasons) == 0 || !strings.Contains(strings.Join(reasons, " | "), "partners") {
		t.Fatalf("hold-dropped feed did not reject the whole snapshot with a named reason: %v", reasons)
	}
}
