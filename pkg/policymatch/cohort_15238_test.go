package policymatch

import (
	"net"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15238 A55-01: within the single-wildcard tier (tier 1) the cross-tier
// shadow pass iterates the lexically sorted `pairs`, not config order, so it
// names the wrong coverer and flips SHADOWED to REDUNDANT. Runtime tier 2
// merges the two wildcard sub-buckets in CONFIG order; inside tier 1 the
// first coverer must be the authored-first single-wildcard stanza.
func TestCrossTierShadowingWithinWildcardTierUsesConfigOrder15238(t *testing.T) {
	zpol := func(name string, action config.PolicyAction) *config.Policy {
		return &config.Policy{Name: name, Action: action, Match: config.PolicyMatch{
			SourceAddresses: []string{"any"}, DestinationAddresses: []string{"any"}, Applications: []string{"any"}}}
	}
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust"}, "untrust": {Name: "untrust"},
	}
	// Config order: to-any-deny authored BEFORE from-any-permit. Lexical
	// sort puts ("any","untrust") before ("trust","any"), so the pre-fix
	// pass records the permit and reports REDUNDANT.
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{FromZone: "trust", ToZone: "any", Policies: []*config.Policy{zpol("to-any-deny", config.PolicyDeny)}},
		{FromZone: "any", ToZone: "untrust", Policies: []*config.Policy{zpol("from-any-permit", config.PolicyPermit)}},
	}
	cfg.Security.GlobalPolicies = []*config.Policy{
		{Name: "scoped-permit", Action: config.PolicyPermit, Match: config.PolicyMatch{
			SourceAddresses: []string{"any"}, DestinationAddresses: []string{"any"}, Applications: []string{"any"},
			FromZones: []string{"trust"}, ToZones: []string{"untrust"}}},
	}
	joined := strings.Join(AnalyzePolicyShadowing(cfg), "\n")
	// Runtime: trust->any deny is the tier-2 first match, so scoped-permit
	// is SHADOWED by to-any-deny, never REDUNDANT behind from-any-permit.
	if !strings.Contains(joined, `"scoped-permit" is SHADOWED`) ||
		!strings.Contains(joined, `"to-any-deny"`) {
		t.Fatalf("within-tier-1 config order must report SHADOWED naming to-any-deny, got:\n%s", joined)
	}
	if strings.Contains(joined, "REDUNDANT") {
		t.Fatalf("lexical-first wildcard permit must not downgrade SHADOWED to REDUNDANT:\n%s", joined)
	}

	// Control: authored order flipped — the permit is now runtime-first,
	// so REDUNDANT naming from-any-permit is the correct reading.
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{FromZone: "any", ToZone: "untrust", Policies: []*config.Policy{zpol("from-any-permit", config.PolicyPermit)}},
		{FromZone: "trust", ToZone: "any", Policies: []*config.Policy{zpol("to-any-deny", config.PolicyDeny)}},
	}
	joined = strings.Join(AnalyzePolicyShadowing(cfg), "\n")
	if !strings.Contains(joined, `"scoped-permit" is REDUNDANT`) ||
		!strings.Contains(joined, `"from-any-permit"`) {
		t.Fatalf("flipped config order must report REDUNDANT naming from-any-permit, got:\n%s", joined)
	}
	if strings.Contains(joined, "SHADOWED") {
		t.Fatalf("flipped config order must not report SHADOWED:\n%s", joined)
	}
}

// #15238 A55-02: show security match-policies must flag flows the helper
// drops at the transit src/dst martian gates (addr_class.rs
// transit_src_is_martian / transit_dst_is_martian) BEFORE policy. The old
// routeDropClass only classified a dst subset, so plain permits were
// reported for martian src and for dst classes it missed.
func TestTransitMartianAdvisory15238(t *testing.T) {
	cfg := cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		Policies: []*config.ZonePairPolicies{
			zonePair("trust", "untrust", permit("permit-any", config.PolicyMatch{
				SourceAddresses: []string{"any"}, DestinationAddresses: []string{"any"}, Applications: []string{"any"}})),
		},
	}, config.ApplicationsConfig{})
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.2.0.1/24"}},
		}},
	}

	cases := []struct {
		name      string
		src, dst  string
		wantClass string
	}{
		// Martian sources (previously no advisory at all).
		{"v4-src-this-network", "0.1.2.3", "198.51.100.7", "this-network"},
		{"v4-src-link-local", "169.254.1.2", "198.51.100.7", "link-local"},
		{"v4-src-reserved", "240.0.0.1", "198.51.100.7", "reserved"},
		{"v4-src-multicast", "224.0.0.5", "198.51.100.7", "multicast"},
		{"v4-src-loopback", "127.0.0.1", "198.51.100.7", "loopback"},
		{"v4-src-directed-broadcast", "10.2.0.255", "198.51.100.7", "directed-broadcast"},
		{"v6-src-unspecified", "::", "2001:db8::7", "unspecified"},
		{"v6-src-loopback", "::1", "2001:db8::7", "loopback"},
		{"v6-src-multicast", "ff02::1", "2001:db8::7", "multicast"},
		{"v6-src-link-local", "fe80::1", "2001:db8::7", "link-local"},
		// Martian destinations the old dst-only list missed.
		{"v4-dst-this-network", "198.51.100.9", "0.1.2.3", "this-network"},
		{"v4-dst-link-local", "198.51.100.9", "169.254.1.2", "link-local"},
		{"v4-dst-reserved", "198.51.100.9", "240.0.0.1", "reserved"},
		{"v6-dst-link-local", "2001:db8::9", "fe80::1", "link-local"},
		// Directed-broadcast dst keeps its established neighbour class
		// spelling (the simulator cannot see routing domains).
		{"v4-dst-directed-broadcast", "198.51.100.9", "10.2.0.255", "directed-broadcast"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := Match(cfg, Query{
				FromZone: "trust", ToZone: "untrust",
				SrcIP: net.ParseIP(tc.src), DstIP: net.ParseIP(tc.dst),
			})
			if !res.Matched || res.Action != config.PolicyPermit {
				t.Fatalf("verdict changed: got Matched=%v Action=%v, want matched permit (advisory is additive)", res.Matched, res.Action)
			}
			if !res.RouteDropBeforePolicy {
				t.Fatalf("RouteDropBeforePolicy = false, want true for %s -> %s (%s)", tc.src, tc.dst, tc.wantClass)
			}
			if res.RouteDropClass != tc.wantClass {
				t.Fatalf("RouteDropClass = %q, want %q for %s -> %s", res.RouteDropClass, tc.wantClass, tc.src, tc.dst)
			}
			if note := res.RouteDropNote(); !strings.HasPrefix(note, RouteDropNotePrefix) || !strings.Contains(note, tc.wantClass) {
				t.Fatalf("RouteDropNote %q must carry the SSOT prefix and class %q", note, tc.wantClass)
			}
		})
	}

	// Controls: ordinary unicast both sides and nil sides stay unflagged;
	// host-bound queries stay exempt even with a martian source.
	uni := Match(cfg, Query{FromZone: "trust", ToZone: "untrust",
		SrcIP: net.ParseIP("198.51.100.9"), DstIP: net.ParseIP("203.0.113.7")})
	if uni.RouteDropBeforePolicy || uni.RouteDropClass != "" {
		t.Fatalf("ordinary unicast wrongly flagged: %+v", uni)
	}
	nilSides := Match(cfg, Query{FromZone: "trust", ToZone: "untrust"})
	if nilSides.RouteDropBeforePolicy {
		t.Fatalf("omitted src/dst (simulator wildcards) wrongly flagged: %+v", nilSides)
	}
	host := Match(cfg, Query{FromZone: "trust", ToZone: JunosHostZone,
		SrcIP: net.ParseIP("169.254.1.2"), DstIP: net.ParseIP("224.0.0.5")})
	if host.RouteDropBeforePolicy {
		t.Fatalf("host-bound query wrongly stamped with transit martian advisory: %+v", host)
	}
}

// #15238 A55-03: a host-inbound global scoped only to a quarantined zone
// (z214, the StableZoneID collision loser vs z174) is dropped by the
// snapshot builder (globalScopeFullyQuarantined), so the published
// snapshot has zero such rules. globalScopeSetMatches tested raw
// cfg.Security.Zones membership and matched it, reporting the deny as
// governing while the runtime applies none.
func TestHostGlobalQuarantinedScopeDoesNotMatch15238(t *testing.T) {
	if config.StableZoneID("z174") != config.StableZoneID("z214") {
		t.Fatalf("test premise broken: z174/z214 no longer collide")
	}
	hostDeny := &config.Policy{
		Name:   "host-deny-quarantined-scope",
		Action: config.PolicyDeny,
		Match: config.PolicyMatch{
			SourceAddresses:      []string{"any"},
			DestinationAddresses: []string{"any"},
			Applications:         []string{"any"},
			FromZones:            []string{"z214"},
			ToZones:              []string{"junos-host"},
		},
	}
	cfg := &config.Config{
		Security: config.SecurityConfig{
			DefaultPolicy:  config.PolicyDeny,
			Zones:          zones("z174", "z214", "trust"),
			GlobalPolicies: []*config.Policy{hostDeny},
		},
		Applications: config.ApplicationsConfig{},
	}
	res := Match(cfg, Query{FromZone: "z214", ToZone: JunosHostZone})
	if res.Matched {
		t.Fatalf("host global scoped only to quarantined z214 matched; the published snapshot drops it (#15238 A55-03): %+v", res)
	}
	if !res.HostInboundUnmatched {
		t.Fatalf("want HostInboundUnmatched for the dropped host global, got %+v", res)
	}

	// Trust control unchanged: the same global scoped to the surviving
	// trust zone still governs a trust-ingress host query.
	cfg2 := &config.Config{
		Security: config.SecurityConfig{
			DefaultPolicy: config.PolicyDeny,
			Zones:         zones("z174", "z214", "trust"),
			GlobalPolicies: []*config.Policy{{
				Name:   "host-deny-trust-scope",
				Action: config.PolicyDeny,
				Match: config.PolicyMatch{
					SourceAddresses:      []string{"any"},
					DestinationAddresses: []string{"any"},
					Applications:         []string{"any"},
					FromZones:            []string{"trust"},
					ToZones:              []string{"junos-host"},
				},
			}},
		},
		Applications: config.ApplicationsConfig{},
	}
	res2 := Match(cfg2, Query{FromZone: "trust", ToZone: JunosHostZone})
	if !res2.Matched || !res2.Global || res2.PolicyName != "host-deny-trust-scope" || res2.Action != config.PolicyDeny {
		t.Fatalf("trust-scoped host global control must still match, got %+v", res2)
	}

	// Transit leg of the same defect: a transit global scoped only to the
	// quarantined zone on its from side must not match either.
	cfg3 := &config.Config{
		Security: config.SecurityConfig{
			DefaultPolicy: config.PolicyDeny,
			Zones:         zones("z174", "z214", "trust", "untrust"),
			GlobalPolicies: []*config.Policy{{
				Name:   "transit-permit-quarantined-scope",
				Action: config.PolicyPermit,
				Match: config.PolicyMatch{
					SourceAddresses:      []string{"any"},
					DestinationAddresses: []string{"any"},
					Applications:         []string{"any"},
					FromZones:            []string{"z214"},
					ToZones:              []string{"untrust"},
				},
			}},
		},
		Applications: config.ApplicationsConfig{},
	}
	res3 := Match(cfg3, Query{FromZone: "z214", ToZone: "untrust"})
	if res3.Matched || !res3.UnzonedIngress {
		t.Fatalf("transit global scoped only to quarantined z214 must not match (want unzoned-ingress deny), got %+v", res3)
	}
	// Survivor control: scoped to z174 (owns the colliding id) it matches.
	cfg3.Security.GlobalPolicies[0].Match.FromZones = []string{"z174"}
	res3 = Match(cfg3, Query{FromZone: "z174", ToZone: "untrust"})
	if !res3.Matched || !res3.Global || res3.PolicyName != "transit-permit-quarantined-scope" {
		t.Fatalf("survivor-scoped transit global control must still match, got %+v", res3)
	}
}
