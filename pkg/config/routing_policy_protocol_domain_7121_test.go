package config

import (
	"strings"
	"testing"
)

// #7121: `policy-options policy-statement <p> term <t> from protocol <tok>` had
// no value-domain check in ANY spelling. The token is rendered verbatim as
// ` match source-protocol <tok>`, FRR rejects an unknown one, and ONE rejected
// line fails the whole managed reload (#1880/#2223) — so a single typo was a
// green commit that stopped stale-config removal for the whole managed FRR
// section.
func TestRoutingPolicyProtocolDomainIsGated_7121(t *testing.T) {
	cfgWith := func(proto string) *Config {
		return &Config{PolicyOptions: PolicyOptionsConfig{
			PolicyStatements: map[string]*PolicyStatement{
				"p1": {Name: "p1", Terms: []*PolicyTerm{
					{Name: "t1", FromProtocols: []string{proto}},
				}},
			},
		}}
	}

	for _, tc := range []struct {
		proto  string
		accept bool
	}{
		// Every FRR keyword the renderers can emit.
		{"bgp", true}, {"ospf", true}, {"ospf6", true}, {"static", true},
		{"rip", true}, {"ripng", true}, {"isis", true}, {"kernel", true},
		{"connected", true},
		// Junos spells directly-connected routes "direct"; BOTH renderers
		// rewrite it to "connected". Rejecting it would break a working config.
		{"direct", true},
		// The issue's own example.
		{"ospv", false},
		// NOT the sibling leaf's domain. `firewall filter ... from protocol` is
		// IP protocols and is gated by filterProtocolResolvable; the two leaves
		// share a spelling and nothing else. Resolving one through the other
		// would accept these here.
		{"tcp", false}, {"udp", false}, {"icmp", false}, {"gre", false},
	} {
		t.Run(tc.proto, func(t *testing.T) {
			err := validateRoutingPolicyProtocolsStrict(cfgWith(tc.proto))
			if tc.accept && err != nil {
				t.Errorf("%q is a protocol the renderer emits, but commit rejected it: %v",
					tc.proto, err)
			}
			if !tc.accept && err == nil {
				t.Errorf("%q was ACCEPTED at commit. It renders as `match source-protocol %s`, "+
					"which FRR rejects — and one rejected line degrades the whole managed "+
					"reload, so this does not fail alone", tc.proto, tc.proto)
			}
			if !tc.accept && err != nil {
				// The operator has to be able to find it: a multi-valued leaf on
				// a term that may carry several protocols.
				for _, want := range []string{"p1", "t1", tc.proto} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("the rejection does not name %q, so the operator cannot "+
							"locate the offending token: %v", want, err)
					}
				}
			}
		})
	}
}

// The two identically-spelled leaves must NOT resolve through one another.
// Asserting the domains are disjoint where it matters is what stops a later
// "consolidation" merging the two lists.
func TestRoutingAndFilterProtocolDomainsAreDistinct_7121(t *testing.T) {
	// IP protocols the filter leaf accepts and the routing leaf must not.
	for _, ipProto := range []string{"tcp", "udp", "gre", "icmpv6"} {
		if !filterProtocolResolvable(ipProto) {
			t.Fatalf("premise broken: %q is no longer accepted by the FILTER domain, so this "+
				"test is not comparing the two domains any more", ipProto)
		}
		if RoutingProtocolResolvable(ipProto) {
			t.Errorf("%q resolves in the ROUTING domain; it is an IP protocol, and accepting "+
				"it renders `match source-protocol %s` which FRR rejects", ipProto, ipProto)
		}
	}
	// And a routing protocol the filter leaf must not silently accept as an
	// IP protocol number. `ospf` is deliberately in BOTH (IP protocol 89 and an
	// FRR keyword), so it is excluded — the overlap is real and not a bug.
	for _, routingOnly := range []string{"bgp", "static", "kernel", "isis"} {
		if !RoutingProtocolResolvable(routingOnly) {
			t.Fatalf("premise broken: %q left the routing domain", routingOnly)
		}
		if filterProtocolResolvable(routingOnly) {
			t.Errorf("%q resolves in the FILTER domain, which is IP protocols — if that is "+
				"intended, this test needs updating; if not, the filter gate is too wide",
				routingOnly)
		}
	}
}

// The `direct` -> `connected` rewrite lived in TWO renderers with a copy each.
// Single-sourcing it means the mapping itself must be asserted, or a future
// edit could make the domain accept `direct` while the keyword lookup returns
// something else.
func TestDirectMapsToConnected_7121(t *testing.T) {
	got, ok := FRRRoutingProtocolKeyword("direct")
	if !ok || got != "connected" {
		t.Fatalf(`FRRRoutingProtocolKeyword("direct") = (%q, %v), want ("connected", true) — `+
			`Junos spells directly-connected routes "direct" and FRR's keyword is "connected"`, got, ok)
	}
	if got, _ := FRRRoutingProtocolKeyword("connected"); got != "connected" {
		t.Errorf(`the FRR spelling must resolve to itself, got %q`, got)
	}
}
