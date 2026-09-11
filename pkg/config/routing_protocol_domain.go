package config

import "strings"

// FRRRoutingProtocolKeyword maps a Junos routing-protocol token to the FRR
// keyword that renders it, and reports whether the token is in the domain at
// all.
//
// #7121: this is the SSOT for the value domain of every place a routing-protocol
// NAME crosses into FRR — `policy-options policy-statement <p> term <t> from
// protocol <tok>` (rendered as ` match source-protocol`), and the
// `export`/redistribute path. Before this it existed only inside pkg/frr, so the
// commit-time gate could not consult it and an unknown token committed clean.
//
// That matters more than an ordinary typo: FRR rejects an unknown
// `source-protocol`, and one rejected line fails the WHOLE managed reload
// (#1880/#2223). The `vtysh -f` fallback still applies every other line, but no
// stale route, neighbour or policy is removed anywhere in the managed section
// while the line is rendered. A single `from protocol ospv;` was a green commit
// that froze the managed FRR section.
//
// NOT the same domain as the identically-spelled `firewall filter ... from
// protocol`, which is IP protocols (tcp/udp/gre/icmp) and is gated separately by
// filterProtocolResolvable. The two leaves share a spelling and nothing else;
// resolving one through the other's list would accept `tcp` for a routing policy
// and `bgp` for a firewall filter.
//
// The `direct` alias is carried here because BOTH renderers rewrite it and each
// had its own copy — `redistribute.go` and `policy_render.go`. Junos spells
// directly-connected routes `direct`; FRR's keyword is `connected`. A divergence
// between those two copies is always a bug, so they are single-sourced rather
// than bound by an agreement test.
func FRRRoutingProtocolKeyword(token string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(token)) {
	// Junos spelling for directly-connected routes; FRR calls it "connected".
	case "direct", "connected":
		return "connected", true
	case "static":
		return "static", true
	// ospf6 / ripng are the FRR keywords for OSPFv3 / RIPng. Without them a
	// bare `export ospf6` / `export ripng` falls through to the skip-and-warn
	// path and IPv6 IGP redistribution cannot be expressed (#2943).
	case "ospf":
		return "ospf", true
	case "ospf6":
		return "ospf6", true
	case "bgp":
		return "bgp", true
	case "rip":
		return "rip", true
	case "ripng":
		return "ripng", true
	case "isis":
		return "isis", true
	case "kernel":
		return "kernel", true
	default:
		return "", false
	}
}

// RoutingProtocolResolvable reports whether a routing-policy `from protocol`
// token names a protocol the FRR renderer can emit.
func RoutingProtocolResolvable(token string) bool {
	_, ok := FRRRoutingProtocolKeyword(token)
	return ok
}
