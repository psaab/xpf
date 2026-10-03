package config

import (
	"sort"
	"strings"
)

// host_inbound_multicast.go is the protocol -> well-known multicast-group
// catalog for host-bound routing multicast (#4455, HI-1, #11571).
//
// The Go/kernel nft path scopes catalog-group accepts by ingress interface and
// drops groups not admitted by that ingress zone. The Rust classifier mirrors
// the same group dimension; keep its catalog mirror in lockstep. This is the
// sole Go/kernel catalog source, and behavior outside its configured groups is
// unchanged.
//
// Managed OSPF/OSPF3/RIP configuration is checked by the compiler's strict
// commit / tolerant-load migration gate. See docs/host-inbound-multicast.md for
// the enforcement and migration contract.

// HostInboundMulticastGroups is the well-known multicast groups a protocol's
// host-bound control traffic is addressed to, split by family. A dual-family
// protocol (pim, vrrp) populates both; family-specific protocols populate only
// their matching family, consistent with HostInboundProtocolFamily.
type HostInboundMulticastGroups struct {
	V4    []string // well-known IPv4 groups (nil for an IPv6-only protocol)
	V6    []string // well-known IPv6 groups (nil for an IPv4-only protocol)
	Label string   // short human-readable protocol label
}

// hostInboundMulticastCatalog maps a `host-inbound-traffic protocols` token to
// its well-known multicast groups. Only protocols whose host-bound CONTROL
// traffic rides a well-known multicast group are listed — unicast routing
// control (bgp/ldp/msdp/nhrp: TCP/UDP to a peer address; bfd: UDP to the peer)
// is deliberately absent, and L2/non-IP protocols (isis) never reach the IP
// input chain. `all` is handled by the callers via
// HostInboundAllExpansionProtocols (it expands to this set's members plus the
// unicast ones). Family split mirrors HostInboundProtocolFamily.
var hostInboundMulticastCatalog = map[string]HostInboundMulticastGroups{
	// OSPFv2 AllSPFRouters / AllDRouters (IP proto 89, IPv4).
	"ospf": {V4: []string{"224.0.0.5", "224.0.0.6"}, Label: "OSPFv2"},
	// OSPFv3 AllSPFRouters / AllDRouters (IP proto 89, IPv6).
	"ospf3": {V6: []string{"ff02::5", "ff02::6"}, Label: "OSPFv3"},
	// RIPv2 (UDP 520, IPv4).
	"rip": {V4: []string{"224.0.0.9"}, Label: "RIPv2"},
	// RIPng (UDP 521, IPv6).
	"ripng": {V6: []string{"ff02::9"}, Label: "RIPng"},
	// PIM ALL-PIM-ROUTERS (IP proto 103, dual-family).
	"pim": {V4: []string{"224.0.0.13"}, V6: []string{"ff02::d"}, Label: "PIM"},
	// IGMP all-hosts / IGMPv3 membership reports (IP proto 2, IPv4 only).
	"igmp": {V4: []string{"224.0.0.1", "224.0.0.22"}, Label: "IGMP"},
	// DVMRP ALL-DVMRP-ROUTERS — carried inside IGMP (IP proto 2), IPv4 only.
	"dvmrp": {V4: []string{"224.0.0.4"}, Label: "DVMRP"},
	// VRRP (IP proto 112, dual-family; ff02::12 is the IPv6 VRRP group).
	"vrrp": {V4: []string{"224.0.0.18"}, V6: []string{"ff02::12"}, Label: "VRRP"},
	// ICMP router discovery (IRDP): advertisements to 224.0.0.1 (all-hosts),
	// solicitations to 224.0.0.2 (all-routers). IPv4 only — the IPv6 equivalent
	// is Neighbor Discovery RS/RA, already in the always-accepted ND set.
	"router-discovery": {V4: []string{"224.0.0.1", "224.0.0.2"}, Label: "router-discovery (IRDP)"},
}

// HostInboundMulticastProtocol reports whether a `host-inbound-traffic
// protocols` token is a MULTICAST routing protocol (its host-bound control
// traffic is addressed to a well-known multicast group) and returns its groups.
// Unicast routing-control tokens (bgp/ldp/msdp/nhrp/bfd), L2 tokens (isis), and
// the `all` meta-token return ok=false — callers expand `all` via
// HostInboundAllExpansionProtocols before consulting this.
func HostInboundMulticastProtocol(token string) (HostInboundMulticastGroups, bool) {
	g, ok := hostInboundMulticastCatalog[strings.ToLower(token)]
	return g, ok
}

// HostInboundMulticastProtocolTokens returns the multicast routing-protocol
// tokens (catalog keys) in sorted order.
func HostInboundMulticastProtocolTokens() []string {
	out := make([]string, 0, len(hostInboundMulticastCatalog))
	for tok := range hostInboundMulticastCatalog {
		out = append(out, tok)
	}
	sort.Strings(out)
	return out
}

// HostInboundMulticastRule is one ingress-scoped enforcement tuple (#11571): a
// lower-cased protocol token, family ("ip" or "ip6"), and catalog group address.
type HostInboundMulticastRule struct {
	Protocol string
	Family   string
	Group    string
}

// HostInboundMulticastRules expands the supplied tokens into deterministic
// catalog enforcement tuples. Matching is case-insensitive and `all` expands
// via HostInboundAllExpansionProtocols; non-catalog protocols produce no rules.
// Results are sorted by protocol, family, and group with duplicates removed.
func HostInboundMulticastRules(protocols []string) []HostInboundMulticastRule {
	tokens := hostInboundMulticastTokensPresent(protocols)
	if len(tokens) == 0 {
		return nil
	}
	var out []HostInboundMulticastRule
	for _, tok := range tokens {
		g := hostInboundMulticastCatalog[tok]
		for _, group := range g.V4 {
			out = append(out, HostInboundMulticastRule{Protocol: tok, Family: "ip", Group: group})
		}
		for _, group := range g.V6 {
			out = append(out, HostInboundMulticastRule{Protocol: tok, Family: "ip6", Group: group})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Protocol != out[j].Protocol {
			return out[i].Protocol < out[j].Protocol
		}
		if out[i].Family != out[j].Family {
			return out[i].Family < out[j].Family
		}
		return out[i].Group < out[j].Group
	})
	if len(out) == 0 {
		return nil
	}
	return out
}

// HostInboundMulticastGroups returns the sorted, deduplicated catalog addresses
// for an nft family ("ip" or "ip6"). It returns a fresh slice that does not
// alias catalog storage, or nil for an unknown family.
func HostInboundMulticastGroupsForFamily(family string) []string {
	fam := strings.ToLower(strings.TrimSpace(family))
	wantV6 := false
	switch fam {
	case "ip":
	case "ip6":
		wantV6 = true
	default:
		return nil
	}
	var out []string
	for _, g := range hostInboundMulticastCatalog {
		if wantV6 {
			out = append(out, g.V6...)
		} else {
			out = append(out, g.V4...)
		}
	}
	sort.Strings(out)
	n := 0
	for _, group := range out {
		if n == 0 || out[n-1] != group {
			out[n] = group
			n++
		}
	}
	if n == 0 {
		return nil
	}
	return out[:n]
}

// hostInboundMulticastTokensPresent returns the sorted set of MULTICAST
// routing-protocol tokens implied by a zone/interface `host-inbound-traffic
// protocols` list, expanding the `all` meta-token to its routing-protocol set
// (#3199, HostInboundAllExpansionProtocols) first. Unicast/L2 tokens are
// dropped. Returns nil when the list admits no multicast protocol.
func hostInboundMulticastTokensPresent(protocols []string) []string {
	seen := map[string]bool{}
	var add func(tok string)
	add = func(tok string) {
		tok = strings.ToLower(tok)
		if tok == "all" {
			for _, p := range HostInboundAllExpansionProtocols() {
				add(p)
			}
			return
		}
		if _, ok := hostInboundMulticastCatalog[tok]; ok {
			seen[tok] = true
		}
	}
	for _, p := range protocols {
		add(p)
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for tok := range seen {
		out = append(out, tok)
	}
	sort.Strings(out)
	return out
}
