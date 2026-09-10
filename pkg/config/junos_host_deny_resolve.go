package config

import (
	"net/netip"
	"strconv"
	"strings"
)

// junos_host_deny_resolve.go holds the NAME-RESOLUTION half of the junos-host
// deny projection: turning the address, application and port tokens a policy
// carries into the concrete per-family CIDR sets and L4 tuples the projection
// consumes. Split out of junos_host_deny.go when that file crossed the 1500-LOC
// [WATCH] floor (#6705).
//
// The seam is a real one rather than a line-count convenience: nothing here
// reads or writes projection state. Every function is a pure map from config
// tokens (plus the address book and the feed-taint set) to resolved values, and
// the projection side calls into it and never the reverse. That is also why the
// split is safe to make inside a bug-fix change — no call site moved, no
// behaviour depends on which file a symbol lives in, and the package-internal
// names are unchanged.

// junosHostFamilyL4 keeps the L4 fragments meaningful for a family (ICMP -> v4
// only, ICMPv6 -> v6 only; TCP/UDP/bare-proto -> both).
func junosHostFamilyL4(family string, l4 []JunosHostDenyL4) []JunosHostDenyL4 {
	if len(l4) == 0 {
		return nil
	}
	wantV6 := family == "ip6"
	var out []JunosHostDenyL4
	for _, f := range l4 {
		switch f.Proto {
		case HostInboundProtoICMP:
			if wantV6 {
				continue
			}
		case HostInboundProtoICMPv6:
			if !wantV6 {
				continue
			}
		}
		out = append(out, f)
	}
	return out
}

// junosHostResolveAddrSet resolves a policy source/destination token list to
// static per-family CIDR sets. ok=false when any token (or nested member) is
// feed-tainted, resolves through a wildcard/dns-name/range address (Value ""),
// or names an unknown book entry. any* is true when a wildcard token widens the
// family to match-all.
func junosHostResolveAddrSet(cfg *Config, tokens []string, feedBound map[string]bool) (v4, v6 []string, anyV4, anyV6, ok bool) {
	ok = true
	if len(tokens) == 0 {
		return nil, nil, true, true, true
	}
	ab := cfg.Security.AddressBook
	seen4 := map[string]bool{}
	seen6 := map[string]bool{}
	addCIDR := func(val string) {
		val = strings.TrimSpace(val)
		if val == "" {
			ok = false
			return
		}
		if val == "any" || val == "any-ipv4" || val == "any-ipv6" {
			switch val {
			case "any":
				anyV4, anyV6 = true, true
			case "any-ipv4":
				anyV4 = true
			case "any-ipv6":
				anyV6 = true
			}
			return
		}
		pfx, perr := netip.ParsePrefix(val)
		if perr != nil {
			if a, aerr := netip.ParseAddr(val); aerr == nil {
				pfx = netip.PrefixFrom(a, a.BitLen())
			} else {
				ok = false
				return
			}
		}
		s := pfx.Masked().String()
		if pfx.Addr().Is6() {
			if !seen6[s] {
				seen6[s] = true
				v6 = append(v6, s)
			}
		} else if !seen4[s] {
			seen4[s] = true
			v4 = append(v4, s)
		}
	}
	for _, tok := range tokens {
		switch tok {
		case "", "any":
			anyV4, anyV6 = true, true
			continue
		case "any-ipv4":
			anyV4 = true
			continue
		case "any-ipv6":
			anyV6 = true
			continue
		}
		if junosHostNameFeedTainted(ab, feedBound, tok, map[string]bool{}) {
			ok = false
			continue
		}
		if ab != nil {
			if a, found := ab.Addresses[tok]; found {
				addCIDR(a.UsableValue())
				continue
			}
			if _, found := ab.AddressSets[tok]; found {
				names, err := ExpandAddressSet(tok, ab)
				if err != nil {
					ok = false
					continue
				}
				for _, n := range names {
					if a, f := ab.Addresses[n]; f {
						addCIDR(a.UsableValue())
					} else {
						ok = false
					}
				}
				continue
			}
		}
		// Not a book name: try a literal prefix/IP.
		addCIDR(tok)
	}
	return v4, v6, anyV4, anyV6, ok
}

// junosHostAddrScoped reports whether a token list names a concrete (non-any)
// address scope.
func junosHostAddrScoped(tokens []string) bool {
	for _, t := range tokens {
		switch t {
		case "", "any", "any-ipv4", "any-ipv6":
			continue
		}
		return true
	}
	return false
}

// junosHostNameFeedTainted reports whether an address token, or ANY nested
// address-set member, is bound to a dynamic feed (so its resolved set is not
// commit-stable and cannot be a static nft rule, §6.2). A name may be
// SIMULTANEOUSLY static and feed-backed, so the whole closure is inspected.
func junosHostNameFeedTainted(ab *AddressBook, feedBound map[string]bool, name string, visited map[string]bool) bool {
	if feedBound[name] {
		return true
	}
	if ab == nil || visited[name] {
		return false
	}
	set, ok := ab.AddressSets[name]
	if !ok {
		return false
	}
	visited[name] = true
	defer delete(visited, name)
	for _, m := range set.Addresses {
		if junosHostNameFeedTainted(ab, feedBound, m, visited) {
			return true
		}
	}
	for _, s := range set.AddressSets {
		if junosHostNameFeedTainted(ab, feedBound, s, visited) {
			return true
		}
	}
	return false
}

// junosHostFeedBoundNames returns the set of address-names bound to any dynamic
// feed (config-knowable membership; the live feed CONTENT is irrelevant to
// representability — a feed-bound name is never commit-stable).
func junosHostFeedBoundNames(cfg *Config) map[string]bool {
	out := map[string]bool{}
	for name := range cfg.Security.DynamicAddress.AddressBindings {
		out[name] = true
	}
	return out
}

// junosHostResolveApplications reduces a policy `match application` token list to
// OR-expanded L4 fragments. appAny is true for `any`/empty (match every
// protocol). ok=false when any application is un-resolvable, multi-term, ALG,
// protocol-less, has a non-numeric port, or is scoped to an IPsec/ident exempt
// tuple (which the IPsec/ident path owns — §6.6).
func junosHostResolveApplications(cfg *Config, tokens []string) (l4 []JunosHostDenyL4, appAny, ok bool) {
	ok = true
	if len(tokens) == 0 {
		return nil, true, true
	}
	for _, tok := range tokens {
		switch tok {
		case "", "any":
			appAny = true
			continue
		}
		// #5677: resolve a user/predefined APPLICATION first, so a user
		// application shadowing a same-named application-set keeps ITS OWN
		// ports on this direct host-bound projection. Only OR-expand as an
		// application-set when the token is NOT an application — mirroring the
		// app-first precedence of resolveUserspaceApplicationNames and the
		// #5629/#5664 policy-match / NAT / catalog fixes. Consulting the
		// application-SET table first (the pre-#5677 bug) mis-resolved a
		// shadowed user application to the set's members, so the kernel
		// direct-host DENY projected the wrong ports.
		_, isApp := ResolveApplication(tok, cfg.Applications.Applications)
		if _, isSet := ResolveApplicationSet(tok, cfg.Applications.ApplicationSets); !isApp && isSet {
			members, err := ExpandApplicationSet(tok, &cfg.Applications)
			if err != nil {
				ok = false
				continue
			}
			for _, m := range members {
				if frags, mok := junosHostReduceApp(cfg, m); mok {
					l4 = append(l4, frags...)
				} else {
					ok = false
				}
			}
			continue
		}
		if frags, aok := junosHostReduceApp(cfg, tok); aok {
			l4 = append(l4, frags...)
		} else {
			ok = false
		}
	}
	if appAny {
		// `application any` present -> the whole match is all-protocols; drop any
		// narrow fragments accumulated alongside it (any subsumes them).
		return nil, true, ok
	}
	return l4, false, ok
}

// junosHostReduceApp reduces a single application to L4 fragments. Rejects
// multi-term apps (MixedDirectTermApps), ALG-bearing apps, protocol-less apps,
// non-numeric ports, and apps scoped to an IPsec/ident exempt tuple.
func junosHostReduceApp(cfg *Config, name string) ([]JunosHostDenyL4, bool) {
	for _, mixed := range cfg.Applications.MixedDirectTermApps {
		if mixed == name {
			return nil, false
		}
	}
	app, ok := ResolveApplication(name, cfg.Applications.Applications)
	if !ok || app == nil {
		return nil, false
	}
	if app.ALG != "" {
		return nil, false
	}
	proto := strings.ToLower(strings.TrimSpace(app.Protocol))
	if proto == "" {
		return nil, false
	}
	var frag JunosHostDenyL4
	switch proto {
	case "tcp":
		frag.Proto = HostInboundProtoTCP
	case "udp":
		frag.Proto = HostInboundProtoUDP
	case "icmp":
		frag.Proto = HostInboundProtoICMP
		frag.ICMPType, frag.ICMPCode = app.ICMPType, app.ICMPCode
	case "icmp6", "icmpv6", "icmp-v6":
		frag.Proto = HostInboundProtoICMPv6
		frag.ICMPType, frag.ICMPCode = app.ICMPType, app.ICMPCode
	default:
		n, err := strconv.Atoi(proto)
		if err != nil || n < 0 || n > 255 {
			return nil, false
		}
		frag.Proto = uint8(n)
	}
	if frag.Proto == HostInboundProtoTCP || frag.Proto == HostInboundProtoUDP {
		dp, dok := junosHostParsePorts(app.DestinationPort)
		if !dok {
			return nil, false
		}
		sp, sok := junosHostParsePorts(app.SourcePort)
		if !sok {
			return nil, false
		}
		frag.Ports, frag.SourcePorts = dp, sp
	}
	// A deny scoped to an IPsec/ident exempt tuple can't be faithfully modeled by
	// the DENY slice (the IPsec passthrough / ident-reset path owns it, §6.6).
	if junosHostFragIsExemptTuple(frag) {
		return nil, false
	}
	return []JunosHostDenyL4{frag}, true
}

// junosHostFragIsExemptTuple reports whether an L4 fragment collides with a
// pre-fine exempt class: raw ESP/AH (proto 50/51), IKE/NAT-T (udp 500/4500), or
// ident (tcp 113).
func junosHostFragIsExemptTuple(f JunosHostDenyL4) bool {
	switch f.Proto {
	case 50, 51:
		return true
	case HostInboundProtoUDP:
		return junosHostPortsInclude(f.Ports, 500) || junosHostPortsInclude(f.Ports, 4500)
	case HostInboundProtoTCP:
		return junosHostPortsInclude(f.Ports, 113)
	}
	return false
}

func junosHostPortsInclude(ports []PortRange, p uint16) bool {
	if len(ports) == 0 {
		return true // no port constraint => all ports => includes p
	}
	for _, r := range ports {
		if p >= r.Lo && p <= r.Hi {
			return true
		}
	}
	return false
}

// junosHostParsePorts parses a Junos port spec into PortRange(s). "" => nil (all
// ports). Only numeric single ports and "lo-hi" ranges are representable; a
// named alias returns ok=false.
func junosHostParsePorts(spec string) ([]PortRange, bool) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, true
	}
	var out []PortRange
	for _, part := range strings.Fields(spec) {
		if lo, hi, found := strings.Cut(part, "-"); found {
			l, lerr := parseCanonicalPort(strings.TrimSpace(lo))
			h, herr := parseCanonicalPort(strings.TrimSpace(hi))
			if lerr != nil || herr != nil || !junosHostPortInRange(l) || !junosHostPortInRange(h) || l > h {
				return nil, false
			}
			out = append(out, PortRange{Lo: uint16(l), Hi: uint16(h)})
			continue
		}
		v, err := parseCanonicalPort(part)
		if err != nil || !junosHostPortInRange(v) {
			return nil, false
		}
		out = append(out, PortRange{Lo: uint16(v), Hi: uint16(v)})
	}
	return out, true
}

// junosHostPortInRange is the port domain this parser accepts, and it is
// deliberately the SAME one validatePortSpec enforces: 1..65535.
//
// #8597 (muse-004 K67). This parser used strconv.Atoi with a `v < 0 || v >
// 65535` check, and diverged from the commit-time gate in two ways. Measured:
//
//	spec     junosHostParsePorts     validatePortSpec
//	"+80"    [{80 80}], true         rejected (not a number)
//	"0"      [{0 0}],  true          rejected (must be 1-65535)
//	"00"     [{0 0}],  true          rejected
//	"0-100"  [{0 100}], true         rejected
//
// Why the divergence matters rather than being cosmetic: the projection this
// parser feeds sets RenderedPolicyKeys, which is a SUPPRESSION claim — "this
// deny is enforced, so do not warn about it". For a port-0 spec that claim is
// false, and the operator's only diagnostic is the one being silenced.
//
// parseCanonicalPort is the same helper the commit gate uses (ParseCanonicalUint
// underneath), so the two cannot drift on what a numeric token is. The floor is
// stated here rather than inlined twice because both the range and single-port
// arms need it and a hand-copied bound in one of them is how this started.
//
// The space-separated multi-port spelling this parser accepts and
// validatePortSpec does not is NOT a divergence to close: it is this parser's
// documented input shape (`strings.Fields`), and the over-reach control pins it.
func junosHostPortInRange(p int) bool {
	return p >= 1 && p <= 65535
}
