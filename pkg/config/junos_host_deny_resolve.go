package config

import (
	"net"
	"net/netip"
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
// feed-tainted, colliding, resolves through a wildcard/dns-name/range address
// (Value==""), or names an unknown book entry. any* is true when a wildcard token
// widens the family to match-all.
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
		if kwV4, kwV6, kw := PolicyAddressWildcardFamilies(val); kw {
			anyV4 = anyV4 || kwV4
			anyV6 = anyV6 || kwV6
			return
		}
		// netip.ParsePrefix rejects every padded mask, including forms the
		// userspace helper accepts. Only normalize a Go-valid mask that the
		// helper accepts; helper-refused or malformed values remain
		// unrepresentable on this direct-enforcement path.
		if _, _, err := net.ParseCIDR(val); err == nil &&
			!CIDRMaskHelperRefusesPadding(val) {
			val = normalizeCIDRMaskPadding(val)
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
		// Keywords before any name lookup (#9523), from the SSOT family table so
		// the short forms `any4` / `any6` the strict gate accepts project exactly
		// like `any-ipv4` / `any-ipv6` instead of failing as an unresolvable
		// literal and withdrawing the whole ingress-zone program (#12242).
		if tok == "" {
			anyV4, anyV6 = true, true
			continue
		}
		if kwV4, kwV6, kw := PolicyAddressWildcardFamilies(tok); kw {
			anyV4 = anyV4 || kwV4
			anyV6 = anyV6 || kwV6
			continue
		}
		if junosHostNameUnrepresentable(ab, feedBound, tok, map[string]bool{}) {
			ok = false
			continue
		}
		if ab != nil {
			if a, found := ab.Addresses[tok]; found {
				addCIDR(a.UsableValue())
				continue
			}
			if _, found := ab.AddressSets[tok]; found {
				names, err := expandAddressSetLeaves(tok, ab)
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
// address scope. The empty token and every match-all keyword (#12242: the SSOT
// set, short forms included) are not a scope.
func junosHostAddrScoped(tokens []string) bool {
	for _, t := range tokens {
		if t == "" || IsPolicyAddressWildcardKeyword(t) {
			continue
		}
		return true
	}
	return false
}

// junosHostNameUnrepresentable reports whether an address token, or ANY nested
// address-set member, is bound to a dynamic feed or has an ambiguous colliding
// name. Either condition prevents a complete, static host projection. A name
// may be SIMULTANEOUSLY static and feed-backed, so the whole closure is inspected.
func junosHostNameUnrepresentable(ab *AddressBook, feedBound map[string]bool, name string, visited map[string]bool) bool {
	if ab != nil {
		if _, collision := ab.CollidingNames[name]; collision {
			return true
		}
	}
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
		if junosHostNameUnrepresentable(ab, feedBound, m, visited) {
			return true
		}
	}
	for _, s := range set.AddressSets {
		if junosHostNameUnrepresentable(ab, feedBound, s, visited) {
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
		if applicationReferenceCollides(tok, &cfg.Applications) {
			ok = false
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

		// A mixed direct+term application is not represented by its generated
		// term members: compileApplications drops the direct body. Reject the
		// original token before expanding its implicit application-set.
		if !isApp && junosHostMixedDirectTermReference(cfg, tok, make(map[string]bool)) {
			ok = false
			continue
		}
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

// junosHostMixedDirectTermReference reports whether a token names a mixed
// direct+term app directly or through any nested application-set. Such an app's
// direct match body was dropped during compilation, so projecting only its
// synthesized term members would under-match the authored deny.
func junosHostMixedDirectTermReference(cfg *Config, name string, visiting map[string]bool) bool {
	for _, mixed := range cfg.Applications.MixedDirectTermApps {
		if mixed == name {
			return true
		}
	}
	if visiting[name] {
		return false
	}
	visiting[name] = true
	defer delete(visiting, name)
	set, found := ResolveApplicationSet(name, cfg.Applications.ApplicationSets)
	if !found || set == nil {
		return false
	}
	for _, member := range set.Applications {
		for _, mixed := range cfg.Applications.MixedDirectTermApps {
			if member == mixed {
				return true
			}
		}
		if _, isApp := ResolveApplication(member, cfg.Applications.Applications); isApp {
			continue
		}
		if _, nested := ResolveApplicationSet(member, cfg.Applications.ApplicationSets); nested &&
			junosHostMixedDirectTermReference(cfg, member, visiting) {
			return true
		}
	}
	return false
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

	// small protocol-number mapping aligned with appid.ProtocolNumber.
	switch proto {
	case "tcp", "junos-tcp-any":
		frag.Proto = HostInboundProtoTCP
	case "udp", "junos-udp-any":
		frag.Proto = HostInboundProtoUDP
	case "icmp", "junos-icmp-all", "junos-ping":
		frag.Proto = HostInboundProtoICMP
		frag.ICMPType, frag.ICMPCode = app.ICMPType, app.ICMPCode
	case "icmp6", "icmpv6", "icmp-v6", "junos-icmp6-all", "junos-pingv6":
		frag.Proto = HostInboundProtoICMPv6
		frag.ICMPType, frag.ICMPCode = app.ICMPType, app.ICMPCode
	case "gre", "junos-gre":
		frag.Proto = 47
	case "ipip", "junos-ipip", "junos-ip-in-ip":
		frag.Proto = 4
	case "ospf", "junos-ospf":
		frag.Proto = 89
	case "igmp":
		frag.Proto = 2
	case "pim":
		frag.Proto = 103
	case "sctp":
		frag.Proto = 132
	case "vrrp":
		frag.Proto = 112
	case "egp":
		frag.Proto = 8
	case "ipv6":
		frag.Proto = 41
	case "ah":
		frag.Proto = 51
	case "esp":
		frag.Proto = 50
	default:
		n, err := ParseCanonicalUint(app.Protocol)
		if err != nil || n < 0 || n > 255 {
			return nil, false
		}
		frag.Proto = uint8(n)
		// #11064(e): a NUMERIC ICMP-family protocol ('1'/'58') carries the
		// same icmp-type/code constraint as the named form — dropping it here
		// widens a type-scoped deny to every type of that family.
		if n == int(HostInboundProtoICMP) || n == int(HostInboundProtoICMPv6) {
			frag.ICMPType, frag.ICMPCode = app.ICMPType, app.ICMPCode
		}
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
		if err != nil || v < 1 || !junosHostPortInRange(v) {
			return nil, false
		}
		out = append(out, PortRange{Lo: uint16(v), Hi: uint16(v)})
	}
	return out, true
}

// junosHostPortInRange is the range endpoint domain shared with
// validatePortSpec: 0..65535. The single-port arm separately rejects 0
// because only an explicit range can distinguish it from an omitted port.
func junosHostPortInRange(p int) bool {
	return p >= 0 && p <= 65535
}
