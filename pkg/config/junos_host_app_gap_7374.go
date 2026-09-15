package config

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// junos_host_app_gap_7374.go — #7374.
//
// A `to-zone junos-host` PERMIT narrowed by `match application` is stricter than
// the coarse kernel host-inbound gate, is not enforced on the direct
// host-bound path, and drew NO commit-time warning.
//
// junosHostPolicyStricterThanCoarseGate tested only the SOURCE dimension
// (#4168) and later the DESTINATION one (#6612). An application-narrowed permit
// never reached either test, so it compiled to zero kernel rules and zero
// warnings: the nft `xpf_hostinbound` chain admits every configured
// system-service to the zone's local addresses, so a policy permitting only
// `junos-ssh` leaves https, ping, snmp and the rest admitted by the kernel
// while Junos would drop them to the junos-host default.
//
// WHY THIS IS A COMPARISON AND NOT A TOKEN TEST. A syntactic
// "application != any" test would fire on the very common
//
//	policy allow-mgmt { match { ... application [ junos-ssh junos-ping ]; } then permit; }
//
// even when the zone's host-inbound-traffic admits nothing beyond ssh and
// ping -- i.e. when there is no gap at all. That is a false positive on a large
// fraction of real configs, and the project has explicit precedent against it
// (#4455 Component B, and the #3226 `all` advisory, are both gated on whether
// the narrowing can actually change enforcement).
//
// So this compares the permitted application set against the zone's EFFECTIVE
// host-inbound admit set, expanded through the same SSOTs the dataplane uses
// (InterfaceHostInboundEffective, HostInboundServiceMatch,
// HostInboundProtocolMatch), and reports only a tuple the gate admits and the
// permit does not cover.
//
// IT FAILS QUIET, DELIBERATELY. Anything it cannot resolve -- an unknown
// application, a malformed port, a custom application it cannot reduce to an
// L4 tuple -- yields NO warning. A false negative here costs an advisory; a
// false positive costs the advisory's credibility on every config that does
// not have the problem, which is the failure mode this issue exists to avoid.

// appL4Matches reduces an application name to the L4 tuples it admits, or
// ok=false when it cannot be reduced (unknown name, unparseable port, an
// application-set, or a protocol this comparison does not model).
func appL4Matches(cfg *Config, name string) (out []L4Match, ok bool) {
	app := PredefinedApplications[name]
	if app == nil && cfg != nil && cfg.Applications.Applications != nil {
		app = cfg.Applications.Applications[name]
	}
	if app == nil {
		return nil, false
	}
	proto, ok := appProtoNumber(app.Protocol)
	if !ok {
		return nil, false
	}
	switch proto {
	case HostInboundProtoTCP, HostInboundProtoUDP:
		ports, ok := parsePortRangeSpec(app.DestinationPort)
		if !ok {
			return nil, false
		}
		return []L4Match{{Proto: proto, Ports: ports}}, true
	case HostInboundProtoICMP, HostInboundProtoICMPv6:
		// A nil ICMPType means "every type of its protocol" (#3020), which
		// covers any admitted ICMP tuple of that protocol.
		return []L4Match{{Proto: proto, ICMPType: app.ICMPType}}, true
	default:
		return []L4Match{{Proto: proto}}, true
	}
}

func appProtoNumber(p string) (uint8, bool) {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "tcp":
		return HostInboundProtoTCP, true
	case "udp":
		return HostInboundProtoUDP, true
	case "icmp":
		return HostInboundProtoICMP, true
	case "icmp6", "icmpv6":
		return HostInboundProtoICMPv6, true
	case "":
		return 0, false
	}
	n, err := ParseCanonicalUint(p)
	if err != nil || n > 255 {
		return 0, false
	}
	return uint8(n), true
}

// parsePortRangeSpec parses "80" or "8080-8090". An EMPTY spec is not "every
// port" here -- it is unresolvable, and returns ok=false so the caller stays
// quiet rather than assuming coverage it cannot demonstrate.
func parsePortRangeSpec(spec string) ([]PortRange, bool) {
	s := strings.TrimSpace(spec)
	if s == "" {
		return nil, false
	}
	lo, hi, found := strings.Cut(s, "-")
	l, err := strconv.ParseUint(strings.TrimSpace(lo), 10, 16)
	if err != nil {
		return nil, false
	}
	if !found {
		return []PortRange{{Lo: uint16(l), Hi: uint16(l)}}, true
	}
	h, err := strconv.ParseUint(strings.TrimSpace(hi), 10, 16)
	if err != nil || h < l {
		return nil, false
	}
	return []PortRange{{Lo: uint16(l), Hi: uint16(h)}}, true
}

// l4Covered reports whether `admitted` is fully covered by any match in `by`.
func l4Covered(admitted L4Match, by []L4Match) bool {
	for _, p := range by {
		if p.Proto != admitted.Proto {
			continue
		}
		switch admitted.Proto {
		case HostInboundProtoTCP, HostInboundProtoUDP:
			if portsCover(p.Ports, admitted.Ports) {
				return true
			}
		case HostInboundProtoICMP, HostInboundProtoICMPv6:
			// A permit with no type constraint covers every type.
			if p.ICMPType == nil {
				return true
			}
			if admitted.ICMPType != nil && *p.ICMPType == *admitted.ICMPType {
				return true
			}
		default:
			return true // bare IP protocol: the protocol number is the match
		}
	}
	return false
}

func portsCover(by, admitted []PortRange) bool {
	if len(admitted) == 0 {
		return false
	}
	for _, a := range admitted {
		covered := false
		for _, b := range by {
			if b.Lo <= a.Lo && a.Hi <= b.Hi {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

// zoneAdmittedTokens returns the zone's EFFECTIVE host-inbound tokens: the
// zone level, plus every per-interface override, since the coarse gate admits
// the union across the zone's local addresses.
func zoneAdmittedTokens(z *ZoneConfig) (svc, proto []string) {
	if z == nil {
		return nil, nil
	}
	seenSvc, seenProto := map[string]bool{}, map[string]bool{}
	add := func(dst *[]string, seen map[string]bool, toks []string) {
		for _, t := range toks {
			t = strings.ToLower(strings.TrimSpace(t))
			if t == "" || seen[t] {
				continue
			}
			seen[t] = true
			*dst = append(*dst, t)
		}
	}
	if z.HostInboundTraffic != nil {
		add(&svc, seenSvc, z.HostInboundTraffic.SystemServices)
		add(&proto, seenProto, z.HostInboundTraffic.Protocols)
	}
	for _, ref := range z.SortedInterfaceHostInboundRefs() {
		s, p, _ := z.InterfaceHostInboundEffective(ref)
		add(&svc, seenSvc, s)
		add(&proto, seenProto, p)
	}
	return svc, proto
}

// junosHostPermitApplicationGap reports whether an application-scoped junos-host
// PERMIT leaves the coarse gate admitting a token the permit does not cover, and
// names the first such token.
func junosHostPermitApplicationGap(cfg *Config, z *ZoneConfig, m PolicyMatch) (bool, string) {
	if len(m.Applications) == 0 {
		return false, ""
	}
	var permitted []L4Match
	for _, a := range m.Applications {
		if strings.EqualFold(strings.TrimSpace(a), "any") {
			return false, "" // not narrowed at all
		}
		ms, ok := appL4Matches(cfg, a)
		if !ok {
			// Unresolvable: stay quiet rather than claim a gap we cannot show.
			return false, ""
		}
		permitted = append(permitted, ms...)
	}
	if len(permitted) == 0 {
		return false, ""
	}

	svc, proto := zoneAdmittedTokens(z)
	var uncovered []string

	// FAMILY HANDLING, and it is the difference between a useful advisory and a
	// false positive on nearly every real config.
	//
	// A host-inbound token expands PER FAMILY: `ping` yields ICMP echo-request
	// for ip AND ICMPv6 echo-request (128) for ip6. The application catalogue
	// keys the two separately -- `junos-ping` is the v4 one, with a v6 twin
	// under a different name. So comparing every family against the permit
	// reports a v6 gap for the extremely common `application junos-ping`, which
	// is precisely the false positive this issue forbids.
	//
	// A token is therefore judged in its PRIMARY family: ip when it has any ip
	// matches, ip6 only for a token that is v6-only. That still catches a token
	// the permit does not cover at all (https against a junos-ssh permit), and
	// it stops the advisory firing on a dual-stack expansion the operator did
	// not write.
	//
	// The narrower reading -- warn on the v4/v6 asymmetry too -- may well be
	// correct Junos semantics, but it is a SEPARATE advisory with its own
	// false-positive profile and should not ride in on this one.
	check := func(tokens []string, lookup func(string, string) []L4Match) {
		for _, tok := range tokens {
			fam := "ip"
			if len(lookup(tok, "ip")) == 0 {
				fam = "ip6"
			}
			for _, adm := range lookup(tok, fam) {
				if adm.Reject {
					// #3310 ident-reset RESETS rather than admits.
					continue
				}
				if !l4Covered(adm, permitted) {
					uncovered = append(uncovered, tok)
					break
				}
			}
		}
	}
	check(svc, HostInboundServiceMatch)
	check(proto, HostInboundProtocolMatch)
	if len(uncovered) == 0 {
		return false, ""
	}
	sort.Strings(uncovered)
	return true, fmt.Sprintf("application-restricted permit (the zone's host-inbound "+
		"gate still admits %q, which no permitted application covers)", uncovered[0])
}

// zoneByName looks up a security zone, or nil.
func zoneByName(cfg *Config, name string) *ZoneConfig {
	if cfg == nil || cfg.Security.Zones == nil {
		return nil
	}
	return cfg.Security.Zones[name]
}

// sortedZoneNames returns the zone names in a deterministic order, so a global
// policy's first-reported gap does not change between runs on one config.
func sortedZoneNames(cfg *Config) []string {
	if cfg == nil || cfg.Security.Zones == nil {
		return nil
	}
	out := make([]string, 0, len(cfg.Security.Zones))
	for n := range cfg.Security.Zones {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
