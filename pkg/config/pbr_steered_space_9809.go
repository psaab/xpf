package config

import (
	"net/netip"
	"strconv"
	"strings"
)

// PBRDirectionSteers reports the address space one match direction of a
// firewall-filter term steers, the way pkg/routing's resolvePBRDirection
// realises it as ip rules (#9809). The #7924 overlap detector used to read only
// literal prefixes that netip.ParsePrefix accepts, so the same steer written as
// a prefix-list, a bare host, `any` or no match at all slipped past the gate.
//
//   - all: the direction matches every address. That is no address match, the
//     `any` keyword, or a pure `except` list with no entries.
//   - none: the direction matches nothing, or the builder drops the whole
//     term. That is a non-empty pure `except` list (an ip rule has no negated
//     selector), a literal that does not parse, or positive references that
//     resolve to no prefix.
//   - prefixes: otherwise, with prefix-lists expanded and a bare host as a /32
//     or /128. An unparseable prefix-list entry is skipped, as the builder
//     skips it. A positive set mixed with `except` keeps the positive set.
//
// One deliberate difference from the builder: a literal 0.0.0.0/0 or ::/0 is
// returned as a PREFIX, not as `all`. The builder treats it as match-all; the
// detector has always paired it with every other prefix, and #9809 keeps that.
// When `any` appears beside positive prefixes, both are reported: the prefixes
// and all=true.
func PBRDirectionSteers(literal []string, refs []PrefixListRef, pls map[string]*PrefixList) (prefixes []string, all, none bool) {
	if len(literal) == 0 && len(refs) == 0 {
		return nil, true, false
	}
	var (
		positive       []string
		hasPositiveRef bool
		hasExcept      bool
		exceptCount    int
		anySeen        bool
	)
	add := func(tok string) bool {
		t := strings.TrimSpace(tok)
		if t == "" || strings.EqualFold(t, "any") {
			anySeen = true
			return true
		}
		if p, err := netip.ParsePrefix(t); err == nil {
			positive = append(positive, p.String())
			return true
		}
		if a, err := netip.ParseAddr(t); err == nil && a.Zone() == "" {
			positive = append(positive, netip.PrefixFrom(a, a.BitLen()).String())
			return true
		}
		return false
	}
	for _, tok := range literal {
		if !add(tok) {
			return nil, false, true
		}
	}
	for _, ref := range refs {
		pl := pls[ref.Name]
		if ref.Except {
			hasExcept = true
			if pl != nil {
				exceptCount += len(pl.Prefixes)
			}
			continue
		}
		hasPositiveRef = true
		if pl == nil {
			continue
		}
		for _, p := range pl.Prefixes {
			add(p)
		}
	}
	if hasExcept && len(positive) == 0 && !hasPositiveRef && !anySeen {
		if exceptCount == 0 {
			return nil, true, false
		}
		return nil, false, true
	}
	if anySeen {
		return positive, true, false
	}
	if len(positive) == 0 {
		return nil, false, true
	}
	return positive, false, false
}

// RoutingInstanceMemberUnit is one interface unit a routing-instance member
// reference binds, with its configured addresses.
type RoutingInstanceMemberUnit struct {
	Ref       string // "<base>.<unit>"
	Addresses []string
}

// RoutingInstanceMemberUnits resolves a routing-instance `interface` member to
// the units it binds (#9809): a unit reference binds that unit, and a BARE
// reference binds every configured unit. That is the fan-down the userspace FIB
// applies (InterfaceUnitRefKeys, #9132). The overlap detector and
// RibGroupConnectedPrefixes read a bare member as unit 0 alone, so an addressed
// unit >= 1 was invisible to the gate and missing from the rib-group leak.
func RoutingInstanceMemberUnits(cfg *Config, member string) []RoutingInstanceMemberUnit {
	if cfg == nil {
		return nil
	}
	var out []RoutingInstanceMemberUnit
	for _, key := range InterfaceUnitRefKeys(cfg, member) {
		base, unitTok, hasUnit := strings.Cut(key, ".")
		if !hasUnit {
			continue // the base key a bare reference also keeps
		}
		n, err := strconv.Atoi(unitTok)
		if err != nil {
			continue
		}
		ifc := cfg.Interfaces.Interfaces[base]
		if ifc == nil {
			continue
		}
		unit := ifc.Units[n]
		if unit == nil {
			continue
		}
		out = append(out, RoutingInstanceMemberUnit{Ref: key, Addresses: unit.Addresses})
	}
	return out
}
