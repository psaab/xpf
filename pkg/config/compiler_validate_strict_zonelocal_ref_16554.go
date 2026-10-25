package config

import (
	"fmt"
	"sort"
	"strings"
)

// validateReservedZoneLocalRefTokensStrict (#16554) rejects any AUTHORED
// address reference token that begins with the reserved `zone-local/` prefix.
//
// resolveZoneLocalAddressBooks mints synthetic global keys
// `zone-local/<zone>/<name>` for zone-local entries and rewrites a policy
// token to that key only when the token resolves in the policy's own
// from/to zone book. Before this gate an operator could spell the synthetic
// key directly in a policy, global-policy, NAT, NAT64, or address-set-member
// token: the token was not rewritten (it is not an authored name in the
// rule's zones), the post-fold global book DID contain it (minted for the
// other zone), and every downstream definedness gate accepted it — so an
// untrust->dmz policy could bind trust's zone-local `web`, and a later edit
// of trust's book silently changed that rule. Display surfaces then stripped
// the prefix and showed `web`, a name absent from the rule's zones.
//
// This gate runs on the PRISTINE compiled config BEFORE
// resolveZoneLocalAddressBooks (see runEarlyStrictAndFolds), so every token
// it sees is authored — the fold has not yet minted or rewritten anything.
// Compiler-generated references are therefore never rejected: an own-zone
// authored `web` still compiles and is rewritten to the synthetic key by
// the fold. Only a literal `zone-local/...` spelling is reserved, exactly
// like operator entry names (#3061/#4340).
//
// Strict on commit / commit-check (hard reject naming the surface and the
// token); the call site downgrades to a warning on the tolerant load /
// peer-sync paths (lenientReservedZoneLocalRefs, #1960 no-brick) and poisons
// the offenders via poisonReservedZoneLocalRefs16554 so a leniently-loaded
// cross-zone binding never enforces the other zone's object.
func validateReservedZoneLocalRefTokensStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	return firstReservedZoneLocalRef(cfg)
}

// reservedZoneLocalRef is one authored token carrying the reserved prefix.
type reservedZoneLocalRef struct {
	surface string // operator-facing location, e.g. `security policies from-zone untrust to-zone dmz policy "p1" match source-address`
	token   string
}

func isReservedZoneLocalToken(tok string) bool {
	return strings.HasPrefix(tok, zoneLocalNamePrefix)
}

// reservedZoneLocalRefs enumerates every authored reserved-prefix token in
// deterministic order: address-set members (global, named, zone-local
// books), zone-pair then global policies, source/destination NAT,
// static-NAT prefix-name, then NAT64. It reads the PRISTINE books (before
// the fold), so zone-local set members are still authored names.
func reservedZoneLocalRefs(cfg *Config) []reservedZoneLocalRef {
	var refs []reservedZoneLocalRef
	add := func(surface, tok string) {
		if isReservedZoneLocalToken(tok) {
			refs = append(refs, reservedZoneLocalRef{surface: surface, token: tok})
		}
	}
	// Address-set members: global, named, and zone-local books.
	checkBook := func(scope string, ab *AddressBook) {
		if ab == nil {
			return
		}
		names := make([]string, 0, len(ab.AddressSets))
		for n := range ab.AddressSets {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			set := ab.AddressSets[n]
			if set == nil {
				continue
			}
			for _, m := range set.Addresses {
				add(fmt.Sprintf("%saddress-set %q address", scope, n), m)
			}
			for _, m := range set.AddressSets {
				add(fmt.Sprintf("%saddress-set %q address-set", scope, n), m)
			}
		}
	}
	checkBook("security address-book global ", cfg.Security.AddressBook)
	for _, bn := range sortedNamedBookNames15672(cfg.Security.NamedAddressBooks) {
		nb := cfg.Security.NamedAddressBooks[bn]
		checkBook(fmt.Sprintf("security address-book %s ", bn), &nb.AddressBook)
	}
	for _, zn := range sortedZoneNames(cfg) {
		z := cfg.Security.Zones[zn]
		if z == nil {
			continue
		}
		checkBook(fmt.Sprintf("security-zone %q address-book ", zn), z.AddressBook)
	}
	// Security policies (zone-pair, then global).
	checkPolicy := func(scope string, pol *Policy) {
		if pol == nil {
			return
		}
		for _, tok := range pol.Match.SourceAddresses {
			add(fmt.Sprintf("security policies %s policy %q match source-address", scope, pol.Name), tok)
		}
		for _, tok := range pol.Match.DestinationAddresses {
			add(fmt.Sprintf("security policies %s policy %q match destination-address", scope, pol.Name), tok)
		}
	}
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil {
			continue
		}
		scope := fmt.Sprintf("from-zone %s to-zone %s", zpp.FromZone, zpp.ToZone)
		for _, pol := range zpp.Policies {
			checkPolicy(scope, pol)
		}
	}
	for _, pol := range cfg.Security.GlobalPolicies {
		checkPolicy("global", pol)
	}
	// Source / destination NAT address-name references.
	checkNAT := func(kind string, rs *NATRuleSet) {
		if rs == nil {
			return
		}
		for _, rule := range rs.Rules {
			if rule == nil {
				continue
			}
			for _, tok := range rule.Match.SourceAddressNameList() {
				add(fmt.Sprintf("security nat %s rule-set %q rule %q match source-address-name", kind, rs.Name, rule.Name), tok)
			}
			for _, tok := range rule.Match.DestinationAddressNameList() {
				add(fmt.Sprintf("security nat %s rule-set %q rule %q match destination-address-name", kind, rs.Name, rule.Name), tok)
			}
		}
	}
	for _, rs := range cfg.Security.NAT.Source {
		checkNAT("source", rs)
	}
	if cfg.Security.NAT.Destination != nil {
		for _, rs := range cfg.Security.NAT.Destination.RuleSets {
			checkNAT("destination", rs)
		}
	}
	// Static NAT `then static-nat prefix-name` targets.
	for _, rs := range cfg.Security.NAT.Static {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil {
				continue
			}
			add(fmt.Sprintf("security nat static rule-set %q rule %q then static-nat prefix-name", rs.Name, rule.Name), rule.ThenPrefixName)
		}
	}
	// NAT64 source-address-name references.
	for _, rs := range cfg.Security.NAT.NAT64 {
		if rs == nil {
			continue
		}
		names := append([]string(nil), rs.SourceAddressNames...)
		if len(names) == 0 && rs.SourceAddressName != "" {
			names = append(names, rs.SourceAddressName)
		}
		for _, tok := range names {
			add(fmt.Sprintf("security nat nat64 rule-set %q match source-address-name", rs.Name), tok)
		}
	}
	return refs
}

func firstReservedZoneLocalRef(cfg *Config) error {
	refs := reservedZoneLocalRefs(cfg)
	if len(refs) == 0 {
		return nil
	}
	r := refs[0]
	return fmt.Errorf(
		"%s %q must not begin with the reserved %q prefix; that namespace is "+
			"reserved for the internal zone-local address book — reference the "+
			"address by its authored name in the owning zone, or define it in "+
			"the global address book (#16554)",
		r.surface, r.token, zoneLocalNamePrefix)
}

// reservedInSetClosure16554 reports whether the address-set `name` in the
// global book contains a reserved-prefix member, directly or through nested
// address-sets. Used on the pristine book to poison a policy/NAT reference
// that names such a set (the set itself is quarantined via CollidingNames,
// but marking the referencing rule makes the fail-closed verdict visible on
// the rule, not only inside the resolver).
func reservedInSetClosure16554(ab *AddressBook, name string, seen map[string]bool) bool {
	if ab == nil || seen[name] {
		return false
	}
	set := ab.AddressSets[name]
	if set == nil {
		return false
	}
	seen[name] = true
	for _, m := range set.Addresses {
		if isReservedZoneLocalToken(m) {
			return true
		}
	}
	for _, m := range set.AddressSets {
		if isReservedZoneLocalToken(m) || reservedInSetClosure16554(ab, m, seen) {
			return true
		}
	}
	return false
}

// poisonReservedZoneLocalRefs16554 makes every authored reserved-prefix
// reference fail closed on the tolerant path (#16554). It runs BEFORE the
// zone-local fold, while tokens are still authored:
//
//   - a policy carrying such a token is marked LenientContentDropped, so
//     the snapshot builder ships the __unsupported__ sentinel and the helper
//     refuses the whole snapshot rather than arming a cross-zone binding;
//   - a NAT / NAT64 rule carrying one is marked LenientMatchDropped, so the
//     snapshot builders fail that rule closed instead of resolving the other
//     zone's object;
//   - each distinct token is recorded in the global book's CollidingNames
//     under its literal spelling. After the fold that spelling IS the
//     synthetic key (when the owning zone defines it), so every resolver
//     that consults CollidingNames (policy, NAT, NAT64, static prefix-name)
//     refuses it — which also poisons any address-set whose member is the
//     reserved token, without rewriting authored set membership.
func poisonReservedZoneLocalRefs16554(cfg *Config) {
	if cfg == nil {
		return
	}
	refs := reservedZoneLocalRefs(cfg)
	if len(refs) == 0 {
		return
	}
	if cfg.Security.AddressBook == nil {
		cfg.Security.AddressBook = &AddressBook{
			Addresses:   make(map[string]*Address),
			AddressSets: make(map[string]*AddressSet),
		}
	}
	gb := cfg.Security.AddressBook
	if gb.CollidingNames == nil {
		gb.CollidingNames = make(map[string]struct{})
	}
	for _, r := range refs {
		gb.CollidingNames[r.token] = struct{}{}
	}
	markPolicy := func(pol *Policy) {
		if pol == nil {
			return
		}
		for _, tok := range append(append([]string(nil), pol.Match.SourceAddresses...), pol.Match.DestinationAddresses...) {
			if isReservedZoneLocalToken(tok) || reservedInSetClosure16554(gb, tok, make(map[string]bool)) {
				pol.LenientContentDropped = true
				return
			}
		}
	}
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil {
			continue
		}
		for _, pol := range zpp.Policies {
			markPolicy(pol)
		}
	}
	for _, pol := range cfg.Security.GlobalPolicies {
		markPolicy(pol)
	}
	markRule := func(rule *NATRule) {
		if rule == nil {
			return
		}
		for _, tok := range append(rule.Match.SourceAddressNameList(), rule.Match.DestinationAddressNameList()...) {
			if isReservedZoneLocalToken(tok) || reservedInSetClosure16554(gb, tok, make(map[string]bool)) {
				rule.LenientMatchDropped = true
				return
			}
		}
	}
	for _, rs := range cfg.Security.NAT.Source {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			markRule(rule)
		}
	}
	if cfg.Security.NAT.Destination != nil {
		for _, rs := range cfg.Security.NAT.Destination.RuleSets {
			if rs == nil {
				continue
			}
			for _, rule := range rs.Rules {
				markRule(rule)
			}
		}
	}
	// NAT64 has no LenientMatchDropped field; its poison is the
	// CollidingNames entry above (appendNATAddressNamesPoisoned refuses a
	// colliding name and ships a never-match source). Static-NAT
	// prefix-name likewise resolves through resolveStaticNATThenPrefixName,
	// which already refuses colliding names, leaving Then empty.
}
