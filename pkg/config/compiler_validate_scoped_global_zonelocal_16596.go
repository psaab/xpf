package config

import (
	"fmt"
	"strings"
)

// scopedGlobalZoneLocalRef is one global-policy address token that resolves
// only against a zone-local book (#16596).
type scopedGlobalZoneLocalRef struct {
	policy *Policy
	field  string // "source-address" or "destination-address"
	token  string
	zone   string
	viaSet string // global address-set through which the local-only name is reached; "" for a direct token
}

// scopedGlobalZoneLocalRefs enumerates, in deterministic order, every
// single-zone scoped-global address token whose meaning would require the
// scoped zone's local book (#16596). It MUST run after
// resolveNamedAddressBooks15672 (attached books folded into zones) and
// BEFORE resolveZoneLocalAddressBooks (which folds zone-local entries into
// the global book under qualified keys, erasing the authored/global
// distinction). Only single-concrete-zone scopes are considered: Junos
// requires global-policy addresses to be in the global book regardless of
// scope, but the live defect (and the former #3287 extension) is the
// single-zone rewrite; multi-zone/unscoped globals already resolve globally
// and a token defined only zone-locally there stays undefined for the
// #2008 gate to reject. A side whose scope is multi-zone, empty, or `any`
// is skipped here by design.
//
// A token offends when it is a non-literal name that is NOT resolvable from
// the global book (direct global entry, or a global address-set whose
// closure resolves globally, or a dynamic-address binding) but IS defined
// in the scoped zone's book (directly, or member-reachable through a global
// address-set — a global set may not smuggle a zone-local member into global
// scope). Reserved `zone-local/` spellings are the #16554 gate's domain and
// are skipped; `any`/family keywords and literal CIDR/IP tokens never name
// a book entry.
func scopedGlobalZoneLocalRefs(cfg *Config) []scopedGlobalZoneLocalRef {
	if cfg == nil {
		return nil
	}
	sec := &cfg.Security
	gb := sec.AddressBook

	globalDefines := func(name string) bool {
		if gb == nil {
			return false
		}
		if _, ok := gb.Addresses[name]; ok {
			return true
		}
		if _, ok := gb.AddressSets[name]; ok {
			return true
		}
		return false
	}
	bindingDefines := func(name string) bool {
		_, ok := sec.DynamicAddress.AddressBindings[name]
		return ok
	}
	// localDefines mirrors the fold's zone-local lookup, including the
	// DroppedEnforcementChild bookkeeping: a poisoned zone book still
	// "defines" its colliding/unknown names for quarantine purposes, so a
	// scoped global naming one must not fall through to the global book.
	localDefines := func(zone, name string) bool {
		z := sec.Zones[zone]
		if z == nil || z.AddressBook == nil {
			return false
		}
		if z.DroppedEnforcementChild {
			if _, ok := z.AddressBook.CollidingNames[name]; ok {
				return true
			}
			for _, entry := range z.AddressBook.UnknownBookEntries {
				for _, candidate := range entry.Names {
					if candidate == name {
						return true
					}
				}
			}
			return false
		}
		if _, ok := z.AddressBook.Addresses[name]; ok {
			return true
		}
		if _, ok := z.AddressBook.AddressSets[name]; ok {
			return true
		}
		for _, entry := range z.AddressBook.UnknownBookEntries {
			for _, candidate := range entry.Names {
				if candidate == name {
					return true
				}
			}
		}
		return false
	}
	// globalResolves reports whether a global address-set's member closure
	// fully resolves without any zone book: every leaf must be a global
	// entry, a binding, a literal, or a keyword.
	var globalClosureResolves func(name string, seen map[string]bool) bool
	globalClosureResolves = func(name string, seen map[string]bool) bool {
		if IsPolicyAddressWildcardKeyword(name) || looksLikeIPOrCIDR(name) {
			return true
		}
		if bindingDefines(name) {
			return true
		}
		if gb == nil {
			return false
		}
		if _, ok := gb.Addresses[name]; ok {
			return true
		}
		set, ok := gb.AddressSets[name]
		if !ok || set == nil {
			return false
		}
		if len(set.UnknownMembers) > 0 {
			return false
		}
		if seen[name] {
			return true
		}
		seen[name] = true
		for _, m := range set.Addresses {
			if !globalClosureResolves(m, seen) {
				return false
			}
		}
		for _, m := range set.AddressSets {
			if !globalClosureResolves(m, seen) {
				return false
			}
		}
		return true
	}
	// localOnlyMember returns the first zone-local-only member reachable
	// through the global address-set `name` (a name not defined globally and
	// not a binding/literal/keyword), or "" when the closure is clean. A
	// member that is defined nowhere is NOT this gate's finding — it is a
	// dangling/undefined reference for the #2008/#3149 gates.
	var localOnlyMember func(zone, name string, seen map[string]bool) string
	localOnlyMember = func(zone, name string, seen map[string]bool) string {
		if gb == nil {
			return ""
		}
		set, ok := gb.AddressSets[name]
		if !ok || set == nil {
			return ""
		}
		if seen[name] {
			return ""
		}
		seen[name] = true
		members := append(append([]string(nil), set.Addresses...), set.AddressSets...)
		for _, m := range members {
			if m == "" || IsPolicyAddressWildcardKeyword(m) || looksLikeIPOrCIDR(m) {
				continue
			}
			if bindingDefines(m) {
				continue
			}
			if globalDefines(m) {
				if found := localOnlyMember(zone, m, seen); found != "" {
					return found
				}
				continue
			}
			if localDefines(zone, m) {
				return m
			}
		}
		return ""
	}

	var refs []scopedGlobalZoneLocalRef
	for _, p := range sec.GlobalPolicies {
		if p == nil {
			continue
		}
		check := func(scope []string, field string, tokens []string) {
			if len(scope) != 1 || IsWildcardZone(scope[0]) {
				return
			}
			zone := scope[0]
			for _, tok := range tokens {
				if tok == "" || IsPolicyAddressWildcardKeyword(tok) || looksLikeIPOrCIDR(tok) {
					continue
				}
				if strings.HasPrefix(tok, zoneLocalNamePrefix) {
					continue // #16554 reserved-spelling gate
				}
				if bindingDefines(tok) {
					continue
				}
				if globalDefines(tok) {
					// A global address-set may still smuggle a member
					// that exists only in the scoped zone's book.
					if _, isSet := gb.AddressSets[tok]; isSet {
						if !globalClosureResolves(tok, make(map[string]bool)) {
							if member := localOnlyMember(zone, tok, make(map[string]bool)); member != "" {
								refs = append(refs, scopedGlobalZoneLocalRef{
									policy: p, field: field, token: member, zone: zone, viaSet: tok,
								})
							}
						}
					}
					continue
				}
				if localDefines(zone, tok) {
					refs = append(refs, scopedGlobalZoneLocalRef{
						policy: p, field: field, token: tok, zone: zone,
					})
				}
			}
		}
		check(p.Match.FromZones, "source-address", p.Match.SourceAddresses)
		check(p.Match.ToZones, "destination-address", p.Match.DestinationAddresses)
	}
	return refs
}

// validateScopedGlobalZoneLocalRefsStrict (#16596) rejects a single-zone
// scoped global policy whose address token is defined only in that zone's
// address book. Junos requires global-policy addresses to be defined in the
// global address book ("Addresses used in a global policy must be defined in
// global address book"); the zone scope narrows which flows the policy
// applies to, it does not rebind its address names to the zone's book.
// Before this gate, resolveZoneLocalAddressBooks rewrote such a token to
// `zone-local/<zone>/<name>` (#3287), so adding `match from-zone trust` to a
// global `deny BLOCKED` silently changed the enforced object from the
// global BLOCKED (say 10.0.0.0/8) to trust's BLOCKED (10.1.1.1/32) — and
// adding a second scope zone silently changed it back. Strict on commit /
// commit-check; the tolerant path warns and poisons (see
// poisonScopedGlobalZoneLocalRefs16596).
func validateScopedGlobalZoneLocalRefsStrict(cfg *Config) error {
	refs := scopedGlobalZoneLocalRefs(cfg)
	if len(refs) == 0 {
		return nil
	}
	r := refs[0]
	return scopedGlobalZoneLocalError(r)
}

func scopedGlobalZoneLocalError(r scopedGlobalZoneLocalRef) error {
	name := "?"
	if r.policy != nil {
		name = r.policy.Name
	}
	if r.viaSet != "" {
		return fmt.Errorf(
			"security policies global policy %q match %s %q: address-set member %q is defined only in the address book of zone %q (its attached or zone-local book), not in the global address book — Junos requires addresses used in a global policy to be defined in the global address book, so the zone scope does not rebind the name to the zone's book; define %q in `security address-book global` or reference it from a zone-pair policy for zone %q instead (#16596)",
			name, r.field, r.viaSet, r.token, r.zone, r.token, r.zone)
	}
	return fmt.Errorf(
		"security policies global policy %q match %s %q is defined only in the address book of zone %q (its attached or zone-local book), not in the global address book — Junos requires addresses used in a global policy to be defined in the global address book, so the zone scope does not rebind the name to the zone's book; define %q in `security address-book global` or reference it from a zone-pair policy for zone %q instead (#16596)",
		name, r.field, r.token, r.zone, r.token, r.zone)
}

// poisonScopedGlobalZoneLocalRefs16596 makes every scoped-global zone-local
// reference fail closed on the tolerant path (#16596, #1960 no-brick). It
// marks each referencing global policy LenientContentDropped: the userspace
// snapshot builder then poisons the rule with the __unsupported__ sentinel
// and the helper refuses the whole snapshot (previous-good retained;
// fresh-boot default-deny) rather than enforcing the zone-local object (or
// the same-named global twin) as the global policy's meaning. The
// policymatch simulator reports the same retention via
// PolicyContentRejectionReasons, so no surface certifies the wrong object.
func poisonScopedGlobalZoneLocalRefs16596(cfg *Config) {
	for _, r := range scopedGlobalZoneLocalRefs(cfg) {
		if r.policy != nil {
			r.policy.LenientContentDropped = true
		}
	}
}

