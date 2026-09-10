package config

import (
	"fmt"
	"sort"
)

// policyAddressWildcardKeywords are the policy source/destination-address tokens
// that mean "every address" (both families, or one): the Junos keywords `any`,
// `any-ipv4` and `any-ipv6`, and the internal short forms `any4` / `any6` that the
// userspace matcher also reads as family wildcards (policy.rs
// parse_v3_literal_set).
var policyAddressWildcardKeywords = map[string]struct{}{
	"any":      {},
	"any4":     {},
	"any6":     {},
	"any-ipv4": {},
	"any-ipv6": {},
}

// IsPolicyAddressWildcardKeyword reports whether tok is a match-all keyword
// (#9523).
//
// THE CONTRACT. Every resolver of a policy address token asks this BEFORE it
// looks tok up as an address-book address, address-set or dynamic-address
// name. Name-before-literal precedence is deliberate and documented (an entry
// named `10.0.1.0/24` with another value is still resolved by name, as on
// Junos), and it stays in force for every token that is not one of these. The
// keywords are the exception because Junos reserves them: no object can be
// created under them, so no object can capture them. Before #9523 the snapshot
// builder and the simulator resolved a name first, so an address, address-set
// or dynamic-address binding literally named `any` silently turned every
// `match ... any` in every policy into a match on that object's prefixes.
//
// validateReservedAddressNamesStrict rejects such an object at commit; this
// predicate is what keeps the keyword a keyword on the tolerant path, where the
// object loads with a warning.
func IsPolicyAddressWildcardKeyword(tok string) bool {
	_, ok := policyAddressWildcardKeywords[tok]
	return ok
}

// validateReservedAddressNamesStrict hard-rejects an address-book address or
// address-set (global or zone-local) or a dynamic-address address-name whose
// name is a policy match-all keyword (#9523).
//
// It mirrors validateReservedZoneNamesStrict (#3055), which reserves `any` out
// of the ZONE namespace for the same reason: a real object of that name can
// never be selected by name and would shadow the wildcard. Strict on commit /
// commit-check; the tolerant load / peer-sync paths downgrade it to a warning
// (lenientReservedAddressNames, #1960 no-brick), and there
// IsPolicyAddressWildcardKeyword keeps the keyword matching every address.
//
// It MUST run on the pristine books, before resolveZoneLocalAddressBooks mints
// qualified names, so a zone-local object is reported under its authored name.
// Iteration is in sorted order so the first-reported error is deterministic.
func validateReservedAddressNamesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	check := func(kind, name string) error {
		if !IsPolicyAddressWildcardKeyword(name) {
			return nil
		}
		return fmt.Errorf(
			"%s %q uses a reserved name: %q is a policy match-all address keyword, so "+
				"`source-address %s` / `destination-address %s` in a policy could never "+
				"refer to this object — rename it (#9523)",
			kind, name, name, name, name)
	}
	checkBook := func(where string, ab *AddressBook) error {
		if ab == nil {
			return nil
		}
		for _, n := range sortedKeys9523(ab.Addresses) {
			if err := check(where+" address", n); err != nil {
				return err
			}
		}
		for _, n := range sortedKeys9523(ab.AddressSets) {
			if err := check(where+" address-set", n); err != nil {
				return err
			}
		}
		return nil
	}
	if err := checkBook("security address-book global", cfg.Security.AddressBook); err != nil {
		return err
	}
	for _, z := range sortedKeys9523(cfg.Security.Zones) {
		if zone := cfg.Security.Zones[z]; zone != nil {
			if err := checkBook(fmt.Sprintf("security-zone %q address-book", z), zone.AddressBook); err != nil {
				return err
			}
		}
	}
	for _, n := range sortedKeys9523(cfg.Security.DynamicAddress.AddressBindings) {
		if err := check("security dynamic-address address-name", n); err != nil {
			return err
		}
	}
	return nil
}

func sortedKeys9523[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
