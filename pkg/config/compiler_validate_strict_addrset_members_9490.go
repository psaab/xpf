package config

import (
	"fmt"
	"sort"
)

// validateAddressSetMembersDefinedStrict (#9490/#11822, #12243) refuses
// address-set members that name no address or address-set, unknown member
// statements that the lenient compiler would otherwise drop, and policy
// match-all wildcards (`any`, `any-ipv4`, ...) used as set members. A dangling
// member leaves the set short at runtime; an unknown statement silently drops
// an authored member outright. Either can narrow a DENY policy and permit
// traffic the operator meant to block.
//
// It runs on the compiled global book, after resolveZoneLocalAddressBooks has
// folded zone-local books in and qualified the members they define locally.
// A name is checked against the same maps the runtime resolver reads. A member
// is accepted if it is EITHER an address or an address-set, matching that
// resolver, so this refuses only a name that resolves to nothing — plus the
// policy wildcards, which resolve to nothing as set members on EVERY consumer:
// the legacy compiler's AddrIDs map holds only book names (so
// `compileAddressBook` aborts the whole apply with `member "any" not found`),
// and the userspace resolver's resolve() has no wildcard branch (so a set
// carrying one fails the #3149 mirror when referenced, and would silently
// narrow the set's snapshot row when not). Admitting them here while every
// runtime rejects them is a commit-green/apply-red split (#12243).
func validateAddressSetMembersDefinedStrict(cfg *Config) error {
	if cfg == nil || cfg.Security.AddressBook == nil {
		return nil
	}
	ab := cfg.Security.AddressBook
	defined := func(name string) bool {
		if _, ok := ab.Addresses[name]; ok {
			return true
		}
		_, ok := ab.AddressSets[name]
		return ok
	}
	show := func(name string) string {
		if zone, local, ok := ZoneLocalUnqualify(name); ok {
			return fmt.Sprintf("%s (security-zone %s)", local, zone)
		}
		return name
	}
	names := make([]string, 0, len(ab.AddressSets))
	for n := range ab.AddressSets {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		set := ab.AddressSets[name]
		if set == nil {
			continue
		}
		if len(set.UnknownMembers) > 0 {
			return fmt.Errorf("address-set %s: unknown member statement %q; the "+
				"unrecognized keyword is silently dropped, leaving the set under-populated "+
				"and a deny policy referencing it able to permit traffic meant to be blocked",
				show(name), set.UnknownMembers[0])
		}
		for _, kind := range []struct {
			leaf    string
			members []string
		}{{"address", set.Addresses}, {"address-set", set.AddressSets}} {
			for _, m := range kind.members {
				if IsPolicyAddressWildcardKeyword(m) {
					return fmt.Errorf("address-set %s %s %q is a policy match-all "+
						"wildcard, not an address-book name; no runtime resolves it "+
						"as a set member, so the set aborts the apply that compiles "+
						"it (#12243)", show(name), kind.leaf, show(m))
				}
				if !defined(m) {
					return fmt.Errorf("address-set %s %s %q is not a defined address or "+
						"address-set; the member resolves to nothing, so the set "+
						"silently matches less than it lists", show(name), kind.leaf, show(m))
				}
			}
		}
	}
	return nil
}
