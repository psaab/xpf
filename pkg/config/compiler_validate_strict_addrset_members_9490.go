package config

import (
	"fmt"
	"sort"
)

// validateAddressSetMembersDefinedStrict (#9490) refuses an address-set member
// that names no address or address-set.
//
// `address-set s1 { address a1 xpfbogus9206 v1; }` committed clean, and
// Addresses carried all three names. The runtime resolver drops a name it
// cannot find, so the set a policy matches on silently resolves to FEWER
// members than it lists: #9088's shape on a security object. The policy-side
// gate (validatePolicyMatchAddressSetMembersStrict) resolves only sets that a
// policy references, and it runs after the #2008 token gate, so a set nothing
// references yet, or a bad member beside a good one, was never refused.
//
// It runs on the compiled global book, after resolveZoneLocalAddressBooks has
// folded zone-local books in and qualified the members they define locally.
// A name is checked against the same maps the runtime resolver reads. A member
// is accepted if it is EITHER an address or an address-set, matching that
// resolver, so this refuses only a name that resolves to nothing. The policy
// wildcards stay admissible.
func validateAddressSetMembersDefinedStrict(cfg *Config) error {
	if cfg == nil || cfg.Security.AddressBook == nil {
		return nil
	}
	ab := cfg.Security.AddressBook
	defined := func(name string) bool {
		if IsPolicyAddressWildcardKeyword(name) {
			return true
		}
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
		for _, kind := range []struct {
			leaf    string
			members []string
		}{{"address", set.Addresses}, {"address-set", set.AddressSets}} {
			for _, m := range kind.members {
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
