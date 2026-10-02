package config

import (
	"fmt"
	"sort"
	"strings"
)

// Address book entries resolve only through a parsed IP/CIDR prefix or the
// separately modeled `description` attribute. The compiler records known
// unsupported Junos forms (dns-name, wildcard-address, range-address) and
// unknown future form keywords in UnimplementedForms (#11508).

func appendUniqueForm9524(forms []string, form string) []string {
	for _, f := range forms {
		if f == form {
			return forms
		}
	}
	return append(forms, form)
}

// validateAddressUnimplementedFormsStrict rejects an address-book entry that
// configures a prefix AND an unsupported or unknown value form.
//
// Before #9524 such an entry compiled to the prefix alone on all config
// channels with no warning, so a `deny` naming the object silently under-covered
// it by exactly the form the compiler dropped. The strict gate rejects this
// mixed shape, while the tolerant path warns and Address.UsableValue returns
// empty so both policy and NAT resolvers treat the entry as unresolvable.
// A sole unsupported form remains unusable and is rejected when referenced,
// preserving its existing behavior (#2229/#3149/#3261).
//
// It walks the global book and every zone-local book, and skips the synthetic
// zone-local/ names the fold injects into the global book, so an error names
// what the operator wrote. Sorted, so the first error is deterministic.
func validateAddressUnimplementedFormsStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	check := func(scope string, book *AddressBook) error {
		if book == nil {
			return nil
		}
		names := make([]string, 0, len(book.Addresses))
		for name := range book.Addresses {
			if strings.HasPrefix(name, zoneLocalNamePrefix) {
				continue
			}
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			a := book.Addresses[name]
			if a == nil || a.Value == "" || len(a.UnimplementedForms) == 0 {
				continue
			}
			form := a.UnimplementedForms[0]
			return fmt.Errorf(
				"security %saddress-book address %q configures the prefix %q and also %s: a Junos address "+
					"takes exactly one value form, and %s is not implemented, so the prefix would be "+
					"enforced alone and the %s silently dropped; keep one of them (#9524/#11508)",
				scope, name, a.Value, strings.Join(a.UnimplementedForms, ", "), form, form)
		}
		return nil
	}
	if err := check("", cfg.Security.AddressBook); err != nil {
		return err
	}
	zones := make([]string, 0, len(cfg.Security.Zones))
	for z := range cfg.Security.Zones {
		zones = append(zones, z)
	}
	sort.Strings(zones)
	for _, z := range zones {
		if zc := cfg.Security.Zones[z]; zc != nil {
			if err := check(fmt.Sprintf("zones security-zone %s ", z), zc.AddressBook); err != nil {
				return err
			}
		}
	}
	return nil
}
