package config

import (
	"fmt"
	"sort"
	"strings"
)

// unimplementedAddressForms9524 are the Junos address value forms the compiler
// does not implement (#9524). An address takes exactly one value form: a prefix,
// or one of these.
var unimplementedAddressForms9524 = map[string]bool{
	"dns-name":         true,
	"wildcard-address": true,
	"range-address":    true,
}

func appendUniqueForm9524(forms []string, form string) []string {
	for _, f := range forms {
		if f == form {
			return forms
		}
	}
	return append(forms, form)
}

// validateAddressUnimplementedFormsStrict rejects an address-book entry that
// configures a prefix AND an unimplemented value form (#9524).
//
// Before #9524 such an entry compiled to the prefix alone on all four config
// channels with no warning, so a `deny` naming the object silently under-covered
// it by exactly the form the compiler dropped. The sole-value case (only a
// dns-name, say) was already loud: Value "" is warned (#2229), strict-rejected
// when referenced (#3149), and poisons the snapshot on the tolerant path
// (#3261). A mixed entry is not valid Junos, so strict commit rejects it
// outright, naming the entry, the prefix and the dropped form. A sole
// unimplemented form stays as it was: it is valid Junos, merely unimplemented.
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
					"enforced alone and the %s silently dropped; keep one of them (#9524)",
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
