package config

import (
	"fmt"
	"sort"
)

// validateAddressBookCIDRMaskSpellingStrict rejects address-book prefixes whose
// redundant mask digits are preserved on the wire. Address-book and policy
// literals use canonical decimal masks so Go and userspace paths cannot diverge.
// It runs on pristine global and zone-local books so diagnostics name the
// authored entry before zone-local folding.
func validateAddressBookCIDRMaskSpellingStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	check := func(scope string, book *AddressBook) error {
		if book == nil {
			return nil
		}
		names := make([]string, 0, len(book.Addresses))
		for name := range book.Addresses {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			address := book.Addresses[name]
			if address == nil {
				continue
			}
			value := address.UsableValue()
			if !CIDRMaskHasRedundantLeadingZero(value) {
				continue
			}
			return fmt.Errorf(
				"%s address-book address %q has CIDR prefix %q with redundant leading-zero mask digits; policy CIDR masks must use canonical decimal spelling (#12047)",
				scope, name, value)
		}
		return nil
	}
	if err := check("security global", cfg.Security.AddressBook); err != nil {
		return err
	}
	zoneNames := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		zoneNames = append(zoneNames, name)
	}
	sort.Strings(zoneNames)
	for _, name := range zoneNames {
		zone := cfg.Security.Zones[name]
		if zone == nil {
			continue
		}
		if err := check(fmt.Sprintf("security zone %q", name), zone.AddressBook); err != nil {
			return err
		}
	}
	return nil
}
