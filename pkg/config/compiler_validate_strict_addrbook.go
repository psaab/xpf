package config

import (
	"fmt"
	"sort"
	"strings"
)

// AddressBookRefKind classifies how a bare address-book name resolves within a
// SINGLE address book. `address` and `address-set` entries are stored in
// DISTINCT maps (AddressBook.Addresses / AddressBook.AddressSets), so absent a
// same-name collision every name resolves unambiguously to exactly one kind —
// the two kinds ARE namespace-distinguishable at the storage layer.
type AddressBookRefKind int

const (
	// AddrRefNone: the name is defined as neither an address nor an address-set.
	AddrRefNone AddressBookRefKind = iota
	// AddrRefAddress: the name resolves to a plain `address` entry.
	AddrRefAddress
	// AddrRefAddressSet: the name resolves to an `address-set` entry.
	AddrRefAddressSet
)

// resolveAddressBookNameKind classifies a name within ab and reports whether
// the name COLLIDES — i.e. it is defined as BOTH a plain `address` AND an
// `address-set` in the same book (the #5676 shadow).
//
// `address` and `address-set` share one operator-visible namespace but land in
// separate maps, so a same-name collision is possible. Before #12049, userspace
// policy resolution checked `ab.Addresses[name]` before `ab.AddressSets[name]`;
// the plain address therefore shadowed the set and silently changed which
// traffic the rule covered. Strict admission rejects the ambiguity. On tolerant
// load, the collision marker is retained so policy references are refused with
// the unsupported-address sentinel rather than selecting either definition.
func resolveAddressBookNameKind(ab *AddressBook, name string) (kind AddressBookRefKind, collision bool) {
	if ab == nil {
		return AddrRefNone, false
	}
	_, isAddr := ab.Addresses[name]
	_, isSet := ab.AddressSets[name]
	switch {
	case isAddr && isSet:
		return AddrRefAddress, true // address-first deterministic winner
	case isAddr:
		return AddrRefAddress, false
	case isSet:
		return AddrRefAddressSet, false
	default:
		return AddrRefNone, false
	}
}

// validateAddressBookNameCollisionStrict (#5676) hard-rejects an address book —
// the global book or ANY zone-local book — that defines the SAME name as BOTH a
// plain `address` and an `address-set`.
//
// The two kinds share one operator-visible namespace but are stored in two
// separate maps (AddressBook.Addresses / AddressBook.AddressSets), so an
// operator can author `address blocklist 10.0.0.0/24` AND
// `address-set blocklist { address other; ... }` in the same book with no
// commit error. A security-policy `match source-address blocklist` /
// `destination-address blocklist` is then AMBIGUOUS: before #12049 userspace
// resolution checked Addresses before AddressSets, so the plain address
// silently WINS and the same-named address-set's other members are dropped. A
// deny built on the SET then covers only the single address (an under-block —
// traffic the operator meant to deny is permitted); symmetrically a permit
// built on the address is unaffected but the operator's mental model (a group)
// is wrong. This is a silent, security-relevant change to which traffic a rule
// covers — an admission / root-identity defect (codex-review-182 M10, High).
//
// Junos itself forbids a same-name `address` + `address-set` in one address
// book (the CLI rejects the second definition at commit), so there is no
// vendor-defined precedence to honor — the hard reject MATCHES vSRX. The error
// names both colliding entries and the book (global / the zone) so the operator
// renames one and the reference becomes unambiguous.
//
// MUST run on the PRISTINE books — i.e. BEFORE resolveZoneLocalAddressBooks
// folds zone-local entries into the global book under synthetic
// zone-local/<zone>/<name> names — so a global `address foo` and a DIFFERENT
// zone's zone-local `address-set foo` (two genuinely distinct namespaces after
// the fold) are never misreported as a collision, and so a real zone-local
// collision is reported against the clean zone name rather than the synthetic
// key. The caller (runEarlyStrictAndFolds) enforces that ordering.
//
// Strict on commit / commit-check hard-rejects the ambiguity. The tolerant
// load / peer-sync path (opts.lenientAddressBookNameCollision, #1960 no-brick)
// downgrades it to a warning so an existing config still BOOTS, records all
// colliding names on AddressBook, and lets userspace reject any policy that
// references one with a non-empty rejection mirror. Mirrors
// validateAddressBookEntryNamesStrict.
func validateAddressBookNameCollisionStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	if err := addressBookNameCollision("security address-book global", cfg.Security.AddressBook); err != nil {
		return err
	}
	// Walk zones in sorted order so the first-reported error is deterministic
	// regardless of Go map iteration order.
	zoneNames := make([]string, 0, len(cfg.Security.Zones))
	for z := range cfg.Security.Zones {
		zoneNames = append(zoneNames, z)
	}
	sort.Strings(zoneNames)
	for _, z := range zoneNames {
		zone := cfg.Security.Zones[z]
		if zone == nil {
			continue
		}
		scope := fmt.Sprintf("security zone %q address-book", z)
		if err := addressBookNameCollision(scope, zone.AddressBook); err != nil {
			return err
		}
	}
	return nil
}
func recordAddressBookNameCollisions(cfg *Config) {
	if cfg == nil {
		return
	}
	record := func(ab *AddressBook) {
		names := addressBookCollisionNames(ab)
		if len(names) == 0 {
			return
		}
		if ab.CollidingNames == nil {
			ab.CollidingNames = make(map[string]struct{}, len(names))
		}
		for _, name := range names {
			ab.CollidingNames[name] = struct{}{}
		}
	}
	record(cfg.Security.AddressBook)
	for _, zone := range cfg.Security.Zones {
		if zone != nil {
			record(zone.AddressBook)
		}
	}
}

func addressBookCollisionNames(ab *AddressBook) []string {
	if ab == nil {
		return nil
	}
	names := make([]string, 0, len(ab.Addresses))
	for name := range ab.Addresses {
		if _, collision := resolveAddressBookNameKind(ab, name); collision {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}


// addressBookNameCollision returns the first same-name `address` +
// `address-set` collision in ab (walked in sorted name order for a
// deterministic first error), naming the offending entry and the book scope.
func addressBookNameCollision(scope string, ab *AddressBook) error {
	if ab == nil {
		return nil
	}
	names := addressBookCollisionNames(ab)
	if len(names) == 0 {
		return nil
	}
	n := names[0]
	return fmt.Errorf(
		"%s defines %q as BOTH an `address` and an `address-set`; "+
			"the two share one namespace, so a policy `match "+
			"source-address %s` / `destination-address %s` resolves "+
			"ambiguously and the plain address silently shadows the "+
			"same-named address-set (dropping its other members and "+
			"changing which traffic a permit/deny rule covers). Rename one "+
			"of the two entries so every policy reference is unambiguous",
		scope, n, n, n)
}

// validateAddressBookMappedPrefixesStrict rejects IPv4-mapped IPv6 address-book
// values (#10688). Go's net.IP.To4 folds these prefixes into the IPv4 wire
// array, while the userspace helper parses the colon-bearing token as IPv6 and
// rejects the whole snapshot's wrong-family prefix. A strict commit must not
// create that silent whole-snapshot refusal.
func validateAddressBookMappedPrefixesStrict(cfg *Config) error {
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
			address := book.Addresses[name]
			if address != nil && FRRAddrIsMapped(address.Value) {
				return fmt.Errorf(
					"%s address-book address %q has IPv4-mapped IPv6 prefix %q; "+
						"the userspace snapshot builder files it in prefixes_v4, "+
						"but the helper parses it as IPv6 and rejects the entire policy snapshot; "+
						"use a non-mapped IPv4 or IPv6 prefix (#10688)",
					scope, name, address.Value)
			}
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
		if zone := cfg.Security.Zones[name]; zone != nil {
			if err := check(fmt.Sprintf("security zone %q", name), zone.AddressBook); err != nil {
				return err
			}
		}
	}
	return nil
}
