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

// resolveAddressBookNameKind classifies name within ab and reports whether the
// name COLLIDES — i.e. is defined as BOTH a plain `address` AND an
// `address-set` in the same book (the #5676 shadow).
//
// `address` and `address-set` share one operator-visible namespace (an operator
// types a single token in `match source-address <name>`), yet land in two
// separate maps, so a same-name collision is possible. Before #5676 that
// collision resolved silently and INCONSISTENTLY-looking but actually
// address-first everywhere a name is turned into prefixes: the dataplane
// resolver (pkg/dataplane/userspace expandBookNameRecursive / nameRepresentability
// / capabilities) and the host-inbound deny compiler (junos_host_deny) all check
// `ab.Addresses[name]` before `ab.AddressSets[name]`. So a plain `address`
// silently SHADOWED a same-named `address-set`, dropping the set's other members
// and CHANGING which traffic a permit/deny rule covers with no diagnostic.
//
// This helper is the single source of truth for that deterministic winner: on a
// collision the plain `address` WINS (address-first), matching the runtime
// resolver bit-for-bit. The strict admission gate
// (validateAddressBookNameCollisionStrict) hard-rejects the collision so it can
// never be freshly authored; the tolerant load / peer-sync path KEEPS this
// address-first winner (so a reload does not silently change the forwarding an
// already-running config has been doing — the #1960 no-behavior-change-on-boot
// doctrine) and only warns.
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
// `destination-address blocklist` is then AMBIGUOUS: every place a name is
// resolved to prefixes checks Addresses before AddressSets (address-first — see
// resolveAddressBookNameKind), so the plain address silently WINS and the
// same-named address-set's other members are dropped. A deny built on the SET
// then covers only the single address (an under-block — traffic the operator
// meant to deny is permitted); symmetrically a permit built on the address is
// unaffected but the operator's mental model (a group) is wrong. This is a
// silent, security-relevant change to which traffic a rule covers — an
// admission / root-identity defect (codex-review-182 M10, High).
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
// Strict on commit / commit-check (hard reject so the ambiguity is
// operator-visible); the call site downgrades this to a warning on the tolerant
// load / peer-sync path (opts.lenientAddressBookNameCollision, #1960 no-brick)
// so an already-persisted or peer-synced config carrying a pre-existing
// collision still BOOTS — the runtime then resolves the deterministic
// address-first winner exactly as it already did. Mirrors
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

// addressBookNameCollision returns the first same-name `address` +
// `address-set` collision in ab (walked in sorted name order for a
// deterministic first error), naming the offending entry and the book scope.
func addressBookNameCollision(scope string, ab *AddressBook) error {
	if ab == nil {
		return nil
	}
	names := make([]string, 0, len(ab.Addresses))
	for n := range ab.Addresses {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if _, collision := resolveAddressBookNameKind(ab, n); collision {
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
	}
	return nil
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
