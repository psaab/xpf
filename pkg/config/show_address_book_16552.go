package config

import (
	"fmt"
	"sort"
	"strings"
)

// #16552: shared `show security address-book` value renderer.
//
// Before this, the local CLI, gRPC ShowText and REST show-text each
// printed only Address.Value. #15673 made dns-name / range-address /
// wildcard-address enforceable with Value empty by design, so every
// such entry rendered blank and a resolved dns-name was
// indistinguishable from an unresolved (match-none) one.
//
// AddressDisplayValue returns the single cell all three surfaces print
// after the entry name: the authored form plus the enforced set from
// UsableValues(). A tainted entry (unsupported/unknown form, duplicate
// prefix, trailing tokens, invalid range) prints NOT ENFORCED with
// the taint; an untainted entry with no usable prefixes (unresolved
// dns-name, or an entry with no value at all) prints an explicit
// unresolved marker instead of a blank.

// addressDisplayTaint returns the NOT ENFORCED marker for a tainted
// entry, or "" when the entry is untainted. The marker wording names
// the taint so an operator can find the authored problem.
func addressDisplayTaint(a *Address) string {
	switch {
	case len(a.UnimplementedForms) > 0:
		return "NOT ENFORCED: unsupported form " + strings.Join(a.UnimplementedForms, ", ")
	case a.OversizedRange != "":
		return "NOT ENFORCED: invalid range-address " + a.OversizedRange
	case len(a.DuplicatePrefixes) > 0:
		return "NOT ENFORCED: duplicate prefixes " + strings.Join(a.DuplicatePrefixes, ", ")
	case len(a.TrailingTokens) > 0:
		return "NOT ENFORCED: trailing tokens " + strings.Join(a.TrailingTokens, " ")
	}
	return ""
}

// AddressDisplayValue renders addr for `show security address-book`.
// Nil renders empty (surfaces skip nil slots before calling).
func AddressDisplayValue(a *Address) string {
	if a == nil {
		return ""
	}
	// Authored form. DNSRange/DNSWildcard hold the specification the
	// operator configured (#15673 stores only the expansion, so the
	// spec is retained alongside it); DNSName is the authored FQDN.
	form := ""
	switch {
	case a.DNSName != "":
		form = "dns-name " + a.DNSName
		if a.DNSFamily != "" {
			form += " [" + a.DNSFamily + "]"
		}
	case a.RangeSpec != "":
		form = "range-address " + a.RangeSpec
	case a.WildcardSpec != "":
		form = "wildcard-address " + a.WildcardSpec
	}

	if taint := addressDisplayTaint(a); taint != "" {
		if form != "" {
			return form + " (" + taint + ")"
		}
		if a.Value != "" {
			return a.Value + " (" + taint + ")"
		}
		return taint
	}

	usable := a.UsableValues()
	if form != "" {
		if len(usable) == 0 {
			// Unresolved dns-name (or a range/wildcard whose
			// expansion was lost): fail-closed, matches nothing.
			return form + " (unresolved — matches nothing)"
		}
		return form + " => " + strings.Join(usable, ", ")
	}
	if len(usable) == 0 {
		if a.Value != "" {
			return a.Value + " (unresolved — matches nothing)"
		}
		return "(unresolved — matches nothing)"
	}
	// Plain prefix entry (and any expansion without a recorded spec):
	// the enforced set is the whole story.
	return strings.Join(usable, ", ")
}

// RenderAddressBook writes the `show security address-book` body
// shared by the local CLI, gRPC ShowText and REST show-text so the
// three surfaces are byte-equal (#16552). Entries render in
// deterministic sorted key order — the only sane shared contract.
func RenderAddressBook(sb *strings.Builder, ab *AddressBook) {
	if ab == nil {
		sb.WriteString("No address book configured\n")
		return
	}
	if len(ab.Addresses) > 0 {
		sb.WriteString("Addresses:\n")
		for _, name := range sortedAddressNames(ab.Addresses) {
			addr := ab.Addresses[name]
			if addr == nil {
				// #7197/#10439/#12903: tolerate present-but-nil
				// slots from lenient restore/peer-sync loads.
				continue
			}
			fmt.Fprintf(sb, "  %-20s %s\n", name, AddressDisplayValue(addr))
		}
	}
	if len(ab.AddressSets) > 0 {
		sb.WriteString("Address sets:\n")
		for _, name := range sortedAddressSetNames(ab.AddressSets) {
			as := ab.AddressSets[name]
			if as == nil {
				continue
			}
			parts := make([]string, 0, len(as.Addresses)+len(as.AddressSets))
			parts = append(parts, as.Addresses...)
			for _, nested := range as.AddressSets {
				parts = append(parts, "set:"+nested)
			}
			fmt.Fprintf(sb, "  %-20s members: %s\n", name, strings.Join(parts, ", "))
		}
	}
}

func sortedAddressNames(m map[string]*Address) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedAddressSetNames(m map[string]*AddressSet) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
