package config

import (
	"fmt"
	"sort"
)

// validateFirewallPrefixListEntriesStrict rejects a malformed entry inside a
// policy-options prefix-list that a firewall filter term references (#7273).
// The existing reference gate proves only that the list NAME resolves. A
// malformed entry otherwise makes the userspace resolver silently retain the
// parseable subset, narrowing the term's authored address scope. This gate is
// deliberately scoped to lists referenced by inet/inet6 firewall filters;
// routing-only prefix-lists belong to their own consumers and remain outside
// this firewall contract.
func validateFirewallPrefixListEntriesStrict(cfg *Config) error {
	if cfg == nil || cfg.PolicyOptions.PrefixLists == nil {
		return nil
	}

	type ref struct {
		family string
		filter string
		term   string
		leaf   string
	}
	referenced := map[string][]ref{}
	note := func(family string, filters map[string]*FirewallFilter) {
		names := make([]string, 0, len(filters))
		for name := range filters {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			filter := filters[name]
			if filter == nil {
				continue
			}
			for _, term := range filter.Terms {
				if term == nil {
					continue
				}
				for _, r := range term.SourcePrefixLists {
					referenced[r.Name] = append(referenced[r.Name], ref{
						family, name, term.Name, "source-prefix-list",
					})
				}
				for _, r := range term.DestPrefixLists {
					referenced[r.Name] = append(referenced[r.Name], ref{
						family, name, term.Name, "destination-prefix-list",
					})
				}
			}
		}
	}
	note("inet", cfg.Firewall.FiltersInet)
	note("inet6", cfg.Firewall.FiltersInet6)

	listNames := make([]string, 0, len(referenced))
	for name := range referenced {
		listNames = append(listNames, name)
	}
	sort.Strings(listNames)
	for _, listName := range listNames {
		pl := cfg.PolicyOptions.PrefixLists[listName]
		if pl == nil {
			// The unresolved-name gate reports this separately and first.
			continue
		}
		for _, entry := range pl.Prefixes {
			if entry == "" {
				continue
			}
			if _, ok := classifyFilterAddrFamily(entry); ok {
				continue
			}
			r := referenced[listName][0]
			return fmt.Errorf(
				"policy-options prefix-list %q contains malformed entry %q, and firewall "+
					"family %s filter %q term %q references it as %s — the term's address "+
					"scope would silently narrow to the entries that happen to parse "+
					"(use a valid address or CIDR prefix) (#7273)",
				listName, entry, r.family, r.filter, r.term, r.leaf)
		}
	}
	return nil
}
