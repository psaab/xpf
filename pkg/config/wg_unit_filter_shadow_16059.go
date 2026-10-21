package config

import (
	"fmt"
	"sort"
	"strings"
)

// #16059 — commit-time advisory for an interface-level WireGuard tunnel
// whose units carry different input/output filters while sharing one
// kernel ifindex.
//
// WG units under an interface-level `tunnel mode wireguard` all resolve
// to the single wgN netdev (TunnelNameMap), so wg0.0/wg0.1 land on one
// ifindex. The Rust filter fast maps are keyed by that ifindex alone, so
// differing per-unit filters would last-win order-dependently and the
// losing filter would never evaluate. Rust now REJECTS such a snapshot
// at build (InterfaceFilterSharedIfindexConflict, #16059); this advisory
// gives the operator the same news at commit time, before the snapshot
// is refused and the prior good state is kept.
//
// SCOPE: interface-level WG only, units WITHOUT their own tunnel stanza
// (per-unit WG stanzas get their own device wgNuN and their own
// ifindex). All four hooks are compared: unlike GRE decap (#10816,
// input-only, first-sorting-wins by design), WG/output has no designed
// winner, so input and output both shadow. A unit that names no filter
// for a hook does not shadow that hook (Rust admits a single claimant);
// the advisory therefore fires only when two DIFFERENT non-empty names
// claim the same family+direction.
func appendWgUnitFilterShadowAdvisory16059Locked(cfg *Config, opts compileOpts) {
	_ = opts
	if cfg == nil || cfg.Interfaces.Interfaces == nil {
		return
	}
	bases := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for base := range cfg.Interfaces.Interfaces {
		bases = append(bases, base)
	}
	sort.Strings(bases)
	type hook struct {
		family, direction string
		get               func(*InterfaceUnit) string
	}
	hooks := []hook{
		{"inet", "input", func(u *InterfaceUnit) string { return u.FilterInputV4 }},
		{"inet", "output", func(u *InterfaceUnit) string { return u.FilterOutputV4 }},
		{"inet6", "input", func(u *InterfaceUnit) string { return u.FilterInputV6 }},
		{"inet6", "output", func(u *InterfaceUnit) string { return u.FilterOutputV6 }},
	}
	for _, base := range bases {
		ifc := cfg.Interfaces.Interfaces[base]
		if ifc == nil || ifc.Tunnel == nil || ifc.Tunnel.Mode != "wireguard" {
			continue
		}
		if len(ifc.Units) < 2 {
			continue
		}
		unitNums := make([]int, 0, len(ifc.Units))
		for unitNum, unit := range ifc.Units {
			if unit == nil || unit.Tunnel != nil {
				continue
			}
			unitNums = append(unitNums, unitNum)
		}
		if len(unitNums) < 2 {
			continue
		}
		sort.Ints(unitNums)
		var conflicts []string
		for _, h := range hooks {
			seen := ""
			seenUnit := 0
			for _, unitNum := range unitNums {
				name := h.get(ifc.Units[unitNum])
				if name == "" {
					continue
				}
				if seen == "" {
					seen, seenUnit = name, unitNum
					continue
				}
				if name != seen {
					conflicts = append(conflicts, fmt.Sprintf(
						"%s %s: %s.%d names %q, %s.%d names %q",
						h.family, h.direction, base, seenUnit, seen, base, unitNum, name))
					break
				}
			}
		}
		if len(conflicts) == 0 {
			continue
		}
		cfg.Warnings = append(cfg.Warnings, fmt.Sprintf(
			"interface %s: units sharing one WireGuard device (one ifindex) "+
				"name different filters (%s) — the dataplane keys interface "+
				"filters by ifindex alone, so only one filter per "+
				"family/direction can apply and the snapshot will be "+
				"refused (#16059). Use one filter per family/direction "+
				"across the units of %s, or give each filtered unit its "+
				"own WireGuard tunnel.",
			base, strings.Join(conflicts, "; "), base))
	}
}
