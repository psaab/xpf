package config

import (
	"fmt"
	"sort"
	"strings"
)

// #16059/#16847 — commit-time advisory for an interface-level WireGuard
// tunnel whose units do not all name the same input/output filter while
// sharing one kernel ifindex.
//
// WG units under an interface-level `tunnel mode wireguard` all resolve
// to the single wgN netdev (TunnelNameMap), so wg0.0/wg0.1 land on one
// ifindex. The Rust filter fast maps are keyed by that ifindex alone.
// #16059 rejected two DIFFERENT non-empty names (silent last-win, the
// loser never evaluates); #16847 extends the refusal to the single-
// claimant shape: a filter on wg0.1 alone would be installed for the
// whole ifindex, so every wg0.0 packet is evaluated by a filter that
// unit never configured (discard/policer/VRF steering misapplied, no
// warning). Rust rejects the snapshot at build
// (InterfaceFilterSharedIfindexConflict, #16059/#16847, an empty name
// rendered `<none>`); this advisory gives the operator the same news at
// commit time, before the snapshot is refused and the prior good state
// is kept.
//
// SCOPE: interface-level WG only, units WITHOUT their own tunnel stanza
// (per-unit WG stanzas get their own device wgNuN and their own
// ifindex). All four hooks are compared: unlike GRE decap (#10816,
// input-only, first-sorting-wins by design), WG/output has no designed
// winner, so input and output both shadow. A hook is disputed whenever
// the counted units do not all name the same filter, counting an empty
// name as a claim that the unit is unfiltered — so a single claimant
// fires (one filtered unit + one unfiltered sibling), while uniform
// names and both-unfiltered hooks stay silent.
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
		if ifc == nil || ifc.Tunnel == nil || ifc.Tunnel.Mode != TunnelModeWireGuard {
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
			// #16847: an empty name counts as a claim ("this unit is
			// unfiltered"), rendered <none>; the hook is disputed when
			// the counted units do not all agree.
			render := func(name string) string {
				if name == "" {
					return "<none>"
				}
				return name
			}
			firstName := h.get(ifc.Units[unitNums[0]])
			for _, unitNum := range unitNums[1:] {
				name := h.get(ifc.Units[unitNum])
				if name != firstName {
					conflicts = append(conflicts, fmt.Sprintf(
						"%s %s: %s.%d names %q, %s.%d names %q",
						h.family, h.direction, base, unitNums[0], render(firstName), base, unitNum, render(name)))
					break
				}
			}
		}
		if len(conflicts) == 0 {
			continue
		}
		cfg.Warnings = append(cfg.Warnings, fmt.Sprintf(
			"interface %s: units sharing one WireGuard device (one ifindex) "+
				"do not all name the same filter (%s) — the dataplane keys "+
				"interface filters by ifindex alone, so one filter per "+
				"family/direction would apply to every unit on the device "+
				"(a unit naming no filter would still be filtered) and the "+
				"snapshot will be refused (#16059/#16847). Name the same "+
				"filter per family/direction on every unit of %s, or give "+
				"each filtered unit its own WireGuard tunnel.",
			base, strings.Join(conflicts, "; "), base))
	}
}
