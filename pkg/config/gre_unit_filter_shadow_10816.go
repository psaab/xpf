package config

import (
	"fmt"
	"sort"
	"strings"
)

// #10816 — commit-time advisory for an interface-level GRE tunnel whose
// inheriting units carry different input filters.
//
// MODEL (decided here, pinned in userspace-dp): decap attribution is per
// tunnel DEFINITION, not per unit. The emitter fans one *TunnelConfig out to
// one row per unit, and every row shares one decap identity (source,
// destination, key, transport VRF — #10654 guarantees no second DEFINITION
// shares it, rejecting same-identity per-unit clones). The Rust matcher
// returns the first row in snapshot order (lowest unit number), and the
// inner packet is adjudicated as ingressing on THAT row's logical unit: its
// zone, input filter, and counters. Sibling units are addressing/egress
// constructs; they never receive decap attribution.
//
// WHY ZONES NEED NO ADVISORY HERE: inheriting units share the tunnel's
// kernel device (TunnelNameMap), so cross-zone inheriting units are a
// #7509 contested parent — left UNZONED and DENIED, with #7509's own
// warning. Same-zone attribution is identical whichever row wins. Zones
// are safe; per-unit INPUT FILTERS are not: two inheriting units in one
// zone with different `family inet filter input` names silently police
// everything under the first-sorting unit's filter while the sibling's
// filter never sees a packet. That is what this advisory flags.
//
// SCOPE (narrow by construction):
//   - GRE-kind interface tunnels only (`gre`/`ip6gre`, mirroring the
//     #10654 mode predicate). WireGuard emits one row, never fans out;
//     `ipip` rows are not decap-indexed.
//   - INHERITING units only (unit.Tunnel == nil): units with their own
//     stanza are separate definitions — same-identity clones are already
//     rejected by #10654, distinct ones decap into their own bucket and
//     their filters apply normally.
//   - Input filters only (v4 + v6). Output filters apply at egress by
//     resolution, not by decap row, so they are unaffected. Per-unit
//     host-inbound overrides are the same class but exotic on tunnel
//     units; intentionally not covered.
//   - Bases WITHOUT a #7509 contest only. A contested parent's transit
//     is DENIED, so "policed under unit N's filter" would misdescribe
//     the consequence — #7509 already warns there.
func appendGreUnitFilterShadowAdvisoryLocked(cfg *Config, opts compileOpts) {
	_ = opts
	if cfg == nil || cfg.Interfaces.Interfaces == nil {
		return
	}
	tunnelNames := tunnelNameMapFn(cfg)
	contested := contestedTrunkZonesWithMaps(cfg, InterfaceZoneMap(cfg), tunnelNames)
	bases := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for base := range cfg.Interfaces.Interfaces {
		bases = append(bases, base)
	}
	sort.Strings(bases)
	for _, base := range bases {
		ifc := cfg.Interfaces.Interfaces[base]
		if ifc == nil || ifc.Tunnel == nil {
			continue
		}
		if ifc.Tunnel.Mode != "gre" && ifc.Tunnel.Mode != "ip6gre" {
			continue
		}
		if len(ifc.Units) < 2 {
			continue
		}
		if _, isContested := contested[base]; isContested {
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
		first := ifc.Units[unitNums[0]]
		var shadowed []string
		for _, unitNum := range unitNums[1:] {
			unit := ifc.Units[unitNum]
			if unit.FilterInputV4 != first.FilterInputV4 ||
				unit.FilterInputV6 != first.FilterInputV6 {
				shadowed = append(shadowed, fmt.Sprintf("%s.%d", base, unitNum))
			}
		}
		if len(shadowed) == 0 {
			continue
		}
		cfg.Warnings = append(cfg.Warnings, fmt.Sprintf(
			"interface %s: inheriting GRE units carry different input filters "+
				"but share one decap identity: inbound frames attribute to the "+
				"first-sorting unit row (%s.%d), so the input filter on %s never "+
				"sees a packet (#10816). Use one input filter across the "+
				"inheriting units, or give each filtered unit its own tunnel "+
				"definition with a distinct outer pair or GRE key.",
			base, base, unitNums[0], strings.Join(shadowed, ", ")))
	}
}
