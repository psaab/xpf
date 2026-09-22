package config

import (
	"fmt"
	"sort"
	"strings"
)

// #7509 — commit-time advisory for a parent interface whose UNITS span
// different security zones.
//
// WHY THIS EXISTS AS WELL AS THE DATAPLANE CHANGE. The dataplane now leaves a
// contested parent ifindex UNZONED rather than adjudicating a packet against
// whichever sibling unit was walked first (`forwarding_build/interfaces.rs`).
// That makes the failure SAFE — transit is DENIED as unattributed (#6682
// refuses it before the implicit default policy) instead of being policed
// under a zone the operator never wrote for it, and host-bound traffic to the
// firewall itself is denied by the contested-parent host-inbound sentinel
// (#10503). It does not make it LEGIBLE: an operator whose untagged trunk
// traffic starts being denied has no way to reach "these units share a base
// netdev and disagree about their zone" without reading source. That is the
// #8296 shape, where a config committed clean, rendered back verbatim, and
// reached no consumer while traffic died with nothing in the logs.
//
// The dataplane also only knows an IFINDEX. It cannot name `ge-0/0/0.100`, and
// "contested ifindex 42" is not something an operator can act on. The config
// compiler has the names, and it has them BEFORE the config is deployed — so
// the operator learns at commit rather than after traffic changes behaviour.
//
// SCOPE, wider than #7509's own framing. The issue describes interface-level
// TUNNEL units sharing one netdev. The condition is any parent whose units span
// different zones, which includes an ordinary VLAN trunk. Only traffic that
// resolves to the RAW PARENT is affected — a tagged frame resolves to its own
// logical unit ifindex first (#3021) — so in practice this is untagged traffic
// on a mixed-zone trunk.
//
// WHAT WOULD INVALIDATE IT (#4308): `native-vlan-id` is accepted-only and not
// enforced today, so untagged frames have no defined unit. If #4308 is ever
// implemented they acquire one, and this advisory becomes wrong for the native
// VLAN specifically while staying right for every other contested case.

// contestedTrunkZones returns, per base interface, the sorted distinct zones its
// UNITS are bound to — only for bases whose units span MORE THAN ONE zone.
//
// Keyed off `InterfaceZoneMap` rather than walking zones directly so this and
// the snapshot builder answer from the same source. That map already canonicalises
// unit refs (#5878), so `ge-0/0/0.01` and `ge-0/0/0.1` are one unit here, not two
// units that appear to disagree.
func contestedTrunkZones(cfg *Config) map[string][]string {
	zoneByIface := InterfaceZoneMap(cfg)
	if len(zoneByIface) == 0 {
		return nil
	}
	// base -> set of zones its units name. UNIT keys only: the base's own entry
	// in InterfaceZoneMap is the inherited fan-UP value (first unit wins), which
	// is the very guess this change removes — counting it would let a base
	// "agree" with whichever unit happened to be first.
	byBase := map[string]map[string]struct{}{}
	for iface, zone := range zoneByIface {
		if zone == "" {
			continue
		}
		// #9821 D17: group by the SPLIT base, and skip exact-declared bare
		// keys — the function's own base-key exclusion invariant above,
		// violated once fan-down adds a declared dotted bare (`p.0`) that
		// first-dot-cut would file as a "unit" of `p`. Without this, two
		// trunks sharing a first segment false-contest.
		s := cfg.SplitInterfaceUnitRef(iface)
		if !s.HasUnit || s.Base == "" {
			continue
		}
		base := s.Base
		if byBase[base] == nil {
			byBase[base] = map[string]struct{}{}
		}
		byBase[base][zone] = struct{}{}
	}
	var out map[string][]string
	for base, zones := range byBase {
		if len(zones) < 2 {
			continue
		}
		names := make([]string, 0, len(zones))
		for z := range zones {
			names = append(names, z)
		}
		sort.Strings(names)
		if out == nil {
			out = map[string][]string{}
		}
		out[base] = names
	}
	return out
}

// sharedDeviceUnzonedUnits returns, per base interface, the sorted names of the
// units that SHARE the base's kernel device and are in NO security zone, but
// only for bases some OTHER unit of which IS zoned (#7509, the zoned-vs-UNZONED
// half).
//
// The dataplane refuses to attribute a zone to a device whose logical unit was
// left out of every zone, even when the base interface's row carries a zone —
// because that zone was INHERITED from a sibling unit on another device
// (`InterfaceZoneMap` fans a unit-suffixed reference UP to the base) and the
// unit that actually receives frames on the device was never zoned. Transit
// there is DENIED as unattributed before any policy is consulted (#6682), and
// host-bound traffic to the firewall itself is denied by the contested-parent
// host-inbound sentinel (#10503).
//
// SCOPED TO THE UNITS THAT ACTUALLY COLLAPSE, which is the difference between
// this and a restatement of the contest above. A unit on its OWN device is
// adjudicated per unit and is unaffected; warning about it would describe a
// consequence that does not happen. Two units collapse onto the base device:
//
//   - unit 0 with no vlan-id — `snapshotLinuxName`'s non-VLAN unit-0 fold; and
//   - every unit of an INTERFACE-level tunnel with no per-unit tunnel stanza —
//     `TunnelNameMap` maps them all onto the tunnel device.
//
// Both conditions are read off the config here rather than from the snapshot
// builder, which lives in a package that imports this one. The pairing is
// pinned from the other side: the userspace-dp fixtures are measured against
// the real builders in pkg/dataplane/userspace/zone_unit_provenance_7509_test.go.
func sharedDeviceUnzonedUnits(cfg *Config) map[string][]string {
	if cfg == nil || len(cfg.Interfaces.Interfaces) == 0 {
		return nil
	}
	zoneByIface := InterfaceZoneMap(cfg)
	if len(zoneByIface) == 0 {
		return nil
	}
	var out map[string][]string
	for name, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil || len(ifc.Units) < 2 {
			// One unit cannot disagree with a sibling, and a base with no units
			// has nothing that collapses onto it.
			continue
		}
		zoned, unzonedShared := false, []string(nil)
		for num, unit := range ifc.Units {
			if unit == nil {
				continue
			}
			unitName := fmt.Sprintf("%s.%d", name, num)
			if zoneByIface[unitName] != "" {
				zoned = true
				continue
			}
			sharesDevice := (num == 0 && unit.VlanID == 0) ||
				(ifc.Tunnel != nil && unit.Tunnel == nil)
			if sharesDevice {
				unzonedShared = append(unzonedShared, unitName)
			}
		}
		if !zoned || len(unzonedShared) == 0 {
			continue
		}
		sort.Strings(unzonedShared)
		if out == nil {
			out = map[string][]string{}
		}
		out[name] = unzonedShared
	}
	return out
}

// appendSharedDeviceUnzonedUnitAdvisoryLocked adds one advisory per base whose
// device-sharing unit is unzoned while a sibling unit is zoned.
//
// A WARNING, never an error, for the same reason as the contest advisory: the
// configuration is legitimate — leaving a unit out of every zone is a statement
// the operator is entitled to make, and this describes what the dataplane does
// with it rather than forbidding it.
func appendSharedDeviceUnzonedUnitAdvisoryLocked(cfg *Config, opts compileOpts) {
	if cfg == nil || opts.suppressContestedTrunkZoneAdvisory {
		return
	}
	shared := sharedDeviceUnzonedUnits(cfg)
	if len(shared) == 0 {
		return
	}
	bases := make([]string, 0, len(shared))
	for base := range shared {
		bases = append(bases, base)
	}
	sort.Strings(bases)
	for _, base := range bases {
		cfg.Warnings = append(cfg.Warnings, fmt.Sprintf(
			"interface %s has unit(s) %s in no security zone sharing one kernel "+
				"device with %s, whose other units ARE zoned: the dataplane sees the "+
				"device, not the unit, so it declines to adjudicate that traffic under "+
				"a sibling unit's zone and leaves it UNZONED (#7509). Transit arriving "+
				"there is DENIED as unattributed — #6682 refuses it before the implicit "+
				"default policy is consulted, default-policy permit-all does not admit "+
				"it, and the deny logs as unattributed (#9989, counter "+
				"UNZONED_INGRESS_DENIED); host-bound traffic to the firewall itself is "+
				"denied by the contested-parent host-inbound sentinel (#10503; ICMP "+
				"errors/PMTUD/ND control messages remain admitted; an explicit "+
				"per-interface host-inbound stanza still takes precedence). Put those "+
				"units in a zone if their traffic must be forwarded.",
			base, strings.Join(shared[base], ", "), base))
	}
}

// appendContestedTrunkZoneAdvisoryLocked adds one advisory per contested base.
//
// A WARNING, never an error. A mixed-zone trunk is a legitimate configuration —
// its TAGGED traffic is adjudicated per unit and is unaffected — so rejecting it
// would outlaw a working config to describe a narrow consequence. We are
// declining to guess for one traffic class, not forbidding the shape.
//
// `opts.suppressContestedTrunkZoneAdvisory` silences it on the TOLERANT paths,
// which back `Store.Load` (persisted-config boot) and `Store.SyncApply` (HA peer
// sync). Without that it would fire on every boot and every peer sync of a
// config committed long ago, and an advisory an operator sees on every boot for
// a decision already made is one they learn to skip.
func appendContestedTrunkZoneAdvisoryLocked(cfg *Config, opts compileOpts) {
	if cfg == nil || opts.suppressContestedTrunkZoneAdvisory {
		return
	}
	contested := contestedTrunkZones(cfg)
	if len(contested) == 0 {
		return
	}
	bases := make([]string, 0, len(contested))
	for base := range contested {
		bases = append(bases, base)
	}
	sort.Strings(bases)
	for _, base := range bases {
		cfg.Warnings = append(cfg.Warnings, fmt.Sprintf(
			"interface %s has units in more than one security zone (%s): UNTAGGED "+
				"traffic arriving on %s cannot be attributed to a unit, so it is left "+
				"UNZONED (#7509). Transit arriving there is DENIED as unattributed — "+
				"#6682 refuses it before the implicit default policy is consulted, "+
				"default-policy permit-all does not admit it, and the deny logs as "+
				"unattributed (#9989, counter UNZONED_INGRESS_DENIED); host-bound "+
				"traffic to the firewall itself is denied by the contested-parent "+
				"host-inbound sentinel (#10503; ICMP errors/PMTUD/ND control messages "+
				"remain admitted; an explicit per-interface host-inbound stanza still "+
				"takes precedence). Tagged traffic on each unit is unaffected. Give "+
				"the units distinct devices, or put them in one zone, if untagged "+
				"traffic on %s must be forwarded.",
			base, strings.Join(contested[base], ", "), base, base))
	}
}
