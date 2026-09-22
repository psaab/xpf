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
// genuinely contested parent ifindex UNZONED rather than adjudicating a packet
// against whichever sibling unit was walked first (`forwarding_build/interfaces.rs`).
// That makes the failure SAFE — transit is DENIED as unattributed (#6682
// refuses it before the implicit default policy) instead of being policed
// under a zone the operator never wrote for it. Host-bound handling is scoped
// below: a genuine non-lifeline contest uses #10503; an unzoned addressed /
// unzoned tunnel refusal uses #5659; narrow lifelines and shapes with no
// sentinel remain admitted; prefix-only / lo0 names are zone-gated (neither
// sentinel arms there, and kernel lifeline exclusion does not apply). An
// all-zoned tunnel Disagree admits with neither sentinel.
// It does not make the consequence LEGIBLE: an operator whose untagged trunk
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
// different zones and whose raw parent is not disambiguated by a collapsed,
// zoned native unit 0. Only traffic that resolves to the RAW PARENT is affected
// — a tagged frame resolves to its own logical unit ifindex first (#3021) — so
// in practice this is untagged traffic on a mixed-zone trunk.
//
// WHAT WOULD INVALIDATE IT (#4308): `native-vlan-id` is accepted-only and not
// enforced today, so untagged frames have no defined unit. If #4308 is ever
// implemented they acquire one, and this advisory becomes wrong for the native
// VLAN specifically while staying right for every other contested case.

// nativeUnitZeroDisambiguatesParent reports whether native unit 0 resolves to
// the base device and is zoned there. Its zone is the raw parent identity, so
// sibling units on their own devices cannot make that parent a contested ifindex.
func nativeUnitZeroDisambiguatesParent(
	cfg *Config,
	base string,
	zoneByIface map[string]string,
	tunnelNames map[string]string,
) bool {
	if cfg == nil || cfg.Interfaces.Interfaces == nil {
		return false
	}
	ifc := cfg.Interfaces.Interfaces[base]
	if ifc == nil || ifc.Tunnel != nil {
		return false
	}
	unit := ifc.Units[0]
	if unit == nil || unit.VlanID != 0 {
		return false
	}
	unitRef := fmt.Sprintf("%s.0", base)
	return zoneByIface[unitRef] != "" &&
		snapshotUnitDevice(cfg, unitRef, tunnelNames) ==
			cfg.resolveKernelIfNameWith(base, tunnelNames)
}

// snapshotUnitDevice follows the userspace snapshot's unit-device precedence:
// secure-tunnel ownership wins, then TunnelNameMap owns emitted unit
// references, while the canonical resolver is the fallback for references
// without an explicit tunnel-device mapping.
func snapshotUnitDevice(
	cfg *Config,
	name string,
	tunnelNames map[string]string,
) string {
	if device, ok := cfg.SecureTunnelUnitNetdev(name); ok {
		return device
	}
	if device := tunnelNames[name]; device != "" {
		return device
	}
	return cfg.resolveKernelIfNameWith(name, tunnelNames)
}

// interfaceUnitCollapsesOnBase reports whether a unit reference resolves to
// the same kernel device as the interface-level tunnel. Per-unit tunnel stanzas
// usually own their own device, but unit 0 can deliberately anchor to the base
// device; compare the canonical resolver answers rather than the stanza shape.
func interfaceUnitCollapsesOnBase(
	cfg *Config,
	base string,
	name string,
	tunnelNames map[string]string,
) bool {
	if cfg == nil || cfg.Interfaces.Interfaces == nil {
		return true
	}
	ifc := cfg.Interfaces.Interfaces[base]
	if ifc == nil || ifc.Tunnel == nil {
		return true
	}
	return snapshotUnitDevice(cfg, name, tunnelNames) ==
		cfg.resolveKernelIfNameWith(base, tunnelNames)
}

// userspaceHostInboundLifeline is the config-aware host-inbound lifeline
// selector. Keep this narrow: the broad AF_XDP bind exclusions are not all
// unconditional host-inbound admits.
func userspaceHostInboundLifeline(cfg *Config, name string) bool {
	return HostInboundLifelineInterface(name, HostInboundLifelineSet(cfg))
}

// userspaceHostInboundZoneGated identifies names excluded from the AF_XDP bind
// path that are not canonical/configured host-inbound lifelines. Their
// host-bound traffic remains subject to the applicable zone policy; neither
// warning site may describe them as a sentinel deny or unconditional admit.
func userspaceHostInboundZoneGated(cfg *Config, name string) bool {
	if userspaceHostInboundLifeline(cfg, name) {
		return false
	}
	base := LifelineBaseName(name)
	return strings.HasPrefix(base, "fxp") ||
		strings.HasPrefix(base, "em") ||
		strings.HasPrefix(base, "fab") ||
		base == "lo0"
}

func zoneGatedHostBoundAdvisory() string {
	return "Host-bound traffic on this AF_XDP bind-excluded interface is " +
		"zone-gated by applicable zone policy; the name is excluded from " +
		"userspace binding, but it is neither an unconditional lifeline admit " +
		"nor a host-inbound sentinel deny. "
}

func sharedUnitIsAddressedOrTunnel(
	cfg *Config,
	base string,
	names []string,
) bool {
	if cfg == nil || cfg.Interfaces.Interfaces == nil {
		return false
	}
	ifc := cfg.Interfaces.Interfaces[base]
	if ifc == nil {
		return false
	}
	for _, name := range names {
		for num, unit := range ifc.Units {
			if fmt.Sprintf("%s.%d", base, num) != name {
				continue
			}
			if ifc.Tunnel != nil || (unit != nil && len(unit.Addresses) > 0) {
				return true
			}
		}
	}
	return false
}

func sharedDeviceHostBoundAdvisory(
	cfg *Config,
	base string,
	shared map[string][]string,
) string {
	if userspaceHostInboundZoneGated(cfg, base) {
		return zoneGatedHostBoundAdvisory()
	}
	if userspaceHostInboundLifeline(cfg, base) {
		return "Host-bound traffic on this lifeline remains admitted; #5659 " +
			"deliberately does not arm an empty-zone host-inbound sentinel. "
	}
	if sharedUnitIsAddressedOrTunnel(cfg, base, shared[base]) {
		return "Host-bound traffic to the firewall itself is denied by the #5659 " +
			"empty-zone host-inbound sentinel when local-target/tunnel exposure " +
			"arms that path (ICMP errors/PMTUD/ND control messages remain admitted; " +
			"an explicit per-interface host-inbound stanza still takes precedence). "
	}
	return "Host-bound traffic remains admitted via the global None => true " +
		"host-inbound path because this address-less non-tunnel refusal has no " +
		"#5659 sentinel. "
}

func interfaceTunnelHasCollapsedUnits(
	cfg *Config,
	base string,
	tunnelNames map[string]string,
) bool {
	if cfg == nil || cfg.Interfaces.Interfaces == nil {
		return false
	}
	ifc := cfg.Interfaces.Interfaces[base]
	if ifc == nil || ifc.Tunnel == nil || len(ifc.Units) == 0 {
		return false
	}
	baseDevice := cfg.resolveKernelIfNameWith(base, tunnelNames)
	for num, unit := range ifc.Units {
		if unit == nil {
			continue
		}
		unitRef := fmt.Sprintf("%s.%d", base, num)
		if snapshotUnitDevice(cfg, unitRef, tunnelNames) == baseDevice {
			return true
		}
	}
	return false
}

func contestedHostBoundAdvisory(
	cfg *Config,
	base string,
	shared map[string][]string,
	tunnelNames map[string]string,
) string {
	if len(shared[base]) != 0 {
		return sharedDeviceHostBoundAdvisory(cfg, base, shared)
	}
	if userspaceHostInboundZoneGated(cfg, base) {
		return zoneGatedHostBoundAdvisory()
	}
	lifeline := userspaceHostInboundLifeline(cfg, base)
	if interfaceTunnelHasCollapsedUnits(cfg, base, tunnelNames) {
		return "Host-bound traffic remains admitted: all collapsed tunnel " +
			"units are zoned, so neither the #5659 empty-zone sentinel nor " +
			"the #10503 contested-parent sentinel applies. "
	}
	if lifeline {
		return "Host-bound traffic on this lifeline remains admitted; #10503 " +
			"deliberately does not arm a contested-parent sentinel. "
	}
	return "Host-bound traffic to the firewall itself is denied by the " +
		"contested-parent host-inbound sentinel (#10503; ICMP errors/PMTUD/ND " +
		"control messages remain admitted; an explicit per-interface host-inbound " +
		"stanza still takes precedence). "
}


// contestedTrunkZones returns, per base interface, the sorted distinct zones its
// COLLAPSED UNITS are bound to — only for bases whose collapsed units span MORE
// THAN ONE zone and whose raw parent is not disambiguated by a zoned native unit
// 0. A per-unit tunnel stanza resolving to a distinct device is not part of this
// set; a unit stanza that resolves to the base device remains part of it.
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
	return contestedTrunkZonesWithMaps(cfg, zoneByIface, tunnelNameMapFn(cfg))
}

func contestedTrunkZonesWithMaps(
	cfg *Config,
	zoneByIface map[string]string,
	tunnelNames map[string]string,
) map[string][]string {
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
		if !interfaceUnitCollapsesOnBase(cfg, base, iface, tunnelNames) {
			continue
		}
		if byBase[base] == nil {
			byBase[base] = map[string]struct{}{}
		}
		byBase[base][zone] = struct{}{}
	}
	var out map[string][]string
	for base, zones := range byBase {
		if len(zones) < 2 || nativeUnitZeroDisambiguatesParent(cfg, base, zoneByIface, tunnelNames) {
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
// unit that actually receives frames on the device was never zoned. Transit is
// denied as unattributed before any policy is consulted (#6682) only when the
// resulting ingress is fully unzoned; a retained unit zone is policy-evaluated.
// Host-bound handling is shape-dependent: addressed/tunnel traffic follows the
// #5659 empty-zone host-inbound path when local-target/tunnel exposure arms it,
// address-less non-tunnel traffic remains on the global `None => true` admit
// path, and retained-zone traffic is zone-gated. ICMP errors/PMTUD/ND control
// messages remain admitted, and an explicit per-interface host-inbound stanza
// takes precedence.
//
// SCOPED TO THE UNITS THAT ACTUALLY COLLAPSE, which is the difference between
// this and a restatement of the contest above. A unit on its OWN device is
// adjudicated per unit and is unaffected; warning about it would describe a
// consequence that does not happen. Device identity follows the snapshot's
// secure-tunnel, TunnelNameMap, and canonical fallback precedence:
//   - a native unit 0 whose effective device is the bare interface; and
//   - an interface-level tunnel unit whose effective device is that tunnel.
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
	return sharedDeviceUnzonedUnitsWithMaps(cfg, zoneByIface, tunnelNameMapFn(cfg))
}

func sharedDeviceUnzonedUnitsWithMaps(
	cfg *Config,
	zoneByIface map[string]string,
	tunnelNames map[string]string,
) map[string][]string {
	if cfg == nil || len(cfg.Interfaces.Interfaces) == 0 || len(zoneByIface) == 0 {
		return nil
	}
	var out map[string][]string
	for name, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil || len(ifc.Units) < 2 {
			// One unit cannot disagree with a sibling, and a base with no units
			// has nothing that collapses onto it.
			continue
		}
		baseDevice := cfg.resolveKernelIfNameWith(name, tunnelNames)
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
			sharesDevice := snapshotUnitDevice(cfg, unitName, tunnelNames) == baseDevice
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
		hostBound := sharedDeviceHostBoundAdvisory(cfg, base, shared)
		cfg.Warnings = append(cfg.Warnings, fmt.Sprintf(
			"interface %s has unit(s) %s in no security zone sharing one kernel "+
				"device with %s, whose other units ARE zoned: the dataplane sees the "+
				"device, not the unit, so it declines to adjudicate that traffic under "+
				"a sibling unit's zone and leaves it UNZONED (#7509). Transit arriving "+
				"there is DENIED as unattributed — #6682 refuses it before the implicit "+
				"default policy is consulted, default-policy permit-all does not admit "+
				"it, and the deny logs as unattributed (#9989, counter "+
				"UNZONED_INGRESS_DENIED); %sPut those units in a zone if their "+
				"traffic must be forwarded.",
			base, strings.Join(shared[base], ", "), base, hostBound))
	}
}

// A WARNING, never an error. A mixed-zone ordinary trunk is a legitimate
// configuration — its TAGGED traffic is adjudicated per unit and is unaffected
// — so rejecting it would outlaw a working config to describe a narrow
// consequence. Interface-level tunnels use a separate complete sentence below:
// units whose resolved kernel device matches the base collapse onto one netdev,
// while independent per-unit devices remain separate. We are declining to
// guess for one traffic class, not forbidding either shape.
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
	zoneByIface := InterfaceZoneMap(cfg)
	if len(zoneByIface) == 0 {
		return
	}
	tunnelNames := tunnelNameMapFn(cfg)
	contested := contestedTrunkZonesWithMaps(cfg, zoneByIface, tunnelNames)
	if len(contested) == 0 {
		return
	}
	bases := make([]string, 0, len(contested))
	for base := range contested {
		bases = append(bases, base)
	}
	sort.Strings(bases)
	shared := sharedDeviceUnzonedUnitsWithMaps(cfg, zoneByIface, tunnelNames)
	for _, base := range bases {
		hostBound := contestedHostBoundAdvisory(cfg, base, shared, tunnelNames)
		if interfaceTunnelHasCollapsedUnits(cfg, base, tunnelNames) {
			cfg.Warnings = append(cfg.Warnings, fmt.Sprintf(
				"interface %s has units in more than one security zone (%s): this "+
					"interface-level tunnel maps units whose resolved kernel device "+
					"matches its base onto one netdev; units whose resolved kernel "+
					"device differs remain independent, so transit cannot be "+
					"attributed to a unit where it collapses and remains UNZONED "+
					"(#7509). Transit arriving "+
					"there is DENIED as unattributed — #6682 refuses it before the "+
					"implicit default policy is consulted, default-policy permit-all "+
					"does not admit it, and the deny logs as unattributed (#9989, "+
					"counter UNZONED_INGRESS_DENIED); %sConfigure per-unit tunnel "+
					"devices or one consistent zone if this traffic must be forwarded.",
				base, strings.Join(contested[base], ", "), hostBound))
			continue
		}
		cfg.Warnings = append(cfg.Warnings, fmt.Sprintf(
			"interface %s has units in more than one security zone (%s): UNTAGGED "+
				"traffic arriving on %s cannot be attributed to a unit, so it is left "+
				"UNZONED (#7509). Transit arriving there is DENIED as unattributed — "+
				"#6682 refuses it before the implicit default policy is consulted, "+
				"default-policy permit-all does not admit it, and the deny logs as "+
				"unattributed (#9989, counter UNZONED_INGRESS_DENIED); %sTagged "+
				"traffic on each unit is unaffected. Give the units distinct "+
				"devices, or put them in one zone, if untagged traffic on %s must be "+
				"forwarded.",
			base, strings.Join(contested[base], ", "), base, hostBound, base))
	}
}
