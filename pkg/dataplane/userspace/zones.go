package userspace

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// The host-inbound LIFELINE matcher is the SSOT in pkg/config (lifeline.go,
// #3682) so the shared host-inbound presenter can render the exemption on the
// operator-visible zone views. These thin wrappers keep the dataplane call sites
// and #3277 tests reading against the local names while the matching logic
// (fxp0 + configured control/fabric roles; no bare-name defaults) lives in
// exactly one place shared with display.

func hostInboundLifelineSet(cfg *config.Config) map[string]bool {
	return config.HostInboundLifelineSet(cfg)
}

func hostInboundLifelineInterface(name string, lifelines map[string]bool) bool {
	return config.HostInboundLifelineInterface(name, lifelines)
}

// hostIPFromCIDR returns the bare host IP of a "ip/prefix" string (or a bare
// IP). Returns "" if unparseable.
func hostIPFromCIDR(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if ip, _, err := net.ParseCIDR(s); err == nil && ip != nil {
		return ip.String()
	}
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	return ""
}

// authoredZoneRefs returns the operator's LITERAL `security-zone <z> interfaces
// <ref>` bindings, expanded to every logical identity the reference SPEAKS FOR
// but never to one it does not (#6722):
//
//   - canonicalised through CanonicalInterfaceUnitRef, so ".01" and ".1" agree
//     with the snapshot's unit naming;
//   - a BARE interface reference is fanned DOWN onto that interface's
//     configured units, or its bound IPsec units when no interface stanza
//     exists. In xpf `security-zone lan interfaces ge-0/0/1` MEANS "every unit
//     of ge-0/0/1 is in lan" — the rule buildInterfaceZoneMap also enforces.
//     A collision-vetoed IPsec unit is not claimed on tolerant loads;
//   - a unit-suffixed reference is NOT fanned UP to its base. That is the
//     direction that manufactures a claim about a DIFFERENT identity: `st0.1`
//     names one unit, and writing `st0` from it says something about `st0.0`
//     (which shares the base netdev) that the operator never said.
//
// It is the PROVENANCE half of buildInterfaceZoneMap. That map derives in BOTH
// directions; only the fan-UP is a restatement of a sentence about another
// identity, and once several config identities collapse onto ONE netdev
// (`snapshotLinuxName`) such a derived entry becomes indistinguishable from an
// authored one by inspection of the result alone. stampEgressZones (the sole
// consumer of this map, in interfaces.go) needs to tell them apart, so the
// provenance is recorded here rather than
// reconstructed downstream from the outcome. Reconstructing it is exactly what
// #6722 attempted four times, and each attempt was holed by a new config shape.
//
// FAIL-ON-REVERT for the fan-down: drop it and
// TestBareInterfaceZoneRefReachesItsOwnNetdevUnits_6722 goes RED. Without it a
// unit that lands on its OWN netdev (any VLAN unit; any non-zero unit) is
// reached by NEITHER rule 2 — no authored reference names its row — NOR rule 3,
// which is skipped precisely because a unit row IS on that ifindex. The ifindex
// resolves no egress zone at all while its rows carry the operator's zone, so
// the INGRESS half attributes traffic to `lan` and the EGRESS half answers the 0
// sentinel: every transit flow out of a bare-referenced trunk's VLAN units falls
// to the default policy. origin/master answered the operator's zone there.
//
// The maps share the same logical-key expansion, but ambiguous keys are
// omitted from both rather than silently choosing the first sorted zone.
func authoredZoneRefs(cfg *config.Config) map[string]string {
	if cfg == nil || len(cfg.Security.Zones) == 0 {
		return nil
	}
	out := make(map[string]string, len(cfg.Security.Zones))
	zoneNames := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		zoneNames = append(zoneNames, name)
	}
	sort.Strings(zoneNames)
	excludedZones := config.ZoneQuarantineExclusionsForConfig(cfg)
	conflictedInterfaces := config.QuarantinedZoneInterfaceKeys(cfg)
	for _, zoneName := range zoneNames {
		if _, excluded := excludedZones[zoneName]; excluded {
			continue
		}
		zone := cfg.Security.Zones[zoneName]
		if zone == nil {
			continue
		}
		for _, rawIface := range zone.Interfaces {
			if rawIface == "" {
				continue
			}
			// Share the zone binder's declared-first canonicalization and bare
			// fan-down, including bind-interface-only secure-tunnel units.
			// Unit refs never fan up into a separately named base device.
			for _, key := range config.InterfaceUnitRefKeys(cfg, rawIface) {
				if _, conflicted := conflictedInterfaces[key]; conflicted {
					continue
				}
				if _, exists := out[key]; !exists {
					out[key] = zoneName
				}
			}
		}
	}
	return out
}

// quarantinedZoneNames returns the zone names excluded from dataplane install.
// It uses the compiler's runtime zone-name set (config.ZoneQuarantineNamesForConfig).
func quarantinedZoneNames(cfg *config.Config) map[string]struct{} {
	return config.ZoneQuarantineExclusionsForConfig(cfg)
}

func buildInterfaceZoneMap(cfg *config.Config) map[string]string {
	// #6640: the resolution itself lives in pkg/config so the commit-time
	// advisories can reason about the SAME object this builder enforces. See
	// config.InterfaceZoneMap for the fan-up/fan-down rules and the #5878
	// canonicalisation.
	return config.InterfaceZoneMap(cfg)
}

// wgFanUpBaseRows identifies snapshot BASE rows whose Zone exists only because
// InterfaceZoneMap fanned a unit reference up to its physical parent. The WG
// mapper needs this provenance to avoid treating that derived label as a
// direct untagged owner or address owner.
func wgFanUpBaseRows(cfg *config.Config) map[string]bool {
	if cfg == nil {
		return nil
	}
	zones := buildInterfaceZoneMap(cfg)
	if len(zones) == 0 {
		return nil
	}
	authored := authoredZoneRefs(cfg)
	rows := make(map[string]bool)
	for name := range cfg.Interfaces.Interfaces {
		if zones[name] != "" && authored[name] == "" {
			rows[name] = true
		}
	}
	return rows
}

// hostInboundUnzonedFanUpBaseRows identifies physical snapshot rows whose
// zone is derived solely from tagged unit membership and whose netdev is not
// also owned by an untagged unit. Such a row describes untagged parent traffic,
// not the tagged unit's zone.
func hostInboundUnzonedFanUpBaseRows(cfg *config.Config, snaps []InterfaceSnapshot) map[string]bool {
	fanUp := wgFanUpBaseRows(cfg)
	if len(fanUp) == 0 {
		return nil
	}
	untaggedNetdevs := make(map[string]bool)
	for _, snap := range snaps {
		if snap.IsUnit && snap.VLANID == 0 && snap.LinuxName != "" {
			untaggedNetdevs[snap.LinuxName] = true
		}
	}
	nativeUnits := nativeVLANUnitRefs(cfg)
	rows := make(map[string]bool)
	for _, snap := range snaps {
		if snap.IsUnit || !fanUp[snap.Name] {
			continue
		}
		// An explicitly configured unit 0 can intentionally own the parent
		// identity even when VLAN-tagged. Preserve that established address
		// attribution; this predicate is for fan-up caused by nonzero units.
		if ifc := cfg.Interfaces.Interfaces[snap.Name]; ifc != nil && ifc.Units[0] != nil {
			continue
		}
		if nativeUnits[snap.Name] != "" {
			continue
		}
		if !untaggedNetdevs[snap.LinuxName] {
			rows[snap.Name] = true
		}
	}
	return rows
}

// nativeVLANUnitRefs returns base-interface refs whose configured native VLAN
// resolves to exactly one valid unit. Unresolved and ambiguous native VLANs
// deliberately have no entry: their untagged parent traffic remains unzoned.
func nativeVLANUnitRefs(cfg *config.Config) map[string]string {
	if cfg == nil {
		return nil
	}
	refs := make(map[string]string)
	for name, iface := range cfg.Interfaces.Interfaces {
		if iface == nil || iface.NativeVlanID <= 0 || iface.NativeVlanID > 4094 {
			continue
		}
		matches := 0
		var unitRef string
		for unitNum, unit := range iface.Units {
			if unit == nil || unit.VlanID != iface.NativeVlanID {
				continue
			}
			matches++
			unitRef = fmt.Sprintf("%s.%d", name, unitNum)
		}
		if matches == 1 {
			refs[name] = unitRef
		}
	}
	return refs
}
