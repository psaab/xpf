package config

import (
	"fmt"
	"sort"
)

// sshUnmanagedAdvisory16737 is the commit-time advisory for a zone whose
// host-inbound-traffic admits SSH while no `system services ssh` stanza
// exists (#16737, R3-A45-03).
//
// Removing the stanza does NOT stop sshd: applySSHConfig removes only the
// xpf-managed drop-in, so sshd reverts to the base-image defaults and keeps
// serving (pkg/daemon/README.md: the factory drop-in applies whether or
// not the stanza is configured). A Junos-trained operator who deletes the
// stanza to decommission SSH therefore keeps tcp/22 reachable on every
// zone admitting `ssh`, `all` (which expands to the named-service union
// including ssh, #3226), or `any-service`, with no signal. This advisory
// is that signal at commit; `show system services` states the same fact
// continuously. To actually stop SSH, remove the host-inbound admission
// (or stop/disable sshd outside xpf, which does not own the unit).
const sshUnmanagedAdvisory16737 = "no `system services ssh` stanza is configured, but security zone %q " +
	"host-inbound-traffic admits SSH (tcp/22): xpf does not own sshd enablement, so removing the stanza " +
	"only removes the xpf-managed sshd drop-in and sshd keeps serving under base-image defaults. " +
	"To stop SSH from this zone, remove the ssh/all/any-service host-inbound admission; " +
	"to manage sshd hardening, configure `system services ssh` (#16737)"

// appendSSHUnmanagedAdvisory16737Locked adds the #16737 advisory once per
// zone with an effective SSH-admitting host-inbound set when no
// `system services ssh` stanza exists.
//
// Suppressed on the tolerant paths (Store.Load / Store.SyncApply) via
// opts.suppressSSHUnmanagedAdvisory16737, for the same reason as the
// #8357 cluster/NTP advisory: the condition is a property of an
// already-committed config, so firing on every boot and peer sync would
// train operators to ignore it. It belongs where an operator types, once.
func appendSSHUnmanagedAdvisory16737Locked(cfg *Config, opts compileOpts) {
	if cfg == nil || opts.suppressSSHUnmanagedAdvisory16737 {
		return
	}
	if cfg.System.Services != nil && cfg.System.Services.SSH != nil {
		return
	}
	names := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		names = append(names, name)
	}
	if len(names) == 0 {
		return
	}
	sort.Strings(names)
	zoneByIface := InterfaceZoneMap(cfg)
	lifelines := HostInboundLifelineSet(cfg)
	tunnelNames := cfg.TunnelNameMap()
	for _, name := range names {
		zone := cfg.Security.Zones[name]
		if zone == nil || !sshAdmitted16737InZone(cfg, name, zone, zoneByIface, lifelines, tunnelNames) {
			continue
		}
		cfg.Warnings = append(cfg.Warnings, fmt.Sprintf(sshUnmanagedAdvisory16737, name))
	}
}

// sshAdmitted16737InZone checks effective member sets through the shared
// host-inbound resolver. It considers only interface keys owned by this
// zone, ignores lifelines, and checks physical parents directly named by a
// bare member or retained by a distinct configured unit 0.
func sshAdmitted16737InZone(
	cfg *Config,
	zoneName string,
	zone *ZoneConfig,
	zoneByIface map[string]string,
	lifelines map[string]bool,
	tunnelNames map[string]string,
) bool {
	if zone == nil {
		return false
	}
	// With no declared members, retain the zone-level advisory: there is no
	// interface override that can prove the zone admission is replaced.
	if len(zone.Interfaces) == 0 && sshAdmitted16737(zone.HostInboundTraffic) {
		return true
	}
	for _, ref := range zone.Interfaces {
		if ref == "" {
			continue
		}
		split := cfg.SplitInterfaceUnitRef(ref)
		for _, effectiveRef := range InterfaceUnitRefKeys(cfg, ref) {
			if sshAdmitted16737OnMemberKey(cfg, zoneName, zone, zoneByIface, lifelines, split.Base, effectiveRef, !split.HasUnit, tunnelNames) {
				return true
			}
		}
		// Fan-up from a unit-only member does not normally make the physical
		// parent an enforcement identity. A configured distinct unit 0 is the
		// exception retained by hostInboundUnzonedFanUpBaseRows.
		if split.HasUnit && split.Base != "" &&
			sshAdmitted16737OnMemberKey(cfg, zoneName, zone, zoneByIface, lifelines, split.Base, split.Base, false, tunnelNames) {
			return true
		}
	}
	return false
}

func sshAdmitted16737OnMemberKey(
	cfg *Config,
	zoneName string,
	zone *ZoneConfig,
	zoneByIface map[string]string,
	lifelines map[string]bool,
	parentRef string,
	effectiveRef string,
	parentDirect bool,
	tunnelNames map[string]string,
) bool {
	if HostInboundLifelineInterface(effectiveRef, lifelines) {
		return false
	}
	if effectiveRef == parentRef && parentRef != "" {
		unit0Configured, collapsed := sshParentUnit0CarrierState16737(cfg, parentRef, tunnelNames)
		if collapsed || (!parentDirect && !unit0Configured) {
			return false
		}
		if nativeRef, nativeZone, ok := sshNativeVLANParentPolicyRef16737(cfg, parentRef, zoneByIface); ok {
			if nativeZone != zoneName {
				return false
			}
			effectiveRef = nativeRef
		}
	}
	if zoneByIface[effectiveRef] != zoneName ||
		HostInboundLifelineInterface(effectiveRef, lifelines) {
		return false
	}
	services, _, _ := zone.InterfaceHostInboundEffective(effectiveRef)
	return sshAdmitted16737Services(services)
}

// sshNativeVLANParentPolicyRef16737 mirrors the native-unit selection used by
// userspace views. A configured unique match matters only when InterfaceZoneMap
// resolves that unit to a zone; otherwise the parent retains its own policy.
func sshNativeVLANParentPolicyRef16737(
	cfg *Config,
	base string,
	zoneByIface map[string]string,
) (string, string, bool) {
	ifName, iface, ok := LookupInterfaceByLinuxName(cfg, base)
	if !ok || iface.NativeVlanID > 4094 {
		return "", "", false
	}
	unitNum, ok := NativeVLANUnitNumber(iface)
	if !ok {
		return "", "", false
	}
	unitRef := fmt.Sprintf("%s.%d", ifName, unitNum)
	unitZone := zoneByIface[unitRef]
	if unitZone == "" {
		return "", "", false
	}
	return unitRef, unitZone, true
}

// sshParentUnit0CarrierState16737 mirrors the same-netdev unit-0 check in
// userspace host-inbound view construction. Config.ResolveKernelIfName is
// its config-side counterpart, guarded against drift by
// TestResolveKernelIfName_DriftGuardVsSnapshotLinuxName.
func sshParentUnit0CarrierState16737(cfg *Config, base string, tunnelNames map[string]string) (bool, bool) {
	_, iface, ok := LookupInterfaceByLinuxName(cfg, base)
	if !ok {
		return false, false
	}
	if _, ok := LookupUnit(iface, 0); !ok {
		return false, false
	}
	parentDevice := cfg.resolveKernelIfNameWith(base, tunnelNames)
	unit0Device := cfg.resolveKernelIfNameWith(base+".0", tunnelNames)
	return true, parentDevice == unit0Device
}

// sshAdmitted16737 reports whether a host-inbound stanza admits SSH,
// through the same expansion the dataplane uses (`all` expands to the
// named-service union, `any-service` is the full admit).
func sshAdmitted16737(hib *HostInboundTraffic) bool {
	if hib == nil {
		return false
	}
	return sshAdmitted16737Services(hib.SystemServices)
}

func sshAdmitted16737Services(services []string) bool {
	return hostInboundAdmitsSystemService(services, "ssh")
}
