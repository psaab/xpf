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
// SSH-admitting zone (zone-level stanza and per-interface overrides) when
// the config carries no `system services ssh` stanza.
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
	sort.Strings(names)
	for _, name := range names {
		zone := cfg.Security.Zones[name]
		if zone == nil {
			continue
		}
		if sshAdmitted16737(zone.HostInboundTraffic) {
			cfg.Warnings = append(cfg.Warnings, fmt.Sprintf(sshUnmanagedAdvisory16737, name))
			continue
		}
		ifRefs := make([]string, 0, len(zone.InterfaceHostInbound))
		for ref := range zone.InterfaceHostInbound {
			ifRefs = append(ifRefs, ref)
		}
		sort.Strings(ifRefs)
		for _, ref := range ifRefs {
			if sshAdmitted16737(zone.InterfaceHostInbound[ref]) {
				cfg.Warnings = append(cfg.Warnings, fmt.Sprintf(sshUnmanagedAdvisory16737, name))
				break
			}
		}
	}
}

// sshAdmitted16737 reports whether a host-inbound stanza admits SSH,
// through the same expansion the dataplane uses (`all` expands to the
// named-service union, `any-service` is the full admit).
func sshAdmitted16737(hib *HostInboundTraffic) bool {
	if hib == nil {
		return false
	}
	return hostInboundAdmitsSystemService(hib.SystemServices, "ssh")
}
