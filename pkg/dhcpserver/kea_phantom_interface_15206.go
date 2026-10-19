package dhcpserver

import (
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// FilterKeaInterfaces15206 drops, from one DHCP family config, every
// group interface name that remains unresolved after the daemon's
// resolution pass — a device name no configured interface produces
// (#15206, A17-03, the #9407 residual).
//
// The daemon (pkg/daemon resolveDHCPRethInterfaces) resolves every group
// ref through Config.ResolveKernelIfName, whose honest fallback for a
// ref naming no configured interface or unit returns the ref verbatim.
// Such a name reaches this renderer unchanged (`reth1.7`, `ge-0-0-9.0`)
// and would render verbatim into interfaces-config AND into the
// per-subnet selector of a single-interface group. Kea validates the
// file as one unit, refuses it for the nonexistent interface, and every
// pool of the family stops — while the #9407-era advisory said only
// "the segment gets no leases".
//
// The criterion is exact identity with a declared interface's resolved
// device: an interface name is usable IFF some interface the ACTIVE
// config declares resolves (Config.ResolveKernelIfName, the daemon's own
// resolver) to the same name. This keeps every real device — physical,
// RETH member, VLAN sub-device, tunnel, IRB/bridge, fab0, lo, st — and
// drops only names no declaration explains. It is deliberately NOT a
// kernel-existence test: the active config, not netlink, is what the
// daemon resolved against, so renderer and resolver cannot drift.
//
// Commit refuses the authored ref (validateDHCPServerInterfaceRefStrict
// in pkg/config); this is the belt for a config that reached the
// renderer anyway through the tolerant load or peer-sync path. Groups
// whose interfaces are all dropped lose their subnets too (warned
// per interface); a surviving group keeps its pools, and a dropped
// member simply stops contributing its selector/interfaces entry.
//
// It operates on the daemon-resolved copy (resolveDHCPRethInterfaces
// returns fresh Groups/Interfaces), never on the shared active config.
// Returns the original cfg and false when nothing was dropped.
func FilterKeaInterfaces15206(cfg *config.DHCPServerConfig, active *config.Config, family string, warn func(msg string, args ...any)) (*config.DHCPServerConfig, bool) {
	if cfg == nil || active == nil {
		return cfg, false
	}
	usable := usableKeaDevices15206(active)
	lifelines := config.HostInboundLifelineSet(active)
	if len(usable) == 0 {
		return cfg, false
	}
	filter := func(src *config.DHCPLocalServerConfig) (*config.DHCPLocalServerConfig, bool) {
		if src == nil || len(src.Groups) == 0 {
			return src, false
		}
		groups := make(map[string]*config.DHCPServerGroup, len(src.Groups))
		changed := false
		for name, group := range src.Groups {
			if group == nil {
				groups[name] = nil
				continue
			}
			cp := *group
			kept := make([]string, 0, len(group.Interfaces))
			for _, iface := range group.Interfaces {
				if iface == "" || strings.HasSuffix(iface, "*") || usable[iface] || config.HostInboundLifelineInterface(iface, lifelines) {
					kept = append(kept, iface)
					continue
				}
				warn("skipping DHCP interface that is not a configured device (Kea refuses the whole file for an unknown interface and would stop serving every pool of the family)",
					"family", family, "group", group.Name, "interface", iface)
				changed = true
			}
			cp.Interfaces = kept
			groups[name] = &cp
		}
		if !changed {
			return src, false
		}
		out := *src
		out.Groups = groups
		return &out, true
	}
	out := *cfg
	var changed bool
	if family == "4" {
		out.DHCPLocalServer, changed = filter(cfg.DHCPLocalServer)
	} else {
		out.DHCPv6LocalServer, changed = filter(cfg.DHCPv6LocalServer)
	}
	if !changed {
		return cfg, false
	}
	return &out, true
}

// usableKeaDevices15206 is the set of kernel device names the active
// config's declared interfaces resolve to. Both spellings of every
// declared name are resolved (the config key and its Linux form, #8829),
// because a group ref authored in either spelling resolves from either.
func usableKeaDevices15206(active *config.Config) map[string]bool {
	usable := make(map[string]bool)
	for name := range active.Interfaces.Interfaces {
		usable[active.ResolveKernelIfName(name)] = true
		if linux := config.LinuxIfName(name); linux != name {
			usable[active.ResolveKernelIfName(linux)] = true
		}
	}
	return usable
}
