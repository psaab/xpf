package dhcpserver

import (
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// keaTunnelNameMapFn is the dhcpserver-side twin of pkg/config's
// tunnelNameMapFn seam (#8862): production always holds
// (*config.Config).TunnelNameMap, and the #18923 built-once cell swaps it
// to count builds, because "the belt builds the map once, not once per
// ref" is a cost property no output assertion can observe.
var keaTunnelNameMapFn = (*config.Config).TunnelNameMap

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

// usableKeaDevices15206 is the set of kernel device names the active config's
// declared interfaces and units resolve to. Both spellings of each authored
// interface are resolved (the config key and its Linux form, #8829), because
// a group ref authored in either spelling resolves from either.
//
// #18923: the tunnel-name map is built ONCE per call, through the seam
// above, and every ref is resolved through the exported hoisted twin
// Config.ResolveKernelIfNameWith. ResolveKernelIfName rebuilds that map per
// call — a walk of every interface and unit — so the per-ref form made this
// loop O((I+U)^2) per DHCP family per standalone commit. The active config
// is not mutated during a filter call, so one build is sound.
func usableKeaDevices15206(active *config.Config) map[string]bool {
	tunMap := keaTunnelNameMapFn(active)
	usable := make(map[string]bool)
	for name, ifc := range active.Interfaces.Interfaces {
		// #17474: a present-but-nil interface still declares its name: the
		// pre-belt name-only loop counted it usable, and skipping it could
		// leave usable empty, which disables filtering entirely (fail-open).
		usable[active.ResolveKernelIfNameWith(name, tunMap)] = true
		linux := config.LinuxIfName(name)
		if linux != name {
			usable[active.ResolveKernelIfNameWith(linux, tunMap)] = true
		}
		if ifc == nil {
			continue
		}
		for unitNum, unit := range ifc.Units {
			if unit == nil {
				continue
			}
			suffix := "." + strconv.Itoa(unitNum)
			usable[active.ResolveKernelIfNameWith(name+suffix, tunMap)] = true
			if linux != name {
				usable[active.ResolveKernelIfNameWith(linux+suffix, tunMap)] = true
			}
		}
	}
	return usable
}
