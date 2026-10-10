// Package daemon implements the xpf daemon lifecycle.
package daemon

import (
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dhcp"
)

// buildRAConfigs merges static RA configs from the Junos config with
// PD-derived prefixes from DHCPv6 prefix delegation.
func (d *Daemon) buildRAConfigs(cfg *config.Config) []*config.RAInterfaceConfig {
	// Start with static RA configs from the configuration.
	raByIface := make(map[string]*config.RAInterfaceConfig)
	var result []*config.RAInterfaceConfig
	for _, ra := range cfg.Protocols.RouterAdvertisement {
		clone := cloneRAInterfaceConfig(ra)
		raByIface[clone.Interface] = clone
		result = append(result, clone)
	}

	if d.dhcp != nil {
		// Merge PD-derived prefixes from DHCPv6 clients.
		for _, mapping := range d.dhcp.DelegatedPrefixesForRA() {
			if overlap, ok := delegatedPrefixOverlapsConfigured(mapping.Prefix, cfg); ok {
				slog.Warn("DHCPv6 PD: refusing configured-prefix overlap",
					"delegated", mapping.Prefix,
					"configured", overlap,
					"source_interface", mapping.Interface,
					"ra_interface", mapping.RAIface)
				continue
			}
			subPrefix := dhcp.DeriveSubPrefix(mapping.Prefix, mapping.SubPrefLen)
			if !subPrefix.IsValid() {
				slog.Warn("DHCPv6 PD: invalid sub-prefix derivation",
					"delegated", mapping.Prefix, "sub_len", mapping.SubPrefLen)
				continue
			}

			pfx := &config.RAPrefix{
				Prefix:     subPrefix.String(),
				OnLink:     true,
				Autonomous: true,
				// #6587: mark the provenance so pkg/ra can apply a floor to a
				// DELEGATED prefix without breaking an operator-authored ::/0.
				Delegated: true,
			}
			if mapping.ValidLifetime > 0 {
				pfx.ValidLifetime = int(mapping.ValidLifetime.Seconds())
			}
			if mapping.PreferredLifetime > 0 {
				pfx.PreferredLife = int(mapping.PreferredLifetime.Seconds())
			}

			if existing, ok := raByIface[mapping.RAIface]; ok {
				// Append prefix to existing RA interface config.
				existing.Prefixes = append(existing.Prefixes, pfx)
			} else {
				// Create a new RA interface config for this downstream interface.
				ra := &config.RAInterfaceConfig{
					Interface: mapping.RAIface,
					Prefixes:  []*config.RAPrefix{pfx},
				}
				raByIface[mapping.RAIface] = ra
				result = append(result, ra)
			}

			// Debug, not Info: buildRAConfigs is a pure builder now re-run on
			// every ~2s periodic cluster RA reconcile (reconcileClusterRAServices),
			// so this line would repeat per PD prefix every tick — per-poll-tick
			// Info spam the logging discipline forbids. The one-time operational
			// signal ("a PD prefix is being advertised") belongs on the actual
			// apply, which the reconcile's hash-gated Info already carries.
			slog.Debug("DHCPv6 PD: advertising prefix via RA",
				"prefix", subPrefix, "interface", mapping.RAIface,
				"delegated_from", mapping.Interface)
		}
	}

	// Detect explicitly configured link-local addresses on RA interfaces.
	// If a user configures e.g. fe80::face/64 on a RETH interface (or on a
	// VLAN subinterface), the RA sender should bind to that address instead
	// of auto-selecting a transient EUI-64 link-local.
	for _, ra := range result {
		ifc, ll := resolveRASourceLinkLocal(cfg, ra.Interface)
		if ifc == nil {
			continue
		}
		if ll != "" {
			ra.SourceLinkLocal = ll
		}
		if ra.SourceLinkLocal == "" && cfg.Chassis.Cluster != nil && ifc.RedundancyGroup != 0 {
			// RETH HA startup installs a stable router link-local on the active
			// member. Bind RA to that address so the sender does not auto-pick a
			// transient EUI-64 link-local which can later be removed by HA reconcile.
			ra.SourceLinkLocal = cluster.StableRethLinkLocal(
				cfg.Chassis.Cluster.ClusterID,
				ifc.RedundancyGroup,
			).String()
		}
	}

	// Resolve interface names for RA senders (needs real Linux names).
	// ResolveKernelIfName maps a logical unit to its configured vlan-id for
	// the kernel VLAN sub-interface suffix (reth0.80 with `vlan-id 180` →
	// member.180), whereas the old LinuxIfName(ResolveReth(...)) preserved the
	// UNIT number as the suffix (member.80) and bound RA to a netdev that does
	// not exist. It also keeps the resolved name consistent with
	// rethInterfacesForRG (which already suffixes by unit.VlanID), so the
	// cluster RA ownership match in desiredClusterRA does not drop the sender
	// when unit# != vlan-id (#5107).
	for _, ra := range result {
		ra.Interface = cfg.ResolveKernelIfName(ra.Interface)
	}

	return result
}

// delegatedPrefixOverlapsConfigured rejects a DHCP delegation that intersects
// any configured interface address, static RA prefix, or NAT64 prefix. There is
// no PD pin/allowlist mechanism, so intentional overlap cannot be exempted.
func delegatedPrefixOverlapsConfigured(delegated netip.Prefix, cfg *config.Config) (string, bool) {
	if cfg == nil || !delegated.IsValid() {
		return "", false
	}
	for _, iface := range cfg.Interfaces.Interfaces {
		if iface == nil {
			continue
		}
		for _, unit := range iface.Units {
			if unit == nil {
				continue
			}
			for _, address := range unit.Addresses {
				if configuredIPv6PrefixOverlaps(delegated, address) {
					return address, true
				}
			}
			if configuredIPv6PrefixOverlaps(delegated, unit.PrimaryAddress) {
				return unit.PrimaryAddress, true
			}
			if configuredIPv6PrefixOverlaps(delegated, unit.PreferredAddress) {
				return unit.PreferredAddress, true
			}
			for _, group := range unit.VRRPGroups {
				if group == nil {
					continue
				}
				for _, address := range group.VirtualAddresses {
					if configuredIPv6PrefixOverlaps(delegated, address) {
						return address, true
					}
				}
			}
		}
	}
	for _, ra := range cfg.Protocols.RouterAdvertisement {
		if ra == nil {
			continue
		}
		for _, pfx := range ra.Prefixes {
			if pfx != nil && configuredIPv6PrefixOverlaps(delegated, pfx.Prefix) {
				return pfx.Prefix, true
			}
		}
		if configuredIPv6PrefixOverlaps(delegated, ra.NAT64Prefix) {
			return ra.NAT64Prefix, true
		}
	}
	for _, nat64 := range cfg.Security.NAT.NAT64 {
		if nat64 != nil && configuredIPv6PrefixOverlaps(delegated, nat64.Prefix) {
			return nat64.Prefix, true
		}
	}
	return "", false
}

func configuredIPv6PrefixOverlaps(delegated netip.Prefix, raw string) bool {
	if raw == "" {
		return false
	}
	configured, err := netip.ParsePrefix(raw)
	if err != nil {
		addr, addrErr := netip.ParseAddr(raw)
		if addrErr != nil || !addr.Is6() || addr.Is4In6() {
			return false
		}
		configured = netip.PrefixFrom(addr, addr.BitLen())
	}
	return config.IPv6PrefixesOverlap(delegated, configured)
}

// resolveRASourceLinkLocal resolves the operator-configured IPv6 link-local
// source address for an RA interface, returning the base InterfaceConfig (used
// by the caller for the RETH stable-link-local fallback) and the link-local
// string ("" when none is configured).
//
// raInterface arrives in Junos form straight from
// `protocols router-advertisement interface <name>`. It may be a bare
// physical/RETH name ("reth1", "ge-0/0/2") OR unit-qualified ("reth0.50",
// "ge-0/0/2.50"). cfg.Interfaces.Interfaces is keyed by the BASE name with
// logical units under ifc.Units, so a unit-qualified RA name never matches the
// map directly — split the unit off first (this was the #2996 miss: the old
// lookup hit the map with the full unit-qualified string and only ever read
// Units[0]).
//
// Selection rule (must be deterministic across reconciles):
//   - unit-qualified ("base.N"): use the link-local configured on THAT unit.
//   - bare ("base"): scan units in ASCENDING unit-number order and use the
//     first (lowest-numbered) unit that carries a configured link-local. This
//     is byte-identical to the historical Units[0]-only lookup when unit 0
//     holds the link-local, and now also finds a link-local that lives only on
//     a higher unit.
//
// Within a single unit, the first link-local in Addresses order wins (matching
// the prior `break`-on-first-match behavior).
func resolveRASourceLinkLocal(cfg *config.Config, raInterface string) (*config.InterfaceConfig, string) {
	base, unitTok, hasUnit := strings.Cut(raInterface, ".")
	ifc, ok := cfg.Interfaces.Interfaces[base]
	if !ok || ifc == nil {
		return nil, ""
	}
	if hasUnit && unitTok != "" {
		// RA bound to a specific unit: prefer that unit's link-local only.
		if n, err := strconv.Atoi(unitTok); err == nil {
			if unit, ok := ifc.Units[n]; ok {
				return ifc, unitConfiguredLinkLocal(unit)
			}
		}
		return ifc, ""
	}
	// Bare interface: scan units lowest-first for a stable choice.
	nums := make([]int, 0, len(ifc.Units))
	for n := range ifc.Units {
		nums = append(nums, n)
	}
	sort.Ints(nums)
	for _, n := range nums {
		if ll := unitConfiguredLinkLocal(ifc.Units[n]); ll != "" {
			return ifc, ll
		}
	}
	return ifc, ""
}

// unitConfiguredLinkLocal returns the first configured IPv6 link-local unicast
// address (CIDR-stripped) on the unit, or "" when none is configured.
func unitConfiguredLinkLocal(unit *config.InterfaceUnit) string {
	if unit == nil {
		return ""
	}
	for _, addr := range unit.Addresses {
		ip, _, err := net.ParseCIDR(addr)
		if err != nil {
			continue
		}
		if ip.IsLinkLocalUnicast() && ip.To4() == nil {
			return ip.String()
		}
	}
	return ""
}

func cloneRAInterfaceConfig(src *config.RAInterfaceConfig) *config.RAInterfaceConfig {
	if src == nil {
		return nil
	}
	clone := *src
	if len(src.DNSServers) > 0 {
		clone.DNSServers = append([]string(nil), src.DNSServers...)
	}
	if len(src.Prefixes) > 0 {
		clone.Prefixes = make([]*config.RAPrefix, 0, len(src.Prefixes))
		for _, pfx := range src.Prefixes {
			if pfx == nil {
				clone.Prefixes = append(clone.Prefixes, nil)
				continue
			}
			pfxClone := *pfx
			clone.Prefixes = append(clone.Prefixes, &pfxClone)
		}
	}
	return &clone
}
