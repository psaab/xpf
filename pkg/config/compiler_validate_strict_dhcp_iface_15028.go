package config

import (
	"fmt"
	"sort"
	"strings"
)

// dhcpResolvedDevice15028 returns the kernel device a resolved interface
// name denotes for duplicate comparison. Config.ResolveKernelIfName
// collapses a declared unit 0 to the bare device (reth1.0 -> ge-0-0-1)
// but preserves the ".0" suffix for an UNDECLARED unit-0 ref
// (ge-0/0/1.0 -> ge-0-0-1.0, its honest verbatim fallback, #9407). There
// is no ".0" kernel device for an untagged unit — the daemon's own
// stripUntaggedUnitSuffix (pkg/daemon, #4647) normalizes the same
// spelling onto the bare member — so the comparison keys a trailing
// ".0" onto the bare device. Non-zero suffixes (VLAN devices, unit
// devices) are kept.
func dhcpResolvedDevice15028(resolved string) string {
	return strings.TrimSuffix(resolved, ".0")
}

// validateDHCPGroupInterfacesUniqueStrict refuses, at commit / commit-check,
//
// Every group's interface refs are resolved by the daemon
// (resolveDHCPRethInterfaces, Config.ResolveKernelIfName) and emitted flat
// into Kea's interfaces-config list with no de-duplication. Different
// authored refs can name one device:
//
//	reth1.0  and ge-0/0/1.0  both resolve to ge-0-0-1 (the reth member)
//	reth1.0  and reth1       both resolve to ge-0-0-1 (unit-0 collapse)
//	ge-0/0/0.0 and ge-0/0/0  both resolve to ge-0-0-0
//
// and even one ref repeated inside a group or across two groups lands
// twice. Kea refuses a duplicate in the interfaces list and then loads
// nothing, so every pool of that family stops while the commit itself
// reports success — the #9785/#14601 whole-family outage through the
// interface list instead of a pool leaf.
//
// The scope is one server family: dhcp-local-server refs against each
// other, and dhcpv6-local-server refs against each other, because the two
// families render separate Dhcp4/Dhcp6 files. Two refs in ONE group count
// too, because they render into the same list.
//
// Empty refs are skipped: they are not this gate's defect (the renderer
// de-duplication skips them too), and an empty ref has no device to
// collide on.
func validateDHCPGroupInterfacesUniqueStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	check := func(srv *DHCPLocalServerConfig, server string) error {
		if srv == nil {
			return nil
		}
		// One tunnel-name map for the whole family (#8862): building it
		// per ref is quadratic.
		tunMap := tunnelNameMapFn(cfg)
		// Sorted so the reported pair is stable across runs.
		names := make([]string, 0, len(srv.Groups))
		for name := range srv.Groups {
			names = append(names, name)
		}
		sort.Strings(names)
		seen := make(map[string]string) // kernel device -> first ref/group
		for _, gname := range names {
			group := srv.Groups[gname]
			if group == nil {
				continue
			}
			for _, ref := range group.Interfaces {
				if ref == "" {
					continue
				}
				device := dhcpResolvedDevice15028(cfg.resolveKernelIfNameWith(ref, tunMap))
				where := fmt.Sprintf("group %q interface %q", gname, ref)
				if prev, dup := seen[device]; dup {
					return fmt.Errorf("%s %s resolves to kernel device %q, which duplicates %s: Kea refuses a duplicate interface and stops serving every pool of the family",
						server, where, device, prev)
				}
				seen[device] = where
			}
		}
		return nil
	}
	if err := check(cfg.System.DHCPServer.DHCPLocalServer, "dhcp-local-server"); err != nil {
		return err
	}
	return check(cfg.System.DHCPServer.DHCPv6LocalServer, "dhcpv6-local-server")
}
