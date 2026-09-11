package config

import (
	"fmt"
	"net/netip"
	"sort"
)

// validateDHCPPoolSubnetsUniqueStrict refuses two pools of one DHCP server
// whose subnets are the same prefix (#9785).
//
// Every pool renders as its own Kea subnet4 (or subnet6) entry, and Kea
// refuses a second entry for a prefix it already holds: `subnet with the
// prefix of '10.0.61.0/24' already exists`. The whole Dhcp4 config then fails
// to load, kea-dhcp4-server exits, and the node serves no DHCP at all,
// including every pool that worked before the commit, while the commit
// itself printed `commit complete` (observed on the loss userspace cluster,
// #9785).
//
// The scope is one server: dhcp-local-server pools against each other, and
// dhcpv6-local-server pools against each other. Two pools in ONE group count
// too, because they render the same way.
//
// The key is the MASKED prefix, so `10.0.61.1/24` duplicates `10.0.61.0/24`:
// both spellings name one network, and the renderer's belt (claimPoolSubnet)
// keys the same way. Overlapping prefixes of different lengths are a
// different question; warnAmbiguousV4SubnetSelection in pkg/dhcpserver warns
// about ambiguous selection between them, and this gate leaves them alone.
func validateDHCPPoolSubnetsUniqueStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	check := func(srv *DHCPLocalServerConfig, server string) error {
		if srv == nil {
			return nil
		}
		// Sorted so the reported pair is stable across runs.
		names := make([]string, 0, len(srv.Groups))
		for name := range srv.Groups {
			names = append(names, name)
		}
		sort.Strings(names)
		seen := make(map[netip.Prefix]string)
		for _, gname := range names {
			group := srv.Groups[gname]
			if group == nil {
				continue
			}
			for _, pool := range group.Pools {
				if pool == nil || pool.Subnet == "" {
					continue
				}
				p, err := netip.ParsePrefix(pool.Subnet)
				if err != nil {
					continue // not this gate's defect; Kea names a malformed subnet itself
				}
				where := fmt.Sprintf("group %q pool %q", gname, pool.Name)
				if prev, dup := seen[p.Masked()]; dup {
					return fmt.Errorf("%s %s subnet %s duplicates %s (prefix %s): Kea refuses a second subnet with the same prefix and stops serving every pool on the node",
						server, where, pool.Subnet, prev, p.Masked())
				}
				seen[p.Masked()] = where
			}
		}
		return nil
	}
	if err := check(cfg.System.DHCPServer.DHCPLocalServer, "dhcp-local-server"); err != nil {
		return err
	}
	return check(cfg.System.DHCPServer.DHCPv6LocalServer, "dhcpv6-local-server")
}
