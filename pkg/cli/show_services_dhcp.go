package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/dhcp"
	"github.com/psaab/xpf/pkg/dhcpserver"
	"github.com/psaab/xpf/pkg/termsafe"
)

func (c *CLI) showDHCPLeases() error {
	if c.dhcp == nil {
		fmt.Println("No DHCP clients running")
		return nil
	}

	leases := c.dhcp.Leases()
	if len(leases) == 0 {
		fmt.Println("No active DHCP leases")
		return nil
	}

	fmt.Println("DHCP leases:")
	for _, l := range leases {
		family := "inet"
		if l.Family == dhcp.AFInet6 {
			family = "inet6"
		}
		elapsed := time.Since(l.Obtained).Round(time.Second)
		remaining := l.LeaseTime - elapsed
		if remaining < 0 {
			remaining = 0
		}
		fmt.Printf("  Interface: %s, Family: %s\n", l.Interface, family)
		fmt.Printf("    Address:   %s\n", l.Address)
		if l.Gateway.IsValid() {
			fmt.Printf("    Gateway:   %s\n", l.Gateway)
		}
		if len(l.DNS) > 0 {
			dnsStrs := make([]string, len(l.DNS))
			for i, d := range l.DNS {
				dnsStrs[i] = d.String()
			}
			fmt.Printf("    DNS:       %s\n", strings.Join(dnsStrs, ", "))
		}
		fmt.Printf("    Lease:     %s (remaining: %s)\n", l.LeaseTime.Round(time.Second), remaining.Round(time.Second))
		fmt.Printf("    Obtained:  %s\n", l.Obtained.Format("2006-01-02 15:04:05"))
		fmt.Println()
	}

	// Show delegated prefixes
	pds := c.dhcp.DelegatedPrefixes()
	if len(pds) > 0 {
		fmt.Println("Delegated prefixes (DHCPv6 PD):")
		for _, dp := range pds {
			elapsed := time.Since(dp.Obtained).Round(time.Second)
			remaining := dp.ValidLifetime - elapsed
			if remaining < 0 {
				remaining = 0
			}
			fmt.Printf("  Interface: %s\n", dp.Interface)
			fmt.Printf("    Prefix:    %s\n", dp.Prefix)
			fmt.Printf("    Preferred: %s\n", dp.PreferredLifetime.Round(time.Second))
			fmt.Printf("    Valid:     %s (remaining: %s)\n", dp.ValidLifetime.Round(time.Second), remaining.Round(time.Second))
			fmt.Printf("    Obtained:  %s\n", dp.Obtained.Format("2006-01-02 15:04:05"))
			fmt.Println()
		}
	}

	return nil
}

func (c *CLI) showDHCPClientIdentifier() error {
	if c.dhcp == nil {
		fmt.Println("No DHCP clients running")
		return nil
	}

	duids := c.dhcp.DUIDs()
	if len(duids) == 0 {
		fmt.Println("No DHCPv6 DUIDs configured")
		return nil
	}

	fmt.Println("DHCPv6 client identifiers:")
	for _, d := range duids {
		fmt.Printf("  Interface: %s\n", d.Interface)
		fmt.Printf("    Type:    %s\n", d.Type)
		fmt.Printf("    DUID:    %s\n", d.Display)
		fmt.Printf("    Hex:     %s\n", d.HexBytes)
		fmt.Println()
	}
	return nil
}

func (c *CLI) showDHCPRelay() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil || cfg.ForwardingOptions.DHCPRelay == nil {
		fmt.Println("No DHCP relay configured")
		return nil
	}
	relay := cfg.ForwardingOptions.DHCPRelay

	if len(relay.ServerGroups) > 0 {
		fmt.Println("Server groups:")
		for name, sg := range relay.ServerGroups {
			fmt.Printf("  %s: %s\n", name, strings.Join(sg.Servers, ", "))
		}
	}

	if len(relay.Groups) > 0 {
		fmt.Println("Relay groups:")
		for name, g := range relay.Groups {
			fmt.Printf("  %s:\n", name)
			fmt.Printf("    Interfaces: %s\n", strings.Join(g.Interfaces, ", "))
			fmt.Printf("    Active server group: %s\n", g.ActiveServerGroup)
			var overrides []string
			if g.AlwaysBroadcast {
				overrides = append(overrides, "always-broadcast")
			}
			// #4309: maximum-hop-count is enforced; forward-only /
			// relay-agent-option are accepted-only (annotated so the operator
			// sees they match the relay's existing default behavior).
			if g.MaximumHopCount > 0 {
				overrides = append(overrides, fmt.Sprintf("maximum-hop-count %d", g.MaximumHopCount))
			}
			// #5670: per-interface ingress rate limit (pps). Enforced; unset uses
			// the default (100 pps) — show the effective bound either way.
			if g.MaximumPacketRate > 0 {
				overrides = append(overrides, fmt.Sprintf("maximum-packet-rate %d", g.MaximumPacketRate))
			}
			if g.ForwardOnly {
				overrides = append(overrides, "forward-only (accepted-only)")
			}
			if g.RelayAgentOption {
				overrides = append(overrides, "relay-agent-option (accepted-only)")
			}
			if g.TrustOption82 {
				overrides = append(overrides, "trust-option-82")
			}
			if len(overrides) > 0 {
				fmt.Printf("    Overrides: %s\n", strings.Join(overrides, ", "))
			}
		}
	}

	// Runtime statistics
	if c.dhcpRelay != nil {
		stats := c.dhcpRelay.Stats()
		if len(stats) > 0 {
			fmt.Println("\nRelay statistics:")
			// #9406: the BOUND DEVICE is shown beside the configured
			// interface. The two differ under the canonical Junos spelling
			// (`ge-0/0/0.0` binds `ge-0-0-0`), and an all-zero counter row is
			// otherwise indistinguishable from an idle segment — which is
			// exactly how the relay being bound to nothing at all stayed
			// invisible.
			fmt.Printf("  %-16s %-16s %-18s %-18s %-18s %s\n", "Interface", "Bound device", "Requests relayed", "Replies forwarded", "Dropped (max-hops)", "Dropped (rate-limit)")
			for _, s := range stats {
				bound := s.KernelInterface
				if bound == "" {
					bound = s.Interface
				}
				fmt.Printf("  %-16s %-16s %-18d %-18d %-18d %d\n", s.Interface, bound, s.RequestsRelayed, s.RepliesForwarded, s.RequestsDroppedMaxHops, s.RequestsDroppedRateLimit)
			}
			// Reply-delivery breakdown (#2076). L2-fallback is the one to
			// alert on: it means the raw-L2 path failed (CAP_NET_RAW,
			// driver, or MTU) and the relay degraded to broadcast.
			fmt.Println("\nReply delivery (#2076):")
			fmt.Printf("  %-16s %-10s %-10s %-10s %-10s %-10s %-12s %s\n",
				"Interface", "L2-unicast", "ciaddr", "bcast-flag", "bcast-fwd",
				"no-target", "L2-fallback", "nak-bcast")
			for _, s := range stats {
				fmt.Printf("  %-16s %-10d %-10d %-10d %-10d %-10d %-12d %d\n",
					s.Interface, s.RepliesL2Unicast, s.RepliesUnicastCiaddr,
					s.RepliesBroadcastFlag1, s.RepliesBroadcastForced,
					s.RepliesBroadcastNoTarget, s.RepliesBroadcastL2Fallback,
					s.RepliesBroadcastNak)
			}
			// Reply source validation (#4163). A non-zero count means a reply
			// arrived from a source IP that is NOT one of the configured DHCP
			// servers and was dropped — a rogue-reply injection attempt, or a
			// multi-homed server unicasting from an unlisted source IP.
			fmt.Println("\nReply source validation (#4163):")
			fmt.Printf("  %-16s %s\n", "Interface", "Dropped (unknown server)")
			for _, s := range stats {
				fmt.Printf("  %-16s %d\n", s.Interface, s.RepliesDroppedUnknownServer)
			}
			// Outstanding-request binding (#6562). A source IP is spoofable, so
			// a reply must also answer a request the relay actually forwarded.
			// "no-request" counts replies that did not bind — an injection
			// attempt, OR a legitimate reply that missed the binding window,
			// which is a client-visible DHCP failure. "Pending" is
			// occupancy/capacity — the LEADING indicator: as it approaches
			// capacity the relay is about to evict bindings and drop legitimate
			// replies. "pending-evicted" is COINCIDENT, not leading — it only
			// rises once bindings are already being lost. "forcerenew" counts
			// DHCPFORCERENEW refused (RFC 3203 §6 requires RFC 3118 auth that a
			// relay cannot verify).
			fmt.Println("\nReply request binding (#6562):")
			fmt.Printf("  %-16s %-14s %-22s %-16s %s\n",
				"Interface", "Pending", "Dropped (no-request)", "Pending evicted",
				"Refused (forcerenew)")
			for _, s := range stats {
				fmt.Printf("  %-16s %-14s %-22d %-16d %d\n",
					s.Interface,
					fmt.Sprintf("%d/%d", s.PendingSize, s.PendingCapacity),
					s.RepliesDroppedNoRequest, s.PendingEvicted,
					s.RepliesDroppedForceRenew)
			}
		}
	}
	return nil
}

// newDHCPServer builds the dhcpserver.Manager used to read the live lease set
// for `show dhcp server`. Production returns a fresh dhcpserver.New(); a test
// seam (dhcpServerFn) overrides it to point at a controlled Kea lease-file set.
func (c *CLI) newDHCPServer() *dhcpserver.Manager {
	if c.dhcpServerFn != nil {
		return c.dhcpServerFn()
	}
	return dhcpserver.New()
}

func (c *CLI) showDHCPServer(detail bool) error {
	cfg := c.store.ActiveConfig()
	if cfg == nil || (cfg.System.DHCPServer.DHCPLocalServer == nil && cfg.System.DHCPServer.DHCPv6LocalServer == nil) {
		fmt.Println("No DHCP server configured")
		return nil
	}

	// In detail mode, show pool configuration first
	if detail {
		if srv := cfg.System.DHCPServer.DHCPLocalServer; srv != nil && len(srv.Groups) > 0 {
			fmt.Println("DHCPv4 Server Configuration:")
			for name, group := range srv.Groups {
				fmt.Printf("  Group: %s\n", name)
				if len(group.Interfaces) > 0 {
					fmt.Printf("    Interfaces: %s\n", strings.Join(group.Interfaces, ", "))
				}
				for _, pool := range group.Pools {
					fmt.Printf("    Pool: %s\n", pool.Name)
					if pool.Subnet != "" {
						fmt.Printf("      Subnet: %s\n", pool.Subnet)
					}
					if pool.RangeLow != "" {
						fmt.Printf("      Range: %s - %s\n", pool.RangeLow, pool.RangeHigh)
					}
					if pool.Router != "" {
						fmt.Printf("      Router: %s\n", pool.Router)
					}
					if len(pool.DNSServers) > 0 {
						fmt.Printf("      DNS: %s\n", strings.Join(pool.DNSServers, ", "))
					}
					if pool.LeaseTime > 0 {
						fmt.Printf("      Lease time: %ds\n", pool.LeaseTime)
					}
				}
			}
			fmt.Println()
		}
		if srv := cfg.System.DHCPServer.DHCPv6LocalServer; srv != nil && len(srv.Groups) > 0 {
			fmt.Println("DHCPv6 Server Configuration:")
			for name, group := range srv.Groups {
				fmt.Printf("  Group: %s\n", name)
				if len(group.Interfaces) > 0 {
					fmt.Printf("    Interfaces: %s\n", strings.Join(group.Interfaces, ", "))
				}
				for _, pool := range group.Pools {
					fmt.Printf("    Pool: %s\n", pool.Name)
					if pool.Subnet != "" {
						fmt.Printf("      Subnet: %s\n", pool.Subnet)
					}
					if pool.RangeLow != "" {
						fmt.Printf("      Range: %s - %s\n", pool.RangeLow, pool.RangeHigh)
					}
				}
			}
			fmt.Println()
		}
	}

	// Read the Kea lease set through the SOURCE-AWARE path (#5967): prefer the
	// live lease_cmds DB and surface the #5938 degraded-source banner, matching
	// the authoritative gRPC `show dhcp server` handler that the remote `cli`
	// drives. The in-process interactive shell previously called GetLeases4/6
	// (memfile only, no live-socket preference, no banner), so a degraded read
	// on THIS surface alone looked like a healthy empty set — a divergence from
	// the remote path. GetLeasesWithSource4/6 skips an unreadable Kea LFC sibling
	// and records it in the LeaseSource banner detail instead of aborting, so the
	// #4908 "a degraded read is never rendered as a clean empty table" invariant
	// is preserved by the banner rather than the old per-family read warnings.
	server := c.newDHCPServer()
	leases4, src4 := server.GetLeasesWithSource4()
	leases6, src6 := server.GetLeasesWithSource6()

	// Emit each degraded family's banner (shared selection with the gRPC handler
	// via dhcpserver.DegradedBanners: both distinct details when both families
	// are degraded, an exact duplicate collapsed to one line).
	for _, b := range dhcpserver.DegradedBanners(src4, src6) {
		fmt.Println(b)
	}

	if len(leases4) == 0 && len(leases6) == 0 {
		if !detail {
			fmt.Println("No active leases")
		} else {
			fmt.Println("Active leases: none")
		}
		return nil
	}

	if len(leases4) > 0 {
		fmt.Printf("DHCPv4 Leases (%d active):\n", len(leases4))
		if detail {
			fmt.Printf("  %-18s %-20s %-15s %-10s %-12s %s\n", "Address", "MAC", "Hostname", "Subnet", "Lifetime", "Expires")
			for _, l := range leases4 {
				// HWAddress and Hostname are device-supplied (client chaddr /
				// DHCP option 12) — escape terminal control sequences (#6468).
				fmt.Printf("  %-18s %-20s %-15s %-10s %-12s %s\n",
					l.Address, termsafe.SanitizeForDisplay(l.HWAddress), termsafe.SanitizeForDisplay(l.Hostname), l.SubnetID, l.ValidLife, l.ExpireTime)
			}
		} else {
			fmt.Printf("  %-18s %-20s %-15s %-12s %s\n", "Address", "MAC", "Hostname", "Lifetime", "Expires")
			for _, l := range leases4 {
				fmt.Printf("  %-18s %-20s %-15s %-12s %s\n",
					l.Address, termsafe.SanitizeForDisplay(l.HWAddress), termsafe.SanitizeForDisplay(l.Hostname), l.ValidLife, l.ExpireTime)
			}
		}
	}
	if len(leases6) > 0 {
		fmt.Printf("DHCPv6 Leases (%d active):\n", len(leases6))
		// #4908 (C175-HC-080): label the column "HWAddress", not "DUID". Kea's
		// GetLeases6 populates Lease.HWAddress (the link-layer address), not the
		// client DUID/IAID, so a "DUID" header mislabeled the printed value.
		if detail {
			fmt.Printf("  %-40s %-20s %-15s %-10s %-12s %s\n", "Address", "HWAddress", "Hostname", "Subnet", "Lifetime", "Expires")
			for _, l := range leases6 {
				// HWAddress and Hostname are device-supplied — escape terminal
				// control sequences before display (#6468).
				fmt.Printf("  %-40s %-20s %-15s %-10s %-12s %s\n",
					l.Address, termsafe.SanitizeForDisplay(l.HWAddress), termsafe.SanitizeForDisplay(l.Hostname), l.SubnetID, l.ValidLife, l.ExpireTime)
			}
		} else {
			fmt.Printf("  %-40s %-20s %-15s %-12s %s\n", "Address", "HWAddress", "Hostname", "Lifetime", "Expires")
			for _, l := range leases6 {
				fmt.Printf("  %-40s %-20s %-15s %-12s %s\n",
					l.Address, termsafe.SanitizeForDisplay(l.HWAddress), termsafe.SanitizeForDisplay(l.Hostname), l.ValidLife, l.ExpireTime)
			}
		}
	}
	return nil
}
