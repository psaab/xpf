package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/appid"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/dhcp"
	"github.com/psaab/xpf/pkg/dhcpserver"
	"github.com/psaab/xpf/pkg/rpm"
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

func (c *CLI) showClassOfServiceInterface(selector string) error {
	cfg := c.store.ActiveConfig()
	var status *dpuserspace.ProcessStatus
	if userspaceStatus, err := c.userspaceDataplaneStatus(); err == nil {
		status = &userspaceStatus
	}
	fmt.Print(dpuserspace.FormatCoSInterfaceSummary(cfg, status, selector))
	return nil
}

func (c *CLI) showRPMProbeResults() error {
	// Show live results if RPM manager is available
	if c.rpmResultsFn != nil {
		results := c.rpmResultsFn()
		if len(results) > 0 {
			fmt.Println("RPM Probe Results:")
			for _, r := range results {
				fmt.Printf("  Probe: %s, Test: %s\n", r.ProbeName, r.TestName)
				fmt.Printf("    Type: %s, Target: %s\n", r.ProbeType, r.Target)
				fmt.Printf("    Status: %s", r.LastStatus)
				if r.LastRTT > 0 {
					fmt.Printf(", RTT: %s", r.LastRTT)
				}
				fmt.Println()
				if r.MinRTT > 0 {
					fmt.Printf("    RTT: min %s, max %s, avg %s, jitter %s\n",
						r.MinRTT, r.MaxRTT, r.AvgRTT, r.Jitter)
				}
				fmt.Printf("    Sent: %d, Received: %d", r.TotalSent, r.TotalRecv)
				if r.TotalSent > 0 {
					loss := float64(r.TotalSent-r.TotalRecv) / float64(r.TotalSent) * 100
					fmt.Printf(", Loss: %.1f%%", loss)
				}
				fmt.Println()
				if !r.LastProbeAt.IsZero() {
					fmt.Printf("    Last probe: %s\n", r.LastProbeAt.Format("2006-01-02 15:04:05"))
				}
			}
			return nil
		}
	}

	// Fallback: show config only
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}
	if cfg.Services.RPM == nil || len(cfg.Services.RPM.Probes) == 0 {
		fmt.Println("No RPM probes configured")
		return nil
	}

	fmt.Println("RPM Probe Configuration:")
	for _, probeName := range rpm.SortedProbeNames(cfg.Services.RPM.Probes) {
		probe := cfg.Services.RPM.Probes[probeName]
		for _, testName := range rpm.SortedTestNames(probe.Tests) {
			rpm.WriteConfiguredTest(os.Stdout, probeName, testName, probe.Tests[testName])
			fmt.Println()
		}
	}
	return nil
}

// showApplicationIdentificationStatus delegates to the shared
// renderer in `pkg/appid` so the local CLI and the gRPC
// text-show surface stay byte-identical (Copilot review #5 on
// PR #1196). #653.
func (c *CLI) showApplicationIdentificationStatus() error {
	cfg := c.store.ActiveConfig()
	var buf strings.Builder
	appid.RenderStatus(&buf, cfg)
	fmt.Print(buf.String())
	return nil
}

func (c *CLI) showSchedulers() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil || len(cfg.Schedulers) == 0 {
		fmt.Println("No schedulers configured")
		return nil
	}

	for name, sched := range cfg.Schedulers {
		fmt.Printf("Scheduler: %s\n", name)
		if sched.StartTime != "" {
			fmt.Printf("  Start time: %s\n", sched.StartTime)
		}
		if sched.StopTime != "" {
			fmt.Printf("  Stop time:  %s\n", sched.StopTime)
		}
		if sched.StartDate != "" {
			fmt.Printf("  Start date: %s\n", sched.StartDate)
		}
		if sched.StopDate != "" {
			fmt.Printf("  Stop date:  %s\n", sched.StopDate)
		}
		if sched.Daily {
			fmt.Println("  Recurrence: daily")
		}
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
		}
	}

	// Runtime statistics
	if c.dhcpRelay != nil {
		stats := c.dhcpRelay.Stats()
		if len(stats) > 0 {
			fmt.Println("\nRelay statistics:")
			fmt.Printf("  %-16s %-20s %s\n", "Interface", "Requests relayed", "Replies forwarded")
			for _, s := range stats {
				fmt.Printf("  %-16s %-20d %d\n", s.Interface, s.RequestsRelayed, s.RepliesForwarded)
			}
		}
	}
	return nil
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

	// Read Kea lease files directly.
	server := dhcpserver.New()
	leases4, _ := server.GetLeases4()
	leases6, _ := server.GetLeases6()

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
				fmt.Printf("  %-18s %-20s %-15s %-10s %-12s %s\n",
					l.Address, l.HWAddress, l.Hostname, l.SubnetID, l.ValidLife, l.ExpireTime)
			}
		} else {
			fmt.Printf("  %-18s %-20s %-15s %-12s %s\n", "Address", "MAC", "Hostname", "Lifetime", "Expires")
			for _, l := range leases4 {
				fmt.Printf("  %-18s %-20s %-15s %-12s %s\n",
					l.Address, l.HWAddress, l.Hostname, l.ValidLife, l.ExpireTime)
			}
		}
	}
	if len(leases6) > 0 {
		fmt.Printf("DHCPv6 Leases (%d active):\n", len(leases6))
		if detail {
			fmt.Printf("  %-40s %-20s %-15s %-10s %-12s %s\n", "Address", "DUID", "Hostname", "Subnet", "Lifetime", "Expires")
			for _, l := range leases6 {
				fmt.Printf("  %-40s %-20s %-15s %-10s %-12s %s\n",
					l.Address, l.HWAddress, l.Hostname, l.SubnetID, l.ValidLife, l.ExpireTime)
			}
		} else {
			fmt.Printf("  %-40s %-20s %-15s %-12s %s\n", "Address", "DUID", "Hostname", "Lifetime", "Expires")
			for _, l := range leases6 {
				fmt.Printf("  %-40s %-20s %-15s %-12s %s\n",
					l.Address, l.HWAddress, l.Hostname, l.ValidLife, l.ExpireTime)
			}
		}
	}
	return nil
}

func (c *CLI) showSNMP() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil || cfg.System.SNMP == nil {
		fmt.Println("No SNMP configured")
		return nil
	}
	snmpCfg := cfg.System.SNMP

	if snmpCfg.Location != "" {
		fmt.Printf("Location:    %s\n", snmpCfg.Location)
	}
	if snmpCfg.Contact != "" {
		fmt.Printf("Contact:     %s\n", snmpCfg.Contact)
	}
	if snmpCfg.Description != "" {
		fmt.Printf("Description: %s\n", snmpCfg.Description)
	}

	if len(snmpCfg.Communities) > 0 {
		fmt.Println("Communities:")
		for name, comm := range snmpCfg.Communities {
			fmt.Printf("  %s: %s\n", name, comm.Authorization)
		}
	}

	if len(snmpCfg.TrapGroups) > 0 {
		fmt.Println("Trap groups:")
		for name, tg := range snmpCfg.TrapGroups {
			fmt.Printf("  %s: %s\n", name, strings.Join(tg.Targets, ", "))
		}
	}

	if len(snmpCfg.V3Users) > 0 {
		fmt.Println("SNMPv3 USM users:")
		for name, u := range snmpCfg.V3Users {
			auth := u.AuthProtocol
			if auth == "" {
				auth = "none"
			}
			priv := u.PrivProtocol
			if priv == "" {
				priv = "none"
			}
			fmt.Printf("  %s: auth=%s priv=%s\n", name, auth, priv)
		}
	}
	return nil
}

func (c *CLI) showSNMPv3() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil || cfg.System.SNMP == nil || len(cfg.System.SNMP.V3Users) == 0 {
		fmt.Println("No SNMPv3 users configured")
		return nil
	}
	fmt.Println("SNMPv3 USM Users:")
	fmt.Printf("  %-20s %-12s %-12s\n", "User", "Auth", "Privacy")
	for _, u := range cfg.System.SNMP.V3Users {
		auth := u.AuthProtocol
		if auth == "" {
			auth = "none"
		}
		priv := u.PrivProtocol
		if priv == "" {
			priv = "none"
		}
		fmt.Printf("  %-20s %-12s %-12s\n", u.Name, auth, priv)
	}
	return nil
}

func (c *CLI) showLLDP() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil || cfg.Protocols.LLDP == nil {
		fmt.Println("LLDP not configured")
		return nil
	}
	lldpCfg := cfg.Protocols.LLDP
	if lldpCfg.Disable {
		fmt.Println("LLDP: disabled")
		return nil
	}
	fmt.Println("LLDP:")
	interval := lldpCfg.Interval
	if interval <= 0 {
		interval = 30
	}
	holdMult := lldpCfg.HoldMultiplier
	if holdMult <= 0 {
		holdMult = 4
	}
	fmt.Printf("  Transmit interval: %ds\n", interval)
	fmt.Printf("  Hold multiplier:   %d\n", holdMult)
	fmt.Printf("  Hold time:         %ds\n", interval*holdMult)
	if len(lldpCfg.Interfaces) > 0 {
		var ifNames []string
		for _, iface := range lldpCfg.Interfaces {
			if iface.Disable {
				ifNames = append(ifNames, iface.Name+" (disabled)")
			} else {
				ifNames = append(ifNames, iface.Name)
			}
		}
		fmt.Printf("  Interfaces:        %s\n", strings.Join(ifNames, ", "))
	}
	if c.lldpNeighborsFn != nil {
		neighbors := c.lldpNeighborsFn()
		fmt.Printf("  Neighbors:         %d\n", len(neighbors))
	}
	return nil
}

func (c *CLI) showLLDPNeighbors() error {
	if c.lldpNeighborsFn == nil {
		fmt.Println("LLDP not running")
		return nil
	}
	neighbors := c.lldpNeighborsFn()
	if len(neighbors) == 0 {
		fmt.Println("No LLDP neighbors discovered")
		return nil
	}
	fmt.Printf("%-12s %-20s %-16s %-20s %-6s %s\n",
		"Interface", "Chassis ID", "Port ID", "System Name", "TTL", "Age")
	for _, n := range neighbors {
		age := time.Since(n.LastSeen).Truncate(time.Second)
		fmt.Printf("%-12s %-20s %-16s %-20s %-6d %s\n",
			n.Interface, n.ChassisID, n.PortID, n.SystemName, n.TTL, age)
	}
	return nil
}

// showPortMirroring displays port mirroring (SPAN) configuration.

func (c *CLI) showPortMirroring() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}

	pm := cfg.ForwardingOptions.PortMirroring
	if pm == nil || len(pm.Instances) == 0 {
		fmt.Println("No port-mirroring instances configured")
		return nil
	}

	for name, inst := range pm.Instances {
		fmt.Printf("Instance: %s\n", name)
		if inst.InputRate > 0 {
			fmt.Printf("  Input rate: 1/%d\n", inst.InputRate)
		} else {
			fmt.Printf("  Input rate: all packets\n")
		}
		if len(inst.Input) > 0 {
			fmt.Printf("  Input interfaces: %s\n", strings.Join(inst.Input, ", "))
		}
		if inst.Output != "" {
			fmt.Printf("  Output interface: %s\n", inst.Output)
		}
		fmt.Println()
	}
	return nil
}
