package cli

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

func (c *CLI) showNATSource(cfg *config.Config, args []string) error {
	// Sub-command dispatch: summary, pool <name>, rule-set <name>, rule all
	if len(args) > 0 {
		switch args[0] {
		case "summary":
			return c.showNATSourceSummary(cfg)
		case "pool":
			poolName := ""
			if len(args) > 1 {
				poolName = args[1]
			}
			return c.showNATSourcePool(cfg, poolName)
		case "rule":
			if len(args) > 1 && args[1] == "detail" {
				return c.showNATSourceRuleDetail(cfg)
			}
			return c.showNATSourceRuleAll(cfg)
		case "rule-set":
			if len(args) > 1 {
				return c.showNATSourceRuleSet(cfg, args[1])
			}
			return fmt.Errorf("usage: show security nat source rule-set <name>")
		}
	}

	// Default: show all pools, rules, and summary
	if cfg != nil && cfg.Security.NAT.AddressPersistent {
		fmt.Println("Address-persistent: enabled")
		fmt.Println()
	}
	// Show configured source NAT pools
	if cfg != nil && len(cfg.Security.NAT.SourcePools) > 0 {
		fmt.Println("Source NAT pools:")
		for name, pool := range cfg.Security.NAT.SourcePools {
			fmt.Printf("  Pool: %s\n", name)
			for _, addr := range pool.Addresses {
				fmt.Printf("    Address: %s\n", addr)
			}
			portLow, portHigh := pool.PortLow, pool.PortHigh
			if portLow == 0 {
				portLow = 1024
			}
			if portHigh == 0 {
				portHigh = 65535
			}
			fmt.Printf("    Port range: %d-%d\n", portLow, portHigh)
		}
		fmt.Println()
	}

	// Show configured source NAT rules
	if cfg != nil {
		for _, rs := range cfg.Security.NAT.Source {
			fmt.Printf("Source NAT rule-set: %s\n", rs.Name)
			fmt.Printf("  From zone: %s, To zone: %s\n", rs.FromZone, rs.ToZone)
			for _, rule := range rs.Rules {
				action := "interface"
				if rule.Then.PoolName != "" {
					action = "pool " + rule.Then.PoolName
				}
				fmt.Printf("  Rule: %s -> %s\n", rule.Name, action)
				if rule.Match.SourceAddress != "" {
					fmt.Printf("    Match source-address: %s\n", rule.Match.SourceAddress)
				}
			}
			fmt.Println()
		}
	}

	// Show summary of active SNAT sessions
	if c.dp == nil || !c.dp.IsLoaded() {
		return nil
	}

	snatCount := 0
	_ = c.dp.IterateSessions(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		if val.IsReverse != 0 {
			return true
		}
		if val.Flags&dataplane.SessFlagSNAT != 0 {
			snatCount++
		}
		return true
	})
	_ = c.dp.IterateSessionsV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		if val.IsReverse != 0 {
			return true
		}
		if val.Flags&dataplane.SessFlagSNAT != 0 {
			snatCount++
		}
		return true
	})
	fmt.Printf("Active SNAT sessions: %d\n", snatCount)

	// Show NAT alloc fail counter
	if allocFails, err := c.dp.ReadGlobalCounter(dataplane.GlobalCtrNATAllocFail); err == nil {
		fmt.Printf("NAT allocation failures: %d\n", allocFails)
	}

	return nil
}

// showNATSourceSummary displays a Junos-style summary of all source NAT pools.

func (c *CLI) showNATSourceSummary(cfg *config.Config) error {
	if cfg == nil {
		fmt.Println("No source NAT configured")
		return nil
	}

	// Count pools: named pools + interface-mode rules
	type ruleSetKey struct{ from, to string }
	type poolInfo struct {
		name    string
		address string
		total   int // total ports (0 = N/A for interface)
		used    int
		isIface bool
		key     ruleSetKey
	}
	var pools []poolInfo

	// Named pools
	for name, pool := range cfg.Security.NAT.SourcePools {
		portLow, portHigh := pool.PortLow, pool.PortHigh
		if portLow == 0 {
			portLow = 1024
		}
		if portHigh == 0 {
			portHigh = 65535
		}
		totalPorts := (portHigh - portLow + 1) * len(pool.Addresses)
		addr := strings.Join(pool.Addresses, ",")
		pools = append(pools, poolInfo{name: name, address: addr, total: totalPorts})
	}

	// Interface-mode pools (count from rules, deduplicated by zone pair).
	ifacePoolSeen := make(map[ruleSetKey]struct{})
	for _, rs := range cfg.Security.NAT.Source {
		key := ruleSetKey{from: rs.FromZone, to: rs.ToZone}
		for _, rule := range rs.Rules {
			if rule.Then.Interface {
				if _, exists := ifacePoolSeen[key]; exists {
					continue
				}
				ifacePoolSeen[key] = struct{}{}
				pools = append(pools, poolInfo{
					name:    fmt.Sprintf("%s/%s (interface)", rs.FromZone, rs.ToZone),
					address: "interface",
					isIface: true,
					key:     key,
				})
			}
		}
	}

	// Count active SNAT translations and per-rule-set sessions
	totalSNAT := 0
	rsSessions := make(map[ruleSetKey]int)
	if c.dp != nil && c.dp.IsLoaded() {
		cr := c.applyResult()
		// Build reverse zone ID map
		var zoneByID map[uint16]string
		if cr != nil {
			zoneByID = make(map[uint16]string, len(cr.ZoneIDs))
			for name, id := range cr.ZoneIDs {
				zoneByID[id] = name
			}
			for i := range pools {
				if pools[i].isIface {
					continue
				}
				if id, ok := cr.PoolIDs[pools[i].name]; ok {
					cnt, err := c.dp.ReadNATPortCounter(uint32(id))
					if err == nil {
						pools[i].used = int(cnt)
					}
				}
			}
		}
		// Count SNAT sessions per zone pair
		_ = c.dp.IterateSessions(func(_ dataplane.SessionKey, val dataplane.SessionValue) bool {
			if val.IsReverse == 0 && val.Flags&dataplane.SessFlagSNAT != 0 {
				totalSNAT++
				if zoneByID != nil {
					rsSessions[ruleSetKey{zoneByID[val.IngressZone], zoneByID[val.EgressZone]}]++
				}
			}
			return true
		})
		// Count IPv6 SNAT sessions
		_ = c.dp.IterateSessionsV6(func(_ dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
			if val.IsReverse == 0 && val.Flags&dataplane.SessFlagSNAT != 0 {
				totalSNAT++
				if zoneByID != nil {
					rsSessions[ruleSetKey{zoneByID[val.IngressZone], zoneByID[val.EgressZone]}]++
				}
			}
			return true
		})
		for i := range pools {
			if pools[i].isIface {
				pools[i].used = rsSessions[pools[i].key]
			}
		}
	}

	fmt.Printf("Total active translations: %d\n", totalSNAT)
	fmt.Printf("Total pools: %d\n", len(pools))
	fmt.Println()
	fmt.Printf("%-20s %-20s %-8s %-8s %-12s %-12s\n",
		"Pool", "Address", "Ports", "Used", "Available", "Utilization")
	for _, p := range pools {
		ports := "N/A"
		avail := "N/A"
		util := "N/A"
		if p.total > 0 {
			ports = fmt.Sprintf("%d", p.total)
			a := p.total - p.used
			if a < 0 {
				a = 0
			}
			avail = fmt.Sprintf("%d", a)
			util = fmt.Sprintf("%.1f%%", float64(p.used)/float64(p.total)*100)
		}
		fmt.Printf("%-20s %-20s %-8s %-8d %-12s %-12s\n",
			p.name, p.address, ports, p.used, avail, util)
	}

	// Per-rule-set session counts
	if len(rsSessions) > 0 {
		fmt.Println()
		fmt.Printf("%-30s %-12s\n", "Rule-set (from -> to)", "Sessions")
		for _, rs := range cfg.Security.NAT.Source {
			key := ruleSetKey{rs.FromZone, rs.ToZone}
			if cnt, ok := rsSessions[key]; ok {
				fmt.Printf("%-30s %-12d\n",
					fmt.Sprintf("%s -> %s", rs.FromZone, rs.ToZone), cnt)
			}
		}
	}
	return nil
}

// showNATSourcePool displays detailed information about a specific NAT pool.

func (c *CLI) showNATSourcePool(cfg *config.Config, poolName string) error {
	if cfg == nil {
		fmt.Println("No source NAT configured")
		return nil
	}

	// If poolName is empty or "all", show all pools
	showAll := poolName == "" || poolName == "all"

	for name, pool := range cfg.Security.NAT.SourcePools {
		if !showAll && name != poolName {
			continue
		}

		portLow, portHigh := pool.PortLow, pool.PortHigh
		if portLow == 0 {
			portLow = 1024
		}
		if portHigh == 0 {
			portHigh = 65535
		}
		totalPorts := (portHigh - portLow + 1) * len(pool.Addresses)

		fmt.Printf("Pool name: %s\n", name)
		for _, addr := range pool.Addresses {
			fmt.Printf("  Address: %s\n", addr)
		}
		fmt.Printf("  Port range: %d-%d\n", portLow, portHigh)

		if c.dp != nil && c.dp.IsLoaded() {
			if cr := c.applyResult(); cr != nil {
				if id, ok := cr.PoolIDs[name]; ok {
					cnt, err := c.dp.ReadNATPortCounter(uint32(id))
					if err == nil {
						avail := totalPorts - int(cnt)
						if avail < 0 {
							avail = 0
						}
						fmt.Printf("  Ports allocated: %d\n", cnt)
						fmt.Printf("  Ports available: %d\n", avail)
						if totalPorts > 0 {
							fmt.Printf("  Utilization: %.1f%%\n",
								float64(cnt)/float64(totalPorts)*100)
						}
					}
				}
			}
		}
		fmt.Println()
	}

	if !showAll {
		if _, ok := cfg.Security.NAT.SourcePools[poolName]; !ok {
			fmt.Printf("Pool %q not found\n", poolName)
		}
	}
	return nil
}

// showNATSourceRuleSet displays a specific source NAT rule-set with hit counters.

func (c *CLI) showNATSourceRuleSet(cfg *config.Config, rsName string) error {
	if cfg == nil {
		fmt.Println("No source NAT configured")
		return nil
	}

	for _, rs := range cfg.Security.NAT.Source {
		if rs.Name != rsName {
			continue
		}
		fmt.Printf("Rule-set: %s\n", rs.Name)
		fmt.Printf("  From zone: %s  To zone: %s\n", rs.FromZone, rs.ToZone)
		for _, rule := range rs.Rules {
			action := "interface"
			if rule.Then.PoolName != "" {
				action = "pool " + rule.Then.PoolName
			}
			fmt.Printf("  Rule: %s\n", rule.Name)
			srcMatch := "0.0.0.0/0"
			if rule.Match.SourceAddress != "" {
				srcMatch = rule.Match.SourceAddress
			}
			dstMatch := "0.0.0.0/0"
			if rule.Match.DestinationAddress != "" {
				dstMatch = rule.Match.DestinationAddress
			}
			fmt.Printf("    Match: source %s destination %s\n", srcMatch, dstMatch)
			fmt.Printf("    Action: %s\n", action)

			// Show hit counters if dataplane is loaded
			if c.dp != nil && c.applyResult() != nil {
				ruleKey := rs.Name + "/" + rule.Name
				if cid, ok := c.applyResult().NATCounterIDs[ruleKey]; ok {
					cnt, err := c.dp.ReadNATRuleCounter(uint32(cid))
					if err == nil {
						fmt.Printf("    Translation hits: %d packets  %d bytes\n",
							cnt.Packets, cnt.Bytes)
					}
				}
			}
		}
		fmt.Println()
		return nil
	}
	fmt.Printf("Rule-set %q not found\n", rsName)
	return nil
}

// showNATSourceRuleAll displays all source NAT rules across all rule-sets with hit counters.

func (c *CLI) showNATSourceRuleAll(cfg *config.Config) error {
	if cfg == nil || len(cfg.Security.NAT.Source) == 0 {
		fmt.Println("No source NAT rules configured")
		return nil
	}

	totalRules := 0
	for _, rs := range cfg.Security.NAT.Source {
		for _, rule := range rs.Rules {
			totalRules++
			action := "interface"
			if rule.Then.PoolName != "" {
				action = "pool " + rule.Then.PoolName
			}
			srcMatch := "0.0.0.0/0"
			if rule.Match.SourceAddress != "" {
				srcMatch = rule.Match.SourceAddress
			}
			dstMatch := "0.0.0.0/0"
			if rule.Match.DestinationAddress != "" {
				dstMatch = rule.Match.DestinationAddress
			}

			fmt.Printf("Rule-set: %-20s Rule: %-12s %s -> %s  Action: %s\n",
				rs.Name, rule.Name, rs.FromZone, rs.ToZone, action)
			fmt.Printf("  Match: source %s destination %s\n", srcMatch, dstMatch)

			if c.dp != nil && c.applyResult() != nil {
				ruleKey := rs.Name + "/" + rule.Name
				if cid, ok := c.applyResult().NATCounterIDs[ruleKey]; ok {
					cnt, err := c.dp.ReadNATRuleCounter(uint32(cid))
					if err == nil {
						fmt.Printf("  Translation hits: %d packets  %d bytes\n",
							cnt.Packets, cnt.Bytes)
					}
				}
			}
		}
	}
	fmt.Printf("\nTotal source NAT rules: %d\n", totalRules)
	return nil
}

// showNATSourceRuleDetail displays Junos-style detailed source NAT rules.

func (c *CLI) showNATSourceRuleDetail(cfg *config.Config) error {
	if cfg == nil || len(cfg.Security.NAT.Source) == 0 {
		fmt.Println("No source NAT rules configured")
		return nil
	}

	// Count active SNAT sessions per rule-set
	type ruleSetKey struct{ from, to string }
	rsSessions := make(map[ruleSetKey]int)
	if c.dp != nil && c.dp.IsLoaded() && c.applyResult() != nil {
		cr := c.applyResult()
		zoneByID := make(map[uint16]string, len(cr.ZoneIDs))
		for name, id := range cr.ZoneIDs {
			zoneByID[id] = name
		}
		_ = c.dp.IterateSessions(func(_ dataplane.SessionKey, val dataplane.SessionValue) bool {
			if val.IsReverse == 0 && val.Flags&dataplane.SessFlagSNAT != 0 {
				rsSessions[ruleSetKey{zoneByID[val.IngressZone], zoneByID[val.EgressZone]}]++
			}
			return true
		})
		_ = c.dp.IterateSessionsV6(func(_ dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
			if val.IsReverse == 0 && val.Flags&dataplane.SessFlagSNAT != 0 {
				rsSessions[ruleSetKey{zoneByID[val.IngressZone], zoneByID[val.EgressZone]}]++
			}
			return true
		})
	}

	ruleIdx := 0
	for _, rs := range cfg.Security.NAT.Source {
		for _, rule := range rs.Rules {
			ruleIdx++
			action := "interface"
			if rule.Then.PoolName != "" {
				action = "pool " + rule.Then.PoolName
			} else if rule.Then.Off {
				action = "off"
			}
			srcMatch := "0.0.0.0/0"
			if rule.Match.SourceAddress != "" {
				srcMatch = rule.Match.SourceAddress
			}
			dstMatch := "0.0.0.0/0"
			if rule.Match.DestinationAddress != "" {
				dstMatch = rule.Match.DestinationAddress
			}

			fmt.Printf("source NAT rule: %s\n", rule.Name)
			fmt.Printf("  Rule-set: %s                        ID: %d\n", rs.Name, ruleIdx)
			fmt.Printf("    From zone: %s    To zone: %s\n", rs.FromZone, rs.ToZone)
			fmt.Printf("    Match:\n")
			fmt.Printf("      Source addresses:      %s\n", srcMatch)
			fmt.Printf("      Destination addresses: %s\n", dstMatch)
			if rule.Match.Protocol != "" {
				fmt.Printf("      IP protocol:           %s\n", rule.Match.Protocol)
			}
			fmt.Printf("    Action:                  %s\n", action)

			if rule.Then.PoolName != "" && cfg.Security.NAT.SourcePools != nil {
				if pool, ok := cfg.Security.NAT.SourcePools[rule.Then.PoolName]; ok {
					if pool.PersistentNAT != nil {
						fmt.Printf("    Persistent NAT:          enabled\n")
					}
					if len(pool.Addresses) > 0 {
						fmt.Printf("    Pool addresses:          %s\n", strings.Join(pool.Addresses, ", "))
					}
					portLow, portHigh := pool.PortLow, pool.PortHigh
					if portLow == 0 {
						portLow = 1024
					}
					if portHigh == 0 {
						portHigh = 65535
					}
					fmt.Printf("    Port range:              %d-%d\n", portLow, portHigh)
				}
			}

			if c.dp != nil && c.applyResult() != nil {
				ruleKey := rs.Name + "/" + rule.Name
				if cid, ok := c.applyResult().NATCounterIDs[ruleKey]; ok {
					cnt, err := c.dp.ReadNATRuleCounter(uint32(cid))
					if err == nil {
						fmt.Printf("    Translation hits:        %d packets  %d bytes\n",
							cnt.Packets, cnt.Bytes)
					}
				}
			}

			sessions := rsSessions[ruleSetKey{rs.FromZone, rs.ToZone}]
			fmt.Printf("    Number of sessions:      %d\n", sessions)
			fmt.Println()
		}
	}
	return nil
}

func (c *CLI) showNATDestination(cfg *config.Config, args []string) error {
	if cfg == nil || cfg.Security.NAT.Destination == nil {
		fmt.Println("No destination NAT rules configured.")
		return nil
	}

	// Sub-command dispatch: summary, pool <name>, rule-set <name>, rule all
	if len(args) > 0 {
		switch args[0] {
		case "summary":
			return c.showNATDestinationSummary(cfg)
		case "pool":
			poolName := ""
			if len(args) > 1 {
				poolName = args[1]
			}
			return c.showNATDestinationPool(cfg, poolName)
		case "rule":
			if len(args) > 1 && args[1] == "detail" {
				return c.showNATDestinationRuleDetail(cfg)
			}
			return c.showNATDestinationRuleAll(cfg)
		case "rule-set":
			if len(args) > 1 {
				return c.showNATDestinationRuleSet(cfg, args[1])
			}
			return fmt.Errorf("usage: show security nat destination rule-set <name>")
		}
	}

	dnat := cfg.Security.NAT.Destination

	// Show destination NAT pools
	if len(dnat.Pools) > 0 {
		fmt.Println("Destination NAT pools:")
		for name, pool := range dnat.Pools {
			fmt.Printf("  Pool: %s\n", name)
			fmt.Printf("    Address: %s\n", pool.Address)
			if pool.Port != 0 {
				fmt.Printf("    Port: %d\n", pool.Port)
			}
		}
		fmt.Println()
	}

	// Show destination NAT rule sets
	for _, rs := range dnat.RuleSets {
		fmt.Printf("Destination NAT rule-set: %s\n", rs.Name)
		fmt.Printf("  From zone: %s, To zone: %s\n", rs.FromZone, rs.ToZone)
		for _, rule := range rs.Rules {
			fmt.Printf("  Rule: %s\n", rule.Name)
			if rule.Match.DestinationAddress != "" {
				fmt.Printf("    Match destination-address: %s\n", rule.Match.DestinationAddress)
			}
			if rule.Match.DestinationPort != 0 {
				fmt.Printf("    Match destination-port: %d\n", rule.Match.DestinationPort)
			}
			if rule.Then.PoolName != "" {
				fmt.Printf("    Then pool: %s\n", rule.Then.PoolName)
			}

			// Show hit counters if dataplane is loaded
			if c.dp != nil && c.applyResult() != nil {
				ruleKey := rs.Name + "/" + rule.Name
				if cid, ok := c.applyResult().NATCounterIDs[ruleKey]; ok {
					cnt, err := c.dp.ReadNATRuleCounter(uint32(cid))
					if err == nil {
						fmt.Printf("    Translation hits: %d packets  %d bytes\n",
							cnt.Packets, cnt.Bytes)
					}
				}
			}
		}
		fmt.Println()
	}

	// Show summary of active DNAT sessions
	if c.dp != nil && c.dp.IsLoaded() {
		dnatCount := 0
		_ = c.dp.IterateSessions(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
			if val.IsReverse != 0 {
				return true
			}
			if val.Flags&dataplane.SessFlagDNAT != 0 {
				dnatCount++
			}
			return true
		})
		_ = c.dp.IterateSessionsV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
			if val.IsReverse != 0 {
				return true
			}
			if val.Flags&dataplane.SessFlagDNAT != 0 {
				dnatCount++
			}
			return true
		})
		fmt.Printf("Active DNAT sessions: %d\n", dnatCount)
	}

	return nil
}

// showNATDestinationSummary displays a summary of all destination NAT pools.

func (c *CLI) showNATDestinationSummary(cfg *config.Config) error {
	dnat := cfg.Security.NAT.Destination
	if dnat == nil || len(dnat.Pools) == 0 {
		fmt.Println("No destination NAT pools configured")
		return nil
	}

	// Count active DNAT sessions per pool and per rule-set
	poolHits := make(map[string]int)
	totalDNAT := 0
	type ruleSetKey struct{ from, to string }
	rsSessions := make(map[ruleSetKey]int)

	if c.dp != nil && c.dp.IsLoaded() && c.applyResult() != nil {
		cr := c.applyResult()
		for _, rs := range dnat.RuleSets {
			for _, rule := range rs.Rules {
				if rule.Then.PoolName == "" {
					continue
				}
				ruleKey := rs.Name + "/" + rule.Name
				if cid, ok := cr.NATCounterIDs[ruleKey]; ok {
					cnt, err := c.dp.ReadNATRuleCounter(uint32(cid))
					if err == nil {
						poolHits[rule.Then.PoolName] += int(cnt.Packets)
					}
				}
			}
		}

		// Count active DNAT sessions by iterating sessions
		zoneByID := make(map[uint16]string, len(cr.ZoneIDs))
		for name, id := range cr.ZoneIDs {
			zoneByID[id] = name
		}
		_ = c.dp.IterateSessions(func(_ dataplane.SessionKey, val dataplane.SessionValue) bool {
			if val.IsReverse == 0 && val.Flags&dataplane.SessFlagDNAT != 0 {
				totalDNAT++
				rsSessions[ruleSetKey{zoneByID[val.IngressZone], zoneByID[val.EgressZone]}]++
			}
			return true
		})
		_ = c.dp.IterateSessionsV6(func(_ dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
			if val.IsReverse == 0 && val.Flags&dataplane.SessFlagDNAT != 0 {
				totalDNAT++
				rsSessions[ruleSetKey{zoneByID[val.IngressZone], zoneByID[val.EgressZone]}]++
			}
			return true
		})
	}

	fmt.Printf("Total active translations: %d\n", totalDNAT)
	fmt.Printf("Total pools: %d\n", len(dnat.Pools))
	fmt.Println()
	fmt.Printf("%-20s %-20s %-8s %-12s\n",
		"Pool", "Address", "Port", "Hits")
	for name, pool := range dnat.Pools {
		portStr := "-"
		if pool.Port != 0 {
			portStr = fmt.Sprintf("%d", pool.Port)
		}
		hits := poolHits[name]
		fmt.Printf("%-20s %-20s %-8s %-12d\n",
			name, pool.Address, portStr, hits)
	}

	// Per-rule-set session counts
	if len(rsSessions) > 0 {
		fmt.Println()
		fmt.Printf("%-30s %-12s\n", "Rule-set (from -> to)", "Sessions")
		for _, rs := range dnat.RuleSets {
			key := ruleSetKey{rs.FromZone, rs.ToZone}
			if cnt, ok := rsSessions[key]; ok {
				fmt.Printf("%-30s %-12d\n",
					fmt.Sprintf("%s -> %s", rs.FromZone, rs.ToZone), cnt)
			}
		}
	}
	return nil
}

// showNATDestinationPool displays detailed information about a specific DNAT pool.

func (c *CLI) showNATDestinationPool(cfg *config.Config, poolName string) error {
	dnat := cfg.Security.NAT.Destination
	if dnat == nil || len(dnat.Pools) == 0 {
		fmt.Println("No destination NAT pools configured")
		return nil
	}

	showAll := poolName == "" || poolName == "all"

	for name, pool := range dnat.Pools {
		if !showAll && name != poolName {
			continue
		}
		fmt.Printf("Pool name: %s\n", name)
		fmt.Printf("  Address: %s\n", pool.Address)
		if pool.Port != 0 {
			fmt.Printf("  Port: %d\n", pool.Port)
		}

		// Show which rule-sets reference this pool
		for _, rs := range dnat.RuleSets {
			for _, rule := range rs.Rules {
				if rule.Then.PoolName == name {
					fmt.Printf("  Referenced by: %s/%s (from %s)\n",
						rs.Name, rule.Name, rs.FromZone)
				}
			}
		}

		// Show hit counters from all rules referencing this pool
		if c.dp != nil && c.applyResult() != nil {
			cr := c.applyResult()
			var totalPkts, totalBytes uint64
			for _, rs := range dnat.RuleSets {
				for _, rule := range rs.Rules {
					if rule.Then.PoolName != name {
						continue
					}
					ruleKey := rs.Name + "/" + rule.Name
					if cid, ok := cr.NATCounterIDs[ruleKey]; ok {
						cnt, err := c.dp.ReadNATRuleCounter(uint32(cid))
						if err == nil {
							totalPkts += cnt.Packets
							totalBytes += cnt.Bytes
						}
					}
				}
			}
			fmt.Printf("  Total hits: %d packets  %d bytes\n", totalPkts, totalBytes)
		}
		fmt.Println()
	}

	if !showAll {
		if _, ok := dnat.Pools[poolName]; !ok {
			fmt.Printf("Pool %q not found\n", poolName)
		}
	}
	return nil
}

// showNATDestinationRuleSet displays a specific destination NAT rule-set with hit counters.

func (c *CLI) showNATDestinationRuleSet(cfg *config.Config, rsName string) error {
	dnat := cfg.Security.NAT.Destination
	if dnat == nil {
		fmt.Println("No destination NAT configured")
		return nil
	}

	for _, rs := range dnat.RuleSets {
		if rs.Name != rsName {
			continue
		}
		fmt.Printf("Rule-set: %s\n", rs.Name)
		fmt.Printf("  From zone: %s  To zone: %s\n", rs.FromZone, rs.ToZone)
		for _, rule := range rs.Rules {
			fmt.Printf("  Rule: %s\n", rule.Name)
			dstMatch := "0.0.0.0/0"
			if rule.Match.DestinationAddress != "" {
				dstMatch = rule.Match.DestinationAddress
			}
			fmt.Printf("    Match destination-address: %s\n", dstMatch)
			if rule.Match.DestinationPort != 0 {
				fmt.Printf("    Match destination-port: %d\n", rule.Match.DestinationPort)
			}
			action := "off"
			if rule.Then.PoolName != "" {
				action = "pool " + rule.Then.PoolName
			}
			fmt.Printf("    Action: %s\n", action)

			// Show hit counters if dataplane is loaded
			if c.dp != nil && c.applyResult() != nil {
				ruleKey := rs.Name + "/" + rule.Name
				if cid, ok := c.applyResult().NATCounterIDs[ruleKey]; ok {
					cnt, err := c.dp.ReadNATRuleCounter(uint32(cid))
					if err == nil {
						fmt.Printf("    Translation hits: %d packets  %d bytes\n",
							cnt.Packets, cnt.Bytes)
					}
				}
			}
		}
		fmt.Println()
		return nil
	}
	fmt.Printf("Rule-set %q not found\n", rsName)
	return nil
}

// showNATDestinationRuleAll displays all destination NAT rules with hit counters.

func (c *CLI) showNATDestinationRuleAll(cfg *config.Config) error {
	dnat := cfg.Security.NAT.Destination
	if dnat == nil || len(dnat.RuleSets) == 0 {
		fmt.Println("No destination NAT rules configured")
		return nil
	}

	totalRules := 0
	for _, rs := range dnat.RuleSets {
		for _, rule := range rs.Rules {
			totalRules++
			dstMatch := "0.0.0.0/0"
			if rule.Match.DestinationAddress != "" {
				dstMatch = rule.Match.DestinationAddress
			}
			if rule.Match.DestinationPort != 0 {
				dstMatch += fmt.Sprintf(":%d", rule.Match.DestinationPort)
			}
			action := "off"
			if rule.Then.PoolName != "" {
				action = "pool " + rule.Then.PoolName
			}

			fmt.Printf("Rule-set: %-20s Rule: %-12s from %s  Action: %s\n",
				rs.Name, rule.Name, rs.FromZone, action)
			fmt.Printf("  Match: destination %s\n", dstMatch)

			if c.dp != nil && c.applyResult() != nil {
				ruleKey := rs.Name + "/" + rule.Name
				if cid, ok := c.applyResult().NATCounterIDs[ruleKey]; ok {
					cnt, err := c.dp.ReadNATRuleCounter(uint32(cid))
					if err == nil {
						fmt.Printf("  Translation hits: %d packets  %d bytes\n",
							cnt.Packets, cnt.Bytes)
					}
				}
			}
		}
	}
	fmt.Printf("\nTotal destination NAT rules: %d\n", totalRules)
	return nil
}

// showNATDestinationRuleDetail displays Junos-style detailed destination NAT rules.

func (c *CLI) showNATDestinationRuleDetail(cfg *config.Config) error {
	dnat := cfg.Security.NAT.Destination
	if dnat == nil || len(dnat.RuleSets) == 0 {
		fmt.Println("No destination NAT rules configured")
		return nil
	}

	// Count active DNAT sessions per rule-set
	type ruleSetKey struct{ from, to string }
	rsSessions := make(map[ruleSetKey]int)
	if c.dp != nil && c.dp.IsLoaded() && c.applyResult() != nil {
		cr := c.applyResult()
		zoneByID := make(map[uint16]string, len(cr.ZoneIDs))
		for name, id := range cr.ZoneIDs {
			zoneByID[id] = name
		}
		_ = c.dp.IterateSessions(func(_ dataplane.SessionKey, val dataplane.SessionValue) bool {
			if val.IsReverse == 0 && val.Flags&dataplane.SessFlagDNAT != 0 {
				rsSessions[ruleSetKey{zoneByID[val.IngressZone], zoneByID[val.EgressZone]}]++
			}
			return true
		})
		_ = c.dp.IterateSessionsV6(func(_ dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
			if val.IsReverse == 0 && val.Flags&dataplane.SessFlagDNAT != 0 {
				rsSessions[ruleSetKey{zoneByID[val.IngressZone], zoneByID[val.EgressZone]}]++
			}
			return true
		})
	}

	ruleIdx := 0
	for _, rs := range dnat.RuleSets {
		for _, rule := range rs.Rules {
			ruleIdx++
			action := "off"
			if rule.Then.PoolName != "" {
				action = "pool " + rule.Then.PoolName
			}
			dstMatch := "0.0.0.0/0"
			if rule.Match.DestinationAddress != "" {
				dstMatch = rule.Match.DestinationAddress
			}

			fmt.Printf("destination NAT rule: %s\n", rule.Name)
			fmt.Printf("  Rule-set: %s                        ID: %d\n", rs.Name, ruleIdx)
			fmt.Printf("    From zone: %s    To zone: %s\n", rs.FromZone, rs.ToZone)
			fmt.Printf("    Match:\n")
			fmt.Printf("      Destination addresses: %s\n", dstMatch)
			if rule.Match.DestinationPort != 0 {
				fmt.Printf("      Destination port:      %d\n", rule.Match.DestinationPort)
			}
			if rule.Match.Protocol != "" {
				fmt.Printf("      IP protocol:           %s\n", rule.Match.Protocol)
			}
			if rule.Match.Application != "" {
				fmt.Printf("      Application:           %s\n", rule.Match.Application)
			}
			fmt.Printf("    Action:                  %s\n", action)

			if rule.Then.PoolName != "" && dnat.Pools != nil {
				if pool, ok := dnat.Pools[rule.Then.PoolName]; ok {
					fmt.Printf("    Pool address:            %s\n", pool.Address)
					if pool.Port != 0 {
						fmt.Printf("    Pool port:               %d\n", pool.Port)
					}
				}
			}

			if c.dp != nil && c.applyResult() != nil {
				ruleKey := rs.Name + "/" + rule.Name
				if cid, ok := c.applyResult().NATCounterIDs[ruleKey]; ok {
					cnt, err := c.dp.ReadNATRuleCounter(uint32(cid))
					if err == nil {
						fmt.Printf("    Translation hits:        %d packets  %d bytes\n",
							cnt.Packets, cnt.Bytes)
					}
				}
			}

			sessions := rsSessions[ruleSetKey{rs.FromZone, rs.ToZone}]
			fmt.Printf("    Number of sessions:      %d\n", sessions)
			fmt.Println()
		}
	}
	return nil
}

func (c *CLI) showNATStatic(cfg *config.Config) error {
	if cfg == nil || len(cfg.Security.NAT.Static) == 0 {
		fmt.Println("No static NAT rules configured.")
		return nil
	}

	for _, rs := range cfg.Security.NAT.Static {
		fmt.Printf("Static NAT rule-set: %s\n", rs.Name)
		fmt.Printf("  From zone: %s\n", rs.FromZone)
		for _, rule := range rs.Rules {
			fmt.Printf("  Rule: %s\n", rule.Name)
			fmt.Printf("    Match destination-address: %s\n", rule.Match)
			if rule.IsNPTv6 {
				fmt.Printf("    Then nptv6-prefix:         %s\n", rule.Then)
			} else {
				fmt.Printf("    Then static-nat prefix:    %s\n", rule.Then)
			}
		}
		fmt.Println()
	}

	return nil
}

func (c *CLI) showNAT64(cfg *config.Config) error {
	if cfg == nil || len(cfg.Security.NAT.NAT64) == 0 {
		fmt.Println("No NAT64 rule-sets configured.")
		return nil
	}

	for _, rs := range cfg.Security.NAT.NAT64 {
		fmt.Printf("NAT64 rule-set: %s\n", rs.Name)
		if rs.Prefix != "" {
			fmt.Printf("  Prefix:      %s\n", rs.Prefix)
		}
		if rs.SourcePool != "" {
			fmt.Printf("  Source pool:  %s\n", rs.SourcePool)
		}
		fmt.Println()
	}

	return nil
}

func (c *CLI) showPersistentNAT() error {
	if c.dp == nil || c.dp.GetPersistentNAT() == nil {
		fmt.Println("Persistent NAT table not available")
		return nil
	}
	bindings := c.dp.GetPersistentNAT().All()
	if len(bindings) == 0 {
		fmt.Println("No persistent NAT bindings")
		return nil
	}
	fmt.Printf("Total persistent NAT bindings: %d\n\n", len(bindings))
	fmt.Printf("%-20s %-8s %-20s %-8s %-15s %-10s\n",
		"Source IP", "SrcPort", "NAT IP", "NATPort", "Pool", "Timeout")
	for _, b := range bindings {
		remaining := time.Until(b.LastSeen.Add(b.Timeout))
		if remaining < 0 {
			remaining = 0
		}
		fmt.Printf("%-20s %-8d %-20s %-8d %-15s %-10s\n",
			b.SrcIP, b.SrcPort, b.NatIP, b.NatPort, b.PoolName,
			remaining.Truncate(time.Second))
	}
	return nil
}

// showPersistentNATDetail displays detailed persistent NAT bindings with session counts and age.

func (c *CLI) showPersistentNATDetail() error {
	if c.dp == nil || c.dp.GetPersistentNAT() == nil {
		fmt.Println("Persistent NAT table not available")
		return nil
	}
	bindings := c.dp.GetPersistentNAT().All()
	if len(bindings) == 0 {
		fmt.Println("No persistent NAT bindings")
		return nil
	}

	// #1152: natKey uses a unified `netip.Addr` so v4 and v6 NAT IPs
	// share one map. v4 sessions use netip.AddrFrom4 (recovered from
	// the BPF u32 via NativeEndian — see CLAUDE.md "Byte Order"),
	// v6 sessions use netip.AddrFrom16. Mirrors the producer side in
	// conntrack/gc.go (Save calls). The pre-fix code used
	// `b.NatIP.As4()` which panicked on any v6 binding.
	type natKey struct {
		addr netip.Addr
		port uint16
	}
	sessionCounts := make(map[natKey]int)
	if c.dp.IsLoaded() {
		_ = c.dp.IterateSessions(func(_ dataplane.SessionKey, val dataplane.SessionValue) bool {
			if val.IsReverse == 0 && val.Flags&dataplane.SessFlagSNAT != 0 {
				// SessionValue.NATSrcIP is a u32 holding the IP's
				// network-order bytes in native-endian word form
				// (CLAUDE.md "Byte Order"). Recover the original
				// 4 bytes via NativeEndian.PutUint32 to match
				// conntrack/gc.go:277-279's storage path.
				var ip4 [4]byte
				binary.NativeEndian.PutUint32(ip4[:], val.NATSrcIP)
				sessionCounts[natKey{netip.AddrFrom4(ip4), val.NATSrcPort}]++
			}
			return true
		})
		_ = c.dp.IterateSessionsV6(func(_ dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
			if val.IsReverse == 0 && val.Flags&dataplane.SessFlagSNAT != 0 {
				// Match conntrack/gc.go:397 — no Unmap, the binding
				// stores the 16-byte form for v6 NAT.
				addr := netip.AddrFrom16(val.NATSrcIP)
				sessionCounts[natKey{addr, val.NATSrcPort}]++
			}
			return true
		})
	}

	fmt.Printf("Total persistent NAT bindings: %d\n\n", len(bindings))
	for i, b := range bindings {
		if i > 0 {
			fmt.Println()
		}
		remaining := time.Until(b.LastSeen.Add(b.Timeout))
		if remaining < 0 {
			remaining = 0
		}

		sessions := sessionCounts[natKey{b.NatIP, b.NatPort}]

		fmt.Printf("Persistent NAT binding:\n")
		fmt.Printf("  Internal IP:        %s\n", b.SrcIP)
		fmt.Printf("  Internal port:      %d\n", b.SrcPort)
		fmt.Printf("  Reflexive IP:       %s\n", b.NatIP)
		fmt.Printf("  Reflexive port:     %d\n", b.NatPort)
		fmt.Printf("  Pool:               %s\n", b.PoolName)
		if b.PermitAnyRemoteHost {
			fmt.Printf("  Any remote host:    yes\n")
		}
		fmt.Printf("  Current sessions:   %d\n", sessions)
		fmt.Printf("  Left time:          %s\n", remaining.Truncate(time.Second))
		fmt.Printf("  Configured timeout: %ds\n", int(b.Timeout.Seconds()))
	}
	return nil
}

func (c *CLI) showNPTv6(cfg *config.Config) error {
	if cfg == nil || len(cfg.Security.NAT.Static) == 0 {
		fmt.Println("No NPTv6 rules configured.")
		return nil
	}

	found := false
	for _, rs := range cfg.Security.NAT.Static {
		for _, rule := range rs.Rules {
			if !rule.IsNPTv6 {
				continue
			}
			if !found {
				fmt.Printf("%-20s %-20s %-50s %-50s\n",
					"Rule-set", "Rule", "External prefix", "Internal prefix")
				found = true
			}
			fmt.Printf("%-20s %-20s %-50s %-50s\n",
				rs.Name, rule.Name, rule.Match, rule.Then)
		}
	}
	if !found {
		fmt.Println("No NPTv6 rules configured.")
	}
	return nil
}
