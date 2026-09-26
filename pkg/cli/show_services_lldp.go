package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/termsafe"
)

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
			termsafe.QuoteFieldForDisplay(n.Interface, 12),
			termsafe.QuoteFieldForDisplay(n.ChassisID, 20),
			termsafe.QuoteFieldForDisplay(n.PortID, 16),
			termsafe.QuoteFieldForDisplay(n.SystemName, 20), n.TTL, age)
	}
	return nil
}
