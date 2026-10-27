package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/psaab/xpf/pkg/lldp"
	"github.com/psaab/xpf/pkg/termsafe"
)

func (c *CLI) showLLDP() error {
	cfg := c.store.ActiveConfig()
	var lldpCfg *lldp.LLDPConfig
	if cfg != nil && cfg.Protocols.LLDP != nil {
		src := cfg.Protocols.LLDP
		lldpCfg = &lldp.LLDPConfig{
			Interval:       src.Interval,
			HoldMultiplier: src.HoldMultiplier,
			Disable:        src.Disable,
		}
		for _, iface := range src.Interfaces {
			lldpCfg.Interfaces = append(lldpCfg.Interfaces, lldp.LLDPInterface{Name: iface.Name, Disable: iface.Disable})
		}
	}
	neighbors := -1
	if c.lldpNeighborsFn != nil {
		neighbors = len(c.lldpNeighborsFn())
	}
	lldp.RenderSummary(os.Stdout, lldpCfg, neighbors)
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
