package cli

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// showInterfacesExtensive shows detailed per-interface statistics including
// all error counters, queue depths, and ethtool-style information.

func (c *CLI) showInterfacesExtensive() error {
	return c.showInterfacesExtensiveFiltered("")
}

func (c *CLI) showInterfacesExtensiveFiltered(filterName string) error {
	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("listing interfaces: %w", err)
	}

	sort.Slice(links, func(i, j int) bool {
		return links[i].Attrs().Name < links[j].Attrs().Name
	})

	// Build zone lookup from active config, keyed by the AUTHORED Junos name
	// (#4984) — the netlink walk yields kernel dash-form names, so kernelToAuthored
	// maps them back and the joins key by the authored form (zone bindings are
	// logical refs, so strip the unit to a base key) instead of silently blanking.
	ifZoneMap := make(map[string]string)
	ifDescMap := make(map[string]string)
	ifCfgMap := make(map[string]*config.InterfaceConfig)
	cfg := c.store.ActiveConfig()
	kernelToAuthored := kernelToAuthoredMap(cfg)
	// #4328: reth resolution — synthesize bondless reth aggregates (no kernel
	// netdev) and annotate physical members with their aenet aggregation.
	var rethMaps config.RethShowMaps
	if cfg != nil {
		rethMaps = cfg.RethShowMaps()
		for _, z := range cfg.Security.Zones {
			if z == nil { // #3493: tolerant/HA-sync path may carry a nil zone value
				continue
			}
			for _, ifName := range z.Interfaces {
				ifZoneMap[baseIfName(ifName)] = z.Name
			}
		}
		for _, ifc := range cfg.Interfaces.Interfaces {
			if ifc == nil { // #5886: skip present-but-nil InterfaceConfig
				continue
			}
			if ifc == nil { // #5068: tolerant/HA-sync path may carry a nil interface value
				continue
			}
			ifCfgMap[ifc.Name] = ifc
			if ifc.Description != "" {
				ifDescMap[ifc.Name] = ifc.Description
			}
		}
	}

	found := false
	for _, link := range links {
		attrs := link.Attrs()
		if attrs.Name == "lo" {
			continue
		}
		// Render the authored Junos identity (ge-0/0/2), not the kernel netdev
		// name (ge-0-0-2), and accept either spelling as the filter (#4984).
		dispName := authoredName(kernelToAuthored, attrs.Name)
		if filterName != "" && !ifaceFilterMatches(filterName, attrs.Name, dispName) {
			continue
		}
		found = true

		// State
		adminUp := attrs.Flags&net.FlagUp != 0
		operUp := attrs.OperState == netlink.OperUp
		adminStr := "Disabled"
		if adminUp {
			adminStr = "Enabled"
		}
		linkStr := "Down"
		if operUp {
			linkStr = "Up"
		}
		fmt.Printf("Physical interface: %s, %s, Physical link is %s\n", dispName, adminStr, linkStr)
		if desc, ok := ifDescMap[dispName]; ok {
			fmt.Printf("  Description: %s\n", desc)
		}
		if zone, ok := ifZoneMap[dispName]; ok {
			qualifier := ""
			if cfg != nil && config.ZoneQuarantineExcludedReason(zone, cfg) != "" {
				qualifier = " " + config.ZoneQuarantineInterfacesQualifier
			}
			fmt.Printf("  Security zone: %s%s\n", zone, qualifier)
		}
		// #4328: annotate a physical reth member with its aenet aggregation.
		if rethName, ok := rethMaps.LookupMember(attrs.Name); ok && cfg != nil {
			fmt.Printf("  Redundant-ethernet: member of %s\n", rethName)
			for _, ru := range cfg.RethShowUnits(rethName) {
				fmt.Printf("  Logical interface %s.%d --> aenet %s.%d\n",
					dispName, ru.Unit, rethName, ru.Unit)
			}
		}
		if ifCfg, ok := ifCfgMap[dispName]; ok {
			if ifCfg.Speed != "" {
				fmt.Printf("  Configured speed: %s\n", ifCfg.Speed)
			}
			if ifCfg.Duplex != "" {
				fmt.Printf("  Configured duplex: %s\n", ifCfg.Duplex)
			}
		}

		// Type + speed + MTU
		linkType := "Ethernet"
		if attrs.EncapType != "" {
			linkType = attrs.EncapType
		}
		var linkExtras []string
		if speed := readLinkSpeed(attrs.Name); speed > 0 {
			linkExtras = append(linkExtras, "Speed: "+formatSpeed(speed))
		}
		duplexStr := "Full-duplex"
		if duplex := readLinkDuplex(attrs.Name); duplex != "" {
			duplexStr = formatDuplex(duplex)
		}
		linkExtras = append(linkExtras, "Link-mode: "+duplexStr)
		fmt.Printf("  Link-level type: %s, MTU: %d, %s\n",
			linkType, attrs.MTU, strings.Join(linkExtras, ", "))

		// MAC
		if len(attrs.HardwareAddr) > 0 {
			fmt.Printf("  Current address: %s, Hardware address: %s\n",
				attrs.HardwareAddr, attrs.HardwareAddr)
		}

		// Device flags
		var flags []string
		flags = append(flags, "Present")
		if operUp {
			flags = append(flags, "Running")
		}
		if !adminUp {
			flags = append(flags, "Down")
		}
		fmt.Printf("  Device flags   : %s\n", strings.Join(flags, " "))
		fmt.Printf("  Interface index: %d, SNMP ifIndex: %d\n", attrs.Index, attrs.Index)

		if attrs.TxQLen > 0 {
			fmt.Printf("  Link type      : %s, TxQueueLen: %d\n", attrs.EncapType, attrs.TxQLen)
		}

		// Detailed statistics
		if s := attrs.Statistics; s != nil {
			fmt.Println("  Traffic statistics:")
			fmt.Printf("    Input:  %d bytes, %d packets\n", s.RxBytes, s.RxPackets)
			fmt.Printf("    Output: %d bytes, %d packets\n", s.TxBytes, s.TxPackets)
			fmt.Println("  Input errors:")
			fmt.Printf("    Errors: %d, Drops: %d, Overruns: %d, Frame: %d\n",
				s.RxErrors, s.RxDropped, s.RxOverErrors, s.RxFrameErrors)
			fmt.Printf("    FIFO errors: %d, Missed: %d, Compressed: %d\n",
				s.RxFifoErrors, s.RxMissedErrors, s.RxCompressed)
			fmt.Println("  Output errors:")
			fmt.Printf("    Errors: %d, Drops: %d, Carrier: %d, Collisions: %d\n",
				s.TxErrors, s.TxDropped, s.TxCarrierErrors, s.Collisions)
			fmt.Printf("    FIFO errors: %d, Heartbeat: %d, Compressed: %d\n",
				s.TxFifoErrors, s.TxHeartbeatErrors, s.TxCompressed)
			if s.Multicast > 0 {
				fmt.Printf("    Multicast: %d\n", s.Multicast)
			}
		}

		// BPF traffic counters (XDP/TC level)
		if c.dp != nil && c.dp.IsLoaded() {
			if ctrs, err := c.dp.ReadInterfaceCounters(attrs.Index); err == nil && (ctrs.RxPackets > 0 || ctrs.TxPackets > 0) {
				fmt.Println("  BPF statistics:")
				fmt.Printf("    Input:  %d packets, %d bytes\n", ctrs.RxPackets, ctrs.RxBytes)
				fmt.Printf("    Output: %d packets, %d bytes\n", ctrs.TxPackets, ctrs.TxBytes)
			}
		}

		// Addresses
		addrs, _ := netlink.AddrList(link, netlink.FAMILY_ALL)
		if len(addrs) > 0 {
			var v4, v6 []string
			for _, a := range addrs {
				if a.IP.To4() != nil {
					v4 = append(v4, a.IPNet.String())
				} else {
					v6 = append(v6, a.IPNet.String())
				}
			}
			if len(v4) > 0 {
				fmt.Printf("  Protocol inet, MTU: %d\n", attrs.MTU)
				for _, a := range v4 {
					fmt.Printf("    Local: %s\n", a)
				}
			}
			if len(v6) > 0 {
				fmt.Printf("  Protocol inet6, MTU: %d\n", attrs.MTU)
				for _, a := range v6 {
					flags := "Is-Preferred Is-Primary"
					if strings.HasPrefix(a, "fe80:") {
						flags = "Is-Preferred"
					}
					fmt.Printf("    Local: %s, Flags: %s\n", a, flags)
				}
			}
		}
		fmt.Println()
	}

	// #4328: bondless reth aggregates + absent-device members (see the detail
	// path). The extensive view reuses the same synthesized block.
	if cfg != nil {
		c.showInterfacesRethDetail(cfg, rethMaps, filterName, found)
	}
	return nil
}
