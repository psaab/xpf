package cli

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

func (c *CLI) showInterfacesDetail(filterName string) error {
	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("listing interfaces: %w", err)
	}

	sort.Slice(links, func(i, j int) bool {
		return links[i].Attrs().Name < links[j].Attrs().Name
	})

	// Build zone + description lookup from active config, keyed by the AUTHORED
	// Junos name (#4984). The netlink walk below yields kernel dash-form names,
	// so kernelToAuthored maps them back to the authored identity; the zone /
	// description maps are keyed by that authored form (zone bindings are
	// logical refs like "ge-0/0/9.0" — strip the unit to a base key) so the
	// joins actually match instead of being silently blanked.
	ifZoneMap := make(map[string]string)
	ifDescMap := make(map[string]string)
	cfg := c.store.ActiveConfig()
	kernelToAuthored := kernelToAuthoredMap(cfg)
	// #4328: reth resolution — a bondless reth has no kernel netdev, so the
	// netlink walk below never emits it. Build the shared maps so a reth
	// aggregate is synthesized from config and its physical members are
	// annotated with their aenet aggregation.
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
		fmt.Printf("  Interface index: %d, SNMP ifIndex: %d\n", attrs.Index, attrs.Index)

		// Link type, MTU, speed, duplex
		linkType := "Ethernet"
		if attrs.EncapType != "" {
			linkType = attrs.EncapType
		}
		speedStr := ""
		if speed := readLinkSpeed(attrs.Name); speed > 0 {
			speedStr = ", Speed: " + formatSpeed(speed)
		}
		duplexStr := ""
		if d := readLinkDuplex(attrs.Name); d != "" {
			duplexStr = ", Duplex: " + formatDuplex(d)
		}
		fmt.Printf("  Link-level type: %s, MTU: %d%s%s\n", linkType, attrs.MTU, speedStr, duplexStr)

		if len(attrs.HardwareAddr) > 0 {
			fmt.Printf("  Current address: %s\n", attrs.HardwareAddr)
		}
		if zone, ok := ifZoneMap[dispName]; ok {
			qualifier := ""
			if cfg != nil && config.ZoneQuarantineExcludedReason(zone, cfg) != "" {
				qualifier = " " + config.ZoneQuarantineInterfacesQualifier
			}
			fmt.Printf("  Security zone: %s%s\n", zone, qualifier)
		}

		// Logical interface with flags and addresses
		var flags []string
		if adminUp {
			flags = append(flags, "Up")
		}
		if attrs.RawFlags&0x2 != 0 { // IFF_BROADCAST
			flags = append(flags, "BROADCAST")
		}
		if attrs.OperState == netlink.OperUp {
			flags = append(flags, "RUNNING")
		}
		if attrs.RawFlags&0x1000 != 0 { // IFF_MULTICAST
			flags = append(flags, "MULTICAST")
		}
		fmt.Printf("  Logical interface %s.0\n", dispName)
		if len(flags) > 0 {
			fmt.Printf("    Flags: %s\n", strings.Join(flags, " "))
		}

		// #4328: a physical reth member carries the reth's logical units as
		// aenet aggregation — surface that membership here (terse already does).
		if rethName, ok := rethMaps.LookupMember(attrs.Name); ok && cfg != nil {
			fmt.Printf("    Redundant-ethernet: member of %s\n", rethName)
			for _, ru := range cfg.RethShowUnits(rethName) {
				fmt.Printf("    Logical interface %s.%d --> aenet %s.%d\n",
					dispName, ru.Unit, rethName, ru.Unit)
			}
		}

		addrs, _ := netlink.AddrList(link, netlink.FAMILY_ALL)
		if len(addrs) > 0 {
			fmt.Println("    Addresses:")
			for _, a := range addrs {
				fmt.Printf("      %s\n", a.IPNet)
			}
		}

		// Traffic statistics
		if s := attrs.Statistics; s != nil {
			fmt.Println("  Traffic statistics:")
			fmt.Printf("    Input  packets:             %12d\n", s.RxPackets)
			fmt.Printf("    Output packets:             %12d\n", s.TxPackets)
			fmt.Printf("    Input  bytes:               %12d\n", s.RxBytes)
			fmt.Printf("    Output bytes:               %12d\n", s.TxBytes)
			fmt.Printf("    Input  errors:              %12d\n", s.RxErrors)
			fmt.Printf("    Output errors:              %12d\n", s.TxErrors)
		}
		fmt.Println()
	}

	// #4328: render bondless reth aggregates (no kernel netdev) and, when the
	// filter names a reth member whose kernel device is absent, a synthetic
	// member block. This runs after the netlink walk so an unfiltered
	// `show interfaces detail` lists reths alongside the physical members.
	if cfg != nil {
		if c.showInterfacesRethDetail(cfg, rethMaps, filterName, found) {
			found = true
		}
	}

	if filterName != "" && !found {
		fmt.Printf("Interface %s not found\n", filterName)
	}
	return nil
}

// showInterfacesRethDetail renders the `show interfaces ... detail` view for
// bondless reth aggregates (which have no kernel netdev) and, when the filter
// names a reth member whose kernel device is absent, a synthetic member block.
// alreadyFound reports whether the netlink walk already rendered the filtered
// interface (a real member device). Returns true when anything was rendered.
func (c *CLI) showInterfacesRethDetail(cfg *config.Config, maps config.RethShowMaps, filterName string, alreadyFound bool) bool {
	// Zone lookup keyed by logical ref (reth0.50 -> zone).
	ifZone := make(map[string]string)
	for _, z := range cfg.Security.Zones {
		if z == nil {
			continue
		}
		for _, ifName := range z.Interfaces {
			ifZone[ifName] = z.Name
		}
	}

	rendered := false
	reths := make([]string, 0, len(maps.RethToPhys))
	for reth := range maps.RethToPhys {
		reths = append(reths, reth)
	}
	sort.Strings(reths)
	for _, reth := range reths {
		if filterName != "" && baseIfName(filterName) != reth {
			continue
		}
		member := maps.RethToPhys[reth]
		attrs, haveDev := rethMemberAttrs(member)
		adminStr, linkStr := "Disabled", "Down"
		mtu := 0
		var hwAddr net.HardwareAddr
		if haveDev {
			if attrs.Flags&net.FlagUp != 0 {
				adminStr = "Enabled"
			}
			if attrs.OperState == netlink.OperUp {
				linkStr = "Up"
			}
			mtu = attrs.MTU
			hwAddr = attrs.HardwareAddr
		}
		fmt.Printf("Physical interface: %s, %s, Physical link is %s\n", reth, adminStr, linkStr)
		if ifc, ok := config.LookupInterface(cfg, reth); ok && ifc.Description != "" {
			fmt.Printf("  Description: %s\n", ifc.Description)
		}
		fmt.Printf("  Redundant-ethernet: aggregate over member %s\n", member)
		fmt.Printf("  Link-level type: Ethernet, MTU: %d\n", mtu)
		if len(hwAddr) > 0 {
			fmt.Printf("  Current address: %s\n", hwAddr)
		}
		for _, ru := range cfg.RethShowUnits(reth) {
			fmt.Printf("  Logical interface %s.%d", reth, ru.Unit)
			if ru.VlanID > 0 {
				fmt.Printf(" VLAN-Tag [ 0x8100.%d ]", ru.VlanID)
			}
			fmt.Println()
			if zone, ok := ifZone[fmt.Sprintf("%s.%d", reth, ru.Unit)]; ok {
				qualifier := ""
				if config.ZoneQuarantineExcludedReason(zone, cfg) != "" {
					qualifier = " " + config.ZoneQuarantineInterfacesQualifier
				}
				fmt.Printf("    Security zone: %s%s\n", zone, qualifier)
			}
			if len(ru.V4Addrs) > 0 || len(ru.V6Addrs) > 0 {
				fmt.Println("    Addresses:")
				for _, a := range ru.V4Addrs {
					fmt.Printf("      %s\n", a)
				}
				for _, a := range ru.V6Addrs {
					fmt.Printf("      %s\n", a)
				}
			}
		}
		fmt.Println()
		rendered = true
	}

	// A reth member whose kernel device is absent never surfaces through the
	// netlink walk; render its aenet membership synthetically so the filtered
	// lookup is not empty.
	if !alreadyFound && !rendered && filterName != "" {
		if reth, ok := maps.LookupMember(filterName); ok {
			member := baseIfName(filterName)
			admin, link := rethMemberLinkState(member)
			adminStr, linkStr := "Enabled", "Up"
			if admin == "down" {
				adminStr = "Disabled"
			}
			if link == "down" {
				linkStr = "Down"
			}
			fmt.Printf("Physical interface: %s, %s, Physical link is %s\n", member, adminStr, linkStr)
			if ifc, ok := config.LookupInterface(cfg, member); ok && ifc.Description != "" {
				fmt.Printf("  Description: %s\n", ifc.Description)
			}
			fmt.Printf("  Redundant-ethernet: member of %s\n", reth)
			for _, ru := range cfg.RethShowUnits(reth) {
				fmt.Printf("  Logical interface %s.%d --> aenet %s.%d\n", member, ru.Unit, reth, ru.Unit)
			}
			fmt.Println()
			rendered = true
		}
	}
	return rendered
}
