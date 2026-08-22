package cli

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dhcp"
	"github.com/vishvananda/netlink"
)

func (c *CLI) showTunnelInterfaces() error {
	if c.routing == nil {
		fmt.Println("Routing manager not available")
		return nil
	}

	tunnels, err := c.routing.GetTunnelStatus()
	if err != nil {
		return fmt.Errorf("tunnel status: %w", err)
	}

	if len(tunnels) == 0 {
		fmt.Println("No tunnel interfaces")
		return nil
	}

	for _, t := range tunnels {
		fmt.Printf("Tunnel interface: %s\n", t.Name)
		fmt.Printf("  State: %s\n", t.State)
		if t.Source != "" {
			fmt.Printf("  Source: %s\n", t.Source)
		}
		if t.Destination != "" {
			fmt.Printf("  Destination: %s\n", t.Destination)
		}
		for _, addr := range t.Addresses {
			fmt.Printf("  Address: %s\n", addr)
		}
		if t.KeepaliveInfo != "" {
			fmt.Printf("  Keepalive: %s\n", t.KeepaliveInfo)
		}
		fmt.Println()
	}
	return nil
}

func (c *CLI) showInterfaces(args []string) error {
	// Handle "show interfaces queue [<interface>]" sub-command (#4228 Gap 7)
	if len(args) > 0 && args[0] == "queue" {
		selector := ""
		if len(args) > 1 {
			selector = args[1]
		}
		return c.showInterfacesQueue(selector)
	}

	// Handle "show interfaces tunnel" sub-command
	if len(args) > 0 && args[0] == "tunnel" {
		return c.showTunnelInterfaces()
	}

	// Handle "show interfaces terse" sub-command
	if len(args) > 0 && args[0] == "terse" {
		return c.showInterfacesTerse()
	}
	// Handle "show interfaces detail" sub-command
	if len(args) > 0 && args[0] == "detail" {
		return c.showInterfacesDetail("")
	}
	// Handle "show interfaces extensive" sub-command
	if len(args) > 0 && args[0] == "extensive" {
		return c.showInterfacesExtensive()
	}
	// Handle "show interfaces statistics" sub-command
	if len(args) > 0 && args[0] == "statistics" {
		return c.showInterfacesStatistics()
	}

	// Handle "show interfaces <name> detail"
	if len(args) >= 2 && args[len(args)-1] == "detail" {
		return c.showInterfacesDetail(args[0])
	}
	// Handle "show interfaces <name> extensive"
	if len(args) >= 2 && args[len(args)-1] == "extensive" {
		return c.showInterfacesExtensiveFiltered(args[0])
	}

	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("no active configuration")
		return nil
	}

	// Optional filter by interface name
	var filterName string
	if len(args) > 0 {
		filterName = args[0]
	}

	// Build interface -> zone mapping
	ifaceZone := make(map[string]*config.ZoneConfig)
	ifaceZoneName := make(map[string]string)
	for name, zone := range cfg.Security.Zones {
		if zone == nil { // #3493: tolerant/HA-sync path may carry a nil zone value
			continue
		}
		for _, ifaceName := range zone.Interfaces {
			ifaceZone[ifaceName] = zone
			ifaceZoneName[ifaceName] = name
		}
	}

	// Collect logical interfaces
	type logicalIface struct {
		zoneName string
		zone     *config.ZoneConfig
		ifaceRef string // zone-interface ref as authored (host-inbound override key, #3654)
		physName string
		unitNum  int
		vlanID   int
	}
	var logicals []logicalIface

	for ifaceName, zone := range ifaceZone {
		if filterName != "" && !strings.HasPrefix(ifaceName, filterName) {
			continue
		}
		parts := strings.SplitN(ifaceName, ".", 2)
		physName := parts[0]
		unitNum := 0
		if len(parts) == 2 {
			// #6218 item 12: strconv.Atoi's ignored error left a malformed
			// unit token (e.g. "ge-0-0-0.abc") silently defaulting to unit 0
			// — a display-only misattribution that could ALSO borrow unit 0's
			// real VLAN ID below (config.LookupUnit) for a zone reference that
			// names no real unit. -1 can never match a configured unit (units
			// are always >= 0), so it neither borrows a foreign unit's VLAN ID
			// nor renders as a plausible-but-wrong "0".
			if n, err := strconv.Atoi(parts[1]); err == nil {
				unitNum = n
			} else {
				unitNum = -1
			}
		}
		vlanID := 0
		if ifCfg, ok := config.LookupInterface(cfg, physName); ok && ifCfg != nil {
			if unit, ok := config.LookupUnit(ifCfg, unitNum); ok && unit != nil {
				vlanID = unit.VlanID
			}
		}
		logicals = append(logicals, logicalIface{
			zoneName: ifaceZoneName[ifaceName],
			zone:     zone,
			ifaceRef: ifaceName,
			physName: physName,
			unitNum:  unitNum,
			vlanID:   vlanID,
		})
	}

	// #4328: a bondless reth has no kernel netdev of its own — resolve it to
	// its local physical member so link state / MAC / counters come from the
	// member while the logical name stays reth<N>. The addresses come from
	// config (they live on the member's VLAN sub-interfaces, not on "reth0").
	rethMaps := cfg.RethShowMaps()

	// A physical reth member is not zoned, so it never appears in the
	// zone-driven collection above. When the operator asks for one by name,
	// render its aggregation membership (aenet --> reth<N>.<unit>) directly.
	if len(logicals) == 0 && filterName != "" {
		if rethName, ok := rethMaps.LookupMember(filterName); ok {
			c.showInterfacesRethMemberSummary(cfg, filterName, rethName)
			return nil
		}
		return fmt.Errorf("interface %s not found in configuration", filterName)
	}

	// Group by physical interface
	physGroups := make(map[string][]logicalIface)
	var physOrder []string
	for _, li := range logicals {
		if _, seen := physGroups[li.physName]; !seen {
			physOrder = append(physOrder, li.physName)
		}
		physGroups[li.physName] = append(physGroups[li.physName], li)
	}
	sort.Strings(physOrder)

	for _, physName := range physOrder {
		group := physGroups[physName]

		_, rethMember, isReth := rethMaps.LookupReth(physName)
		// A config/zone-ref name is Junos-form ("ge-0/0/2") or an alias, while
		// the kernel netdev is "ge-0-0-2" — resolve to the kernel ifname before
		// the lookup so a valid non-reth interface does not render "Not present"
		// (mirrors Server.GetInterfaces, #3460 / #4328 Copilot follow-up). A
		// reth is resolved to its local physical member instead.
		kernelLookup := cfg.ResolveKernelIfName(physName)
		if isReth {
			kernelLookup = config.LinuxIfName(rethMember)
		}

		// Get netlink link for richer info
		link, nlErr := netlink.LinkByName(kernelLookup)

		// Fallback to net.InterfaceByName if netlink fails
		iface, stdErr := net.InterfaceByName(kernelLookup)
		if stdErr != nil && nlErr != nil && !isReth {
			fmt.Printf("Physical interface: %s, Not present\n\n", physName)
			continue
		}

		// Determine link state
		linkUp := "Down"
		enabled := "Enabled"
		if nlErr == nil {
			attrs := link.Attrs()
			if attrs.OperState == netlink.OperUp {
				linkUp = "Up"
			}
			if attrs.Flags&net.FlagUp == 0 {
				enabled = "Disabled"
			}
		} else if iface != nil {
			if iface.Flags&net.FlagUp != 0 {
				linkUp = "Up"
			}
		}

		fmt.Printf("Physical interface: %s, %s, Physical link is %s\n",
			physName, enabled, linkUp)
		if ifCfg, ok := config.LookupInterface(cfg, physName); ok && ifCfg.Description != "" {
			fmt.Printf("  Description: %s\n", ifCfg.Description)
		}
		if isReth {
			// Name the local physical member backing this bondless reth so the
			// operator can see which link carries the aggregate (#4328).
			fmt.Printf("  Redundant-ethernet: aggregate over member %s\n", rethMember)
		}

		// Link-level details
		mtu := 0
		var hwAddr net.HardwareAddr
		if nlErr == nil {
			attrs := link.Attrs()
			mtu = attrs.MTU
			hwAddr = attrs.HardwareAddr
		} else if iface != nil {
			mtu = iface.MTU
			hwAddr = iface.HardwareAddr
		}

		linkType := "Ethernet"
		var linkDetails []string
		// Read speed/duplex from the resolved kernel device (#4341): the reth
		// aggregate has no /sys/class/net/reth0, and a Junos-form physName has
		// no sysfs entry either — kernelLookup is the real netdev.
		if speed := readLinkSpeed(kernelLookup); speed > 0 {
			linkDetails = append(linkDetails, "Speed: "+formatSpeed(speed))
		}
		if duplex := readLinkDuplex(kernelLookup); duplex != "" {
			linkDetails = append(linkDetails, "Link-mode: "+formatDuplex(duplex))
		}
		extra := ""
		if len(linkDetails) > 0 {
			extra = ", " + strings.Join(linkDetails, ", ")
		}

		fmt.Printf("  Link-level type: %s, MTU: %d%s\n", linkType, mtu, extra)

		if len(hwAddr) > 0 {
			fmt.Printf("  Current address: %s, Hardware address: %s\n", hwAddr, hwAddr)
		}

		// Device flags
		if nlErr == nil {
			attrs := link.Attrs()
			var flags []string
			flags = append(flags, "Present")
			if attrs.OperState == netlink.OperUp {
				flags = append(flags, "Running")
			}
			if linkUp == "Down" {
				flags = append(flags, "Down")
			}
			fmt.Printf("  Device flags   : %s\n", strings.Join(flags, " "))
		}

		// VLAN tagging
		if ifCfg, ok := config.LookupInterface(cfg, physName); ok && ifCfg.VlanTagging {
			fmt.Println("  VLAN tagging: Enabled")
		}

		// Kernel link statistics
		if nlErr == nil {
			attrs := link.Attrs()
			if s := attrs.Statistics; s != nil {
				fmt.Printf("  Input rate     : %d packets, %d bytes\n",
					s.RxPackets, s.RxBytes)
				fmt.Printf("  Output rate    : %d packets, %d bytes\n",
					s.TxPackets, s.TxBytes)
				if s.RxErrors > 0 || s.TxErrors > 0 {
					fmt.Printf("  Errors         : %d input, %d output\n",
						s.RxErrors, s.TxErrors)
				}
				if s.RxDropped > 0 || s.TxDropped > 0 {
					fmt.Printf("  Drops          : %d input, %d output\n",
						s.RxDropped, s.TxDropped)
				}
			}
		}

		// BPF traffic counters (XDP/TC level)
		if c.dp != nil && c.dp.IsLoaded() && iface != nil {
			counters, err := c.dp.ReadInterfaceCounters(iface.Index)
			if err == nil && (counters.RxPackets > 0 || counters.TxPackets > 0) {
				fmt.Println("  BPF statistics:")
				fmt.Printf("    Input:  %d packets, %d bytes\n",
					counters.RxPackets, counters.RxBytes)
				fmt.Printf("    Output: %d packets, %d bytes\n",
					counters.TxPackets, counters.TxBytes)
			}
		}

		// Show each logical unit
		for _, li := range group {
			// The display identity stays authored ("ge-0/0/0.<unit>"), but the
			// kernel-address lookup below needs the Linux dash-form netdev name,
			// and a VLAN-tagged unit's addresses live on the ".<vlan-id>"
			// sub-device. Passing the authored "ge-0/0/0.50" to
			// net.InterfaceByName failed the lookup and fell back to the parent,
			// printing the parent's addresses under the sub-unit (#4984 / #4884
			// sub-defect B). Resolve to the kernel name like the terse path does.
			kernelBase := config.LinuxIfName(physName)
			lookupName := kernelBase
			if li.vlanID > 0 {
				lookupName = fmt.Sprintf("%s.%d", kernelBase, li.vlanID)
			}

			fmt.Printf("\n  Logical interface %s.%d", physName, li.unitNum)
			if li.vlanID > 0 {
				fmt.Printf(" VLAN-Tag [ 0x8100.%d ]", li.vlanID)
			}
			fmt.Println()

			fmt.Printf("    Security: Zone: %s\n", li.zoneName)

			// Host-inbound traffic services (#3654 H05/M03): show the EFFECTIVE
			// admitted set for THIS logical interface — the UNION of the zone
			// set and any per-interface override — flag an interface-local
			// override, and print an explicit default-deny posture line so a
			// blank section is never misread as "not enforced".
			if li.zone != nil {
				svc, proto, overridden := li.zone.InterfaceHostInboundEffective(li.ifaceRef)
				// #3682: a management / cluster-control lifeline interface is
				// EXCLUDED from host-inbound deny scoping; flag it explicitly
				// so the exemption is visible here rather than being masked by a
				// (misleading) default-deny line.
				lifeline := config.HostInboundLifelineInterface(
					li.ifaceRef, config.HostInboundLifelineSet(cfg))
				if overridden {
					fmt.Println("    Host-inbound: interface-specific override (effective set below)")
				}
				if len(svc) > 0 {
					fmt.Printf("    Allowed host-inbound traffic : %s\n", strings.Join(svc, " "))
				}
				if len(proto) > 0 {
					fmt.Printf("    Allowed host-inbound protocols: %s\n", strings.Join(proto, " "))
				}
				if lifeline {
					fmt.Println("    Host-inbound: lifeline-exempt (management/fabric, bypasses host-inbound deny)")
				} else if len(svc) == 0 && len(proto) == 0 {
					fmt.Printf("    Host-inbound: default deny (%s)\n",
						config.HostInboundDenyReason(overridden, li.zone.HostInboundTraffic != nil))
				}
			}

			// DHCP annotations
			var unit *config.InterfaceUnit
			if ifCfg, ok := config.LookupInterface(cfg, physName); ok && ifCfg != nil {
				if u, ok := config.LookupUnit(ifCfg, li.unitNum); ok {
					unit = u
				}
			}
			if unit != nil {
				if unit.DHCP {
					fmt.Println("    DHCPv4: enabled")
					if lease := c.dhcpLease(physName, dhcp.AFInet); lease != nil {
						fmt.Printf("      Address: %s, Gateway: %s\n",
							lease.Address, lease.Gateway)
					}
				}
				if unit.DHCPv6 {
					duidInfo := ""
					if unit.DHCPv6Client != nil && unit.DHCPv6Client.DUIDType != "" {
						duidInfo = fmt.Sprintf(" (DUID type: %s)", unit.DHCPv6Client.DUIDType)
					}
					fmt.Printf("    DHCPv6: enabled%s\n", duidInfo)
					if lease := c.dhcpLease(physName, dhcp.AFInet6); lease != nil {
						fmt.Printf("      Address: %s, Gateway: %s\n",
							lease.Address, lease.Gateway)
					}
				}
			}

			// Addresses grouped by protocol. For a reth aggregate the addresses
			// are configured on reth<N>.<unit> but the kernel carries them on the
			// physical member's VLAN sub-interface, so read them from config
			// (#4328). Normal interfaces read live addresses from the kernel.
			var v4Addrs, v6Addrs []string
			if isReth {
				if unit != nil {
					for _, addr := range unit.Addresses {
						ip, _, perr := net.ParseCIDR(addr)
						if perr != nil {
							continue
						}
						if ip.To4() != nil {
							v4Addrs = append(v4Addrs, addr)
						} else {
							v6Addrs = append(v6Addrs, addr)
						}
					}
				}
			} else {
				liface, err := net.InterfaceByName(lookupName)
				if err != nil && iface != nil {
					liface = iface
				}
				if liface != nil {
					if addrs, err := liface.Addrs(); err == nil {
						for _, addr := range addrs {
							ipNet, ok := addr.(*net.IPNet)
							if !ok {
								continue
							}
							ones, _ := ipNet.Mask.Size()
							if ipNet.IP.To4() != nil {
								v4Addrs = append(v4Addrs, fmt.Sprintf("%s/%d", ipNet.IP, ones))
							} else {
								v6Addrs = append(v6Addrs, fmt.Sprintf("%s/%d", ipNet.IP, ones))
							}
						}
					}
				}
			}
			if len(v4Addrs) > 0 {
				fmt.Printf("    Protocol inet, MTU: %d\n", mtu)
				for _, a := range v4Addrs {
					fmt.Printf("      Addresses, Flags: Is-Preferred Is-Primary\n")
					fmt.Printf("        Local: %s\n", a)
				}
			}
			if len(v6Addrs) > 0 {
				fmt.Printf("    Protocol inet6, MTU: %d\n", mtu)
				for _, a := range v6Addrs {
					flags := "Is-Preferred Is-Primary"
					if strings.HasPrefix(a, "fe80:") {
						flags = "Is-Preferred"
					}
					fmt.Printf("      Addresses, Flags: %s\n", flags)
					fmt.Printf("        Local: %s\n", a)
				}
			}
		}

		fmt.Println()
	}

	return nil
}

// showInterfacesRethMemberSummary renders `show interfaces <member>` for a
// physical reth member (which is not zoned and so never surfaces through the
// zone-driven summary walk). It names the reth parent and lists the aggregated
// logical units (aenet --> reth<N>.<unit>), mirroring the terse handler (#4328).
func (c *CLI) showInterfacesRethMemberSummary(cfg *config.Config, member, reth string) {
	admin, link := rethMemberLinkState(member)
	enabled := "Enabled"
	if admin == "down" {
		enabled = "Disabled"
	}
	linkUp := "Up"
	if link == "down" {
		linkUp = "Down"
	}
	fmt.Printf("Physical interface: %s, %s, Physical link is %s\n", member, enabled, linkUp)
	if ifCfg, ok := config.LookupInterface(cfg, member); ok && ifCfg.Description != "" {
		fmt.Printf("  Description: %s\n", ifCfg.Description)
	}
	fmt.Printf("  Redundant-ethernet: member of %s\n", reth)
	for _, ru := range cfg.RethShowUnits(reth) {
		fmt.Printf("  Logical interface %s.%d", member, ru.Unit)
		if ru.VlanID > 0 {
			fmt.Printf(" VLAN-Tag [ 0x8100.%d ]", ru.VlanID)
		}
		fmt.Println()
		fmt.Printf("    aenet --> %s.%d\n", reth, ru.Unit)
	}
	fmt.Println()
}
