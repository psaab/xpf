package cli

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

func (c *CLI) showInterfacesStatistics() error {
	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("listing links: %w", err)
	}

	sort.Slice(links, func(i, j int) bool {
		return links[i].Attrs().Name < links[j].Attrs().Name
	})

	// Render the authored Junos identity (ge-0/0/2) rather than the kernel
	// netdev name (ge-0-0-2), consistent with the summary / terse / detail /
	// extensive paths (#4984). The prefix filters below still operate on the
	// kernel name.
	kernelToAuthored := kernelToAuthoredMap(c.store.ActiveConfig())

	fmt.Printf("%-16s %15s %15s %15s %15s %10s %10s\n",
		"Interface", "Input packets", "Input bytes", "Output packets", "Output bytes", "In errors", "Out errors")

	for _, l := range links {
		name := l.Attrs().Name
		if name == "lo" || strings.HasPrefix(name, "vrf-") ||
			strings.HasPrefix(name, "xfrm") || strings.HasPrefix(name, "gre-") {
			continue
		}
		stats := l.Attrs().Statistics
		if stats == nil {
			continue
		}
		fmt.Printf("%-16s %15d %15d %15d %15d %10d %10d\n",
			authoredName(kernelToAuthored, name), stats.RxPackets, stats.RxBytes,
			stats.TxPackets, stats.TxBytes, stats.RxErrors, stats.TxErrors)
	}
	return nil
}

// showVlans displays VLAN assignments per interface (like Junos "show vlans").

func (c *CLI) showVlans() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}

	// Build zone lookup: interface name → zone name.
	//
	// #5325: a zone binds a LOGICAL interface such as "ge-0/0/9.0", but the
	// VLAN-entry loop below keys by the BASE interface name plus the unit
	// number. Keying ifZone by the raw zone-member string and then querying
	// it with the bare base name (ifc.Name) missed every unit-qualified
	// binding, blanking the Zone column for a correctly zoned VLAN unit.
	// Build ifZone with the SAME canonical "base.unit" key the query uses,
	// and keep a base-only map for un-unit-qualified bindings (which govern
	// every unit of the interface). Mirrors the #4908/C175-HC-116 base/unit
	// resolution in showChassisClusterStatus.
	ifZone := make(map[string]string)     // "base.unit" -> zone
	ifZoneBase := make(map[string]string) // "base"      -> zone (all units)
	for zoneName, zone := range cfg.Security.Zones {
		if zone == nil { // #3493: tolerant/HA-sync path may carry a nil zone value
			continue
		}
		for _, iface := range zone.Interfaces {
			if parts := strings.SplitN(iface, ".", 2); len(parts) == 2 {
				if u, err := strconv.Atoi(parts[1]); err == nil {
					ifZone[fmt.Sprintf("%s.%d", parts[0], u)] = zoneName
					continue
				}
			}
			ifZoneBase[iface] = zoneName
		}
	}

	// Collect VLAN entries
	type vlanEntry struct {
		iface  string
		unit   int
		vlanID int
		zone   string
		trunk  bool
	}
	var entries []vlanEntry
	for _, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil { // #5886: skip present-but-nil InterfaceConfig
			continue
		}
		if ifc == nil { // #5068: tolerant/HA-sync path may carry a nil interface value
			continue
		}
		for unitNum, unit := range ifc.Units {
			if unit == nil { // #5886: skip present-but-nil InterfaceUnit
				continue
			}
			if unit == nil { // #5068: nil unit value
				continue
			}
			if unit.VlanID > 0 || ifc.VlanTagging {
				// #5325: query with the SAME canonical "base.unit" key used
				// when building ifZone; fall back to a base-only binding
				// (which governs every unit) so a non-unit-qualified zone
				// member still resolves.
				zone := ifZone[fmt.Sprintf("%s.%d", ifc.Name, unitNum)]
				if zone == "" {
					zone = ifZoneBase[ifc.Name]
				}
				entries = append(entries, vlanEntry{
					iface:  ifc.Name,
					unit:   unitNum,
					vlanID: unit.VlanID,
					zone:   zone,
					trunk:  ifc.VlanTagging,
				})
			}
		}
	}

	if len(entries) == 0 {
		fmt.Println("No VLANs configured")
		return nil
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].iface != entries[j].iface {
			return entries[i].iface < entries[j].iface
		}
		return entries[i].unit < entries[j].unit
	})

	fmt.Printf("%-16s %-6s %-8s %-12s %s\n", "Interface", "Unit", "VLAN ID", "Zone", "Mode")
	for _, e := range entries {
		mode := "access"
		if e.trunk {
			mode = "trunk"
		}
		vid := fmt.Sprintf("%d", e.vlanID)
		if e.vlanID == 0 {
			vid = "native"
		}
		qualifier := ""
		if config.ZoneQuarantineExcludedReason(e.zone, cfg) != "" {
			qualifier = " " + config.ZoneQuarantineInterfacesQualifier
		}
		fmt.Printf("%-16s %-6d %-8s %-12s%s %s\n", e.iface, e.unit, vid, e.zone, qualifier, mode)
	}
	return nil
}
