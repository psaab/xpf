package api

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dhcp"
)

func (s *Server) interfacesHandler(w http.ResponseWriter, _ *http.Request) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		writeOK(w, []InterfaceStats{})
		return
	}

	// Build interface->zone map
	ifZone := make(map[string]string)
	for zoneName, zone := range cfg.Security.Zones {
		if zone == nil { // #3493: tolerant/HA-sync path may carry a nil zone value
			continue
		}
		for _, ifName := range zone.Interfaces {
			ifZone[ifName] = zoneName
		}
	}

	var result []InterfaceStats
	for ifName := range allInterfaceNames(cfg) {
		// Translate Junos config name to Linux kernel ifname before
		// the kernel lookup. Config names may contain '/' (e.g.
		// "ge-0/0/0", forbidden by IFNAMSIZ) or be virtual aliases
		// (reth0, fab0, irb.0, gr-0/0/0.0) that don't directly map
		// to a kernel ifindex. See #1565.
		iface, err := net.InterfaceByName(cfg.ResolveKernelIfName(ifName))
		is := InterfaceStats{
			Name: ifName,
			Zone: ifZone[ifName],
		}
		if err == nil {
			is.Ifindex = iface.Index
			if s.dp != nil && s.dp.IsLoaded() {
				if ctrs, err := s.dp.ReadInterfaceCounters(iface.Index); err == nil {
					is.RxPackets = ctrs.RxPackets
					is.RxBytes = ctrs.RxBytes
					is.TxPackets = ctrs.TxPackets
					is.TxBytes = ctrs.TxBytes
				} else {
					// #3464: counter read failed — keep the row but flag it
					// Unavailable so the clean-0 counters are not mistaken for a
					// real idle interface (uniform with /stats/interfaces, gRPC
					// GetInterfaces, and xpf_interface_counter_read_errors_total).
					is.Unavailable = true
				}
			}
		}
		result = append(result, is)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	writeOK(w, result)
}

func (s *Server) interfacesDetailHandler(w http.ResponseWriter, r *http.Request) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		writeOK(w, TextResponse{Output: "no active configuration\n"})
		return
	}

	filterName := r.URL.Query().Get("filter")
	terse := r.URL.Query().Get("terse") == "true"

	if terse {
		s.writeInterfacesTerse(w, cfg, filterName)
		return
	}

	s.writeInterfacesDetail(w, cfg, filterName)
}

func (s *Server) writeInterfacesTerse(w http.ResponseWriter, cfg *config.Config, filterName string) {
	ifaceZoneName := make(map[string]string)
	for name, zone := range cfg.Security.Zones {
		if zone == nil { // #3493: tolerant/HA-sync path may carry a nil zone value
			continue
		}
		for _, ifName := range zone.Interfaces {
			ifaceZoneName[ifName] = name
		}
	}

	// Build RETH mappings
	physToReth := make(map[string]string) // physical member → reth parent
	rethToPhys := cfg.RethToPhysical()    // reth → physical member
	for _, ifCfg := range cfg.Interfaces.Interfaces {
		if ifCfg == nil { // #5886: skip present-but-nil InterfaceConfig
			continue
		}
		if ifCfg.RedundantParent != "" {
			physToReth[ifCfg.Name] = ifCfg.RedundantParent
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%-20s %-10s %-10s %s\n", "Interface", "Admin", "Link", "Addresses")

	var ifNames []string
	for ifName := range allInterfaceNames(cfg) {
		if filterName != "" && !strings.HasPrefix(ifName, filterName) {
			continue
		}
		ifNames = append(ifNames, ifName)
	}
	sort.Strings(ifNames)

	for _, ifName := range ifNames {
		baseName := strings.SplitN(ifName, ".", 2)[0]

		// Physical RETH member: show aenet --> rethN[.M]
		if rethName, ok := physToReth[baseName]; ok {
			kernelIf := config.LinuxIfName(baseName)
			iface, err := net.InterfaceByName(kernelIf)
			admin, link := "down", "down"
			if err == nil {
				if iface.Flags&net.FlagUp != 0 {
					admin = "up"
				}
				if data, err := os.ReadFile("/sys/class/net/" + kernelIf + "/operstate"); err == nil {
					if strings.TrimSpace(string(data)) == "up" {
						link = "up"
					}
				}
			}
			aenetTarget := rethName
			if parts := strings.SplitN(ifName, ".", 2); len(parts) == 2 {
				aenetTarget = rethName + "." + parts[1]
			}
			fmt.Fprintf(&b, "%-20s %-10s %-10s aenet --> %s\n", ifName, admin, link, aenetTarget)
			continue
		}

		// RETH interface: get addresses from config, status from physical member
		if physMember, ok := rethToPhys[baseName]; ok {
			kernelPhys := config.LinuxIfName(physMember)
			iface, err := net.InterfaceByName(kernelPhys)
			admin, link := "down", "down"
			if err == nil {
				if iface.Flags&net.FlagUp != 0 {
					admin = "up"
				}
				if data, err := os.ReadFile("/sys/class/net/" + kernelPhys + "/operstate"); err == nil {
					if strings.TrimSpace(string(data)) == "up" {
						link = "up"
					}
				}
			}
			var addrs []string
			if ifCfg, ok := config.LookupInterface(cfg, baseName); ok {
				// Determine which unit to look up
				unitNum := 0
				if parts := strings.SplitN(ifName, ".", 2); len(parts) == 2 {
					fmt.Sscanf(parts[1], "%d", &unitNum)
				}
				if unit, ok := config.LookupUnit(ifCfg, unitNum); ok {
					addrs = append(addrs, unit.Addresses...)
				}
			}
			addrStr := strings.Join(addrs, ", ")
			if addrStr == "" {
				addrStr = "-"
			}
			fmt.Fprintf(&b, "%-20s %-10s %-10s %s\n", ifName, admin, link, addrStr)
			continue
		}

		// Normal interface: get addresses from kernel. Use the full
		// ResolveKernelIfName helper so tunnel refs (gr-0/0/0.0 ->
		// gr-0-0-0), IRB, and VLAN-tag-aware composition all resolve
		// correctly. Plain LinuxIfName would mis-resolve gr-0/0/0.0
		// to gr-0-0-0.0 (#1565).
		kernelName := cfg.ResolveKernelIfName(ifName)
		iface, err := net.InterfaceByName(kernelName)
		admin, link := "down", "down"
		var addrs []string
		if err == nil {
			if iface.Flags&net.FlagUp != 0 {
				admin = "up"
			}
			if data, err := os.ReadFile("/sys/class/net/" + kernelName + "/operstate"); err == nil {
				if strings.TrimSpace(string(data)) == "up" {
					link = "up"
				}
			}
			if ifAddrs, err := iface.Addrs(); err == nil {
				for _, a := range ifAddrs {
					addrs = append(addrs, a.String())
				}
			}
		}
		addrStr := strings.Join(addrs, ", ")
		if addrStr == "" {
			addrStr = "-"
		}
		fmt.Fprintf(&b, "%-20s %-10s %-10s %s\n", ifName, admin, link, addrStr)
	}

	writeOK(w, TextResponse{Output: b.String()})
}

func (s *Server) writeInterfacesDetail(w http.ResponseWriter, cfg *config.Config, filterName string) {
	ifaceZoneName := make(map[string]string)
	for name, zone := range cfg.Security.Zones {
		if zone == nil { // #3493: tolerant/HA-sync path may carry a nil zone value
			continue
		}
		for _, ifName := range zone.Interfaces {
			ifaceZoneName[ifName] = name
		}
	}

	var b strings.Builder
	var ifNames []string
	for ifName := range allInterfaceNames(cfg) {
		if filterName != "" && !strings.HasPrefix(ifName, filterName) {
			continue
		}
		ifNames = append(ifNames, ifName)
	}
	sort.Strings(ifNames)

	for _, ifName := range ifNames {
		// Translate Junos config name to Linux kernel ifname before
		// kernel lookups (#1565).
		kernel := cfg.ResolveKernelIfName(ifName)
		iface, err := net.InterfaceByName(kernel)
		if err != nil {
			fmt.Fprintf(&b, "Interface: %s, Not present\n\n", ifName)
			continue
		}

		linkUp := "Down"
		if iface.Flags&net.FlagUp != 0 {
			linkUp = "Up"
		}
		if data, err := os.ReadFile("/sys/class/net/" + kernel + "/operstate"); err == nil {
			if strings.TrimSpace(string(data)) == "up" {
				linkUp = "Up"
			}
		}

		fmt.Fprintf(&b, "Interface: %s, Physical link is %s\n", ifName, linkUp)
		fmt.Fprintf(&b, "  MTU: %d", iface.MTU)
		if len(iface.HardwareAddr) > 0 {
			fmt.Fprintf(&b, ", MAC: %s", iface.HardwareAddr)
		}
		b.WriteString("\n")

		if zone, ok := ifaceZoneName[ifName]; ok {
			qualifier := ""
			if config.ZoneQuarantineExcludedReason(zone, cfg) != "" {
				qualifier = " " + config.ZoneQuarantineInterfacesQualifier
			}
			fmt.Fprintf(&b, "  Zone: %s%s\n", zone, qualifier)
		}

		if s.dp != nil && s.dp.IsLoaded() {
			if ctrs, err := s.dp.ReadInterfaceCounters(iface.Index); err == nil && (ctrs.RxPackets > 0 || ctrs.TxPackets > 0) {
				fmt.Fprintf(&b, "  BPF Input:  %d packets, %d bytes\n", ctrs.RxPackets, ctrs.RxBytes)
				fmt.Fprintf(&b, "  BPF Output: %d packets, %d bytes\n", ctrs.TxPackets, ctrs.TxBytes)
			}
		}

		if addrs, err := iface.Addrs(); err == nil && len(addrs) > 0 {
			fmt.Fprintf(&b, "  Addresses:\n")
			for _, a := range addrs {
				fmt.Fprintf(&b, "    %s\n", a.String())
			}
		}

		// DHCP annotations — key by the daemon's actual lease-key
		// shape (LinuxIfName(configRef)+ ".VlanID" when > 0).
		// This is distinct from the kernel link name (#1565).
		if s.dhcp != nil {
			if base, unitNum, ok := parseRefBaseUnit(ifName); ok {
				if key, ok := cfg.DHCPLeaseKey(base, unitNum); ok {
					if lease := s.dhcp.LeaseFor(key, dhcp.AFInet); lease != nil {
						fmt.Fprintf(&b, "  DHCPv4: %s (gw %s)\n", lease.Address, lease.Gateway)
					}
					if lease := s.dhcp.LeaseFor(key, dhcp.AFInet6); lease != nil {
						fmt.Fprintf(&b, "  DHCPv6: %s (gw %s)\n", lease.Address, lease.Gateway)
					}
				}
			}
		}

		b.WriteString("\n")
	}

	writeOK(w, TextResponse{Output: b.String()})
}
