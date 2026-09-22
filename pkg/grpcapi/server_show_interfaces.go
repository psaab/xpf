package grpcapi

import (
	"context"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/dhcp"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

func (s *Server) GetInterfaces(_ context.Context, _ *pb.GetInterfacesRequest) (*pb.GetInterfacesResponse, error) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		return &pb.GetInterfacesResponse{}, nil
	}

	ifZone := make(map[string]string)
	for zoneName, zone := range cfg.Security.Zones {
		if zone == nil { // #3493: tolerant/HA-sync path may carry a nil zone value
			continue
		}
		for _, ifName := range zone.Interfaces {
			ifZone[ifName] = zoneName
		}
	}

	resp := &pb.GetInterfacesResponse{}
	for ifName := range allInterfaceNames(cfg) {
		// Translate the Junos config name to the Linux kernel ifname
		// before the kernel lookup. Config names may contain '/' (e.g.
		// "ge-0/0/0", forbidden by IFNAMSIZ) or be virtual aliases
		// (reth0, fab0, irb.0, gr-0/0/0.0) that don't directly map to a
		// kernel ifindex. Matches REST /interfaces (pkg/api/interfaces.go)
		// and the Prometheus collector. See #1565, #3460.
		iface, err := net.InterfaceByName(cfg.ResolveKernelIfName(ifName))
		ii := &pb.InterfaceInfo{
			Name: ifName,
			Zone: ifZone[ifName],
		}
		if err == nil {
			ii.Ifindex = int32(iface.Index)
			if s.dp != nil && s.dp.IsLoaded() {
				if ctrs, err := s.dp.ReadInterfaceCounters(iface.Index); err == nil {
					ii.RxPackets = ctrs.RxPackets
					ii.RxBytes = ctrs.RxBytes
					ii.TxPackets = ctrs.TxPackets
					ii.TxBytes = ctrs.TxBytes
				} else {
					// #3464: counter read failed — keep the row but set
					// Unavailable so the clean-0 counters are not mistaken for a
					// real idle interface. Uniform with REST /stats/interfaces,
					// REST /interfaces, and the Prometheus
					// xpf_interface_counter_read_errors_total contract.
					ii.Unavailable = true
				}
			}
		}
		resp.Interfaces = append(resp.Interfaces, ii)
	}
	sort.Slice(resp.Interfaces, func(i, j int) bool { return resp.Interfaces[i].Name < resp.Interfaces[j].Name })
	return resp, nil
}

func (s *Server) ShowInterfacesDetail(_ context.Context, req *pb.ShowInterfacesDetailRequest) (*pb.ShowInterfacesDetailResponse, error) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		return &pb.ShowInterfacesDetailResponse{Output: "no active configuration\n"}, nil
	}

	filterName := req.Filter

	if req.Terse {
		return s.showInterfacesTerse(cfg, filterName)
	}

	// #9841: the last apply's unconverged MTUs, annotated onto their rows
	// below (or the leftover section when no row matches). Nil-safe: an
	// unpublished backend simply yields no records. The terse path above
	// stays out of scope.
	var mtuRecs []dataplane.MTUUnconverged
	if ar := s.applyResult(); ar != nil {
		mtuRecs = ar.UnconvergedMTUs
	}
	mtuConsumed := make(map[string]bool)

	// Build interface -> zone mapping
	ifaceZone := make(map[string]*config.ZoneConfig)
	ifaceZoneName := make(map[string]string)
	for name, zone := range cfg.Security.Zones {
		if zone == nil { // #3493: tolerant/HA-sync path may carry a nil zone value
			continue
		}
		for _, ifName := range zone.Interfaces {
			ifaceZone[ifName] = zone
			ifaceZoneName[ifName] = name
		}
	}

	// Collect logical interfaces
	type logicalIface struct {
		zoneName string
		zone     *config.ZoneConfig
		ifaceRef string // zone-interface ref as authored (the #9841 exact-match key)
		physName string
		unitNum  int
		vlanID   int
	}
	var logicals []logicalIface

	for ifName, zone := range ifaceZone {
		if filterName != "" && !strings.HasPrefix(ifName, filterName) {
			continue
		}
		parts := strings.SplitN(ifName, ".", 2)
		physName := parts[0]
		unitNum := 0
		if len(parts) == 2 {
			fmt.Sscanf(parts[1], "%d", &unitNum)
		}
		vlanID := 0
		if ifCfg, ok := config.LookupInterface(cfg, physName); ok {
			if unit, ok := config.LookupUnit(ifCfg, unitNum); ok {
				vlanID = unit.VlanID
			}
		}
		logicals = append(logicals, logicalIface{
			zoneName: ifaceZoneName[ifName],
			zone:     zone,
			ifaceRef: ifName,
			physName: physName,
			unitNum:  unitNum,
			vlanID:   vlanID,
		})
	}

	// #4328: a bondless reth has no kernel netdev of its own — resolve it to
	// its local physical member for link state / MAC / counters, while the
	// logical name stays reth<N> and its addresses come from config. A reth
	// member is not zoned, so it never surfaces through the zone walk above —
	// render its aenet aggregation directly when asked for by name.
	rethMaps := cfg.RethShowMaps()
	if len(logicals) == 0 && filterName != "" {
		if rethName, ok := rethMaps.LookupMember(filterName); ok {
			var mb strings.Builder
			writeRethMemberSummary(&mb, cfg, baseIfName(filterName), rethName)
			for _, line := range dataplane.RenderMTUUnconvergedLeftovers(mtuRecs, mtuConsumed, filterName) {
				fmt.Fprintln(&mb, line)
			}
			return &pb.ShowInterfacesDetailResponse{Output: mb.String()}, nil
		}
		// No row rendered at all: surface matching leftovers (a rename
		// between the apply and this show) ahead of the error. Nil when
		// nothing qualifies, so record-less output stays byte-identical.
		var eb strings.Builder
		for _, line := range dataplane.RenderMTUUnconvergedLeftovers(mtuRecs, mtuConsumed, filterName) {
			fmt.Fprintln(&eb, line)
		}
		fmt.Fprintf(&eb, "interface %s not found in configuration\n", filterName)
		return &pb.ShowInterfacesDetailResponse{Output: eb.String()}, nil
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

	var buf strings.Builder
	for _, physName := range physOrder {
		group := physGroups[physName]

		_, rethMember, isReth := rethMaps.LookupReth(physName)
		// A config/zone-ref name is Junos-form ("ge-0/0/2") or an alias, while
		// the kernel netdev is "ge-0-0-2" — resolve to the kernel ifname before
		// the lookup so a valid non-reth interface does not render "Not present"
		// (mirrors GetInterfaces, #3460 / #4328 Copilot follow-up). A reth is
		// resolved to its local physical member instead.
		kernelLookup := cfg.ResolveKernelIfName(physName)
		if isReth {
			kernelLookup = config.LinuxIfName(rethMember)
		}

		iface, ifErr := net.InterfaceByName(kernelLookup)
		if ifErr != nil && !isReth {
			fmt.Fprintf(&buf, "Physical interface: %s, Not present\n\n", physName)
			continue
		}

		// Determine link state (best-effort from the resolved kernel device).
		linkUp := "Down"
		enabled := "Enabled"
		if iface != nil {
			if iface.Flags&net.FlagUp != 0 {
				linkUp = "Up"
			}
			if iface.Flags&net.FlagUp == 0 {
				enabled = "Disabled"
			}
		}
		// Try /sys/class/net for operstate
		if data, err := os.ReadFile("/sys/class/net/" + kernelLookup + "/operstate"); err == nil {
			state := strings.TrimSpace(string(data))
			if state == "up" {
				linkUp = "Up"
			} else if state == "down" {
				linkUp = "Down"
			}
		}

		fmt.Fprintf(&buf, "Physical interface: %s, %s, Physical link is %s\n", physName, enabled, linkUp)
		if isReth {
			fmt.Fprintf(&buf, "  Redundant-ethernet: aggregate over member %s\n", rethMember)
		}

		// Show interface description and configured speed/duplex from config
		if ifCfg, ok := config.LookupInterface(cfg, physName); ok {
			if ifCfg.Description != "" {
				fmt.Fprintf(&buf, "  Description: %s\n", ifCfg.Description)
			}
			if ifCfg.Speed != "" {
				fmt.Fprintf(&buf, "  Configured speed: %s\n", ifCfg.Speed)
			}
			if ifCfg.Duplex != "" {
				fmt.Fprintf(&buf, "  Configured duplex: %s\n", ifCfg.Duplex)
			}
		}

		// Link-level details
		mtu := 0
		if iface != nil {
			mtu = iface.MTU
		}
		linkType := "Ethernet"
		var linkExtras []string
		if raw, err := os.ReadFile("/sys/class/net/" + kernelLookup + "/speed"); err == nil {
			var mbps int
			if _, err := fmt.Sscanf(strings.TrimSpace(string(raw)), "%d", &mbps); err == nil && mbps > 0 {
				if mbps >= 1000 {
					linkExtras = append(linkExtras, fmt.Sprintf("Speed: %dGbps", mbps/1000))
				} else {
					linkExtras = append(linkExtras, fmt.Sprintf("Speed: %dMbps", mbps))
				}
			}
		}
		if raw, err := os.ReadFile("/sys/class/net/" + kernelLookup + "/duplex"); err == nil {
			d := strings.TrimSpace(string(raw))
			if d == "full" {
				linkExtras = append(linkExtras, "Link-mode: Full-duplex")
			} else if d == "half" {
				linkExtras = append(linkExtras, "Link-mode: Half-duplex")
			}
		}
		speedStr := ""
		if len(linkExtras) > 0 {
			speedStr = ", " + strings.Join(linkExtras, ", ")
		}
		fmt.Fprintf(&buf, "  Link-level type: %s, MTU: %d%s\n", linkType, mtu, speedStr)
		// #9841: unconverged-MTU annotations for this netdev. The helper
		// matches, freshly observes, and formats; matched keys are consumed
		// (even when verified converged and rendering nothing) so only
		// rowless records reach the leftover section.
		mtuLines, mtuMatched := dataplane.AnnotateMTUUnconvergedRow(mtuRecs, physName, kernelLookup, "  ")
		for _, m := range mtuMatched {
			mtuConsumed[m] = true
		}
		for _, line := range mtuLines {
			fmt.Fprintln(&buf, line)
		}

		if iface != nil && len(iface.HardwareAddr) > 0 {
			fmt.Fprintf(&buf, "  Current address: %s, Hardware address: %s\n", iface.HardwareAddr, iface.HardwareAddr)
		}

		// Device flags
		var flags []string
		flags = append(flags, "Present")
		if linkUp == "Up" {
			flags = append(flags, "Running")
		}
		if linkUp == "Down" {
			flags = append(flags, "Down")
		}
		fmt.Fprintf(&buf, "  Device flags   : %s\n", strings.Join(flags, " "))

		// VLAN tagging
		if ifCfg, ok := config.LookupInterface(cfg, physName); ok && ifCfg.VlanTagging {
			fmt.Fprintln(&buf, "  VLAN tagging: Enabled")
		}

		// Kernel link statistics via /sys/class/net
		s.writeKernelStats(&buf, kernelLookup)

		// BPF traffic counters
		if s.dp != nil && s.dp.IsLoaded() && iface != nil {
			if ctrs, err := s.dp.ReadInterfaceCounters(iface.Index); err == nil && (ctrs.RxPackets > 0 || ctrs.TxPackets > 0) {
				fmt.Fprintln(&buf, "  BPF statistics:")
				fmt.Fprintf(&buf, "    Input:  %d packets, %d bytes\n", ctrs.RxPackets, ctrs.RxBytes)
				fmt.Fprintf(&buf, "    Output: %d packets, %d bytes\n", ctrs.TxPackets, ctrs.TxBytes)
			}
		}

		// Show each logical unit
		for _, li := range group {
			lookupName := physName
			if li.vlanID > 0 {
				lookupName = fmt.Sprintf("%s.%d", physName, li.vlanID)
			}

			fmt.Fprintf(&buf, "\n  Logical interface %s.%d", physName, li.unitNum)
			if li.vlanID > 0 {
				fmt.Fprintf(&buf, " VLAN-Tag [ 0x8100.%d ]", li.vlanID)
			}
			fmt.Fprintln(&buf)
			// #9841: this unit's unconverged-MTU annotations, first in the
			// section so units without addresses still surface them. The
			// live read targets the record's own kernel netdev (Linux form,
			// like the terse path — never the authored lookupName), and the
			// kernel-name fallback resolves through the actual member for
			// RETH units (the child lives on ge-0-0-2.50, not reth0.50) —
			// never the parent MTU the Protocol lines below print.
			unitKernel := config.LinuxIfName(physName)
			if isReth {
				unitKernel = config.LinuxIfName(rethMember)
			}
			if li.vlanID > 0 {
				unitKernel = fmt.Sprintf("%s.%d", unitKernel, li.vlanID)
			}
			unitLines, unitMatched := dataplane.AnnotateMTUUnconvergedRow(mtuRecs, li.ifaceRef, unitKernel, "    ")
			for _, m := range unitMatched {
				mtuConsumed[m] = true
			}
			for _, line := range unitLines {
				fmt.Fprintln(&buf, line)
			}

			// Show unit description
			if ifCfg, ok := config.LookupInterface(cfg, physName); ok {
				if u, ok := config.LookupUnit(ifCfg, li.unitNum); ok && u.Description != "" {
					fmt.Fprintf(&buf, "    Description: %s\n", u.Description)
				}
			}

			zoneLabel := li.zoneName
			if config.ZoneQuarantineExcludedReason(li.zoneName, cfg) != "" {
				zoneLabel += " " + config.ZoneQuarantineInterfacesQualifier
			}
			fmt.Fprintf(&buf, "    Security: Zone: %s\n", zoneLabel)

			// Host-inbound traffic services (#8183): render the EFFECTIVE
			// admitted set for THIS logical interface, not the zone's.
			//
			// Since #6515 a per-interface `host-inbound-traffic` stanza REPLACES
			// the zone stanza on that interface, so reading
			// `li.zone.HostInboundTraffic` verbatim — which this did — reports
			// services the box does not admit. The inverse is the dangerous one:
			// a zone admitting `ssh` under an interface stanza of `{ ping; }`
			// rendered as admitting `ssh` here, which reads as an exposure that
			// does not exist, and whose obvious remedy (removing `ssh` from the
			// zone) changes nothing on that interface. That is the #5619
			// doctrine: a surface that answers "what does this interface admit"
			// must answer for the interface.
			//
			// This is the surface the REMOTE cli prints — cmd/cli/show_interfaces.go
			// renders `resp.GetOutput()` verbatim — so it was the copy most
			// operators actually read, while its local-CLI twin
			// (pkg/cli/cli_show_interfaces.go) had been correct since #3654.
			// Both now route through the same resolver, which is what
			// host_inbound_surface_agreement_8183_test.go pins.
			if li.zone != nil {
				ref := fmt.Sprintf("%s.%d", physName, li.unitNum)
				svc, proto, overridden := li.zone.InterfaceHostInboundEffective(ref)
				// #3682: a management / cluster-control lifeline interface is
				// EXCLUDED from host-inbound deny scoping; flag it explicitly so
				// the exemption is visible rather than masked by a (misleading)
				// default-deny line.
				lifeline := config.HostInboundLifelineInterface(
					ref, config.HostInboundLifelineSet(cfg))
				if overridden {
					fmt.Fprintln(&buf, "    Host-inbound: interface-specific override (effective set below)")
				}
				if len(svc) > 0 {
					fmt.Fprintf(&buf, "    Allowed host-inbound traffic : %s\n", strings.Join(svc, " "))
				}
				if len(proto) > 0 {
					fmt.Fprintf(&buf, "    Allowed host-inbound protocols: %s\n", strings.Join(proto, " "))
				}
				if lifeline {
					fmt.Fprintln(&buf, "    Host-inbound: lifeline-exempt (management/fabric, bypasses host-inbound deny)")
				} else if len(svc) == 0 && len(proto) == 0 {
					fmt.Fprintf(&buf, "    Host-inbound: default deny (%s)\n",
						config.HostInboundDenyReason(overridden, li.zone.HostInboundTraffic != nil))
				}
			}

			// DHCP annotations
			var unit *config.InterfaceUnit
			if ifCfg, ok := config.LookupInterface(cfg, physName); ok {
				if u, ok := config.LookupUnit(ifCfg, li.unitNum); ok {
					unit = u
				}
			}
			if unit != nil {
				if unit.DHCP {
					fmt.Fprintln(&buf, "    DHCPv4: enabled")
					if s.dhcp != nil {
						if lease := s.dhcp.LeaseFor(physName, dhcp.AFInet); lease != nil {
							fmt.Fprintf(&buf, "      Address: %s, Gateway: %s\n", lease.Address, lease.Gateway)
						}
					}
				}
				if unit.DHCPv6 {
					duidInfo := ""
					if unit.DHCPv6Client != nil && unit.DHCPv6Client.DUIDType != "" {
						duidInfo = fmt.Sprintf(" (DUID type: %s)", unit.DHCPv6Client.DUIDType)
					}
					fmt.Fprintf(&buf, "    DHCPv6: enabled%s\n", duidInfo)
					if s.dhcp != nil {
						if lease := s.dhcp.LeaseFor(physName, dhcp.AFInet6); lease != nil {
							fmt.Fprintf(&buf, "      Address: %s, Gateway: %s\n", lease.Address, lease.Gateway)
						}
					}
				}
			}

			// Addresses grouped by protocol. For a reth aggregate the addresses
			// live on the physical member's VLAN sub-interface, not on "reth0",
			// so read them from config (#4328). Normal interfaces read live
			// addresses from the kernel.
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
				liface, _ := net.InterfaceByName(lookupName)
				if liface == nil {
					liface = iface
				}
				if liface != nil {
					if addrs, err := liface.Addrs(); err == nil {
						for _, addr := range addrs {
							a := addr.String()
							ip, _, err := net.ParseCIDR(a)
							if err != nil {
								continue
							}
							if ip.To4() != nil {
								v4Addrs = append(v4Addrs, a)
							} else {
								v6Addrs = append(v6Addrs, a)
							}
						}
					}
				}
			}
			if len(v4Addrs) > 0 {
				fmt.Fprintf(&buf, "    Protocol inet, MTU: %d\n", mtu)
				for _, a := range v4Addrs {
					fmt.Fprintln(&buf, "      Addresses, Flags: Is-Preferred Is-Primary")
					fmt.Fprintf(&buf, "        Local: %s\n", a)
				}
			}
			if len(v6Addrs) > 0 {
				fmt.Fprintf(&buf, "    Protocol inet6, MTU: %d\n", mtu)
				for _, a := range v6Addrs {
					fl := "Is-Preferred Is-Primary"
					if strings.HasPrefix(a, "fe80:") {
						fl = "Is-Preferred"
					}
					fmt.Fprintf(&buf, "      Addresses, Flags: %s\n", fl)
					fmt.Fprintf(&buf, "        Local: %s\n", a)
				}
			}
		}

		fmt.Fprintln(&buf)
	}

	// #9841: records no row consumed (absent at show time, renamed since
	// the apply), restricted to the filter. Nil when nothing qualifies, so
	// record-less output is byte-identical.
	for _, line := range dataplane.RenderMTUUnconvergedLeftovers(mtuRecs, mtuConsumed, filterName) {
		fmt.Fprintln(&buf, line)
	}

	return &pb.ShowInterfacesDetailResponse{Output: buf.String()}, nil
}

func (s *Server) showInterfacesTerse(cfg *config.Config, filterName string) (*pb.ShowInterfacesDetailResponse, error) {
	// Build zone mapping: interface name -> zone name
	ifaceZoneName := make(map[string]string)
	for name, zone := range cfg.Security.Zones {
		if zone == nil { // #3493: tolerant/HA-sync path may carry a nil zone value
			continue
		}
		for _, ifName := range zone.Interfaces {
			ifaceZoneName[ifName] = name
		}
	}

	// Build RETH mappings (shared resolver, #4328 — the same maps back the
	// summary/detail/extensive paths so they can never drift from terse again).
	rethMaps := cfg.RethShowMaps()
	physToReth := rethMaps.PhysToReth // physical member → reth parent
	rethToPhys := rethMaps.RethToPhys // reth → physical member

	// Collect all configured interfaces with units
	type ifUnit struct {
		physName string
		unitNum  int
		vlanID   int
	}
	var units []ifUnit
	seen := make(map[string]bool)
	for physName, ifCfg := range cfg.Interfaces.Interfaces {
		if ifCfg == nil { // #5886: skip present-but-nil InterfaceConfig
			continue
		}
		if filterName != "" && !strings.HasPrefix(physName, filterName) {
			continue
		}
		seen[physName] = true
		if rethName, ok := physToReth[physName]; ok {
			// Physical RETH member: inherit units from RETH parent
			if rethCfg, ok := config.LookupInterface(cfg, rethName); ok {
				for unitNum, unit := range rethCfg.Units {
					if unit == nil { // #5886: skip present-but-nil InterfaceUnit
						continue
					}
					units = append(units, ifUnit{physName: physName, unitNum: unitNum, vlanID: unit.VlanID})
				}
			}
		} else {
			for unitNum, unit := range ifCfg.Units {
				if unit == nil { // #5886: skip present-but-nil InterfaceUnit
					continue
				}
				units = append(units, ifUnit{physName: physName, unitNum: unitNum, vlanID: unit.VlanID})
			}
		}
	}
	// Also include zone-only interfaces not in interfaces config
	for ifName := range ifaceZoneName {
		parts := strings.SplitN(ifName, ".", 2)
		physName := parts[0]
		if filterName != "" && !strings.HasPrefix(physName, filterName) {
			continue
		}
		if !seen[physName] {
			seen[physName] = true
			unitNum := 0
			if len(parts) == 2 {
				fmt.Sscanf(parts[1], "%d", &unitNum)
			}
			units = append(units, ifUnit{physName: physName, unitNum: unitNum})
		}
	}

	// Add peer node interfaces (cluster mode).
	// Peer interfaces don't exist locally — compile the peer's config from the
	// raw tree and extract interfaces not in our compiled config.
	peerIfaces := make(map[string]bool) // peer-only interface names
	peerLinkUp := make(map[string]bool) // peer interface link status from heartbeat
	if s.cluster != nil {
		// Determine peer node ID.
		peerNodeID := -1
		if s.cluster.PeerAlive() {
			peerNodeID = s.cluster.PeerNodeID()
		} else if cfg.Chassis.Cluster != nil {
			// Derive from config: find the other node in any RG.
			localID := s.cluster.NodeID()
			for _, rg := range cfg.Chassis.Cluster.RedundancyGroups {
				for nid := range rg.NodePriorities {
					if nid != localID {
						peerNodeID = nid
						break
					}
				}
				if peerNodeID >= 0 {
					break
				}
			}
		}
		if peerNodeID >= 0 {
			// Build peer monitor status map.
			if peerMons := s.cluster.PeerMonitorStatuses(); peerMons != nil {
				for _, pm := range peerMons {
					peerLinkUp[pm.Interface] = pm.Up
				}
			}
			tree := s.store.ActiveTree()
			if tree != nil {
				// Lenient compile — the active tree was already tolerated
				// on load (Store.Load compiles with the tolerant-path
				// downgrades, e.g. #1798 control-char sanitize). A strict
				// re-compile here could error on such a legacy config and
				// silently drop peer-interface display via the err==nil
				// guard below.
				peerCfg, err := config.CompileConfigForNodeLenient(tree, peerNodeID)
				if err == nil {
					for physName, ifCfg := range peerCfg.Interfaces.Interfaces {
						if ifCfg == nil { // #5886: skip present-but-nil InterfaceConfig
							continue
						}
						if _, isLocal := cfg.Interfaces.Interfaces[physName]; isLocal {
							continue // shared (reth, fxp, fab, etc.)
						}
						if filterName != "" && !strings.HasPrefix(physName, filterName) {
							continue
						}
						peerIfaces[physName] = true
						if ifCfg.RedundantParent != "" {
							physToReth[physName] = ifCfg.RedundantParent
							if rethCfg, ok := config.LookupInterface(peerCfg, ifCfg.RedundantParent); ok {
								for unitNum, unit := range rethCfg.Units {
									if unit == nil { // #5886: skip present-but-nil InterfaceUnit
										continue
									}
									units = append(units, ifUnit{physName: physName, unitNum: unitNum, vlanID: unit.VlanID})
								}
							}
						} else {
							for unitNum, unit := range ifCfg.Units {
								if unit == nil { // #5886: skip present-but-nil InterfaceUnit
									continue
								}
								units = append(units, ifUnit{physName: physName, unitNum: unitNum, vlanID: unit.VlanID})
							}
						}
					}
				}
			}
		}
	}

	// Sort by physical name then unit number
	sort.Slice(units, func(i, j int) bool {
		if units[i].physName != units[j].physName {
			return units[i].physName < units[j].physName
		}
		return units[i].unitNum < units[j].unitNum
	})

	var buf strings.Builder
	fmt.Fprintf(&buf, "%-24s%-6s%-6s%-9s%-22s\n", "Interface", "Admin", "Link", "Proto", "Local")

	// Track which physical interfaces we've printed
	printedPhys := make(map[string]bool)

	for _, u := range units {
		isPeer := peerIfaces[u.physName]

		// Print the physical interface line if not printed yet
		if !printedPhys[u.physName] {
			printedPhys[u.physName] = true
			admin := "up"
			link := "up"
			if isPeer {
				// Peer interface: use heartbeat monitor data.
				if up, ok := peerLinkUp[u.physName]; ok {
					if !up {
						link = "down"
					}
				} else if s.cluster != nil && !s.cluster.PeerAlive() {
					link = "down"
				}
			} else {
				// Local interface: query kernel.
				// For RETH interfaces, get status from physical member
				statusIf := u.physName
				if phys, ok := rethToPhys[u.physName]; ok {
					statusIf = phys
				}
				kernelIf := config.LinuxIfName(statusIf)
				iface, err := net.InterfaceByName(kernelIf)
				if err != nil {
					link = "down"
				} else {
					if iface.Flags&net.FlagUp == 0 {
						admin = "down"
					}
					data, err := os.ReadFile("/sys/class/net/" + kernelIf + "/operstate")
					if err == nil {
						state := strings.TrimSpace(string(data))
						if state != "up" {
							link = "down"
						}
					}
				}
			}
			// Show description if configured
			desc := ""
			if ifCfg, ok := config.LookupInterface(cfg, u.physName); ok && ifCfg.Description != "" {
				desc = ifCfg.Description
			}
			if desc != "" {
				fmt.Fprintf(&buf, "%-24s%-6s%-6s%s\n", u.physName, admin, link, desc)
			} else {
				fmt.Fprintf(&buf, "%-24s%-6s%-6s\n", u.physName, admin, link)
			}
		}

		// Determine the logical interface name
		logicalName := fmt.Sprintf("%s.%d", u.physName, u.unitNum)

		// Physical RETH member: show aenet --> rethN.M
		if rethName, ok := physToReth[u.physName]; ok {
			admin := "up"
			link := "up"
			if isPeer {
				if up, ok := peerLinkUp[u.physName]; ok {
					if !up {
						link = "down"
					}
				} else if s.cluster != nil && !s.cluster.PeerAlive() {
					link = "down"
				}
			} else {
				kernelIf := config.LinuxIfName(u.physName)
				iface, err := net.InterfaceByName(kernelIf)
				if err != nil {
					link = "down"
				} else {
					if iface.Flags&net.FlagUp == 0 {
						admin = "down"
					}
					data, err := os.ReadFile("/sys/class/net/" + kernelIf + "/operstate")
					if err == nil && strings.TrimSpace(string(data)) != "up" {
						link = "down"
					}
				}
			}
			rethLogical := fmt.Sprintf("%s.%d", rethName, u.unitNum)
			fmt.Fprintf(&buf, "%-24s%-6s%-6s%-9s%s\n", logicalName, admin, link, "aenet", "--> "+rethLogical)
			continue
		}

		// RETH interface: get addresses from config, status from physical member
		if physMember, ok := rethToPhys[u.physName]; ok {
			var v4Addrs, v6Addrs []string
			if ifCfg, ok := config.LookupInterface(cfg, u.physName); ok {
				if unit, ok := config.LookupUnit(ifCfg, u.unitNum); ok {
					for _, addr := range unit.Addresses {
						ip, _, err := net.ParseCIDR(addr)
						if err != nil {
							continue
						}
						if ip.To4() != nil {
							v4Addrs = append(v4Addrs, addr)
						} else {
							v6Addrs = append(v6Addrs, addr)
						}
					}
				}
			}
			admin := "up"
			link := "up"
			kernelPhys := config.LinuxIfName(physMember)
			iface, err := net.InterfaceByName(kernelPhys)
			if err != nil {
				link = "down"
			} else {
				if iface.Flags&net.FlagUp == 0 {
					admin = "down"
				}
				data, err := os.ReadFile("/sys/class/net/" + kernelPhys + "/operstate")
				if err == nil && strings.TrimSpace(string(data)) != "up" {
					link = "down"
				}
			}
			firstProto := ""
			firstAddr := ""
			if len(v4Addrs) > 0 {
				firstProto = "inet"
				firstAddr = v4Addrs[0]
			} else if len(v6Addrs) > 0 {
				firstProto = "inet6"
				firstAddr = v6Addrs[0]
			}
			fmt.Fprintf(&buf, "%-24s%-6s%-6s%-9s%-22s\n", logicalName, admin, link, firstProto, firstAddr)
			for i := 1; i < len(v4Addrs); i++ {
				fmt.Fprintf(&buf, "%-36s%-9s%-22s\n", "", "inet", v4Addrs[i])
			}
			startIdx := 0
			if firstProto == "inet6" {
				startIdx = 1
			}
			for i := startIdx; i < len(v6Addrs); i++ {
				fmt.Fprintf(&buf, "%-36s%-9s%-22s\n", "", "inet6", v6Addrs[i])
			}
			continue
		}

		// Normal interface: get addresses from kernel
		lookupName := config.LinuxIfName(u.physName)
		if u.vlanID > 0 {
			lookupName = fmt.Sprintf("%s.%d", config.LinuxIfName(u.physName), u.vlanID)
		}

		var v4Addrs, v6Addrs []string
		liface, err := net.InterfaceByName(lookupName)
		if err != nil {
			// Try the physical interface for unit 0
			liface, err = net.InterfaceByName(config.LinuxIfName(u.physName))
		}
		if err == nil {
			addrs, _ := liface.Addrs()
			for _, addr := range addrs {
				ipNet, ok := addr.(*net.IPNet)
				if !ok {
					continue
				}
				ones, _ := ipNet.Mask.Size()
				addrStr := fmt.Sprintf("%s/%d", ipNet.IP, ones)
				if ipNet.IP.To4() != nil {
					v4Addrs = append(v4Addrs, addrStr)
				} else {
					v6Addrs = append(v6Addrs, addrStr)
				}
			}
		}

		admin := "up"
		link := "up"
		if liface == nil {
			link = "down"
		} else {
			if liface.Flags&net.FlagUp == 0 {
				admin = "down"
			}
		}

		firstProto := ""
		firstAddr := ""
		if len(v4Addrs) > 0 {
			firstProto = "inet"
			firstAddr = v4Addrs[0]
		} else if len(v6Addrs) > 0 {
			firstProto = "inet6"
			firstAddr = v6Addrs[0]
		}

		fmt.Fprintf(&buf, "%-24s%-6s%-6s%-9s%-22s\n", logicalName, admin, link, firstProto, firstAddr)

		if len(v4Addrs) > 1 {
			for _, a := range v4Addrs[1:] {
				fmt.Fprintf(&buf, "%-36s%-9s%-22s\n", "", "inet", a)
			}
		}

		startIdx := 0
		if firstProto == "inet6" {
			startIdx = 1
		}
		if firstProto == "inet" {
			startIdx = 0
		}
		for i := startIdx; i < len(v6Addrs); i++ {
			fmt.Fprintf(&buf, "%-36s%-9s%-22s\n", "", "inet6", v6Addrs[i])
		}
	}

	return &pb.ShowInterfacesDetailResponse{Output: buf.String()}, nil
}

func (s *Server) writeKernelStats(buf *strings.Builder, ifaceName string) {
	readStat := func(name string) uint64 {
		data, err := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/statistics/%s", ifaceName, name))
		if err != nil {
			return 0
		}
		var v uint64
		fmt.Sscanf(strings.TrimSpace(string(data)), "%d", &v)
		return v
	}
	rxPkts := readStat("rx_packets")
	rxBytes := readStat("rx_bytes")
	txPkts := readStat("tx_packets")
	txBytes := readStat("tx_bytes")
	fmt.Fprintf(buf, "  Input rate     : %d packets, %d bytes\n", rxPkts, rxBytes)
	fmt.Fprintf(buf, "  Output rate    : %d packets, %d bytes\n", txPkts, txBytes)
	rxErr := readStat("rx_errors")
	txErr := readStat("tx_errors")
	if rxErr > 0 || txErr > 0 {
		fmt.Fprintf(buf, "  Errors         : %d input, %d output\n", rxErr, txErr)
	}
	rxDrop := readStat("rx_dropped")
	txDrop := readStat("tx_dropped")
	if rxDrop > 0 || txDrop > 0 {
		fmt.Fprintf(buf, "  Drops          : %d input, %d output\n", rxDrop, txDrop)
	}
}

// --- #4328: shared reth rendering helpers for the gRPC text surfaces ---

// baseIfName strips a dotted unit suffix ("reth0.50" -> "reth0").
func baseIfName(name string) string {
	if i := strings.IndexByte(name, '.'); i >= 0 {
		return name[:i]
	}
	return name
}

// rethMemberKernelState returns admin/link ("up"/"down") for a reth's physical
// member, best-effort from the kernel (down when the device is absent — a
// peer-owned member or a test host), mirroring the terse handler (#4328).
func rethMemberKernelState(member string) (admin, link string) {
	admin, link = "up", "up"
	kernelIf := config.LinuxIfName(member)
	iface, err := net.InterfaceByName(kernelIf)
	if err != nil {
		return "up", "down"
	}
	if iface.Flags&net.FlagUp == 0 {
		admin = "down"
	}
	if data, err := os.ReadFile("/sys/class/net/" + kernelIf + "/operstate"); err == nil {
		if strings.TrimSpace(string(data)) != "up" {
			link = "down"
		}
	}
	return admin, link
}

// writeRethMemberSummary renders `show interfaces <member>` for a physical reth
// member (not zoned, so absent from the zone-driven walk): it names the reth
// parent and lists the aggregated logical units (aenet --> reth<N>.<unit>) (#4328).
func writeRethMemberSummary(buf *strings.Builder, cfg *config.Config, member, reth string) {
	admin, link := rethMemberKernelState(member)
	enabled := "Enabled"
	if admin == "down" {
		enabled = "Disabled"
	}
	linkUp := "Up"
	if link == "down" {
		linkUp = "Down"
	}
	fmt.Fprintf(buf, "Physical interface: %s, %s, Physical link is %s\n", member, enabled, linkUp)
	if ifc, ok := config.LookupInterface(cfg, member); ok && ifc.Description != "" {
		fmt.Fprintf(buf, "  Description: %s\n", ifc.Description)
	}
	fmt.Fprintf(buf, "  Redundant-ethernet: member of %s\n", reth)
	for _, ru := range cfg.RethShowUnits(reth) {
		fmt.Fprintf(buf, "  Logical interface %s.%d", member, ru.Unit)
		if ru.VlanID > 0 {
			fmt.Fprintf(buf, " VLAN-Tag [ 0x8100.%d ]", ru.VlanID)
		}
		fmt.Fprintln(buf)
		fmt.Fprintf(buf, "    aenet --> %s.%d\n", reth, ru.Unit)
	}
	fmt.Fprintln(buf)
}

// writeRethDetail renders `show interfaces ... detail` for bondless reth
// aggregates (no kernel netdev) and, when the filter names a reth member whose
// kernel device is absent, a synthetic member block. alreadyFound reports
// whether the netlink walk already emitted the filtered interface. Returns true
// when anything was rendered (#4328).
func writeRethDetail(buf *strings.Builder, cfg *config.Config, maps config.RethShowMaps, filterName string, alreadyFound bool) bool {
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
		admin, link := rethMemberKernelState(member)
		adminStr := "Enabled"
		if admin == "down" {
			adminStr = "Disabled"
		}
		linkStr := "Up"
		if link == "down" {
			linkStr = "Down"
		}
		fmt.Fprintf(buf, "Physical interface: %s, %s, Physical link is %s\n", reth, adminStr, linkStr)
		if ifc, ok := config.LookupInterface(cfg, reth); ok && ifc.Description != "" {
			fmt.Fprintf(buf, "  Description: %s\n", ifc.Description)
		}
		fmt.Fprintf(buf, "  Redundant-ethernet: aggregate over member %s\n", member)
		for _, ru := range cfg.RethShowUnits(reth) {
			fmt.Fprintf(buf, "  Logical interface %s.%d", reth, ru.Unit)
			if ru.VlanID > 0 {
				fmt.Fprintf(buf, " VLAN-Tag [ 0x8100.%d ]", ru.VlanID)
			}
			fmt.Fprintln(buf)
			if zone, ok := ifZone[fmt.Sprintf("%s.%d", reth, ru.Unit)]; ok {
				qualifier := ""
				if config.ZoneQuarantineExcludedReason(zone, cfg) != "" {
					qualifier = " " + config.ZoneQuarantineInterfacesQualifier
				}
				fmt.Fprintf(buf, "    Security zone: %s%s\n", zone, qualifier)
			}
			if len(ru.V4Addrs) > 0 || len(ru.V6Addrs) > 0 {
				fmt.Fprintln(buf, "    Addresses:")
				for _, a := range ru.V4Addrs {
					fmt.Fprintf(buf, "      %s\n", a)
				}
				for _, a := range ru.V6Addrs {
					fmt.Fprintf(buf, "      %s\n", a)
				}
			}
		}
		fmt.Fprintln(buf)
		rendered = true
	}

	if !alreadyFound && !rendered && filterName != "" {
		if reth, ok := maps.LookupMember(filterName); ok {
			writeRethMemberSummary(buf, cfg, baseIfName(filterName), reth)
			rendered = true
		}
	}
	return rendered
}
