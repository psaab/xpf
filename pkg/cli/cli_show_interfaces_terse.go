package cli

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

func (c *CLI) showInterfacesTerse() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("no active configuration")
		return nil
	}

	// Build RETH mappings (shared resolver, #4328 — the same maps back the
	// summary/detail/extensive paths so they can never drift from terse again).
	rethMaps := cfg.RethShowMaps()
	physToReth := rethMaps.PhysToReth // physical member → reth parent
	rethToPhys := rethMaps.RethToPhys // reth → physical member

	type ifUnit struct {
		physName string
		unitNum  int
		vlanID   int
	}
	var units []ifUnit

	for physName, ifCfg := range cfg.Interfaces.Interfaces {
		if ifCfg == nil { // #5886: skip present-but-nil InterfaceConfig
			continue
		}
		// #5068: skip a present-but-nil interface value (tolerant / HA-sync
		// path admits it, #3494) rather than dereferencing ifCfg.Units.
		if ifCfg == nil {
			continue
		}
		if rethName, ok := physToReth[physName]; ok {
			// Physical RETH member: inherit units from RETH parent
			if rethCfg, ok := config.LookupInterface(cfg, rethName); ok && rethCfg != nil {
				for unitNum, unit := range rethCfg.Units {
					if unit == nil { // #5886: skip present-but-nil InterfaceUnit
						continue
					}
					if unit == nil { // #5068: nil unit value
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
				if unit == nil { // #5068: nil unit value
					continue
				}
				units = append(units, ifUnit{physName: physName, unitNum: unitNum, vlanID: unit.VlanID})
			}
		}
	}

	// Add peer node interfaces (cluster mode).
	peerIfaces := make(map[string]bool)
	peerLinkUp := make(map[string]bool)
	if c.cluster != nil {
		peerNodeID := -1
		if c.cluster.PeerAlive() {
			peerNodeID = c.cluster.PeerNodeID()
		} else if cfg.Chassis.Cluster != nil {
			localID := c.cluster.NodeID()
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
			if peerMons := c.cluster.PeerMonitorStatuses(); peerMons != nil {
				for _, pm := range peerMons {
					peerLinkUp[pm.Interface] = pm.Up
				}
			}
			tree := c.store.ActiveTree()
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
						// #5068: skip a present-but-nil peer interface value.
						if ifCfg == nil {
							continue
						}
						if _, isLocal := cfg.Interfaces.Interfaces[physName]; isLocal {
							continue
						}
						peerIfaces[physName] = true
						if ifCfg.RedundantParent != "" {
							physToReth[physName] = ifCfg.RedundantParent
							if rethCfg, ok := config.LookupInterface(peerCfg, ifCfg.RedundantParent); ok && rethCfg != nil {
								for unitNum, unit := range rethCfg.Units {
									if unit == nil { // #5886: skip present-but-nil InterfaceUnit
										continue
									}
									if unit == nil { // #5068: nil unit value
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
								if unit == nil { // #5068: nil unit value
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

	sort.Slice(units, func(i, j int) bool {
		if units[i].physName != units[j].physName {
			return units[i].physName < units[j].physName
		}
		return units[i].unitNum < units[j].unitNum
	})

	fmt.Printf("%-24s%-6s%-6s%-9s%-22s\n", "Interface", "Admin", "Link", "Proto", "Local")

	printedPhys := make(map[string]bool)

	for _, u := range units {
		isPeer := peerIfaces[u.physName]

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
				} else if c.cluster != nil && !c.cluster.PeerAlive() {
					link = "down"
				}
			} else {
				// Local interface: query kernel.
				// Check config-level disable flag (#5068: nil-safe lookup)
				if ifCfg, ok := config.LookupInterface(cfg, u.physName); ok && ifCfg != nil && ifCfg.Disable {
					admin = "down"
				}
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
						if admin == "up" {
							admin = "down" // kernel says down
						}
					}
					data, err := os.ReadFile("/sys/class/net/" + kernelIf + "/operstate")
					if err == nil && strings.TrimSpace(string(data)) != "up" {
						link = "down"
					}
				}
			}
			fmt.Printf("%-24s%-6s%-6s\n", u.physName, admin, link)
		}

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
				} else if c.cluster != nil && !c.cluster.PeerAlive() {
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
			fmt.Printf("%-24s%-6s%-6s%-9s%s\n", logicalName, admin, link, "aenet", "--> "+rethLogical)
			continue
		}

		// RETH interface: get addresses from config, status from physical member
		if physMember, ok := rethToPhys[u.physName]; ok {
			var v4Addrs, v6Addrs []string
			if ifCfg, ok := config.LookupInterface(cfg, u.physName); ok && ifCfg != nil {
				if unit, ok := config.LookupUnit(ifCfg, u.unitNum); ok && unit != nil {
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
			fmt.Printf("%-24s%-6s%-6s%-9s%-22s\n", logicalName, admin, link, firstProto, firstAddr)
			for i := 1; i < len(v4Addrs); i++ {
				fmt.Printf("%-36s%-9s%-22s\n", "", "inet", v4Addrs[i])
			}
			startIdx := 0
			if firstProto == "inet6" {
				startIdx = 1
			}
			for i := startIdx; i < len(v6Addrs); i++ {
				fmt.Printf("%-36s%-9s%-22s\n", "", "inet6", v6Addrs[i])
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
		// #14575: unit-level disable is admin-down for this logical row.
		if ifCfg, ok := config.LookupInterface(cfg, u.physName); ok && ifCfg != nil {
			if unit, ok := config.LookupUnit(ifCfg, u.unitNum); ok && unit != nil && unit.Disable {
				admin = "down"
			}
		}
		if liface == nil {
			link = "down"
		} else if liface.Flags&net.FlagUp == 0 {
			admin = "down"
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

		fmt.Printf("%-24s%-6s%-6s%-9s%-22s\n", logicalName, admin, link, firstProto, firstAddr)

		for i := 1; i < len(v4Addrs); i++ {
			fmt.Printf("%-36s%-9s%-22s\n", "", "inet", v4Addrs[i])
		}
		startIdx := 0
		if firstProto == "inet6" {
			startIdx = 1
		}
		for i := startIdx; i < len(v6Addrs); i++ {
			fmt.Printf("%-36s%-9s%-22s\n", "", "inet6", v6Addrs[i])
		}
	}

	return nil
}
