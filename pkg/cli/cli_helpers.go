package cli

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/cmdtree"
	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/vishvananda/netlink"
)

func fmtBytes(b uint64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1fG", float64(b)/float64(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1fM", float64(b)/float64(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1fK", float64(b)/float64(1<<10))
	default:
		return fmt.Sprintf("%dB", b)
	}
}

func (c *CLI) handleShowIPv6(args []string) error {
	if len(args) == 0 {
		cmdtree.PrintTreeHelp("show ipv6:", operationalTree, "show", "ipv6")
		return nil
	}
	switch args[0] {
	case "neighbors":
		return c.showIPv6Neighbors()
	case "router-advertisement":
		return c.showIPv6RouterAdvertisement()
	default:
		return fmt.Errorf("unknown show ipv6 target: %s", args[0])
	}
}

func neighState(state int) string {
	switch state {
	case netlink.NUD_REACHABLE:
		return "reachable"
	case netlink.NUD_STALE:
		return "stale"
	case netlink.NUD_DELAY:
		return "delay"
	case netlink.NUD_PROBE:
		return "probe"
	case netlink.NUD_FAILED:
		return "failed"
	case netlink.NUD_PERMANENT:
		return "permanent"
	case netlink.NUD_INCOMPLETE:
		return "incomplete"
	case netlink.NUD_NOARP:
		return "noarp"
	default:
		return "unknown"
	}
}

func (c *CLI) buildInterfacesInput() cluster.InterfacesInput {
	var input cluster.InterfacesInput
	cfg := c.store.ActiveConfig()
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return input
	}
	cc := cfg.Chassis.Cluster
	input.ControlInterface = cc.ControlInterface
	input.FabricInterface = cc.FabricInterface
	if fabIfc, ok := config.LookupInterface(cfg, cc.FabricInterface); ok {
		input.FabricMembers = fabIfc.FabricMembers
	}
	input.Fabric1Interface = cc.Fabric1Interface
	if fab1Ifc, ok := config.LookupInterface(cfg, cc.Fabric1Interface); ok {
		input.Fabric1Members = fab1Ifc.FabricMembers
	}

	rethMap := cfg.RethToPhysical()
	for name, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil { // #5886: skip present-but-nil InterfaceConfig
			continue
		}
		if ifc.RedundancyGroup > 0 && strings.HasPrefix(name, "reth") {
			status := "Up"
			if phys, ok := rethMap[name]; ok {
				linuxName := config.LinuxIfName(phys)
				link, err := netlink.LinkByName(linuxName)
				if err != nil || !cluster.LinkAttrsUp(link.Attrs()) {
					status = "Down"
				}
			}
			input.Reths = append(input.Reths, cluster.RethInfo{
				Name:            name,
				RedundancyGroup: ifc.RedundancyGroup,
				Status:          status,
			})
		}
	}
	sort.Slice(input.Reths, func(i, j int) bool { return input.Reths[i].Name < input.Reths[j].Name })

	localMonMap := make(map[string]bool)
	monStatuses := make(map[int][]routing.InterfaceMonitorStatus)
	if c.routing != nil {
		if ms := c.routing.InterfaceMonitorStatuses(); ms != nil {
			monStatuses = ms
		}
	}
	for _, rg := range cc.RedundancyGroups {
		if statuses, ok := monStatuses[rg.ID]; ok {
			for _, st := range statuses {
				input.Monitors = append(input.Monitors, cluster.InterfaceMonitorInfo{
					Interface:        st.Interface,
					Weight:           st.Weight,
					Up:               st.Up,
					RedundancyGroup:  rg.ID,
					ConfiguredWeight: st.ConfiguredWeight, // #6589
					Clamped:          st.Clamped,
				})
				localMonMap[st.Interface] = true
			}
		} else {
			for _, mon := range rg.InterfaceMonitors {
				// #6549: render the weight the election would APPLY, not the
				// raw configured one. An out-of-range weight survives the
				// tolerant load / peer-sync compile (#1960 no-brick) and the
				// runtime bounds it to [0,255].
				w, clamped := config.ClampInterfaceMonitorWeight(mon.Weight)
				input.Monitors = append(input.Monitors, cluster.InterfaceMonitorInfo{
					Interface:        mon.Interface,
					Weight:           w,
					Up:               true,
					RedundancyGroup:  rg.ID,
					ConfiguredWeight: mon.Weight,
					Clamped:          clamped, // #6589
				})
				localMonMap[mon.Interface] = true
			}
		}
	}

	if c.cluster != nil {
		peerLive := c.cluster.PeerMonitorStatuses()
		peerMap := make(map[string]bool)
		for _, pm := range peerLive {
			peerMap[pm.Interface] = true
			input.PeerMonitors = append(input.PeerMonitors, pm)
		}
		for _, rg := range cc.RedundancyGroups {
			for _, mon := range rg.InterfaceMonitors {
				if localMonMap[mon.Interface] {
					continue
				}
				if peerMap[mon.Interface] {
					continue
				}
				// #6549: the peer bounds this weight the same way we do, so
				// render the effective value rather than the raw config one.
				w, clamped := config.ClampInterfaceMonitorWeight(mon.Weight)
				input.PeerMonitors = append(input.PeerMonitors, cluster.InterfaceMonitorInfo{
					Interface:        mon.Interface,
					Weight:           w,
					Up:               false,
					RedundancyGroup:  rg.ID,
					ConfiguredWeight: mon.Weight,
					Clamped:          clamped, // #6589
				})
			}
		}
	}

	return input
}

func (c *CLI) userspaceDataplaneStatus() (dpuserspace.ProcessStatus, error) {
	provider, ok := c.dpProbe().(cliUserspaceStatusProvider)
	if !ok {
		return dpuserspace.ProcessStatus{}, fmt.Errorf("userspace status unavailable")
	}
	return provider.Status()
}

func (c *CLI) userspaceDataplaneControl() (cliUserspaceControlProvider, error) {
	provider, ok := c.dpProbe().(cliUserspaceControlProvider)
	if !ok {
		return nil, fmt.Errorf("userspace dataplane control unavailable")
	}
	return provider, nil
}

func (c *CLI) userspaceDataplaneFIB() (uint32, []dpuserspace.FibRouteWire, error) {
	provider, ok := c.dpProbe().(cliUserspaceFIBProvider)
	if !ok {
		return 0, nil, fmt.Errorf("userspace helper FIB unavailable")
	}
	return provider.DumpFIB()
}

func fmtPref(p int) string {
	if p == 0 {
		return "-"
	}
	return strconv.Itoa(p)
}

// The hand-written CLI policy shadow matchers (matchPolicyAddr /
// matchPolicyAddrSet / matchPolicyApp / matchSingleApp) were removed in
// #3042. The `show security match-policies` and `test policy` commands now
// delegate to the single shared simulator in pkg/policymatch, which matches
// the runtime policy evaluator (zone-pair -> global -> default-policy,
// predefined apps, nested application-sets, literal CIDRs, any-ipv4/any-ipv6,
// source/destination exclusion).
