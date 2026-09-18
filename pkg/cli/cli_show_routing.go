package cli

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/cmdtree"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/frr"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/psaab/xpf/pkg/termsafe"
	"github.com/psaab/xpf/pkg/vrrp"
	"github.com/vishvananda/netlink"
)

// handleShowRoute dispatches `show route ...` invocations to the
// per-flavor presenters defined later in this file.
func (c *CLI) handleShowRoute(args []string) error {
	if len(args) >= 2 && args[0] == "instance" {
		return c.showRoutesForInstance(args[1])
	}
	if len(args) >= 2 && args[0] == "table" {
		return c.showRoutesForVRF(args[1])
	}
	if len(args) >= 2 && args[0] == "protocol" {
		return c.showRoutesForProtocol(args[1])
	}
	if len(args) >= 1 && args[0] == "terse" {
		return c.showRouteTerse()
	}
	if len(args) >= 1 && args[0] == "summary" {
		return c.showRouteSummary()
	}
	if len(args) >= 1 && args[0] == "detail" {
		return c.showRouteDetail()
	}
	// Treat first arg as prefix filter (e.g. "show route 10.0.1.0/24")
	// Optional second arg is a modifier: exact, longer, orlonger
	if len(args) >= 1 && (strings.Contains(args[0], "/") || strings.Contains(args[0], ".") || strings.Contains(args[0], ":")) {
		modifier := ""
		if len(args) >= 2 {
			switch args[1] {
			case "exact", "longer", "orlonger":
				modifier = args[1]
			}
		}
		return c.showRoutesForPrefix(args[0], modifier)
	}
	return c.showRoutes()
}

// handleShowProtocols dispatches `show protocols ...` invocations to the
// per-protocol presenters defined later in this file.
func (c *CLI) handleShowProtocols(args []string) error {
	if len(args) == 0 {
		cmdtree.PrintTreeHelp("show protocols:", operationalTree, "show", "protocols")
		return nil
	}

	switch args[0] {
	case "ospf":
		return c.showOSPF(args[1:])
	case "bgp":
		return c.showBGP(args[1:])
	case "bfd":
		return c.showBFD(args[1:])
	case "rip":
		return c.showRIP()
	case "isis":
		return c.showISIS(args[1:])
	default:
		return fmt.Errorf("unknown show protocols target: %s", args[0])
	}
}

func (c *CLI) showRoutes() error {
	if c.routing == nil {
		fmt.Println("Routing manager not available")
		return nil
	}

	cfg := c.store.ActiveConfig()
	var instances []*config.RoutingInstanceConfig
	if cfg != nil {
		instances = cfg.RoutingInstances
	}

	allTables, err := c.routing.GetAllTableRoutes(instances)
	if err != nil {
		// A per-family/per-table dump failure is non-fatal: render whatever
		// was read and surface the failure so the operator can tell a partial
		// from a genuinely empty table (#5125).
		fmt.Printf("warning: partial route display (some address families unavailable): %v\n", err)
	}

	fmt.Print(routing.FormatAllRoutes(allTables))
	return nil
}

func (c *CLI) showRouteTerse() error {
	if c.routing == nil {
		fmt.Println("Routing manager not available")
		return nil
	}
	entries, err := c.routing.GetRoutes()
	if err != nil {
		fmt.Printf("warning: partial route display (some address families unavailable): %v\n", err)
	}
	fmt.Print(routing.FormatRouteTerse(entries))
	return nil
}

func (c *CLI) showRoutesForInstance(instanceName string) error {
	if c.routing == nil {
		fmt.Println("Routing manager not available")
		return nil
	}

	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}

	var tableID int
	found := false
	for _, ri := range cfg.RoutingInstances {
		if ri.Name == instanceName {
			tableID = ri.TableID
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("routing instance %q not found", instanceName)
	}

	entries, err := c.routing.GetRoutesForTable(tableID)
	if err != nil {
		fmt.Printf("warning: partial route display for instance %s (some address families unavailable): %v\n", instanceName, err)
	}

	fmt.Printf("Routing table for instance %s (table %d):\n", instanceName, tableID)
	fmt.Printf("  %-24s %-20s %-14s %-12s %s\n",
		"Destination", "Next-hop", "Interface", "Proto", "Pref")
	for _, e := range entries {
		fmt.Printf("  %-24s %-20s %-14s %-12s %d\n",
			e.Destination, e.NextHop, e.Interface, e.Protocol, e.Preference)
	}
	return nil
}

func (c *CLI) showRoutesForVRF(tableName string) error {
	if c.routing == nil {
		fmt.Println("Routing manager not available")
		return nil
	}

	entries, err := c.routing.GetTableRoutes(tableName)
	if err != nil {
		return fmt.Errorf("get table routes: %w", err)
	}

	if len(entries) == 0 {
		fmt.Printf("No routes in table %s\n", tableName)
		return nil
	}

	fmt.Print(routing.FormatAllRoutes([]routing.TableRoutes{{Name: tableName, Entries: entries}}))
	return nil
}

func (c *CLI) showRoutesForProtocol(proto string) error {
	if c.routing == nil {
		fmt.Println("Routing manager not available")
		return nil
	}

	entries, err := c.routing.GetRoutes()
	if err != nil {
		fmt.Printf("warning: partial route display (some address families unavailable): %v\n", err)
	}

	proto = strings.ToLower(proto)
	fmt.Printf("Routes matching protocol: %s\n", proto)
	fmt.Printf("  %-24s %-20s %-14s %-12s %s\n",
		"Destination", "Next-hop", "Interface", "Proto", "Pref")
	count := 0
	for _, e := range entries {
		if strings.ToLower(e.Protocol) == proto {
			fmt.Printf("  %-24s %-20s %-14s %-12s %d\n",
				e.Destination, e.NextHop, e.Interface, e.Protocol, e.Preference)
			count++
		}
	}
	if count == 0 {
		fmt.Printf("  (no routes)\n")
	}
	return nil
}

func (c *CLI) showRoutesForPrefix(prefix, modifier string) error {
	if c.routing == nil {
		fmt.Println("Routing manager not available")
		return nil
	}

	cfg := c.store.ActiveConfig()
	var instances []*config.RoutingInstanceConfig
	if cfg != nil {
		instances = cfg.RoutingInstances
	}

	allTables, err := c.routing.GetAllTableRoutes(instances)
	if err != nil {
		fmt.Printf("warning: partial route display (some address families unavailable): %v\n", err)
	}

	fmt.Print(routing.FormatRouteDestination(allTables, prefix, modifier))
	return nil
}

func (c *CLI) showRouteSummary() error {
	if c.routing == nil {
		fmt.Println("Routing manager not available")
		return nil
	}

	cfg := c.store.ActiveConfig()
	var instances []*config.RoutingInstanceConfig
	if cfg != nil {
		instances = cfg.RoutingInstances
	}
	allTables, err := c.routing.GetAllTableRoutes(instances)
	if err != nil {
		fmt.Printf("warning: partial route display (some address families unavailable): %v\n", err)
	}

	routerID := ""
	if cfg != nil {
		if cfg.Protocols.OSPF != nil && cfg.Protocols.OSPF.RouterID != "" {
			routerID = cfg.Protocols.OSPF.RouterID
		} else if cfg.Protocols.BGP != nil && cfg.Protocols.BGP.RouterID != "" {
			routerID = cfg.Protocols.BGP.RouterID
		}
	}

	fmt.Print(routing.FormatRouteSummary(allTables, routerID))
	return nil
}

func (c *CLI) showRouteDetail() error {
	if c.frr == nil {
		fmt.Println("FRR manager not available")
		return nil
	}

	routes, err := c.frr.GetRouteDetailJSON(context.Background())
	if err != nil {
		fmt.Printf("warning: partial route display (some address families unavailable): %v\n", err)
	}

	if len(routes) == 0 {
		fmt.Println("No routes")
		return nil
	}

	fmt.Print(frr.FormatRouteDetail(routes))
	return nil
}

func (c *CLI) showOSPF(args []string) error {
	if c.frr == nil {
		fmt.Println("FRR manager not available")
		return nil
	}

	if len(args) == 0 {
		cmdtree.PrintTreeHelp("show protocols ospf:", operationalTree, "show", "protocols", "ospf")
		return nil
	}

	switch args[0] {
	case "neighbor":
		if len(args) >= 2 && args[1] == "detail" {
			output, err := c.frr.GetOSPFNeighborDetail(context.Background())
			if err != nil {
				return fmt.Errorf("OSPF neighbor detail: %w", err)
			}
			fmt.Print(termsafe.SanitizeBlockForDisplay(output))
			return nil
		}
		neighbors, err := c.frr.GetOSPFNeighbors(context.Background())
		if err != nil {
			return fmt.Errorf("OSPF neighbors: %w", err)
		}
		if len(neighbors) == 0 {
			fmt.Println("No OSPF neighbors")
			return nil
		}
		fmt.Printf("  %-18s %-10s %-16s %-18s %s\n",
			"Neighbor ID", "Priority", "State", "Address", "Interface")
		for _, n := range neighbors {
			fmt.Printf("  %-18s %-10s %-16s %-18s %s\n",
				termsafe.SanitizeRowForDisplay(
					n.NeighborID, n.Priority, n.State, n.Address, n.Interface)...)
		}
		return nil

	case "database":
		output, err := c.frr.GetOSPFDatabase(context.Background())
		if err != nil {
			return fmt.Errorf("OSPF database: %w", err)
		}
		fmt.Print(termsafe.SanitizeBlockForDisplay(output))
		return nil

	case "interface":
		output, err := c.frr.GetOSPFInterface(context.Background())
		if err != nil {
			return fmt.Errorf("OSPF interface: %w", err)
		}
		fmt.Print(termsafe.SanitizeBlockForDisplay(output))
		return nil

	case "routes":
		output, err := c.frr.GetOSPFRoutes(context.Background())
		if err != nil {
			return fmt.Errorf("OSPF routes: %w", err)
		}
		fmt.Print(termsafe.SanitizeBlockForDisplay(output))
		return nil

	default:
		return fmt.Errorf("unknown show protocols ospf target: %s", args[0])
	}
}

func (c *CLI) showBGP(args []string) error {
	if c.frr == nil {
		fmt.Println("FRR manager not available")
		return nil
	}

	if len(args) == 0 {
		cmdtree.PrintTreeHelp("show protocols bgp:", operationalTree, "show", "protocols", "bgp")
		return nil
	}

	switch args[0] {
	case "summary":
		peers, err := c.frr.GetBGPSummary(context.Background())
		if err != nil {
			return fmt.Errorf("BGP summary: %w", err)
		}
		if len(peers) == 0 {
			fmt.Println("No BGP peers")
			return nil
		}
		fmt.Printf("  %-20s %-13s %-8s %-9s %-9s %-11s %-12s %s\n",
			"Neighbor", "AF", "AS", "MsgRcvd", "MsgSent", "Up/Down", "State", "PfxRcd")
		for _, p := range peers {
			fmt.Printf("  %-20s %-13s %-8s %-9s %-9s %-11s %-12s %s\n",
				termsafe.SanitizeRowForDisplay(
					p.Neighbor, p.AddressFamily, p.AS, p.MsgRcvd, p.MsgSent, p.UpDown, p.State, p.PfxRcd)...)
		}
		return nil

	case "routes":
		routes, err := c.frr.GetBGPRoutes(context.Background())
		if err != nil {
			return fmt.Errorf("BGP routes: %w", err)
		}
		if len(routes) == 0 {
			fmt.Println("No BGP routes")
			return nil
		}
		fmt.Printf("  %-24s %-20s %s\n", "Network", "Next-hop", "Path")
		for _, r := range routes {
			fmt.Printf("  %-24s %-20s %s\n",
				termsafe.SanitizeRowForDisplay(r.Network, r.NextHop, r.Path)...)
		}
		return nil

	case "neighbor":
		ip := ""
		if len(args) >= 2 {
			ip = args[1]
		}
		// Check for sub-commands: received-routes, advertised-routes
		if len(args) >= 3 {
			switch args[2] {
			case "received-routes":
				output, err := c.frr.GetBGPNeighborReceivedRoutes(context.Background(), ip)
				if err != nil {
					return fmt.Errorf("BGP received routes: %w", err)
				}
				fmt.Print(termsafe.SanitizeBlockForDisplay(output))
				return nil
			case "advertised-routes":
				output, err := c.frr.GetBGPNeighborAdvertisedRoutes(context.Background(), ip)
				if err != nil {
					return fmt.Errorf("BGP advertised routes: %w", err)
				}
				fmt.Print(termsafe.SanitizeBlockForDisplay(output))
				return nil
			}
		}
		output, err := c.frr.GetBGPNeighborDetail(context.Background(), ip)
		if err != nil {
			return fmt.Errorf("BGP neighbor: %w", err)
		}
		fmt.Print(termsafe.SanitizeBlockForDisplay(output))
		return nil

	default:
		return fmt.Errorf("unknown show protocols bgp target: %s", args[0])
	}
}

func (c *CLI) showRIP() error {
	if c.frr == nil {
		fmt.Println("FRR manager not available")
		return nil
	}

	routes, err := c.frr.GetRIPRoutes(context.Background())
	if err != nil {
		return fmt.Errorf("RIP routes: %w", err)
	}
	if len(routes) == 0 {
		fmt.Println("No RIP routes")
		return nil
	}
	fmt.Printf("  %-20s %-18s %-8s %s\n", "Network", "Next Hop", "Metric", "Interface")
	for _, r := range routes {
		fmt.Printf("  %-20s %-18s %-8s %s\n",
			termsafe.SanitizeRowForDisplay(r.Network, r.NextHop, r.Metric, r.Interface)...)
	}
	return nil
}

func (c *CLI) showISIS(args []string) error {
	if c.frr == nil {
		fmt.Println("FRR manager not available")
		return nil
	}

	if len(args) == 0 {
		cmdtree.PrintTreeHelp("show protocols isis:", operationalTree, "show", "protocols", "isis")
		return nil
	}

	switch args[0] {
	case "adjacency":
		if len(args) >= 2 && args[1] == "detail" {
			output, err := c.frr.GetISISAdjacencyDetail(context.Background())
			if err != nil {
				return fmt.Errorf("IS-IS adjacency detail: %w", err)
			}
			fmt.Print(termsafe.SanitizeBlockForDisplay(output))
			return nil
		}
		adjs, err := c.frr.GetISISAdjacency(context.Background())
		if err != nil {
			return fmt.Errorf("IS-IS adjacency: %w", err)
		}
		if len(adjs) == 0 {
			fmt.Println("No IS-IS adjacencies")
			return nil
		}
		fmt.Printf("  %-20s %-14s %-10s %-10s %s\n",
			"System ID", "Interface", "Level", "State", "Hold Time")
		for _, a := range adjs {
			// #7430: an unparseable row is REPORTED, not dropped. A dropped row is
			// indistinguishable from "no such adjacency" to an operator debugging a
			// missing neighbour, and points at the wrong problem. Rendering it with
			// empty derived fields would report a neighbour in state "" — quieter
			// than column-forgery but still false — so the raw line is shown under a
			// single heading instead of split across the parsed columns.
			//
			// Raw is peer-influenced text and goes through termsafe exactly as the
			// parsed cells do (#6468).
			if a.Malformed {
				fmt.Printf("  %s\n",
					termsafe.SanitizeForDisplay("<unparseable IS-IS neighbor row: "+a.Raw+">"))
				continue
			}
			fmt.Printf("  %-20s %-14s %-10s %-10s %s\n",
				termsafe.SanitizeRowForDisplay(
					a.SystemID, a.Interface, a.Level, a.State, a.HoldTime)...)
		}
		return nil

	case "database":
		output, err := c.frr.GetISISDatabase(context.Background())
		if err != nil {
			return fmt.Errorf("IS-IS database: %w", err)
		}
		fmt.Print(termsafe.SanitizeBlockForDisplay(output))
		return nil

	case "routes":
		output, err := c.frr.GetISISRoutes(context.Background())
		if err != nil {
			return fmt.Errorf("IS-IS routes: %w", err)
		}
		fmt.Print(termsafe.SanitizeBlockForDisplay(output))
		return nil

	default:
		return fmt.Errorf("unknown show protocols isis target: %s", args[0])
	}
}

func (c *CLI) showBFD(args []string) error {
	if c.frr == nil {
		fmt.Println("FRR manager not available")
		return nil
	}
	if len(args) == 0 {
		cmdtree.PrintTreeHelp("show protocols bfd:", operationalTree, "show", "protocols", "bfd")
		return nil
	}
	if args[0] == "peers" {
		output, err := c.frr.GetBFDPeers(context.Background())
		if err != nil {
			return fmt.Errorf("BFD peers: %w", err)
		}
		if output == "" {
			fmt.Println("No BFD peers")
			return nil
		}
		fmt.Print(termsafe.SanitizeBlockForDisplay(output))
		return nil
	}
	return fmt.Errorf("unknown show protocols bfd target: %s", args[0])
}

func (c *CLI) showVRRP() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}

	instances := vrrp.CollectInstances(cfg)
	if len(instances) == 0 {
		fmt.Println("No VRRP groups configured")
		return nil
	}

	// Get runtime states from VRRP manager.
	var states map[string]string
	if c.vrrpMgr != nil {
		states = c.vrrpMgr.States()
		fmt.Println(c.vrrpMgr.Status())
	}

	fmt.Printf("%-14s %-6s %-8s %-10s %-16s %-8s\n",
		"Interface", "Group", "State", "Priority", "VIP", "Preempt")
	for _, inst := range instances {
		key := vrrp.StateKey(inst.Interface, inst.GroupID, inst.Family)
		state := "INIT"
		if s, ok := states[key]; ok {
			state = s
		}
		preempt := "no"
		if inst.Preempt {
			preempt = "yes"
		}
		vip := strings.Join(inst.VirtualAddresses, ",")
		fmt.Printf("%-14s %-6d %-8s %-10d %-16s %-8s\n",
			inst.Interface, inst.GroupID, state, inst.Priority, vip, preempt)
	}
	return nil
}

// fmtBytes formats bytes as human-readable (K/M/G).

func (c *CLI) showARP(args []string) error {
	// Accept and validate "no-resolve" argument (Junos syntax)
	for _, arg := range args {
		if arg != "no-resolve" {
			return fmt.Errorf("unknown option: %s (try: show arp no-resolve)", arg)
		}
	}

	neighbors, err := netlink.NeighList(0, netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("listing ARP entries: %w", err)
	}

	// Junos format: MAC Address, Address, Name, Interface, Flags
	fmt.Printf("%-18s%-16s%-25s%s\n", "MAC Address", "Address", "Interface", "Flags")
	var total int
	for _, n := range neighbors {
		if n.IP == nil || n.HardwareAddr == nil {
			continue
		}
		total++
		ifName := ""
		if link, err := netlink.LinkByIndex(n.LinkIndex); err == nil {
			ifName = link.Attrs().Name
		}
		flags := "none"
		if n.State == netlink.NUD_PERMANENT {
			flags = "permanent"
		}
		fmt.Printf("%-18s%-16s%-25s%s\n",
			n.HardwareAddr, n.IP, ifName, flags)
	}
	fmt.Printf("Total entries: %d\n", total)
	return nil
}

// handleShowIPv6 dispatches show ipv6 sub-commands.

func (c *CLI) showIPv6Neighbors() error {
	neighbors, err := netlink.NeighList(0, netlink.FAMILY_V6)
	if err != nil {
		return fmt.Errorf("listing IPv6 neighbors: %w", err)
	}

	// Count entries by state and interface
	var total int
	stateCounts := make(map[string]int)
	ifaceCounts := make(map[string]int)
	for _, n := range neighbors {
		if n.IP == nil || n.HardwareAddr == nil {
			continue
		}
		total++
		stateCounts[neighState(n.State)]++
		if link, err := netlink.LinkByIndex(n.LinkIndex); err == nil {
			ifaceCounts[link.Attrs().Name]++
		}
	}

	// Summary
	fmt.Printf("Total entries: %d", total)
	if total > 0 {
		var parts []string
		for _, s := range []string{"reachable", "stale", "permanent", "delay", "probe", "failed", "incomplete"} {
			if cnt := stateCounts[s]; cnt > 0 {
				parts = append(parts, fmt.Sprintf("%s: %d", s, cnt))
			}
		}
		if len(parts) > 0 {
			fmt.Printf(" (%s)", strings.Join(parts, ", "))
		}
	}
	fmt.Println()
	if len(ifaceCounts) > 1 {
		var ifNames []string
		for name := range ifaceCounts {
			ifNames = append(ifNames, name)
		}
		sort.Strings(ifNames)
		for _, name := range ifNames {
			fmt.Printf("  %-12s %d entries\n", name, ifaceCounts[name])
		}
	}
	fmt.Println()

	fmt.Printf("%-18s %-40s %-12s %-10s\n", "MAC Address", "IPv6 Address", "Interface", "State")
	for _, n := range neighbors {
		if n.IP == nil {
			continue
		}
		// Skip link-local multicast and unresolved entries without MACs
		if n.HardwareAddr == nil {
			continue
		}
		ifName := ""
		if link, err := netlink.LinkByIndex(n.LinkIndex); err == nil {
			ifName = link.Attrs().Name
		}
		state := neighState(n.State)
		fmt.Printf("%-18s %-40s %-12s %-10s\n",
			n.HardwareAddr, n.IP, ifName, state)
	}
	return nil
}

// neighState converts a kernel neighbor state to a human-readable string.

func (c *CLI) showIPv6RouterAdvertisement() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil || len(cfg.Protocols.RouterAdvertisement) == 0 {
		fmt.Println("Router Advertisements: not configured")
		return nil
	}

	fmt.Printf("Router Advertisement: %d interface(s) configured\n\n", len(cfg.Protocols.RouterAdvertisement))

	for _, ra := range cfg.Protocols.RouterAdvertisement {
		fmt.Printf("Interface: %s\n", ra.Interface)

		// #4119: an explicit default-lifetime 0 ("not a default router", RFC
		// 4861 §6.2.1) is shown as 0; only an unset leaf shows the 1800
		// default.
		lifetime := 1800
		if ra.DefaultLifetimeSet {
			lifetime = ra.DefaultLifetime
		}
		fmt.Printf("  Router lifetime:    %ds\n", lifetime)

		pref := ra.Preference
		if pref == "" {
			pref = "medium"
		}
		fmt.Printf("  Preference:         %s\n", pref)

		maxAdv := ra.MaxAdvInterval
		if maxAdv <= 0 {
			maxAdv = 600
		}
		minAdv := ra.MinAdvInterval
		if minAdv <= 0 {
			minAdv = maxAdv / 3
		}
		fmt.Printf("  Max RA interval:    %ds\n", maxAdv)
		fmt.Printf("  Min RA interval:    %ds\n", minAdv)

		if ra.ManagedConfig {
			fmt.Println("  Managed flag:       on")
		}
		if ra.OtherStateful {
			fmt.Println("  Other config flag:  on")
		}
		if ra.LinkMTU > 0 {
			fmt.Printf("  Link MTU:           %d\n", ra.LinkMTU)
		}

		for _, pfx := range ra.Prefixes {
			fmt.Printf("  Prefix: %s\n", pfx.Prefix)
			fmt.Printf("    On-link:          %t\n", pfx.OnLink)
			fmt.Printf("    Autonomous:       %t\n", pfx.Autonomous)
			if pfx.ValidLifetime > 0 {
				fmt.Printf("    Valid lifetime:   %ds\n", pfx.ValidLifetime)
			}
			if pfx.PreferredLife > 0 {
				fmt.Printf("    Preferred life:   %ds\n", pfx.PreferredLife)
			}
		}

		if len(ra.DNSServers) > 0 {
			fmt.Printf("  DNS servers:        %s\n", strings.Join(ra.DNSServers, ", "))
		}
		if ra.NAT64Prefix != "" {
			fmt.Printf("  PREF64:             %s\n", ra.NAT64Prefix)
		}
		fmt.Println()
	}
	return nil
}

// showRouteMap displays FRR route-map information via vtysh.

func (c *CLI) showRouteMap() error {
	if c.frr == nil {
		fmt.Println("FRR manager not available")
		return nil
	}
	output, err := c.frr.GetRouteMapList(context.Background())
	if err != nil {
		return fmt.Errorf("get route-map: %w", err)
	}
	if output == "" {
		fmt.Println("No route-maps configured")
		return nil
	}
	fmt.Print(termsafe.SanitizeBlockForDisplay(output))
	return nil
}

// showPolicyOptions displays prefix-lists and policy-statements.

func (c *CLI) showPolicyOptions() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}
	po := &cfg.PolicyOptions

	if len(po.PrefixLists) > 0 {
		fmt.Println("Prefix lists:")
		for name, pl := range po.PrefixLists {
			fmt.Printf("  %-30s %d prefixes\n", name, len(pl.Prefixes))
			for _, p := range pl.Prefixes {
				fmt.Printf("    %s\n", p)
			}
		}
	}

	if len(po.PolicyStatements) > 0 {
		if len(po.PrefixLists) > 0 {
			fmt.Println()
		}
		fmt.Println("Policy statements:")
		for name, ps := range po.PolicyStatements {
			fmt.Printf("  %s", name)
			if ps.DefaultAction != "" {
				fmt.Printf(" (default: %s)", ps.DefaultAction)
			}
			fmt.Println()
			for _, t := range ps.Terms {
				fmt.Printf("    term %s:\n", t.Name)
				if len(t.FromProtocols) == 1 {
					fmt.Printf("      from protocol %s\n", t.FromProtocols[0])
				} else if len(t.FromProtocols) > 1 {
					fmt.Printf("      from protocol [ %s ]\n", strings.Join(t.FromProtocols, " "))
				}
				for _, pl := range t.PrefixList {
					fmt.Printf("      from prefix-list %s\n", pl)
				}
				for _, c := range t.FromCommunity {
					fmt.Printf("      from community %s\n", c)
				}
				for _, ap := range t.FromASPath {
					fmt.Printf("      from as-path %s\n", ap)
				}
				for _, rf := range t.RouteFilters {
					match := rf.MatchType
					if rf.MatchType == "upto" && rf.UptoLen > 0 {
						match = fmt.Sprintf("upto /%d", rf.UptoLen)
					}
					fmt.Printf("      from route-filter %s %s\n", rf.Prefix, match)
				}
				if t.Action != "" {
					fmt.Printf("      then %s\n", t.Action)
				}
				if t.NextHop != "" {
					fmt.Printf("      then next-hop %s\n", t.NextHop)
				}
				if t.LoadBalance != "" {
					fmt.Printf("      then load-balance %s\n", t.LoadBalance)
				}
			}
		}
	}

	if len(po.PrefixLists) == 0 && len(po.PolicyStatements) == 0 {
		fmt.Println("No policy-options configured")
	}
	return nil
}

// showEventOptions displays event-driven policies.

func (c *CLI) showEventOptions() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}
	if len(cfg.EventOptions) == 0 {
		fmt.Println("No event-options configured")
		return nil
	}

	for _, ep := range cfg.EventOptions {
		fmt.Printf("Policy: %s\n", ep.Name)
		if len(ep.Events) > 0 {
			fmt.Printf("  Events: %s\n", strings.Join(ep.Events, ", "))
		}
		for _, w := range ep.WithinClauses {
			if w == nil {
				continue // #9916 F-135: never panic display on a corrupt clause
			}
			fmt.Printf("  Within: %d seconds", w.Seconds)
			if w.TriggerOn > 0 {
				fmt.Printf(", trigger on %d", w.TriggerOn)
			}
			if w.TriggerUntil > 0 {
				fmt.Printf(", trigger until %d", w.TriggerUntil)
			}
			fmt.Println()
		}
		if len(ep.AttributesMatch) > 0 {
			fmt.Println("  Attributes match:")
			for _, am := range ep.AttributesMatch {
				fmt.Printf("    %s\n", am)
			}
		}
		if len(ep.ThenCommands) > 0 {
			fmt.Println("  Then commands:")
			for _, cmd := range ep.ThenCommands {
				fmt.Printf("    %s\n", cmd)
			}
		}
		fmt.Println()
	}
	return nil
}

// showRoutingOptions displays static routes and routing config.

func (c *CLI) showRoutingOptions() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}
	ro := &cfg.RoutingOptions
	// #7357: which static routes buildRouteSnapshots DROPS. Computed once for
	// the whole config because the next-table window verdict is order-dependent
	// — it depends on how many eligible global leaks precede a route, so it
	// cannot be decided per row. Same predicate the builder consults, so a
	// dropped route cannot render here as an installed one.
	staticExcluded := config.StaticRouteExclusions(cfg)
	hasContent := false

	if ro.AutonomousSystem > 0 {
		fmt.Printf("Autonomous system: %d\n\n", ro.AutonomousSystem)
		hasContent = true
	}

	if ro.ForwardingTableExport != "" {
		fmt.Printf("Forwarding-table export: %s\n\n", ro.ForwardingTableExport)
		hasContent = true
	}

	if len(ro.StaticRoutes) > 0 {
		fmt.Println("Static routes (inet.0):")
		fmt.Printf("  %-24s %-20s %-6s %s\n", "Destination", "Next-Hop", "Pref", "Flags")
		for _, sr := range ro.StaticRoutes {
			if sr.Discard {
				fmt.Printf("  %-24s %-20s %-6s %s\n", sr.Destination, "discard", fmtPref(sr.Preference), "")
				printStaticRouteNotInstalled(staticExcluded, sr)
				continue
			}
			if sr.Reject {
				fmt.Printf("  %-24s %-20s %-6s %s\n", sr.Destination, "reject", fmtPref(sr.Preference), "")
				printStaticRouteNotInstalled(staticExcluded, sr)
				continue
			}
			if sr.NextTable != "" {
				fmt.Printf("  %-24s %-20s %-6s %s\n", sr.Destination, "next-table "+sr.NextTable, fmtPref(sr.Preference), "")
				printStaticRouteNotInstalled(staticExcluded, sr)
				continue
			}
			for i, nh := range sr.NextHops {
				dest := sr.Destination
				if i > 0 {
					dest = "" // don't repeat destination for ECMP entries
				}
				nhStr := nh.Address
				if nh.Interface != "" {
					nhStr += " via " + nh.Interface
				}
				fmt.Printf("  %-24s %-20s %-6s %s\n", dest, nhStr, fmtPref(sr.Preference), "")
			}
			printStaticRouteNotInstalled(staticExcluded, sr)
		}
		fmt.Println()
		hasContent = true
	}

	if len(ro.Inet6StaticRoutes) > 0 {
		fmt.Println("Static routes (inet6.0):")
		fmt.Printf("  %-40s %-30s %-6s\n", "Destination", "Next-Hop", "Pref")
		for _, sr := range ro.Inet6StaticRoutes {
			if sr.Discard {
				fmt.Printf("  %-40s %-30s %-6s\n", sr.Destination, "discard", fmtPref(sr.Preference))
				printStaticRouteNotInstalled(staticExcluded, sr)
				continue
			}
			if sr.Reject {
				fmt.Printf("  %-40s %-30s %-6s\n", sr.Destination, "reject", fmtPref(sr.Preference))
				printStaticRouteNotInstalled(staticExcluded, sr)
				continue
			}
			if sr.NextTable != "" {
				fmt.Printf("  %-40s %-30s %-6s\n", sr.Destination, "next-table "+sr.NextTable, fmtPref(sr.Preference))
				printStaticRouteNotInstalled(staticExcluded, sr)
				continue
			}
			for i, nh := range sr.NextHops {
				dest := sr.Destination
				if i > 0 {
					dest = ""
				}
				nhStr := nh.Address
				if nh.Interface != "" {
					nhStr += " via " + nh.Interface
				}
				fmt.Printf("  %-40s %-30s %-6s\n", dest, nhStr, fmtPref(sr.Preference))
			}
			printStaticRouteNotInstalled(staticExcluded, sr)
		}
		fmt.Println()
		hasContent = true
	}

	if len(ro.RibGroups) > 0 {
		fmt.Println("RIB groups:")
		for name, rg := range ro.RibGroups {
			fmt.Printf("  %-20s import-rib: %s\n", name, strings.Join(rg.ImportRibs, ", "))
		}
		fmt.Println()
		hasContent = true
	}

	if !hasContent {
		fmt.Println("No routing-options configured")
	}
	return nil
}

func (c *CLI) showRoutingInstances(detail bool) error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}
	if len(cfg.RoutingInstances) == 0 {
		fmt.Println("No routing instances configured")
		return nil
	}
	// #7357: a per-instance `next-table` is never programmed (#5830), so this
	// surface must not print it as a live forwarding decision.
	staticExcluded := config.StaticRouteExclusions(cfg)

	if !detail {
		fmt.Printf("%-20s %-16s %-6s %s\n", "Instance", "Type", "Table", "Interfaces")
		for _, ri := range cfg.RoutingInstances {
			tableID := "-"
			if ri.TableID > 0 {
				tableID = fmt.Sprintf("%d", ri.TableID)
			}
			ifaces := "-"
			if len(ri.Interfaces) > 0 {
				ifaces = strings.Join(ri.Interfaces, ", ")
			}
			fmt.Printf("%-20s %-16s %-6s %s\n", ri.Name, ri.InstanceType, tableID, ifaces)
			if ri.Description != "" {
				fmt.Printf("  Description: %s\n", ri.Description)
			}
		}
		return nil
	}

	for _, ri := range cfg.RoutingInstances {
		fmt.Printf("Instance: %s\n", ri.Name)
		if ri.Description != "" {
			fmt.Printf("  Description: %s\n", ri.Description)
		}
		fmt.Printf("  Type: %s\n", ri.InstanceType)
		if ri.TableID > 0 {
			fmt.Printf("  Table ID: %d\n", ri.TableID)
		}
		if len(ri.Interfaces) > 0 {
			fmt.Printf("  Interfaces: %s\n", strings.Join(ri.Interfaces, ", "))
		}
		if ri.TableID > 0 && c.routing != nil {
			routes, err := c.routing.GetRoutesForTable(ri.TableID)
			fmt.Printf("  Route count: %d\n", len(routes))
			if err != nil {
				fmt.Printf("  warning: partial route count (some address families unavailable): %v\n", err)
			}
		}
		var protos []string
		if ri.OSPF != nil {
			protos = append(protos, "OSPF")
		}
		if ri.BGP != nil {
			protos = append(protos, "BGP")
		}
		if ri.RIP != nil {
			protos = append(protos, "RIP")
		}
		if ri.ISIS != nil {
			protos = append(protos, "IS-IS")
		}
		if len(protos) > 0 {
			fmt.Printf("  Protocols: %s\n", strings.Join(protos, ", "))
		}
		if len(ri.StaticRoutes) > 0 {
			fmt.Printf("  Static routes: %d\n", len(ri.StaticRoutes))
			for _, sr := range ri.StaticRoutes {
				if sr.Discard {
					fmt.Printf("    %s -> discard\n", sr.Destination)
					printStaticRouteNotInstalled(staticExcluded, sr)
					continue
				}
				if sr.Reject {
					fmt.Printf("    %s -> reject\n", sr.Destination)
					printStaticRouteNotInstalled(staticExcluded, sr)
					continue
				}
				// #4908 (C175-HC-129): a next-table static route has no
				// NextHops, so it counted toward "Static routes: N" above but
				// emitted no row. Render it so the printed rows account for the
				// count.
				if sr.NextTable != "" {
					fmt.Printf("    %s -> next-table %s\n", sr.Destination, sr.NextTable)
					printStaticRouteNotInstalled(staticExcluded, sr)
					continue
				}
				for _, nh := range sr.NextHops {
					nhStr := nh.Address
					if nh.Interface != "" {
						nhStr += " via " + nh.Interface
					}
					fmt.Printf("    %s -> %s\n", sr.Destination, nhStr)
				}
				printStaticRouteNotInstalled(staticExcluded, sr)
			}
		}
		if len(ri.Inet6StaticRoutes) > 0 {
			fmt.Printf("  Static routes (inet6.0): %d\n", len(ri.Inet6StaticRoutes))
			for _, sr := range ri.Inet6StaticRoutes {
				if sr.Discard {
					fmt.Printf("    %s -> discard\n", sr.Destination)
					printStaticRouteNotInstalled(staticExcluded, sr)
					continue
				}
				if sr.Reject {
					fmt.Printf("    %s -> reject\n", sr.Destination)
					printStaticRouteNotInstalled(staticExcluded, sr)
					continue
				}
				if sr.NextTable != "" {
					fmt.Printf("    %s -> next-table %s\n", sr.Destination, sr.NextTable)
					printStaticRouteNotInstalled(staticExcluded, sr)
					continue
				}
				for _, nh := range sr.NextHops {
					nhStr := nh.Address
					if nh.Interface != "" {
						nhStr += " via " + nh.Interface
					}
					fmt.Printf("    %s -> %s\n", sr.Destination, nhStr)
				}
				printStaticRouteNotInstalled(staticExcluded, sr)
			}
		}
		if ri.InterfaceRoutesRibGroup != "" {
			fmt.Printf("  Interface routes rib-group: %s\n", ri.InterfaceRoutesRibGroup)
		}
		fmt.Println()
	}
	return nil
}

func (c *CLI) showForwardingOptions() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}
	fo := &cfg.ForwardingOptions
	hasContent := false

	if fo.FamilyInet6Mode != "" {
		fmt.Printf("Family inet6 mode: %s\n", fo.FamilyInet6Mode)
		hasContent = true
	}

	if fo.Sampling != nil && len(fo.Sampling.Instances) > 0 {
		fmt.Println("Sampling:")
		for _, name := range sortedInstanceNames(fo.Sampling.Instances) {
			inst := fo.Sampling.Instances[name]
			fmt.Printf("  Instance: %s\n", name)
			if inst.InputRate > 0 {
				fmt.Printf("    Input rate: 1/%d\n", inst.InputRate)
			}
			for _, fam := range []*config.SamplingFamily{inst.FamilyInet, inst.FamilyInet6} {
				if fam == nil {
					continue
				}
				for _, fs := range fam.FlowServers {
					// #6565 row 11 / #7422: annotate a collector the snapshot
					// builder skips, using its own verdict (see
					// flowServerNotInstalledSuffix).
					fmt.Printf("    Flow server: %s:%d%s\n", fs.Address, fs.Port,
						flowServerNotInstalledSuffix(fs))
					if fs.Version9Template != "" {
						fmt.Printf("      Version 9 template: %s\n", fs.Version9Template)
					}
					if fs.VersionIPFIXTemplate != "" {
						fmt.Printf("      IPFIX template: %s\n", fs.VersionIPFIXTemplate)
					}
					// Per-collector source-address override (#3745).
					if fs.SourceAddress != "" {
						fmt.Printf("      Source address: %s\n", fs.SourceAddress)
					}
				}
				if fam.SourceAddress != "" {
					fmt.Printf("    Source address: %s\n", fam.SourceAddress)
				}
				if fam.InlineJflow {
					fmt.Printf("    Inline jflow: enabled\n")
				}
				if fam.InlineJflowSourceAddress != "" {
					fmt.Printf("    Inline jflow source: %s\n", fam.InlineJflowSourceAddress)
				}
			}
		}
		hasContent = true
	}

	if fo.DHCPRelay != nil {
		fmt.Println("DHCP relay: (see 'show dhcp-relay' for details)")
		hasContent = true
	}

	if fo.PortMirroring != nil && len(fo.PortMirroring.Instances) > 0 {
		fmt.Println("Port mirroring:")
		for _, name := range sortedInstanceNames(fo.PortMirroring.Instances) {
			inst := fo.PortMirroring.Instances[name]
			fmt.Printf("  Instance: %s\n", name)
			if inst.InputRate > 0 {
				fmt.Printf("    Sampling rate: 1/%d\n", inst.InputRate)
			}
			if len(inst.Input) > 0 {
				fmt.Printf("    Input interfaces:  %s\n", strings.Join(inst.Input, ", "))
			}
			if inst.Output != "" {
				fmt.Printf("    Output interface:  %s\n", inst.Output)
			}
			// #6534: this is the THIRD renderer of a port-mirroring instance
			// and the only one that was still printing a dropped instance as
			// if it were armed. `show forwarding-options port-mirroring`
			// (showPortMirroring) and the gRPC ShowText twin both annotate;
			// this one prints strictly MORE per-instance detail than the gRPC
			// `show forwarding-options`, which only emits a pointer line, so
			// it was the surface most likely to be believed. Same verdict
			// function as the snapshot builder, so the three copies cannot
			// disagree about which instances the dataplane installs.
			if reason := config.PortMirroringInstanceExcludedReason(inst); reason != "" {
				fmt.Printf("    NOT INSTALLED: %s\n", reason)
			}
		}
		hasContent = true
	}

	if !hasContent {
		fmt.Println("No forwarding-options configured")
	}
	return nil
}

// sortedInstanceNames returns a map's keys in a stable order.
//
// #7357: every `show forwarding-options` renderer iterated its instance map
// with a bare `range`, which Go randomises per run. The listings therefore
// changed order between two calls with identical config -- an operator diffing
// captures sees churn that is not there, and any golden or transcript over
// these surfaces is unstable for a reason unrelated to the config.
//
// Generic over the value type because the same defect appeared in BOTH the
// port-mirroring and sampling families, whose instance types differ. The
// issue named only the two port-mirroring renderers and said its census was a
// FLOOR; measuring the tree found six sites across three files.
func sortedInstanceNames[T any](m map[string]T) []string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// printStaticRouteNotInstalled emits the `NOT INSTALLED` line for a static
// route buildRouteSnapshots drops, or nothing when it publishes it.
//
// #7357: a dropped route rendered as configured reads as an installed one —
// the #6534 archetype, and sharpest for `next-table`, whose whole point is a
// forwarding decision. The verdict is config.StaticRouteExclusions, the SAME
// map the builder's predicate produces, so the renderer and the builder cannot
// disagree about which routes are live.
func printStaticRouteNotInstalled(excluded map[*config.StaticRoute]string, sr *config.StaticRoute) {
	if reason := excluded[sr]; reason != "" {
		fmt.Printf("      NOT INSTALLED: %s\n", reason)
	}
}
