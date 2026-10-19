package main

import (
	"fmt"
	"os"
	"slices"
	"strconv"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/nat"
)

func (c *ctl) handleShowNAT(args []string) error {
	if len(args) == 0 {
		printRemoteTreeHelp("show security nat:", "show", "security", "nat")
		return nil
	}
	switch args[0] {
	case "static":
		if len(args) >= 2 && args[1] == "rule" {
			detail := len(args) >= 3 && args[2] == "detail"
			if detail {
				return c.showCommand("show security nat static rule detail")
			}
			return c.showCommand("show security nat static rule")
		}
		return c.showCommand("show security nat static")
	case "nptv6":
		return c.showCommand("show security nat nptv6")
	case "source":
		if len(args) >= 2 && args[1] == "summary" {
			return c.showNATSourceSummary()
		}
		if len(args) >= 2 && args[1] == "pool" {
			// #9065: args[2], the pool name, used to be discarded here.
			poolName := ""
			if len(args) >= 3 {
				poolName = args[2]
			}
			return c.showNATPoolStats(poolName)
		}
		if len(args) >= 3 && args[1] == "persistent-nat-table" && args[2] == "detail" {
			return c.showCommand("show security nat source persistent-nat-table detail")
		}
		if len(args) >= 2 && args[1] == "persistent-nat-table" {
			return c.showCommand("show security nat source persistent-nat-table")
		}
		if len(args) >= 3 && args[1] == "rule" && args[2] == "detail" {
			return c.showCommand("show security nat source rule detail")
		}
		if len(args) >= 2 && args[1] == "rule" {
			return c.showNATRuleStats("")
		}
		if len(args) >= 3 && args[1] == "rule-set" {
			return c.showNATRuleStats(args[2])
		}
		if len(args) >= 2 && args[1] == "rule-set" {
			return c.showNATRuleStats("")
		}
		if len(args) >= 2 && args[1] == "deterministic-nat" {
			return c.showNATDeterministic(args[2:])
		}
		resp, err := c.client.GetNATSource(c.ctx(), &pb.GetNATSourceRequest{})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		for _, r := range resp.Rules {
			fmt.Printf("  %s -> %s: %s", r.FromZone, r.ToZone, r.Type)
			if r.Pool != "" {
				fmt.Printf(" (pool: %s)", r.Pool)
			}
			fmt.Println()
		}
		return nil
	case "destination":
		if len(args) >= 2 && args[1] == "summary" {
			return c.showNATDestinationSummary()
		}
		if len(args) >= 2 && args[1] == "pool" {
			poolName := ""
			if len(args) >= 3 {
				poolName = args[2]
			}
			if len(args) > 3 {
				return fmt.Errorf("usage: show security nat destination pool [<name>]")
			}
			return c.showNATDestinationPool(poolName)
		}
		if len(args) >= 3 && args[1] == "rule" && args[2] == "detail" {
			return c.showCommand("show security nat destination rule detail")
		}
		if len(args) >= 2 && args[1] == "rule" {
			return c.showNATDNATRuleStats("")
		}
		if len(args) >= 3 && args[1] == "rule-set" {
			return c.showNATDNATRuleStats(args[2])
		}
		if len(args) >= 2 && args[1] == "rule-set" {
			return c.showNATDNATRuleStats("")
		}
		resp, err := c.client.GetNATDestination(c.ctx(), &pb.GetNATDestinationRequest{})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		for _, r := range resp.Rules {
			fmt.Printf("  Rule: %s  dst=%s%s", r.Name, r.DstAddr, natDestPortsSuffix(r))
			fmt.Printf(" -> %s", r.TranslateIp)
			if r.TranslatePort > 0 {
				fmt.Printf(":%d", r.TranslatePort)
			}
			fmt.Println()
		}
		return nil
	case "nat64":
		return c.showCommand("show security nat nat64")
	default:
		return fmt.Errorf("unknown show security nat target: %s", args[0])
	}
}

// showNATDeterministic resolves a deterministic source-NAT mapping via the
// GetNATDeterministic RPC (#5794). args are the tokens AFTER
// "deterministic-nat":
//
//	internal-host <ip> [pool <name>]           (forward)
//	nat-ip <ip> nat-port <port> [pool <name>]  (reverse)
func (c *ctl) showNATDeterministic(args []string) error {
	usage := "usage: show security nat source deterministic-nat (internal-host <ip> | nat-ip <ip> nat-port <port>) [pool <name>]"
	if len(args) == 0 {
		return fmt.Errorf("%s", usage)
	}
	req := &pb.GetNATDeterministicRequest{}
	reverse := false
	switch args[0] {
	case "internal-host":
		if len(args) < 2 {
			return fmt.Errorf("%s", usage)
		}
		req.Direction = pb.NATDeterministicDirection_NAT_DETERMINISTIC_DIRECTION_FORWARD
		req.InternalHost = args[1]
		var err error
		req.Pool, err = natPoolArg(args[2:])
		if err != nil {
			return fmt.Errorf("%s", usage)
		}
	case "nat-ip":
		if len(args) < 4 || args[2] != "nat-port" {
			return fmt.Errorf("%s", usage)
		}
		port, err := strconv.Atoi(args[3])
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("nat-port must be 1-65535")
		}
		reverse = true
		req.Direction = pb.NATDeterministicDirection_NAT_DETERMINISTIC_DIRECTION_REVERSE
		req.NatIp = args[1]
		req.NatPort = uint32(port)
		req.Pool, err = natPoolArg(args[4:])
		if err != nil {
			return fmt.Errorf("%s", usage)
		}
	default:
		return fmt.Errorf("unknown deterministic-nat query %q (want internal-host or nat-ip)", args[0])
	}

	resp, err := c.client.GetNATDeterministic(c.ctx(), req)
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	if !resp.Found {
		fmt.Printf("No deterministic mapping (%s): %s\n", resp.ErrorCode, resp.ErrorDetail)
		return nil
	}
	if reverse {
		reverseResultFromPB(resp).Render(os.Stdout)
	} else {
		forwardResultFromPB(resp).Render(os.Stdout)
	}
	return nil
}

// natPoolArg parses the optional trailing `pool <name>` selector.
func natPoolArg(rest []string) (string, error) {
	if len(rest) == 0 {
		return "", nil
	}
	if len(rest) != 2 || rest[0] != "pool" || rest[1] == "" {
		return "", fmt.Errorf("expected optional pool <name>")
	}
	return rest[1], nil
}

func forwardResultFromPB(resp *pb.GetNATDeterministicResponse) *nat.ForwardResult {
	return &nat.ForwardResult{
		Pool:              resp.Pool,
		Mode:              nat.Mode(resp.Mode),
		InternalHost:      resp.InternalHost,
		ExternalIP:        resp.ExternalIp,
		PortLow:           uint16(resp.PortLow),
		PortHigh:          uint16(resp.PortHigh),
		BlockSize:         uint16(resp.BlockSize),
		BlockIndex:        resp.BlockIndex,
		AppliedGeneration: resp.AppliedGeneration,
	}
}

func reverseResultFromPB(resp *pb.GetNATDeterministicResponse) *nat.ReverseResult {
	return &nat.ReverseResult{
		Pool:              resp.Pool,
		Mode:              nat.Mode(resp.Mode),
		ExternalIP:        resp.ExternalIp,
		NATPort:           uint16(resp.NatPort),
		InternalHost:      resp.InternalHost,
		PortLow:           uint16(resp.PortLow),
		PortHigh:          uint16(resp.PortHigh),
		BlockSize:         uint16(resp.BlockSize),
		BlockIndex:        resp.BlockIndex,
		AppliedGeneration: resp.AppliedGeneration,
	}
}

func (c *ctl) showNATSourceSummary() error {
	resp, err := c.client.GetNATPoolStats(c.ctx(), &pb.GetNATPoolStatsRequest{})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	fmt.Printf("Total active translations: %d\n", resp.TotalActiveTranslations)
	fmt.Printf("Total pools: %d\n", len(resp.Pools))
	fmt.Println()
	fmt.Printf("%-20s %-20s %-8s %-8s %-12s %-12s\n",
		"Pool", "Address", "Ports", "Used", "Available", "Utilization")
	for _, p := range resp.Pools {
		ports := "N/A"
		avail := "N/A"
		util := "N/A"
		if !p.IsInterface {
			ports = fmt.Sprintf("%d", p.TotalPorts)
			avail = fmt.Sprintf("%d", p.AvailablePorts)
			util = p.Utilization
		}
		fmt.Printf("%-20s %-20s %-8s %-8d %-12s %-12s\n",
			p.Name, p.Address, ports, p.UsedPorts, avail, util)
	}
	if len(resp.RuleSetSessions) > 0 {
		fmt.Println()
		fmt.Printf("%-30s %-12s\n", "Rule-set (from -> to)", "Sessions")
		for _, rs := range resp.RuleSetSessions {
			fmt.Printf("%-30s %-12d\n",
				fmt.Sprintf("%s -> %s", rs.FromZone, rs.ToZone), rs.Sessions)
		}
	}
	return nil
}

// showNATPoolStats renders `show security nat source pool [<name>]`.
//
// #9065: the pool name was read off args[2] and DISCARDED — the operator asked
// about one pool and was shown every pool, with nothing saying the selector had
// been dropped. Scoped CLIENT-SIDE deliberately: GetNATPoolStatsRequest carries
// no selector (`{}` in xpf.proto), so the daemon does identical work either way
// and only the printing differs. Adding a proto field to narrow it would be a
// wire change for no server-side saving.
//
// An unmatched name FAILS rather than printing nothing: "no such pool" and
// "this pool has no sessions" must not read identically, which is the same
// silence the dropped selector produced.
func (c *ctl) showNATPoolStats(name string) error {
	resp, err := c.client.GetNATPoolStats(c.ctx(), &pb.GetNATPoolStatsRequest{})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	matched := false
	for _, p := range resp.Pools {
		if name != "" && p.Name != name {
			continue
		}
		matched = true
		fmt.Printf("Pool name: %s\n", p.Name)
		fmt.Printf("  Address: %s\n", p.Address)
		if !p.IsInterface {
			fmt.Printf("  Ports allocated: %d\n", p.UsedPorts)
			fmt.Printf("  Ports available: %d\n", p.AvailablePorts)
			fmt.Printf("  Utilization: %s\n", p.Utilization)
		} else {
			fmt.Printf("  Active sessions: %d\n", p.UsedPorts)
		}
		fmt.Println()
	}
	if name != "" && !matched {
		return fmt.Errorf("source NAT pool %q not found", name)
	}
	return nil
}

func (c *ctl) showNATRuleStats(ruleSet string) error {
	resp, err := c.client.GetNATRuleStats(c.ctx(), &pb.GetNATRuleStatsRequest{
		RuleSet: ruleSet,
	})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	if len(resp.Rules) == 0 {
		if ruleSet != "" {
			fmt.Printf("Rule-set %q not found\n", ruleSet)
		} else {
			fmt.Println("No source NAT rules configured")
		}
		return nil
	}

	curRS := ""
	for _, r := range resp.Rules {
		if r.RuleSet != curRS {
			if curRS != "" {
				fmt.Println()
			}
			curRS = r.RuleSet
			fmt.Printf("Rule-set: %s\n", r.RuleSet)
			fmt.Printf("  From zone: %s  To zone: %s\n", r.FromZone, r.ToZone)
		}
		fmt.Printf("  Rule: %s\n", r.RuleName)
		fmt.Printf("    Match: source %s destination %s\n", r.SourceMatch, r.DestinationMatch)
		fmt.Printf("    Action: %s\n", r.Action)
		fmt.Printf("    Translation hits: %d packets  %d bytes\n", r.HitPackets, r.HitBytes)
	}
	fmt.Println()
	return nil
}

func (c *ctl) showNATDestinationSummary() error {
	resp, err := c.client.GetNATDestination(c.ctx(), &pb.GetNATDestinationRequest{})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	if len(resp.Rules) == 0 {
		fmt.Println("No destination NAT pools configured")
		return nil
	}

	type poolInfo struct {
		addr string
		port uint32
	}
	pools := make(map[string]poolInfo)
	for _, r := range resp.Rules {
		name := r.PoolName
		if name == "" {
			name = r.TranslateIp // compatibility with daemons predating #13199
		}
		if name == "" {
			continue // `destination-nat off` rules do not reference pools.
		}
		if _, ok := pools[name]; !ok {
			pools[name] = poolInfo{addr: r.TranslateIp, port: r.TranslatePort}
		}
	}
	if len(pools) == 0 {
		fmt.Println("No destination NAT pools configured")
		return nil
	}

	statsResp, err := c.client.GetNATRuleStats(c.ctx(), &pb.GetNATRuleStatsRequest{
		NatType: "destination",
	})
	if err != nil {
		return fmt.Errorf("get destination NAT rule stats: %w", err)
	}
	poolHits := make(map[string]uint64)
	for _, r := range statsResp.Rules {
		poolHits[r.Action] += r.HitPackets
	}

	fmt.Printf("Total active translations: %d\n", resp.TotalActiveTranslations)
	fmt.Printf("Total pools: %d\n", len(pools))
	fmt.Println()
	fmt.Printf("%-20s %-20s %-8s %-12s\n", "Pool", "Address", "Port", "Hits")
	names := make([]string, 0, len(pools))
	for name := range pools {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		p := pools[name]
		portStr := "-"
		if p.port > 0 {
			portStr = fmt.Sprintf("%d", p.port)
		}
		fmt.Printf("%-20s %-20s %-8s %-12d\n", name, p.addr, portStr, poolHits["pool "+name])
	}
	if len(resp.RuleSetSessions) > 0 {
		fmt.Println()
		fmt.Printf("%-30s %-12s\n", "Rule-set (from -> to)", "Sessions")
		for _, rs := range resp.RuleSetSessions {
			fmt.Printf("%-30s %-12d\n",
				fmt.Sprintf("%s -> %s", rs.FromZone, rs.ToZone), rs.Sessions)
		}
	}
	return nil
}

func (c *ctl) showNATDestinationPool(poolName string) error {
	resp, err := c.client.GetNATDestination(c.ctx(), &pb.GetNATDestinationRequest{})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	poolRules := make(map[string][]*pb.NATDestInfo)
	for _, r := range resp.Rules {
		name := r.PoolName
		if name == "" {
			name = r.TranslateIp // compatibility with daemons predating #13199
		}
		if name == "" {
			continue // `destination-nat off` rules do not reference pools.
		}
		if poolName != "" && poolName != "all" && name != poolName {
			continue
		}
		poolRules[name] = append(poolRules[name], r)
	}
	if len(poolRules) == 0 {
		if poolName != "" && poolName != "all" {
			return fmt.Errorf("destination NAT pool %q not found", poolName)
		}
		fmt.Println("No destination NAT pools configured")
		return nil
	}
	names := make([]string, 0, len(poolRules))
	for name := range poolRules {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		fmt.Printf("Pool name: %s\n", name)
		for _, r := range poolRules[name] {
			fmt.Printf("  Address: %s\n", r.TranslateIp)
			if r.TranslatePort > 0 {
				fmt.Printf("  Port: %d\n", r.TranslatePort)
			}
			fmt.Printf("  Rule: %s (dst %s%s", r.Name, r.DstAddr, natDestPortsSuffix(r))
			fmt.Println(")")
		}
		fmt.Println()
	}
	return nil
}

func (c *ctl) showNATDNATRuleStats(ruleSet string) error {
	resp, err := c.client.GetNATRuleStats(c.ctx(), &pb.GetNATRuleStatsRequest{
		RuleSet: ruleSet,
		NatType: "destination",
	})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	if len(resp.Rules) == 0 {
		if ruleSet != "" {
			fmt.Printf("Rule-set %q not found\n", ruleSet)
		} else {
			fmt.Println("No destination NAT rules configured")
		}
		return nil
	}

	curRS := ""
	for _, r := range resp.Rules {
		if r.RuleSet != curRS {
			if curRS != "" {
				fmt.Println()
			}
			curRS = r.RuleSet
			fmt.Printf("Rule-set: %s\n", r.RuleSet)
			fmt.Printf("  From zone: %s  To zone: %s\n", r.FromZone, r.ToZone)
		}
		fmt.Printf("  Rule: %s\n", r.RuleName)
		fmt.Printf("    Match destination: %s\n", r.DestinationMatch)
		fmt.Printf("    Action: %s\n", r.Action)
		fmt.Printf("    Translation hits: %d packets  %d bytes\n", r.HitPackets, r.HitBytes)
	}
	fmt.Println()
	return nil
}
