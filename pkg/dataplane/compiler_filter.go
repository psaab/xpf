package dataplane

import (
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// compileFirewallFilters compiles firewall filter config into BPF maps.
// It creates filter_rules, filter_configs, iface_filter_map, and policer_configs entries.
func compileFirewallFilters(dp DataPlane, cfg *config.Config, result *CompileResult) error {
	// Track written keys for populate-before-clear.
	writtenIfaceFilter := make(map[IfaceFilterKey]bool)

	// Build routing instance name -> table ID map (skip forwarding instances)
	riTableIDs := make(map[string]uint32)
	for _, ri := range cfg.RoutingInstances {
		if ri.InstanceType != "forwarding" {
			riTableIDs[ri.Name] = uint32(ri.TableID)
		}
	}

	// Compile policer definitions (sorted for deterministic IDs, 1-based)
	policerIDs := make(map[string]uint32) // policer name -> ID (1-based)
	if len(cfg.Firewall.Policers) > 0 {
		polNames := make([]string, 0, len(cfg.Firewall.Policers))
		for name := range cfg.Firewall.Policers {
			polNames = append(polNames, name)
		}
		sort.Strings(polNames)
		for i, name := range polNames {
			polID := uint32(i + 1) // 1-based (0 = no policer)
			if polID >= MaxPolicers {
				slog.Warn("policer limit reached", "policer", name)
				break
			}
			pol := cfg.Firewall.Policers[name]
			bpfCfg := PolicerConfig{
				RateBytesSec: pol.BandwidthLimit,
				BurstBytes:   pol.BurstSizeLimit,
			}
			if err := dp.SetPolicerConfig(polID, bpfCfg); err != nil {
				return fmt.Errorf("set policer config %s: %w", name, err)
			}
			policerIDs[name] = polID
			slog.Info("compiled policer",
				"name", name, "rate_bps", pol.BandwidthLimit,
				"burst", pol.BurstSizeLimit, "id", polID)
		}
	}

	// Compile three-color policer definitions (continue IDs after single-rate)
	if len(cfg.Firewall.ThreeColorPolicers) > 0 {
		nextPolID := uint32(len(policerIDs) + 1) // continue after single-rate IDs
		tcpNames := make([]string, 0, len(cfg.Firewall.ThreeColorPolicers))
		for name := range cfg.Firewall.ThreeColorPolicers {
			tcpNames = append(tcpNames, name)
		}
		sort.Strings(tcpNames)
		for _, name := range tcpNames {
			polID := nextPolID
			if polID >= MaxPolicers {
				slog.Warn("three-color policer limit reached", "policer", name)
				break
			}
			tcp := cfg.Firewall.ThreeColorPolicers[name]
			bpfCfg := PolicerConfig{
				RateBytesSec: tcp.CIR,
				BurstBytes:   tcp.CBS,
				PeakRate:     tcp.PIR,
				PeakBurst:    tcp.PBS,
			}
			if tcp.TwoRate {
				bpfCfg.ColorMode = PolicerModeTwoRate
			} else {
				bpfCfg.ColorMode = PolicerModeSR3C
			}
			if err := dp.SetPolicerConfig(polID, bpfCfg); err != nil {
				return fmt.Errorf("set three-color policer %s: %w", name, err)
			}
			policerIDs[name] = polID
			slog.Info("compiled three-color policer",
				"name", name, "mode", bpfCfg.ColorMode,
				"cir", tcp.CIR, "cbs", tcp.CBS,
				"pir", tcp.PIR, "pbs", tcp.PBS, "id", polID)
			nextPolID++
		}
	}

	filterID := uint32(0)
	ruleIdx := uint32(0)
	filterIDs := make(map[string]uint32) // "inet:name" or "inet6:name" -> filter_id
	filterSpans := make(map[string]FilterCounterSpan)

	// Compile inet filters (sorted for deterministic IDs)
	inetNames := make([]string, 0, len(cfg.Firewall.FiltersInet))
	for name := range cfg.Firewall.FiltersInet {
		inetNames = append(inetNames, name)
	}
	sort.Strings(inetNames)
	for _, name := range inetNames {
		filter := cfg.Firewall.FiltersInet[name]
		if filterID >= MaxFilterConfigs || ruleIdx >= MaxFilterRules {
			slog.Warn("firewall filter limit reached", "filter", name)
			break
		}
		startIdx := ruleIdx
		var allRules []FilterRule
		for _, term := range filter.Terms {
			rules := expandFilterTerm(term, AFInet, riTableIDs, cfg.PolicyOptions.PrefixLists, policerIDs)
			for _, rule := range rules {
				if ruleIdx >= MaxFilterRules {
					slog.Warn("filter rule limit reached", "filter", name, "term", term.Name)
					break
				}
				if err := dp.SetFilterRule(ruleIdx, rule); err != nil {
					return fmt.Errorf("set filter rule %d: %w", ruleIdx, err)
				}
				allRules = append(allRules, rule)
				ruleIdx++
			}
		}
		numRules := ruleIdx - startIdx
		fcfg := FilterConfig{
			NumRules:  numRules,
			RuleStart: startIdx,
		}
		computeFilterProtoPrefilter(&fcfg, allRules)
		if err := dp.SetFilterConfig(filterID, fcfg); err != nil {
			return fmt.Errorf("set filter config %s: %w", name, err)
		}
		filterKey := "inet:" + name
		filterIDs[filterKey] = filterID
		filterSpans[filterKey] = FilterCounterSpan{
			FilterID:  filterID,
			RuleStart: startIdx,
			RuleCount: numRules,
		}
		slog.Info("compiled firewall filter",
			"name", name, "family", "inet", "terms", len(filter.Terms),
			"rules", numRules, "filter_id", filterID)
		filterID++
	}

	// Compile inet6 filters (sorted for deterministic IDs)
	inet6Names := make([]string, 0, len(cfg.Firewall.FiltersInet6))
	for name := range cfg.Firewall.FiltersInet6 {
		inet6Names = append(inet6Names, name)
	}
	sort.Strings(inet6Names)
	for _, name := range inet6Names {
		filter := cfg.Firewall.FiltersInet6[name]
		if filterID >= MaxFilterConfigs || ruleIdx >= MaxFilterRules {
			slog.Warn("firewall filter limit reached", "filter", name)
			break
		}
		startIdx := ruleIdx
		var allRules []FilterRule
		for _, term := range filter.Terms {
			rules := expandFilterTerm(term, AFInet6, riTableIDs, cfg.PolicyOptions.PrefixLists, policerIDs)
			for _, rule := range rules {
				if ruleIdx >= MaxFilterRules {
					slog.Warn("filter rule limit reached", "filter", name, "term", term.Name)
					break
				}
				if err := dp.SetFilterRule(ruleIdx, rule); err != nil {
					return fmt.Errorf("set filter rule %d: %w", ruleIdx, err)
				}
				allRules = append(allRules, rule)
				ruleIdx++
			}
		}
		numRules := ruleIdx - startIdx
		fcfg := FilterConfig{
			NumRules:  numRules,
			RuleStart: startIdx,
		}
		computeFilterProtoPrefilter(&fcfg, allRules)
		if err := dp.SetFilterConfig(filterID, fcfg); err != nil {
			return fmt.Errorf("set filter config %s: %w", name, err)
		}
		filterKey := "inet6:" + name
		filterIDs[filterKey] = filterID
		filterSpans[filterKey] = FilterCounterSpan{
			FilterID:  filterID,
			RuleStart: startIdx,
			RuleCount: numRules,
		}
		slog.Info("compiled firewall filter",
			"name", name, "family", "inet6", "terms", len(filter.Terms),
			"rules", numRules, "filter_id", filterID)
		filterID++
	}

	// Map interfaces to their assigned filters
	for _, ifCfg := range cfg.Interfaces.Interfaces {
		for _, unit := range ifCfg.Units {
			if unit.FilterInputV4 == "" && unit.FilterInputV6 == "" &&
				unit.FilterOutputV4 == "" && unit.FilterOutputV6 == "" {
				continue
			}

			physName := config.LinuxIfName(cfg.ResolveReth(ifCfg.Name))
			vlanID := uint16(unit.VlanID)

			// Resolve ifindex (cached to avoid redundant syscalls)
			iface, err := result.cachedInterfaceByName(physName)
			if err != nil {
				slog.Warn("interface not found for filter assignment",
					"interface", physName, "err", err)
				continue
			}

			ifindex := uint32(iface.Index)
			// If VLAN sub-interface, use the sub-interface ifindex
			if vlanID > 0 {
				subName := fmt.Sprintf("%s.%d", physName, vlanID)
				subIface, err := result.cachedInterfaceByName(subName)
				if err != nil {
					slog.Warn("VLAN sub-interface not found for filter",
						"name", subName, "err", err)
					continue
				}
				ifindex = uint32(subIface.Index)
				// Physical ifindex is used in iface_filter_key since
				// xdp_main uses ctx->ingress_ifindex (parent phys NIC)
				ifindex = uint32(iface.Index)
			}

			if unit.FilterInputV4 != "" {
				fid, ok := filterIDs["inet:"+unit.FilterInputV4]
				if !ok {
					slog.Warn("filter not found for interface",
						"filter", unit.FilterInputV4, "interface", physName)
				} else {
					key := IfaceFilterKey{
						Ifindex: ifindex,
						VlanID:  vlanID,
						Family:  AFInet,
					}
					if err := dp.SetIfaceFilter(key, fid); err != nil {
						return fmt.Errorf("set iface filter %s inet: %w", physName, err)
					}
					writtenIfaceFilter[key] = true
					slog.Info("assigned filter to interface",
						"interface", physName, "vlan", vlanID,
						"family", "inet", "filter", unit.FilterInputV4)
				}
			}

			if unit.FilterInputV6 != "" {
				fid, ok := filterIDs["inet6:"+unit.FilterInputV6]
				if !ok {
					slog.Warn("filter not found for interface",
						"filter", unit.FilterInputV6, "interface", physName)
				} else {
					key := IfaceFilterKey{
						Ifindex: ifindex,
						VlanID:  vlanID,
						Family:  AFInet6,
					}
					if err := dp.SetIfaceFilter(key, fid); err != nil {
						return fmt.Errorf("set iface filter %s inet6: %w", physName, err)
					}
					writtenIfaceFilter[key] = true
					slog.Info("assigned filter to interface",
						"interface", physName, "vlan", vlanID,
						"family", "inet6", "filter", unit.FilterInputV6)
				}
			}

			// Output filters use direction=1 and the egress ifindex.
			// For VLAN sub-interfaces, TC egress sees skb->ifindex as
			// the sub-interface, so use its ifindex (not parent).
			egressIfindex := ifindex
			if vlanID > 0 {
				subName := fmt.Sprintf("%s.%d", physName, vlanID)
				if subIface, err := result.cachedInterfaceByName(subName); err == nil {
					egressIfindex = uint32(subIface.Index)
				}
			}

			if unit.FilterOutputV4 != "" {
				fid, ok := filterIDs["inet:"+unit.FilterOutputV4]
				if !ok {
					slog.Warn("output filter not found for interface",
						"filter", unit.FilterOutputV4, "interface", physName)
				} else {
					key := IfaceFilterKey{
						Ifindex:   egressIfindex,
						VlanID:    0, // TC egress doesn't track VLAN separately
						Family:    AFInet,
						Direction: 1,
					}
					if err := dp.SetIfaceFilter(key, fid); err != nil {
						return fmt.Errorf("set output filter %s inet: %w", physName, err)
					}
					writtenIfaceFilter[key] = true
					slog.Info("assigned output filter to interface",
						"interface", physName, "vlan", vlanID,
						"family", "inet", "filter", unit.FilterOutputV4)
				}
			}

			if unit.FilterOutputV6 != "" {
				fid, ok := filterIDs["inet6:"+unit.FilterOutputV6]
				if !ok {
					slog.Warn("output filter not found for interface",
						"filter", unit.FilterOutputV6, "interface", physName)
				} else {
					key := IfaceFilterKey{
						Ifindex:   egressIfindex,
						VlanID:    0,
						Family:    AFInet6,
						Direction: 1,
					}
					if err := dp.SetIfaceFilter(key, fid); err != nil {
						return fmt.Errorf("set output filter %s inet6: %w", physName, err)
					}
					writtenIfaceFilter[key] = true
					slog.Info("assigned output filter to interface",
						"interface", physName, "vlan", vlanID,
						"family", "inet6", "filter", unit.FilterOutputV6)
				}
			}
		}
	}

	// Delete stale filter entries and zero unused filter config/rule slots.
	dp.DeleteStaleIfaceFilter(writtenIfaceFilter)
	dp.ZeroStaleFilterConfigs(filterID)

	result.FilterIDs = filterIDs
	result.FilterSpans = filterSpans

	// Resolve lo0 filter IDs for host-bound traffic filtering
	if cfg.System.Lo0FilterInputV4 != "" {
		if fid, ok := filterIDs["inet:"+cfg.System.Lo0FilterInputV4]; ok {
			result.Lo0FilterV4 = fid
			slog.Info("lo0 inet filter assigned", "filter", cfg.System.Lo0FilterInputV4, "id", fid)
		} else {
			slog.Warn("lo0 inet filter not found", "filter", cfg.System.Lo0FilterInputV4)
		}
	}
	if cfg.System.Lo0FilterInputV6 != "" {
		if fid, ok := filterIDs["inet6:"+cfg.System.Lo0FilterInputV6]; ok {
			result.Lo0FilterV6 = fid
			slog.Info("lo0 inet6 filter assigned", "filter", cfg.System.Lo0FilterInputV6, "id", fid)
		} else {
			slog.Warn("lo0 inet6 filter not found", "filter", cfg.System.Lo0FilterInputV6)
		}
	}

	return nil
}

// expandFilterTerm expands a single filter term into one or more BPF filter rules.
// Terms with multiple source/destination addresses generate the cross product of rules.
func expandFilterTerm(term *config.FirewallFilterTerm, family uint8, riTableIDs map[string]uint32, prefixLists map[string]*config.PrefixList, policerIDs map[string]uint32) []FilterRule {
	// Base rule with common fields
	base := FilterRule{
		Family:      family,
		DSCPRewrite: 0xFF, // no DSCP rewrite by default
	}

	// Set log flag
	if term.Log {
		base.LogFlag = 1
	}

	// Set action
	if term.RoutingInstance != "" {
		base.Action = FilterActionRoute
		if tableID, ok := riTableIDs[term.RoutingInstance]; ok {
			base.RoutingTable = tableID
		} else {
			slog.Warn("routing-instance not found for filter term",
				"term", term.Name, "instance", term.RoutingInstance)
			base.Action = FilterActionAccept
		}
	} else {
		switch term.Action {
		case "discard":
			base.Action = FilterActionDiscard
		case "reject":
			base.Action = FilterActionReject
		default:
			base.Action = FilterActionAccept
		}
	}

	// DSCP match
	if term.DSCP != "" {
		base.MatchFlags |= FilterMatchDSCP
		if val, ok := DSCPValues[strings.ToLower(term.DSCP)]; ok {
			base.DSCP = val
		} else if v, err := strconv.Atoi(term.DSCP); err == nil {
			base.DSCP = uint8(v)
		}
	}

	// DSCP rewrite action (then dscp <value>)
	if term.DSCPRewrite != "" {
		if val, ok := DSCPValues[strings.ToLower(term.DSCPRewrite)]; ok {
			base.DSCPRewrite = val
		} else if v, err := strconv.Atoi(term.DSCPRewrite); err == nil {
			base.DSCPRewrite = uint8(v)
		}
	}

	// Forwarding-class + loss-priority → DSCP rewrite.
	// Only applies if no explicit dscp rewrite was set.
	if term.ForwardingClass != "" && base.DSCPRewrite == 0xFF {
		if val, ok := forwardingClassToDSCP(term.ForwardingClass, term.LossPriority); ok {
			base.DSCPRewrite = val
		}
	}

	// Policer reference
	if term.Policer != "" {
		if polID, ok := policerIDs[term.Policer]; ok {
			base.PolicerID = uint8(polID)
		} else {
			slog.Warn("policer not found for filter term",
				"term", term.Name, "policer", term.Policer)
		}
	}

	// Protocol match
	if term.Protocol != "" {
		base.MatchFlags |= FilterMatchProtocol
		switch strings.ToLower(term.Protocol) {
		case "tcp":
			base.Protocol = 6
		case "udp":
			base.Protocol = 17
		case "icmp":
			base.Protocol = 1
		case "icmpv6":
			base.Protocol = 58
		default:
			if v, err := strconv.Atoi(term.Protocol); err == nil {
				base.Protocol = uint8(v)
			}
		}
	}

	// ICMP type/code
	if term.ICMPType >= 0 {
		base.MatchFlags |= FilterMatchICMPType
		base.ICMPType = uint8(term.ICMPType)
	}
	if term.ICMPCode >= 0 {
		base.MatchFlags |= FilterMatchICMPCode
		base.ICMPCode = uint8(term.ICMPCode)
	}

	// TCP flags match
	if len(term.TCPFlags) > 0 {
		base.MatchFlags |= FilterMatchTCPFlags
		for _, flag := range term.TCPFlags {
			switch strings.ToLower(flag) {
			case "syn":
				base.TCPFlags |= 0x02
			case "ack":
				base.TCPFlags |= 0x10
			case "fin":
				base.TCPFlags |= 0x01
			case "rst":
				base.TCPFlags |= 0x04
			case "psh":
				base.TCPFlags |= 0x08
			case "urg":
				base.TCPFlags |= 0x20
			}
		}
	}

	// Fragment match
	if term.IsFragment {
		base.MatchFlags |= FilterMatchFragment
		base.IsFragment = 1
	}

	// Flexible match
	if term.FlexMatch != nil {
		base.MatchFlags |= FilterMatchFlex
		base.FlexOffset = term.FlexMatch.ByteOffset
		base.FlexLength = term.FlexMatch.BitLength / 8
		if base.FlexLength == 0 {
			base.FlexLength = 4 // default 32-bit
		}
		base.FlexValue = term.FlexMatch.Value & term.FlexMatch.Mask
		base.FlexMask = term.FlexMatch.Mask
	}

	// Expand prefix list references into address lists.
	// Each address tracks whether it came from an "except" prefix-list reference.
	type filterAddr struct {
		cidr   string
		negate bool
	}
	var srcAddrs []filterAddr
	for _, a := range term.SourceAddresses {
		srcAddrs = append(srcAddrs, filterAddr{cidr: a})
	}
	for _, ref := range term.SourcePrefixLists {
		if pl, ok := prefixLists[ref.Name]; ok {
			for _, p := range pl.Prefixes {
				srcAddrs = append(srcAddrs, filterAddr{cidr: p, negate: ref.Except})
			}
		} else {
			slog.Warn("prefix-list not found", "name", ref.Name, "term", term.Name)
		}
	}
	var dstAddrs []filterAddr
	for _, a := range term.DestAddresses {
		dstAddrs = append(dstAddrs, filterAddr{cidr: a})
	}
	for _, ref := range term.DestPrefixLists {
		if pl, ok := prefixLists[ref.Name]; ok {
			for _, p := range pl.Prefixes {
				dstAddrs = append(dstAddrs, filterAddr{cidr: p, negate: ref.Except})
			}
		} else {
			slog.Warn("prefix-list not found", "name", ref.Name, "term", term.Name)
		}
	}
	if len(srcAddrs) == 0 {
		srcAddrs = []filterAddr{{}} // "any"
	}
	if len(dstAddrs) == 0 {
		dstAddrs = []filterAddr{{}} // "any"
	}

	// Port lists: expand multiple ports into separate rules
	dstPorts := term.DestinationPorts
	if len(dstPorts) == 0 {
		dstPorts = []string{""} // "any"
	}
	srcPorts := term.SourcePorts
	if len(srcPorts) == 0 {
		srcPorts = []string{""} // "any"
	}

	var rules []FilterRule
	for _, src := range srcAddrs {
		for _, dst := range dstAddrs {
			for _, dp := range dstPorts {
				for _, sp := range srcPorts {
					rule := base
					if src.cidr != "" {
						rule.MatchFlags |= FilterMatchSrcAddr
						if src.negate {
							rule.MatchFlags |= FilterMatchSrcNegate
						}
						setFilterAddr(&rule.SrcAddr, &rule.SrcMask, src.cidr, family)
					}
					if dst.cidr != "" {
						rule.MatchFlags |= FilterMatchDstAddr
						if dst.negate {
							rule.MatchFlags |= FilterMatchDstNegate
						}
						setFilterAddr(&rule.DstAddr, &rule.DstMask, dst.cidr, family)
					}
					if dp != "" {
						rule.MatchFlags |= FilterMatchDstPort
						lo, hi := resolvePortRange(dp)
						rule.DstPort = htons(lo)
						if hi > lo {
							rule.DstPortHi = htons(hi)
						}
					}
					if sp != "" {
						rule.MatchFlags |= FilterMatchSrcPort
						lo, hi := resolvePortRange(sp)
						rule.SrcPort = htons(lo)
						if hi > lo {
							rule.SrcPortHi = htons(hi)
						}
					}
					rules = append(rules, rule)
				}
			}
		}
	}

	return rules
}

// setFilterAddr parses a CIDR string and populates addr/mask byte arrays.
func setFilterAddr(addr, mask *[16]byte, cidr string, family uint8) {
	// Strip "except" suffix if present (defensive — negate is tracked via MatchFlags)
	cidr = strings.TrimSuffix(cidr, " except")
	cidr = strings.TrimSuffix(cidr, ";")

	// If no prefix length, assume /32 (v4) or /128 (v6)
	if !strings.Contains(cidr, "/") {
		if family == AFInet {
			cidr += "/32"
		} else {
			cidr += "/128"
		}
	}

	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		slog.Warn("invalid CIDR in filter term", "cidr", cidr, "err", err)
		return
	}

	if family == AFInet {
		ip4 := ip.To4()
		if ip4 == nil {
			return
		}
		copy(addr[:4], ip4)
		copy(mask[:4], ipNet.Mask)
	} else {
		ip16 := ip.To16()
		if ip16 == nil {
			return
		}
		copy(addr[:], ip16)
		copy(mask[:], ipNet.Mask)
	}
}

// resolvePortName maps well-known port names to numbers.
// resolvePortRange parses a port specification that may be a name, number,
// or range ("1000-2000"). Returns low and high port numbers. If not a range,
// hi equals lo.
// computeFilterProtoPrefilter populates the protocol pre-filter fields on a
// FilterConfig. If ALL rules specify FILTER_MATCH_PROTOCOL, the BPF code can
// skip the entire evaluation loop when the packet's protocol doesn't match
// any of the (up to 4) distinct protocol values.
func computeFilterProtoPrefilter(fcfg *FilterConfig, rules []FilterRule) {
	if len(rules) == 0 {
		return
	}
	allHave := true
	protos := make(map[uint8]bool)
	for _, r := range rules {
		if r.MatchFlags&FilterMatchProtocol == 0 {
			allHave = false
			break
		}
		protos[r.Protocol] = true
	}
	if !allHave || len(protos) == 0 || len(protos) > 4 {
		return
	}
	fcfg.AllHaveProto = 1
	i := 0
	for p := range protos {
		fcfg.ProtoList[i] = p
		i++
	}
	fcfg.ProtoCount = uint8(len(protos))
}

func resolvePortRange(s string) (lo, hi uint16) {
	if idx := strings.IndexByte(s, '-'); idx > 0 && idx < len(s)-1 {
		lo = resolvePortName(s[:idx])
		hi = resolvePortName(s[idx+1:])
		return lo, hi
	}
	p := resolvePortName(s)
	return p, p
}

// forwardingClassToDSCP maps a Junos forwarding-class + loss-priority to a DSCP value.
// Forwarding classes: best-effort, expedited-forwarding, assured-forwarding, network-control.
// Loss priority selects the AF drop precedence (low=AFx1, medium-low=AFx2, medium-high/high=AFx3).
func forwardingClassToDSCP(fc, lp string) (uint8, bool) {
	fc = strings.ToLower(fc)
	lp = strings.ToLower(lp)
	switch fc {
	case "best-effort":
		return 0, true // CS0/BE
	case "expedited-forwarding":
		return 46, true // EF
	case "network-control":
		return 48, true // CS6
	case "assured-forwarding":
		// AF class 1 with drop precedence from loss-priority
		switch lp {
		case "high", "medium-high":
			return 14, true // AF13
		case "medium-low":
			return 12, true // AF12
		default:
			return 10, true // AF11
		}
	default:
		// Try as DSCP name directly
		if val, ok := DSCPValues[fc]; ok {
			return val, true
		}
		return 0, false
	}
}

func resolvePortName(name string) uint16 {
	switch strings.ToLower(name) {
	case "ssh":
		return 22
	case "http":
		return 80
	case "https":
		return 443
	case "dns", "domain":
		return 53
	case "ftp":
		return 21
	case "ftp-data":
		return 20
	case "smtp":
		return 25
	case "snmp":
		return 161
	case "snmptrap":
		return 162
	case "bgp":
		return 179
	case "ntp":
		return 123
	case "telnet":
		return 23
	case "pop3":
		return 110
	case "imap":
		return 143
	case "ldap":
		return 389
	case "syslog":
		return 514
	case "radacct":
		return 1813
	case "radius":
		return 1812
	case "ike":
		return 500
	default:
		if v, err := strconv.ParseUint(name, 10, 16); err == nil {
			return uint16(v)
		}
		return 0
	}
}
