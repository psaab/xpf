package routing

import (
	"fmt"
	"net"
	"sort"

	"github.com/psaab/xpf/pkg/config"
	"golang.org/x/sys/unix"
)

// PolicyRulePriorityCount is the number of desired xpf policy rules at one
// family-specific priority. The daemon compares this inventory with RuleList
// to detect a flushed policy band without claiming ownership of foreign rules.
type PolicyRulePriorityCount struct {
	Family   int
	Priority int
	Count    int
}

type policyRulePriorityKey struct {
	family   int
	priority int
}

type ribGroupLeakCandidate struct {
	instance *config.RoutingInstanceConfig
	family   int
	prefix   *net.IPNet
}

// DesiredPolicyRulePriorityCounts derives the rule bands written by the
// routing-policy managers. It shares their admission, ordering, and rule
// builders so the retry detector does not maintain a second configuration
// interpretation. A returned rule is counted as desired even if a prior
// netlink add failed; retry debt and this readback probe both repair that case.
func DesiredPolicyRulePriorityCounts(cfg *config.Config) []PolicyRulePriorityCount {
	if cfg == nil {
		return nil
	}
	counts := make(map[policyRulePriorityKey]int)
	add := func(family, priority, count int) {
		if count > 0 {
			counts[policyRulePriorityKey{family: family, priority: priority}] += count
		}
	}

	// Match daemon.applyPolicyRoutingRules' combined default-instance static
	// route input and its IPv4-first admission order.
	allRoutes := make([]*config.StaticRoute, 0,
		len(cfg.RoutingOptions.StaticRoutes)+len(cfg.RoutingOptions.Inet6StaticRoutes))
	allRoutes = append(allRoutes, cfg.RoutingOptions.StaticRoutes...)
	allRoutes = append(allRoutes, cfg.RoutingOptions.Inet6StaticRoutes...)
	if len(allRoutes) > 0 {
		ingressIfaces := DefaultInstanceIngressIfaces(cfg)
		if len(ingressIfaces) != 0 {
			tableIDs := make(map[string]int)
			definedInstances := make(map[string]struct{}, len(cfg.RoutingInstances))
			for _, inst := range cfg.RoutingInstances {
				if inst == nil {
					continue
				}
				tableIDs[inst.Name] = inst.TableID
				definedInstances[inst.Name] = struct{}{}
			}
			orderedRoutes := nextTableFamilyOrdered(allRoutes)
			admitted := nextTableAdmittedRoutes(orderedRoutes, tableIDs, len(ingressIfaces))
			for _, route := range admitted {
				_, dst, err := net.ParseCIDR(route.Destination)
				if err != nil || dst == nil {
					continue
				}
				prefixLength, addressBits := dst.Mask.Size()
				family := unix.AF_INET
				if dst.IP.To4() == nil {
					family = unix.AF_INET6
				}
				add(family, config.RouteLeakNextTableLookupPriority(prefixLength, addressBits), len(ingressIfaces))
				add(family, config.RouteLeakNextTableShadowPriority(prefixLength, addressBits), len(ingressIfaces))
			}
			for _, rule := range nextTableMainCarveoutRules(orderedRoutes, admitted, definedInstances, ingressIfaces) {
				add(rule.Family, rule.Priority, 1)
			}
		}
	}

	// Rib-group forward leaks and peer returns use the same admission helper
	// as Apply. The inventory assumes admitted forward rules install, which is
	// the desired state against which the live kernel table is compared.
	if len(cfg.RoutingOptions.RibGroups) > 0 && len(cfg.RoutingInstances) > 0 {
		tableIDs := make(map[string]int)
		for _, inst := range cfg.RoutingInstances {
			if inst != nil {
				tableIDs[inst.Name] = inst.TableID
			}
		}
		connectedPrefixes := config.RibGroupConnectedPrefixes(cfg)
		candidates, _ := ribGroupLeakCandidates(
			cfg.RoutingOptions.RibGroups, cfg.RoutingInstances, connectedPrefixes, tableIDs, false)
		byInstance := make(map[*config.RoutingInstanceConfig][]ribGroupLeakCandidate)
		for _, candidate := range candidates {
			prefixLength, addressBits := candidate.prefix.Mask.Size()
			add(candidate.family, config.RouteLeakRulePriority(prefixLength, addressBits, config.RouteLeakRibGroup), 1)
			byInstance[candidate.instance] = append(byInstance[candidate.instance], candidate)
		}
		for _, inst := range cfg.RoutingInstances {
			if !ribGroupReturnAllowed(inst) || len(byInstance[inst]) == 0 {
				continue
			}
			installed := map[int][]*net.IPNet{}
			for _, candidate := range byInstance[inst] {
				installed[candidate.family] = append(installed[candidate.family], candidate.prefix)
			}
			peerPrefixes, _ := ribGroupPeerReturnPrefixes(
				inst, cfg.RoutingInstances, cfg.RoutingOptions.RibGroups,
				tableIDs, connectedPrefixes, installed, false)
			seen := make(map[struct {
				family int
				prefix string
				table  int
			}]struct{})
			for family, peers := range peerPrefixes {
				for _, peer := range peers {
					if peer.prefix == nil || peer.tableID <= 0 {
						continue
					}
					key := struct {
						family int
						prefix string
						table  int
					}{family, peer.prefix.String(), peer.tableID}
					if _, duplicate := seen[key]; duplicate {
						continue
					}
					seen[key] = struct{}{}
					add(family, ribGroupReturnRulePriorityFor(peer.prefix), 2)
				}
			}
		}
	}

	// PBR consumes one combined IPv4-then-IPv6 builder slice. Keep its global
	// index when assigning the lookup/shadow slots, as ApplyPBRRules does.
	pbrRules, _ := BuildPBRRules(cfg)
	priority := config.PBRRulePriorityBase
	for _, rule := range pbrRules {
		if priority+1 >= config.PBRRulePriorityBase+config.PBRRuleWindow {
			break
		}
		if rule.IifName == "" {
			continue
		}
		if rule.Src != "" {
			if _, _, err := net.ParseCIDR(rule.Src); err != nil {
				continue
			}
		}
		if rule.Dst != "" {
			if _, _, err := net.ParseCIDR(rule.Dst); err != nil {
				continue
			}
		}
		add(rule.Family, priority, 1)
		add(rule.Family, priority+1, 1)
		priority += 2
	}

	out := make([]PolicyRulePriorityCount, 0, len(counts))
	for key, count := range counts {
		out = append(out, PolicyRulePriorityCount{Family: key.family, Priority: key.priority, Count: count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Family != out[j].Family {
			return out[i].Family < out[j].Family
		}
		return out[i].Priority < out[j].Priority
	})
	return out
}

// ribGroupLeakCandidates mirrors Apply's family selection, shared-table
// deduplication, prefix validation, and per-family admission cap. warnUnknown
// is false for periodic inventories to avoid repeating commit-time warnings.
func ribGroupLeakCandidates(
	ribGroups map[string]*config.RibGroup,
	instances []*config.RoutingInstanceConfig,
	connectedPrefixes map[string][]string,
	tableIDs map[string]int,
	warnUnknown bool,
) ([]ribGroupLeakCandidate, []error) {
	leakedTables := make(map[int]bool)
	admitted := map[int]int{unix.AF_INET: 0, unix.AF_INET6: 0}
	capped := make(map[int]bool)
	var candidates []ribGroupLeakCandidate
	var errs []error
	for _, inst := range instances {
		if inst == nil {
			continue
		}
		leakV4 := ribGroupLeaksIntoMainWithWarnings(
			inst.InterfaceRoutesRibGroup, ribGroups, tableIDs, inst.Name, unix.AF_INET, warnUnknown)
		leakV6 := ribGroupLeaksIntoMainWithWarnings(
			inst.InterfaceRoutesRibGroupV6, ribGroups, tableIDs, inst.Name, unix.AF_INET6, warnUnknown)
		if !leakV4 && !leakV6 {
			continue
		}
		if leakedTables[inst.TableID] {
			continue
		}
		leakedTables[inst.TableID] = true

		v4, v6 := splitConnectedPrefixesByFamily(connectedPrefixes[inst.Name])
		families := []struct {
			family   int
			prefixes []string
			enabled  bool
		}{
			{family: unix.AF_INET, prefixes: v4, enabled: leakV4},
			{family: unix.AF_INET6, prefixes: v6, enabled: leakV6},
		}
		for _, family := range families {
			if !family.enabled {
				continue
			}
			for _, raw := range family.prefixes {
				if capped[family.family] {
					continue
				}
				if admitted[family.family] >= maxRibGroupLeakRules {
					familyStr := "inet"
					if family.family == unix.AF_INET6 {
						familyStr = "inet6"
					}
					errs = append(errs, fmt.Errorf(
						"rib-group leak rule limit (%d) reached for family %s; connected prefixes beyond "+
							"the limit are not leaked — reduce the number of interface-routes "+
							"rib-group prefixes", maxRibGroupLeakRules, familyStr))
					capped[family.family] = true
					continue
				}
				_, prefix, err := net.ParseCIDR(raw)
				if err != nil || prefix == nil {
					errs = append(errs, fmt.Errorf(
						"rib-group leak: parse connected prefix %q instance %s: %w", raw, inst.Name, err))
					continue
				}
				admitted[family.family]++
				candidates = append(candidates, ribGroupLeakCandidate{
					instance: inst, family: family.family, prefix: prefix,
				})
			}
		}
	}
	return candidates, errs
}
