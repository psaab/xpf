package config

import (
	"fmt"
	"sort"
)

// validateMemberFBFKernelBandStrict refuses firewall-filter `then routing-instance`
// (FBF) terms attached as interface-unit INPUT filters on a routing-instance
// MEMBER interface (#11321).
//
// A non-forwarding routing-instance member is enslaved to its Linux VRF device
// (daemon_apply_interfaces.go skips only instance-type forwarding). Ingress on
// such a member is therefore resolved by the kernel's l3mdev rule at pref 1000
// (VRF-table lookup) and, on a miss, stopped by the VRF miss terminator at pref
// 2000 (`l3mdev unreachable`, vrf_miss_terminator_9819.go). Both precede the PBR
// band at 29000-29999 (pbrRulePriority) structurally, so a kernel FBF `ip rule`
// scoped to that member (BuildPBRRules, #5117 iif scoping) is never consulted
// on the kernel slow path — while the userspace helper honours the same term
// (ingress_route_table_override returns RouteOverride::Table with explicit-PBR
// precedence; see tests_ri_native_10312.rs CONTROL). That is a plane divergence
// with no faithful kernel-band realization.
//
// This gate is strict at commit / commit-check to prevent a newly-authored
// divergent configuration. Tolerant load / peer-sync preserves #1960 boot
// safety by warning and removing the member FBF override from the compiled
// filter; when the FBF action was the term's only terminal action, accept is
// retained so the matching packet still terminates in its native VRF.
// Diagnostics name the family, filter, term, attachment unit, and owning
// member instance.
//
// Scope notes:
//   - Only non-forwarding, non-reserved instances bind a VRF: forwarding has no
//     VRF device (daemon skips VRF creation/binding) so its members still reach
//     the PBR band; reserved names (mgmt) are quarantined, never bound (#9622).
//   - Only INPUT attachments are FBF (output-attached routing-instance is
//     rejected by validateFilterRoutingInstanceDirectionStrict, #3432).
//   - lo0 attachments are skipped: BuildPBRRules already drops loopback FBF as
//     degraded (#9810 LEAD-O4) and the lo0 mirror warning already covers the
//     route-selection gap there (#3724 M04).
func validateMemberFBFKernelBandStrict(cfg *Config) error {
	warnings := memberFBFKernelBandWarnings11321(cfg)
	if len(warnings) == 0 {
		return nil
	}
	return fmt.Errorf("%s", warnings[0])
}

// memberFBFKernelBandWarnings11321 reports each FBF term attached on a
// non-forwarding RI member unit. RoutingInstanceMemberDeviceKeys is the shared
// resolver used by VRF binding and dataplane membership, including bare-member
// fan-out and logical/Linux aliases.
func memberFBFKernelBandWarnings11321(cfg *Config) []string {
	return memberFBFKernelBandDiagnostics11321(cfg, false)
}

// suppressMemberFBFKernelBand11321 removes the unreachable FBF override from
// each affected compiled filter term and returns the corresponding diagnostics.
// Clearing only RoutingInstance leaves the authored match and any explicit
// terminal action intact. A routing-instance action by itself is terminal in
// the helper, so preserve that disposition as accept when there is no authored
// action or explicit next-term.
func suppressMemberFBFKernelBand11321(cfg *Config) []string {
	return memberFBFKernelBandDiagnostics11321(cfg, true)
}

func memberFBFKernelBandDiagnostics11321(cfg *Config, suppress bool) []string {
	if cfg == nil {
		return nil
	}
	// Logical interface unit and kernel-device identity -> owning VRF-bound
	// instance. Carry both views: the filter binding is logical, while the
	// routing manager binds the resolved Linux device.
	memberUnitToRI := make(map[string]string)
	memberDeviceToRI := make(map[string]string)
	tunnelNames := cfg.TunnelNameMap()
	for _, ri := range cfg.RoutingInstances {
		if ri == nil || ri.Name == "" {
			continue
		}
		if IsReservedRoutingInstanceName(ri.Name) {
			continue
		}
		if ri.InstanceType == "forwarding" {
			continue
		}
		for _, member := range RoutingInstanceMemberDeviceKeysForInstance(cfg, tunnelNames, ri) {
			if member.InterfaceKey != "" {
				if _, exists := memberUnitToRI[member.InterfaceKey]; !exists {
					memberUnitToRI[member.InterfaceKey] = ri.Name
				}
			}
			if member.LinuxName != "" {
				if _, exists := memberDeviceToRI[member.LinuxName]; !exists {
					memberDeviceToRI[member.LinuxName] = ri.Name
				}
			}
		}
	}
	if len(memberUnitToRI) == 0 && len(memberDeviceToRI) == 0 {
		return nil
	}
	var warnings []string
	var cloneSequence int
	suppressedCloneNames := make(map[string]string)
	// Deterministic order: interfaces sorted, units numeric, terms in config
	// order (same discipline as the other firewall warn gates).
	ifNames := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		ifNames = append(ifNames, name)
	}
	sort.Strings(ifNames)
	for _, ifName := range ifNames {
		ifc := cfg.Interfaces.Interfaces[ifName]
		if ifc == nil {
			continue
		}
		if ifName == "lo0" {
			continue
		}
		unitNums := make([]int, 0, len(ifc.Units))
		for n := range ifc.Units {
			unitNums = append(unitNums, n)
		}
		sort.Ints(unitNums)
		for _, n := range unitNums {
			unit := ifc.Units[n]
			if unit == nil {
				continue
			}
			unitRef := fmt.Sprintf("%s.%d", ifName, n)
			memberRef := cfg.SplitInterfaceUnitRef(unitRef).Literal
			ownerRI, isMember := memberUnitToRI[memberRef]
			if !isMember {
				ownerRI, isMember = memberDeviceToRI[cfg.resolveKernelIfNameWith(unitRef, tunnelNames)]
			}
			if !isMember {
				continue
			}
			hooks := []struct {
				family string
				filter string
			}{
				{"inet", unit.FilterInputV4},
				{"inet6", unit.FilterInputV6},
			}
			for _, h := range hooks {
				if h.filter == "" {
					continue
				}
				var filter *FirewallFilter
				if h.family == "inet" {
					filter = cfg.Firewall.FiltersInet[h.filter]
				} else {
					filter = cfg.Firewall.FiltersInet6[h.filter]
				}
				if filter == nil {
					continue
				}
				var suppressedTerms []string
				for _, term := range filter.Terms {
					if term == nil || term.RoutingInstance == "" {
						continue
					}
					target := term.RoutingInstance
					warnings = append(warnings, fmt.Sprintf(
						"firewall family %s filter %q term %q `then routing-instance %s` "+
							"is attached as input on routing-instance member interface %q "+
							"(member of %q): the kernel l3mdev rule (pref 1000) and VRF miss "+
							"terminator (pref 2000) precede the PBR band (%d-%d), so the "+
							"kernel slow path uses the native table while the userspace "+
							"dataplane would steer to the FBF target (#11321)",
						h.family, h.filter, term.Name, target, unitRef, ownerRI,
						PBRRulePriorityBase, PBRRulePriorityBase+PBRRuleWindow-1))
					if suppress {
						suppressedTerms = append(suppressedTerms, term.Name)
					}
				}
				if len(suppressedTerms) != 0 {
					cloneKey := h.family + ":" + h.filter
					cloneName := suppressedCloneNames[cloneKey]
					if cloneName == "" {
						cloneSequence++
						cloneName = fmt.Sprintf("__xpf_11589_suppressed_%d", cloneSequence)
						var filters map[string]*FirewallFilter
						if h.family == "inet" {
							filters = cfg.Firewall.FiltersInet
						} else {
							filters = cfg.Firewall.FiltersInet6
						}
						for filters[cloneName] != nil {
							cloneSequence++
							cloneName = fmt.Sprintf("__xpf_11589_suppressed_%d", cloneSequence)
						}
						clone := cloneFilterForMemberFBFSuppression11321(filter, h.filter, cloneName, suppressedTerms)
						filters[cloneName] = clone
						suppressedCloneNames[cloneKey] = cloneName
					}
					if h.family == "inet" {
						unit.FilterInputV4 = cloneName
					} else {
						unit.FilterInputV6 = cloneName
					}
				}
			}
		}
	}
	return warnings
}
func cloneFilterForMemberFBFSuppression11321(
	filter *FirewallFilter,
	sourceName, cloneName string,
	suppressedTerms []string,
) *FirewallFilter {
	clone := *filter
	clone.Name = cloneName
	clone.memberFBFSource11321 = sourceName
	clone.memberFBFTerms11321 = append([]string(nil), suppressedTerms...)
	clone.Terms = make([]*FirewallFilterTerm, len(filter.Terms))
	for i, term := range filter.Terms {
		if term == nil {
			continue
		}
		termClone := *term
		if termClone.RoutingInstance != "" {
			termClone.RoutingInstance = ""
			if termClone.Action == "" && !termClone.NextTerm {
				termClone.Action = "accept"
			}
		}
		clone.Terms[i] = &termClone
	}
	return &clone
}

// SuppressedMemberFBF11321 reports the authored filter and terms whose
// routing-instance action was removed from a lenient per-attachment clone.
// A non-empty source identifies an internal #11321 clone.
func (f *FirewallFilter) SuppressedMemberFBF11321() (source string, terms []string) {
	if f == nil {
		return "", nil
	}
	return f.memberFBFSource11321, f.memberFBFTerms11321
}
