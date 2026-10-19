package config

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

// #15050: a VRRP virtual-address without a /prefix must not reach the
// runtime. pkg/vrrp passes the compiled string verbatim to
// netlink.ParseAddr (pkg/vrrp/instance_vip.go addVIPsListLocked), and
// ParseAddr REQUIRES a prefix — a bare Junos-style literal ("10.0.1.100")
// is recorded as a failed VIP, vipActuationResult.ok() is false, and
// becomeMaster (#5082 fail-closed) rolls back to BACKUP and re-arms on
// every promotion. The VRRP-protected gateway therefore has no owner on
// every node carrying the config.
//
// The structured spellings ARE gated: vrrpGroupSchemaNode's
// virtual-address leaf carries ValidateIPv4CIDR / ValidateIPv6CIDR. The
// PACKED hierarchical one-liner `vrrp-group 1 virtual-address 10.0.1.100;`
// packs the value onto the instance node's Keys, which the schema walker
// consumes as an unvalidated identity token (walkInstanceChildren) — the
// same bypass #5184 (priority) and #8483 (timers) closed one leaf over.
// It is reachable through hierarchical `load` / day-0 / config-sync, not
// through `set` (SetPath normalizes packed tokens into schema-structured
// children).
//
// validateVRRPVIPPrefixStrict is the compiled-*Config gate beside the
// #8483 timers gate. It runs on the typed VirtualAddresses, so it catches
// both the packed spelling and any other spelling that produced a bare
// literal. A bare literal is a VALID IP (vrrpVIPHostIP parses it) with no
// "/" — garbage literals stay the #7577 empty gate's concern (they parse
// as neither CIDR nor IP) and are not re-reported here.
//
// On the tolerant load / peer-sync paths the call site downgrades this
// to a warning AND normalizes (normalizeBareVRRPVIPs in the tail gates,
// opts.lenientVRRPVIPPrefix) so an already-persisted or peer-synced
// config an older binary accepted still boots AND actuates (#1960
// no-brick): the bare VIP gains the enclosing address prefix of its
// unit, or a host prefix (/32, /128) when no enclosing prefix of the
// matching family exists. Without the normalization the tolerant path
// would boot a group that reverts every promotion forever — the exact
// defect, merely warned about.

// isBareVRRPVIP reports whether vip is a parseable IP literal with no
// prefix — the shape netlink.ParseAddr rejects. CIDRs and unparseable
// tokens return false.
func isBareVRRPVIP(vip string) bool {
	if vip == "" || strings.Contains(vip, "/") {
		return false
	}
	return net.ParseIP(vip) != nil
}

// validateVRRPVIPPrefixStrict hard-rejects, at commit / commit-check, an
// explicit `vrrp-group` carrying a prefix-less virtual-address (#15050).
// Scope: explicit groups only — RETH-derived instances take their VIPs
// from unit Addresses, which are authored CIDRs, so there is no bare
// literal source there (same scope reasoning as #7577).
func validateVRRPVIPPrefixStrict(cfg *Config) error {
	if cfg == nil || cfg.Interfaces.Interfaces == nil {
		return nil
	}
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
		unitNums := make([]int, 0, len(ifc.Units))
		for n := range ifc.Units {
			unitNums = append(unitNums, n)
		}
		sort.Ints(unitNums)
		for _, un := range unitNums {
			unit := ifc.Units[un]
			if unit == nil || len(unit.VRRPGroups) == 0 {
				continue
			}
			gkeys := make([]string, 0, len(unit.VRRPGroups))
			for k := range unit.VRRPGroups {
				gkeys = append(gkeys, k)
			}
			sort.Strings(gkeys)
			for _, gk := range gkeys {
				vg := unit.VRRPGroups[gk]
				if vg == nil {
					continue
				}
				for _, vip := range vg.VirtualAddresses {
					if !isBareVRRPVIP(vip) {
						continue
					}
					return fmt.Errorf("interfaces %s unit %d vrrp-group %d virtual-address %s "+
						"has no prefix length — pkg/vrrp installs VIPs with netlink.ParseAddr, "+
						"which requires a prefix, so this address would fail to actuate and "+
						"every promotion would roll back to BACKUP with no owner for the "+
						"gateway — write it with its prefix (e.g. %s)",
						ifName, un, vg.ID, vip, bareVIPExample(vip, unit))
				}
			}
		}
	}
	return nil
}

// bareVIPExample renders the corrected spelling for the strict error:
// the bare VIP with the enclosing prefix when one is known, else a host
// prefix. Display only — the strict path does not mutate the config.
func bareVIPExample(vip string, unit *InterfaceUnit) string {
	normalized, _ := normalizeBareVIP(vip, unit)
	return normalized
}

// enclosingPrefixLen returns the prefix length of the first unit address
// of the VIP's family whose subnet contains the VIP, or of the first
// same-family address when none contains it, or -1 when the unit has no
// parseable same-family address.
func enclosingPrefixLen(ip net.IP, unit *InterfaceUnit) int {
	if unit == nil {
		return -1
	}
	wantV4 := ip.To4() != nil
	first := -1
	for _, a := range unit.Addresses {
		_, ipnet, err := net.ParseCIDR(a)
		if err != nil || ipnet == nil {
			continue
		}
		if (ipnet.IP.To4() != nil) != wantV4 {
			continue
		}
		ones, _ := ipnet.Mask.Size()
		if first < 0 {
			first = ones
		}
		if ipnet.Contains(ip) {
			return ones
		}
	}
	return first
}

// normalizeBareVIP rewrites one bare VIP to CIDR form: the enclosing
// address prefix of the unit when available, else the host prefix
// (/32 or /128). The second return reports whether a change was made.
// Non-bare values are returned unchanged.
func normalizeBareVIP(vip string, unit *InterfaceUnit) (string, bool) {
	if !isBareVRRPVIP(vip) {
		return vip, false
	}
	ip := net.ParseIP(vip)
	ones := enclosingPrefixLen(ip, unit)
	if ones < 0 {
		if ip.To4() != nil {
			ones = 32
		} else {
			ones = 128
		}
	}
	// Canonicalize through net.IP.String so the normalized form matches
	// what the advert / netlink paths parse (IPv4-mapped forms collapse).
	return ip.String() + "/" + strconv.Itoa(ones), true
}

// normalizeBareVRRPVIPs rewrites every bare VIP in the compiled config in
// place and returns one operator warning per rewritten address. It runs
// only on the tolerant path (see the call site in compiler_tailgates.go):
// the strict path rejects instead of silently rewriting an operator's
// commit. After this pass the strict gate passes, so the tolerant config
// actuates instead of reverting every promotion. Post-normalization
// duplicates (a bare VIP and its CIDR spelling in one group) are deduped
// with the same helper parseVRRPGroups uses.
func normalizeBareVRRPVIPs(cfg *Config) []string {
	if cfg == nil || cfg.Interfaces.Interfaces == nil {
		return nil
	}
	var warnings []string
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
		unitNums := make([]int, 0, len(ifc.Units))
		for n := range ifc.Units {
			unitNums = append(unitNums, n)
		}
		sort.Ints(unitNums)
		for _, un := range unitNums {
			unit := ifc.Units[un]
			if unit == nil || len(unit.VRRPGroups) == 0 {
				continue
			}
			gkeys := make([]string, 0, len(unit.VRRPGroups))
			for k := range unit.VRRPGroups {
				gkeys = append(gkeys, k)
			}
			sort.Strings(gkeys)
			for _, gk := range gkeys {
				vg := unit.VRRPGroups[gk]
				if vg == nil {
					continue
				}
				changed := false
				for i, vip := range vg.VirtualAddresses {
					normalized, ok := normalizeBareVIP(vip, unit)
					if !ok {
						continue
					}
					warnings = append(warnings, fmt.Sprintf(
						"interfaces %s unit %d vrrp-group %d virtual-address %s "+
							"has no prefix length (downgraded to warning on tolerant path): "+
							"normalized to %s so the VIP can actuate; write the prefix "+
							"explicitly to silence this",
						ifName, un, vg.ID, vip, normalized))
					vg.VirtualAddresses[i] = normalized
					changed = true
				}
				if changed {
					vg.VirtualAddresses = dedupeVRRPVIPs(vg.VirtualAddresses)
				}
			}
		}
	}
	return warnings
}
