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
// #16558: Junos accepts the bare spelling, so EVERY compile path now
// normalizes it (normalizeBareVRRPVIPs, called unconditionally from
// the tail gates BEFORE the subnet gate) to the enclosing unit prefix
// of the same family, and the Juniper example commits to the same
// VRRPGroup as the CIDR form. A bare VIP with NO same-family enclosing
// prefix is still strict-rejected by validateVRRPVIPPrefixStrict
// below: inventing a host prefix (/32//128) would install a VIP with
// no connected route (the #3013 blackhole). The tolerant path keeps
// the #1960 no-brick host-prefix fallback so an already-persisted
// bare VIP still boots and actuates.
//
// Earlier this gate rejected ANY bare VIP and its comment claimed the
// flat `set` spelling was already normalized by SetPath. It was not:
// SetPath structured the leaf, whose CIDR validator then rejected the
// bare value at SchemaValidate, while the tolerant compile normalized
// the identical text — a strict/tolerant disagreement over the same
// config. The schema validator now accepts bare-or-CIDR
// (ValidateIPv4CIDROrBare / ValidateIPv6CIDROrBare) and this file's
// remaining strict job is the no-enclosing-prefix case only.
//
// validateVRRPVIPPrefixStrict runs on the typed VirtualAddresses, so
// it catches both the packed spelling and any other spelling that
// produced a bare literal. It must run AFTER normalization (the tail
// gates guarantee that order): a bare literal that still reaches it
// on the strict path is one normalization could not place. A bare
// literal is a VALID IP (vrrpVIPHostIP parses it) with no "/" —
// garbage literals stay the #7577 empty gate's concern (they parse
// as neither CIDR nor IP) and are not re-reported here.

// isBareVRRPVIP reports whether vip is a parseable IP literal with no
// prefix — the shape netlink.ParseAddr rejects. CIDRs and unparseable
// tokens return false.
func isBareVRRPVIP(vip string) bool {
	if vip == "" || strings.Contains(vip, "/") {
		return false
	}
	return net.ParseIP(vip) != nil
}

// validateVRRPVIPPrefixStrict hard-rejects, at commit / commit-check, a
// bare virtual-address that normalization could not place: one with no
// same-family enclosing prefix on its unit (#16558). Bare VIPs WITH an
// enclosing prefix never reach here on either path — the tail gates
// normalized them first. Scope: explicit groups only — RETH-derived
// instances take their VIPs from unit Addresses, which are authored
// CIDRs, so there is no bare literal source there (same scope
// reasoning as #7577).
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
					fam := "inet"
					if net.ParseIP(vip).To4() == nil {
						fam = "inet6"
					}
					return fmt.Errorf("interfaces %s unit %d vrrp-group %d virtual-address %s "+
						"has no prefix length and no family %s address with a prefix is "+
						"configured on the unit to enclose it — a bare Junos virtual-address "+
						"gains the enclosing unit prefix at compile, and with none it would "+
						"install without a connected route; write it with its prefix "+
						"(e.g. %s) or configure a family %s address on the unit",
						ifName, un, vg.ID, vip, fam, bareVIPExample(vip, unit), fam)
				}
				if vg.Inet6AdvertiseIntervalMS != 0 &&
					(vg.Inet6AdvertiseIntervalMS < MinInet6AdvertiseIntervalMS || vg.Inet6AdvertiseIntervalMS > MaxInet6AdvertiseIntervalMS) {
					return fmt.Errorf("interfaces %s unit %d vrrp-group %d inet6-advertise-interval %d "+
						"is outside %d..%d milliseconds (Junos range; the VRRPv3 Max Advert Int "+
						"field is 12 bits of centiseconds) — set it in %d..%d or omit it",
						ifName, un, vg.ID, vg.Inet6AdvertiseIntervalMS,
						MinInet6AdvertiseIntervalMS, MaxInet6AdvertiseIntervalMS,
						MinInet6AdvertiseIntervalMS, MaxInet6AdvertiseIntervalMS)
				}
				if vg.VirtualLinkLocalAddress != "" {
					return fmt.Errorf("interfaces %s unit %d vrrp-group %d virtual-link-local-address %s "+
						"is not supported: xpf auto-derives the virtual-router link-local address "+
						"for IPv6 VRRP (RFC 5798 %s) and has no per-group override — remove the "+
						"statement; the derived link-local is advertised as address[0]",
						ifName, un, vg.ID, vg.VirtualLinkLocalAddress, "§6.1")
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
	normalized, _ := normalizeBareVIP(vip, unit, true)
	return normalized
}

// Junos `inet6-advertise-interval` bounds in milliseconds (#16558).
const (
	MinInet6AdvertiseIntervalMS = 100
	MaxInet6AdvertiseIntervalMS = 40000
)

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

// normalizeBareVIP rewrites one bare VIP to CIDR form with the enclosing
// address prefix of the unit. When no same-family enclosing prefix
// exists it returns ok=false UNLESS hostFallback is set (the tolerant
// path), in which case it falls back to the host prefix (/32 or /128)
// so a persisted bare VIP still actuates. Non-bare values are returned
// unchanged with ok=false.
func normalizeBareVIP(vip string, unit *InterfaceUnit, hostFallback bool) (string, bool) {
	if !isBareVRRPVIP(vip) {
		return vip, false
	}
	ip := net.ParseIP(vip)
	ones := enclosingPrefixLen(ip, unit)
	if ones < 0 {
		if !hostFallback {
			return vip, false
		}
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

// normalizeBareVRRPVIPs rewrites every bare VIP in the compiled config
// in place and returns one operator warning per rewritten address. It
// runs on EVERY compile path (#16558, see compiler_tailgates.go): the
// Juniper bare spelling commits to the same VRRPGroup as the CIDR form.
// hostFallback selects the tolerant behaviour for a bare VIP with no
// same-family enclosing prefix (host prefix + warning); on the strict
// path such a VIP is left bare so validateVRRPVIPPrefixStrict rejects
// it by name. Post-normalization duplicates (a bare VIP and its CIDR
// spelling in one group) are deduped with the same helper
// parseVRRPGroups uses.
func normalizeBareVRRPVIPs(cfg *Config, hostFallback bool) []string {
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
					normalized, ok := normalizeBareVIP(vip, unit, hostFallback)
					if !ok {
						continue
					}
					if hostFallback {
						warnings = append(warnings, fmt.Sprintf(
							"interfaces %s unit %d vrrp-group %d virtual-address %s "+
								"has no prefix length (downgraded to warning on tolerant path): "+
								"normalized to %s so the VIP can actuate; write the prefix "+
								"explicitly to silence this",
							ifName, un, vg.ID, vip, normalized))
					}
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
