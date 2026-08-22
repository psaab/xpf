package config

import (
	"fmt"
	"sort"
)

// compiler_validate_warn_nat_iface_addr.go is the Track-1 (#5837) commit-time
// advisory: a destination-NAT or static-NAT rule whose PUBLIC / matched
// destination address (the address the outside world targets) equals a
// configured interface address on this firewall.
//
// Why it matters (the #5837 bypass): on a non-GRE session miss the userspace
// AF_XDP shim (userspace-xdp/src/lib.rs try_xdp_userspace / is_local_destination)
// classifies a packet whose destination is a firewall-local interface address as
// kernel-local and shunts it to the host stack BEFORE consulting destination-NAT
// or static-NAT. `is_local_destination` inspects the INGRESS destination — for a
// DNAT rule that is the `match destination-address` (the public IP the client
// targets), NOT the `then destination-nat pool` address (the internal
// translation TARGET, which the ingress classifier never sees). So a legitimate
// Junos port-forward / static 1:1 mapping that matches the WAN interface's own
// address is INERT on the first packet: the client's SYN is delivered to a local
// service instead of translated + zone-policed. Reply packets and packets on an
// already-established session are unaffected (the translation is applied once a
// session exists); only the FIRST packet of a new flow is misrouted.
//
// Track-1 makes that silent bypass LOUD, and it is the TERMINAL answer, not an
// interim one. The full dataplane fix (a dedicated intent map probed before local
// classification, Option B / Track-2) was tracked as #6051 and is PLAN-KILLED: it
// is a large, verifier-gated, HA-aware project — the shim is a real eBPF program
// under a real verifier, so the 1M-insn cap and the tail-call ban still bind — and
// the converged #5837 research plan left two correctness dimensions unsolved
// (fail-closed on incomplete intent-reconcile state, and HA-failover
// generation-safety of the intent map across a primary swap). The design survives
// on branch research/5837-xdp-dnat-before-local
// (docs/research/5837-xdp-dnat-before-local/plan.md §0b + §1-§13) if a measured
// operator report ever revives it. Until then this commit-time WARNING, naming the
// offending rule and the colliding interface address, IS the mitigation.
//
// Note the interface-mode SNAT fold below (#5837 rev6052): the canonical
// masquerade + WAN-port-forward config is NOT affected by the bypass at all,
// because those addresses live in interface_nat_v4/v6 rather than the kernel-local
// set. The residual this advisory covers is the narrower case of a DNAT /
// static-NAT rule on an interface whose zone is not the to-zone of any
// interface-mode source-NAT rule.
//
// WARN-only on BOTH the strict commit path and the tolerant load / peer-sync
// path (it is emitted from ValidateConfig, which runs on every compile): the
// config is legal Junos and works for reply / established traffic, so it must
// never reject or change forwarding — a hard reject would also brick a boot on a
// previously-committed config (#1960 no-brick doctrine), and the operator may be
// relying on the reply / established-session behaviour the advisory describes.
// This mirrors the sibling direct host-bound advisories in
// compiler_validate_warn_host_inbound.go.
//
// Scope: literal `match destination-address` host / prefix values are checked
// (address-book-NAME-referenced matches are out of scope — resolving them needs
// the address-book fold and the overwhelmingly common #5837 case uses a literal
// address). Both IPv4 and IPv6 are covered (the normalization strips the prefix
// and canonicalizes the host, so `10.0.61.1/32` on the rule matches `10.0.61.1/24`
// on the interface). Configured static interface addresses AND VRRP virtual
// addresses (VIPs — also firewall-local) are enumerated.

// interfaceLocalAddressIndex returns a map from a normalized host IP (the value
// hostLocalAddrFamily produces) to a human label for the interface unit that
// carries it. Both static unit addresses and VRRP virtual addresses (VIPs) are
// included, since both are classified firewall-local by the shim. Iteration is
// fully sorted so the label chosen for an address shared by several units is
// deterministic (first unit in sorted interface+unit order wins).
func interfaceLocalAddressIndex(cfg *Config) map[string]string {
	if cfg == nil || len(cfg.Interfaces.Interfaces) == 0 {
		return nil
	}
	out := make(map[string]string)
	record := func(host, label string) {
		if host == "" {
			return
		}
		if _, ok := out[host]; !ok {
			out[host] = label
		}
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
		for un := range ifc.Units {
			unitNums = append(unitNums, un)
		}
		sort.Ints(unitNums)
		for _, un := range unitNums {
			unit := ifc.Units[un]
			if unit == nil {
				continue
			}
			label := fmt.Sprintf("%s.%d", ifName, un)
			for _, a := range unit.Addresses {
				if host, _ := hostLocalAddrFamily(a); host != "" {
					record(host, label)
				}
			}
			vgKeys := make([]string, 0, len(unit.VRRPGroups))
			for k := range unit.VRRPGroups {
				vgKeys = append(vgKeys, k)
			}
			sort.Strings(vgKeys)
			for _, k := range vgKeys {
				vg := unit.VRRPGroups[k]
				if vg == nil {
					continue
				}
				for _, vip := range vg.VirtualAddresses {
					if host, _ := hostLocalAddrFamily(vip); host != "" {
						record(host, label+" (VRRP VIP)")
					}
				}
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// interfaceModeSNATExcludedAddresses mirrors the userspace-dp dataplane's
// nat_translated_local_exclusions (userspace-dp/src/afxdp/rst.rs:15-40): it
// returns the set of normalized host IPs the dataplane moves OUT of the
// kernel-local set and INTO interface_nat_v4/v6. Those addresses are therefore
// NOT classified kernel-local by is_local_destination (which short-circuits to
// FALSE for a USERSPACE_INTERFACE_NAT member BEFORE the local_v4/v6 check), so a
// DNAT / static-NAT rule matching one of them is NOT inert on the first packet —
// the SYN reaches the helper and inbound DNAT applies (static_nat.rs inbound DNAT
// is not gated on local membership). Warning on such a rule is a false-warn; the
// #5837 rev6052 fold excludes these addresses.
//
// Predicate mirror (rst.rs): collect the to-zone of every source-NAT rule that is
// interface-mode, not `off`, and has a non-empty to-zone
// (rule.interface_mode && !rule.off && !rule.to_zone.is_empty()); then, for every
// interface whose security zone is in that to-zone set, the dataplane excludes
// that interface's picked v4/v6 address (pick_interface_v4/v6). The Go predicate
// mirrors the snapshot mapping exactly: SourceNATRuleSnapshot.InterfaceMode is
// rule.Then.Interface, .Off is rule.Then.Off, and .ToZone is the rule-set ToZone
// (pkg/dataplane/userspace/nat_source.go:185-194).
//
// This mirror uses the SAFE SUPERSET: it excludes EVERY configured address of
// such an interface unit, not just the single pick_interface_v4/v6 result. The
// superset can never false-warn (the whole point of this fold — the canonical
// masquerade + WAN-port-forward config no longer trips the advisory); it can only
// slightly UNDER-warn on a genuinely-inert SECONDARY (non-picked) address of a
// multi-address interface, an accepted trade vs a false-warn on the canonical
// config, and one that also insulates the commit-time check from the kernel /
// config address-ordering divergence a runtime pick_interface would see. VRRP
// VIPs are deliberately NOT excluded: pick_interface_v4/v6 iterates
// iface.addresses (configured unit addresses), never VIPs, so the dataplane keeps
// a VIP kernel-local and a DNAT/static match on a VIP stays genuinely inert (it
// must still warn).
func interfaceModeSNATExcludedAddresses(cfg *Config) map[string]bool {
	if cfg == nil {
		return nil
	}
	// Step 1: the interface-mode SNAT to-zone set (rst.rs predicate).
	toZones := make(map[string]bool)
	for _, rs := range cfg.Security.NAT.Source {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil {
				continue
			}
			if rule.Then.Interface && !rule.Then.Off && rs.ToZone != "" {
				toZones[rs.ToZone] = true
			}
		}
	}
	if len(toZones) == 0 {
		return nil
	}
	// Step 2: every interface unit whose security zone is in that to-zone set;
	// exclude all of its configured addresses (safe superset of the dataplane's
	// pick_interface_v4/v6). zoneByIface keys both `name.unit` and (when a bare
	// interface is zone-listed) the physical `name`, so try the unit key first.
	zoneByIface := buildZoneInterfaceMapLocal(cfg)
	if len(zoneByIface) == 0 {
		return nil
	}
	excluded := make(map[string]bool)
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
		for un := range ifc.Units {
			unitNums = append(unitNums, un)
		}
		sort.Ints(unitNums)
		for _, un := range unitNums {
			unit := ifc.Units[un]
			if unit == nil {
				continue
			}
			unitName := fmt.Sprintf("%s.%d", ifName, un)
			zone := zoneByIface[unitName]
			if zone == "" {
				zone = zoneByIface[ifName]
			}
			if zone == "" || !toZones[zone] {
				continue
			}
			for _, a := range unit.Addresses {
				if host, _ := hostLocalAddrFamily(a); host != "" {
					excluded[host] = true
				}
			}
		}
	}
	if len(excluded) == 0 {
		return nil
	}
	return excluded
}

// validateNATInterfaceAddressCollisionWarnings emits the Track-1 (#5837)
// commit-time advisory for each destination-NAT / static-NAT rule whose public
// (matched / external) destination address equals a configured interface address.
// See the file header for the mechanism. WARN-only, both compile paths.
//
// An address that interface-mode source-NAT routes into interface_nat (the
// dataplane's nat_translated_local_exclusions) is EXCLUDED: it is not
// kernel-local, so a DNAT/static match on it is not inert — warning there is the
// #5837 rev6052 false-warn on the canonical masquerade + WAN-port-forward config.
func validateNATInterfaceAddressCollisionWarnings(cfg *Config) []string {
	if cfg == nil {
		return nil
	}
	ifAddrs := interfaceLocalAddressIndex(cfg)
	if len(ifAddrs) == 0 {
		return nil
	}
	excluded := interfaceModeSNATExcludedAddresses(cfg)
	var warnings []string

	// Destination NAT: the address the outside world targets is the rule's
	// `match destination-address` (NOT the pool / translated-to address). Only a
	// rule that actually translates (has a pool, is not a `destination-nat off`
	// exemption) is inert on the first packet, so gate on that.
	if dst := cfg.Security.NAT.Destination; dst != nil {
		for _, rs := range dst.RuleSets {
			if rs == nil {
				continue
			}
			for _, rule := range rs.Rules {
				if rule == nil {
					continue
				}
				if rule.Then.Off || rule.Then.PoolName == "" {
					continue // no translation → nothing to be inert
				}
				for _, addr := range natMatchValues(rule.Match.DestinationAddresses, rule.Match.DestinationAddress) {
					host, _ := hostLocalAddrFamily(addr)
					if host == "" {
						continue
					}
					if excluded[host] {
						continue // interface-mode SNAT routes this addr into
						// interface_nat (rst.rs) — NOT kernel-local, so the DNAT
						// translation is not inert (#5837 rev6052).
					}
					if iface, ok := ifAddrs[host]; ok {
						warnings = append(warnings, fmt.Sprintf(
							"security nat destination rule-set %q rule %q matches "+
								"destination-address %s, which is a configured interface "+
								"address (%s): the userspace AF_XDP shim classifies the first "+
								"packet to a firewall-local address as kernel-local BEFORE "+
								"consulting destination-NAT, so this translation is INERT on "+
								"the first packet of a new flow (the packet is delivered to the "+
								"host instead of translated + zone-policed). Reply / "+
								"established-session traffic is unaffected. Known first-packet "+
								"interface-address DNAT limitation (#5837); the dataplane fix is "+
								"not planned (#6051). Use a non-interface public address, or "+
								"expect first-packet local delivery.",
							rs.Name, rule.Name, host, iface))
					}
				}
			}
		}
	}

	// Static NAT: the public address is the rule `match destination-address`
	// (StaticNATRule.Match, the external / public IP). Only a rule with a
	// translation target is meaningful.
	for _, rs := range cfg.Security.NAT.Static {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil {
				continue
			}
			if rule.Then == "" && rule.ThenPrefixName == "" {
				continue // no translation target → not a first-packet-inert rule
			}
			host, _ := hostLocalAddrFamily(rule.Match)
			if host == "" {
				continue
			}
			if excluded[host] {
				continue // interface-mode SNAT routes this addr into interface_nat
				// (rst.rs) — NOT kernel-local, so the static translation is not
				// inert (#5837 rev6052).
			}
			if iface, ok := ifAddrs[host]; ok {
				warnings = append(warnings, fmt.Sprintf(
					"security nat static rule-set %q rule %q matches destination-address "+
						"%s, which is a configured interface address (%s): the userspace "+
						"AF_XDP shim classifies the first packet to a firewall-local address "+
						"as kernel-local BEFORE consulting static-NAT, so this 1:1 "+
						"translation is INERT on the first packet of a new flow (the packet "+
						"is delivered to the host instead of translated + zone-policed). "+
						"Reply / established-session traffic is unaffected. Known first-packet "+
						"interface-address static-NAT limitation (#5837); the dataplane fix is "+
						"not planned (#6051). Use a non-interface external address, or expect "+
						"first-packet local delivery.",
					rs.Name, rule.Name, host, iface))
			}
		}
	}

	return warnings
}
