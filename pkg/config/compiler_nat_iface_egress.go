package config

import (
	"fmt"
	"sort"
)

// interfaceSNATEgressAddresses derives, from CONFIG alone, the set of addresses
// an interface-mode source-NAT rule can translate onto — the "egress-address
// derivation matrix" of the #6751 plan §5.7.
//
// Interface-mode SNAT rewrites the source to the EGRESS interface's own address.
// Which interfaces those are is decided by the rule-set's to-side scope, and the
// dataplane's `scope_matches` (userspace-dp/src/nat/source.rs) treats an EMPTY
// scope field as a WILDCARD — it only rejects when a non-empty scope disagrees.
// So the candidate set per rule-set is:
//
//	to-interface set          -> that interface's addresses
//	to-routing-instance set   -> that routing instance's interfaces' addresses
//	to-zone set               -> that zone's interfaces' addresses
//	no to-side scope at all   -> EVERY dataplane interface's addresses
//
// The last row is the one that matters and the one the previous Go precedent got
// wrong: `maps_sync.go` collected only non-empty `ToZone` and returned NOTHING
// for an unscoped rule-set. An unscoped interface-mode rule can egress anywhere,
// so returning nothing understates the candidate set precisely where it is
// widest — and an understated set means an overlap goes unreported, which is a
// silent admission of the collision the validator exists to foreclose.
//
// The result maps address -> a human label naming why it is a candidate, so a
// diagnostic can say which rule-set and which interface put it there. Addresses
// are host strings (no prefix length), matching interfaceLocalAddressIndex.
//
// This is CONFIG-time derivation only. Runtime-resolved addresses (DHCP,
// netlink) are deliberately out of scope here — foreclosing those is the
// snapshot-builder half of §5.7 and needs the DRAIN discipline behind it,
// because marking a pool unusable with nothing draining would strand live
// sessions.
func interfaceSNATEgressAddresses(cfg *Config) map[string]string {
	if cfg == nil || len(cfg.Interfaces.Interfaces) == 0 {
		return nil
	}
	zoneByIface := buildZoneInterfaceMapLocal(cfg)
	riByIface := routingInstanceByInterface(cfg)
	out := make(map[string]string)
	record := func(host, label string) {
		if host == "" {
			return
		}
		if _, ok := out[host]; !ok {
			out[host] = label
		}
	}

	// Stable iteration so a diagnostic's attribution does not flip between
	// runs when one address is a candidate under two rule-sets.
	ruleSets := make([]*NATRuleSet, 0, len(cfg.Security.NAT.Source))
	ruleSets = append(ruleSets, cfg.Security.NAT.Source...)
	sort.SliceStable(ruleSets, func(i, j int) bool {
		if ruleSets[i] == nil || ruleSets[j] == nil {
			return ruleSets[i] != nil
		}
		return ruleSets[i].Name < ruleSets[j].Name
	})

	for _, rs := range ruleSets {
		if rs == nil || !ruleSetHasInterfaceModeSNAT(rs) {
			continue
		}
		for _, ifName := range sortedInterfaceNames(cfg) {
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
				logical := fmt.Sprintf("%s.%d", ifName, un)
				if !interfaceInEgressScope(rs, ifName, logical, zoneByIface, riByIface) {
					continue
				}
				for _, a := range unit.Addresses {
					if host, _ := hostLocalAddrFamily(a); host != "" {
						record(host, fmt.Sprintf(
							"interface-mode source-NAT rule-set %q egress %s", rs.Name, logical))
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

// ruleSetHasInterfaceModeSNAT reports whether rs carries at least one live
// interface-mode source-NAT rule. `Then.Off` is a disabled rule and mints no
// translation, so it contributes no egress candidate.
func ruleSetHasInterfaceModeSNAT(rs *NATRuleSet) bool {
	for _, rule := range rs.Rules {
		if rule == nil {
			continue
		}
		if rule.Then.Interface && !rule.Then.Off {
			return true
		}
	}
	return false
}

// interfaceInEgressScope applies the derivation matrix for ONE interface unit
// against ONE rule-set's to-side scope.
//
// It mirrors the dataplane's `scope_matches` AND-of-non-empty-constraints shape:
// each configured to-side scope must agree, and a scope that is not configured
// does not constrain. When NO to-side scope is configured the rule-set is a
// wildcard and every interface is a candidate.
func interfaceInEgressScope(rs *NATRuleSet, ifName, logical string, zoneByIface, riByIface map[string]string) bool {
	if rs.ToInterface != "" && rs.ToInterface != logical && rs.ToInterface != ifName {
		return false
	}
	if rs.ToRoutingInstance != "" {
		// Membership is recorded RI -> interfaces, and an entry may name either
		// the logical unit or the bare physical interface, so try both.
		ri, ok := riByIface[logical]
		if !ok {
			ri, ok = riByIface[ifName]
		}
		if !ok || ri != rs.ToRoutingInstance {
			return false
		}
	}
	if rs.ToZone != "" {
		// zoneByIface keys both `name.unit` and (when a bare interface is
		// zone-listed) the physical `name`; try the unit key first, exactly as
		// interfaceModeSNATExcludedAddresses does.
		zone, ok := zoneByIface[logical]
		if !ok {
			zone, ok = zoneByIface[ifName]
		}
		if !ok || zone != rs.ToZone {
			return false
		}
	}
	return true
}

// sortedInterfaceNames returns the configured interface names in a stable order.
func sortedInterfaceNames(cfg *Config) []string {
	names := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// routingInstanceByInterface indexes routing-instance membership the direction
// the scope check needs it. The config records RI -> interfaces; the derivation
// asks "which RI is this interface in", so invert it once rather than scanning
// every instance per interface.
//
// An interface listed in two instances is a config error the routing validator
// owns; here the FIRST instance in sorted order wins deterministically, so the
// derivation cannot flip between runs while that error stands.
func routingInstanceByInterface(cfg *Config) map[string]string {
	if cfg == nil || len(cfg.RoutingInstances) == 0 {
		return nil
	}
	insts := make([]*RoutingInstanceConfig, 0, len(cfg.RoutingInstances))
	insts = append(insts, cfg.RoutingInstances...)
	sort.SliceStable(insts, func(i, j int) bool {
		if insts[i] == nil || insts[j] == nil {
			return insts[i] != nil
		}
		return insts[i].Name < insts[j].Name
	})
	out := make(map[string]string)
	for _, ri := range insts {
		if ri == nil || ri.Name == "" {
			continue
		}
		for _, ifName := range ri.Interfaces {
			if ifName == "" {
				continue
			}
			// #9821: index the canonical Literal so padded spellings
			// (`p.0.01`) hit the same key the runtime binds (`p.0.1`); bare
			// members keep their spelling (Literal == member when bare).
			key := cfg.SplitInterfaceUnitRef(ifName).Literal
			if _, ok := out[key]; !ok {
				out[key] = ri.Name
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// sortedAddrKeys returns m's keys in a deterministic order so the owner list —
// and therefore every overlap diagnostic's wording and ordering — is stable
// across runs. Go map iteration order is randomised per process, and an
// unstable owner index would make the same config emit the same violation with
// two different attributions on two commits.
func sortedAddrKeys(m map[string]string) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// staticOnInterfaceEgressCollisions reports whole-address, port-preserving
// static-NAT mappings whose external address is ALSO an interface-mode SNAT
// egress address (#6751 §5.7).
//
// This is the arm the pre-#6751 gates left open, and it was open in the worst
// possible way: the #5837 first-packet-inert advisory
// (compiler_validate_warn_nat_iface_addr.go) SUPPRESSES itself when interface
// SNAT owns the address, because interface-mode routing means the translation
// is genuinely not inert. That reasoning is correct for INERTNESS and leaves the
// operator with NO diagnostic for the case that actually matters:
//
//	static    A:5555 -> S:80  translates to  E:5555 -> S:80
//	interface H:5555 -> S:80  translates to  E:5555 -> S:80
//
// One wire identity, two internal hosts, and a reverse index that cannot
// disambiguate — the #6751 misdelivery, reached through the static path. The
// suppression is therefore NARROWED rather than removed: the inert advisory
// stays suppressed (it would be wrong), and this collision finding takes its
// place.
//
// Only WHOLE-ADDRESS mappings qualify. A mapped-port static
// (`MatchDestinationPort` / `MappedPort` set) emits a distinct external port, so
// it does not produce the ambiguous identity; reserving its emitted port is the
// runtime half's job (PR 3b/3c), not a config-time rejection.
func staticOnInterfaceEgressCollisions(cfg *Config) []string {
	if cfg == nil || len(cfg.Security.NAT.Static) == 0 {
		return nil
	}
	egress := interfaceSNATEgressAddresses(cfg)
	if len(egress) == 0 {
		return nil
	}
	ruleSets := append([]*StaticNATRuleSet(nil), cfg.Security.NAT.Static...)
	sort.SliceStable(ruleSets, func(i, j int) bool {
		if ruleSets[i] == nil || ruleSets[j] == nil {
			return ruleSets[i] != nil
		}
		return ruleSets[i].Name < ruleSets[j].Name
	})
	var out []string
	for _, rs := range ruleSets {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil {
				continue
			}
			if rule.Then == "" && rule.ThenPrefixName == "" {
				continue // no translation target
			}
			// Mapped-port statics emit a different external port and are not
			// this ambiguity.
			if rule.MatchDestinationPort != 0 || rule.MappedPort != 0 {
				continue
			}
			host, _ := hostLocalAddrFamily(rule.Match)
			if host == "" {
				continue
			}
			owner, ok := egress[host]
			if !ok {
				continue
			}
			out = append(out, fmt.Sprintf(
				"security nat static rule-set %q rule %q maps whole address %s, which is "+
					"also an interface-mode source-NAT egress address (%s): static NAT "+
					"preserves the source port for a whole-address mapping, and interface-mode "+
					"SNAT translates onto the same address, so both can emit the SAME external "+
					"(address, port) tuple to one remote endpoint. The reverse NAT index keys "+
					"on the translated tuple and cannot tell the two apart, so replies are "+
					"delivered to whichever session the index resolves first — across the "+
					"boundary the firewall exists to keep (#6751). Give the static mapping an "+
					"external address that is not an interface-SNAT egress, or scope the "+
					"interface-mode rule-set away from that interface.",
				rs.Name, rule.Name, host, owner))
		}
	}
	return out
}
