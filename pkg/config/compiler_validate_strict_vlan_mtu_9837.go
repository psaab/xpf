package config

import (
	"fmt"
	"sort"
	"strconv"
)

// validateVlanUnitMTUStrict hard-rejects a tagged unit whose family MTU is
// above the EFFECTIVE parent MTU when both are set (#9837).
//
// The two values land on different netdevs: the effective parent MTU is what
// planPhysDesired writes on the parent link (the interface-level `mtu`, or an
// untagged sibling unit's override — see below; since #9761 a parent whose
// zone references are all tagged still gets the interface-level value), while
// the compiled unit MTU (compiler_interfaces.go) is written to the VLAN
// sub-interface (applyVLANSubInterfaceMTU9757). Linux refuses a VLAN child
// MTU above its parent's (vlan_dev_change_mtu), so before this gate the
// commit was clean, every apply logged `failed to set VLAN sub-interface
// MTU`, and the child kept its old MTU: the committed config was never
// realised, and only the journal said so.
//
// The predicate keys on unit.VlanID > 0 — exactly what mapZoneInterface
// branches on (compiler_iface.go resolveInterfaceRef reads unit.VlanID before
// the per-unit-tunnel arm, so a tunnel unit carrying a vlan-id takes the VLAN
// child path too) — rather than the `vlan-tagging` flag, which the dataplane
// never consults. Two cases need no check and are unchanged:
//   - an untagged unit's MTU replaces the parent's, so it cannot exceed it;
//   - a tagged unit on an interface with no interface-level `mtu` AND no
//     referenced sibling override is limited by the parent's RUNNING MTU,
//     which the commit cannot see — that case stays a runtime warning. A
//     referenced sibling override pins the parent to a commit-visible value,
//     so that sub-case IS checked.

// The effective parent preserves the planner's own precedence
// (compiler_iface_desired.go: the unit-level MTU overrides the interface
// level, lowest unit number wins between units, and a tagged unit contributes
// only the interface-level value): the lowest-numbered REFERENCED untagged
// non-tunnel sibling with an MTU wins, else the interface-level `mtu`. Only a
// referenced sibling counts, because planPhysDesired iterates security-zone
// references — an unzoned sibling never reaches the parent plan. A per-unit
// tunnel sibling is excluded: it resolves to its own tunnel device, not this
// parent. Without this, ifc 1400 + untagged unit0 1500 + tagged unit50 1500 —
// runtime-fine, since the parent runs 1500 — would newly refuse against 1400.
// The tagged side stays shape-based (no zone requirement), matching the
// issue's mandate; the sibling side is runtime-based, matching the kernel.

// The compiled unit MTU is the MIN of its family MTUs, independent of authored
// order. The gate judges that same compiled value the dataplane writes, so a
// mixed-family unit now has one order-independent commit verdict as well as
// one runtime target.
//
// Strict on the commit / commit-check path; downgraded to a cfg.Warnings
// entry on the tolerant load / peer-sync path (flag lenientVlanUnitMTU) so an
// already-persisted or peer-synced config still boots (#1960 no-brick; the
// runtime warning already covers the leniently-loaded case). Interfaces and
// units are visited in sorted order so commit-check surfaces a STABLE
// first-error message.
func validateVlanUnitMTUStrict(cfg *Config) error {
	if cfg == nil || cfg.Interfaces.Interfaces == nil {
		return nil
	}
	referenced := vlanUnitMTUReferencedUnits9837(cfg)
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
		// Ascending scan: the first match is the lowest-numbered, which is
		// what the planner selects between competing unit MTUs. This runs
		// BEFORE the unknown-parent skip: with no interface-level `mtu`, a
		// referenced sibling still pins the parent to a commit-visible value.
		parentMTU, parentUnit := ifc.MTU, -1
		for _, un := range unitNums {
			sib := ifc.Units[un]
			if sib == nil || sib.VlanID > 0 || sib.Tunnel != nil || sib.MTU <= 0 {
				continue
			}
			if !referenced[ifName][un] {
				continue
			}
			parentMTU, parentUnit = sib.MTU, un
			break
		}
		if parentMTU <= 0 {
			// No interface-level `mtu` and no referenced sibling override:
			// the parent runs whatever it runs, which the commit cannot see.
			continue
		}
		for _, un := range unitNums {
			unit := ifc.Units[un]
			if unit == nil || unit.VlanID <= 0 || unit.MTU <= parentMTU {
				continue
			}
			if parentUnit < 0 {
				return fmt.Errorf("interfaces %s unit %d: family mtu %d exceeds "+
					"interface mtu %d — Linux refuses a VLAN child MTU above its "+
					"parent's, so the committed MTU would never be realised; lower "+
					"the unit's family mtu or raise the interface mtu (#9837)",
					ifName, un, unit.MTU, ifc.MTU)
			}
			ifaceNote := fmt.Sprintf("interface mtu %d", ifc.MTU)
			if ifc.MTU <= 0 {
				ifaceNote = "no interface mtu"
			}
			return fmt.Errorf("interfaces %s unit %d: family mtu %d exceeds "+
				"effective parent mtu %d (from untagged unit %d; %s) — "+
				"Linux refuses a VLAN child MTU above its parent's, so the committed "+
				"MTU would never be realised; lower the unit's family mtu or raise "+
				"unit %d's mtu (#9837)",
				ifName, un, unit.MTU, parentMTU, parentUnit, ifaceNote, parentUnit)
		}
	}
	return nil
}

// vlanUnitMTUReferencedUnits9837 collects, per interface, the unit numbers
// named by security-zone references — the same reference set planPhysDesired
// iterates, parsed the same way resolveInterfaceRef parses (#9821 D13: the
// declared-aware split, so a dotted unit ref resolves against its declared
// stanza instead of an undeclared first segment). ALL zones count: the
// planner does not skip mgmt/control. A unit the zones never name
// contributes nothing to the parent plan, so it must not raise this gate's
// effective parent.
func vlanUnitMTUReferencedUnits9837(cfg *Config) map[string]map[int]bool {
	out := map[string]map[int]bool{}
	for _, zone := range cfg.Security.Zones {
		if zone == nil {
			continue
		}
		for _, ref := range zone.Interfaces {
			s := cfg.SplitInterfaceUnitRef(ref)
			// Mirror resolveInterfaceRef EXACTLY (it assigns, then ignores
			// the error): a bare ref names unit 0; a syntactically-invalid
			// suffix yields Atoi's 0; but a RANGE-OVERFLOWED suffix yields
			// the saturated value, which the planner looks up (and misses)
			// — it never falls back to unit 0. Zeroing here would credit
			// an unreferenced unit-0 override the planner never selects.
			// Strict #5933 rejects garbage first, so the malformed arms run
			// only on the tolerant path — but the claim is all-shape
			// agreement with the runtime, so match it bit-for-bit.
			n := 0
			if s.HasUnit {
				var atoiErr error
				n, atoiErr = strconv.Atoi(s.UnitTok)
				if atoiErr != nil {
					// Checked, deliberately uncorrected: #6940 forbids a
					// discarded Atoi error in the compiler, and no
					// correction is owed — the comment above explains why
					// Atoi's return (0 on syntax errors, saturated on
					// range errors) is kept verbatim in both modes.
				}
			}
			if out[s.Base] == nil {
				out[s.Base] = map[int]bool{}
			}
			out[s.Base][n] = true
		}
	}
	return out
}
