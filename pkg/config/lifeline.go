package config

import (
	"strconv"
	"strings"
)

// lifeline.go is the SSOT for host-inbound LIFELINE interface matching (#3682).
// Before #3682 the matcher lived privately in pkg/dataplane/userspace/zones.go
// and drove the host-inbound deny-scoping decision, but no operator-visible zone
// view could re-derive it, so a zone-assigned lifeline interface silently
// dropped out of the host-inbound default-deny with nothing to render the
// exemption. Hoisting the matcher here lets the shared host-inbound presenter
// (host_inbound_view.go) surface the exemption on every text zone view while the
// dataplane path keeps using the identical logic (userspace/zones.go now
// delegates here) — one source of truth for both enforcement and display.

// LifelineBaseName strips the final unit suffix and surrounding whitespace from
// a logical interface name, preserving dotted interface names ("hb.1.0" ->
// "hb.1", "fxp0.0" -> "fxp0"). Returns "" for an empty name.
func LifelineBaseName(name string) string {
	base := strings.TrimSpace(name)
	if i := strings.LastIndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}
	return base
}

// HostInboundLifelineSet resolves the explicitly configured management /
// cluster-control interface names that must NEVER be subjected to a
// host-inbound deny:
//
//   - fxp0 (out-of-band management) is always a lifeline.
//   - Chassis-cluster control and fabric interfaces are included only when
//     configured, including operator-renamed links. Fabric-options
//     member-interfaces also explicitly identify a cluster fabric interface.
//
// Bare interface names such as em0/fab0 are not proof of a management or
// cluster role and are not implicit lifelines (#11068). A standalone config
// therefore contributes only fxp0.
func HostInboundLifelineSet(cfg *Config) map[string]bool {
	set := map[string]bool{"fxp0": true, "fxp0.0": true}
	if cfg == nil {
		return set
	}
	// #14348: positive lifeline designations and negative transit
	// exclusions are tracked separately, so a negative marker (a
	// declared transit VLAN unit, a non-zero-unit parent demotion) can
	// never overwrite an explicit positive lifeline role, no matter
	// which role or interface is walked first. set is the merged view:
	// a key is false only when it is excluded and not designated.
	pos := map[string]bool{"fxp0": true, "fxp0.0": true}
	neg := map[string]bool{}
	markPositive := func(key string) {
		pos[key] = true
		set[key] = true
	}
	markNegative := func(key string) {
		neg[key] = true
		if !pos[key] {
			set[key] = false
		}
	}
	// unit0SharesParent reports whether unit 0 of iface shares the bare
	// parent kernel netdev: true when unit 0 is undeclared or untagged.
	// A VLAN-tagged unit 0 has its own netdev (#14192), so the bare
	// parent and its tagged unit 0 must never alias each other (#14348).
	unit0SharesParent := func(iface *InterfaceConfig) bool {
		if iface == nil {
			return true
		}
		u, declared := iface.Units[0]
		return !declared || u == nil || u.VlanID == 0
	}
	// Retain every declared interface identity (false for ordinary links).
	// The matcher uses key presence to prefer a declared dotted base over
	// interpreting that same spelling as a unit on the shorter parent.
	for name, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		name = strings.TrimSpace(name)
		if _, known := set[name]; !known {
			markNegative(name)
		}
		// #14192: register every DECLARED unit as ordinary too. A bare
		// control/fabric lifeline base (e.g. control-interface ge-0/0/0)
		// must not cover a declared transit VLAN unit (ge-0/0/0.100) that
		// has its own kernel netdev. Without these keys the matcher's
		// numeric-suffix fallback returned the parent's true. Unit 0 is
		// registered false here and re-marked true below only when it is
		// itself the designated lifeline.
		for unit := range ifc.Units {
			key := name + "." + strconv.Itoa(unit)
			if _, known := set[key]; !known {
				markNegative(key)
			}
		}
		// #14192: a role name spelled with a unit (control-interface hb.1,
		// fabric-interface ge-0/0/0.100) declares that UNIT as the lifeline,
		// not a new interface. Its declared key must read true. #14302:
		// when that same DOTTED spelling is a DECLARED interface (hb.1
		// declared with units hb.1.<unit>), it is an interface identity,
		// not a unit of a shorter parent (hb is undeclared or a sibling),
		// so its declared units are units OF the lifeline and must not
		// stay registered false. A BARE designated name (ge-0/0/0) is the
		// #14192 case instead: only its unit 0 shares its netdev, so its
		// other declared units stay false below.
		if cfg.Chassis.Cluster != nil {
			cc := cfg.Chassis.Cluster
			for _, role := range []string{cc.ControlInterface, cc.FabricInterface, cc.Fabric1Interface} {
				if role = strings.TrimSpace(role); role == name {
					markPositive(name)
					if strings.Contains(name, ".") {
						for unit := range ifc.Units {
							markPositive(name + "." + strconv.Itoa(unit))
						}
					}
				}
			}
		}
	}
	if cfg.Chassis.Cluster != nil {
		cc := cfg.Chassis.Cluster
		// #14302: dotted role spellings that are themselves DECLARED
		// interfaces (control-interface hb.1 with hb.1 declared) name an
		// interface, not a unit of a shorter parent; their declared units
		// are units OF the lifeline. Compute that set before the walks
		// below so markBaseLifeline does not re-demote them.
		dottedLifelineBases := map[string]bool{}
		for _, role := range []string{cc.ControlInterface, cc.FabricInterface, cc.Fabric1Interface} {
			role = strings.TrimSpace(role)
			if role == "" || !strings.Contains(role, ".") {
				continue
			}
			if ifc, declared := cfg.Interfaces.Interfaces[role]; declared && ifc != nil {
				dottedLifelineBases[role] = true
			}
		}
		// markBaseLifeline exempts base and classifies its declared
		// units. A VLAN-tagged unit never inherits through this walk: it
		// is demoted to ordinary UNLESS it was explicitly designated
		// (markNegative never overrides a positive). Only an untagged
		// (or undeclared) unit 0 shares the parent netdev, so only then
		// does unit 0 follow the parent; a tagged unit 0 leaves the
		// parent ordinary unless another role designated it (#14348).
		// markBaseLifelineCore classifies base and its declared units
		// WITHOUT touching base.0: a VLAN-tagged unit is demoted (never
		// overriding a positive), an untagged unit 0 is promoted, other
		// untagged units are demoted, and a declared dotted lifeline
		// owns every declared unit (#14302).
		markBaseLifelineCore := func(base string) {
			if iface := cfg.Interfaces.Interfaces[base]; iface != nil {
				for unit, u := range iface.Units {
					if dottedLifelineBases[base] {
						markPositive(base + "." + strconv.Itoa(unit))
						continue
					}
					if u != nil && u.VlanID != 0 {
						markNegative(base + "." + strconv.Itoa(unit))
					} else if unit == 0 {
						markPositive(base + "." + strconv.Itoa(unit))
					} else {
						markNegative(base + "." + strconv.Itoa(unit))
					}
				}
			}
		}
		// markBaseLifeline: the base itself is a lifeline (explicit
		// fabric member, or a unit-0 role whose untagged unit 0 shares
		// the parent netdev). A declared unit 0 that is VLAN-tagged
		// does NOT demote an explicitly designated base (#14348 bare
		// role): its tagged unit stays demoted unless designated.
		markBaseLifeline := func(base string) {
			markPositive(base)
			markBaseLifelineCore(base)
		}
		// markUnit0Parent classifies the parent of a ".0" role/member:
		// the parent is promoted only when unit 0 shares its netdev
		// (undeclared or untagged); a tagged unit 0 leaves the parent
		// ordinary unless another role designated it, while the
		// designated tagged unit itself stays positive.
		markUnit0Parent := func(base string) {
			if unit0SharesParent(cfg.Interfaces.Interfaces[base]) {
				markPositive(base)
			} else {
				markNegative(base)
			}
			markBaseLifelineCore(base)
		}
		for _, name := range []string{cc.ControlInterface, cc.FabricInterface, cc.Fabric1Interface} {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			markPositive(name)
			split := cfg.SplitInterfaceUnitRef(name)
			// #14192/#14348: name+".0" is the lifeline's own unit-0 view
			// only when that unit shares the name's netdev. A declared
			// interface's own unit 0 follows it (hb.1.0); a bare parent's
			// unit 0 follows only when untagged; a unit of a bare parent
			// (ge-0/0/0.100 -> ge-0/0/0.100.0) and undeclared names keep
			// the historical alias.
			aliasUnit0 := true
			if !split.HasUnit {
				if iface, declared := cfg.Interfaces.Interfaces[name]; declared && iface != nil {
					aliasUnit0 = unit0SharesParent(iface)
				}
			} else if iface, declared := cfg.Interfaces.Interfaces[name]; declared && iface != nil {
				// Declared dotted interface (hb.1): its own unit 0.
				aliasUnit0 = unit0SharesParent(iface)
			} else if _, canon, err := CanonicalLogicalUnit(split.UnitTok); err == nil && canon == "0" {
				if iface, declared := cfg.Interfaces.Interfaces[split.Base]; declared && iface != nil {
					if u, ok := iface.Units[0]; ok && u != nil && u.VlanID != 0 {
						aliasUnit0 = false
					}
				}
			}
			if aliasUnit0 {
				markPositive(name + ".0")
			}
			// #14302: when the role spelling is itself a DECLARED interface
			// (hb.1 declared with units hb.1.<unit>) it names that interface,
			// not a unit of a shorter parent, so the naive-cut demotion of its
			// prefix (hb) must not run. For undeclared-parent spellings the
			// #14192 rule stands: a role at a non-zero unit designates that
			// unit only; never promote its bare parent. #14348: demotions go
			// through markNegative, so they never clobber a parent that
			// another role on the same trunk designated.
			if _, roleDeclared := cfg.Interfaces.Interfaces[name]; !roleDeclared {
				if base, suf, hasSuffix := strings.Cut(name, "."); hasSuffix {
					if _, unit, err := CanonicalLogicalUnit(suf); err == nil && unit != "0" {
						if _, declared := set[base]; declared {
							markNegative(base)
						}
					}
				}
			}
			// A unit-0 role shares its parent netdev only when unit 0 is
			// untagged; markBaseLifeline encodes that. Do not promote
			// non-zero units.
			if split.HasUnit {
				if _, unit, err := CanonicalLogicalUnit(split.UnitTok); err == nil {
					if unit == "0" {
						markUnit0Parent(split.Base)
					} else {
						// #14192: role at a non-zero unit of a DECLARED
						// bare parent: the parent stays ordinary.
						if _, declared := set[split.Base]; declared {
							markNegative(split.Base)
						}
					}
				}
			}
		}
		// fabric-options member-interfaces also identify their fabric
		// aggregate and the physical member links carrying fabric traffic.
		for name, ifc := range cfg.Interfaces.Interfaces {
			if ifc == nil || len(ifc.FabricMembers) == 0 {
				continue
			}
			// Keep the fabric interface itself exempt as before; its
			// member links are independent lifelines as well.
			markPositive(strings.TrimSpace(name))
			if unit0SharesParent(ifc) {
				markPositive(strings.TrimSpace(name) + ".0")
			}
			for _, member := range ifc.FabricMembers {
				member = strings.TrimSpace(member)
				if member == "" {
					continue
				}
				// A member spelled with a unit designates that unit: mark
				// it directly and, for unit 0, classify the parent via
				// markUnit0Parent. A BARE member designates the member
				// interface itself (markBaseLifeline): the member stays
				// positive even when its unit 0 is VLAN-tagged, and that
				// tagged unit follows only its own designation.
				msplit := cfg.SplitInterfaceUnitRef(member)
				if msplit.HasUnit {
					if _, unit, err := CanonicalLogicalUnit(msplit.UnitTok); err == nil {
						markPositive(member)
						if unit == "0" {
							markUnit0Parent(msplit.Base)
						} else if _, declared := set[msplit.Base]; declared {
							markNegative(msplit.Base)
						}
						continue
					}
				}
				markBaseLifeline(member)
				// A bare member whose unit 0 is VLAN-tagged carries the
				// fabric traffic on that tagged netdev (#14348 member
				// case, mirroring a bare role): exempt the tagged unit
				// alongside the explicitly designated member.
				if iface := cfg.Interfaces.Interfaces[member]; iface != nil {
					if u, ok := iface.Units[0]; ok && u != nil && u.VlanID != 0 {
						markPositive(member + ".0")
					}
				}
			}
		}
	}
	return set
}

// HostInboundLifelineInterface reports whether the given logical interface name
// is an explicitly identified management / cluster-control LIFELINE that must
// NEVER be subjected to a host-inbound deny. Exact and longest declared names
// take precedence; only an undeclared final suffix is treated as a unit.
func HostInboundLifelineInterface(name string, lifelines map[string]bool) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return false
	}
	if isLifeline, declared := lifelines[name]; declared {
		return isLifeline
	}
	for prefix := name; ; {
		dot := strings.LastIndexByte(prefix, '.')
		if dot < 0 {
			break
		}
		prefix = prefix[:dot]
		if isLifeline, declared := lifelines[prefix]; declared {
			_, unit, err := CanonicalLogicalUnit(name[len(prefix)+1:])
			if err != nil {
				return false
			}
			// #14192: unit 0 is decided decisively when the stripped prefix
			// is itself a lifeline (set true): then .0 is that lifeline's own
			// netdev view and wins over a registered sibling's false
			// (ge-0/0/0.0, hb.1.0, ge-0/0/0.100.0). When the prefix verdict
			// is false — a dotted declared sibling under a lifeline parent
			// (hb under hb.1.0) — the registered verdict governs.
			if unit == "0" && isLifeline {
				return true
			}
			return isLifeline
		}
	}
	return false
}
