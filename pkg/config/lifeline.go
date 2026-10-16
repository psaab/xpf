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
	// Retain every declared interface identity (false for ordinary links).
	// The matcher uses key presence to prefer a declared dotted base over
	// interpreting that same spelling as a unit on the shorter parent.
	for name, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		name = strings.TrimSpace(name)
		if _, known := set[name]; !known {
			set[name] = false
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
				set[key] = false
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
					set[name] = true
					if strings.Contains(name, ".") {
						for unit := range ifc.Units {
							set[name+"."+strconv.Itoa(unit)] = true
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
		markBaseLifeline := func(base string) {
			set[base] = true
			if iface := cfg.Interfaces.Interfaces[base]; iface != nil {
				for unit, u := range iface.Units {
					// #14302: a declared dotted lifeline owns every declared
					// unit, VLAN-tagged or not (hb.1.7 is the lifeline's own
					// netdev, not a transit VLAN of a bare parent).
					if dottedLifelineBases[base] {
						set[base+"."+strconv.Itoa(unit)] = true
						continue
					}
					// #14192: a VLAN-tagged unit has a distinct netdev
					// and never inherits a bare parent lifeline; an
					// untagged unit keeps the prior unit==0 rule.
					if u != nil && u.VlanID != 0 {
						set[base+"."+strconv.Itoa(unit)] = false
					} else {
						set[base+"."+strconv.Itoa(unit)] = unit == 0
					}
				}
			}
		}
		for _, name := range []string{cc.ControlInterface, cc.FabricInterface, cc.Fabric1Interface} {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			set[name] = true
			// #14192: the lifeline's own unit 0 shares the parent netdev;
			// register it explicitly so the declared-unit false above does
			// not strand it (ge-0/0/0.0, hb.1.0, ge-0/0/0.100.0).
			set[name+".0"] = true
			// #14302: when the role spelling is itself a DECLARED interface
			// (hb.1 declared with units hb.1.<unit>) it names that interface,
			// not a unit of a shorter parent, so the naive-cut demotion of its
			// prefix (hb) must not run. For undeclared-parent spellings the
			// #14192 rule stands: a role at a non-zero unit designates that
			// unit only; never promote its bare parent.
			if _, roleDeclared := cfg.Interfaces.Interfaces[name]; !roleDeclared {
				if base, suf, hasSuffix := strings.Cut(name, "."); hasSuffix {
					if _, unit, err := CanonicalLogicalUnit(suf); err == nil && unit != "0" {
						if _, declared := set[base]; declared {
							set[base] = false
						}
					}
				}
			}
			// An untagged unit 0 shares the parent kernel netdev. Mark
			// that netdev as a lifeline too; do not promote non-zero units.
			split := cfg.SplitInterfaceUnitRef(name)
			if split.HasUnit {
				if _, unit, err := CanonicalLogicalUnit(split.UnitTok); err == nil {
					if unit == "0" {
						markBaseLifeline(split.Base)
					} else {
						// #14192: role at a non-zero unit of a DECLARED
						// bare parent: the parent stays ordinary.
						if _, declared := set[split.Base]; declared {
							set[split.Base] = false
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
			set[strings.TrimSpace(name)] = true
			set[strings.TrimSpace(name)+".0"] = true
			for _, member := range ifc.FabricMembers {
				member = strings.TrimSpace(member)
				if member != "" {
					markBaseLifeline(member)
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
