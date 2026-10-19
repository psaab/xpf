package config

import "strings"

// RETH redundancy-group ownership — the single source of truth for "does this
// interface own a chassis-cluster redundancy group?" (#6781).
//
// The question has one right answer and, before this file, had two wrong ones.
// Consumers split into two camps, and BOTH were measurably wrong, in OPPOSITE
// directions:
//
//	RedundancyGroup > 0 alone            (pkg/vrrp CollectRethInstances)
//	RedundancyGroup > 0 && name "reth*"  (everyone else)
//
// Measured on configs that COMMIT CLEANLY today:
//
//	`ge-0/0/5 redundant-ether-options redundancy-group 1`, nothing naming it as
//	a redundant-parent. The RG-only reading synthesizes a VRRP instance on it
//	whose "VIPs" are that interface's OWN unit addresses — so the node ADDS
//	them on MASTER and DELETES them on BACKUP, stripping a plain interface's
//	configured address. The name reading excludes it. Over-inclusion, harmful.
//
//	`bond0 redundant-ether-options redundancy-group 1` with
//	`ge-0/0/1 gigether-options redundant-parent bond0` — a STRUCTURALLY valid
//	redundant pair whose owner is not named "reth*". The RG-only reading
//	resolves it correctly to the physical member; the name reading returns
//	NOTHING, so the direct ownership mode installs no VIPs at all and the group
//	is dark. Under-inclusion, an outage.
//
// So the fix is not to make one camp match the other — that would ship one of
// the two defects everywhere. The discriminator both readings miss is
// STRUCTURAL: a redundant-ethernet interface is the L3 owner of a pair of
// member PORTS, and what makes it one is that ports name it
// (`gigether-options redundant-parent <name>`), not how it is spelled.
// RethToPhysical already keys on exactly that relation, and the whole runtime
// resolves a RETH to its local member through it — an interface absent from
// that map has no netdev for VRRP to bind, no member to fail over between, and
// nothing for a VIP to move onto.
//
// Naming is NOT used as the test, deliberately. Interface names are validated
// by character class only (validate_interface_name.go), so "reth" is a
// convention rather than a closed namespace, and rejecting an odd-named but
// structurally valid pair would turn a working config into a failed commit with
// no operator workaround — the #6564 lesson that file already records.
//
// validateRethRedundancyGroupStrict rejects the over-inclusion shape at commit;
// this predicate makes every runtime consumer agree on the answer.

// RethRGOwners returns interface name -> redundancy-group id for every
// interface that is a REDUNDANT-ETHERNET INTERFACE — either STRUCTURALLY (some
// port names it as its `gigether-options redundant-parent`) or NOMINALLY (it is
// spelled `reth*`) — mapped to the redundancy group it carries.
//
// It deliberately does NOT filter on `RedundancyGroup > 0`. That term belongs
// to the CALLER, because the two ownership modes need different things from it:
// the VRRP-backed collector synthesizes instances only for groups above 0,
// while the direct collector is legitimately queried FOR group 0 and must
// answer for a reth carrying it. Folding `> 0` in here silently broke the
// second. What the RG-0 query actually needs protecting from is every
// unconfigured interface DEFAULTING to 0 — and the structural/nominal test
// above already excludes those, since a fabric, control, or management
// interface is neither a reth by name nor by membership. That is the guard the
// replaced `strings.HasPrefix(name, "reth")` filter was really providing.
//
// The predicate is deliberately the UNION of the two readings it replaces,
// minus their shared blind spot. That direction matters: it EXCLUDES only the
// shape that was actively wrong (a redundancy group on an interface that is
// neither, which one mode half-applied and the other ignored) and INCLUDES the
// shape one mode was wrongly dropping (a structurally valid pair not spelled
// `reth*`, which the direct mode left with no VIPs at all). No configuration
// that either mode previously owned stops being owned — in HA ownership code a
// newly-excluded interface is an outage, so the nominal term is kept even
// though a `reth*` with no members yet is an incomplete config: both modes
// accepted it before, and narrowing that is not what #6781 is about.
//
// Build it ONCE per walk and look names up in it; it is O(interfaces) and
// recomputes RethToPhysical on each call. Present-but-nil interface slots are
// skipped (#6780).
func (c *Config) RethRGOwners() map[string]int {
	if c == nil {
		return nil
	}
	rethToPhys := c.RethToPhysical()
	owners := make(map[string]int, len(rethToPhys))
	for name, ifc := range c.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		_, hasMembers := rethToPhys[name]
		if !hasMembers && !strings.HasPrefix(name, "reth") {
			// Neither structurally nor nominally a redundant-ethernet
			// interface: no port names it as their redundant-parent AND it is
			// not spelled `reth*`. It owns no group. Commit rejects this shape
			// (validateRethRedundancyGroupStrict); a tolerantly-loaded config
			// that still carries it is excluded here rather than half-applied.
			continue
		}
		owners[name] = ifc.RedundancyGroup
	}
	return owners
}

// RethRGOwner reports which redundancy group `name` owns, and whether it owns
// one at all. Convenience for a caller inspecting a single interface; a caller
// walking every interface should build RethRGOwners once instead.
func (c *Config) RethRGOwner(name string) (int, bool) {
	rg, ok := c.RethRGOwners()[name]
	return rg, ok
}

// SessionHAState returns "Active", "Backup", or "unknown" for a session whose
// ingress/egress interfaces and zones are known (#15236 A52-03). The owning
// data redundancy group is derived from the session's interface RETH RG
// (via RethRGOwners, resolving reth units to their parent) or, failing that,
// from an interface bound to its zones. primary reports local primary state
// for a group and whether the group is known. "unknown" is returned when no
// owning RG can be derived or the group is not known — never a guess from RG0.
func SessionHAState(cfg *Config, ingressIface, egressIface string, ingressZoneID, egressZoneID uint16, zoneNames map[uint16]string, primary func(rg int) (bool, bool)) string {
	if cfg == nil || primary == nil {
		return "unknown"
	}
	owners := cfg.RethRGOwners()
	if len(owners) == 0 {
		return "unknown"
	}
	rgForIface := func(name string) (int, bool) {
		if name == "" {
			return 0, false
		}
		if rg, ok := owners[name]; ok {
			return rg, true
		}
		if i := strings.LastIndex(name, "."); i > 0 {
			if rg, ok := owners[name[:i]]; ok {
				return rg, true
			}
		}
		// Linux spelling (ge-0-0-0) vs Junos (ge-0/0/0): try both.
		alt := strings.ReplaceAll(name, "-", "/")
		if rg, ok := owners[alt]; ok {
			return rg, true
		}
		if i := strings.LastIndex(alt, "."); i > 0 {
			if rg, ok := owners[alt[:i]]; ok {
				return rg, true
			}
		}
		return 0, false
	}
	for _, name := range []string{ingressIface, egressIface} {
		if rg, ok := rgForIface(name); ok {
			if isPrimary, known := primary(rg); known {
				if isPrimary {
					return "Active"
				}
				return "Backup"
			}
			return "unknown"
		}
	}
	// Fall back to interfaces bound to the session's zones.
	if cfg.Security.Zones != nil && zoneNames != nil {
		for _, zid := range []uint16{ingressZoneID, egressZoneID} {
			zname := zoneNames[zid]
			if zname == "" {
				continue
			}
			zone := cfg.Security.Zones[zname]
			if zone == nil {
				continue
			}
			for _, ifName := range zone.Interfaces {
				if rg, ok := rgForIface(ifName); ok {
					if isPrimary, known := primary(rg); known {
						if isPrimary {
							return "Active"
						}
						return "Backup"
					}
					return "unknown"
				}
			}
		}
	}
	return "unknown"
}
