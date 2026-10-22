package config

import (
	"sort"
	"strconv"
	"strings"
)

// userspaceRxMTUBoundParent is one AF_XDP bind parent whose effective MTU is
// determined entirely from the compiled config.
type userspaceRxMTUBoundParent struct {
	// AuthoredBase is the stanza named by the zone reference that selects
	// this parent. It can differ from Parent for a RETH reference.
	AuthoredBase string
	// Parent is the authored stanza that supplies the parent interface MTU.
	// For an ordinary interface it is AuthoredBase; for a RETH reference it
	// is the `reth<N>` stanza, while Netdev names its local member.
	Parent string
	// Netdev is the Linux AF_XDP bind parent resolved the way the dataplane
	// builder resolves it.
	Netdev string
	// MTU is the effective parent MTU: a referenced, enabled, untagged,
	// non-tunnel unit's MTU at the lowest referenced unit number replaces
	// the interface MTU. Tagged units do not replace it. Zero means the
	// configured value could not be determined (for example, an interface
	// MTU is absent and no referenced untagged sibling pins one); callers
	// must not treat zero as either in-budget or over-budget.
	MTU int
}

// userspaceRxMTUBoundParents returns every AF_XDP bind parent selected by a
// surviving zone reference, keyed by Linux netdev. It mirrors the production
// path rather than re-deriving a second approximation from zone spellings:
//
//   - InterfaceZoneMap supplies zone membership after quarantine handling
//     and bare-reference fan-down, including the base row a unit reference
//     binds.
//   - Each canonical logical key is expanded back to its authored stanza
//     and unit, then resolved with ResolveKernelIfName. A tagged row
//     redirects to its physical parent in exactly the same way
//     userspaceBindTargetNetdev does: strip the VLAN suffix from the
//     child's resolved Linux name.
//   - The planner's precedence is then applied: tagged references
//     contribute only the interface-level MTU, while a referenced
//     untagged unit replaces it; among referenced untagged units, the
//     lowest unit number wins.
//
// Disabled interfaces and units contribute no binding candidate, matching
// the helper's forwarding-build admission. Config-owned tunnel and
// secure-tunnel rows, lifeline names, and local-fabric rows are excluded.
// Live-kernel xfrm state cannot be known at commit time, so this is
// deliberately the config-owned half of userspaceSkipsIngressInterface,
// as the existing #9727 policy already states.
func userspaceRxMTUBoundParents(cfg *Config) map[string]userspaceRxMTUBoundParent {
	out := map[string]userspaceRxMTUBoundParent{}
	if cfg == nil || cfg.Interfaces.Interfaces == nil {
		return out
	}
	zoneByInterface := InterfaceZoneMap(cfg)
	if len(zoneByInterface) == 0 {
		return out
	}

	keys := make([]string, 0, len(zoneByInterface))
	for key := range zoneByInterface {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	selectedUnit := map[string]int{}
	// Resolve the tunnel map once; ResolveKernelIfName otherwise rebuilds
	// it for every reference and makes this walk quadratic in tunnel-heavy
	// configurations.
	tunMap := tunnelNameMapFn(cfg)
	for _, key := range keys {
		split := cfg.SplitInterfaceUnitRef(key)
		base := split.Base
		if base == "" || userspaceRxMTULifelineBase(base) {
			continue
		}
		ifc, ok := LookupInterface(cfg, base)
		if !ok || ifc.Disable || ifc.Tunnel != nil || ifc.LocalFabricMember != "" {
			continue
		}

		isUnit := split.HasUnit
		unitNum := 0
		if isUnit {
			var err error
			unitNum, err = strconv.Atoi(split.UnitTok)
			if err != nil {
				// Match the runtime resolvers' Atoi treatment: syntax
				// errors select unit 0, while range errors select the
				// saturated value and therefore normally miss the
				// configured unit. Strict compilation rejects malformed
				// suffixes elsewhere; tolerant compilation must not
				// invent a different unit.
				_ = err
			}
		}
		var unit *InterfaceUnit
		if isUnit {
			unit, _ = LookupUnit(ifc, unitNum)
			if unit != nil && unit.Disable {
				continue
			}
			if unit != nil && unit.Tunnel != nil {
				continue
			}
			// Secure-tunnel ownership is directional and cannot be
			// inferred from an `st<N>` spelling. Reuse the shared
			// resolver on the canonical unit reference. An owned
			// device is an xfrmi and is never an AF_XDP parent.
			if _, owned := cfg.SecureTunnelUnitNetdev(split.Literal); owned {
				continue
			}
		}

		resolved := cfg.resolveKernelIfNameWith(key, tunMap)
		if resolved == "" {
			continue
		}
		target := resolved
		if isUnit && unit != nil && unit.VlanID > 0 {
			target = userspaceRxMTUParentNetdev(resolved, unit.VlanID)
		}
		if target == "" || userspaceRxMTULifelineNetdev(target) {
			continue
		}

		parentBase, parentIfc := userspaceRxMTUParentStanza(cfg, base, target)
		if parentIfc == nil || parentIfc.Disable || parentIfc.Tunnel != nil || parentIfc.LocalFabricMember != "" {
			continue
		}

		candidate, exists := out[target]
		if !exists {
			candidate = userspaceRxMTUBoundParent{
				AuthoredBase: base,
				Parent:       parentBase,
				Netdev:       target,
				MTU:          parentIfc.MTU,
			}
			out[target] = candidate
		} else if candidate.Parent != parentBase {
			// Two authored parents resolving to one bind netdev with
			// different interface stanzas cannot be ordered by config
			// alone (notably a RETH and a directly zoned member). Keep
			// the deterministic first (sorted-key) parent rather than
			// silently merging unlike stanzas.
			continue
		}

		// Tagged references never replace the parent. A unit that
		// resolves to a tunnel device likewise does not speak for this
		// parent. The unit stanza is read from the parent stanza, not
		// merely from a dotted ref's split base: RETH units live on the
		// `reth<N>` stanza even though the bind parent is the member.
		if !isUnit || unit == nil || unit.VlanID > 0 || resolved != target {
			continue
		}
		parentUnit, ok := LookupUnit(parentIfc, unitNum)
		if !ok || parentUnit.Disable || parentUnit.Tunnel != nil || parentUnit.MTU <= 0 {
			continue
		}
		if current, exists := selectedUnit[target]; exists && unitNum >= current {
			continue
		}
		selectedUnit[target] = unitNum
		candidate.MTU = parentUnit.MTU
		out[target] = candidate
	}
	return out
}

func userspaceRxMTUParentStanza(cfg *Config, base, target string) (string, *InterfaceConfig) {
	// RETH zone references name the logical parent, while
	// ResolveKernelIfName returns the local physical member. If the
	// target is exactly that member, the RETH stanza supplies the
	// interface MTU and carries the units; the member stanza is only
	// the resolved device.
	if strings.HasPrefix(base, "reth") {
		if ifc, ok := LookupInterface(cfg, base); ok {
			if member := cfg.ResolveReth(base); member != "" && LinuxIfName(member) == target {
				return base, ifc
			}
		}
	}
	if key, ifc, ok := LookupInterfaceByLinuxName(cfg, target); ok {
		return key, ifc
	}
	// Keep programmatic or otherwise unusual configurations conservative
	// rather than panicking if target matching cannot identify a stanza.
	// Compiled RETH shapes take the exact arm above.
	if ifc, ok := LookupInterface(cfg, base); ok {
		return base, ifc
	}
	return "", nil
}

func userspaceRxMTUParentNetdev(child string, vlanID int) string {
	suffix := "." + strconv.Itoa(vlanID)
	if !strings.HasSuffix(child, suffix) {
		return child
	}
	return strings.TrimSuffix(child, suffix)
}

func userspaceRxMTULifelineBase(base string) bool {
	return strings.HasPrefix(base, "fxp") || strings.HasPrefix(base, "em") ||
		strings.HasPrefix(base, "fab") || base == "lo0"
}

func userspaceRxMTULifelineNetdev(netdev string) bool {
	return strings.HasPrefix(netdev, "fxp") || strings.HasPrefix(netdev, "em") ||
		strings.HasPrefix(netdev, "fab") || netdev == "lo0" || netdev == "lo"
}
