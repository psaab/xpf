package config

import (
	"fmt"
	"sort"
)

// validateRIDualClaimStrict11060 hard-rejects a configuration that assigns
// the same interface to more than one routing-instance (#11060).
//
// Before this gate a dual-claimed member committed clean and then flapped
// between VRFs: the kernel bind loop (daemon bindRoutingInstanceMembers)
// binds every RI's members in slice order, last-wins; the userspace domain
// map (forEachRoutingInstanceInterfaceKey pass 0) likewise last-wins; and
// the 30s reassert loop (riMembersOutsideTheirVRF) treats the non-master RI
// as drift and re-binds the member to the other VRF on EVERY tick. The
// table/domain flips under a fixed zone: sessions re-resolve into the other
// VRF, return traffic goes asymmetric, and packets cross a VRF boundary the
// operator never authorized.
//
// Worse, the two planes resolve the same dual membership in OPPOSITE
// orders (F-147): Rust member-vs-member is unconditional LAST-WINS
// (forwarding_build/interfaces.rs) while Go routingInstanceByInterface is
// FIRST-in-sorted-wins — so NAT scope and the dataplane VRF can disagree,
// not just flap over time.
//
// This validator restores the fail-CLOSED parity Junos has (an interface in
// two routing-instances is rejected at commit). It mirrors
// validateZoneInterfaceMembershipStrict (#3072): per RI (in sorted order
// for a deterministic first-reported error), it expands each member to the
// logical-interface keys the routing binders bind (InterfaceUnitRefKeys —
// a unit ref claims its canonical literal, a bare ref claims the base plus
// every configured unit) and rejects the first key claimed by two different
// instances, naming the interface and BOTH conflicting instances. Listing
// the same interface twice WITHIN one instance is harmless (a repeated
// `set`) and is not flagged. Two distinct units of one physical interface
// in two instances (a valid VLAN split) is NOT flagged.
//
// Forwarding instances are NOT exempt: the userspace snapshot and the NAT
// egress scope index them like any other instance, so a forwarding+VRF
// dual claim disagrees across planes the same way. (A reserved-name
// instance never reaches this gate on the strict path — the prewalk
// reserved-name gate fires first.)
//
// Strict on the commit / commit-check path (CompileConfig — hard-reject);
// downgraded to a cfg.Warnings entry on the tolerant load / peer-sync paths
// (CompileConfigLenient / CompileConfigForNodeLenient, flag
// lenientRIDualClaim11060) so an already-persisted or peer-synced config
// that an older binary accepted still BOOTS (#1960 fail-closed-on-load
// doctrine). On that tolerant path behavior is unchanged and deterministic:
// the apply keeps its last-wins bind, the reassert loop leaves
// multi-claimed keys alone (daemon riDualClaimedLinuxNames, no per-tick
// flap), and each plane keeps its deterministic resolution — just with an
// operator-visible warning.
func validateRIDualClaimStrict11060(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	owner := make(map[string]string)
	ris := make([]*RoutingInstanceConfig, 0, len(cfg.RoutingInstances))
	for _, ri := range cfg.RoutingInstances {
		if ri == nil {
			continue // #3494: tolerant/HA-sync path may carry a nil routing-instance
		}
		ris = append(ris, ri)
	}
	sort.Slice(ris, func(i, j int) bool { return ris[i].Name < ris[j].Name })
	for _, ri := range ris {
		for _, member := range ri.Interfaces {
			if member == "" {
				continue
			}
			for _, key := range InterfaceUnitRefKeys(cfg, member) {
				prev, exists := owner[key]
				if exists {
					if prev != ri.Name {
						return fmt.Errorf(
							"interface %q is claimed by routing-instances %q and %q; an interface must belong to exactly one routing-instance (#11060: the kernel bind loop last-wins while the reassert loop re-binds the member to the other VRF on every tick, flapping traffic between VRFs, and the Go/Rust planes resolve the same dual claim in opposite orders) — remove it from one instance",
							member, prev, ri.Name)
					}
					// Same instance (repeated set, or base/unit overlap within
					// one instance): keep the first claim, not a conflict.
					continue
				}
				owner[key] = ri.Name
			}
		}
	}
	return nil
}

// runUniformGatesRIDualClaim11060 wires validateRIDualClaimStrict11060 into
// the P6b uniform-gate phase. Strict on commit / commit-check (hard-reject
// a dual-claimed member that would flap between VRFs); lenient on load /
// peer-sync (downgrade to a warning so an already-persisted dual-claimed
// config still boots — #1960 no-brick; the apply keeps its deterministic
// last-wins bind and the reassert loop leaves multi-claimed keys alone).
// Called DEAD-LAST from runUniformGates; see its comment.
func runUniformGatesRIDualClaim11060(_ *ConfigTree, cfg *Config, opts compileOpts) error {
	if err := validateRIDualClaimStrict11060(cfg); err != nil {
		if opts.lenientRIDualClaim11060 {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("routing-instance interface membership (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}
	return nil
}
