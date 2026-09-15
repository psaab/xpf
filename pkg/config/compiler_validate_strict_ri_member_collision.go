package config

import (
	"fmt"
	"sort"
	"strings"
)

// validateRIMemberDeclaredCollisionStrict hard-rejects a routing-instance
// member that claims a key which is BOTH a declared interface name and
// `base.<unit>` of another declared interface's non-nil unit — the
// residual #9821 leaves for commit time.
//
// Most #9821 consumers now resolve declared-first, so a lone declared dotted
// name (`ge-0/0/5.0`, no `ge-0/0/5` anywhere) is unambiguous and compiles.
// But when BOTH spellings are declared — e.g. `gr-0/0/0` with unit 0 AND
// `gr-0/0/0.0` (the #8994 tunnel corpus) — the two objects share a row
// keyspace: the declared dotted name's base row and the other interface's
// unit row both key `gr-0/0/0.0`. Consumers then cannot all be right at
// once: the AUTHORED ref `gr-0/0/0.0` names the declared interface's device
// (`gr-0-0-0.0`) while the STRUCTURAL (interface, unit) pair names the
// tunnel device (`gr-0-0-0`), and a member spelling that key conflates the
// two. Declared-first resolution picks a CONSISTENT side for every
// consumer, but consistency is not attribution: one object's instance would
// be stamped on the other's row. Reject instead, and say which two objects
// collide so the operator can rename one of them.
//
// The gate checks every CLAIMED key, not just the member spelling: claimed
// is {M} ∪ InterfaceUnitRefKeys(cfg, M), so a bare member that fans down
// onto a colliding key (`gr-0/0/0` → `gr-0/0/0.0`) and a padded alias
// (`gr-0/0/0.00` → `gr-0/0/0.0`) are caught the same way. The unit must be
// non-nil: a nil unit slot emits no row (buildInterfaceSnapshots skips it),
// so it cannot collide in the snapshot keyspace — and on the strict path
// unit presence implies non-nil anyway (the parser allocates every unit it
// records).
//
// RIs are visited in sorted order so commit-check surfaces a STABLE
// first-error message (sibling-gate convention).
//
// Strict on the commit / commit-check path (CompileConfig — hard-reject);
// downgraded to a cfg.Warnings entry on the tolerant load / peer-sync paths
// (flag lenientRIMemberCollision) so an already-persisted or peer-synced
// config that an older binary accepted still BOOTS (#1960 fail-closed-on-
// load doctrine; the runtime resolves every consumer declared-first, so a
// leniently-loaded colliding member is CONSISTENT — attributed to the
// declared side — now with an operator-visible warning). Wired DEAD-LAST in
// runUniformGates so it can only claim the first-error slot when nothing
// else failed (#9424 invariant #6).
func validateRIMemberDeclaredCollisionStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	declared := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		declared = append(declared, name)
	}
	sort.Strings(declared)
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
			seen := map[string]struct{}{member: {}}
			claimed := []string{member}
			for _, k := range InterfaceUnitRefKeys(cfg, member) {
				if _, dup := seen[k]; dup {
					continue
				}
				seen[k] = struct{}{}
				claimed = append(claimed, k)
			}
			for _, key := range claimed {
				ifc, ok := cfg.Interfaces.Interfaces[key]
				if !ok || ifc == nil {
					continue
				}
				for _, other := range declared {
					if other == key {
						continue
					}
					rest, ok := strings.CutPrefix(key, other+".")
					if !ok {
						continue
					}
					// #9821 (review): the collision must be a STRING collision,
					// not a numeric equivalence. CanonicalLogicalUnit("01") is
					// unit 1, but the GENERATED key for (other,1) is `other.1`
					// (fan-down `%d`, Literal canon) — a declared `other.01`
					// shares no row key with it and must not refuse. Require the
					// suffix to already BE canonical; raw-exact precedence holds
					// here as elsewhere (a declared spelling that names no
					// generated key is unambiguous).
					n, canon, err := CanonicalLogicalUnit(rest)
					if err != nil || rest != canon {
						continue
					}
					ob := cfg.Interfaces.Interfaces[other]
					if ob == nil {
						continue
					}
					if u, ok := ob.Units[n]; !ok || u == nil {
						continue
					}
					return fmt.Errorf(
						"routing-instance %q: member %q is ambiguous — it claims %q, "+
							"which is BOTH a declared interface and unit %d of declared "+
							"%q; rename one of them", ri.Name, member, key, n, other)
				}
			}
		}
	}
	return nil
}

// runUniformGatesRIMemberCollision wires validateRIMemberDeclaredCollisionStrict
// into the P6b uniform-gate phase. Strict on commit / commit-check
// (hard-reject an ambiguous member that would attribute one object's
// instance to another object's row); lenient on load / peer-sync
// (downgrade to a warning so an already-persisted colliding config still
// boots — #1960 no-brick; every runtime consumer resolves declared-first,
// so the leniently-loaded member is consistent). Called DEAD-LAST from
// runUniformGates; see its comment.
func runUniformGatesRIMemberCollision(_ *ConfigTree, cfg *Config, opts compileOpts) error {
	if err := validateRIMemberDeclaredCollisionStrict(cfg); err != nil {
		if opts.lenientRIMemberCollision {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("routing-instance member collision (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}
	return nil
}
