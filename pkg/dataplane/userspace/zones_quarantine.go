package userspace

import (
	"fmt"
	"sort"

	"github.com/psaab/xpf/pkg/config"
)

// ZoneIDCollision records one StableZoneID collision the snapshot builder
// resolved by QUARANTINING the later-sorting zone (#3719). Survivor keeps the
// numeric ID and stays installed; Quarantined is dropped from the wire (its
// interfaces are unzoned and its policies removed) so the dataplane never
// receives two zones sharing an id. Both names fold to ID.
type ZoneIDCollision struct {
	ID          uint16
	Survivor    string
	Quarantined string
}

// String renders a ZoneIDCollision for the operator alarm and status output.
func (c ZoneIDCollision) String() string {
	return fmt.Sprintf(
		"zone %q QUARANTINED: StableZoneID %d collides with zone %q — rename one zone (#3719)",
		c.Quarantined, c.ID, c.Survivor)
}

// quarantineCollidingZones enforces the StableZoneID zone-isolation invariant on
// a built snapshot: it removes every zone whose numeric id collides with an
// earlier-sorting zone's id, UNZONES any interface bound to a quarantined zone,
// and scrubs quarantined zones out of policies — DROPPING a rule whose
// structurally-required zone (a zone-pair FromZone/ToZone, or a scoped-global
// match side left with no surviving member) is quarantined, but PRUNING only the
// colliding member(s) from a scoped-global's plural match-zone SET so a deny
// scoped to several zones SURVIVES for the members that did not collide (#5577,
// fail-closed). The published snapshot is thus internally consistent and the
// dataplane never receives two zones that share an id (#3719). Publishing both
// would merge two security zones — the
// Rust id-keyed maps (zone_id_to_name / zone_host_inbound / zone_tcp_rst) would
// have the later zone overwrite the earlier's reverse name, host-inbound set,
// and tcp-rst bit, and both zones' interfaces/policies would resolve to one id.
//
// The strict commit path REJECTS a collision (config.validateZoneIDCollisionAST,
// #3075). This is the fail-closed backstop for the LENIENT path — a tolerant
// load, an HA config-sync from an un-upgraded peer, or a config a pre-#3075
// binary persisted with no collision check. It preserves the #1960 no-brick
// intent: only the later-sorting colliding zone is dropped; the rest of the
// config still loads. Dropping the zone but LEAVING its policies would trip the
// Rust helper's UnresolvableZoneReference preflight and reject the WHOLE snapshot
// (a brick on a fresh boot), so the scrub is coordinated across zones,
// interfaces, and policies.
//
// The quarantine set is config.ZoneQuarantineExclusions over the snapshot's own zone
// names — a pure function of the name set, so both HA nodes and a cold-booting
// node resolve the identical set. Returns the collisions it resolved, sorted for
// deterministic operator output (nil in the common no-collision case).
func quarantineCollidingZones(snap *ConfigSnapshot) []ZoneIDCollision {
	if snap == nil || len(snap.Zones) < 2 {
		return nil
	}
	names := make([]string, 0, len(snap.Zones))
	for _, z := range snap.Zones {
		names = append(names, z.Name)
	}
	quarantined := config.ZoneQuarantineExclusions(names)
	if len(quarantined) == 0 {
		return nil
	}
	collisions := make([]ZoneIDCollision, 0, len(quarantined))
	kept := snap.Zones[:0]
	for _, z := range snap.Zones {
		if _, drop := quarantined[z.Name]; drop {
			collisions = append(collisions, ZoneIDCollision{
				ID:          z.ID,
				Survivor:    config.StableZoneIDOwner(names, z.ID),
				Quarantined: z.Name,
			})
			continue
		}
		kept = append(kept, z)
	}
	snap.Zones = kept
	// Unzone interfaces bound to a quarantined zone. An unzoned interface
	// matches no zone policy -> default-deny (fail closed), and it removes the
	// dangling interface->zone reference from the snapshot.
	//
	// Lifeline note (#3719 review, secondary): if the operator's management zone
	// happens to be the later-sorting collider it is quarantined and its
	// interfaces are unzoned. This does NOT strand management, because lifeline
	// interfaces (fxp0/em0/fab*) never reach the AF_XDP local-delivery
	// classifier (#3682) — their host-bound traffic is served by the kernel
	// path regardless of zone — and the loud operator alarm names both zones. We
	// deliberately keep the quarantine loser purely a function of the sorted
	// name (HA-symmetric, and reused by the reverse-map callers that have no
	// lifeline context) rather than making it lifeline-aware.
	for i := range snap.Interfaces {
		if _, drop := quarantined[snap.Interfaces[i].Zone]; drop {
			snap.Interfaces[i].Zone = ""
		}
		// #6722: the EGRESS answer (InterfaceSnapshot.EgressZone) is NOT blanked
		// here, deliberately. stampEgressZones already excludes a quarantined
		// zone from the AUTHORED bindings it decides from — it must, because
		// dropping one of two colliding zones can turn a contested ifindex into
		// an unanimous one, and blanking after the fact would leave that ifindex
		// unzoned instead of resolving the SURVIVOR. Doing it in one place also
		// keeps a second, weaker copy of the rule from going quietly vacuous.
		// Pinned by TestQuarantinedMemberZoneLetsTheRethZoneResolve_6722.
	}
	// Scrub quarantined zones out of policies so the snapshot carries no dangling
	// policy->zone reference (which the Rust UnresolvableZoneReference preflight
	// would reject wholesale — a whole-snapshot brick on a fresh boot, the exact
	// failure this quarantine exists to prevent). The scrub is shared with the
	// scheduler-only / route-overlay republish paths (#6480) via
	// scrubPoliciesForQuarantinedZones — whose doc comment documents the two
	// drop/prune cases — because those paths rebuild next.Policies from raw cfg
	// and must re-establish this SAME invariant against the already-reduced
	// next.Zones they inherit.
	snap.Policies = scrubPoliciesForQuarantinedZones(snap.Policies, quarantined)
	sort.Slice(collisions, func(i, j int) bool {
		if collisions[i].ID != collisions[j].ID {
			return collisions[i].ID < collisions[j].ID
		}
		return collisions[i].Quarantined < collisions[j].Quarantined
	})
	return collisions
}

// scrubPoliciesForQuarantinedZones is the policy half of quarantineCollidingZones,
// factored out (#6480) so the partial-republish paths that rebuild next.Policies
// from raw cfg — PublishRouteOverlaySnapshot (route-overlay) and
// UpdatePolicyScheduleState (scheduler-only) — re-establish the SAME
// zone-isolation invariant against the already-reduced next.Zones they inherit.
// Both rebuild the FULL policy set (the raw builder has no knowledge of the
// StableZoneID quarantine), so a policy referencing a quarantined zone is
// reintroduced; leaving it in next.Policies while next.Zones stays reduced ships
// a dangling policy->zone reference that the Rust UnresolvableZoneReference
// preflight (userspace-dp/src/policy.rs) rejects wholesale — a whole-snapshot
// brick. quarantined is the set of dropped zone names (config.ZoneQuarantineExclusions
// over the FULL zone-name set); "" and "junos-global" are never members (not real
// zone names), so global/zone-pair sentinels are preserved.
//
// Two cases, treated differently:
//
//  1. A STRUCTURALLY-REQUIRED zone is quarantined -> DROP the whole rule. This is
//     the singular FromZone/ToZone of a zone-pair policy (a rule from/to a
//     quarantined zone can no longer be applied), OR a scoped-global match side
//     that is CONFIGURED but has NO surviving member after pruning (every member
//     collided — leaving the side empty would silently BROADEN the rule to all
//     zones, a fail-open in the opposite direction).
//
//  2. A scoped-GLOBAL policy's match-zone context is a zone SET (#4626 M03, plural
//     MatchFromZones/MatchToZones; singular kept for back-compat). When only SOME
//     members collide, PRUNE the quarantined member(s) and KEEP the rule scoped to
//     the survivors — dropping the whole rule for one colliding member is
//     FAIL-OPEN (#5577). After pruning we regenerate the SINGULAR
//     MatchFromZone/MatchToZone from the surviving set (config.ScopeSingular) so an
//     old Rust helper reading only the singular field also sees a surviving,
//     non-quarantined zone — never the dropped one.
//
// It compacts in place (policies[:0]); the caller must own the slice (a freshly
// built or snapshot-owned slice), never an alias of the live config. The per-rule
// prune allocates a NEW slice so it never mutates an aliased config.Match slice
// (policies_lower.go). A nil/empty quarantined set returns policies unchanged, so
// callers may invoke it unconditionally.
func scrubPoliciesForQuarantinedZones(policies []PolicyRuleSnapshot, quarantined map[string]struct{}) []PolicyRuleSnapshot {
	if len(policies) == 0 || len(quarantined) == 0 {
		return policies
	}
	isQuarantined := func(z string) bool {
		_, drop := quarantined[z]
		return drop
	}
	pruneQuarantined := func(zs []string) []string {
		out := make([]string, 0, len(zs))
		for _, z := range zs {
			if !isQuarantined(z) {
				out = append(out, z)
			}
		}
		return out
	}
	keptPol := policies[:0]
	for _, p := range policies {
		// Case 1a: a zone-pair rule's required endpoint is quarantined.
		if isQuarantined(p.FromZone) || isQuarantined(p.ToZone) {
			continue
		}
		drop := false
		// Case 2 / 1b: prune each configured scoped-global match side; drop the
		// rule only if a configured side is emptied by the prune.
		if from := p.effectiveMatchFromZones(); len(from) > 0 {
			kept := pruneQuarantined(from)
			if len(kept) == 0 {
				drop = true
			} else {
				p.MatchFromZones = kept
				p.MatchFromZone = config.ScopeSingular(kept)
			}
		}
		if !drop {
			if to := p.effectiveMatchToZones(); len(to) > 0 {
				kept := pruneQuarantined(to)
				if len(kept) == 0 {
					drop = true
				} else {
					p.MatchToZones = kept
					p.MatchToZone = config.ScopeSingular(kept)
				}
			}
		}
		if drop {
			continue
		}
		keptPol = append(keptPol, p)
	}
	return keptPol
}

// quarantinedZoneNamesForConfig computes the StableZoneID quarantine set — the
// zone names quarantineCollidingZones drops — directly from a config's zone-name
// set, WITHOUT building a full snapshot. The partial-republish paths use it to
// re-scrub a freshly rebuilt policy slice against the SAME quarantine the full
// build applied (#6480). The name set is exactly buildZoneSnapshots' source
// (cfg.Security.Zones keys), so the computed set matches the full build's
// quarantine by construction; the inherited next.Zones (reduced by the full
// build) is therefore full(cfg) minus this set, and scrubbing the rebuilt
// policies against it leaves no reference to a zone absent from next.Zones.
func quarantinedZoneNamesForConfig(cfg *config.Config) map[string]struct{} {
	if cfg == nil || len(cfg.Security.Zones) < 2 {
		return nil
	}
	names := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		names = append(names, name)
	}
	return config.ZoneQuarantineExclusions(names)
}
