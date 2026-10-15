package config

import (
	"fmt"
	"hash/fnv"
	"sort"
)

// ZoneIDReservedMin is the Go mirror of the Rust ZONE_ID_RESERVED_MIN
// (userspace-dp/src/policy.rs: u16::MAX-1 = 0xFFFE). The top two ids of the
// u16 zone space are reserved sentinels — JUNOS_GLOBAL_ZONE_ID (u16::MAX) and
// the junos-host self-traffic zone (u16::MAX-1) — so the largest id a
// CONFIGURED zone may carry is ZoneIDReservedMin-1 (65533). StableZoneID folds
// strictly into [1, ZoneIDReservedMin-1] so a hashed zone id can never collide
// with either sentinel.
const ZoneIDReservedMin uint16 = 0xFFFE // mirrors Rust ZONE_ID_RESERVED_MIN

// StableZoneID maps a security-zone name to a stable nonzero u16 zone id:
// FNV-1a/64 xor-folded to 16 bits, mapped into [1, ZoneIDReservedMin-1].
//
// THE FOLD IS WIRE-ADJACENT AND MUST NEVER CHANGE (#3075): zone ids ride the
// daemon↔helper event-stream delta wire (a u16 field after #3075) and the
// per-flow conntrack value, and both HA nodes must compute identical ids from
// identical config. The id is a pure function of the zone NAME alone — never of
// the rest of the zone set, the compile order, or allocation history — so
// adding, renaming, or removing a zone can never renumber another zone (the
// sorted-positional defect this replaces; see #3075), and both nodes plus a
// cold-booting node agree by construction with zero synced/persisted state.
//
// This is the #1873 tunnelid.go pattern, ported to zones now that the two
// same-host event-stream u8 chokepoints have been widened to u16 (#3075). It
// supersedes the #2391 u8 zone-count cap: the binding constraint is no longer a
// 255-id wire field but the reserved-sentinel range, so the usable space is
// [1, ZoneIDReservedMin-1] = [1, 65533].
//
// 0 is never returned: id 0 means "unassigned / unknown zone" across the
// dataplane.
func StableZoneID(name string) uint16 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(name))
	s := h.Sum64()
	folded := uint16(s) ^ uint16(s>>16) ^ uint16(s>>32) ^ uint16(s>>48)
	return folded%(ZoneIDReservedMin-1) + 1 // [1, 65533]
}

// collectZoneNamesAST appends the security-zone names declared under one
// "security" hierarchy node into out. The AST path mirrors compileZones
// (compiler_security.go): security -> zones -> security-zone <name>, handling
// both the hierarchical merged-key shape and the flat-set single-key chain via
// the shared namedInstances helper.
func collectZoneNamesAST(securityNode *Node, out map[string]struct{}) {
	if securityNode == nil {
		return
	}
	// compileSecurity processes each sibling `zones` block. Keep collision
	// detection and runtime quarantine enumeration aligned with that same
	// behavior instead of silently considering only the first block (#12829).
	for _, zonesNode := range securityNode.FindChildren("zones") {
		for _, inst := range bracketedGroupInstances8794(zonesNode.FindChildren("security-zone")) {
			if inst.name == "" {
				continue
			}
			out[inst.name] = struct{}{}
		}
	}
}

// emitNodeExpandedZoneNames returns the security-zone names that survive
// expanding the candidate tree for chassis-cluster node nodeID (View 2 for
// node0, View 3 for node1), used by validateZoneIDCollisionAST. It is the
// post-`${node}`/apply-groups view: a `${node}`-interpolated or wildcard
// apply-group zone name is only concrete after expansion.
//
// It is RECURSION-FREE by construction: it clones the candidate, expands groups
// for the node, and reads the zone names straight off the expanded AST — it
// NEVER calls CompileConfig* (which would call this gate and recurse). Per-node
// expansion errors are NON-FATAL: the view contributes the EMPTY set. A config
// that defines only `groups node0` and references `${node}` legitimately has no
// `groups node1`, so expanding for node1 hits `undefined group "node1"`; that
// is already handled on the real per-node compile path (CompileConfig falls
// back to node0), and the collision gate must not turn it into a spurious
// commit failure. View 1's pre-expansion presence union still covers any
// collision inside the un-expandable group, so dropping the failed node's view
// loses no real coverage and keeps the verdict a pure function of the candidate
// (both nodes compute identical error-to-empty-set handling).
func emitNodeExpandedZoneNames(tree *ConfigTree, nodeID int, out map[string]struct{}) {
	clone := tree.Clone()
	vars := map[string]string{"node": fmt.Sprintf("node%d", nodeID)}
	if err := clone.ExpandGroupsWithVars(vars); err != nil {
		return
	}
	// #5691: union across every top-level `security` root — a split config can
	// declare zones in a second `security { }` stanza that compileSections still
	// compiles.
	for _, sec := range clone.FindChildren("security") {
		collectZoneNamesAST(sec, out)
	}
}

// zoneRuntimeNameUnionAST is the security-zone name set tolerant compiles
// record as Config.ZoneQuarantineNames (#12247): the main, node0 and node1
// views — every top-level `security` root (#5691) plus the node0/node1
// expansions (Views 2/3), i.e. every name a cluster node installs. Both nodes
// compute it from the same candidate, so both quarantine the same survivor even
// when a collider exists only in the peer's view; a node view whose expansion
// fails contributes nothing. The generic compile, and a node compile for any
// other ID, add their own zones where the set is consumed
// (ZoneQuarantineNamesForConfig merges cfg.Security.Zones), so a name only
// such a compile lands — a group literally named "${node}" — never quarantines
// a zone on the cluster nodes.
//
// View 1's raw `groups` scan is deliberately absent. A name only a groups block
// declares — a `<*>` wildcard template, a group nothing applies, or a group
// applied under another stanza — is installed by no node. Letting it quarantine
// a live zone would unzone that zone's interfaces and deny its traffic in
// favour of a zone that exists nowhere (the zone analogue of #9657).
func zoneRuntimeNameUnionAST(tree *ConfigTree) map[string]struct{} {
	names := make(map[string]struct{})
	for _, sec := range tree.FindChildren("security") {
		collectZoneNamesAST(sec, names)
	}
	emitNodeExpandedZoneNames(tree, 0, names)
	emitNodeExpandedZoneNames(tree, 1, names)
	return names
}

func sortedZoneNameSet(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for name := range set {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// collisionCandidateZoneName reports whether a name can own a StableZoneID.
// Reserved context tokens are excluded by QuarantinedZoneNames, and wildcard
// group templates are patterns rather than installed zones.
func collisionCandidateZoneName(name string) bool {
	if _, reserved := reservedZoneNames[name]; reserved {
		return false
	}
	_, wildcard := groupKeyPattern(name)
	return !wildcard
}

// validateZoneIDCollisionAST checks the UNION of concrete, non-reserved
// security-zone names across three views of the candidate config for
// StableZoneID collisions (#3075), mirroring
// validateTunnelEndpointIDCollisionAST (#1873/#1914):
//
// View 1 — the PRE-expansion presence union across the main "security"
// hierarchy AND every "groups" block. It runs on the pre-expansion tree
// (ExpandGroups removes the groups stanza), so collisions involving a
// group-scoped zone fail commit on both chassis-cluster nodes.
//
// View 2 — the zone names that survive expanding the candidate for node0.
// View 3 — the same for node1.
//
// Zones ARE group/`${node}`-scoped. Views 2/3 are REQUIRED because a
// `${node}`-interpolated or wildcard-apply-group zone name is only concrete
// post-expansion; the verdict must be identical on both nodes.
//
// Wildcard templates and reserved context names are not ID claimants:
// reserved names never claim in QuarantinedZoneNames, and wildcard templates
// are patterns rather than concrete zone instances. Admitting either here
// would make strict commits reject valid configs and lenient warnings
// quarantine unrelated zones.
// Strict (commit / commit-check) returns an error; lenient (load / peer-sync of
// an already-active config) returns a warning. The function also returns the
// sorted runtime name set for tolerant compiles to record as
// Config.ZoneQuarantineNames (#12247).
func validateZoneIDCollisionAST(tree *ConfigTree, lenient bool) ([]string, []string, error) {

	runtimeNames := zoneRuntimeNameUnionAST(tree)
	names := make(map[string]struct{}, len(runtimeNames))
	addCollisionNames := func(source map[string]struct{}) {
		for name := range source {
			if collisionCandidateZoneName(name) {
				names[name] = struct{}{}
			}
		}
	}
	addCollisionNames(runtimeNames)
	// View 1 — pre-expansion presence union. Its main `security` roots (every
	// root, #5691) are already in runtimeNames; add every groups block so a
	// collision with a group-scoped zone fails commit on both nodes.
	groupNames := make(map[string]struct{})
	for _, child := range tree.Children {
		if child.Name() != "groups" {
			continue
		}
		for _, group := range child.Children {
			// Node{Keys:["groups","node0"]} merges the group name into
			// Keys[1]; the children are then the group body. The other shape
			// nests the group name as a child node.
			if len(child.Keys) >= 2 {
				for _, sec := range child.FindChildren("security") {
					clear(groupNames)
					collectZoneNamesAST(sec, groupNames)
					addCollisionNames(groupNames)
				}
				break
			}
			for _, sec := range group.FindChildren("security") {
				clear(groupNames)
				collectZoneNamesAST(sec, groupNames)
				addCollisionNames(groupNames)
			}
		}
	}
	runtime := sortedZoneNameSet(runtimeNames)
	sorted := sortedZoneNameSet(names)
	if len(sorted) < 2 {
		return nil, runtime, nil
	}
	byID := make(map[uint16]string, len(sorted))
	var warnings []string
	for _, name := range sorted {
		id := StableZoneID(name)
		owner, taken := byID[id]
		if !taken {
			byID[id] = name
			continue
		}
		msg := fmt.Sprintf(
			"zone id collision between %q and %q (both fold to %d) — rename one zone (#3075)",
			owner, name, id)
		if !lenient {
			return nil, nil, fmt.Errorf("security zones: %s", msg)
		}
		// #3719: the lenient path keeps booting but QUARANTINES the
		// later-sorting zone (QuarantinedZoneNames) so the dataplane never
		// receives two zones sharing a numeric id. Word the warning so the
		// operator knows the box is running in a degraded zone-isolation state:
		// the quarantined zone is dropped from the dataplane, its interfaces are
		// unzoned, and its traffic is denied until one zone is renamed.
		warnings = append(warnings, fmt.Sprintf("%s; the later-sorting zone %q is QUARANTINED"+
			" (dropped from the dataplane, its interfaces unzoned and its traffic denied) —"+
			" zone isolation is DEGRADED until one zone is renamed", msg, name))
	}
	return warnings, runtime, nil
}

// ZoneQuarantineNamesForConfig returns the sorted runtime zone-name set the
// compiler recorded (Config.ZoneQuarantineNames, see zoneRuntimeNameUnionAST)
// merged with cfg's effective zone keys. Manually constructed Config values
// carry no recorded set and fall back to their effective zone keys alone.
func ZoneQuarantineNamesForConfig(cfg *Config) []string {
	if cfg == nil {
		return nil
	}
	if len(cfg.ZoneQuarantineNames) > 0 {
		var merged []string
		for name := range cfg.Security.Zones {
			i := sort.SearchStrings(cfg.ZoneQuarantineNames, name)
			if i < len(cfg.ZoneQuarantineNames) && cfg.ZoneQuarantineNames[i] == name {
				continue
			}
			if merged == nil {
				merged = append([]string(nil), cfg.ZoneQuarantineNames...)
			}
			merged = append(merged, name)
		}
		if merged == nil {
			return cfg.ZoneQuarantineNames
		}
		sort.Strings(merged)
		return merged
	}
	names := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ZoneQuarantineExclusionsForConfig returns the collision losers, reserved
// names, and DroppedEnforcementChild-poisoned (#11575/#12623) zones excluded
// from cfg's runtime zone-name set (ZoneQuarantineNamesForConfig). A poisoned
// zone is quarantined in its own right and never claims a StableZoneID
// against a healthy peer (#13099).
func ZoneQuarantineExclusionsForConfig(cfg *Config) map[string]struct{} {
	return zoneQuarantineExclusionsForNames(ZoneQuarantineNamesForConfig(cfg), poisonedZoneNamesForConfig(cfg))
}

// CollisionSurvivorForConfig returns the healthy installed zone that owns
// quarantined's StableZoneID under cfg ("" for a reserved name, a poisoned
// zone with no healthy collider, or a non-quarantined name). Poisoned zones
// never own an ID, so a poisoned collider's survivor is its healthy peer
// (#13099) — unlike ZoneQuarantineSurvivorName over raw names, which would
// name the poisoned sorted-first zone.
func CollisionSurvivorForConfig(cfg *Config, quarantined string) string {
	if cfg == nil || quarantined == "" {
		return ZoneQuarantineSurvivorName(quarantined, ZoneQuarantineNamesForConfig(cfg))
	}
	if _, reserved := reservedZoneNames[quarantined]; reserved {
		return ""
	}
	if _, excluded := ZoneQuarantineExclusionsForConfig(cfg)[quarantined]; !excluded {
		return ""
	}
	id := StableZoneID(quarantined)
	best := ""
	for _, name := range ZoneQuarantineNamesForConfig(cfg) {
		if name == quarantined {
			continue
		}
		if _, reserved := reservedZoneNames[name]; reserved {
			continue
		}
		if isPoisonedZoneForConfig(cfg, name) {
			continue
		}
		if StableZoneID(name) != id {
			continue
		}
		if best == "" || name < best {
			best = name
		}
	}
	return best
}

// QuarantinedZoneNames returns the set of security-zone names that MUST NOT be
// installed in the dataplane because their StableZoneID collides with an
// earlier (alphabetically-sorted) zone's id. For each numeric id claimed by
// more than one name, the sorted-FIRST name keeps the id and every later name
// that folds to the same id is quarantined.
//
// This is the RUNTIME enforcement of the promise the lenient collision warning
// (validateZoneIDCollisionAST) already makes — "the later-sorting zone is NOT
// installed in the dataplane" — so the dataplane never receives two zones that
// share a numeric id. Publishing both would MERGE two security zones: one
// zone's interfaces, policies, counters, host-inbound admission set, and
// tcp-rst bit would stand in for the other (#3719 — the wire builder, the Rust
// id-keyed maps, and the id→name reverse maps all key on the numeric id). The
// STRICT commit path REJECTS a collision outright; the LENIENT path (tolerant
// load / peer-sync / a config a pre-#3075 binary persisted with no collision
// check) keeps booting but quarantines the colliding zone here, preserving the
// #1960 no-brick intent — the rest of the config still loads and only the
// later-sorting colliding zone is dropped.
//
// The decision is a pure function of the zone-name SET (StableZoneID is a pure
// function of the name and the sorted tie-break is deterministic), so both HA
// nodes and a cold-booting node compute the IDENTICAL quarantine set from the
// identical config — the same HA-symmetry guarantee StableZoneID itself carries.
// Returns nil when no id collides (the common case).
func QuarantinedZoneNames(names []string) map[string]struct{} {
	return quarantinedZoneNamesExcluding(names, nil)
}

// quarantinedZoneNamesExcluding is QuarantinedZoneNames with an extra set of
// names that must never claim a StableZoneID (#13099): a zone poisoned by
// DroppedEnforcementChild is unbound, so it is quarantined in its own right
// and must not win the collision tournament against a healthy peer.
func quarantinedZoneNamesExcluding(names []string, excluded map[string]struct{}) map[string]struct{} {
	sorted := make([]string, len(names))
	copy(sorted, names)
	sort.Strings(sorted)
	owner := make(map[uint16]string, len(sorted))
	var quarantined map[string]struct{}
	mark := func(name string) {
		if quarantined == nil {
			quarantined = make(map[string]struct{})
		}
		quarantined[name] = struct{}{}
	}
	for _, name := range sorted {
		if _, reserved := reservedZoneNames[name]; reserved {
			continue
		}
		if _, drop := excluded[name]; drop {
			mark(name)
			continue
		}
		id := StableZoneID(name)
		if existing, taken := owner[id]; taken {
			if existing == name {
				// Defensive: a duplicated name in the input slice is the same
				// zone, not a collision (map-keyed callers never hit this).
				continue
			}
			mark(name)
			continue
		}
		owner[id] = name
	}
	return quarantined
}

// poisonedZoneNamesForConfig returns the effective zones poisoned by
// DroppedEnforcementChild (#11575/#12623). compileZones already unbound such
// a zone (Interfaces/InterfaceHostInbound/ScreenProfile cleared); every
// quarantine consumer must also treat it as excluded so it cannot claim a
// StableZoneID, host-inbound view, or classifier admit (#13099).
func poisonedZoneNamesForConfig(cfg *Config) map[string]struct{} {
	if cfg == nil || len(cfg.Security.Zones) == 0 {
		return nil
	}
	var out map[string]struct{}
	for name, zone := range cfg.Security.Zones {
		if zone == nil || !zone.DroppedEnforcementChild {
			continue
		}
		if out == nil {
			out = make(map[string]struct{})
		}
		out[name] = struct{}{}
	}
	return out
}

// isPoisonedZoneForConfig reports whether cfg's effective zone name is
// poisoned by DroppedEnforcementChild (#13099).
func isPoisonedZoneForConfig(cfg *Config, name string) bool {
	if cfg == nil || name == "" {
		return false
	}
	zone := cfg.Security.Zones[name]
	return zone != nil && zone.DroppedEnforcementChild
}

// ZoneQuarantineExclusions returns every zone name that snapshot builders must
// omit: collision losers plus reserved dataplane/Junos context names. It is
// the builder-facing *Exclusions spelling used by the #6534 showaudit registry;
// QuarantinedZoneNames remains the collision-only decision.
func ZoneQuarantineExclusions(names []string) map[string]struct{} {
	excluded := QuarantinedZoneNames(names)
	for _, name := range names {
		if _, reserved := reservedZoneNames[name]; !reserved {
			continue
		}
		if excluded == nil {
			excluded = make(map[string]struct{})
		}
		excluded[name] = struct{}{}
	}
	return excluded
}

// zoneQuarantineExclusionsForNames is ZoneQuarantineExclusions over names
// with poisoned zones additionally excluded and barred from claiming an ID
// (#13099). Poisoned-only input (no collision/reserved) still excludes.
func zoneQuarantineExclusionsForNames(names []string, poisoned map[string]struct{}) map[string]struct{} {
	excluded := quarantinedZoneNamesExcluding(names, poisoned)
	for _, name := range names {
		if _, reserved := reservedZoneNames[name]; !reserved {
			continue
		}
		if excluded == nil {
			excluded = make(map[string]struct{})
		}
		excluded[name] = struct{}{}
	}
	return excluded
}

// ZoneQuarantineExcludedReason returns the operator-facing reason for a
// quarantined zone in cfg. It returns an empty string for an ordinary or
// survivor zone, and uses the same runtime name set as the snapshot builders
// (ZoneQuarantineNamesForConfig).
func ZoneQuarantineExcludedReason(name string, cfg *Config) string {
	if cfg == nil || name == "" {
		return ""
	}
	quarantined := ZoneQuarantineExclusionsForConfig(cfg)
	if _, excluded := quarantined[name]; !excluded {
		return ""
	}
	if isPoisonedZoneForConfig(cfg, name) {
		return fmt.Sprintf(
			"security zone %q is quarantined: an unrecognized enforcement child was dropped (DroppedEnforcementChild) so the zone is unbound and was omitted from the dataplane",
			name)
	}
	if _, reserved := reservedZoneNames[name]; reserved {
		return fmt.Sprintf(
			"security zone %q is quarantined: %q is a reserved dataplane/Junos context token and cannot be installed",
			name, name)
	}
	id := StableZoneID(name)
	owner := CollisionSurvivorForConfig(cfg, name)
	return fmt.Sprintf(
		"security zone %q is quarantined: stable ID %d is owned by surviving zone %q and was omitted from the dataplane",
		name, id, owner)
}

// ZoneQuarantineSurvivorName returns the installed zone that owns a quarantined
// zone's stable ID, or "" when the zone was excluded for a reserved name.
func ZoneQuarantineSurvivorName(name string, names []string) string {
	if _, reserved := reservedZoneNames[name]; reserved {
		return ""
	}
	return StableZoneIDOwner(names, StableZoneID(name))
}

// ScopedGlobalQuarantineDropped reports whether the zone-quarantine scrub
// mirrors the runtime DROP decision for a scoped-global policy
// (userspace scrubPoliciesForQuarantinedZones, #5577): true exactly when a
// CONFIGURED match side (len > 0) has EVERY member in the quarantined set —
// leaving that side installed would silently broaden the rule to all zones,
// so the whole rule is dropped and cannot match, count, or be enforced.
//
// A MIXED scope — some members quarantined, at least one survivor on every
// configured side — keeps the rule installed and enforced for the survivors,
// so the observability surfaces must keep reading its live counters instead
// of marking the whole rule quarantined (#12897). An unscoped side (len == 0,
// all-zones) can never be emptied, matching the runtime prune which leaves it
// untouched.
//
// quarantined is the caller's display-facing exclusion set
// (ZoneQuarantineExclusionsForConfig); zone-pair rules do not route through
// this helper — their singular endpoints quarantine the whole rule by
// definition and each surface keeps its existing isQuarantined(from) ||
// isQuarantined(to) spelling.
func ScopedGlobalQuarantineDropped(from, to []string, quarantined map[string]struct{}) bool {
	sideDropped := func(scope []string) bool {
		if len(scope) == 0 {
			return false
		}
		for _, name := range scope {
			if _, drop := quarantined[name]; !drop {
				return false
			}
		}
		return true
	}
	return sideDropped(from) || sideDropped(to)
}

// StableZoneIDOwner returns the sorted-first installed zone name that owns a
// numeric zone id among names. Reserved context names are excluded because
// snapshot builders quarantine them rather than installing them. It returns
// "" when no installed name in names folds to id.
func StableZoneIDOwner(names []string, id uint16) string {
	owner := ""
	for _, name := range names {
		if _, reserved := reservedZoneNames[name]; reserved {
			continue
		}
		if StableZoneID(name) != id {
			continue
		}
		if owner == "" || name < owner {
			owner = name
		}
	}
	return owner
}

// StableZoneIDOwnerForConfig is StableZoneIDOwner over cfg's runtime name
// set, skipping poisoned zones so a poisoned collider never resolves as the
// installed owner of its ID (#13099).
func StableZoneIDOwnerForConfig(cfg *Config, id uint16) string {
	if cfg == nil {
		return ""
	}
	owner := ""
	for _, name := range ZoneQuarantineNamesForConfig(cfg) {
		if _, reserved := reservedZoneNames[name]; reserved {
			continue
		}
		if isPoisonedZoneForConfig(cfg, name) {
			continue
		}
		if StableZoneID(name) != id {
			continue
		}
		if owner == "" || name < owner {
			owner = name
		}
	}
	return owner
}

// SurvivorZoneNames builds the id→name reverse map the show/telemetry surfaces
// render from (#10530). assignZoneIDs stamps EVERY configured name into
// cr.ZoneIDs — both sides of a StableZoneID collision with the SAME id — so a
// naive `for name, id := range cr.ZoneIDs { m[id] = name }` loop resolves a
// colliding id to whichever name won a map-iteration overwrite race and can
// name live traffic after a quarantined zone the dataplane never installed.
// This helper skips every name the active config quarantines, so a colliding id
// resolves deterministically to the SAME surviving zone the dataplane actually
// installed (the sorted-first owner QuarantinedZoneNames keeps). Sessions (all
// three stacks) and events (fallback map) share this one implementation instead
// of each re-deriving the verdict.
//
// A nil cfg carries no quarantine verdict, so the helper keeps the
// deterministic sorted-first name for each id (rather than reintroducing map
// iteration nondeterminism); callers that always have a config never hit that
// arm.
// Names outside cfg's runtime zone-name set (a rename/delete the apply result
// predates, #3075) are kept: ExcludedReason only fires for names that set
// quarantines, which can include a collider that exists only in a peer node's
// view (#12247).
func SurvivorZoneNames(zoneIDs map[string]uint16, cfg *Config) map[uint16]string {
	names := make([]string, 0, len(zoneIDs))
	for name := range zoneIDs {
		names = append(names, name)
	}
	sort.Strings(names)
	m := make(map[uint16]string, len(zoneIDs))
	for _, name := range names {
		id := zoneIDs[name]
		if cfg != nil && ZoneQuarantineExcludedReason(name, cfg) != "" {
			continue
		}
		if _, exists := m[id]; exists {
			continue
		}
		m[id] = name
	}
	return m
}
