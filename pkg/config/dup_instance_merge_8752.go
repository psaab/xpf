package config

import "strings"

// #8752: fold a repeated named-instance statement into the FIRST occurrence, on
// the TOLERANT compile path.
//
// THE DEFECT. `security policies from-zone <a> to-zone <b> { policy p1 { … }
// policy p1 <leaf> <v>; }` compiles to TWO policies named p1 on the lenient
// path: the operator's, and a spurious one carrying only the second statement.
// The spurious one has no match criteria, so it contributes a match-less deny,
// and the operator's policy never receives the leaf. Measured on the path that
// production uses for `Store.Load` and `Store.SyncApply` — boot-time config load
// and HA config sync.
//
// WHY THIS PATH AND NOT THE STRICT ONE. The #3473 gate hard-rejects a duplicate
// policy name at commit, and it should keep doing so: its message tells the
// operator to rename, because a duplicate shares a name-keyed hit counter. That
// diagnostic is worth keeping, and merging before it would silently destroy it.
// The tolerant path cannot reject — it exists to boot a config that is already
// on disk (#1960 no-brick) — so its only choices are to split (today) or to
// merge.
//
// AND THE TOLERANT PATH'S OWN CLAIM IS WHAT MAKES MERGING THE RIGHT ONE. The
// #3473 gate documents its lenient behaviour as "first-match enforcement is
// still correct, only the shared-counter observability bug remains". Measured,
// that is FALSE today: the operator's policy loses the second statement's
// content and gains a match-less-deny sibling, which is a change to what is
// permitted, not an observability gap. Merging makes the comment true.
//
// #9571: NOT FOR EVERY MERGE. A merge takes the LAST terminal action and the
// UNION of the statements' match criteria, because compilePolicy is last-wins on
// a tolerant load. When one statement has restrictive effective semantics —
// an explicit deny or reject, or an actionless statement defaulted to deny
// (#3043) — and the merged policy permits, the merge admits traffic that
// statement restricted: a deny turned into a permit, over a wider match, with
// the simulator agreeing. Such a merge is still performed, so the configuration
// keeps one policy object and one warning, but the merged policy is poisoned
// with the #5575 LenientContentDropped flag and the helper refuses the whole
// snapshot. Before the fold the same text was refused too, by the helper's
// duplicate-rule-id check, so this restores that outcome for exactly this case.
// The narrowing direction (a later deny over an earlier permit) is left alone:
// it admits nothing a statement denied, and it is the #8752 fixture this fold was
// built for.
//
// #14968 (D30-02): THE SAME QUESTION, ASKED OF THE MATCH AND THE SCHEDULE.
// #9571 compared the statements' ACTIONS against the merged action, but the
// fold also overwrites WHAT the merged action applies to. Three ways, all
// measured on the tolerant path:
//   - CROSS-PRODUCT PERMIT WIDENING. Two PERMIT statements that differ in two
//     or more match dimensions fold into source-union × destination-union ×
//     application-union (compilePolicy accumulates every match block), so the
//     merged permit covers source/destination/application combinations no
//     statement permitted (#9571 passes over this: no statement restricts).
//   - EXCLUDED-SET DENY DISARMING. An excluded-address flag/list authored on
//     one statement is OR-ed/unioned onto the merged policy (compilePolicy
//     sets the flag if any statement sets it and unions the lists), so a DENY
//     that survives the fold matches the COMPLEMENT of that union and no
//     longer covers traffic its own statement denied.
//   - SCHEDULER NARROWING. A `scheduler-name` authored on one statement is
//     inherited by the merged policy (last-wins), so an unconditional DENY
//     that survives the fold is only active inside another statement's window.
// Each still folds into one policy object, but is poisoned exactly like a
// #9571 widening (LenientContentDropped; the helper refuses the snapshot).
// Folds whose merged semantics ARE the union of the statements — a permit
// pair whose domains are equal in all but at most one dimension or where
// one statement dominates the other in every dimension (#16419), a deny
// pair with identical excluded sets, a pair sharing one scheduler — stay
// unpoisoned (#8752).
//
// #16418 (R3-F03-03): THE ZONE SCOPE OF A GLOBAL POLICY IS THE SAME KIND OF
// DIMENSION. `match from-zone`/`to-zone` (PolicyMatch.FromZones/ToZones) are
// match predicates where empty or `any` means all zones, so two PERMITs
// differing in from-zone AND in source fold into from-zone-union ×
// source-union and permit (zone, source) pairs no statement permitted; and a
// scoped DENY folded with an unscoped DENY keeps only the scoped zone set
// (the union fold drops the empty/universal scope), so the surviving deny
// no longer covers traffic the unscoped statement denied. Both now poison
// exactly like the #14968 legs. Zone-pair policies compile no zone scope, so
// this changes nothing for them.
//
// #16419 (R3-F03-04): THE PER-DIMENSION CONTAINMENT EXEMPTION IS UNSOUND.
// #14968 counted a dimension only when NEITHER statement's set contained
// the other's, claiming a contained dimension "cannot contribute a new
// combination". Per dimension that is true; for the tuple it is false:
// `ssh from 10.0.1.0/25` plus `http from any` trades a narrow source for
// a narrow application, so the fold permits ssh from any — a tuple no
// statement permitted — while counting zero differing dimensions. The
// permit leg now compares whole match domains (source/destination/
// application value+sense, zone scope, scheduler): a pair is an exact
// union only when the domains are equal in all but at most one dimension
// or one domain contains the other. A scheduler mismatch or an
// excluded-sense mismatch between permit statements poisons for the same
// reason (the merged permit then applies outside a statement's window or
// inside its carve-out).

// WHY MERGE RATHER THAN REPLACE, and it is not a preference. Flat `set` already
// MERGES — pinned by TestFlatSetMergesWhereHierarchicalDuplicates — so the two
// spellings of one configuration disagree, and hierarchical is the deviant one.
// Replacing would mean choosing to keep them disagreeing and then owning a rule
// about which spelling a user must write to mean what they meant.
//
// WHY IN PLACE. The compiled collections that duplicate are SLICES
// (`Policies []*Policy`) and the ones that merge are MAPS. They are slices
// because ORDER IS SEMANTIC — policy evaluation is first-match — so folding into
// anything but the first occurrence's position would trade a visible duplicate
// for an invisible reordering. A duplicate shows up as two objects; a reordered
// first-match rulebase evaluates differently with nothing to see.
//
// SCOPE IS A PAIR LIST, not a shape. Only the two containers measured on BOTH
// paths are folded. `security nat source rule-set <r>` duplicates too, but its
// lenient/strict pair has not been measured, and admitting a container on the
// strength of "it has the same shape" is the family-level reasoning #8690 spent
// a day removing.
//
// Direct conflicts are collected from each policy instance before folding.
// The lenient entry points scan the original tree for inline conflicts and, if
// groups apply, an expanded pre-fold clone for inherited conflicts.
// It returns folded names, effective policy instances whose individual
// terminal actions conflict, and policies a fold widened into PERMIT. The
// latter are poisoned after compilation by markFoldWidenedPolicies9571.
func mergeDuplicateNamedInstances(tree *ConfigTree) ([]string, []foldWidenedPolicy9571, []directTerminalActionConflict11063) {
	if tree == nil {
		return nil, nil, nil
	}
	var merged []string
	var widened []foldWidenedPolicy9571
	var conflicting []directTerminalActionConflict11063
	for _, root := range tree.Children {
		if root.Name() != "security" && (len(root.Keys) == 0 || root.Keys[0] != "security") {
			continue
		}
		for _, pol := range root.FindChildren("policies") {
			// from-zone <a> to-zone <b> { policy … }
			for _, fz := range pol.FindChildren("from-zone") {
				if len(fz.Keys) >= 4 && fz.Keys[2] == "to-zone" {
					merged, widened, conflicting = foldPolicyInstances12820(
						fz, fz.Keys, nil, askZonePair9571, merged, widened, conflicting)
					continue
				}
				merged, widened, conflicting = foldPolicyInstances12820(
					fz, fz.Keys, nil, askZonePair9571, merged, widened, conflicting)
				for _, child := range fz.Children {
					if child.Name() != "to-zone" && len(fz.Keys) == 1 {
						// Supported container form:
						// from-zone { A { to-zone { B { policy ... } } } }
						for _, tz := range child.FindChildren("to-zone") {
							if len(tz.Keys) >= 2 {
								merged, widened, conflicting = foldPolicyInstances12820(
									tz, []string{"from-zone", child.Name()}, tz.Keys,
									askZonePair9571, merged, widened, conflicting)
								continue
							}
							for _, destination := range tz.Children {
								merged, widened, conflicting = foldPolicyInstances12820(
									destination, []string{"from-zone", child.Name()},
									[]string{"to-zone", destination.Name()},
									askZonePair9571, merged, widened, conflicting)
							}
						}
					}
				}
				for _, tz := range fz.Children {
					merged, widened, conflicting = foldPolicyInstances12820(
						tz, fz.Keys, tz.Keys, askZonePair9571,
						merged, widened, conflicting)
				}
			}
			// global { policy … }
			for _, g := range pol.FindChildren("global") {
				merged, widened, conflicting = foldPolicyInstancesWith12820(g, askGlobal9571, merged,
					func(names []foldWidenedName14968) []foldWidenedPolicy9571 {
						out := make([]foldWidenedPolicy9571, 0, len(names))
						for _, n := range names {
							out = append(out, foldWidenedPolicy9571{global: true, name: n.name, semantic: n.semantic})
						}
						return out
					},
					func(names []string) []directTerminalActionConflict11063 {
						out := make([]directTerminalActionConflict11063, 0, len(names))
						for _, name := range names {
							out = append(out, directTerminalActionConflict11063{global: true, name: name})
						}
						return out
					}, widened, conflicting)
			}
		}
	}
	return merged, widened, conflicting
}

func foldPolicyInstances12820(parent *Node, fromKeys, toKeys []string,
	ask policyActionAsk9571, merged []string, widened []foldWidenedPolicy9571,
	conflicting []directTerminalActionConflict11063) ([]string, []foldWidenedPolicy9571, []directTerminalActionConflict11063) {
	return foldPolicyInstancesWith12820(parent, ask, merged,
		func(w []foldWidenedName14968) []foldWidenedPolicy9571 {
			return zonePairWidened9571(fromKeys, toKeys, w)
		},
		func(c []string) []directTerminalActionConflict11063 {
			return zonePairDirectConflicts11063(fromKeys, toKeys, c)
		}, widened, conflicting)
}

// foldPolicyInstancesWith12820 folds a container's policy instances plus any
// peeled `policy { name { ... } }` wrappers into one scratch, so duplicates
// across wrappers fold together.
func foldPolicyInstancesWith12820(parent *Node, ask policyActionAsk9571, merged []string,
	wrapW func([]foldWidenedName14968) []foldWidenedPolicy9571,
	wrapC func([]string) []directTerminalActionConflict11063,
	widened []foldWidenedPolicy9571,
	conflicting []directTerminalActionConflict11063) ([]string, []foldWidenedPolicy9571, []directTerminalActionConflict11063) {
	fold := func(container *Node) {
		m, w, c := mergeInstancesUnder(container, "policy", ask)
		merged = append(merged, m...)
		widened = append(widened, wrapW(w)...)
		conflicting = append(conflicting, wrapC(c)...)
	}
	fold(parent)
	if parent != nil {
		var wrappers []*Node
		var peeled []*Node
		for _, child := range parent.FindChildren("policy") {
			if len(child.Keys) == 1 {
				wrappers = append(wrappers, child)
				peeled = append(peeled, child.Children...)
			}
		}
		if len(peeled) > 0 {
			scratch := &Node{Keys: []string{"policy"}, Children: peeled}
			m, w, c := mergeInstancesUnder(scratch, "policy", ask)
			merged = append(merged, m...)
			widened = append(widened, wrapW(w)...)
			conflicting = append(conflicting, wrapC(c)...)
			kept := make(map[*Node]struct{}, len(scratch.Children))
			for _, child := range scratch.Children {
				kept[child] = struct{}{}
			}
			for _, wrapper := range wrappers {
				children := wrapper.Children[:0]
				for _, child := range wrapper.Children {
					if _, ok := kept[child]; ok {
						children = append(children, child)
					}
				}
				wrapper.Children = children
			}
		}
	}
	return merged, widened, conflicting
}

// treeHasGroupApplications11063 avoids cloning and expanding configs whose
// policy provenance cannot change through apply-groups.
func treeHasGroupApplications11063(tree *ConfigTree) bool {
	if tree == nil || tree.FindChild("groups") == nil {
		return false
	}
	return nodesHaveGroupApplications11063(tree.Children)
}

func nodesHaveGroupApplications11063(nodes []*Node) bool {
	for _, node := range nodes {
		if node == nil {
			continue
		}
		if len(node.Keys) > 0 && node.Keys[0] == "apply-groups" {
			return true
		}
		if nodesHaveGroupApplications11063(node.Children) {
			return true
		}
	}
	return false
}

// collectDirectTerminalActionConflictsFromExpandedTree scans each effective
// source policy before duplicate-name folding, keeping safe mixed-action
// fragments separate while recognizing conflicts introduced by inherited
// group content.
func collectDirectTerminalActionConflictsFromExpandedTree(tree *ConfigTree) []directTerminalActionConflict11063 {
	if tree == nil {
		return nil
	}
	var conflicting []directTerminalActionConflict11063
	for _, root := range tree.Children {
		if root.Name() != "security" && (len(root.Keys) == 0 || root.Keys[0] != "security") {
			continue
		}
		for _, policies := range root.FindChildren("policies") {
			for _, fromZone := range policies.FindChildren("from-zone") {
				conflicting = append(conflicting,
					zonePairDirectConflicts11063(fromZone.Keys, nil,
						directPolicyConflictNames11063(fromZone, false))...)
				if len(fromZone.Keys) >= 4 && fromZone.Keys[2] == "to-zone" {
					continue
				}
				for _, child := range fromZone.Children {
					conflicting = append(conflicting,
						zonePairDirectConflicts11063(fromZone.Keys, child.Keys,
							directPolicyConflictNames11063(child, false))...)
					for _, toZone := range child.FindChildren("to-zone") {
						if len(toZone.Keys) >= 2 {
							conflicting = append(conflicting,
								zonePairDirectConflicts11063(
									[]string{"from-zone", child.Name()}, toZone.Keys,
									directPolicyConflictNames11063(toZone, false))...)
							continue
						}
						for _, destination := range toZone.Children {
							conflicting = append(conflicting,
								zonePairDirectConflicts11063(
									[]string{"from-zone", child.Name()},
									[]string{"to-zone", destination.Name()},
									directPolicyConflictNames11063(destination, false))...)
						}
					}
				}
			}
			for _, global := range policies.FindChildren("global") {
				for _, name := range directPolicyConflictNames11063(global, true) {
					conflicting = append(conflicting,
						directTerminalActionConflict11063{global: true, name: name})
				}
			}
		}
	}
	return conflicting
}

func directPolicyConflictNames11063(parent *Node, isGlobal bool) []string {
	if parent == nil {
		return nil
	}
	var conflicting []string
	for _, child := range parent.Children {
		if len(child.Keys) == 0 || child.Keys[0] != "policy" {
			continue
		}
		for _, instance := range namedInstances([]*Node{child}) {
			policy := compilePolicy(instance, isGlobal)
			if conflictingPolicyTerminalActions(policy.terminalActions) {
				conflicting = append(conflicting, instance.name)
			}
		}
	}
	return conflicting
}

func mergeDirectConflicts11063(a, b []directTerminalActionConflict11063) []directTerminalActionConflict11063 {
	if len(a) == 0 {
		return b
	}
	if len(b) == 0 {
		return a
	}
	seen := make(map[directTerminalActionConflict11063]struct{}, len(a)+len(b))
	out := make([]directTerminalActionConflict11063, 0, len(a)+len(b))
	for _, conflict := range a {
		if _, ok := seen[conflict]; !ok {
			seen[conflict] = struct{}{}
			out = append(out, conflict)
		}
	}
	for _, conflict := range b {
		if _, ok := seen[conflict]; !ok {
			seen[conflict] = struct{}{}
			out = append(out, conflict)
		}
	}
	return out
}

// mergeInstancesUnder folds repeated `<keyword> <name>` children of `parent`
// into the first one carrying that name, and returns how many were folded.
//
// The later statement's content can live in EITHER place and both are carried:
// its Children (the braced form) and any packed tail on its own Keys (the
// brace-elided form, `policy p1 scheduler-name S;`). Carrying only Children
// would silently drop exactly the spelling this issue is about.
//
// For security policies, direct terminal-action conflicts are recorded from
// each effective policy instance before folding. Conflicts created only by
// combining otherwise valid instances are handled by the widening classifier.
// The #9023 block sites pass askNone9571, so they do not inspect policy actions.
func mergeInstancesUnder(parent *Node, keyword string, ask policyActionAsk9571) (names []string, widened []foldWidenedName14968, conflicting []string) {
	if parent == nil {
		return nil, nil, nil
	}
	first := map[string]*Node{}
	restrictive := map[string]bool{}
	folded := map[string]bool{}
	// #14968: every source statement's compiled policy, in fold order, so the
	// post-fold classifier can compare the merged match/scheduler against the
	// statements rather than against only the final action (#9571).
	sources := map[string][]*Policy{}
	var foldedNames []string
	var kept []*Node
	for _, child := range parent.Children {
		peeledPolicy := keyword == "policy" && parent.Name() == "policy" &&
			len(child.Keys) == 1 && child.Keys[0] != "policy"
		if (len(child.Keys) < 2 || child.Keys[0] != keyword) && !peeledPolicy {
			kept = append(kept, child)
			continue
		}
		name := child.Keys[0]
		if !peeledPolicy {
			name = child.Keys[1]
		}
		// Asked of each statement BEFORE anything is folded into it: the first
		// occurrence is still as authored when it is first seen, and a later one
		// is its own node until it is appended below.
		if ask != askNone9571 {
			isGlobal := ask == askGlobal9571
			sourcePolicy := compilePolicy(struct {
				name string
				node *Node
			}{name, child}, isGlobal)
			sources[name] = append(sources[name], sourcePolicy)
			if policyRestricts9571(sourcePolicy) {
				restrictive[name] = true
			}
			if conflictingPolicyTerminalActions(sourcePolicy.terminalActions) {
				conflicting = append(conflicting, name)
			}
		}
		prev, seen := first[name]
		if !seen {
			first[name] = child
			kept = append(kept, child)
			continue
		}
		// Fold into the FIRST occurrence, which keeps its position in `kept`.
		if !peeledPolicy {
			if tail := child.Keys[2:]; len(tail) > 0 {
				prev.Children = append(prev.Children, &Node{
					Keys:   append([]string(nil), tail...),
					IsLeaf: true,
				})
			}
		}
		prev.Children = append(prev.Children, child.Children...)
		prev.IsLeaf = false
		// Issue 9209: FOLD THE UNNAMED CONTAINERS TOO. Appending the second
		// block's children leaves the merged node carrying two `if-exceeding`
		// blocks, and the compiler reads the first -- so
		//
		//	policer p1 { if-exceeding { bandwidth-limit 1000000; } }
		//	policer p1 { if-exceeding { burst-size-limit 15000; } }
		//
		// folded to bw=125000 burst=0, recovering the bandwidth-limit that was
		// lost before and losing the burst-size-limit instead. Within ONE named
		// block two identical container heads are the same stanza, so they are
		// merged as well. Scoped to the folded node: this runs only where a
		// duplicate was actually collapsed, never across a config that had no
		// repeats.
		mergeSiblingContainers9209(prev, 0)
		names = append(names, keyword+" "+name)
		if !folded[name] {
			folded[name] = true
			foldedNames = append(foldedNames, name)
		}
	}
	if len(names) > 0 {
		parent.Children = kept
	}
	for _, name := range foldedNames {
		if ask == askNone9571 {
			continue
		}
		isGlobal := ask == askGlobal9571
		merged := compilePolicy(struct {
			name string
			node *Node
		}{name, first[name]}, isGlobal)
		if restrictive[name] && len(merged.terminalActions) > 0 && merged.Action == PolicyPermit {
			widened = append(widened, foldWidenedName14968{name: name})
			continue
		}
		if foldChangesPolicySemantics14968(sources[name], merged) {
			widened = append(widened, foldWidenedName14968{name: name, semantic: true})
		}
	}
	return names, widened, conflicting
}

// foldWidenedName14968 is a folded policy name plus whether the refusal is
// the #14968 semantic (match/scheduler) leg rather than the #9571 action leg.
type foldWidenedName14968 struct {
	name     string
	semantic bool
}

// policyActionAsk9571 says whether mergeInstancesUnder is folding security
// policies, and in which scope, so it knows whether to ask the #9571 question.
type policyActionAsk9571 int

const (
	askNone9571 policyActionAsk9571 = iota
	askZonePair9571
	askGlobal9571
)

// directTerminalActionConflict11063 identifies a source policy whose own
// terminal actions conflict before any duplicate-name fold occurs.
type directTerminalActionConflict11063 struct {
	global           bool
	anyPair          bool
	fromZone, toZone string
	name             string
}

// foldWidenedPolicy9571 names a policy the tolerant fold merged into a PERMIT
// although one of its statements had restrictive effective semantics
// (#9571), or whose merged match/scheduler semantics are not the union of
// its statements (#14968, semantic=true).
type foldWidenedPolicy9571 struct {
	global           bool
	anyPair          bool
	fromZone, toZone string
	name             string
	semantic         bool
}

func (w foldWidenedPolicy9571) String() string {
	switch {
	case w.global:
		return "global policy " + w.name
	case w.anyPair:
		return "policy " + w.name
	}
	return "from-zone " + w.fromZone + " to-zone " + w.toZone + " policy " + w.name
}

// zonePairWidened9571 attaches a zone pair to each widened policy name.
//
// The compiler reads a folded zone-pair stanza's zones from the compound
// `from-zone <a> to-zone <b>` keys (compileSecurity's Keys>=4 arm), so that shape
// is named exactly. Any other shape is recorded as matching EVERY zone pair.
// That errs toward refusal on purpose: marking a same-named policy in another
// pair refuses a snapshot the helper would accept, while missing the widened one
// enforces the permit this exists to stop.
func zonePairWidened9571(fzKeys, tzKeys []string, names []foldWidenedName14968) []foldWidenedPolicy9571 {
	if len(names) == 0 {
		return nil
	}
	pair := foldWidenedPolicy9571{anyPair: true}
	switch {
	case tzKeys == nil && len(fzKeys) >= 4 && fzKeys[2] == "to-zone":
		pair = foldWidenedPolicy9571{fromZone: fzKeys[1], toZone: fzKeys[3]}
	case tzKeys != nil && len(fzKeys) == 2 && len(tzKeys) == 2 && tzKeys[0] == "to-zone":
		pair = foldWidenedPolicy9571{fromZone: fzKeys[1], toZone: tzKeys[1]}
	}
	out := make([]foldWidenedPolicy9571, 0, len(names))
	for _, n := range names {
		w := pair
		w.name = n.name
		w.semantic = n.semantic
		out = append(out, w)
	}
	return out
}

// zonePairDirectConflicts11063 attaches the source zone pair to each direct
// terminal-action conflict. Unknown shapes conservatively match every pair.
func zonePairDirectConflicts11063(fzKeys, tzKeys, names []string) []directTerminalActionConflict11063 {
	if len(names) == 0 {
		return nil
	}
	pair := directTerminalActionConflict11063{anyPair: true}
	switch {
	case tzKeys == nil && len(fzKeys) >= 4 && fzKeys[2] == "to-zone":
		pair = directTerminalActionConflict11063{fromZone: fzKeys[1], toZone: fzKeys[3]}
	case tzKeys != nil && len(fzKeys) == 2 && len(tzKeys) == 2 && tzKeys[0] == "to-zone":
		pair = directTerminalActionConflict11063{fromZone: fzKeys[1], toZone: tzKeys[1]}
	}
	out := make([]directTerminalActionConflict11063, 0, len(names))
	for _, name := range names {
		conflict := pair
		conflict.name = name
		out = append(out, conflict)
	}
	return out
}

// statementAction9571 compiles one policy statement the way the merged result
// will be compiled, and reports its terminal action and whether it names one.
// It CALLS compilePolicy rather than re-reading `then` children, so it cannot
// disagree with the compiler about a collapsed `then deny log`, repeated `then`
// blocks, or the actionless default (compilePolicy defaults an actionless policy
// to deny, which is why "names one" is reported separately).
func statementAction9571(name string, n *Node, isGlobal bool) (PolicyAction, bool) {
	p := compilePolicy(struct {
		name string
		node *Node
	}{name, n}, isGlobal)
	return p.Action, len(p.terminalActions) > 0
}

func policyRestricts9571(policy *Policy) bool {
	if len(policy.terminalActions) == 0 {
		// #9992: compilePolicy's effective action is DENY for an actionless
		// statement (#3043), so empty terminalActions still restrict.
		return policy.Action == PolicyDeny
	}
	return policy.Action != PolicyPermit
}

func statementPermits9571(name string, n *Node, isGlobal bool) bool {
	a, ok := statementAction9571(name, n, isGlobal)
	return ok && a == PolicyPermit
}

// foldChangesPolicySemantics14968 reports whether folding the source
// statements into merged yields a policy whose gating is not the union of
// the statements (#14968): the merged action applies in combinations, to
// complements, or in time windows no statement authored for that action.
// Action-only widening (restrictive to permit) is the #9571 leg and is
// decided by the caller; this covers the folds that survive that check:
//   - a merged PERMIT that is not the exact union of its explicit-permit
//     sources (#16419: domains equal in all but at most one dimension, or
//     one domain containing the other — see permitPairIsUnion16419);
//   - a surviving DENY/REJECT whose excluded-address flags/lists or whose
//     scheduler set differ from a restrictive source's (the deny no longer
//     covers exactly what that statement denied, or only inside a window
//     that statement never named).
//
// #16418 (R3-F03-03): the zone scope of a GLOBAL policy is two more match
// dimensions of the same kind. FromZones/ToZones are match predicates
// (empty or `any` = all zones), so a permit pair differing in from-zone
// AND in source folds into from-zone-union x source-union and permits
// (zone, source) pairs no statement permitted; and a restrictive
// statement whose zone scope is not a subset of the merged scope (which
// the union fold can only narrow when one statement is unscoped and
// another is scoped) leaves the surviving deny covering less than that
// statement denied. Zone-pair policies have no compiled zone scope (their
// zones come from the stanza), so counting these dimensions is a no-op
// for them.
//
// #16419 (R3-F03-04): counting only dimensions where NEITHER set contains
// the other is unsound — containment in one dimension does not stop that
// dimension's wider values combining with another dimension's values from
// the narrower statement. The permit leg therefore tests the whole
// domain, including the scheduler gate and the excluded-address sense.
func foldChangesPolicySemantics14968(sources []*Policy, merged *Policy) bool {
	if len(sources) < 2 || merged == nil {
		return false
	}
	if merged.Action == PolicyPermit {
		var permits []*Policy
		for _, s := range sources {
			if s != nil && len(s.terminalActions) > 0 && s.Action == PolicyPermit {
				permits = append(permits, s)
			}
		}
		for i := range permits {
			for _, other := range permits[i+1:] {
				if !permitPairIsUnion16419(permits[i], other) {
					return true
				}
			}
		}
	}
	if merged.Action != PolicyDeny && merged.Action != PolicyReject {
		return false
	}
	for _, s := range sources {
		if s == nil {
			continue
		}
		// A restrictive source statement (explicit or defaulted deny/reject).
		if len(s.terminalActions) == 0 {
			if s.Action != PolicyDeny {
				continue
			}
		} else if s.Action == PolicyPermit {
			continue
		}
		if s.Match.SourceAddressExcluded != merged.Match.SourceAddressExcluded ||
			s.Match.DestinationAddressExcluded != merged.Match.DestinationAddressExcluded {
			return true
		}
		if s.Match.SourceAddressExcluded &&
			!sameStringSet14968(s.Match.SourceAddresses, merged.Match.SourceAddresses) {
			return true
		}
		if s.Match.DestinationAddressExcluded &&
			!sameStringSet14968(s.Match.DestinationAddresses, merged.Match.DestinationAddresses) {
			return true
		}
		if !zoneScopeSubset16418(s.Match.FromZones, merged.Match.FromZones) ||
			!zoneScopeSubset16418(s.Match.ToZones, merged.Match.ToZones) {
			return true
		}
		if len(s.schedulerNames) == 0 && len(merged.schedulerNames) > 0 {
			return true
		}
		if len(s.schedulerNames) > 0 && !sameStringSet14968(s.schedulerNames, merged.schedulerNames) {
			return true
		}
	}
	return false
}

// permitDomain16419 is one explicit-permit statement's whole match
// domain: the dimensions whose dimension-wise union the fold computes.
// excluded marks an inverted address sense; its domain is the complement
// of values, so token containment does not apply and only identical
// excluded domains can union exactly. A gated domain is active only in
// its scheduler window.
type permitDomain16419 struct {
	src, dst, app   []string
	srcEx, dstEx    bool
	fromZones       []string
	toZones         []string
	scheduler       string
	gated, excluded bool
}

func permitDomainOf16419(p *Policy) permitDomain16419 {
	d := permitDomain16419{
		src: p.Match.SourceAddresses, dst: p.Match.DestinationAddresses,
		app:   p.Match.Applications,
		srcEx: p.Match.SourceAddressExcluded, dstEx: p.Match.DestinationAddressExcluded,
		fromZones: p.Match.FromZones, toZones: p.Match.ToZones,
		scheduler: p.SchedulerName,
	}
	d.gated = d.scheduler != ""
	d.excluded = d.srcEx || d.dstEx
	return d
}

// permitPairIsUnion16419 reports whether the dimension-wise union of two
// permit domains is exactly the union of the domains (#16419). The
// pre-#16419 predicate counted only dimensions where neither set
// contained the other and allowed up to one, which is unsound: a
// contained dimension mints new tuples whenever any other dimension is
// non-equal (ssh from 10.0.1.0/25 + http from any counted 1, yet the
// fold permits ssh from any). The sound test is: the domains are equal
// in all but at most one dimension (nonEqual <= 1, the #14968
// legitimate case), or one domain contains the other in every
// dimension (dominance, tracked as aInB/bInA).
func permitPairIsUnion16419(a, b *Policy) bool {
	da, db := permitDomainOf16419(a), permitDomainOf16419(b)
	if da.gated != db.gated || da.scheduler != db.scheduler {
		return false
	}
	if da.excluded || db.excluded {
		return permitDomainsEqual16419(da, db)
	}
	nonEqual, aInB, bInA := 0, true, true
	tally := func(aSubB, bSubA bool) {
		if !aSubB || !bSubA {
			nonEqual++
		}
		aInB = aInB && aSubB
		bInA = bInA && bSubA
	}
	tally(valueSetSubset14968(da.src, db.src), valueSetSubset14968(db.src, da.src))
	tally(valueSetSubset14968(da.dst, db.dst), valueSetSubset14968(db.dst, da.dst))
	tally(valueSetSubset14968(da.app, db.app), valueSetSubset14968(db.app, da.app))
	tally(zoneScopeSubset16418(da.fromZones, db.fromZones), zoneScopeSubset16418(db.fromZones, da.fromZones))
	tally(zoneScopeSubset16418(da.toZones, db.toZones), zoneScopeSubset16418(db.toZones, da.toZones))
	return nonEqual <= 1 || aInB || bInA
}

func permitDomainsEqual16419(a, b permitDomain16419) bool {
	return a.srcEx == b.srcEx && a.dstEx == b.dstEx &&
		sameStringSet14968(a.src, b.src) && sameStringSet14968(a.dst, b.dst) &&
		sameStringSet14968(a.app, b.app) &&
		zoneScopesEqual16419(a.fromZones, b.fromZones) &&
		zoneScopesEqual16419(a.toZones, b.toZones)
}

// zoneScopesEqual16419 compares zone scopes as sets, with the wildcard
// spellings (empty, or containing `any`) all denoting the universal scope.
func zoneScopesEqual16419(a, b []string) bool {
	if IsWildcardZoneSet(a) || IsWildcardZoneSet(b) {
		return IsWildcardZoneSet(a) && IsWildcardZoneSet(b)
	}
	return sameStringSet14968(a, b)
}

// zoneScopeSubset16418 reports whether zone scope a is a subset of zone
// scope b, treating an empty slice or a set containing `any` as the
// universal scope (IsWildcardZoneSet). Unlike address/application value
// sets, an empty zone scope is universal, not empty, so
// valueSetSubset14968 (where the empty set is a subset of everything)
// would invert the scoped/unscoped comparison: a scoped set must NOT be
// reported as containing the unscoped one, or the cross-zone permit
// widening and the scoped+unscoped deny narrowing both fold unpoisoned.
func zoneScopeSubset16418(a, b []string) bool {
	if IsWildcardZoneSet(b) {
		return true
	}
	if IsWildcardZoneSet(a) {
		return false
	}
	bSet := make(map[string]struct{}, len(b))
	for _, v := range b {
		bSet[v] = struct{}{}
	}
	for _, v := range a {
		if _, ok := bSet[v]; !ok {
			return false
		}
	}
	return true
}

// valueSetSubset14968 reports whether every value in a is in b, treating
// `any` as the universal set (it covers every value, as the evaluator does).
func valueSetSubset14968(a, b []string) bool {
	bSet := make(map[string]struct{}, len(b))
	for _, v := range b {
		if v == "any" {
			return true
		}
		bSet[v] = struct{}{}
	}
	for _, v := range a {
		if v == "any" {
			return false
		}
		if _, ok := bSet[v]; !ok {
			return false
		}
	}
	return true
}

func sameStringSet14968(a, b []string) bool {
	set := make(map[string]struct{}, len(a))
	for _, v := range a {
		set[v] = struct{}{}
	}
	other := make(map[string]struct{}, len(b))
	for _, v := range b {
		other[v] = struct{}{}
	}
	if len(set) != len(other) {
		return false
	}
	for k := range set {
		if _, ok := other[k]; !ok {
			return false
		}
	}
	return true
}

// markFoldWidenedPolicies9571 poisons each compiled policy the fold widened.
//
// It sets the #5575 LenientContentDropped flag, which the userspace snapshot
// builder lowers to the __unsupported__ sentinel (the helper refuses the whole
// snapshot), the content-rejection mirror reports (so `show security
// match-policies` agrees), and the #6707 commit-confirmed preflight reads. It
// runs after the compile because the flag lives on the compiled policy.
func markFoldWidenedPolicies9571(cfg *Config, widened []foldWidenedPolicy9571) {
	for _, w := range widened {
		markPolicyLenientContentDropped11063(cfg, w.global, w.anyPair, w.fromZone, w.toZone, w.name)
	}
}

// foldSemanticWarning14968 is the #14968 sibling of foldWidenedWarning9571:
// the fold kept one policy object, but its match/scheduler semantics are
// not the union of the statements, so it is refused rather than enforced.
func foldSemanticWarning14968(w foldWidenedPolicy9571) string {
	return "duplicate policy name in `" + w.String() + "` — merging the repeated statements " +
		"would change what the merged policy's action applies to (a cross-product of the " +
		"statements' match dimensions — including a global policy's from-zone/to-zone scope — " +
		"an excluded-address set another statement authored, " +
		"or a scheduler-name another statement authored), so the policy is refused instead: " +
		"the dataplane rejects the whole policy snapshot (previous-good retained; fresh-boot " +
		"default-deny) rather than enforce gating no statement authored. Rename one of the " +
		"policies (#3473/#14968)"
}

func markDirectTerminalActionConflicts11063(cfg *Config, conflicts []directTerminalActionConflict11063) {
	for _, conflict := range conflicts {
		markPolicyLenientContentDropped11063(cfg, conflict.global, conflict.anyPair,
			conflict.fromZone, conflict.toZone, conflict.name)
	}
}

func markPolicyLenientContentDropped11063(cfg *Config, global, anyPair bool, fromZone, toZone, name string) {
	if cfg == nil {
		return
	}
	if global {
		for _, p := range cfg.Security.GlobalPolicies {
			if p != nil && p.Name == name {
				p.LenientContentDropped = true
			}
		}
		return
	}
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil || (!anyPair && (zpp.FromZone != fromZone || zpp.ToZone != toZone)) {
			continue
		}
		for _, p := range zpp.Policies {
			if p != nil && p.Name == name {
				p.LenientContentDropped = true
			}
		}
	}
}

// foldWidenedWarning9571 keeps "duplicate policy name" and "#3473" in the text:
// that is the existing contract for the fold's diagnostics.
func foldWidenedWarning9571(w foldWidenedPolicy9571) string {
	return "duplicate policy name in `" + w.String() + "` — merging the repeated statements " +
		"would turn an effective restrictive statement (explicit `then deny`/`then reject` " +
		"or an actionless statement defaulted to deny) into `then permit` over every " +
		"statement's match criteria, so the policy is refused instead: the dataplane " +
		"rejects the whole policy snapshot (previous-good retained; fresh-boot default-deny) " +
		"rather than admit traffic a restrictive statement blocked. Rename one of the policies " +
		"(#3473/#9571)"
}

// mergeSiblingContainers9209 folds sibling containers with identical keys,
// except at an explicitly registered unnamed-routing site. Those site-owned
// duplicates are left for mergeDuplicateBlocks9023 so the fold is independent
// of surrounding stanzas and produces its own scoped diagnostic.
func mergeSiblingContainers9209(n *Node, depth int) {
	mergeSiblingContainers9209WithParentAndPath(n, depth, "", nil)
}

func mergeSiblingContainers9209WithParentAndPath(n *Node, depth int, parent string, path []string) {
	if n == nil || depth > 8 || len(n.Children) < 2 {
		return
	}
	if parent == "" {
		parent = n.Name()
	}
	first := map[string]*Node{}
	var kept []*Node
	changed := false
	for _, ch := range n.Children {
		if ch == nil {
			continue
		}
		if ch.IsLeaf || ch.Children == nil || isRegisteredUnnamedRoutingMergeSite9023(parent, ch.Name(), path) {
			kept = append(kept, ch)
			continue
		}
		key := strings.Join(ch.Keys, "\x00")
		prev, seen := first[key]
		if !seen {
			first[key] = ch
			kept = append(kept, ch)
			continue
		}
		prev.Children = append(prev.Children, ch.Children...)
		changed = true
	}
	if changed {
		n.Children = kept
	}
	childPath := appendDuplicateMergeNodePath9023(path, n)
	for _, ch := range n.Children {
		if ch != nil && !isRegisteredUnnamedRoutingMergeSite9023(parent, ch.Name(), path) {
			mergeSiblingContainers9209WithParentAndPath(ch, depth+1, "", childPath)
		}
	}
}
