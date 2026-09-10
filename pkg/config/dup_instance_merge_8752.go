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
// a tolerant load. When one statement said deny or reject and the merged policy
// permits, the merge admits traffic that statement denied: a deny turned into a
// permit, over a wider match, with the simulator agreeing. Such a merge is still
// performed, so the configuration keeps one policy object and one warning, but
// the merged policy is poisoned with the #5575 LenientContentDropped flag and the
// helper refuses the whole snapshot. Before the fold the same text was refused
// too, by the helper's duplicate-rule-id check, so this restores that outcome for
// exactly this case. The narrowing direction (a later deny over an earlier
// permit) is left alone: it admits nothing a statement denied, and it is the
// #8752 fixture this fold was built for.
//
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
// It returns the folded names, and separately every policy the fold merged into
// a PERMIT although one of its statements said deny or reject (#9571). The
// caller poisons those after the compile (markFoldWidenedPolicies9571).
func mergeDuplicateNamedInstances(tree *ConfigTree) ([]string, []foldWidenedPolicy9571) {
	if tree == nil {
		return nil, nil
	}
	var merged []string
	var widened []foldWidenedPolicy9571
	for _, root := range tree.Children {
		if root.Name() != "security" && (len(root.Keys) == 0 || root.Keys[0] != "security") {
			continue
		}
		for _, pol := range root.FindChildren("policies") {
			// from-zone <a> to-zone <b> { policy … }
			for _, fz := range pol.FindChildren("from-zone") {
				m, w := mergeInstancesUnder(fz, "policy", askZonePair9571)
				merged = append(merged, m...)
				widened = append(widened, zonePairWidened9571(fz.Keys, nil, w)...)
				for _, tz := range fz.Children {
					m, w := mergeInstancesUnder(tz, "policy", askZonePair9571)
					merged = append(merged, m...)
					widened = append(widened, zonePairWidened9571(fz.Keys, tz.Keys, w)...)
				}
			}
			// global { policy … }
			for _, g := range pol.FindChildren("global") {
				m, w := mergeInstancesUnder(g, "policy", askGlobal9571)
				merged = append(merged, m...)
				for _, name := range w {
					widened = append(widened, foldWidenedPolicy9571{global: true, name: name})
				}
			}
		}
	}
	return merged, widened
}

// mergeInstancesUnder folds repeated `<keyword> <name>` children of `parent`
// into the first one carrying that name, and returns how many were folded.
//
// The later statement's content can live in EITHER place and both are carried:
// its Children (the braced form) and any packed tail on its own Keys (the
// brace-elided form, `policy p1 scheduler-name S;`). Carrying only Children
// would silently drop exactly the spelling this issue is about.
//
// #9571: when ask names a security-policy scope, it also returns, in first-fold
// order, every folded name whose merged statement PERMITS although at least one
// of the statements folded into it said deny or reject on its own. Both answers
// come from compilePolicy. The #9023 block sites pass askNone9571: their
// keywords are not security policies (`security ipsec policy` shares the word),
// so the question is never asked of them.
func mergeInstancesUnder(parent *Node, keyword string, ask policyActionAsk9571) (names, widened []string) {
	if parent == nil {
		return nil, nil
	}
	first := map[string]*Node{}
	restrictive := map[string]bool{}
	folded := map[string]bool{}
	var foldedNames []string
	var kept []*Node
	for _, child := range parent.Children {
		if len(child.Keys) < 2 || child.Keys[0] != keyword {
			kept = append(kept, child)
			continue
		}
		name := child.Keys[1]
		// Asked of each statement BEFORE anything is folded into it: the first
		// occurrence is still as authored when it is first seen, and a later one
		// is its own node until it is appended below.
		if ask != askNone9571 && statementRestricts9571(name, child, ask == askGlobal9571) {
			restrictive[name] = true
		}
		prev, seen := first[name]
		if !seen {
			first[name] = child
			kept = append(kept, child)
			continue
		}
		// Fold into the FIRST occurrence, which keeps its position in `kept`.
		if tail := child.Keys[2:]; len(tail) > 0 {
			prev.Children = append(prev.Children, &Node{
				Keys:   append([]string(nil), tail...),
				IsLeaf: true,
			})
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
		if ask != askNone9571 && restrictive[name] && statementPermits9571(name, first[name], ask == askGlobal9571) {
			widened = append(widened, name)
		}
	}
	return names, widened
}

// policyActionAsk9571 says whether mergeInstancesUnder is folding security
// policies, and in which scope, so it knows whether to ask the #9571 question.
type policyActionAsk9571 int

const (
	askNone9571 policyActionAsk9571 = iota
	askZonePair9571
	askGlobal9571
)

// foldWidenedPolicy9571 names a policy the tolerant fold merged into a PERMIT
// although one of its statements said deny or reject.
type foldWidenedPolicy9571 struct {
	global           bool
	anyPair          bool
	fromZone, toZone string
	name             string
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
func zonePairWidened9571(fzKeys, tzKeys, names []string) []foldWidenedPolicy9571 {
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
		w.name = n
		out = append(out, w)
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

func statementRestricts9571(name string, n *Node, isGlobal bool) bool {
	a, ok := statementAction9571(name, n, isGlobal)
	return ok && a != PolicyPermit
}

func statementPermits9571(name string, n *Node, isGlobal bool) bool {
	a, ok := statementAction9571(name, n, isGlobal)
	return ok && a == PolicyPermit
}

// markFoldWidenedPolicies9571 poisons each compiled policy the fold widened.
//
// It sets the #5575 LenientContentDropped flag, which the userspace snapshot
// builder lowers to the __unsupported__ sentinel (the helper refuses the whole
// snapshot), the content-rejection mirror reports (so `show security
// match-policies` agrees), and the #6707 commit-confirmed preflight reads. It
// runs after the compile because the flag lives on the compiled policy.
func markFoldWidenedPolicies9571(cfg *Config, widened []foldWidenedPolicy9571) {
	if cfg == nil {
		return
	}
	for _, w := range widened {
		if w.global {
			for _, p := range cfg.Security.GlobalPolicies {
				if p != nil && p.Name == w.name {
					p.LenientContentDropped = true
				}
			}
			continue
		}
		for _, zpp := range cfg.Security.Policies {
			if zpp == nil || (!w.anyPair && (zpp.FromZone != w.fromZone || zpp.ToZone != w.toZone)) {
				continue
			}
			for _, p := range zpp.Policies {
				if p != nil && p.Name == w.name {
					p.LenientContentDropped = true
				}
			}
		}
	}
}

// foldWidenedWarning9571 keeps "duplicate policy name" and "#3473" in the text:
// that is the existing contract for the fold's diagnostics.
func foldWidenedWarning9571(w foldWidenedPolicy9571) string {
	return "duplicate policy name in `" + w.String() + "` — merging the repeated statements " +
		"would turn a `then deny`/`then reject` into `then permit` over every statement's match " +
		"criteria, so the policy is refused instead: the dataplane rejects the whole policy " +
		"snapshot (previous-good retained; fresh-boot default-deny) rather than admit traffic a " +
		"statement denied. Rename one of the policies (#3473/#9571)"
}

// mergeSiblingContainers9209 folds sibling CONTAINERS that share identical Keys
// into the first of them, recursively.
//
// Issue 9209. It runs only on a node that mergeInstancesUnder has just folded a
// duplicate into, so it cannot change a config that contained no repeated block.
//
// LEAVES ARE LEFT ALONE, deliberately. Two leaves with the same key are a
// value-level question -- replace, accumulate, or reject -- already answered
// per leaf by `multi` and by the compilers, and re-answering it here would
// override those decisions from a layer that cannot see them. Only containers,
// where "the same stanza written twice" has one Junos meaning, are merged.
func mergeSiblingContainers9209(n *Node, depth int) {
	if n == nil || depth > 8 || len(n.Children) < 2 {
		return
	}
	first := map[string]*Node{}
	var kept []*Node
	changed := false
	for _, ch := range n.Children {
		if ch == nil {
			continue
		}
		if ch.IsLeaf || ch.Children == nil {
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
	for _, ch := range n.Children {
		mergeSiblingContainers9209(ch, depth+1)
	}
}
