package config

// compiler_nat_then_occurrences_7013.go — #7013.
//
// `NATThen.PoolName` is a scalar, so ONE `then` block that names two pools —
//
//	then destination-nat pool PD pool PD2
//	then destination-nat { pool PD; pool PD2; }
//
// — lowers to a single pool and the other is gone before any validation runs.
// validateNATTerminalActionCardinalityStrict counts MODES (`n == 1` here), so it
// does not fire and the config commits under STRICT with an operator-authored
// action silently discarded. This records what one block AUTHORED, alongside the
// resolved NATThen, so the gate can reject on occurrences instead of modes. It
// is #7013's option 1: the resolved type keeps its shape and the dataplane
// contract is untouched.
//
// SCOPE IS ONE `then` CONTAINER, and that is the whole of the correctness
// argument for not breaking #3850. Two duplicate `then` containers are ALREADY
// decided: they are last-container-wins and legal, pinned by
// TestNATTerminalActionDupIdentical3850_5628 (same pool twice) and by the
// interface-then-poolB case beside it (different actions, last wins). Summing
// across containers false-rejects both. What #7013 describes is narrower — one
// block naming the mode twice — and that is the only shape counted here.
//
// WHICH SPELLINGS ARE ACTUALLY THIS DEFECT, measured at this head rather than
// taken from the issue, because the issue is wrong about one of them:
//
//   - `then destination-nat pool PD pool PD2` (one packed run) — the tree
//     carries both, the compiler keeps PD, PD2 vanishes. THE DEFECT.
//   - `then { destination-nat { pool PD; pool PD2; } }` (hierarchical braces,
//     the spelling in #7013's acceptance criterion) — the tree carries both,
//     the compiler keeps PD. THE DEFECT.
//   - two separate `set ... then destination-nat pool X` lines — NOT the
//     defect. The second REPLACES the leaf in the candidate tree, which is how
//     a single-value leaf is supposed to behave; only `pool PD2` ever reaches
//     the compiler, `show configuration` displays it, and nothing is hidden.
//     Rejecting it would break the ordinary way an operator edits a pool.
//
// So the survivor is the FIRST wherever the collapse actually happens — the
// issue body's "last wins" was describing leaf replacement, a different
// mechanism at a different layer. The tests still assert REJECTION rather than
// the survivor: rejection is the acceptance criterion, and a fixture built on
// the survivor reds against a correct compiler and a buggy one alike, for
// opposite reasons, which invites "fixing" the assertion.
//
// POOL NAMES AND MODES ARE BOTH RECORDED, and they answer two different
// questions — this paragraph used to say only pools were recorded, which #7033
// made false.
//
// The asymmetry is the part worth stating, because "`off` carries no value, so
// repeating it discards nothing" is true and is NOT a reason to ignore `off`:
//
//   - `off off` in one block discards nothing. Both spellings mean the same
//     exemption, so it is a redundancy and commits. distinctModes is what makes
//     that so, exactly as distinctPools does for `pool P pool P`.
//   - `off pool P` in one block DOES discard something. Two different modes
//     packed onto one run lower to a single field, and the one that loses is
//     gone with no diagnostic — and when the loser is `off`, what the dataplane
//     enforces is the inverse of what was authored. That is #7033, checked on
//     the recorded MODES.
//
// So "carries no value" justifies ignoring a REPEAT of one valueless mode. It
// never justified ignoring the mode itself.
//
// A rule that LOWERS two distinct modes is caught earlier still, by the
// resolved-field count; the modes recorded here are for the packed case that
// count cannot see.

// natThenAuthored is what ONE `then` container authored, before NATThen's
// scalar collapsed it.
type natThenAuthored struct {
	// Pools is every authored pool NAME in encounter order, so the diagnostic
	// can name the discarded one rather than only the survivor.
	Pools []string
	// Modes is every terminal action MODE the container authored, in encounter
	// order: "pool", "off", "interface" (#7033). Two distinct modes packed onto
	// one token run lower to a single field, so the mode COUNT taken from the
	// resolved NATThen sees one and the contradiction commits. This is the
	// authored view the packed-contradiction gate reads.
	Modes []string
}

// distinctPools returns the authored pool names with repeats removed, in
// encounter order.
//
// DISTINCT, not raw: `pool p1 pool p1` discards nothing — both spellings mean
// p1 — and rejecting it would be a diagnostic about a redundancy rather than
// about a lost action. Two DIFFERENT names is the case where the configuration
// as written and the configuration as enforced disagree.
func (a natThenAuthored) distinctPools() []string {
	if len(a.Pools) < 2 {
		return a.Pools
	}
	seen := make(map[string]struct{}, len(a.Pools))
	out := make([]string, 0, len(a.Pools))
	for _, p := range a.Pools {
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

// distinctModes returns the authored modes with repeats removed, in encounter
// order. Repeats of ONE mode are #7013's subject and are not a contradiction;
// two DIFFERENT modes are #7033's.
func (a natThenAuthored) distinctModes() []string {
	if len(a.Modes) < 2 {
		return a.Modes
	}
	seen := make(map[string]struct{}, len(a.Modes))
	out := make([]string, 0, len(a.Modes))
	for _, m := range a.Modes {
		if _, ok := seen[m]; ok {
			continue
		}
		seen[m] = struct{}{}
		out = append(out, m)
	}
	return out
}

// worseThan reports whether c records a more serious authored contradiction than
// a, and is how a rule with several `then` containers picks the one to report.
//
// MODES RANK FIRST, POOLS SECOND, and getting that wrong is not a matter of
// which message you get. The original ranking compared distinct POOLS only, so a
// container with no pool at all — `then { source-nat interface off; }` — never
// beat the zero-valued starting record, was never stored, and its packed
// cross-mode contradiction was never seen. That rule authors an exemption and
// publishes an interface translation: the same inversion #7033 exists to reject,
// silently missed because every fixture in the first draft happened to name a
// pool. Ranking on modes is what makes a pool-less contradiction visible.
func (c natThenAuthored) worseThan(a natThenAuthored) bool {
	if cm, am := len(c.distinctModes()), len(a.distinctModes()); cm != am {
		return cm > am
	}
	return len(c.distinctPools()) > len(a.distinctPools())
}

// natThenAuthoredOccurrences records every pool and every terminal action mode
// of `kind` that thenNode authored.
//
// THREE SHAPES, and all three have to be walked here or the gate is blind to
// one spelling of the same defect:
//
//  1. PACKED ONTO THE `then` NODE ITSELF — `then source-nat pool P` arrives as
//     Keys on the `then` node (the #7014 shape, applyPackedNATThenTokens7014).
//  2. PACKED ONTO THE KIND CHILD — `then { source-nat pool P pool Q; }` arrives
//     as Keys on the `source-nat` child, and a repeated value collapses onto
//     that one leaf's Keys (#2419) rather than producing two nodes.
//  3. HIERARCHICAL — `then { source-nat { pool P; pool Q; } }` arrives as
//     children of the `source-nat` child, one node each.
func natThenAuthoredOccurrences(thenNode *Node, kind string) natThenAuthored {
	var a natThenAuthored
	if thenNode == nil {
		return a
	}
	// Shape 1: `then <kind> <action> ...` — the kind sits at Keys[1].
	if len(thenNode.Keys) > 1 && thenNode.Keys[1] == kind {
		a.scanRun(thenNode.Keys, 2)
	}
	for _, t := range thenNode.Children {
		if t == nil || t.Name() != kind {
			continue
		}
		// Shape 2: the run continues on the kind child, after Keys[0].
		a.scanRun(t.Keys, 1)
		// Shape 3: one node per action below the kind node, which may be a
		// SIBLING list (`{ pool P; off; }`) or a CHAIN (the flat-set path builds
		// `pool P` with `off` as its child). walkActionChain covers both and
		// refuses to descend past a token it does not recognise.
		a.walkActionChain(t.Children)
	}
	return a
}

// scanRun records the terminal actions in a flat token run from index from, and
// STOPS at the first token it does not recognise.
//
// THE STOP IS THE WHOLE SAFETY ARGUMENT (#7033). The `then <kind>` subtree is
// deliberately open-world (#4313): `source-nat pool P persistent-nat permit
// any-remote-host` is valid, and everything from `persistent-nat` onward belongs
// to a sub-grammar this scan knows nothing about. A scan that kept going would
// read those trailing values as terminal actions the moment one of them happened
// to be spelled `off` — inventing a contradiction in a valid config. Round 6 of
// #6820 was reverted for the mirror-image of that mistake, fabricating an
// exemption out of tokens under an unrecognised container.
//
// `pool` consumes EXACTLY ONE value token, which is what keeps a pool
// legitimately named `off` resolving as a name: `pool off` is one pool, not a
// pool plus an exemption. A trailing bare `pool` is malformed rather than an
// authored pool — other gates report it, and recording it here would answer a
// syntax error with a contradiction message.
func (a *natThenAuthored) scanRun(keys []string, from int) {
	for i := from; i < len(keys); i++ {
		switch keys[i] {
		case "pool":
			if i+1 >= len(keys) {
				return
			}
			a.Pools = append(a.Pools, keys[i+1])
			a.Modes = append(a.Modes, "pool")
			i++
		case "off", "interface":
			a.Modes = append(a.Modes, keys[i])
		default:
			// Unrecognised: an open-world tail, not an action. Stop here.
			return
		}
	}
}

// walkActionChain records the actions carried by a list of nodes below the kind
// node, following each recognised node into its own children.
//
// It descends ONLY through recognised action names. A node named anything else
// ends that branch without recording: its subtree belongs to a grammar this walk
// does not model, and reading an `off` out of it would fabricate an exemption
// the operator never authored — the exact regression that reverted #6820 round
// 6 (`then { source-nat { frobnicate { off; } } }` resolving to `{Off:true}`).
func (a *natThenAuthored) walkActionChain(children []*Node) {
	for _, c := range children {
		if c == nil {
			continue
		}
		switch c.Name() {
		case "pool":
			a.addPoolNode(c)
		case "off", "interface":
			a.Modes = append(a.Modes, c.Name())
			a.scanRun(c.Keys, 1)
			a.walkActionChain(c.Children)
		}
	}
}

// addPoolNode records the pool(s) a `pool` NODE authored.
//
// The name may sit on the node (`pool P;` → Keys=["pool","P"]) or below it
// (`pool { P; }` → one child), and the second shape is the one the hierarchical
// fixtures in dual_ast_differential_test.go actually use.
//
// EXACTLY ONE NAME COMES FROM THE CHILDREN, taken from the FIRST child, because
// that is what nodeVal does and therefore what the compiler resolves. Counting
// every child would count Junos's `pool { P; persistent-nat { ... } }` as two
// authored pools and reject a valid config. Whatever the compiler treats as the
// name is what this has to treat as the occurrence, or the record describes a
// config the compiler never saw.
//
// A REPEAT MAY ARRIVE NESTED, not as a sibling: the flat-set path for
// `then source-nat pool PS pool PS2` builds `pool PS` with `pool PS2` as its
// CHILD, because the second `pool` token opens a further path rather than
// extending the leaf. So the walk descends — but only into children NAMED
// `pool`, which is what keeps the descent from swallowing `persistent-nat` and
// the pool-name node itself.
func (a *natThenAuthored) addPoolNode(c *Node) {
	if len(c.Keys) > 1 {
		// Repeats can also collapse onto this leaf's Keys (#2419), so scan the
		// whole run rather than reading Keys[1].
		a.scanRun(c.Keys, 0)
	} else if name := nodeVal(c); name != "" {
		a.Pools = append(a.Pools, name)
		a.Modes = append(a.Modes, "pool")
	}
	// The chain continues below a pool node in the flat-set spelling
	// (`pool P` carrying `off` as its child). The name node itself — `pool { P; }`
	// — is not a recognised action name, so it ends the branch without recording.
	a.walkActionChain(c.Children)
}
