package cmdtree

// CanonicalizeResult reports why Canonicalize could not resolve a word, so a
// caller can tell "this is not a command" from "this abbreviation is ambiguous"
// without re-walking the tree.
type CanonicalizeResult int

const (
	// CanonicalOK — every keyword slot resolved.
	CanonicalOK CanonicalizeResult = iota
	// CanonicalUnknown — a word matched no keyword and no value slot could
	// consume it.
	CanonicalUnknown
	// CanonicalAmbiguous — a word is a prefix of more than one keyword.
	CanonicalAmbiguous
)

// ValidateOperationalLine is the keyword-only gate for the remote CLI
// dispatcher (#16798). It reports a line that Canonicalize could not
// fully resolve but that ends exactly at a keyword node (a node with
// keyword children and no value slot of its own: no dynamic provider,
// no typed leaf, no placeholder child, no AcceptsArgs free-form tail,
// and not an Options container). Such a line's failure is solely the
// trailing unknown/ambiguous token under that node — e.g.
// `clear security ike security-associations` (ike is absent under
// clear security), `request system software add`,
// `request chassis cluster failover` misspelt as `failoverx`.
// Returning its canonical prefix, the offending token and whether it
// was ambiguous lets the dispatcher refuse with
// `unknown <path> command: <token>` instead of printing help and
// exiting 0, while a bare keyword node (no trailing token) stays
// CanonicalOK and keeps its help listing.
//
// Lines whose failure involves a value slot (a value already filled,
// a dangling/missing value, an Options walk, or trailing words after
// a leaf/value) are NOT keyword-only failures: they return ok=false
// so the dispatcher falls through to its existing strict handlers,
// which already refuse those shapes with command-specific errors
// (usage / unknown filter / exact-arity) and must not be pre-empted
// by a mislabelled "unknown command" that would also break lawful
// lines the tree models loosely (dynamic values, AcceptsArgs tails).
// CanonicalAmbiguous under a keyword-only node is reported with
// ambiguous=true so callers can name the ambiguity.
func ValidateOperationalLine(words []string) (prefix []string, bad string, ambiguous bool, ok bool) {
	if len(words) == 0 {
		return nil, "", false, false
	}
	if _, res := Canonicalize(OperationalTree, words); res == CanonicalOK {
		return nil, "", false, false
	}
	// Re-walk with the same prefix rule Canonicalize uses, tracking
	// only keyword descents. Any value-slot consumption makes the
	// failure not keyword-only.
	current := OperationalTree
	var node *Node
	var canon []string
	for i, w := range words {
		if node != nil {
			// The node we are under must be keyword-only for a
			// trailing token beneath it to be a keyword failure.
			// A childless node is a leaf: trailing words there are
			// the handlers' exact-arity/usage domain, not a missing
			// subcommand.
			if len(current) == 0 || node.HasDynamic() || node.IsTypedLeaf() || node.AcceptsArgs || node.Options {
				return nil, "", false, false
			}
			if findPlaceholder(current) != nil {
				return nil, "", false, false
			}
		}
		name, next, matches, resolved := resolveTreeWord(current, w)
		if !resolved {
			if i == 0 {
				// Unknown/ambiguous top-level verb: the dispatcher's
				// existing `unknown command: %s` already refuses it.
				return nil, "", false, false
			}
			if len(current) == 0 || node == nil {
				return nil, "", false, false
			}
			// Trailing token under a keyword-only node.
			if len(matches) > 1 {
				return canon, w, true, true
			}
			return canon, w, false, true
		}
		canon = append(canon, name)
		node = next
		current = next.Children
	}
	// Every word resolved as a keyword but Canonicalize still
	// refused: an incomplete line (dangling value slot, ends inside
	// an option subtree, repeated option, ...). Not keyword-only.
	return nil, "", false, false
}

// Canonicalize expands an abbreviated operational command line to the one
// spelling every consumer must agree on (#7172).
//
// Junos accepts unique prefixes, so `req sys reb` and `request system reboot`
// are the same command. An authorization gate that matches a deny regex against
// what the operator typed can therefore be stepped around by abbreviating, and
// there is no amount of regex cleverness that fixes it — the regex is written
// against one spelling and the input has many. Canonicalization is what makes
// the input single-valued before matching.
//
// WHY NOT REUSE CompleteFromTree's canonWords WALK, which computes exactly this
// and throws it away (see #5196 there): that walk is completion-shaped. It is
// driven by a trailing `partial`, it returns early in several branches to yield
// candidates, and it calls ContextDynamicFn providers — which need a
// *config.Config and exist to enumerate live values, neither of which a
// canonicalizer should require or trigger. Sharing resolveTreeWord (the actual
// prefix rule) rather than the walk keeps the one thing that must agree in one
// place, without dragging completion's needs into an authorization path.
//
// VALUE SLOTS KEEP THE RAW WORD, deliberately. A typed-leaf value, a
// <placeholder> and a dynamic value are operator-supplied data, not keywords —
// there is no canonical spelling to expand them to, and rewriting them would
// change the command. This mirrors the same choice in CompleteFromTree's walk.
//
// A VALUE SLOT TAKES ONE VALUE (#9505). A typed leaf, a dynamic node and a
// placeholder each consume exactly one word. The dynamic and placeholder arms
// used to consume every later word, so `show route table secret-vrf bypass`
// canonicalized OK, the handler dropped `bypass` and ran the command, and an
// anchored deny on the four-word command never saw it. After a value, the next
// word must be a child of the node that took it, or, under a node that declares
// Options, another option. Anything else is refused.
//
// A PLACEHOLDER NAME IS NOT A KEYWORD (#14196). `<host>` and its `<`-prefixes
// name a value slot, never a word an operator may type, so resolveTreeWord
// never resolves them: a literal `<...` word reaches the value-slot arms like
// any other data word — consumed once while its slot is empty, refused once
// filled. Before this, `ping 192.0.2.1 <` canonicalized to
// `ping 192.0.2.1 <host>`, a fake keyword the gate judged while the handler
// ran the real target, and an anchored deny on that target matched neither
// the polluted string nor the keyword-only prefix.
//
// THE BOOL IS NOT ADVISORY. On anything other than CanonicalOK the returned
// words are the input unchanged, and a caller enforcing a restriction MUST fail
// closed: it does not know what command it is holding, so it cannot know that a
// deny regex fails to match it. Treating a failed canonicalization as "no match,
// allow" is the bypass this function exists to close.
//
// A LINE MAY NOT END MID-VALUE (#14687). A typed leaf always awaits its
// value, a dynamic node marked RequiresValue awaits its value, and an
// unfilled childless <placeholder> under a keyword node awaits its value.
// Before this, `show firewall filter secret family` canonicalized OK, the
// gate judged that string, and the dispatcher — needing len>=5 to read a
// family — ran showFirewallFilter("secret",""), defeating an anchored deny
// on either form. Bare dynamic nodes without RequiresValue (e.g. `show
// security zones`), Options nodes with no option started (e.g. `show
// security flow session`), placeholders with children (`show route`), and
// the bare `ping`/`traceroute` command paths stay complete: the RPC/REST
// authorization tables charge those argument-free paths, and their typed
// RPCs carry the target in a field, not in the command string.
//
// REPEATED OPTIONS AND MID-WALK VALUE-SKIPS (#15719). An option keyword
// under an Options node may appear once: loop dispatchers keep the last
// (or ignore a duplicate flag), so a repeated keyword in the judged
// string names a different command from the one that runs — the
// #14688 repeated-key class. Symmetrically, a word that would resolve
// as a child keyword (or as the next option) while a value slot is
// pending must fill that slot first — resolving it as a keyword skips
// the value the dispatcher is waiting for, the mid-walk form of
// #14687's dangling value. Child-keyword values stay refused even when
// they are not keywords elsewhere (e.g. `sort-by` needs its child), and
// a line may not end inside a multi-token option subtree.
func Canonicalize(tree map[string]*Node, words []string) ([]string, CanonicalizeResult) {
	if len(words) == 0 {
		return words, CanonicalOK
	}
	out := append([]string(nil), words...)
	current := tree
	var currentNode *Node
	parentTyped := false
	// #9505: every value slot takes exactly ONE value. dynamicFilled records
	// that the current dynamic node has taken its value, and filled records each
	// placeholder that has. options is the child map of the nearest node that
	// declares Options: once one option is complete, the next word may be any
	// option, in any order, which is how those dispatchers parse them.
	dynamicFilled := false
	filled := map[*Node]bool{}
	var options map[string]*Node
	// #14687: placeholderMandatory records that the walk entered a keyword
	// node (not an Options node, not the tree root) whose level holds an
	// unfilled childless placeholder. The root exception keeps the bare
	// `ping`/`traceroute` command paths complete for the RPC/REST tables.
	// Descending into a placeholder clears it; `show route` (placeholder
	// with children) is never tracked.
	placeholderMandatory := false
	// #14688: seenFilterKeys counts resolved name/type keywords under the
	// current dynamic parent; valueParent is that dynamic node; lastWasValue
	// marks the previous word was consumed as its value.
	seenFilterKeys := map[string]int{}
	var valueParent *Node
	var valueParentChildren map[string]*Node
	lastWasValue := false
	// #15719: seenOptions tracks option keywords already resolved under
	// the active Options node (by node identity, so abbreviated and full
	// spellings collide); optionsNode is that node. A fresh Options node
	// resets the set.
	seenOptions := map[*Node]bool{}
	var optionsNode *Node
	// #15719: optionSubtree is an Options child with Children (e.g.
	// sort-by) that the walk has entered but not completed.
	var optionSubtree *Node
	// #15719: currentPlaceholder is the placeholder node whose value
	// slot is pending via placeholderMandatory (nil otherwise).
	var currentPlaceholder *Node
	// #15719: inOptionsWalk stays true once an Options node is entered:
	// the walk only descends from there into that node's options, their
	// values, or a multi-token option subtree.
	inOptionsWalk := false
	// #15719: phName/phLevel/parentLevel identify the keyword and
	// levels holding the pending placeholder; slotKeywordName/
	// parentLevel identify the keyword that opened the pending slot.
	phName := ""
	var phLevel map[string]*Node
	slotKeywordName := ""
	var parentLevel map[string]*Node

	for wi, w := range words {
		dynamicPending := currentNode != nil && currentNode.HasDynamic() && !dynamicFilled
		// #15719 acceptance: a pending slot is a typed leaf, an unfilled
		// placeholder at this level, or a RequiresValue dynamic. While
		// one is pending w must be consumed by that slot first; a word
		// that IS a child/option/self keyword is refused outright
		// rather than eaten as a value the dispatcher keys differently.
		// Optional dynamics (zones/interfaces/queue) are NOT pending:
		// their child keywords are bare-form vocabulary. A dynamic
		// node's own value may still be a keyword (opts zone fl).
		requiresPending := currentNode != nil && currentNode.RequiresValue && dynamicPending
		placeholderPending := false
		if currentPlaceholder != nil && !filled[currentPlaceholder] && phLevel != nil && currentNode != optionsNode {
			if ph := findPlaceholder(current); ph != nil && ph == currentPlaceholder {
				placeholderPending = true
			}
		}
		// A dynamic slot (any dynamic, incl. optional zone/interface)
		// also gates an option-keyword token at the Options root: the
		// dispatcher would take that token as the next option only if
		// the value were present, so `zone sort-by` / `zone zone`
		// (zone already seen) skip zone's value. A non-keyword token
		// or a keyword that is not an option (fl) stays the value.
		atOptionsRootPre := optionsNode != nil && inOptionsWalk
		dynamicOptionGate := false
		if dynamicPending && atOptionsRootPre && options != nil {
			if _, on, _, oo := resolveTreeWord(options, w); oo && (seenOptions[on] || options[w] == on) {
				dynamicOptionGate = true
			}
		}
		pendingValue := (parentTyped || requiresPending || placeholderPending || dynamicOptionGate) && !lastWasValue
		atOptionsRoot := optionsNode != nil && inOptionsWalk
		var name string
		var node *Node
		var matches []string
		var ok bool
		inGate := pendingValue && !(currentNode != nil && currentNode.AcceptsArgs)
		if inGate {
			_, _, _, childOK := resolveTreeWord(current, w)
			placeholderChild := false
			if placeholderPending && len(currentPlaceholder.Children) > 0 {
				_, _, _, po := resolveTreeWord(currentPlaceholder.Children, w)
				placeholderChild = po
			}
			optionResolves := false
			if atOptionsRoot && currentNode == optionsNode && options != nil {
				_, _, _, oo := resolveTreeWord(options, w)
				optionResolves = oo
			}
			selfKeyword := false
			if slotKeywordName != "" && parentLevel != nil {
				if cn, _, _, cok := resolveTreeWord(parentLevel, w); cok && cn == slotKeywordName {
					selfKeyword = true
				}
			}
			phSelfKeyword := placeholderPending && phName != "" && w == phName
			if placeholderChild || optionResolves || selfKeyword || phSelfKeyword || dynamicOptionGate ||
				(childOK && (parentTyped || requiresPending || currentNode == optionSubtree)) {
				return words, CanonicalUnknown
			}
			// Not a skip: resolve w as a keyword here so the value
			// arms below do not eat a real keyword as a placeholder
			// or dynamic value (route's <destination> eating `table`).
			name, node, matches, ok = resolveTreeWord(current, w)
		} else if dynamicPending && !(currentNode != nil && currentNode.ModifierOnly && !currentNode.RequiresValue) {
			// Pending dynamic value: do not resolve w as a keyword at
			// all, unless it is a child keyword of this dynamic node
			// (interfaces queue/detail: bare-form vocabulary). The
			// !ok arms below consume other words as the one value
			// (opts zone fl: fl abbreviates flag but is zone's value).
			if _, _, _, cok := resolveTreeWord(current, w); cok {
				name, node, matches, ok = resolveTreeWord(current, w)
			}
		} else {
			name, node, matches, ok = resolveTreeWord(current, w)
			if !ok && options != nil && currentNode != optionSubtree {
				// #9505 resume; #15719: never inside a subtree.
				var optionMatches []string
				name, node, optionMatches, ok = resolveTreeWord(options, w)
				if len(optionMatches) > len(matches) {
					matches = optionMatches
				}
			}
		}
		if lastWasValue && valueParent != nil {
			if _, n2, _, ok2 := resolveTreeWord(valueParent.Children, w); ok2 && n2 != nil && n2.ModifierOnly {
				return words, CanonicalUnknown
			}
		}
		if !ok && valueParentChildren != nil && valueParent != nil {
			if name2, node2, _, ok2 := resolveTreeWord(valueParentChildren, w); ok2 && node2 != nil && !node2.ModifierOnly && (name2 == "name" || name2 == "type") {
				name, node, ok = name2, node2, true
			}
		}
		if !ok {
			// Not a keyword at this level. A value slot may legitimately
			// consume it — those keep the raw word.
			if parentTyped {
				parentTyped = false
				slotKeywordName = ""
				continue
			}
			// #8304: AcceptsArgs is honoured HERE and not in the completion
			// walkers above, which ask a different question — those decide what
			// to OFFER, and a node with no completion source has nothing to add.
			// #11770: this arm is deliberately unbounded for free-form arguments.
			// A single-value argument must be modelled by a typed, dynamic, or
			// placeholder node so later words are refused here.
			if currentNode != nil && currentNode.AcceptsArgs {
				continue
			}
			// #9505: a dynamic node takes ONE value. This arm used to share the
			// AcceptsArgs `continue`, which never advances currentNode, so it
			// absorbed ARBITRARILY many words. A second unmatched word now
			// reaches the refusal below.
			if dynamicPending {
				dynamicFilled = true
				valueParent = currentNode
				lastWasValue = true
				slotKeywordName = ""
				continue
			}
			// #9505: the same rule for a placeholder. A childless one never
			// moves `current`, so it used to re-match every later word. Inside
			// an option list it lives at the option level, so it is looked up
			// there once the option before it is complete.
			ph := findPlaceholder(current)
			if ph == nil && options != nil {
				ph = findPlaceholder(options)
			}
			if ph != nil && !filled[ph] {
				if ph.Children != nil {
					currentNode = ph
					current = ph.Children
					dynamicFilled = false
					placeholderMandatory = false
					currentPlaceholder = nil
					phName = ""
					phLevel = nil
					slotKeywordName = ""
				} else {
					filled[ph] = true
					placeholderMandatory = false
					currentPlaceholder = nil
					phName = ""
					phLevel = nil
					slotKeywordName = ""
				}
				continue
			}
			// Ambiguity and absence are different operator errors and
			// different security stories: an ambiguous prefix is a command the
			// dispatcher will also refuse, while an unknown word may be a
			// value slot this tree does not model.
			if len(matches) > 1 {
				return words, CanonicalAmbiguous
			}
			_ = wi
			return words, CanonicalUnknown
		}
		if lastWasValue && valueParent != nil && node.ModifierOnly {
			return words, CanonicalUnknown
		}
		if valueParent != nil && (name == "name" || name == "type") {
			if seenFilterKeys[name] > 0 {
				return words, CanonicalUnknown
			}
			// Bare positional: previous word was the dynamic parent's own
			// value (currentNode still equals valueParent before update).
			if lastWasValue && currentNode == valueParent && name == "name" {
				return words, CanonicalUnknown
			}
			seenFilterKeys[name]++
		}
		// #15719: a keyword resolved at the Options root (the Options
		// node itself, or a completed option resuming via the option
		// map) may appear once. A subtree child completes its option.
		wasSubtreeChild := optionSubtree != nil && currentNode == optionSubtree
		atRoot := optionsNode != nil && inOptionsWalk && !wasSubtreeChild
		if atRoot {
			if seenOptions[node] {
				return words, CanonicalUnknown
			}
			seenOptions[node] = true
			// Entering the Options node itself also marks it, so a later
			// stray repeat of its name cannot be gated as an option; only
			// real options open a subtree.
			if len(node.Children) > 0 && !node.HasDynamic() && !node.IsTypedLeaf() && node != optionsNode {
				optionSubtree = node
			}
		}
		if wasSubtreeChild {
			optionSubtree = nil
		}
		out[wi] = name
		lastWasValue = false
		// #15719: this keyword opens a value slot when typed or a
		// RequiresValue dynamic.
		slotKeywordName = ""
		if node.IsTypedLeaf() || (node.RequiresValue && node.HasDynamic()) {
			slotKeywordName = name
			parentLevel = current
		}
		currentNode = node
		parentTyped = node.IsTypedLeaf()
		dynamicFilled = false
		if node.HasDynamic() && len(node.Children) > 0 && (valueParent == nil || node == valueParent) {
			if valueParent == nil {
				seenFilterKeys = map[string]int{}
			}
			valueParent = node
			valueParentChildren = node.Children
		}
		parentLevel = current
		if node.Options {
			options = node.Children
			optionsNode = node
			seenOptions = map[*Node]bool{node: true}
			optionSubtree = nil
			inOptionsWalk = true
			placeholderMandatory = false
			currentPlaceholder = findPlaceholder(node.Children)
			if currentPlaceholder != nil {
				phName = name
				phLevel = node.Children
				slotKeywordName = name
				parentLevel = current
			} else {
				phName = ""
				phLevel = nil
			}
		} else if wi > 0 {
			if ph := findPlaceholder(node.Children); ph != nil && !filled[ph] {
				currentPlaceholder = ph
				phName = name
				phLevel = node.Children
				if ph.Children == nil {
					placeholderMandatory = true
				} else {
					placeholderMandatory = false
				}
			} else {
				placeholderMandatory = false
				if findPlaceholder(current) != currentPlaceholder {
					currentPlaceholder = nil
					phName = ""
					phLevel = nil
				}
			}
		}
		// #8289: descend UNCONDITIONALLY, including to a leaf's nil child map.
		// This used to `continue` when `node.Children == nil`, leaving `current`
		// pointing at the PARENT map, so the next word resolved against the
		// leaf's own SIBLINGS: `show version configuration` canonicalized OK as
		// a three-word command.
		//
		// That is an RBAC bypass, and not the one it looks like. Both
		// dispatchers run it as plain `show version` — `case "version"` in
		// pkg/cli/cli_show.go and pkg/grpcapi/server_show.go both call a
		// no-argument showVersion and drop the rest — so the trailing word is
		// NOT executed as `show configuration`. The hazard is the reverse:
		// `evaluateCommandRegex` decides on `strings.Join(canon, " ")`, so it
		// judged the three-word string while the box ran the two-word command.
		// An operator's anchored `deny-commands "^show version$"` therefore did
		// not match, and appending ANY sibling keyword ran the denied command.
		// Measured:
		//
		//	deny="^show version$"  line="show version"                -> denied
		//	deny="^show version$"  line="show version configuration"  -> ALLOWED
		//
		// Assigning nil sends the next word into the `!ok` arm above, which
		// still admits the legitimate consumers of a word after a keyword — a
		// typed leaf's value (`parentTyped`), a dynamic node, a placeholder —
		// and refuses anything else as CanonicalUnknown. Callers fail closed on
		// that, per this function's own contract.
		current = node.Children
	}
	// #15719: refuse a line that ends inside a multi-token option
	// subtree (e.g. `sort-by` with no child keyword).
	if optionSubtree != nil {
		return words, CanonicalUnknown
	}
	// #14687: refuse a line that ends while a value slot is still pending.
	if parentTyped {
		return words, CanonicalUnknown
	}
	if currentNode != nil && currentNode.RequiresValue && currentNode.HasDynamic() && !dynamicFilled {
		return words, CanonicalUnknown
	}
	// An unfilled CHILDLESS placeholder under a non-root keyword node
	// is a mandatory positional value (`show chassis cluster
	// data-plane flows` with no limit). A placeholder WITH children
	// ending bare is the list-all form (`show route`) and stays
	// complete (#14687); #15719 only gates its child-keyword values
	// mid-walk. Under an Options node a placeholder is optional, and
	// root-level ping/traceroute targets are excluded (see header).
	if placeholderMandatory {
		return words, CanonicalUnknown
	}
	return out, CanonicalOK
}
