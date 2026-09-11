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
// THE BOOL IS NOT ADVISORY. On anything other than CanonicalOK the returned
// words are the input unchanged, and a caller enforcing a restriction MUST fail
// closed: it does not know what command it is holding, so it cannot know that a
// deny regex fails to match it. Treating a failed canonicalization as "no match,
// allow" is the bypass this function exists to close.
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

	for wi, w := range words {
		name, node, matches, ok := resolveTreeWord(current, w)
		dynamicPending := currentNode != nil && currentNode.HasDynamic() && !dynamicFilled
		if !ok && options != nil && !parentTyped && !dynamicPending {
			// #9505: the previous option is complete, so a word that is not
			// one of its children may be the next option. Only a node that
			// declares Options gets this; everywhere else a leaf still ends
			// the walk (#8289).
			var optionMatches []string
			name, node, optionMatches, ok = resolveTreeWord(options, w)
			if len(optionMatches) > len(matches) {
				matches = optionMatches
			}
		}
		if !ok {
			// Not a keyword at this level. A value slot may legitimately
			// consume it — those keep the raw word.
			if parentTyped {
				parentTyped = false
				continue
			}
			// #8304: AcceptsArgs is honoured HERE and not in the completion
			// walkers above, which ask a different question — those decide what
			// to OFFER, and a node with no completion source has nothing to add.
			if currentNode != nil && currentNode.AcceptsArgs {
				continue
			}
			// #9505: a dynamic node takes ONE value. This arm used to share the
			// AcceptsArgs `continue`, which never advances currentNode, so it
			// absorbed ARBITRARILY many words. A second unmatched word now
			// reaches the refusal below.
			if dynamicPending {
				dynamicFilled = true
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
				} else {
					filled[ph] = true
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
		out[wi] = name
		currentNode = node
		parentTyped = node.IsTypedLeaf()
		dynamicFilled = false
		if node.Options {
			options = node.Children
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
	return out, CanonicalOK
}
