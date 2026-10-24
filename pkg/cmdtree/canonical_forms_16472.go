package cmdtree

import (
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// canonical_forms_16472.go: the argument-free spellings of a canonical
// command, shared by every login-class regex gate (#16472).
//
// This walk used to live only in pkg/cli (canonicalForms there), so the
// console judged a selector-bearing command by its base, full-keyword
// and selector spellings while the gRPC/REST gates judged only the
// registry charge plus the reconstructed full line. An anchored deny on
// the BASE spelling (`^show firewall$`, `^show route$`) therefore held
// on the console and not over the remote CLI. The walk is pure tree
// grammar — it reads only Node shape — so it belongs beside
// Canonicalize, which both remote gates already import; pkg/cli keeps
// its pipe handling and #14687 rescue and calls this.
//
// A caller without a canonical token slice (a remote gate holding only
// a registry charge such as `show firewall filter`) derives the same
// forms via CanonicalFormsForCharge: the charge is run through the
// tree with a placeholder value in each value slot, exactly the
// derivation #16472's acceptance names.

// CanonicalForms renders the argument-free command forms of a canonical
// command for regex evaluation and audit (#15942 H1-01).
//
// Selector keywords (`from-zone <zone>`, `policy-name <name>`, the
// option keywords of an Options node, the trailing words of an
// AcceptsArgs node) FILTER the command accumulated so far; they are not
// subcommands of it. The forms are:
//
//   - the BASE form: the plain keyword chain with every selector
//     subtree removed, so `show security policies from-zone trust`
//     yields "show security policies" — the spelling an anchored
//     `^show security policies$` deny/allow is written against;
//   - the FULL keyword form: base plus completed subcommands under a
//     value (`show firewall filter <name> family inet` continues past
//     the dynamic value into the Options children; `show security
//     zones <name> detail` likewise). Selector keywords and their
//     subtrees never enter it, so it cannot fabricate a spelling that
//     aliases a real sibling (`filter FOO effective` yields full form
//     "show firewall", never "show firewall effective");
//   - one SELECTOR form per selector keyword: the base keyword chain
//     plus that keyword (`show firewall filter`, `show security screen
//     ids-option`) — the documented selector spelling an anchored
//     deny/allow may be written against, so such a rule still names
//     the command in both directions; and
//   - the CHAIN form, reported separately: the parent keyword chain of
//     a completed selector whose value offers a plain subcommand
//     (`ids-option <name>` → `detail`), marking a distinct, narrower
//     executed command for the #14687 rescue.
//
// The spellings are alternative forms under EvaluateForms' unanimity,
// so a rule anchored to any one of them can name the command it
// intends — and only that command. Without the base form, the old walk
// kept the first selector keyword ("show security policies from-zone"),
// which no anchored base rule ever matches: any selector keyword
// stepped around an anchored deny, and a mandatory-selector command
// could never satisfy an anchored allow. Plain keyword subcommands are
// untouched (`show configuration system` stays whole, #9022).
//
// #7172 requires audit output naming "class, canonical command, and
// deny reason WITHOUT leaking argument values". A canonical command
// still contains raw value slots — `request system login user <name>`
// or a ping target — so joining the whole slice would put operator data
// into a log line. CanonicalPrefix (the base form) serves that audit.
func CanonicalForms(canon []string) (string, string, []string, string) {
	base := make([]string, 0, len(canon))
	full := make([]string, 0, len(canon))
	var selectors []string
	selectorOpen := false // inside a selector subtree (full form only)
	current := OperationalTree
	// pendingChildren/pendingSelector describe an open value slot: the
	// next token fills it, and a token after that may resolve as a
	// child keyword of the slot's node.
	var pendingChildren map[string]*Node
	pendingSelector := false
	// pendingOptions records that the open value slot belongs to an
	// Options node, whose option keywords filter the accumulated
	// command rather than extending it.
	pendingOptions := false
	awaitValue := false
	// slotChain is the keyword chain of the PARENT command whose
	// dynamic value slot the walk most recently filled and which offers
	// a plain subcommand under the value (`ids-option <name>` under
	// `screen`, which has a `detail` child). It names a distinct,
	// narrower executed command (#14687), so the parent chain is the
	// chain form reported to the rescue. A selector with NO plain
	// subcommand (`from-zone` on `policies`) merely filters the base
	// listing and names no distinct command. Under an Options node
	// (`filter <name>` then `family inet`) the value names data, not a
	// command, so no chain form is reported either.
	var slotChain []string
	slotCompleted := false
	slotVocab := false
	slotOptions := false
	for i, w := range canon {
		if awaitValue {
			// w is the value itself: data, never a keyword.
			awaitValue = false
			slotCompleted = true
			continue
		}
		if pendingChildren != nil {
			if node, ok := pendingChildren[w]; ok {
				if pendingOptions {
					// An option keyword of the pending Options node
					// (`effective`, or the typed leaf `family`
					// after `filter <name>`): it filters THIS
					// command. Neither extending the full form
					// with it nor minting a `base + family`
					// selector form is sound — both would fabricate
					// a spelling for a command that does not exist.
					// The command form ends here. (This break must
					// precede the typed-leaf branch below, whose
					// selector-form minting applies only to real
					// selector subtrees.)
					break
				}
				if node.IsTypedLeaf() || (node.RequiresValue && node.HasDynamic()) {
					// Fresh selector subtree after a value
					// (from-zone X to-zone Y): judge its keyword as
					// its own selector form; exclude the subtree
					// from base and full.
					selectorOpen = true
					addSelectorForm16472(&selectors, append(append([]string(nil), base...), w))
					pendingChildren = node.Children
					pendingSelector = true
					awaitValue = true
					current = node.Children
					continue
				}
				// (pendingOptions was handled above: an option
				// keyword ends the command form.)
				// A completed subcommand under the value: extend the
				// full keyword chain (and the base too when it is not
				// inside a selector subtree). Only this arm extends
				// the full form, so no fabricated spelling arises.
				full = append(full, w)
				if !pendingSelector {
					base = append(base, w)
				}
				pendingChildren = nil
				if node.Options || node.AcceptsArgs || node.Children == nil {
					break
				}
				if node.HasDynamic() {
					pendingChildren = node.Children
					pendingSelector = selectorOpen
					pendingOptions = node.Options
					awaitValue = true
					slotChain = append([]string(nil), full...)
					slotVocab = hasPlainSubcommand16472(node.Children)
					slotOptions = node.Options
					slotCompleted = false
				} else if hasPlaceholderChild16472(node) {
					// #16469: same keyword-peek as the top-level
					// placeholder arm — a keyword child of this
					// node must not be eaten as the placeholder's
					// value; it resolves in the pending arm on
					// the next iteration.
					pendingChildren = node.Children
					pendingSelector = selectorOpen
					pendingOptions = node.Options
					if i+1 < len(canon) {
						if _, isKeyword := node.Children[canon[i+1]]; !isKeyword {
							awaitValue = true
						}
					}
				}
				current = node.Children
				continue
			}
			// Not a child keyword: the command form ends here.
			break
		}
		node, ok := current[w]
		if !ok {
			break
		}
		if node.IsTypedLeaf() || (node.RequiresValue && node.HasDynamic()) {
			// Selector keyword: excluded from the base and full
			// forms, but ADDRESSABLE as its own selector form
			// (`^show firewall filter$`, `^show security screen
			// ids-option$`), so an anchored rule written against
			// the selector spelling still names this command.
			selectorOpen = true
			addSelectorForm16472(&selectors, append(append([]string(nil), base...), w))
			pendingChildren = node.Children
			pendingSelector = true
			pendingOptions = node.Options
			awaitValue = true
			slotChain = append([]string(nil), full...)
			slotVocab = hasPlainSubcommand16472(node.Children)
			slotOptions = node.Options
			slotCompleted = false
			current = node.Children
			continue
		}
		if selectorOpen {
			full = append(full, w)
		} else {
			base = append(base, w)
			full = append(full, w)
		}
		if node.Options && !node.HasDynamic() {
			// An Options CONTAINER with no value slot of its own
			// (`hit-count`, the flow-session option set): everything
			// after it selects within this command. A RequiresValue
			// dynamic selector (`filter`, `ids-option`) DOES carry
			// a value slot and falls through to open it below.
			break
		}
		if node.AcceptsArgs {
			break
		}
		if node.HasDynamic() {
			// A dynamic value slot: the next token is data. A PLACEHOLDER
			// child (`<destination>` under `show route`) is only a
			// value slot, never a keyword: a following keyword such
			// as `table` resolves in the pending arm above as a real
			// subcommand, it is not swallowed as the value.
			pendingChildren = node.Children
			pendingSelector = selectorOpen
			pendingOptions = node.Options
			awaitValue = true
			slotChain = append([]string(nil), full...)
			slotVocab = hasPlainSubcommand16472(node.Children)
			slotOptions = node.Options
			slotCompleted = false
			if node.Children == nil {
				break
			}
			current = node.Children
			continue
		}
		if hasPlaceholderChild16472(node) {
			// Placeholder beside keywords (#16469): the next token
			// fills the placeholder ONLY if it is not a declared
			// keyword child of this node. A keyword (`table`,
			// `fib`, `summary` beside route's `<destination>`)
			// must fall through to the normal arms below on the
			// next iteration, so a RequiresValue selector mints
			// its selector form (`show route table`) and a plain
			// keyword extends base/full (`show route summary`).
			// Canonicalize guarantees a keyword here is never the
			// placeholder's value, so peeking canon[i+1] against
			// node.Children restates its own ruling. Only a
			// non-keyword token (or end of line) fills the slot.
			// Consumers: canonicalForms and canonicalPrefix
			// (audit, via canonicalForms) — both fixed here.
			if i+1 < len(canon) {
				if _, isKeyword := node.Children[canon[i+1]]; !isKeyword {
					awaitValue = true
				}
			}
			if node.Children == nil {
				break
			}
			current = node.Children
			continue
		}
		if node.Children == nil {
			break
		}
		current = node.Children
	}
	if len(base) == 0 {
		return "<unresolved>", "<unresolved>", nil, ""
	}
	baseStr := strings.Join(base, " ")
	fullStr := strings.Join(full, " ")
	if fullStr == "" {
		fullStr = baseStr
	}
	chainForm := ""
	if slotCompleted && slotVocab && !slotOptions && len(slotChain) > 0 {
		chainForm = strings.Join(slotChain, " ")
	}
	return baseStr, fullStr, selectors, chainForm
}

func addSelectorForm16472(forms *[]string, tokens []string) {
	form := strings.Join(tokens, " ")
	for _, existing := range *forms {
		if existing == form {
			return
		}
	}
	*forms = append(*forms, form)
}

// hasPlainSubcommand reports whether a value slot's node offers a plain
// subcommand keyword under the value (`detail` under `ids-option <name>`),
// as opposed to only further selector keywords (`to-zone` under
// `from-zone <zone>`). Only the former makes the completed selector a
// distinct, narrower command (#14687); the latter merely continues
// filtering the same listing (#15942).
func hasPlainSubcommand16472(children map[string]*Node) bool {
	for _, child := range children {
		if child == nil || child.IsTypedLeaf() || (child.RequiresValue && child.HasDynamic()) {
			continue
		}
		return true
	}
	return false
}

// hasPlaceholderChild reports whether node has a placeholder child
// (`<host>`) whose value the next canonical token would fill.
func hasPlaceholderChild16472(node *Node) bool {
	for name := range node.Children {
		if strings.HasPrefix(name, "<") {
			return true
		}
	}
	return false
}

// canonicalPrefix is the base (selector-free) form of canon, for audit.
func CanonicalPrefix(canon []string) string {
	base, _, _, _ := CanonicalForms(canon)
	return base
}

// CanonicalFormsForCharge derives the CanonicalForms of a command from
// its argument-free registry charge: every value slot on the charge's
// path is filled with a placeholder value, and a trailing selector
// keyword that requires a value gets one too, then the completed token
// slice is walked. ok=false when the charge does not resolve against
// OperationalTree (the caller then judges the charge alone — the
// charge itself is still a form, so nothing is widened).
//
// Examples: `show firewall filter` -> base `show firewall`, selector
// `show firewall filter`; `show security screen statistics zone` ->
// base `show security screen statistics`, selector
// `show security screen statistics zone`; `show route table` -> base
// `show route`. A charge that is already a plain keyword path
// (`show security zones detail`) yields only itself.
func CanonicalFormsForCharge(charge string) (base, full string, selectors []string, ok bool) {
	words := strings.Fields(charge)
	if len(words) == 0 {
		return "", "", nil, false
	}
	tokens := chargeTokens16472(words)
	if tokens == nil {
		return "", "", nil, false
	}
	// The completed slice must be a command Canonicalize accepts and
	// resolves to itself, or the derived forms would name a spelling
	// no operator can run.
	canon, res := Canonicalize(OperationalTree, tokens)
	if res != CanonicalOK || strings.Join(canon, " ") != strings.Join(tokens, " ") {
		return "", "", nil, false
	}
	base, full, selectors, _ = CanonicalForms(canon)
	// The charge itself is a selector spelling when it ends at a
	// value slot (`show route table`, `show firewall filter`):
	// CanonicalForms reports only the base for the completed
	// spelling, because the trailing keyword opened the slot. The
	// charge is the documented selector spelling operators write
	// anchored rules against (and the registry's own spelling), so
	// it joins the selector set whenever it differs from base/full.
	seen := map[string]bool{base: true, full: true}
	out := selectors[:0]
	for _, s := range selectors {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	if c := strings.Join(words, " "); !seen[c] {
		out = append(out, c)
	}
	return base, full, out, true
}

// placeholderValue16472 fills one value slot. It is data, never a
// keyword: CanonicalForms skips the token after a slot opener without
// examining it, and Canonicalize consumes exactly one value there.
const placeholderValue16472 = "xpf-placeholder"

// chargeTokens16472 completes a registry charge into a canonical token
// slice by inserting placeholderValue16472 wherever the walk opens a
// value slot, mirroring CanonicalForms' own slot tracking. It returns
// nil when a charge word is not a tree keyword on its path.
func chargeTokens16472(words []string) []string {
	tokens := make([]string, 0, len(words)+2)
	current := OperationalTree
	// pendingComplete reports whether the word just consumed opened a
	// value slot (CanonicalForms' awaitValue state at that point). The
	// FIRST charge word after it is routing information, not a value:
	// a plain child keyword of the slot's node is a completed
	// subcommand under the value (`detail` under `zones <name>`), a
	// ModifierOnly child is a pre-value charge keyword (`queue` under
	// `interfaces`, judged before any name), anything else means the
	// charge ends inside the slot or names a sibling of it.
	pendingComplete := false
	pendingPlaceholderOnly := false
	var pendingNode *Node
	for _, w := range words {
		if pendingComplete {
			if child, ok := pendingNode.Children[w]; ok && isPlainSubcommand16472(child) {
				if !pendingPlaceholderOnly {
					tokens = append(tokens, placeholderValue16472)
				}
				tokens = append(tokens, w)
				pendingComplete = false
				pendingPlaceholderOnly = false
				pendingNode = nil
				current = child.Children
				if child.HasDynamic() && !child.ModifierOnly {
					tokens = append(tokens, placeholderValue16472)
					pendingComplete = true
					pendingNode = child
					current = child.Children
				} else if child.HasDynamic() {
					pendingComplete = true
					pendingPlaceholderOnly = false
					pendingNode = child
					current = child.Children
				}
				continue
			}
			if child, ok := current[w]; ok {
				// ModifierOnly / selector / option keyword of the
				// pending level: a charge keyword in its own right.
				// Judge it at the pending level WITHOUT filling the
				// slot (the completed line may still fill it later:
				// `show interfaces queue <name>`).
				tokens = append(tokens, w)
				pendingComplete = false
				pendingNode = nil
				current = child.Children
				if child.IsTypedLeaf() || (child.RequiresValue && child.HasDynamic()) || child.HasDynamic() {
					tokens = append(tokens, placeholderValue16472)
					pendingComplete = child.Children != nil
					if pendingComplete {
						pendingNode = child
					}
					current = child.Children
				}
				continue
			}
			// Not a keyword at the pending level: it can only be
			// reached by filling the slot and resolving at the
			// value's level (`show route <dest> table ...` shapes
			// do not occur as charges; Canonicalize arbitrates).
			pendingComplete = false
			pendingNode = nil
		}
		node, isChild := current[w]
		if !isChild {
			return nil
		}
		tokens = append(tokens, w)
		switch {
		case node.IsTypedLeaf() || (node.RequiresValue && node.HasDynamic()):
			tokens = append(tokens, placeholderValue16472)
			pendingComplete = node.Children != nil
			if pendingComplete {
				pendingNode = node
			}
			current = node.Children
		case node.Options && !node.HasDynamic():
			current = node.Children
		case node.AcceptsArgs:
			current = node.Children
		case node.HasDynamic():
			// Do not fill yet: the next charge word routes (see
			// pendingComplete above). A charge ending here simply
			// never fills the slot, which Canonicalize accepts
			// for an optional dynamic (`show security zones`).
			pendingComplete = true
			pendingNode = node
			current = node.Children
		case hasPlaceholderChild16472(node):
			// Placeholder-only slot: likewise unfilled until a
			// following keyword proves it is a sibling (`table`
			// beside `show route`'s <destination>).
			pendingComplete = true
			pendingPlaceholderOnly = true
			pendingNode = node
			current = node.Children
		default:
			if node.Children == nil {
				current = nil
			} else {
				current = node.Children
			}
		}
	}
	return tokens
}

// isPlainSubcommand16472 reports whether node is a plain keyword
// subcommand (not a selector keyword, not a pre-value modifier):
// mirroring CanonicalForms' hasPlainSubcommand16472 test on identity.
func isPlainSubcommand16472(node *Node) bool {
	if node == nil || node.IsTypedLeaf() || (node.RequiresValue && node.HasDynamic()) {
		return false
	}
	return !node.ModifierOnly
}

// DistinctNarrowerAllowed reports whether the base-form denial is the
// ONLY deny verdict on the executed command, so the #14687 rescue may
// re-price the narrower spelling as allowed. It requires the base form
// itself to be deny-decided and NO other spelling (executed canonical
// command, full keyword form, selector forms) deny-decided. When an
// allow rule exists, the rescue additionally requires an AFFIRMATIVE
// allow-rule match on a pipe-less spelling: for such classes an
// allowlist miss is the denial being rescued, and only
// DecidedBy==LoginRegexAllow proves an allow rule actually named a
// spelling (R28/R29 shape). For deny-only classes there is no
// allowlist to satisfy: the base denial is a broad-listing price and
// the narrower command, named by no deny, runs (R09). matched
// carries pipe text, so it is checked last; a tier deny there vetoes.
func DistinctNarrowerAllowed(rules config.CompiledLoginRegexes, matched, command, baseForm, fullForm string, selectorForms []string) bool {
	if rules.Evaluate(baseForm).DecidedBy != config.LoginRegexDeny {
		return false
	}
	// The EXECUTED (value-bearing) spelling is the most specific
	// addressable form: a deny naming it vetoes. (Round-2 fold F1:
	// R28/R29/R30 — this check was missing, so a deny written against
	// the executed spelling, e.g. `^show security screen ids-option
	// prof1$`, was silently overridden.)
	cmdVerdict := rules.Evaluate(command)
	if cmdVerdict.DecidedBy == config.LoginRegexDeny {
		return false
	}
	// An ALLOW rule affirms a spelling only via DecidedBy==Allow on a
	// pipe-less form (R28/R29: a deny-only class must never pass this
	// gate on evaluateForm's default-allow, so the check is not the
	// vacuous `Allowed` boolean). But the requirement must not demand
	// affirmation for classes with NO allow rule at all (R09's
	// deny-only rescue): detect an allow rule by its participation —
	// the base form's verdict carries DecidedBy==Allow exactly when an
	// allow rule matched or an allowlist refused it.
	affirmed := cmdVerdict.DecidedBy == config.LoginRegexAllow && cmdVerdict.Allowed
	allowParticipates := false
	if d := rules.Evaluate(baseForm); d.DecidedBy == config.LoginRegexAllow {
		allowParticipates = true
	}
	for _, form := range append([]string{fullForm}, selectorForms...) {
		if form == baseForm {
			continue
		}
		d := rules.Evaluate(form)
		if d.DecidedBy == config.LoginRegexDeny {
			return false
		}
		if d.DecidedBy == config.LoginRegexAllow {
			// DecidedBy==Allow covers both an allow MATCH
			// (Allowed=true) and an allowlist MISS
			// (Allowed=false): either proves an allow rule
			// governs a pipe-less spelling of this command.
			allowParticipates = true
			if d.Allowed {
				affirmed = true
			}
		}
	}
	if allowParticipates && !affirmed {
		return false
	}
	// R07 (B4): when a pipe is present AND an allow rule participates,
	// the affirmation must hold on a PIPE-LESS spelling. A decision
	// rescued only because `matched` (with pipe text) affirmed would
	// let `| match interfaces` smuggle an allow written for an
	// unrelated word past a base deny. R12's deny-only class has no
	// allow rule to smuggle, so its benign pipe must not block the
	// rescue.
	if matched != command && allowParticipates && !affirmed {
		return false
	}
	if matched != command && rules.Evaluate(matched).DecidedBy == config.LoginRegexDeny {
		return false
	}
	return true
}
