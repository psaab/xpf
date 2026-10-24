package cli

import (
	"fmt"
	"strings"

	"github.com/psaab/xpf/pkg/cliterm"
	"github.com/psaab/xpf/pkg/cmdtree"
	"github.com/psaab/xpf/pkg/config"
)

// Fine-grained operational-command enforcement for `system login class`
// allow-commands / deny-commands (#7172 cut 3).
//
// This runs AFTER checkPermission, never instead of it: Junos authorizes the
// command family with the coarse permission bits first and the regexes narrow
// within that. A caller reaching this without the coarse gate has skipped a
// check rather than replaced one.
//
// WHY dispatchOperational AND NOT dispatch(). dispatch() looks like the
// narrowest entry — it has the untouched line, pipe included — but it is not
// the only one: `case "run"` in dispatchConfig calls dispatchOperational
// DIRECTLY (cli_dispatch.go), so a config-mode `run request system reboot`
// never passes through dispatch() again. Gating at dispatch() would leave that
// path open, and it is reachable by any operator who can enter config mode.
// dispatchOperational is where all five entry paths converge.
//
// THE PIPE IS PART OF THE COMMAND. Junos matches deny regexes against the
// command including its output pipe, and the security argument is independent
// of parity: `show configuration | save /tmp/x` writes a file and
// `| display set` reformats output a deny may be withholding, so a gate that
// cannot see past `|` cannot restrict either. cliterm.SplitPipe strips the
// suffix before dispatchOperational sees the line, so dispatchWithPipe hands it
// back through pendingPipeSuffix for reassembly here.

// loginRegexesFor compiles the calling class's operational allow/deny pair.
//
// Returns ok=false when the class has no fine-grained rules at all, which is
// the overwhelmingly common case and must stay allocation-free of surprises:
// the caller then skips regex evaluation entirely rather than evaluating an
// empty ruleset.
func (c *CLI) loginRegexesFor(class string) (config.CompiledLoginRegexes, bool, error) {
	var cfg *config.Config
	if c.store != nil {
		cfg = c.store.ActiveConfig()
	}
	return loginRegexesFrom(cfg, class)
}

// loginRegexesFrom resolves the operational allow/deny pair in force for class.
//
// #7172 cut 5b moved the decision into pkg/config so this gate and the gRPC one
// cannot come to disagree about WHOSE regexes are in force; cut 6 turned the
// ALLOW half on there, for both of them at once. The scoping comment that used
// to argue for deny-only here is gone with the scoping: `allow-commands` is
// enforced now, and an allow regex is an allowlist, which is the upgrade note
// docs/system-login.md carries.
func loginRegexesFrom(cfg *config.Config, class string) (config.CompiledLoginRegexes, bool, error) {
	return config.OperationalLoginRegexesFor(cfg, class)
}

// checkCommandRegex enforces the class's allow/deny command regexes against the
// canonical spelling of `line` plus its output pipe.
//
// FAIL-CLOSED ON EVERY UNCERTAIN PATH, and each one is a deliberate branch:
//
//   - a class whose regexes do not COMPILE denies. They are validated at
//     commit, so reaching here means a config arrived by a path that did not
//     validate; refusing is the only safe reading.
//   - a command that cannot be CANONICALIZED denies. We do not know what
//     command we are holding, so we cannot know a deny regex fails to match it.
//     Treating "cannot resolve" as "no match, allow" is precisely the bypass
//     canonicalization exists to close.
//
// Both apply ONLY to a class that configured regexes. A class with none is
// unaffected by either, so an ambiguous command still reaches its ordinary
// "ambiguous command" error rather than a permission denial.
func (c *CLI) checkCommandRegex(line string) error {
	var cfg *config.Config
	if c.store != nil {
		cfg = c.store.ActiveConfig()
	}
	return checkCommandRegexWith(cfg, c.UserClass(), line, c.pendingPipeSuffix)
}

// checkCommandRegexWith is the store-free whole decision, including the
// fail-closed arms. Split out for the same reason loginRegexesFrom is: the
// error branches are awkward to reach through a store, so driving the decision
// directly is what keeps them tested.
//
// #8289: this doc used to say "nothing can put a `deny-commands` class into
// ActiveConfig until cut 6". That is STALE — #7172 cut 6 landed and retired the
// #5831/#6838 admission gate (`pkg/config/compiler_tailgates.go` records it),
// so such a config commits now AND takes effect.
func checkCommandRegexWith(cfg *config.Config, class, line, pipeSuffix string) error {
	if class == "" {
		return nil
	}
	rules, ok, err := loginRegexesFrom(cfg, class)
	if err != nil {
		return fmt.Errorf("permission denied: login class %q has an invalid command regex: %w",
			class, err)
	}
	if !ok {
		return nil
	}

	return evaluateCommandRegex(rules, class, line, pipeSuffix)
}

// evaluateCommandRegex is the pure half: compiled rules and a command line in,
// an error or nil out. Split from checkCommandRegex so the decision can be
// driven directly in tests.
//
// That seam matters more than usual here, and the reason has CHANGED — read
// this rather than the sentence it replaced.
//
// It used to say cut 3's enforcement was "UNREACHABLE through the commit path
// until cut 6 retires #6838's gate". #7172 cut 6 has landed
// (`pkg/config/compiler_tailgates.go`: "a config carrying deny-commands /
// deny-configuration was REJECTED at commit before this and commits now — and
// takes effect"), so this path IS reachable by an ordinary operator config. A
// rationale asserting unreachability outlived the change that made it
// reachable, and nothing re-checked it; #8289 found the enforcement defect that
// staleness was hiding.
//
// The seam is still worth having — it is what lets the decision be driven
// directly, including by the #8289 cell that proves an anchored
// `deny-commands` is not defeated by appending a sibling keyword to the denied
// command.
func evaluateCommandRegex(
	rules config.CompiledLoginRegexes,
	class, line, pipeSuffix string,
) error {
	full := strings.TrimSpace(line)
	if suffix := strings.TrimSpace(pipeSuffix); suffix != "" {
		full = full + " | " + suffix
	}

	words := strings.Fields(full)
	// #9628: the output pipe is NOT operational-tree grammar. Canonicalizing it
	// with the command made `|` an unknown word, so a restricted class was
	// refused `show route | match X` and every other piped command whose node
	// could not absorb it. The command words are canonicalized alone, and the
	// pipe is matched as typed: it is still part of the matched string, so a
	// deny on `display set` sees it.
	cmdWords, pipeWords := splitAtPipe(words)
	canon, res := cmdtree.Canonicalize(cmdtree.OperationalTree, cmdWords)
	if res != cmdtree.CanonicalOK {
		return fmt.Errorf(
			"permission denied: login class %q restricts commands and %q could not be "+
				"resolved to a canonical command, so the restriction cannot be evaluated",
			class, firstWord(words))
	}
	if len(pipeWords) > 0 && (len(pipeWords) < 2 || !authorizablePipe(pipeWords[1])) {
		verb := ""
		if len(pipeWords) > 1 {
			verb = pipeWords[1]
		}
		return fmt.Errorf(
			"permission denied: login class %q restricts commands and the output pipe %q is not "+
				"a recognised filter, so the restriction cannot be evaluated",
			class, verb)
	}
	// #14715: a `display` pipe is only authorizable in its exact form
	// `| display <json|set|xml|inheritance>`, optionally followed by one
	// recognised output filter (`| display set | match x` — dispatch
	// SplitPipe splits the trailing filter off and the gate reassembles
	// it, so both segments appear here). The handlers reject any longer
	// form, and the gate must not authorize a shape the executor would
	// reject (or, pre-fix, silently truncated): gate and executor must
	// agree on what was run.
	if len(pipeWords) > 1 && pipeWords[1] == "display" {
		displayOK := len(pipeWords) >= 3 && isDisplayFormat(pipeWords[2]) &&
			(len(pipeWords) == 3 ||
				(len(pipeWords) >= 5 && pipeWords[3] == "|" && cliterm.IsPipeFilter(pipeWords[4])))
		if !displayOK {
			return fmt.Errorf(
				"permission denied: login class %q restricts commands and the output pipe %q is not "+
					"a recognised display format, so the restriction cannot be evaluated",
				class, strings.Join(pipeWords[1:], " "))
		}
	}
	// #14714: a multi-stage chain reaches here as one suffix
	// (`no-more | match xpf`). Every later stage's verb must be a
	// filter the CLI honours, like the first: an unrecognised verb
	// after a recognised first stage cannot be evaluated, so fail
	// closed rather than matching only the recognised prefix. A `|`
	// inside a quoted/typed filter argument is not a stage separator
	// for this check beyond the verb position — #15722: SplitPipe is
	// quote-aware and does not split there, while this gate tokenises
	// with strings.Fields, so a quoted `"a | b"` argument still
	// reaches this loop as bare `|` words whose following word
	// (`b"`) is not an authorised verb: the check fails CLOSED for
	// restricted classes. That over-refusal is pre-existing (see
	// docs/log/14714.md) and the fail-closed direction matches #9628;
	// unrestricted classes skip this gate entirely. Only a `|`
	// immediately followed by a bare verb token is inspected, which
	// is how dispatch recursed over the chain.
	for i := 0; i+2 < len(pipeWords); i++ {
		if pipeWords[i] == "|" && !authorizablePipe(pipeWords[i+1]) {
			return fmt.Errorf(
				"permission denied: login class %q restricts commands and the output pipe %q is not "+
					"a recognised filter, so the restriction cannot be evaluated",
				class, pipeWords[i+1])
		}
	}
	command := strings.Join(canon, " ")
	matched := command
	if len(pipeWords) > 0 {
		matched = command + " " + strings.Join(pipeWords, " ")
	}

	// #9022: match against the full canonical string AND the argument-free
	// command forms. `Canonicalize` passes an AcceptsArgs node's trailing
	// tokens through (#8304, deliberately), so an ANCHORED deny such as
	// `^show log$` stopped matching the moment any argument was appended and
	// the denied command ran. See EvaluateForms for the per-form rule.
	//
	// #15942 H1-01: canonicalForms also strips selector subtrees, so an
	// anchored deny/allow on the base command (`^show security
	// policies$`) reaches the selector-bearing spellings the old
	// leading-keyword walk priced as "show security policies from-zone".
	//
	// #9628: the pipe-less command is measured as well. Without it, fixing the
	// splice would have let `show version | match .` step around
	// `^show version$`, which the refusal used to hide.
	//
	// #14686: when a pipe is present the evaluation is marked as such, so
	// an allow that matches only inside pipe filter text cannot satisfy
	// the allowlist for the bare command.
	baseForm, fullForm, selectorForms, chainForm := canonicalForms(canon)
	forms := append([]string{baseForm, fullForm}, selectorForms...)
	var decision config.LoginRegexDecision
	if len(pipeWords) > 0 {
		decision = rules.EvaluateFormsWithPipe(matched, forms[0], append([]string{command}, forms[1:]...)...)
	} else {
		decision = rules.EvaluateForms(matched, forms[0], append([]string{command}, forms[1:]...)...)
	}
	// #14687 distinct-narrower-selector: a completed selector form
	// whose executed spelling is a distinct, narrower command than
	// its base (`show security screen ids-option <name>` lists one
	// profile; the bare denied `show security screen` lists all) is
	// allowed when no deny names the selector form itself — the base
	// form's denial prices the broader listing, not this one. The
	// rescue fires only when the BASE form is the sole deny-decided
	// spelling: every other addressable spelling (the full canonical
	// command, the keyword-only full form, each selector prefix, and
	// the piped form) must carry no deny verdict, and at least one
	// pipe-less spelling must be affirmatively allowed, so neither a
	// selector-spelling deny nor an allow smuggled inside pipe filter
	// text can be stepped around.
	if !decision.Allowed && chainForm != "" && distinctNarrowerAllowed(rules, matched, command, baseForm, fullForm, selectorForms) {
		decision = config.LoginRegexDecision{Allowed: true, DecidedBy: config.LoginRegexNeither,
			Reason: "distinct narrower selector command; no deny names it"}
	}
	if decision.Allowed {
		return nil
	}
	// AUDIT WITHOUT LEAKING ARGUMENTS, and the limitation is deliberate.
	//
	// A reader will eventually want the FULL canonical command in this record,
	// and the reason they cannot have it belongs here rather than being
	// rediscovered: canonicalization resolves KEYWORD slots but leaves value
	// slots as the operator typed them, so the joined string can carry a ping
	// target, a filename, a username. Naming only the leading resolved keyword
	// run is what keeps operator data out of the log.
	//
	// Widening this needs a way to tell a keyword from a value in the rendered
	// string, which Canonicalize does not currently report.
	return fmt.Errorf("permission denied: login class %q denies %q (%s)",
		class, canonicalPrefix(canon), decision.Reason)
}

// splitAtPipe splits a tokenised line at its FIRST `|` token. Everything after
// it is pipe text, including any later `|` inside a filter argument, because a
// filter argument may itself contain one (`| match "a | b"`).
func splitAtPipe(words []string) (cmd, pipe []string) {
	for i, w := range words {
		if w == "|" {
			return words[:i], words[i:]
		}
	}
	return words, nil
}

// authorizablePipe reports whether the first pipe verb is one the CLI honours:
// an output filter SplitPipe splits off, or `display`, which the show and
// config handlers parse from the line themselves (`| display set`), or
// `compare` (#15657 V47-02: `show system rollback <N> | compare` and
// config-mode `show | compare [rollback <N>]` are handler-parsed pipes,
// so a regex-restricted class must be able to authorize them instead of
// failing closed before the handler runs). Anything else is refused.
// The gate does not know what it would do, so it cannot know
// that a deny fails to match it.
func authorizablePipe(verb string) bool {
	return cliterm.IsPipeFilter(verb) || verb == "display" || verb == "compare"
}

// isDisplayFormat reports whether word is a configuration display format
// the show/config handlers honour after `| display`.
func isDisplayFormat(word string) bool {
	switch word {
	case "json", "set", "xml", "inheritance":
		return true
	}
	return false
}

func firstWord(words []string) string {
	if len(words) == 0 {
		return ""
	}
	return words[0]
}

// distinctNarrowerAllowed reports whether the base-form denial is the
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
func distinctNarrowerAllowed(rules config.CompiledLoginRegexes, matched, command, baseForm, fullForm string, selectorForms []string) bool {
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

// canonicalForms renders the argument-free command forms of a canonical
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
// into a log line. canonicalPrefix (the base form) serves that audit.
func canonicalForms(canon []string) (string, string, []string, string) {
	base := make([]string, 0, len(canon))
	full := make([]string, 0, len(canon))
	var selectors []string
	selectorOpen := false // inside a selector subtree (full form only)
	current := cmdtree.OperationalTree
	// pendingChildren/pendingSelector describe an open value slot: the
	// next token fills it, and a token after that may resolve as a
	// child keyword of the slot's node.
	var pendingChildren map[string]*cmdtree.Node
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
	for _, w := range canon {
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
					addSelectorForm(&selectors, append(append([]string(nil), base...), w))
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
					slotVocab = hasPlainSubcommand(node.Children)
					slotOptions = node.Options
					slotCompleted = false
				} else if hasPlaceholderChild(node) {
					pendingChildren = node.Children
					pendingSelector = selectorOpen
					pendingOptions = node.Options
					awaitValue = true
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
			addSelectorForm(&selectors, append(append([]string(nil), base...), w))
			pendingChildren = node.Children
			pendingSelector = true
			pendingOptions = node.Options
			awaitValue = true
			slotChain = append([]string(nil), full...)
			slotVocab = hasPlainSubcommand(node.Children)
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
			slotVocab = hasPlainSubcommand(node.Children)
			slotOptions = node.Options
			slotCompleted = false
			if node.Children == nil {
				break
			}
			current = node.Children
			continue
		}
		if hasPlaceholderChild(node) {
			// Placeholder-only slot: the next token fills it. Do NOT
			// open a pending-keyword walk, or a real sibling keyword
			// (e.g. `table` beside `<destination>`) would be eaten
			// as the placeholder's value.
			awaitValue = true
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

func addSelectorForm(forms *[]string, tokens []string) {
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
func hasPlainSubcommand(children map[string]*cmdtree.Node) bool {
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
func hasPlaceholderChild(node *cmdtree.Node) bool {
	for name := range node.Children {
		if strings.HasPrefix(name, "<") {
			return true
		}
	}
	return false
}

// canonicalPrefix is the base (selector-free) form of canon, for audit.
func canonicalPrefix(canon []string) string {
	base, _, _, _ := canonicalForms(canon)
	return base
}
