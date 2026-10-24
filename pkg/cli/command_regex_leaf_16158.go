package cli

import (
	"fmt"
	"strings"

	"github.com/psaab/xpf/pkg/cliterm"
	"github.com/psaab/xpf/pkg/cmdtree"
	"github.com/psaab/xpf/pkg/config"
)

// command_regex_leaf_16158.go is the CLI-local testable command-regex leaf
// (#16158, W2.5e narrowed per Codex B).
//
// The leaf lives HERE, in package cli, beside the CLI grammar it depends
// on: pipe handling (cliterm.IsPipeFilter), the selector rescue over
// cmdtree.Canonicalize(OperationalTree), and the privacy-preserving CLI
// error wording. It MUST NOT move into pkg/authz: pkg/authz is the
// principal boundary and must not import cmdtree or CLI pipe semantics,
// and no code in pkg/authz may import this leaf. The reusable
// compiled-regex evaluation (CompiledLoginRegexes) stays in pkg/config;
// the gRPC gate keeps its own request-aware logic. Since #16472 the
// canonicalForms / distinctNarrowerAllowed implementations live in
// pkg/cmdtree (shared with both remote gates); this file keeps
// one-line forwarders under their CLI names.
//
// Named seam: evaluateCommandRegex is the pure (class, line, pipeSuffix)
// decision. TestCommandRegexLeafDifferential16158 pins its verdict AND
// byte-identical error wording over the (class, op) corpus rebuilt
// post-#15994, including the #15994 group-pricing cells reached through
// checkCommandRegexWith and the pipe-filter cases. Every formerly-denied
// input must stay denied; any wording drift fails the corpus.

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
	// #16469 selector-form exception: when the only tier-deny
	// verdicts are on selector forms (`show route table` minted from
	// the placeholder-sibling walk) and the executed command itself
	// is affirmatively allowed by a longer allow (the
	// deny-with-exceptions idiom: `^show route table public-vrf$`
	// beside `^show route table`), the selector spelling's denial
	// prices the broader selector command, not this excepted value.
	// EvaluateForms cannot see this geometry: its truncated-form
	// veto measures the exception against the base/full forms, and a
	// selector form is neither — pre-#15942 the full form WAS
	// `show route table public-vrf`'s keyword run, so the exception
	// fired there. The rescue is narrow (see
	// selectorExceptionAllowed): no tier deny on the executed, base
	// or full forms, and the executed command must be
	// affirmatively allow-decided. A selector-spelling deny with no
	// such exception (the #16469 regression cells) still denies,
	// because the command form is then unaffirmed.
	if !decision.Allowed && selectorExceptionAllowed(rules, matched, command, baseForm, fullForm, selectorForms) {
		decision = config.LoginRegexDecision{Allowed: true, DecidedBy: config.LoginRegexNeither,
			Reason: "selector form denied but the executed command is excepted by a longer allow"}
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

// distinctNarrowerAllowed is the CLI spelling of
// cmdtree.DistinctNarrowerAllowed (#16472: moved with CanonicalForms so
// the console and both remote gates rescue identically). The pipe arms
// live in the shared implementation, driven by matched != command.
func distinctNarrowerAllowed(rules config.CompiledLoginRegexes, matched, command, baseForm, fullForm string, selectorForms []string) bool {
	return cmdtree.DistinctNarrowerAllowed(rules, matched, command, baseForm, fullForm, selectorForms)
}

// selectorExceptionAllowed reports whether a denial driven ONLY by
// selector forms is lifted by a deny-with-exceptions allow naming the
// executed command (#16469, preserving the #9628 public-vrf cell:
// allow `^show route table public-vrf$` beside deny `^show route
// table`). EvaluateForms' truncated-form veto measures the exception
// against the base/full forms; a selector form is neither, and
// pre-#15942 the keyword-full form carried this geometry — the
// pipe arm's core-exception check likewise never sees the selector
// form as the vetoing truncated form. Conditions, all required:
//
//   - at least one selector form is tier-denied, and no other form
//     among {command, base, full} is tier-denied: a tier deny on the
//     executed spelling (a deny naming the value) vetoes, as does a
//     base deny (the broader listing's price — #14687's rescue, not
//     this one) or a full-form deny (a real subcommand's price). The
//     piped form is deliberately not counted: the selector deny
//     re-measured on the piped string (`^show route table` matching
//     `show route table public-vrf | match 10.0`) is this same
//     denial. A deny that additionally reaches into pipe text
//     (`^show route table.*match secret`) is then indistinguishable
//     from it at this seam and lifts too — the same trade
//     EvaluateForms' core-exception geometry makes for truncated
//     forms, and the exception allow still had to name the executed
//     command exactly;
//   - the executed command (value-bearing, pipe-less) is
//     affirmatively allow-decided (DecidedBy==Allow, Allowed), so a
//     deny-only class or an allowlist miss can never pass — in
//     particular the #16469 anchored selector denies, whose executed
//     commands carry no allow, still deny.
//
// Tier denial, not DecidedBy alone: an allowlist miss also carries
// DecidedBy==Allow, and a form denied only for missing the allowlist
// must not veto an exception the executed command satisfies.
func selectorExceptionAllowed(rules config.CompiledLoginRegexes, matched, command, baseForm, fullForm string, selectorForms []string) bool {
	if len(selectorForms) == 0 {
		return false
	}
	cmdVerdict := rules.Evaluate(command)
	if cmdVerdict.DecidedBy != config.LoginRegexAllow || !cmdVerdict.Allowed {
		return false
	}
	tierDeny := func(form string) bool {
		d := rules.Evaluate(form)
		return !d.Allowed && d.DecidedBy == config.LoginRegexDeny
	}
	selectorTierDenied := false
	for _, form := range selectorForms {
		if tierDeny(form) {
			selectorTierDenied = true
		}
	}
	if !selectorTierDenied {
		return false
	}
	for _, form := range []string{command, baseForm, fullForm} {
		if tierDeny(form) {
			return false
		}
	}
	return true
}

// canonicalForms is the CLI spelling of cmdtree.CanonicalForms (#16472:
// the walk moved to the leaf package both remote gates already import, so
// the console and the gRPC/REST gates judge the same spellings). Kept as
// a one-line forwarder so this file's call sites and tests keep their
// vocabulary; the implementation, its invariants and its history live in
// pkg/cmdtree/canonical_forms_16472.go.
func canonicalForms(canon []string) (string, string, []string, string) {
	return cmdtree.CanonicalForms(canon)
}

// canonicalPrefix is the base (selector-free) form of canon, for audit.
func canonicalPrefix(canon []string) string {
	return cmdtree.CanonicalPrefix(canon)
}
