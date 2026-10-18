package config

import (
	"fmt"
	"regexp"
	"strings"
)

// Fine-grained `system login class` allow/deny regex evaluation (#7172).
//
// This is the ONE matcher every enforcement point shares, the fine-grained
// sibling of login_perms.go's coarse `ResolveClassPermissions`. Coarse
// permissions authorize the command FAMILY first; this narrows within it. A
// caller that reaches this without having passed the coarse gate has skipped a
// check, not replaced one.
//
// It is deliberately PURE — patterns and a command string in, a decision out,
// no dispatch surface, no config store, no principal. The dispatch wiring is
// mechanical; this is the part where a mistake is a privilege escalation, so it
// is reviewable on its own.
//
// ── SEMANTICS, AND WHERE THEY COME FROM ──────────────────────────────────
//
// Junos has TWO statement families with DIFFERENT precedence (#7971):
//
//	allow-commands / deny-commands (+ -configuration)  → allow wins
//	allow-commands-regexps / deny-commands-regexps     → DENY wins, and the
//	                                                     regex matches the
//	                                                     command's full path
//
// xpf implements only the first. The precedence is therefore held as PER-FAMILY
// DATA on LoginRegexFamily rather than as a constant, because the natural way to
// add the second family is to reuse "the precedence logic" — and that reuse
// would look responsible while inverting the rule on the leaf that matters.
//
// Matching is UNANCHORED (partial). Juniper: "You must use anchors when
// specifying complex regular expressions with the allow-commands statement",
// with `(^monitor)|(^ping)|(^show)|(^exit)` as the worked example — explicit
// anchors would be redundant if the match were implicitly anchored. Anchors are
// the operator's tool for narrowing, not something we apply for them.
//
// The asymmetry that follows is the sharp edge of this feature and is worked
// through in docs/system-login.md: partial matching makes a DENY broader (safe)
// and an ALLOW broader (fail-open), so combined with allow-over-deny a wide
// allow can silently re-permit a narrow deny.
type LoginRegexLeaf int

const (
	// LoginRegexNeither is "no leaf decided this" — the zero value, so a
	// half-built decision reads as undecided rather than as an allow.
	LoginRegexNeither LoginRegexLeaf = iota
	LoginRegexAllow
	LoginRegexDeny
)

func (l LoginRegexLeaf) String() string {
	switch l {
	case LoginRegexAllow:
		return "allow"
	case LoginRegexDeny:
		return "deny"
	default:
		return "neither"
	}
}

// LoginRegexFamily carries one Junos statement family's precedence rules.
//
// A struct rather than constants because #7971 records that the `-regexps`
// family inverts the first tier and matches a different string. Whoever adds it
// should be forced to supply a family, not tempted to reuse a hardcoded rule.
type LoginRegexFamily struct {
	// Name is the family's operator-facing spelling, for audit strings.
	Name string
	// IdenticalPatternWinner decides the case Juniper states outright: "if you
	// configure the same command for both the allow-commands and deny-commands
	// statements, then the allow operation takes precedence over the deny
	// operation." For the plain family that is LoginRegexAllow. For the
	// `-regexps` family it is LoginRegexDeny.
	IdenticalPatternWinner LoginRegexLeaf
}

// LoginRegexPlainFamily is `allow-commands` / `deny-commands` and the
// `-configuration` pair — the only family xpf implements.
var LoginRegexPlainFamily = LoginRegexFamily{
	Name:                   "allow-commands/deny-commands",
	IdenticalPatternWinner: LoginRegexAllow,
}

// CompiledLoginRegexes is one class's allow/deny pair, compiled once at
// admission so evaluation cannot fail, panic, or fall open at runtime.
//
// PRESENCE IS NOT VALUE. allowSet/denySet record whether the LEAF WAS WRITTEN,
// independently of what it holds, because `deny-commands ""` and an absent
// `deny-commands` mean OPPOSITE things: an empty POSIX regex matches every
// command, so an empty deny denies EVERYTHING, while an absent deny denies
// nothing. Collapsing them is the fail-open direction. This mirrors
// LoginClass.DenyLeavesPresent, which exists for the same reason and must
// survive the #6838 gate's retirement.
type CompiledLoginRegexes struct {
	family LoginRegexFamily

	allow    *regexp.Regexp
	allowSrc string
	allowSet bool

	deny    *regexp.Regexp
	denySrc string
	denySet bool

	// pipeBoundary is set only by EvaluateFormsWithPipe for the single
	// evaluation whose full form carries an output pipe. It is a per-call
	// marker copied into a shallow clone, never stored on a shared ruleset.
	pipeBoundary bool
}

// CompileLoginRegexes compiles one class's pair. Returns an error the strict
// commit path surfaces to the operator; a class that does not compile must
// never reach evaluation.
//
// DIALECT: regexp.CompilePOSIX, Go's egrep/POSIX-ERE mode — the dialect Junos
// uses. Same choice, and for the same reason, as ValidASPathRegex in
// aspath_regex.go, whose comment works through why Go and glibc differing here
// differ in the safe direction.
//
// BUT NOT ITS EMPTY CHECK, AND THIS IS DELIBERATE. ValidASPathRegex opens with
// `if strings.TrimSpace(regex) == "" { return error }`. Copying that here would
// invert the fail-closed direction on the leaf that matters: an operator who
// writes `deny-commands ""` has written the most restrictive thing the grammar
// allows — deny everything — and rejecting it, or worse treating it as "no
// restriction", turns a total lockout into a total permit. The two functions
// look like they should agree and must not. See docs/system-login.md.
func CompileLoginRegexes(
	family LoginRegexFamily,
	allow string, allowPresent bool,
	deny string, denyPresent bool,
) (CompiledLoginRegexes, error) {
	out := CompiledLoginRegexes{family: family}
	if allowPresent {
		re, err := regexp.CompilePOSIX(allow)
		if err != nil {
			return CompiledLoginRegexes{}, fmt.Errorf(
				"allow regex is not a valid POSIX extended regular expression: %w", err)
		}
		out.allow, out.allowSrc, out.allowSet = re, allow, true
	}
	if denyPresent {
		// NO EMPTY-PATTERN GUARD HERE, AND ITS ABSENCE IS THE POINT.
		//
		// The sibling this borrows its dialect from — ValidASPathRegex in
		// pkg/config/aspath_regex.go — opens with
		// `if strings.TrimSpace(regex) == "" { return error }`. Diffing the two
		// functions, the natural conclusion is that this one is missing a guard.
		// It is not.
		//
		// An empty POSIX regex matches EVERY string. For an AS-path filter that
		// is a useless pattern worth rejecting. For a DENY leaf it is the most
		// restrictive thing the grammar can express — deny everything — and it
		// is a spelling operators actually use. Rejecting it, or treating it as
		// "no restriction", converts a total lockout into a total permit.
		//
		// So the two functions must disagree, and this one must not grow that
		// guard. See TestEmptyDenyPatternDeniesEverything7172.
		re, err := regexp.CompilePOSIX(deny)
		if err != nil {
			return CompiledLoginRegexes{}, fmt.Errorf(
				"deny regex is not a valid POSIX extended regular expression: %w", err)
		}
		out.deny, out.denySrc, out.denySet = re, deny, true
	}
	return out, nil
}

// LoginRegexDecision is the verdict.
//
// Reason NEVER carries the command or its arguments. #7172 requires audit
// output that names the class, the canonical command and the deny reason
// "without leaking argument values", and this layer cannot tell an argument
// from a verb — only the caller knows which command string is safe to log. So
// the core describes the RULE that decided, and the caller composes it with
// whatever command text it has already deemed loggable.
type LoginRegexDecision struct {
	Allowed bool
	// DecidedBy is which leaf carried the decision, or LoginRegexNeither when
	// no regex applied at all.
	DecidedBy LoginRegexLeaf
	// Reason is an operator-facing explanation of the RULE. Safe to log.
	Reason string
}

// longestMatchLen returns the length of the longest substring `re` matches
// anywhere in `s`, or -1 when it does not match.
//
// LONGEST MATCH ANYWHERE, not the leftmost one. CompilePOSIX gives Go
// leftmost-longest semantics, but leftmost-longest is not globally longest:
// `a|bbbb` against "a bbbb" matches "a" leftmost while "bbbb" is the longer
// match. Junos's rule is about how much of the command a pattern accounts for,
// so the longest match anywhere is the faithful reading.
//
// Zero is a legitimate return: an empty pattern matches an empty substring
// everywhere. That is why the caller tests >= 0 rather than > 0 — an empty deny
// MUST count as matching, since it is the "deny everything" spelling.
func longestMatchLen(re *regexp.Regexp, s string) int {
	locs := re.FindAllStringIndex(s, -1)
	if locs == nil {
		return -1
	}
	best := -1
	for _, loc := range locs {
		if n := loc[1] - loc[0]; n > best {
			best = n
		}
	}
	return best
}

// Evaluate decides whether `command` is permitted.
//
// ── PRECEDENCE, THREE TIERS ──────────────────────────────────────────────
//
// Tier 1 — IDENTICAL PATTERN in both leaves → family.IdenticalPatternWinner
// (allow, for the plain family). Juniper states this outright: "if you
// configure the same command for both the allow-commands and deny-commands
// statements, then the allow operation takes precedence over the deny
// operation." Not our call to change.
//
// Tier 2 — DIFFERENT patterns, DIFFERENT matched lengths → the LONGEST MATCHED
// SUBSTRING wins, whichever leaf it came from. Juniper: "If the allow-commands
// and deny-commands statements have two different variants of a command, the
// longest match is always executed", with the worked example of a class that
// may run `commit synchronize` but not `commit`.
//
// NOTE WHAT TIER 2 MEANS: a longer DENY beats a shorter ALLOW. "allow always
// wins" is FALSE, and implementing it would be a fail-open — `allow-commands
// "commit"` beside `deny-commands "commit synchronize"` must DENY `commit
// synchronize`.
//
// Tier 3 — DIFFERENT patterns, EQUAL matched lengths → DENY. Upstream is
// silent here (it addresses identical patterns in tier 1 and differing lengths
// in tier 2, not a length tie between different patterns), so this is OUR
// interpretation of an underspecified rule, chosen fail-closed. It is recorded
// as ours in docs/system-login.md rather than presented as Junos behaviour,
// because the next person with a real Junos box needs to know which sentence to
// go and check.
//
// ── A REVIEWER'S WARNING ─────────────────────────────────────────────────
//
// Tier 1 giving ALLOW the win is deliberate and is NOT a fail-open bug. It
// inverts the usual "deny wins" instinct, so a reviewer who assumes deny-wins
// will read this as broken and try to "fix" it. It is Junos parity and it is
// stated in docs/system-login.md:416-418 and on Juniper's own documentation.
// Changing it silently would break the deny-with-exceptions idiom this feature
// exists to support.
func (c CompiledLoginRegexes) Evaluate(command string) LoginRegexDecision {
	return c.EvaluateForms(command, command)
}

// EvaluateForms decides whether a command is permitted, matching each side
// against the supplied forms and letting the precedence tiers decide.
//
// Forms are ALTERNATIVE spellings of the SAME command, not projections to be
// pooled: the full canonical string (arguments/pipe included, as the operator
// typed them), the argument-free keyword prefix, and any caller-supplied
// additional forms such as the pipe-less command. Junos's longest-match rule
// (tier 2) compares how much of THE command each pattern accounts for, so
// allow and deny lengths for one tier comparison MUST be measured against
// the SAME form. #14686: pooling one global max per side across forms of
// different lengths let a wildcard allow measured on a long piped form
// (`^show.*` against `show version | match .`, 22 chars) outgrow an
// end-anchored deny that can only ever match the short pipe-less form
// (`^show version$`, 12 chars), and let an unanchored allow phrase placed
// inside user-controlled pipe filter text (`| except show interfaces`)
// satisfy the allowlist for a command (`show configuration`) that never
// matched it. Both are complete RBAC bypasses for the affected class shapes.
//
// The fix therefore evaluates EVERY form independently under the ordinary
// tiers (identical-pattern, longest-match, tie-to-deny, allowlist) and
// requires UNANIMITY: the command is allowed only if EVERY form is allowed.
// A form is not a weaker hint about the command — each form is a spelling
// under which a deny was meant to bite (an anchored deny against the
// pipe-less form, an anchored exception against the full form). The form
// only a deny matches drags the whole command down; the form only an allow
// exception matches cannot lift it past a deny that matches another form.
//
// #9022: AN ANCHORED DENY WAS DEFEATED BY APPENDING ANY ARGUMENT. With
// `deny-commands "^show log$"`, every one of these RAN:
//
//	show log 100          -> journalctl -u xpfd -n 100
//	show log messages     -> tails a syslog file
//	show log FOO extra    -> `extra` silently dropped, tails a syslog file
//
// while the bare `show log` was correctly denied. `Canonicalize`'s AcceptsArgs
// arm (#8304, deliberately) passes trailing tokens through, so the string the
// rule matched against carried them and `$` no longer matched. Any AcceptsArgs
// node under an anchored rule was affected, including `show configuration
// system`, which discloses the whole committed stanza.
//
// WHY UNANIMITY RATHER THAN "DENY IF ANY FORM MATCHES A DENY". That blunt
// rule BREAKS the deny-with-exceptions idiom this feature exists to support:
//
//	deny-commands  "^show log$"
//	allow-commands "^show log 100$"
//	operator types: show log 100
//
// Deny-if-any denies it, because the prefix form `show log` matches the deny
// and has no allow exception. Unanimity preserves it for a different reason:
// the ALLOWLIST half is not evaluated per form as "must match on every form".
// An allow exception written against the FULL form (`^show log 100$`) is a
// deliberate operator grant for that exact command, so once tier 1/2 on the
// full form grants it, the shorter forms must not veto it merely by failing
// to re-match the exception — they were only ever widenings to let a DENY
// see the bare command past its arguments/pipe. The implementation therefore
// keeps two per-form verdicts apart:
//
//   - a form DENIED by the precedence tiers (a deny matched and beat/tied
//     the allow on that same form), or denied because a deny matched it
//     alone, vetoes the whole command — no other form's allow can outgrow
//     it, because lengths are never compared across forms;
//   - a form denied ONLY by the allowlist ("an allow is configured and this
//     form does not match it") does NOT veto, provided some other form is
//     affirmatively allowed. The allowlist requires the COMMAND to be
//     allowed somewhere; it does not require every truncated spelling of it
//     to spell-matched the allow pattern. But a command allowed NOWHERE is
//     still denied, and smuggled pipe text cannot create an affirmation for
//     the bare command: pipe text is measured only as part of the full form,
//     and the pipe-less/command forms are measured independently, so
//     `show configuration | except show interfaces` affirms nothing on the
//     `show configuration` form and is denied by the allowlist.
//
// The one escape from a truncated-form veto is the deny-with-exceptions
// geometry measured on command cores (see isCoreException): the carrying
// allow covers strictly more of the full core than the vetoing deny
// covers of the truncated core, and the allow does not match the
// truncated core at that vetoing extent. `^show log 100$` / `^show log$`
// over `show log 100` and `^show route table public-vrf$` /
// `^show route table` over its piped form are that geometry. `^show.*`
// over `show version | match .` is not: the wildcard matches the
// truncated `show version` at exactly the deny's extent, so the
// pipe-less veto stands. In the pipe-smuggling geometry the deny side is
// empty and the allow matches only inside the full form's pipe text,
// while the pipe-less form affirms nothing, so the allowlist denies it.

// EvaluateFormsWithPipe is EvaluateForms for a full form that carries an
// output pipe (its text after the first `|` is operator-controlled filter
// text). It marks the pipe boundary so an allow that matches ONLY inside
// that filter text cannot satisfy an allowlist for the bare command
// (#14686). Callers without a pipe use EvaluateForms unchanged.
func (c CompiledLoginRegexes) EvaluateFormsWithPipe(command, prefix string, more ...string) LoginRegexDecision {
	c.pipeBoundary = true
	return c.EvaluateForms(command, prefix, more...)
}

func (c CompiledLoginRegexes) EvaluateForms(command, prefix string, more ...string) LoginRegexDecision {
	// No regexes configured: this class opted out of fine-grained control and
	// the coarse permission bits are the whole story.
	if !c.allowSet && !c.denySet {
		return LoginRegexDecision{Allowed: true, DecidedBy: LoginRegexNeither,
			Reason: "no allow/deny regexes configured for this class"}
	}

	forms := make([]string, 0, 2+len(more))
	forms = append(forms, command)
	if prefix != command {
		forms = append(forms, prefix)
	}
	for _, f := range more {
		dup := false
		for _, g := range forms {
			if f == g {
				dup = true
				break
			}
		}
		if !dup {
			forms = append(forms, f)
		}
	}

	// Evaluate every form on its own terms. verdicts[0] is the full form.
	verdicts := make([]LoginRegexDecision, len(forms))
	for i, f := range forms {
		verdicts[i] = c.evaluateForm(f)
	}

	// A tier denial (deny matched and won/tied on that form, or deny alone
	// matched) on ANY form vetoes, subject only to the documented exception
	// override below. Cross-form length comparison never happens.
	// Track whether any non-full form is tier-denied by a deny that also
	// matches the full form's core. Such a deny is a REAL veto even when
	// an exception-shaped allow also matches: `^show log 100$` beside an
	// unanchored `show log` deny must still deny `show log 100 | match x`,
	// because the deny itself covers the full command, not just a
	// truncated spelling of it.
	denyingFormTier := false
	denyingCoreTier := false
	for _, f := range forms[1:] {
		if c.denySet && longestMatchLen(c.deny, f) >= 0 && longestMatchLen(c.deny, coreOf(forms[0])) >= 0 {
			denyingFormTier = true
		}
		if c.denySet && longestMatchLen(c.deny, coreOf(f)) >= 0 && longestMatchLen(c.deny, coreOf(forms[0])) >= 0 {
			if c.evaluateForm(coreOf(forms[0])).Allowed {
				continue
			}
			denyingCoreTier = true
		}
	}
	for i, v := range verdicts {
		if v.Allowed || !isTierDeny(v) {
			continue
		}
		if i == 0 {
			// The full form itself is tier-denied. With a pipe boundary
			// this can be the pipe-inflated reading of a command whose
			// pipe-less core is exception-allowed (the allow is
			// $-anchored to the core, so it cannot match the piped
			// spelling): when a pipe-less form is allowed on its core,
			// the full form's denial does not stand.
			if c.pipeBoundary && !denyingCoreTier {
				saved := false
				for _, f := range forms[1:] {
					if c.allowSet && c.evaluateForm(coreOf(f)).Allowed && longestMatchLen(c.allow, coreOf(f)) >= 0 {
						saved = true
					}
				}
				// Also saved when a pipe-less form carries the core
				// exception against the vetoing prefix (public-vrf).
				if c.allowSet {
					for _, f := range forms[1:] {
						for _, tf := range forms[1:] {
							if c.evaluateForm(coreOf(f)).Allowed && c.isCoreException(f, tf) {
								saved = true
							}
						}
					}
				}
				if saved {
					continue
				}
			}
			return v
		}
		// Truncated-form veto. It stands unless the full form carries the
		// deny-with-exceptions geometry (see isCoreException): the allow
		// covers strictly more of the full command's core than the vetoing
		// deny covers of this form's core, and the allow does not match
		// this form's core at that vetoing extent. A wildcard that matches
		// the truncated form at the deny's own extent (`^show.*` beside
		// `^show version$`) fails that test, so its veto stands.
		if !denyingFormTier && c.isCoreException(forms[0], forms[i]) && verdicts[0].Allowed && verdicts[0].DecidedBy == LoginRegexAllow {
			continue
		}
		// Non-pipe form of the same override: the full form is allowed
		// and carries the core-exception geometry against this vetoing
		// form, even though the deny also matches the full form's core
		// (an unanchored deny prefix such as `^show route table` beside
		// `^show route table public-vrf$`). denyingFormTier was computed
		// on raw forms; the core geometry is the precise test, and the
		// wildcard arm fails it (allow matches the truncated core at
		// the deny's own extent).
		if !c.pipeBoundary && verdicts[0].Allowed && c.isCoreException(forms[0], forms[i]) {
			continue
		}
		// Same override measured from a pipe-less allowed form: the
		// full form may be tier-denied only through its pipe text while
		// the pipe-less command form is the exception's own spelling.
		if c.pipeBoundary && !denyingCoreTier {
			saved := false
			for _, f := range forms[1:] {
				if c.allowSet && c.evaluateForm(coreOf(f)).Allowed && longestMatchLen(c.allow, coreOf(f)) >= 0 {
					saved = true
				}
			}
			if saved && c.isCoreException(forms[len(forms)-1], forms[i]) {
				continue
			}
		}
		return v
	}

	// No tier veto. With no pipe boundary the command is allowed iff some
	// form is affirmatively allowed; a pure allowlist miss on every form
	// denies. When no allow leaf is configured, evaluateForm already
	// allows every non-denied form, so this also covers the deny-only case.
	//
	// #14686 pipe arm: when a pipe boundary is present, an affirmation that
	// exists ONLY on the full (pipe-bearing) form must not suffice — that
	// affirmation may live entirely inside user-controlled filter text.
	// The pipe-less form (forms[1:], the command/prefix spellings) must
	// affirm as well. A denied pipe-less spelling was already vetoed
	// above; this arm handles the allowlist-only case where the pipe-less
	// form simply does not match the allow.
	if c.pipeBoundary {
		// The pipe-less COMMAND form (the last form: prefix is forms[1]
		// when present, command forms follow it) must affirm by core, or
		// carry the exception geometry against the prefix. Checking the
		// command form by its core is what lets `show log 100 | match x`
		// and the 9628 public-vrf exception through while the smuggled
		// `show configuration | except show interfaces` (command core
		// affirms nothing) still denies.
		for _, f := range forms[1:] {
			if denyingCoreTier {
				break
			}
			if c.allowSet && c.evaluateForm(coreOf(f)).Allowed && longestMatchLen(c.allow, coreOf(f)) >= 0 {
				if verdicts[0].Allowed {
					return verdicts[0]
				}
				return c.evaluateForm(coreOf(f))
			}
			if !c.allowSet && c.evaluateForm(coreOf(f)).Allowed {
				return verdicts[0]
			}
		}
		// Core-exception affirm: a pipe-less form whose core carries the
		// exception geometry against a vetoing truncated form affirms
		// the piped command even though its truncated spellings are
		// tier-denied (public-vrf: allow 27 on the command core vs deny
		// 16 on the truncated core, allow absent there).
		if !denyingCoreTier {
			for _, f := range forms[1:] {
				for _, tf := range forms[1:] {
					if c.isCoreException(f, tf) {
						if verdicts[0].Allowed {
							return verdicts[0]
						}
						return c.evaluateForm(coreOf(f))
					}
				}
			}
		}
		if verdicts[0].Allowed {
			allOverridden := len(forms) > 1
			for _, f := range forms[1:] {
				if !c.isCoreException(forms[0], f) {
					allOverridden = false
					break
				}
			}
			if allOverridden {
				return verdicts[0]
			}
		}
		for _, v := range verdicts[1:] {
			if !v.Allowed {
				return v
			}
		}
		if len(verdicts) > 1 {
			return verdicts[1]
		}
	}
	for _, v := range verdicts {
		if v.Allowed {
			return v
		}
	}
	// Nothing affirmed: report the full form's verdict (the allowlist
	// denial, which is the most informative spelling).
	return verdicts[0]
}

// isTierDeny reports whether a per-form verdict is a denial driven by a
// deny match (tiers 2/3 or deny-alone), as opposed to an allowlist miss
// ("an allow is configured and this form does not match it"), which carries
// DecidedBy=LoginRegexAllow with Allowed=false.
func isTierDeny(d LoginRegexDecision) bool {
	return !d.Allowed && d.DecidedBy == LoginRegexDeny
}

// coreOf returns the command core of a form: the text before its first
// pipe, trimmed. Pipe filter text is operator-controlled output filtering,
// not command identity, so exception extents are measured on cores only.
func coreOf(form string) string {
	if i := strings.Index(form, "|"); i >= 0 {
		return strings.TrimSpace(form[:i])
	}
	return form
}

// isCoreException reports the deny-with-exceptions geometry between the
// full form and a truncated form a deny vetoed, measured on command cores
// (pipe text excluded): the allow must match the full core, the deny must
// match the truncated core, and the allow's full-core extent must STRICTLY
// EXCEED the deny's truncated-core extent, while the allow must NOT match
// the truncated core at an extent >= that deny extent. The last clause is
// what excludes the wildcard arm of #14686: `^show.*` matches the
// truncated `show version` at exactly the anchored deny's 12 chars, so
// it is not an exception written for a longer command — it is the same
// coverage, and the veto stands. `^show log 100$` (12 on the full core,
// no match on `show log`) and `^show route table public-vrf$` (28 on the
// full core, no match on the `show route table` prefix) both qualify.
func (c CompiledLoginRegexes) isCoreException(full, truncated string) bool {
	if !c.allowSet || !c.denySet {
		return false
	}
	fullCore, truncCore := coreOf(full), coreOf(truncated)
	denyTrunc := longestMatchLen(c.deny, truncCore)
	allowFull := longestMatchLen(c.allow, fullCore)
	if allowFull < 0 {
		return false
	}
	if denyTrunc < 0 {
		// This truncated form carries no deny hit at all (e.g. a keyword
		// prefix shorter than the deny's text). The only way it can veto
		// is through the pipe-boundary affirmance arm, and the full core
		// affirming the allow is enough to override that: the exception
		// was written for the full core, not for this shorter spelling.
		return true
	}
	if allowFull <= denyTrunc {
		return false
	}
	if allowTrunc := longestMatchLen(c.allow, truncCore); allowTrunc >= denyTrunc {
		return false
	}
	return true
}

// evaluateForm decides a SINGLE form under the ordinary tiers. It is
// Evaluate's original body with both sides measured against the same
// string, so a length comparison can never borrow extent from a longer
// sibling spelling.
func (c CompiledLoginRegexes) evaluateForm(command string) LoginRegexDecision {
	allowLen, denyLen := -1, -1
	if c.allowSet {
		allowLen = longestMatchLen(c.allow, command)
	}
	if c.denySet {
		denyLen = longestMatchLen(c.deny, command)
	}

	// Both matched — the precedence tiers decide.
	if allowLen >= 0 && denyLen >= 0 {
		switch {
		case c.allowSrc == c.denySrc:
			// TIER 1 — UPSTREAM-DOCUMENTED. DO NOT "HARDEN" THIS TO DENY.
			//
			// Juniper: "if you configure the same command for both the
			// allow-commands and deny-commands statements, then the allow
			// operation takes precedence over the deny operation."
			//
			// Allow winning here reads like a fail-open and is not one. It is
			// the deny-with-exceptions idiom the feature exists to support, and
			// flipping it would be a parity break in the single case the vendor
			// documents BY NAME — found by the first operator who copies the
			// example out of Juniper's docs and watches it behave differently
			// here. "We made it safer" is a poor answer to that.
			//
			// Contrast tier 3 below, which IS ours to choose because upstream
			// says nothing about it.
			winner := c.family.IdenticalPatternWinner
			return LoginRegexDecision{
				Allowed:   winner == LoginRegexAllow,
				DecidedBy: winner,
				Reason: fmt.Sprintf(
					"allow and deny carry the identical pattern; %s wins for the %s family",
					winner, c.family.Name),
			}
		case allowLen > denyLen:
			// Tier 2, allow is the longer match.
			return LoginRegexDecision{Allowed: true, DecidedBy: LoginRegexAllow,
				Reason: fmt.Sprintf(
					"allow matched a longer extent than deny (%d > %d characters)",
					allowLen, denyLen)}
		case denyLen > allowLen:
			// Tier 2, deny is the longer match. THIS is the case that makes
			// "allow always wins" wrong.
			return LoginRegexDecision{Allowed: false, DecidedBy: LoginRegexDeny,
				Reason: fmt.Sprintf(
					"deny matched a longer extent than allow (%d > %d characters)",
					denyLen, allowLen)}
		default:
			// TIER 3 — OURS, AND DELIBERATELY FAIL-CLOSED.
			//
			// Upstream is genuinely silent here: Juniper addresses identical
			// patterns (tier 1) and differing matched lengths (tier 2), but not
			// a length TIE between two DIFFERENT patterns. So there is no parity
			// answer to be faithful to, and the choice is ours to make.
			//
			// Denying is the fail-closed direction, which is the right default
			// for an authorization decision nobody has specified. It is surfaced
			// as xpf's interpretation in the Reason string and recorded as ours
			// in docs/system-login.md, so a reader with a real Junos box knows
			// this is the sentence to go and verify rather than assuming we
			// copied it from somewhere.
			return LoginRegexDecision{Allowed: false, DecidedBy: LoginRegexDeny,
				Reason: fmt.Sprintf(
					"allow and deny matched equal extents (%d characters) with different "+
						"patterns; denied (xpf interpretation of an underspecified rule)",
					denyLen)}
		}
	}

	// Deny alone matched.
	if denyLen >= 0 {
		return LoginRegexDecision{Allowed: false, DecidedBy: LoginRegexDeny,
			Reason: "matched the class's deny regex"}
	}

	// An allow regex, once configured, is an ALLOWLIST: anything it does not
	// match is denied, even with no deny regex present at all.
	if c.allowSet {
		if allowLen >= 0 {
			return LoginRegexDecision{Allowed: true, DecidedBy: LoginRegexAllow,
				Reason: "matched the class's allow regex"}
		}
		return LoginRegexDecision{Allowed: false, DecidedBy: LoginRegexAllow,
			Reason: "an allow regex is configured and this command does not match it"}
	}

	// Only a deny was configured and it did not match.
	return LoginRegexDecision{Allowed: true, DecidedBy: LoginRegexNeither,
		Reason: "did not match the class's deny regex"}
}
