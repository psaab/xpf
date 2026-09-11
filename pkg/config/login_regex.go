package config

import (
	"fmt"
	"regexp"
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
// against BOTH the full canonical string and the argument-free command prefix
// and taking the LONGER match for that side.
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
// WHY THE MAX-PER-SIDE SHAPE RATHER THAN "DENY IF EITHER MATCHES". The obvious
// fix — deny when either form matches a deny pattern — BREAKS the
// deny-with-exceptions idiom this feature exists to support:
//
//	deny-commands  "^show log$"
//	allow-commands "^show log 100$"
//	operator types: show log 100
//
// "deny if either" denies it, because the prefix `show log` matches the deny.
// Taking the max per side instead lets the DOCUMENTED longest-match precedence
// decide: deny matches 8 characters (on the prefix), allow matches 12 (on the
// full string), tier 2 gives it to allow, and the operator's explicit exception
// survives. The tiers are unchanged; only the strings each side is measured
// against widen.
//
// The direction is safe by construction: a side's match length can only grow,
// and growth on the ALLOW side needs a pattern that matches the bare command —
// which is an allow the operator wrote.
//
// #9628 adds forms rather than a third parameter shape: the local gate also
// measures the command WITHOUT its output pipe, so an anchored deny such as
// `^show version$` still covers `show version | match .`. The same max-per-side
// rule applies to every form, so the widening direction is unchanged.
func (c CompiledLoginRegexes) EvaluateForms(command, prefix string, more ...string) LoginRegexDecision {
	// No regexes configured: this class opted out of fine-grained control and
	// the coarse permission bits are the whole story.
	if !c.allowSet && !c.denySet {
		return LoginRegexDecision{Allowed: true, DecidedBy: LoginRegexNeither,
			Reason: "no allow/deny regexes configured for this class"}
	}

	longest := func(re *regexp.Regexp) int {
		best := longestMatchLen(re, command)
		if prefix != command {
			if n := longestMatchLen(re, prefix); n > best {
				best = n
			}
		}
		for _, form := range more {
			if form != command {
				if n := longestMatchLen(re, form); n > best {
					best = n
				}
			}
		}
		return best
	}

	allowLen, denyLen := -1, -1
	if c.allowSet {
		allowLen = longest(c.allow)
	}
	if c.denySet {
		denyLen = longest(c.deny)
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
