package config

import (
	"fmt"
	"regexp"
	"strings"
)

// aspath_regex.go owns the two shared primitives for a `policy-options
// as-path <name> <regex>` definition: reconstructing the regex from the
// token tail the grammar packs onto ONE node, and deciding whether the
// resulting string can be rendered into frr.conf at all (#6686).
//
// Both are shared on purpose. The compiler (compiler_routing.go), the
// strict commit gate (compiler_validate_strict_routing.go) and the FRR
// renderer (pkg/frr/policy_render.go) must agree on what a valid as-path
// regex is: a divergence there is always a bug — either the commit gate
// rejects something the renderer would have emitted happily, or the
// renderer emits a line the gate believed it had already excluded.

// ASPathRegexFromTokens joins the token TAIL of an as-path definition back
// into one regular expression.
//
// The `policy-options as-path` grammar is `args: 2, multi: true`
// (schema_routing.go): the node's own Keys carry `["as-path", <name>,
// <regex>...]`, and `multi` absorbs every trailing token onto that same
// key list. A QUOTED regex — `as-path AP1 ".* 65000 .*"` — is one lexer
// string token and lands whole in Keys[2]. The UNQUOTED spelling of the
// same value — `as-path AP1 .* 65000 .*` — lexes as three identifier
// tokens and lands as Keys[2:] = [".*", "65000", ".*"].
//
// Reading Keys[2] alone therefore kept only the FIRST token of the
// unquoted spelling, silently compiling `.* 65000 .*` down to `.*` — the
// whole-path wildcard. A `from as-path AP1; then accept` term built on
// that definition accepts EVERY BGP path instead of only those transiting
// AS 65000: a route-leak / hijack-acceptance exposure that commits clean
// with zero warnings and displays the authored regex back verbatim in
// `show configuration` (#6686).
//
// Joining with a single space is faithful rather than a guess. The lexer
// only ever hands back identifier tokens here — every regex metacharacter
// that is also lexer syntax (`^`, `{`, `}`, `|`, `[`, `]`, `;`, `"`)
// either fails to lex unquoted or is stripped, so an unquoted regex that
// reaches this function is a whitespace-separated run of identifier
// tokens and re-joining them reconstructs the authored text (runs of
// whitespace collapse to one space, which an AS-path regex — matched
// against a single-space-separated AS_PATH string — treats identically).
// FRR takes the as-path regex as a REST-OF-LINE token (see the
// `bgp as-path access-list` render in pkg/frr/policy_render.go), so an
// embedded space survives the render intact. The one exception is a token the
// lexer stripped brackets from: `[0-9]+` arrives as `0-9`, `+` and joins to
// the valid-but-different `0-9 +`. That span is not faithful to anything, so
// the compiler flags it (asPathKeysHaveUnquotedBracket) and the strict gate
// rejects it with a quote-the-regex diagnostic instead of guessing (#9881).
//
// Empty tokens are skipped so a stray separator cannot introduce a double
// space. A tail of only empty tokens returns "" — the caller decides what
// an absent regex means.
func ASPathRegexFromTokens(tokens []string) string {
	parts := make([]string, 0, len(tokens))
	for _, tok := range tokens {
		if tok != "" {
			parts = append(parts, tok)
		}
	}
	return strings.Join(parts, " ")
}

// ValidASPathRegex reports why an as-path regex cannot be rendered into
// frr.conf, or nil when it can.
//
// xpf renders one `bgp as-path access-list <name> permit <regex>` line per
// definition. Two values break that line rather than narrowing it:
//
//   - an EMPTY regex renders `bgp as-path access-list AP1 permit` with no
//     argument, which FRR rejects as an incomplete command;
//   - a regex that is not a valid POSIX extended regular expression fails
//     FRR's regcomp at config load.
//
// Either one is a CMD_WARNING_CONFIG_FAILED, and a single such failure
// exits the whole vtysh add-batch non-zero — so it does not merely lose
// this one as-path list, it fails the ENTIRE frr-reload and leaves every
// dynamic routing change stale. That is why this is a validation gate and
// not a render-time shrug.
//
// The check is `regexp.CompilePOSIX`, Go's egrep-syntax (POSIX ERE) mode,
// which is the same dialect FRR compiles with REG_EXTENDED. Where the two
// engines differ they differ in the SAFE direction: Go is the stricter of
// the pair, so a pattern rejected here is at worst one glibc would have
// accepted with undefined semantics (a leading bare `*`, a Perl class
// escape POSIX reads as a literal) — an operator-visible commit error on
// a pattern that was not going to mean what it looked like, rather than a
// poisoned reload.
//
// Control characters are NOT re-checked here: the strict #1798 commit
// control-char gate already rejects them, and pkg/frr's sanitizeFRRValue
// is the render-side belt for the leniently-loaded case.
func ValidASPathRegex(regex string) error {
	if strings.TrimSpace(regex) == "" {
		return fmt.Errorf("empty regular expression")
	}
	if _, err := regexp.CompilePOSIX(regex); err != nil {
		return fmt.Errorf("not a valid POSIX extended regular expression: %w", err)
	}
	return nil
}

// asPathKeysHaveUnquotedBracket reports the span-level delimiter-loss
// evidence for an as-path regex span: whether any key of n at position from
// or later was authored inside a `[ ... ]` list WITHOUT quotes, or carries
// a tokenless-loss mark — brackets the lexer stripped with no token between
// them (an empty `[]` pair such as the POSIX `[]...]` char-class head, a
// stray `]`, or a trailing gap pair), attributed to the adjacent token
// (#9881, parent-review MEDIUM).
//
// At a single-value regex position brackets are pattern syntax, never
// grouping: a marked tail token means the lexer stripped a delimiter the
// operator wrote, so the joined Regex differs from the authored text and no
// reconstruction can recover it (`[0-9]+` and `[0-9] +` lex identically —
// and `[]0-9]+` leaves no inside token at all). A quoted token inside
// brackets (`[ "[0-9]+" ]`) is faithful text — the quotes defeat the
// bracket bit — so it does not report. A node with no provenance answers
// false: unknown, not bare.
//
// Callers pass the position where the REGEX starts (2 for an instance node,
// whose Keys[0:2] are the keyword and the name; 0 for a brace-body entry,
// whose keys are all value tokens) and MUST call it on the same span whose
// join became the Regex — the compiler prefers a non-empty instance tail and
// otherwise keeps the last non-empty body entry, and flagging a shadowed span
// would refuse a config whose effective regex is clean.
func asPathKeysHaveUnquotedBracket(n *Node, from int) bool {
	if n == nil {
		return false
	}
	for i := from; i < len(n.Keys); i++ {
		if n.KeyBracketed(i) && !n.KeyQuoted(i) {
			return true
		}
	}
	return false
}
