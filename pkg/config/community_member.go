package config

import (
	"fmt"
	"regexp"
	"strings"
)

// CommunityRegexChars are the characters whose presence in a community member
// forces pkg/frr to render the whole definition as an FRR `expanded`
// community-list rather than a `standard` one (#2643). This is the SSOT for
// that classification; pkg/frr's communityMemberIsRegex reads it so the render
// decision and the commit gate below cannot disagree about which members FRR
// will run through regcomp.
const CommunityRegexChars = `*.+?^$[]()|\{}`

// CommunityMemberIsRegex reports whether a member forces the expanded list
// kind. FRR does NOT allow one list name to be both standard and expanded, so
// the decision is per-DEFINITION: if any member is a regex, the ENTIRE
// definition renders as expanded and EVERY member is compiled as a POSIX ERE.
func CommunityMemberIsRegex(member string) bool {
	return strings.ContainsAny(member, CommunityRegexChars)
}

// ValidCommunityMember reports why a `policy-options community` member cannot
// be rendered into frr.conf, or nil when it can.
//
// xpf renders one `bgp community-list <kind> <name> permit <member>` line per
// member. Two values break that line rather than narrowing it:
//
//   - an EMPTY member renders the command with no argument, which FRR rejects
//     as incomplete;
//   - a member that forces the EXPANDED list kind but is not a valid POSIX
//     extended regular expression fails FRR's regcomp at config load.
//
// Either is a CMD_WARNING_CONFIG_FAILED, and a single such failure exits the
// whole vtysh add-batch non-zero — so it does not merely lose this one
// community-list, it fails the ENTIRE frr-reload and leaves every dynamic
// routing change stale. That is the reasoning #6686 recorded for as-path
// regexes; it applies here unchanged, and this is the sibling gate it never
// got (#8449).
//
// SCOPE, deliberately narrow. A member that renders and compiles today keeps
// committing: this gate rejects only what provably breaks the reload. It used
// not to enumerate the well-known community names, because that was a claim
// about ANOTHER PROGRAM'S grammar that nothing in this repo could verify, and a
// gate that over-approximates would false-reject working configs.
//
// #9490 retires that constraint with evidence rather than overriding it: FRR
// stable/10.6's own parser (bgpd/bgp_community.c community_gettoken and
// community_valid) is the source for frrStandardCommunityLiteral. So a non-regex
// member is now checked against exactly what that parser accepts, and an
// alphanumeric token FRR rejects (`xpfbogus9206`, the Junos-only
// `no-export-subconfed`, a large community A:B:C) no longer commits.
//
// What did NOT survive is the assumption that the excluded class was
// unreachable. The original note said "FRR would reject a bogus literal too"
// and deferred, citing #8449 as tracking the residual. #8449 is CLOSED, so the
// residual was documented here and tracked NOWHERE — and it is reachable
// today: the lexer rejects a bare `@` only in the UNQUOTED spelling, so
// `members "@evil"` commits clean and renders
// `bgp community-list standard C1 permit @evil` into frr.conf (#8934).
//
// So this gate also rejects a NON-REGEX member carrying a character that
// cannot appear in any community literal — see badLiteralCharCommunityMember.
// That is a claim about CHARACTERS, supportable from here, rather than a claim
// about FRR's accepted name set, which is not.
//
// The check is regexp.CompilePOSIX, Go's POSIX-ERE mode, the same dialect FRR
// compiles with REG_EXTENDED. Where the engines differ they differ in the SAFE
// direction: Go is stricter, so a pattern rejected here is at worst one glibc
// would have accepted with undefined semantics.
//
// Control characters are NOT re-checked here: the strict #1798 commit gate
// rejects them, and pkg/frr's sanitizeFRRValue is the render-side belt for the
// leniently-loaded case (#4097).
func ValidCommunityMember(member string) error {
	if strings.TrimSpace(member) == "" {
		return fmt.Errorf("empty community member")
	}
	if !CommunityMemberIsRegex(member) {
		// NON-REGEX members render as a `standard` community-list, which FRR
		// accepts only as a literal: ASN:VALUE, a large-community A:B:C, or a
		// well-known name. Those are spelled with alphanumerics, `:`, `-` and
		// `_`. A character outside that set cannot be part of any of them, so
		// the rendered line is a CMD_WARNING_CONFIG_FAILED and takes the whole
		// frr-reload with it.
		//
		// DELIBERATELY LIMITED TO NON-REGEX MEMBERS. In an `expanded` list the
		// same character is an ordinary literal inside a POSIX ERE and regcomp
		// accepts it, so rejecting it there would false-reject something FRR
		// takes -- the over-approximation this gate's scope note warns about.
		// The regex branch is covered by the CompilePOSIX check below.
		if bad, ok := badLiteralCharCommunityMember(member); ok {
			return fmt.Errorf("contains %q, which cannot appear in a community "+
				"literal (ASN:VALUE or a well-known name -- alphanumerics, `:`, "+
				"`-` and `_`). It carries no regex "+
				"metacharacter (%s) so it renders into an FRR `standard` "+
				"community-list, which FRR rejects at config load -- and a "+
				"single rejected line exits the whole vtysh add-batch non-zero, "+
				"failing the ENTIRE frr-reload and leaving every dynamic routing "+
				"change stale", bad, CommunityRegexChars)
		}
		// #9490: the character check admits any alphanumeric token, so
		// `members [ 65000:1 xpfbogus9206 ]` committed and rendered
		// `bgp community-list standard C permit xpfbogus9206`, which FRR
		// rejects. The note on badLiteralCharCommunityMember left the name
		// enumeration to "whoever has FRR's grammar in hand". It is now read
		// from FRR stable/10.6 bgpd/bgp_community.c (community_gettoken,
		// community_valid), and frrStandardCommunityLiteral mirrors it.
		if !frrStandardCommunityLiteral(member) {
			return fmt.Errorf("%q is not a community FRR accepts in a `standard` "+
				"community-list: each word must be ASN:VALUE with both parts "+
				"0..65535, or one of %s (FRR stable/10.6 community_gettoken). "+
				"A large community A:B:C or an extended community is neither, "+
				"and the rejected line fails the whole frr-reload",
				member, strings.Join(frrWellKnownCommunities, ", "))
		}
		return nil
	}
	if _, err := regexp.CompilePOSIX(member); err != nil {
		return fmt.Errorf("contains a regex metacharacter (%s) so it renders into an "+
			"FRR `expanded` community-list, but it is not a valid POSIX extended "+
			"regular expression: %w", CommunityRegexChars, err)
	}
	return nil
}

// badLiteralCharCommunityMember returns the first character of a NON-REGEX
// community member that cannot appear in an FRR community literal, and whether
// one was found.
//
// The allowed set is deliberately the union of the characters every literal
// form is SPELLED WITH, rather than an enumeration of the forms:
//
//   - `ASN:VALUE` -- digits and `:`
//   - well-known names (`no-export`, `no-advertise`, `no-export-subconfed`,
//     `local-AS`, `internet`, `graceful-shutdown`, ...) -- letters, `-`, `_`
//
// Naming the CHARACTERS was verifiable here when FRR's grammar was not, and it
// is strictly weaker than the enumeration: every literal FRR accepts is spelled
// from this set. It is kept as the first check because its message names the
// offending character. The enumeration it deferred is frrStandardCommunityLiteral
// (#9490), transcribed from FRR's parser.
func badLiteralCharCommunityMember(member string) (string, bool) {
	for _, r := range member {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == ':', r == '-', r == '_':
		// CONTROL CHARACTERS AND SPACE ARE DELIBERATELY NOT THIS GATE'S
		// BUSINESS. They already have dedicated handling that predates it: the
		// #1798 strict commit gate rejects control characters outright, and
		// pkg/frr's sanitizeFRRValue collapses them to a space at render time
		// so a leniently-loaded value cannot inject an frr.conf line (#4097).
		//
		// Claiming them here would not add protection, it would REPLACE that
		// behaviour -- an omitted definition instead of a sanitized rendered
		// one -- and #4097 asserts the sanitized line. Taking a decision that
		// another gate already made, in a change whose whole argument is
		// narrowness, is the wrong trade even when the outcome is defensible.
		case r < 0x20, r == 0x7f, r == ' ':
		default:
			return string(r), true
		}
	}
	return "", false
}

// frrWellKnownCommunities is the exact well-known name set FRR stable/10.6's
// community_gettoken recognises (bgpd/bgp_community.c). The match there is a
// prefix strncmp, but whatever follows the name is parsed as the next token,
// so `no-export-subconfed` (the Junos spelling) is rejected, and `internet` is
// not in the set at all.
var frrWellKnownCommunities = []string{
	"accept-own", "accept-own-nexthop", "blackhole", "graceful-shutdown",
	"llgr-stale", "local-AS", "no-advertise", "no-export", "no-llgr", "no-peer",
	"route-filter-translated-v4", "route-filter-translated-v6",
	"route-filter-v4", "route-filter-v6",
}

// frrStandardCommunityLiteral reports whether a non-regex member parses as
// FRR's `standard` community-list argument. That argument is one or more
// whitespace-separated communities, each a well-known name or ASN:VALUE with
// exactly one `:` and both parts 0..65535 (community_valid). Control bytes
// count as separators, which is what sanitizeFRRValue turns them into at
// render.
func frrStandardCommunityLiteral(member string) bool {
	mapped := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, member)
	words := strings.Fields(mapped)
	if len(words) == 0 {
		return false
	}
	for _, w := range words {
		if !frrCommunityWord(w) {
			return false
		}
	}
	return true
}

func frrCommunityWord(w string) bool {
	for _, n := range frrWellKnownCommunities {
		if w == n {
			return true
		}
	}
	asn, val, ok := strings.Cut(w, ":")
	return ok && communityPart16(asn) && communityPart16(val)
}

// communityPart16 reports whether p is a non-empty decimal 0..65535.
func communityPart16(p string) bool {
	if p == "" {
		return false
	}
	n := 0
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c < '0' || c > '9' {
			return false
		}
		n = n*10 + int(c-'0')
		if n > 65535 {
			return false
		}
	}
	return true
}
