package config

import (
	"fmt"
	"regexp"
	"strings"
)

// #9595: an UNRECOGNIZED statement in an application body or term is recorded
// (UnknownDirectLeaves / UnknownTermLeaves), strict-rejected at commit, and
// only warned about on the tolerant load / HA peer-sync path. #9525 left it
// installed, because #6524's TestStrayStatementDoesNotDisarmSiblingLeaves
// decided that a stray statement must not disarm an otherwise well-formed
// application. That also left a misspelled `destination-poort 22` on
// `protocol tcp` installed as tcp-any.
//
// The unrecognized KEYWORD cannot separate the two cases without a
// string-similarity heuristic, and those rot. STRUCTURE can, as measured over
// 22 shapes in docs/log/9595.md. The statement is refused only when BOTH hold:
//
//   - The application is otherwise PROTOCOL-WIDE on a dimension its protocol
//     has: tcp/udp with neither destination-port nor source-port, or
//     icmp/icmpv6 with no icmp-type.
//   - The unrecognized run carries a CONSTRAINT-SHAPED token: a port spec
//     (validatePortSpec, named ports included), a decimal integer or range, or
//     a Junos ICMP/ICMPv6 type name (icmpTypeNames / icmp6TypeNames).
//
// Together these mean the lost statement could only have narrowed what the
// application matches, and losing it widened the application to the whole
// protocol. #6524's shape (tcp/8080 plus `bogus value`) keeps its port, and
// `bogus value` is not constraint-shaped, so it stays armed.
//
// The measured limits of the line:
//   - NOT refused: a MISSPELLED constraint lost BESIDE a retained one, for
//     example `destination-port 80; source-poort 1024` or `icmp-type 8;
//     icmp-cod 0`. It widens only inside the retained constraint, and
//     structurally it is identical to a numeric stray beside a retained
//     constraint (`inactivity-timout 30`). The #9603 decision keeps this as
//     the documented residual: every strict commit channel rejects both
//     spellings, so only text a looser build committed reaches here. A REAL
//     Junos statement xpf does not implement (`uuid ...` on tcp/135) is refused
//     by exact grammar instead (application_unimplemented_leaves_9603.go).
//   - REFUSED: a numeric or named-port stray on a protocol-wide application
//     (`bogus 8080`). Structurally it is identical to a lost port, so it fails
//     closed.
//
// An application-SET body is closed (`application`, `application-set`,
// `description`). An unrecognized member statement whose value RESOLVES as an
// application or application-set is therefore a misspelled member reference,
// and the set under-covers. That is refused too. A value that resolves to
// nothing is left alone.

var decimalIntegerOrRange9595 = regexp.MustCompile(`^[0-9]+(-[0-9]+)?$`)

// constraintShapedToken9595 reports whether tok has the shape of a match
// constraint's value.
func constraintShapedToken9595(tok string) bool {
	if tok == "" {
		return false
	}
	if validatePortSpec(tok) == nil || decimalIntegerOrRange9595.MatchString(tok) {
		return true
	}
	// A numeric ICMP type is already a decimal integer. The NAMED types come
	// from the compiler's own Junos tables, the way named ports come from
	// validatePortSpec: an application's icmp-type leaf takes only 0..255, so
	// a misspelled `icmp-typ echo-request` would otherwise install as icmp-any.
	key := strings.ToLower(tok)
	_, v4 := icmpTypeNames[key]
	_, v6 := icmp6TypeNames[key]
	return v4 || v6
}

// unknownStatementProtocolWide9595 returns why app's unrecognized statement is
// refused, or "" when it is not (see the file comment).
func unknownStatementProtocolWide9595(app *Application) string {
	if app == nil {
		return ""
	}
	tokens := append(append([]string(nil), app.UnknownDirectTokens...), app.UnknownTermLeaves...)
	if len(tokens) == 0 {
		return ""
	}
	proto := app.Protocol
	portWide := protocolIsPortBearing(proto) && app.DestinationPort == "" && app.SourcePort == ""
	icmpWide := protocolIsICMPFamily(proto) && app.ICMPType == nil
	if !portWide && !icmpWide {
		return ""
	}
	for _, tok := range tokens {
		if constraintShapedToken9595(tok) {
			return fmt.Sprintf(
				"unrecognized statement %q carries the constraint-shaped value %q while the application otherwise matches all of %q, so a match constraint was dropped",
				strings.Join(tokens, " "), tok, proto)
		}
	}
	return ""
}

// unknownMemberReferences9595 returns the values of set's unrecognized member
// statements that resolve as an application or application-set.
func unknownMemberReferences9595(set *ApplicationSet, apps *ApplicationsConfig) []string {
	if set == nil || apps == nil {
		return nil
	}
	var out []string
	for _, v := range set.UnknownMemberValues {
		_, isApp := ResolveApplication(v, apps.Applications)
		_, isSet := lookupApplicationSet(v, apps.ApplicationSets)
		if isApp || isSet {
			out = append(out, v)
		}
	}
	return out
}

// appendSubtreeKeys9595 appends every key of every node under nodes.
func appendSubtreeKeys9595(out []string, nodes []*Node) []string {
	for _, n := range nodes {
		if n == nil {
			continue
		}
		out = append(out, n.Keys...)
		out = appendSubtreeKeys9595(out, n.Children)
	}
	return out
}
