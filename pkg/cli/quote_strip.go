package cli

import (
	"strings"

	"github.com/psaab/xpf/pkg/cliterm"
)

// stripSurroundingQuotes removes ONE layer of matching leading/trailing single
// or double quotes, and otherwise returns s unchanged.
//
// The CLI tokenizer does not honor shell quoting, so an operator who wraps a
// multi-token value in quotes leaves literal quote characters on the first and
// last tokens. Three callers need that layer peeled: the `monitor traffic`
// pcap filter (libpcap rejects literal quotes), the commit comment, and the
// annotate comment.
//
// It lives here rather than beside the pcap filter because the latter two used
// strings.Trim with a quote CUTSET instead, and that is the bug which always
// follows from reaching for Trim to "remove surrounding quotes" (#7171): a
// cutset matches every leading and trailing byte in the set, balanced or not.
// A commit comment ending in a legitimate apostrophe -- `fix for users'` --
// silently became `fix for users` in the AUDIT JOURNAL. An audit record that
// quietly mutates what the operator typed is weaker evidence than one that does
// not; the property at stake is that the journal is verbatim, not how many
// characters were lost. Both callers now share this one implementation, so the
// rule cannot drift between them.
//
// Matched-pair only:
//
//	`"quoted"`      -> `quoted`   (the syntactic quotes this exists to peel)
//	`users'`        -> unchanged  (the defect)
//	`'mixed"`       -> unchanged  (a mismatched pair is not a pair)
//	`""text""`      -> `"text"`   (exactly one layer, not all of them)
//	`"unterminated` -> unchanged
//
// An unterminated leading quote is deliberately KEPT: it is what the operator
// typed, and preserving it is the same verbatim property as the apostrophe
// case. Guessing that they meant to close it is the behaviour being removed.
func stripSurroundingQuotes(s string) string {
	return cliterm.StripSurroundingQuotes(s)
}

// commitCommentFromArgs builds the commit comment from `commit comment ...`
// argv: join the tokens the CLI tokenizer split, then peel one quote layer.
//
// Extracted so the CALL SITE is testable, not just the helper (#7171). A test
// that calls stripSurroundingQuotes directly cannot see this site revert to
// strings.Trim with a cutset -- which is exactly what happened: the first
// version of this change had such a test, and reverting the call site produced
// zero failures across 968 tests. The value returned here is persisted to the
// audit journal, so the site is the thing that must be bound.
func commitCommentFromArgs(args []string) string {
	return stripSurroundingQuotes(strings.Join(args, " "))
}

// annotateCommentFromLine splits an `annotate <path> "comment"` line into the
// config path text and the comment, peeling one quote layer from the latter.
// Returns ok=false when the line carries no quoted comment at all.
//
// Extracted for the same reason as commitCommentFromArgs: this value is
// persisted into the stored configuration, and a test of the helper alone
// cannot see this site stop calling it.
func annotateCommentFromLine(line string) (pathText, comment string, ok bool) {
	return cliterm.AnnotateCommentFromLine(line)
}
