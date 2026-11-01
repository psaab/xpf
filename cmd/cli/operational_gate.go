package main

import (
	"fmt"
	"strings"

	"github.com/psaab/xpf/pkg/cmdtree"
)

// operationalPipeConsumers lists the keyword-only operational commands whose
// handler parses a handler-level pipe (`| display <format>`, `| compare`)
// itself, with splitShowPipe. It is keyed by canonical command path.
//
// Only keyword-only nodes need an entry. A pipe after a value slot, a leaf or
// an AcceptsArgs tail is outside the #16798 gate (ValidateOperationalLine
// returns ok=false there) and reaches its handler unchanged, which is why
// `show system rollback <N> | display set` and `show configuration
// security | display set` never needed listing. Output filters (`| match`,
// `| count`, ...) are not handler-level pipes either: dispatch peels them
// with cliterm.SplitPipe before dispatchOperational runs.
//
// A missing entry fails CLOSED with a pipe-specific syntax error, never as a
// silent success, so a new handler that starts parsing a pipe under a
// keyword-only node must be added here; TestOperationalPipeConsumers18664
// pins that every entry really reaches its RPC.
var operationalPipeConsumers = map[string]bool{
	"show configuration": true,
}

// validateOperationalLine is the #16798 keyword-only gate, pipe-aware since
// #18664.
//
// The output pipe is not operational-tree grammar (#9628 made the same
// correction in the login-class gate). Running ValidateOperationalLine over
// the whole line judged the bare `|` as an unknown trailing keyword, so
// `show configuration | display set` was refused as `unknown show
// configuration command: |` before the handler that parses the pipe could
// run. The gate therefore validates only the words before the first bare `|`
// (showPipeIndex, the handlers' own token rule), so an unknown token BEFORE
// the pipe still refuses exactly as #16798 does.
//
// Removing the pipe from the judged words must not reopen #16798 for piped
// lines. A pipe placed directly under a keyword-only node is the shape #16798
// refused, and most such handlers would print help or run the bare command
// and drop the modifier, exiting 0 (`clear security | display set`,
// `show chassis | display set`). The pipe position is located by asking the
// same validator about the words up to and including that `|`. The answer
// bad == "|" means the pipe sits under a keyword-only node, and only an
// operationalPipeConsumers command may receive it. The keyword-only
// predicate stays defined once, in pkg/cmdtree.
func validateOperationalLine(parts []string) error {
	cut := showPipeIndex(parts, nil)
	cmdWords := parts
	if cut >= 0 {
		cmdWords = parts[:cut]
	}
	if prefix, bad, ambiguous, ok := cmdtree.ValidateOperationalLine(cmdWords); ok {
		path := strings.Join(prefix, " ")
		switch {
		case ambiguous:
			return fmt.Errorf("ambiguous %s command: %s", path, bad)
		case strings.Contains(bad, "|"):
			// A `|` glued to a word is not the pipe operator on any
			// surface (showPipeIndex, cliterm.SplitPipe, pkg/cli
			// splitAtPipe all split on a bare `|` word), so the
			// token really is an unknown command word. Say how to
			// write what was meant.
			return fmt.Errorf("unknown %s command: %s (separate the pipe with spaces: %q)",
				path, bad, strings.Join(strings.Fields(strings.ReplaceAll(bad, "|", " | ")), " "))
		}
		return fmt.Errorf("unknown %s command: %s", path, bad)
	}
	if cut < 0 {
		return nil
	}
	prefix, bad, _, ok := cmdtree.ValidateOperationalLine(parts[:cut+1])
	if !ok || bad != "|" {
		// The pipe follows a value slot, a leaf or an AcceptsArgs
		// tail: the handler's domain, unchanged by #18664.
		return nil
	}
	path := strings.Join(prefix, " ")
	if operationalPipeConsumers[path] {
		return nil
	}
	return fmt.Errorf("syntax error: %q does not accept the output modifier %q",
		path, strings.Join(parts[cut:], " "))
}
