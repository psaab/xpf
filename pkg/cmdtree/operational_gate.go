package cmdtree

import (
	"fmt"
	"strings"
)

// OperationalPipeConsumers lists the keyword-only operational commands whose
// handler parses a handler-level pipe (`| display <format>`) itself, with
// splitShowPipe. It is keyed by canonical command path. (Operational
// `show configuration | compare` is NOT supported; the handler refuses it and
// points at configuration mode.)
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
var OperationalPipeConsumers = map[string]bool{
	"show configuration": true,
}

// ValidateOperationalGate is the shared #16798 keyword-only gate, pipe-aware
// since #18664.
//
// The output pipe is not operational-tree grammar (#9628 made the same
// correction in the login-class gate). Running ValidateOperationalLine over
// the whole line judged the bare `|` as an unknown trailing keyword, so
// `show configuration | display set` was refused as `unknown show
// configuration command: |` before the handler that parses the pipe could
// run. The gate therefore validates only the words before the first bare `|`,
// so an unknown token BEFORE the pipe still refuses exactly as #16798 does.
//
// Removing the pipe from the judged words must not reopen #16798 for piped
// lines. A pipe placed directly under a keyword-only node is a shape #16798
// already refused: on master `show chassis | display set` exits 1 with
// `unknown show chassis command: |`. #18664 keeps that refusal and changes
// only its message, which now names the modifier. Admitting the pipe instead
// would hand it to a handler that prints help or runs the bare command and
// drops the modifier, exiting 0 (`clear security | display set`,
// `show chassis | display set`). The pipe position is located by asking the
// same validator about the words up to and including that `|`. The answer
// bad == "|" means the pipe sits under a keyword-only node, and only an
// OperationalPipeConsumers command may receive it. The keyword-only
// predicate stays defined once, in pkg/cmdtree.
func ValidateOperationalGate(words []string) error {
	cut := firstBarePipe(words)
	cmdWords := words
	if cut >= 0 {
		cmdWords = words[:cut]
	}
	if prefix, bad, ambiguous, ok := ValidateOperationalLine(cmdWords); ok {
		path := strings.Join(prefix, " ")
		switch {
		case ambiguous:
			return fmt.Errorf("ambiguous %s command: %s", path, bad)
		case strings.Contains(bad, "|"):
			// A `|` glued to a word is not the pipe operator on any
			// surface (the first-bare-pipe scan, cliterm.SplitPipe,
			// and the handlers' splitShowPipe all split on a bare `|`
			// word), so the token really is an unknown command word.
			// Say how to write what was meant.
			return fmt.Errorf("unknown %s command: %s (separate the pipe with spaces: %q)",
				path, bad, strings.Join(strings.Fields(strings.ReplaceAll(bad, "|", " | ")), " "))
		}
		return fmt.Errorf("unknown %s command: %s", path, bad)
	}
	if cut < 0 {
		return nil
	}
	prefix, bad, _, ok := ValidateOperationalLine(words[:cut+1])
	if !ok || bad != "|" {
		// The pipe follows a value slot, a leaf or an AcceptsArgs
		// tail: the handler's domain, unchanged by #18664.
		return nil
	}
	path := strings.Join(prefix, " ")
	if OperationalPipeConsumers[path] {
		return nil
	}
	return fmt.Errorf("syntax error: %q does not accept the output modifier %q",
		path, strings.Join(words[cut:], " "))
}

// firstBarePipe returns the first token that is exactly the output-pipe
// operator. Glued tokens such as `|display` and `configuration|display` are
// ordinary command words, not pipe delimiters.
func firstBarePipe(words []string) int {
	for i, word := range words {
		if word == "|" {
			return i
		}
	}
	return -1
}
