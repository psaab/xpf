package cmdtree

import (
	"fmt"
	"strings"
)

// OperationalPipeConsumers lists keyword-only operational commands whose
// handlers parse handler-level pipes themselves, such as `| display <format>`
// or `show configuration [<path>] | compare rollback <N>`. It is keyed by
// canonical command path. The handlers differ per surface: the remote handler
// splits with splitShowPipe, the local one with splitDisplayPipe.
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
// pins that every entry really reaches its handler.
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
// already refused: on the remote console `show chassis | display set`
// exited 1 with `unknown show chassis command: |` before #18664. (The
// local console returned nil for the same line until #18668 shared this
// gate.) #18664 keeps that refusal and changes
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
			// pkg/cli's splitAtPipe, and the handlers' pipe splits
			// all split on a bare `|` word), so the token really is
			// an unknown command word.
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

// ClassifyComparePipe reports whether words contain an operational compare
// pipe and whether its `|` byte is glued to non-space text. The pipe may be
// a standalone token followed by `compare`, or appear in a token as
// `configuration|`, `|compare`, or `configuration|compare`. Gluing is
// determined by adjacency to bytes in the token, not by path/token shape;
// this also makes comment-ending bytes before `|` count as glued.
func ClassifyComparePipe(words []string) (found, glued bool) {
	for i, word := range words {
		for start := 0; start < len(word); {
			rel := strings.IndexByte(word[start:], '|')
			if rel < 0 {
				break
			}
			pipe := start + rel
			after := word[pipe+1:]
			compareFollows := after == "compare" ||
				(after == "" && i+1 < len(words) && words[i+1] == "compare")
			if compareFollows {
				found = true
				if pipe > 0 || after != "" {
					glued = true
				}
			}
			start = pipe + 1
		}
	}
	return found, glued
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
