package cmdtree

import (
	"fmt"
	"strings"
)

// OperationalPipeConsumers lists operational commands whose handlers parse
// handler-level pipes themselves, such as `| display <format>` or
// `show configuration [<path>] | compare rollback <N>`. It is keyed by
// canonical command path. The handlers differ per surface: the remote handler
// splits with splitShowPipe, the local one with splitDisplayPipe.
//
// Only keyword-only nodes and pure keyword leaves need an entry. A pipe after
// a value slot or an AcceptsArgs tail is outside the #16798 gate
// (ValidateOperationalLine returns ok=false there) and reaches its handler
// unchanged. Unregistered terminal leaf pipes are refused by
// ValidateOperationalGate; this is why `show system rollback <N> | display
// set` and `show configuration security | display set` never needed listing:
// rollback is a value slot, and configuration is the registered consumer.
// Output filters (`| match`, `| count`, ...) are not handler-level pipes
// either: dispatch peels them with cliterm.SplitPipe before
// dispatchOperational runs.
// A missing entry fails CLOSED with a pipe-specific syntax error, never as a
// silent success, so a new handler that starts parsing a pipe under a
// keyword-only node or after a leaf must be added here;
// TestOperationalPipeConsumers18664 pins that every entry really reaches
// its handler.

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
//
// #18666: a pipe after a leaf — a childless keyword whose pre-pipe words
// canonicalize cleanly (`show version | display xml`) — was judged neither
// as a keyword-only failure (the pipe sits after a leaf, not under a node
// with keyword children) nor, on either console, by the leaf handler, which
// never looks at trailing words: it ran in its default format and exited 0,
// silently dropping the modifier. The same terminal rule therefore also
// refuses a bare pipe whose pre-pipe words canonicalize to exactly such a
// leaf, unless the command is an OperationalPipeConsumers entry. Words with
// a value head (`show configuration | display set`) resolve below it through
// an AcceptsArgs tail, so their line canonicalizes to the consumer path
// itself. A bare `|` also refuses: it is the same dropped-modifier class.
// Pipes after a value slot, an option tail or an AcceptsArgs tail whose
// pre-pipe line does NOT canonicalize are NOT leaves: they stay their
// handlers' domain, which parses or refuses them (`show system rollback
// <N> | display set`, `show configuration security | display set`, a `show
// interfaces <name>` value). Filter pipes (`| match`, `| count`, ...) are
// peeled by dispatch before the gate and never reach here.
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
	if ok && bad == "|" {
		path := strings.Join(prefix, " ")
		if OperationalPipeConsumers[path] {
			return nil
		}
		return fmt.Errorf("syntax error: %q does not accept the output modifier %q",
			path, strings.Join(words[cut:], " "))
	}
	// #18666: the pipe may sit after a pure keyword leaf. ValidateOperationalLine
	// leaves that position unjudged (ok=false, #16798), so check whether the
	// pre-pipe words resolve entirely as keywords to a childless keyword with
	// no value slot: if so, `|` is a dropped output modifier, not handler data.
	if path, leaf := canonicalLeafPath(cmdWords); leaf {
		if OperationalPipeConsumers[path] {
			return nil
		}
		return fmt.Errorf("syntax error: %q does not accept the output modifier %q",
			path, strings.Join(words[cut:], " "))
	}
	// The pipe follows a value slot or an AcceptsArgs tail: the handler's
	// domain, unchanged by #18664/#18666.
	return nil
}

// canonicalLeafPath reports whether words resolve as keywords only and end
// at a childless keyword with no value slot, returning the canonical path.
// A value or free-form argument ending is not a pure keyword leaf even if its
// accepting node has no keyword children.
func canonicalLeafPath(words []string) (string, bool) {
	if len(words) == 0 {
		return "", false
	}
	current := OperationalTree
	var node *Node
	canonicalLen := 0
	for _, word := range words {
		if node != nil && (node.IsTypedLeaf() ||
			(node.RequiresValue && node.HasDynamic())) {
			// A pending value slot cannot be skipped by resolving a child
			// keyword; Canonicalize rejects that shape.
			return "", false
		}
		name, next, _, resolved := resolveTreeWord(current, word)
		if !resolved {
			return "", false
		}
		canonicalLen += len(name) + 1
		node = next
		current = next.Children
	}
	if node == nil || len(node.Children) != 0 || node.HasDynamic() || node.IsTypedLeaf() {
		return "", false
	}
	// A childless AcceptsArgs node also has no keyword children, but its
	// dispatcher accepts a raw tail rather than a pure keyword command. Probe
	// one impossible trailing token through Canonicalize: it is consumed only
	// by an argument-tail handler. This keeps the gate from changing value /
	// free-form handler semantics without widening AcceptsArgs' scope.
	probe := make([]string, len(words)+1)
	copy(probe, words)
	probe[len(words)] = "\x00"
	if _, res := Canonicalize(OperationalTree, probe); res == CanonicalOK {
		return "", false
	}
	var path strings.Builder
	path.Grow(canonicalLen - 1)
	current = OperationalTree
	for i, word := range words {
		name, next, _, resolved := resolveTreeWord(current, word)
		if !resolved {
			return "", false
		}
		if i > 0 {
			path.WriteByte(' ')
		}
		path.WriteString(name)
		current = next.Children
	}
	return path.String(), true
}

// ClassifyComparePipe reports whether words contain an operational compare
// pipe and whether its `|` byte is glued to non-space text. It recognizes
// compare after skipped inline block comments, while measuring adjacency from
// the original tokens: a block-comment start after `|` and comment-end bytes
// before `|` both make the pipe glued. Pipe text inside a block comment is
// ignored. Line comments consume the rest of the command line.
func ClassifyComparePipe(words []string) (found, glued bool) {
	for i, offset := 0, 0; i < len(words); {
		word := words[i]
		if offset >= len(word) {
			i++
			offset = 0
			continue
		}
		if strings.HasPrefix(word[offset:], "/*") {
			nextWord, nextOffset, closed := skipCompareBlockComment(words, i, offset+2)
			if !closed {
				return found, glued
			}
			i, offset = nextWord, nextOffset
			continue
		}
		if strings.HasPrefix(word[offset:], "//") || word[offset] == '#' {
			return found, glued
		}
		if word[offset] == '|' {
			command, _ := comparePipeCommandAt(words, i, offset+1)
			if command == "compare" {
				found = true
				if offset > 0 || offset+1 < len(word) {
					glued = true
				}
			}
		}
		offset++
	}
	return found, glued
}

func skipCompareBlockComment(words []string, wordIndex, offset int) (int, int, bool) {
	for wordIndex < len(words) {
		word := words[wordIndex]
		if offset <= len(word) {
			if end := strings.Index(word[offset:], "*/"); end >= 0 {
				return wordIndex, offset + end + 2, true
			}
		}
		wordIndex++
		offset = 0
	}
	return wordIndex, 0, false
}

// ComparePipeCommand returns the first command and remaining words after a
// show-configuration pipe, skipping inline block comments. Its returned args
// alias words; line comments end the command tail.
func ComparePipeCommand(words []string) (command string, args []string) {
	return comparePipeCommandAt(words, 0, 0)
}

func comparePipeCommandAt(words []string, wordIndex, offset int) (string, []string) {
	for wordIndex < len(words) {
		word := words[wordIndex]
		if offset >= len(word) {
			wordIndex++
			offset = 0
			continue
		}
		if strings.HasPrefix(word[offset:], "/*") {
			var closed bool
			wordIndex, offset, closed = skipCompareBlockComment(words, wordIndex, offset+2)
			if !closed {
				return "", nil
			}
			continue
		}
		if strings.HasPrefix(word[offset:], "//") || word[offset] == '#' {
			return "", nil
		}
		return word[offset:], words[wordIndex+1:]
	}
	return "", nil
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
