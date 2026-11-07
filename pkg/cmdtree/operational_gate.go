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
// Only keyword-only nodes and pure keyword leaves whose handlers consume
// handler-level pipes need an entry. A pipe after a value slot or an
// AcceptsArgs tail is outside the #16798 gate (ValidateOperationalLine returns
// ok=false there) and reaches its handler unchanged. Otherwise a terminal leaf
// cannot consume arbitrary trailing words: ValidateOperationalGate refuses
// those suffixes unless the leaf is explicitly registered. This is why
// `show system rollback <N> | display set` and
// `show configuration security | display set` never needed listing: rollback
// is a value slot, and configuration is the registered consumer. Output
// filters (`| match`, `| count`, ...) are not handler-level pipes either:
// dispatch peels them with cliterm.SplitPipe before dispatchOperational runs.
// A missing entry fails CLOSED with a pipe-specific syntax error, never as a
// silent success, so a new handler that starts parsing a pipe under a
// keyword-only node or after a leaf must be added here;
// TestOperationalPipeConsumers18664 pins that every entry really reaches
// its handler.
//

var OperationalPipeConsumers = map[string]bool{
	"show configuration": true,
}

// ValidateOperationalGate is the shared #16798 keyword-only gate, pipe-aware
// since #18664.
//
// The output pipe is not operational-tree grammar (#9628 made the same
// correction in the login-class gate). The gate validates words before the
// first bare `|` so unknown tokens before the pipe still refuse exactly as
// #16798 does. It separately checks whether a pipe sits directly under a
// keyword-only node; only an OperationalPipeConsumers command may receive it.
//
// #18666 closes the other silent-drop shape: handlers may ignore words after
// a pure keyword leaf, so any unconsumed suffix after such a leaf is refused.
// This includes a bare `| display`, a trailing unknown command word, and a
// glued pipe token such as `|display` (which gets the same spacing hint as a
// glued pipe under a keyword-only node). The leaf walk excludes value slots
// and uses a Canonicalize probe to preserve childless AcceptsArgs handlers.
// Pipes after value slots or AcceptsArgs tails whose command path does not
// canonicalize to a pure leaf remain in their handlers' domain
// (`show system rollback <N> | display set`,
// `show configuration security | display set`). Implemented filters
// (`| match`, `| count`, ...) are peeled by dispatch before the gate.
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
		case strings.Contains(bad, "|") && !isQuotedOperationalWord(bad):
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
	if cut >= 0 {
		prefix, bad, _, ok := ValidateOperationalLine(words[:cut+1])
		if ok && bad == "|" {
			path := strings.Join(prefix, " ")
			if OperationalPipeConsumers[path] {
				return nil
			}
			return fmt.Errorf("syntax error: %q does not accept the output modifier %q",
				path, strings.Join(words[cut:], " "))
		}
	}
	// #18666: ValidateOperationalLine deliberately leaves trailing words after
	// a leaf to the handler (#16798). Some leaf handlers ignore those words,
	// so locate a pure keyword leaf anywhere in the line and reject any
	// unconsumed suffix, including a bare or glued pipe. Filters do not reach
	// this gate: dispatch strips implemented filter stages first.
	if path, consumed, optionalSelector, leaf := canonicalKeywordLeafPrefix(words); leaf && consumed < len(words) {
		if OperationalPipeConsumers[path] {
			return nil
		}
		optionsReentry := false
		if consumed < len(cmdWords) {
			if _, res := Canonicalize(OperationalTree, cmdWords); res == CanonicalOK {
				// #12527: an Options container may resume at its siblings
				// after a terminal-looking option (for example
				// `summary zone trust`). Those words are consumed by the
				// handler. A trailing pipe remains a separate modifier and
				// must still be checked below.
				if cut < 0 {
					return nil
				}
				consumed = cut
				optionsReentry = true
			}
		}
		tail := words[consumed:]
		if !optionsReentry && optionalSelector && tail[0] != "|" &&
			(!strings.Contains(tail[0], "|") || isQuotedOperationalWord(tail[0])) {
			// A small number of terminal handlers consume exactly one
			// optional selector. Metadata marks that bound explicitly;
			// it does not admit a pipe or any second trailing token.
			consumed++
			if consumed == len(words) {
				return nil
			}
			tail = words[consumed:]
		}
		switch {
		case tail[0] == "|":
			return fmt.Errorf("syntax error: %q does not accept the output modifier %q",
				path, strings.Join(tail, " "))
		case strings.Contains(tail[0], "|") && !isQuotedOperationalWord(tail[0]):
			return fmt.Errorf("unknown %s command: %s (separate the pipe with spaces: %q)",
				path, tail[0], strings.Join(strings.Fields(strings.ReplaceAll(tail[0], "|", " | ")), " "))
		default:
			return fmt.Errorf("unknown %s command: %s", path, tail[0])
		}
	}
	return nil
}

// canonicalKeywordLeafPrefix reports the first pure keyword leaf reached in
// words, including when unconsumed words follow it. A value or free-form
// argument ending is not a pure keyword leaf even if its accepting node has no
// keyword children.
func canonicalKeywordLeafPrefix(words []string) (path string, consumed int, optionalSelector bool, ok bool) {
	if len(words) == 0 {
		return "", 0, false, false
	}
	current := OperationalTree
	var node *Node
	canonicalLen := 0
	for i, word := range words {
		if node != nil && (node.IsTypedLeaf() ||
			(node.RequiresValue && node.HasDynamic())) {
			// A pending value slot cannot be skipped by resolving a child
			// keyword; Canonicalize rejects that shape.
			return "", 0, false, false
		}
		name, next, _, resolved := resolveTreeWord(current, word)
		if !resolved {
			return "", 0, false, false
		}
		canonicalLen += len(name) + 1
		node = next
		current = next.Children
		if i == len(words)-1 || len(node.Children) != 0 {
			continue
		}
		if node.HasDynamic() || node.IsTypedLeaf() {
			return "", 0, false, false
		}
		// A childless AcceptsArgs node has no keyword children either, but
		// accepts a free-form tail. Probe one impossible trailing token
		// through Canonicalize to preserve its handler domain without
		// widening AcceptsArgs' scope.
		probe := make([]string, i+2)
		copy(probe, words[:i+1])
		probe[i+1] = "\x00"
		if _, res := Canonicalize(OperationalTree, probe); res == CanonicalOK {
			return "", 0, false, false
		}
		var canonical strings.Builder
		canonical.Grow(canonicalLen - 1)
		current = OperationalTree
		for j, part := range words[:i+1] {
			name, next, _, resolved := resolveTreeWord(current, part)
			if !resolved {
				return "", 0, false, false
			}
			if j > 0 {
				canonical.WriteByte(' ')
			}
			canonical.WriteString(name)
			current = next.Children
		}
		return canonical.String(), i + 1, node.OptionalSelector, true
	}
	return "", 0, false, false
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

// isQuotedOperationalWord keeps pipe bytes inside single- or double-quoted
// command words as data. dispatchOperational's strings.Fields tokenization
// preserves the quote characters, and all pipe splitters ignore quoted pipes.
func isQuotedOperationalWord(word string) bool {
	if len(word) < 2 {
		return false
	}
	quote := word[0]
	return (quote == '\'' || quote == '"') && word[len(word)-1] == quote
}
