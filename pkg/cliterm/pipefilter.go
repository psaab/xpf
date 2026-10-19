package cliterm

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Junos-style output pipe filtering, shared by BOTH CLI surfaces: the
// in-process interactive CLI (pkg/cli) and the remote gRPC client (cmd/cli).
//
// WHY THIS LIVES HERE RATHER THAN BEING DUPLICATED. The two surfaces must agree
// on filter semantics, and a divergence between them is ALWAYS a bug, never a
// legitimate difference — #4968 is the proof: the remote copy lowercased both
// operands, so `| match Foo` matched `foo` on remote and not on local. Two
// copies can drift; one cannot. cliterm was already the established home for
// exactly this (the readline loop moved here "so there is one"), and it adds no
// dependency edge — both surfaces already import it, while cmd/cli deliberately
// does NOT import pkg/cli, which would drag the whole in-process CLI into the
// thin remote client.
//
// Everything here streams. match/except/find/no-more hold at most one line at a
// time; count keeps only a running tally; last keeps a bounded ring. None
// buffers the full output (#4731, #7210).

// SplitPipe splits a Junos command line into the command and its output-pipe
// suffix, e.g. `show interfaces | match ge-` -> ("show interfaces", "match",
// "ge-", true). Returns the line unchanged with ok=false when there is no pipe,
// or when the token after `|` is not a filter this CLI implements.
//
// WHY THIS IS HERE AND NOT DUPLICATED, same argument as FilterStream below it,
// and it is not hypothetical: the two surfaces carried byte-identical copies of
// this splitter while the FILTER they feed was unified by #7210 — so the half
// with a documented divergence bug (#4968: the remote copy lowercased both
// operands, so `| match Foo` matched `foo` remotely and not locally) got one
// implementation, and the half that decides WHERE THE COMMAND ENDS kept two.
//
// That half is now load-bearing for authorization. #7172 matches login-class
// deny regexes against the command, and Junos matches the pipe as part of it —
// `show configuration | save /tmp/x` writes a file, `| display set` reformats
// output a deny may be withholding. If the authorization gate and the
// dispatcher split the same line differently, they disagree about what the
// operator ran, and that disagreement IS the bypass. Two copies can drift; one
// cannot.
//
// The split is on the LAST unquoted " | ", so a QUOTED filter argument may
// itself contain a pipe (`| match "a | b"` -> arg `a | b`), and an
// unrecognized filter word returns the ORIGINAL line untouched rather than a
// truncated command — the fail-safe direction for a caller that is about to
// authorize what it gets back. An unquoted argument pipe
// (`| match a | b`) still resolves the trailing token as the filter word and
// declines whole, exactly as before (#15722).
//
// Quotes (#15722): a pipeArg entirely wrapped in matching single or double
// quotes has the quotes stripped (`| match "Physical interface"` filters on
// `Physical interface`, not `"Physical interface"`). The delimiter scan
// tracks quote state (both quote kinds, backslash-escaped quote/backslash
// inside double quotes) so a " | " inside a quoted region is data, never a
// delimiter — including a quoted region in the command part. An unterminated
// quote leaves the rest of the line unquoted-as-typed: a trailing
// `| match "a | b` is treated as an unquoted filter whose arg keeps its
// leading quote, while an unterminated quote before the only pipe hides
// that pipe, so the line declines whole. Quotes that do not wrap the whole
// argument (internal, mismatched, trailing-text) are data and stay.
func SplitPipe(line string) (cmd, pipeType, pipeArg string, ok bool) {
	idx := lastUnquotedPipeSep(line)
	if idx < 0 {
		return line, "", "", false
	}
	cmd = strings.TrimSpace(line[:idx])
	pipe := strings.TrimSpace(line[idx+3:])
	parts := strings.SplitN(pipe, " ", 2)
	pipeType = parts[0]
	if len(parts) > 1 {
		pipeArg = stripPipeArgQuotes(parts[1])
	}
	if IsPipeFilter(pipeType) {
		return cmd, pipeType, pipeArg, true
	}
	return line, "", "", false
}

// lastUnquotedPipeSep returns the index of the last " | " occurring outside
// any quoted region, or -1. Quote state is tracked in one forward scan:
// inside double quotes a backslash escapes the next byte (so `\"` does not
// close, and `\\` consumes both backslashes so the quote after them closes);
// inside single quotes a backslash is literal (POSIX shell rule). An
// unterminated quote swallows the rest of the line, so no later " | " is a
// delimiter.
func lastUnquotedPipeSep(line string) int {
	last := -1
	var quote byte // 0 when outside quotes, else '"' or '\''
	for i := 0; i < len(line); i++ {
		c := line[i]
		if quote != 0 {
			if quote == '"' && c == '\\' {
				i++ // escaped byte cannot close the quote
				continue
			}
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '"', '\'':
			quote = c
		case '|':
			if i > 0 && i+1 < len(line) && line[i-1] == ' ' && line[i+1] == ' ' {
				last = i - 1
			}
		}
	}
	return last
}

// stripPipeArgQuotes removes one pair of matching surrounding quotes from a
// pipe argument. Inside double quotes, `\"` and `\\` are unescaped (the same
// spellings the config lexer honours); other backslash sequences stay as
// typed, so a pattern like `"a\nb"` keeps its backslash for FilterStream.
// Inside single quotes nothing is unescaped. Anything that is not a whole
// argument wrapped in one matching pair — unquoted, internal, mismatched, or
// followed by more text — is returned unchanged.
func stripPipeArgQuotes(arg string) string {
	if len(arg) < 2 {
		return arg
	}
	q := arg[0]
	if q != '"' && q != '\'' {
		return arg
	}
	// Find the closing quote: it must be the final byte. In double quotes a
	// backslash-escaped byte cannot close.
	for i := 1; i < len(arg); i++ {
		if q == '"' && arg[i] == '\\' {
			i++
			continue
		}
		if arg[i] == q {
			if i != len(arg)-1 {
				return arg // closing quote is not at the end: quotes are data
			}
			inner := arg[1:i]
			if q == '\'' {
				return inner
			}
			return unescapeDoubleQuotedPipeArg(inner)
		}
	}
	return arg // unterminated: keep as typed
}

// unescapeDoubleQuotedPipeArg resolves \" and \\ inside a double-quoted pipe
// argument, leaving every other backslash sequence untouched.
func unescapeDoubleQuotedPipeArg(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) && (s[i+1] == '"' || s[i+1] == '\\') {
			b.WriteByte(s[i+1])
			i++
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// IsPipeFilter reports whether verb is an output filter SplitPipe splits off.
// It is the ONE list, for the same reason SplitPipe is one function: the
// authorization gate refuses a pipe it does not recognise (#9628), so a verb
// the dispatcher honours and the gate does not know would refuse a lawful
// command, and the reverse would authorize a pipe nobody reviewed.
func IsPipeFilter(verb string) bool {
	switch verb {
	case "match", "grep", "except", "find", "count", "last", "no-more":
		return true
	}
	return false
}

// MaxTailLines bounds the ring the `| last N` filter retains and grows,
// independent of the operator-supplied N (#5037). `show` is a read-only
// (PermView) command, so without a bound a viewer could run
// `show ... | last 2000000000` and force a ~32 GiB up-front []string
// allocation. 100,000 lines is far more tail than any operator needs, yet caps
// the ring's worst-case slice header at ~1.6 MiB (64-bit) plus the retained
// line strings.
const MaxTailLines = 100_000

// ParseLastCount parses the `| last N` operand. It defaults to 10, ignores a
// non-positive or unparseable N (Junos-compatible leniency), and clamps N to
// MaxTailLines so the retained/grown ring is bounded by a fixed operator cap
// rather than an untrusted operand (#5037).
func ParseLastCount(arg string) int {
	n := 10
	if arg != "" {
		if v, err := strconv.Atoi(arg); err == nil && v > 0 {
			n = v
		}
	}
	if n > MaxTailLines {
		n = MaxTailLines
	}
	return n
}

// LineSource is a one-line-lookahead reader. The lookahead is what lets a
// filter ask "is there more?" without reading the rest of the stream, which is
// what keeps the filters streaming rather than buffering.
// NewLineSource wraps src with the one-line lookahead the streaming filters
// and the pager both rely on.
func NewLineSource(src io.Reader) *LineSource {
	return &LineSource{r: bufio.NewReader(src)}
}

type LineSource struct {
	r       *bufio.Reader
	peeked  string
	hasPeek bool
	done    bool
}

// read pulls the next line directly from the underlying reader.
func (ls *LineSource) read() (string, bool) {
	line, err := ls.r.ReadString('\n')
	if len(line) == 0 && err != nil {
		ls.done = true
		return "", false
	}
	if err != nil {
		ls.done = true
	}
	return strings.TrimSuffix(line, "\n"), true
}

// Next returns the next line, or ("", false) at end of input.
func (ls *LineSource) Next() (string, bool) {
	if ls.hasPeek {
		ls.hasPeek = false
		return ls.peeked, true
	}
	return ls.read()
}

// HasMore reports whether another line is available, buffering it for the next
// next() call.
func (ls *LineSource) HasMore() bool {
	if ls.hasPeek {
		return true
	}
	if ls.done {
		return false
	}
	l, ok := ls.read()
	if !ok {
		return false
	}
	ls.peeked = l
	ls.hasPeek = true
	return true
}

// FilterStream reads newline-delimited output from src and applies a Junos-style
// output filter (match/grep/except/find/count/last/no-more), writing the result
// to out as each line is read.
//
// match/grep/except/find are CASE-SENSITIVE. Junos `| match` never case-folds
// (#4968).
//
// The line splitting is byte-identical to a
// strings.Split(output, "\n")-with-trailing-empty-dropped pass over the same
// input, so replacing a buffer-then-filter implementation with this one changes
// no output.
func FilterStream(src io.Reader, out io.Writer, pipeType, pipeArg string) {
	ls := NewLineSource(src)

	switch pipeType {
	case "match", "grep":
		for ls.HasMore() {
			line, _ := ls.Next()
			if strings.Contains(line, pipeArg) {
				fmt.Fprintln(out, line)
			}
		}
	case "except":
		for ls.HasMore() {
			line, _ := ls.Next()
			if !strings.Contains(line, pipeArg) {
				fmt.Fprintln(out, line)
			}
		}
	case "find":
		found := false
		for ls.HasMore() {
			line, _ := ls.Next()
			if !found && strings.Contains(line, pipeArg) {
				found = true
			}
			if found {
				fmt.Fprintln(out, line)
			}
		}
	case "count":
		count := 0
		for ls.HasMore() {
			ls.Next()
			count++
		}
		fmt.Fprintf(out, "Count: %d lines\n", count)
	case "last":
		n := ParseLastCount(pipeArg)
		// Circular buffer of the last n lines: slot i%n holds the i-th line,
		// overwriting the oldest once more than n have arrived. The ring GROWS
		// LAZILY (append until it holds n lines, then overwrite) so its memory
		// is O(min(n, lines produced)) — never O(operand), never pre-allocated
		// from an untrusted N (#5037). Only n lines are ever retained, not the
		// whole output.
		ring := make([]string, 0)
		count := 0
		for ls.HasMore() {
			line, _ := ls.Next()
			if len(ring) < n {
				ring = append(ring, line)
			} else {
				ring[count%n] = line
			}
			count++
		}
		total := count
		if total > n {
			total = n
		}
		for i := count - total; i < count; i++ {
			fmt.Fprintln(out, ring[i%n])
		}
	case "no-more":
		for ls.HasMore() {
			line, _ := ls.Next()
			fmt.Fprintln(out, line)
		}
	}
}
