// Package config implements the Junos configuration parser and data model.
package config

import (
	"fmt"
	"strings"
	"unicode"
)

// TokenType represents the type of a lexer token.
type TokenType int

const (
	TokenLBrace     TokenType = iota // {
	TokenRBrace                      // }
	TokenSemicolon                   // ;
	TokenIdentifier                  // unquoted word
	TokenString                      // "quoted string"
	TokenPipe                        // |
	TokenEOF
	TokenError
)

func (t TokenType) String() string {
	switch t {
	case TokenLBrace:
		return "'{'"
	case TokenRBrace:
		return "'}'"
	case TokenSemicolon:
		return "';'"
	case TokenIdentifier:
		return "identifier"
	case TokenString:
		return "string"
	case TokenPipe:
		return "'|'"
	case TokenEOF:
		return "EOF"
	case TokenError:
		return "error"
	default:
		return "unknown"
	}
}

// Token is a single lexer token.
type Token struct {
	Type   TokenType
	Value  string
	Line   int
	Column int
}

func (t Token) String() string {
	if t.Type == TokenIdentifier || t.Type == TokenString {
		return fmt.Sprintf("%s(%q)", t.Type, t.Value)
	}
	return t.Type.String()
}

// Lexer tokenizes Junos configuration text.
type Lexer struct {
	input  string
	pos    int
	line   int
	column int
	// pending holds a TokenError produced while skipping whitespace and
	// comments (an unterminated block comment) that must be surfaced by the
	// next call to Next. skipWhitespaceAndComments cannot return a token, so
	// the error is stashed here and drained at the top of Next.
	pending *Token
	// bracketDepth counts the '[' the skip loop has consumed and not yet
	// balanced with a ']'. The lexer still STRIPS the delimiters (#2419) —
	// this only records, for the token about to be returned, whether it was
	// authored INSIDE a bracket list.
	//
	// #6668: the flat-set language has no other way to say where one node's
	// key group ends. `set <parent> a b c` is re-split by SetPath at the
	// schema's arity, so a CONTAINER node carrying more keys than its arity
	// (`interfaces [ ge-0/0/0 ge-0/0/1 ] { ... }`) cannot be written down at
	// all: the surplus members are demoted to a leaf keyword and the body is
	// re-parented under them. Preserving the bracket lets the replay put the
	// boundary back exactly where it was authored.
	bracketDepth int
	// tokInBracket is bracketDepth > 0 as of the token most recently returned
	// by Next — OR the gap-loss mark when the preceding gap stripped
	// tokenless brackets (see gapLoss). It is sampled after the skip loop,
	// so it describes THAT token and not the lexer's current position.
	tokInBracket bool
	// gapLoss records whether the gap most recently scanned by Next (or by
	// Peek's internal Next) stripped tokenless brackets: an empty `[]` pair
	// closed within the gap, or a stray `]` at depth zero. It is sampled
	// into tokInBracket for the token the gap precedes, and ALSO persists
	// after the return so a span-end check can ask about a TRAILING gap —
	// brackets stripped after the span's last value token, which precede
	// no recorded token at all (LastGapLoss). Reset at every Next entry;
	// Peek deliberately does NOT restore it (see Peek).
	gapLoss bool
}

// InBracket reports whether the token most recently returned by Next was
// authored inside a `[ ... ]` list. It ALSO reports true when the token
// follows a gap in which brackets were stripped tokenlessly — an empty `[]`
// pair (including the POSIX `[]...]` char-class head) or a stray `]` at
// depth zero (#9881): those delimiters vanish leaving no inside token, so
// the following token carries the loss instead. Balanced, non-empty lists
// never mark this way — their delimiters always have a token between them.
// It is only meaningful immediately after a Next that returned an identifier
// or string; callers that do not need the grouping ignore it, which is every
// caller predating #6668.
func (l *Lexer) InBracket() bool { return l.tokInBracket }

// LastGapLoss reports whether the most recently scanned gap — the one just
// before the token Peek returned, or just before the EOF/semicolon that
// ended the loop — stripped tokenless brackets (#9881). Span-end checks
// (parseKeys, ParseSetVerbGrouped) taint the span's last key with it, so a
// trailing `[]` or stray `]` cannot silently narrow a value. Meaningful only
// immediately after the Peek/Next that scanned the span-ending gap.
func (l *Lexer) LastGapLoss() bool { return l.gapLoss }

// NewLexer creates a new Lexer for the given input string.
func NewLexer(input string) *Lexer {
	return &Lexer{
		input:  input,
		line:   1,
		column: 1,
	}
}

// Next returns the next token, advancing the position.
func (l *Lexer) Next() Token {
	// Gap-loss state is recomputed from scratch on every call (see gapLoss):
	// whatever a previous gap (or a Peek's internal scan) recorded is dead
	// the moment a new scan starts.
	l.gapLoss = false
	// sawOpenAtZero remembers a `[` consumed at depth zero during THIS
	// call's gap. If the gap later closes back to zero, the pair was
	// tokenless — no Next returned between the delimiters, so no token
	// carries the inside bit for them.
	sawOpenAtZero := false
	// Skip leading whitespace, comments, and bracket-list delimiters. The
	// bracket characters of a Junos list (`[ a b c ]`) are structural sugar:
	// the lexer strips them and yields the enclosed words as ordinary tokens
	// (#2419). Consuming them in this loop — rather than the old
	// `l.advance(); return l.Next()` self-recursion — keeps bracket handling
	// O(1) stack. Otherwise a payload of N consecutive '[' recurses one
	// goroutine-stack frame per bracket and a sub-4 MiB config overflows Go's
	// 1 GiB maxstacksize with an unrecoverable `fatal error: stack overflow`
	// (fable-review-164 H-2).
	for {
		l.skipWhitespaceAndComments()

		// An unterminated block comment detected during skipping surfaces as a
		// TokenError here so parseStatements records a ParseError and the load
		// / commit paths reject the config instead of silently accepting a
		// truncated one (matching the unterminated-string behavior, M-8
		// #4149). This MUST be checked BEFORE the EOF return: an unterminated
		// `/* */` consumes to EOF AND sets l.pending, so an EOF-first check
		// would swallow the error and return TokenEOF — reopening the #4147
		// fail-open (a truncated config parses with zero errors).
		if l.pending != nil {
			tok := *l.pending
			l.pending = nil
			return tok
		}

		if l.pos >= len(l.input) {
			return Token{Type: TokenEOF, Line: l.line, Column: l.column}
		}
		if c := l.input[l.pos]; c == '[' || c == ']' {
			// A bracketed IPv6 socket literal `[<addr>]:port` is NOT
			// bracket-list sugar — emit it whole so the address's inner
			// colons and its port survive (#5182). Only the '[' form can
			// open such a literal.
			if c == '[' {
				if tok, ok := l.tryBracketedEndpointLiteral(); ok {
					l.tokInBracket = l.bracketDepth > 0 || l.gapLoss
					return tok
				}
				if l.bracketDepth == 0 {
					sawOpenAtZero = true
				}
				l.bracketDepth++
			} else if l.bracketDepth > 0 {
				// Floor at zero: a stray ']' with no opener must not make the
				// depth negative and mark every LATER token as un-bracketed by
				// underflow. The parser reports the malformed input; the
				// grouping record simply stays off.
				l.bracketDepth--
				if l.bracketDepth == 0 && sawOpenAtZero {
					// Tokenless pair: the gap opened at zero and closed
					// within itself — `[]`, `[ ]`, or the POSIX `[]...]`
					// char-class head — so the delimiters vanish leaving
					// no inside token. The following token carries the
					// loss instead (#9881).
					l.gapLoss = true
				}
			} else {
				// Stray ']' at depth zero: floored (see above), and it
				// vanishes with no trace — no depth change for any later
				// token to observe. The following token carries the loss
				// instead (#9881).
				l.gapLoss = true
			}
			l.advance()
			continue
		}
		break
	}
	l.tokInBracket = l.bracketDepth > 0 || l.gapLoss

	ch := l.input[l.pos]
	line, col := l.line, l.column

	switch ch {
	case '{':
		l.advance()
		return Token{Type: TokenLBrace, Value: "{", Line: line, Column: col}
	case '}':
		l.advance()
		return Token{Type: TokenRBrace, Value: "}", Line: line, Column: col}
	case ';':
		l.advance()
		return Token{Type: TokenSemicolon, Value: ";", Line: line, Column: col}
	case '|':
		l.advance()
		return Token{Type: TokenPipe, Value: "|", Line: line, Column: col}
	case '"':
		return l.readString(line, col)
	default:
		if isIdentChar(ch) {
			return l.readIdentifier(line, col)
		}
		l.advance()
		return Token{
			Type:   TokenError,
			Value:  fmt.Sprintf("unexpected character: %c", ch),
			Line:   line,
			Column: col,
		}
	}
}

// tryBracketedEndpointLiteral recognizes a bracketed IPv6 socket literal
// `[<addr>]:port` at the current '[' and, on a match, returns it as ONE
// identifier token WITH the brackets and port intact. The lexer otherwise
// strips '[' / ']' as bracket-list sugar (#2419), which split a WireGuard
// `endpoint [2001:db8::1]:51820` into a bare host `2001:db8::1` plus an
// orphan `:51820` — dropping the port so the peer hydrated responder-only
// (#5182). Keeping the brackets means both net.SplitHostPort (Go commit
// gate) and SocketAddr::parse (Rust hydrate) recover host and port.
//
// The match is deliberately narrow so it can NEVER collide with a genuine
// bracket list: it requires '[' immediately followed (no interior
// whitespace) by a run of identifier chars, a closing ']', and then a ':'
// port separator. A list `[ a b c ]` has whitespace after '['; a
// single-element `[tcp]` has no trailing ':'; a spaceless `[a b]` has no
// ']' terminating the first run — all three fail the match and fall
// through to the existing strip path. Returns ok=false leaving l
// unmodified when the pattern does not match.
func (l *Lexer) tryBracketedEndpointLiteral() (Token, bool) {
	// Caller guarantees l.input[l.pos] == '['.
	j := l.pos + 1
	if j >= len(l.input) || !isIdentChar(l.input[j]) {
		return Token{}, false // '[' opens a list / empty list, not a literal
	}
	for j < len(l.input) && isIdentChar(l.input[j]) {
		j++
	}
	if j >= len(l.input) || l.input[j] != ']' {
		return Token{}, false // first run not closed by ']' — list sugar
	}
	j++ // consume ']'
	if j >= len(l.input) || l.input[j] != ':' {
		return Token{}, false // no ':port' — a bare `[x]`, keep stripping
	}
	for j < len(l.input) && isIdentChar(l.input[j]) {
		j++ // ':port' (and any trailing identifier chars, e.g. a scope)
	}
	line, col := l.line, l.column
	value := l.input[l.pos:j]
	for l.pos < j {
		l.advance()
	}
	return Token{Type: TokenIdentifier, Value: value, Line: line, Column: col}, true
}

// Peek returns the next token without advancing.
func (l *Lexer) Peek() Token {
	savedPos := l.pos
	savedLine := l.line
	savedCol := l.column
	savedPending := l.pending
	// #6668: Next consumes (and counts) any bracket delimiters it skips, so
	// the bracket state is part of the position Peek must restore. Without
	// this a Peek that stepped over a '[' left the depth incremented, and
	// every token after it — including tokens outside the list — reported as
	// bracketed.
	savedDepth := l.bracketDepth
	savedInBracket := l.tokInBracket
	tok := l.Next()
	l.pos = savedPos
	l.line = savedLine
	l.column = savedCol
	l.pending = savedPending
	l.bracketDepth = savedDepth
	l.tokInBracket = savedInBracket
	// gapLoss is deliberately NOT restored: the peeked gap may BE the
	// span's trailing gap (parseKeys breaks on the peeked `;`/`}`/EOF),
	// and its loss must survive to the span-end LastGapLoss check. Every
	// Next recomputes it from scratch, so the leak cannot contaminate a
	// later span — the next real Next overwrites it.
	return tok
}

func (l *Lexer) advance() {
	if l.pos < len(l.input) {
		if l.input[l.pos] == '\n' {
			l.line++
			l.column = 1
		} else {
			l.column++
		}
		l.pos++
	}
}

func (l *Lexer) skipWhitespaceAndComments() {
	for l.pos < len(l.input) {
		ch := l.input[l.pos]

		// Whitespace
		if ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' {
			l.advance()
			continue
		}

		// Line comment: # ... \n
		if ch == '#' {
			for l.pos < len(l.input) && l.input[l.pos] != '\n' {
				l.advance()
			}
			continue
		}

		// Block comment: /* ... */
		if ch == '/' && l.pos+1 < len(l.input) && l.input[l.pos+1] == '*' {
			startLine, startCol := l.line, l.column
			l.advance() // /
			l.advance() // *
			terminated := false
			for l.pos+1 < len(l.input) {
				if l.input[l.pos] == '*' && l.input[l.pos+1] == '/' {
					l.advance() // *
					l.advance() // /
					terminated = true
					break
				}
				l.advance()
			}
			if !terminated {
				// Reached EOF without a closing */. Consume the final byte the
				// pos+1 loop bound left behind and stash an error keyed to the
				// opening /* so the truncation is reported, not swallowed.
				for l.pos < len(l.input) {
					l.advance()
				}
				l.pending = &Token{
					Type:   TokenError,
					Value:  "unterminated block comment",
					Line:   startLine,
					Column: startCol,
				}
				return
			}
			continue
		}

		// Line comment: // ... \n
		if ch == '/' && l.pos+1 < len(l.input) && l.input[l.pos+1] == '/' {
			for l.pos < len(l.input) && l.input[l.pos] != '\n' {
				l.advance()
			}
			continue
		}

		break
	}
}

func (l *Lexer) readString(line, col int) Token {
	l.advance() // opening quote
	var b strings.Builder
	for l.pos < len(l.input) {
		ch := l.input[l.pos]
		if ch == '\\' && l.pos+1 < len(l.input) {
			l.advance()
			switch l.input[l.pos] {
			case '"':
				b.WriteByte('"')
			case '\\':
				b.WriteByte('\\')
			case 'n':
				b.WriteByte('\n')
			default:
				b.WriteByte('\\')
				b.WriteByte(l.input[l.pos])
			}
			l.advance()
			continue
		}
		if ch == '"' {
			l.advance()
			return Token{Type: TokenString, Value: b.String(), Line: line, Column: col}
		}
		b.WriteByte(ch)
		l.advance()
	}
	return Token{Type: TokenError, Value: "unterminated string", Line: line, Column: col}
}

// readIdentifier scans one identifier token.
//
// #8453: a '[' or ']' reached MID-TOKEN, outside any open bracket list, is a
// literal character of the value rather than list sugar.
//
// isIdentChar excludes both brackets, so before this the scanner stopped at one
// and Next's skip loop then consumed it as a list delimiter (#2419). For a value
// whose domain legitimately contains brackets that silently rewrote the value
// into a different, still-valid one:
//
//	as-path ap1 .*65000[0-9]*   ->  stored ".*65000 0-9 *"   (a valid regex that
//	                                 matches literal "65000 0-9", so the term
//	                                 never fires; ValidASPathRegex compiles it)
//	community c1 members a[b]c  ->  ["a","b","c"]            (one member became
//	                                 three — the route-map now matches a OR b OR c)
//
// The quoted spelling was preserved byte-for-byte through the same path, which
// is what made the diagnosis unambiguous.
//
// THE DISCRIMINATOR IS POSITION, NOT SHAPE. A Junos list opener always BEGINS a
// token — `[ a b c ]` — so a bracket the scanner meets after already consuming a
// character cannot be one. That is the same principle #5182's
// tryBracketedEndpointLiteral established for `[<addr>]:port`, narrowed further:
// that one looks FORWARD from a leading '[' and needs a ':port' suffix to stay
// unambiguous, while this one never fires on a leading '[' at all.
//
// "Never fires on a leading '['" is STRUCTURAL, not a condition checked here.
// Next's skip loop `continue`s on every '[' / ']' and breaks only on a character
// that is neither, so by the time this function runs `l.input[l.pos]` cannot be
// a bracket and the first iteration cannot see one. An earlier draft also tested
// `l.pos > start` for that; a mutation deleting it survived the whole package
// suite, because no input can distinguish it. It is gone rather than kept as
// belt-and-braces: an unfalsifiable condition reads as a guard while binding
// nothing, and the property it was meant to express is the skip loop's.
//
// GATED ON bracketDepth == 0, which is what keeps a genuine list intact. Inside
// `[ a b ]` the depth is 1, so the closing ']' still terminates `b` and closes
// the list; a spaceless `[a b]` likewise still yields `a`,`b`. Only a bracket met
// outside any list changes meaning, and outside a list there is no list for it to
// belong to.
//
// Deliberately NOT fixed here: a LEADING '[' — `as-path ap1 [0-9]+` — is
// genuinely indistinguishable from a one-element list by any local rule, and
// still requires quoting. See lexer_mid_token_bracket_8453_test.go. The
// quoting requirement is ENFORCED, not aspirational: the bracket bit travels
// with the token (InBracket) into the AST (Node.KeysBracketed), and the
// strict commit gate rejects an unquoted-bracketed as-path tail with a
// quote-the-regex diagnostic (#9881).
func (l *Lexer) readIdentifier(line, col int) Token {
	start := l.pos
	for l.pos < len(l.input) {
		ch := l.input[l.pos]
		if !isIdentChar(ch) {
			if !(l.bracketDepth == 0 && (ch == '[' || ch == ']')) {
				break
			}
		}
		l.pos++
		l.column++
	}
	return Token{Type: TokenIdentifier, Value: l.input[start:l.pos], Line: line, Column: col}
}

// isIdentChar returns true if ch is valid in a Junos identifier.
// Junos identifiers can contain letters, digits, hyphens, underscores,
// dots, slashes, colons, asterisks, plus signs, percent signs, and angle
// brackets.
// This handles IP addresses (10.0.1.0/24), interface names (eth0.0),
// wildcards (*), and group wildcards (<*>).
func isIdentChar(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') ||
		(ch >= 'A' && ch <= 'Z') ||
		(ch >= '0' && ch <= '9') ||
		ch == '-' || ch == '_' || ch == '.' ||
		ch == '/' || ch == ':' || ch == '*' || ch == '+' ||
		ch == '%' || ch == '=' || ch == ',' ||
		ch == '<' || ch == '>'
}

// IsIdentRune is the rune version for use in tab completion.
func IsIdentRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) ||
		r == '-' || r == '_' || r == '.' ||
		r == '/' || r == ':' || r == '*' || r == '+' ||
		r == '%' || r == '=' || r == ',' ||
		r == '<' || r == '>'
}
