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
}

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
	l.skipWhitespaceAndComments()

	if l.pos >= len(l.input) {
		return Token{Type: TokenEOF, Line: l.line, Column: l.column}
	}

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
	case '[':
		// Bracket list: [ a b c ] — skip brackets, treat contents as regular tokens
		l.advance()
		return l.Next()
	case ']':
		l.advance()
		return l.Next()
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

// Peek returns the next token without advancing.
func (l *Lexer) Peek() Token {
	savedPos := l.pos
	savedLine := l.line
	savedCol := l.column
	tok := l.Next()
	l.pos = savedPos
	l.line = savedLine
	l.column = savedCol
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
			l.advance() // /
			l.advance() // *
			for l.pos+1 < len(l.input) {
				if l.input[l.pos] == '*' && l.input[l.pos+1] == '/' {
					l.advance() // *
					l.advance() // /
					break
				}
				l.advance()
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

func (l *Lexer) readIdentifier(line, col int) Token {
	start := l.pos
	for l.pos < len(l.input) && isIdentChar(l.input[l.pos]) {
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
