package config

import "fmt"

// ParseError represents a configuration parse error with location. Message is
// retained for trusted, programmatic diagnostics; Error deliberately exposes
// only the position because parser messages can contain bytes from the
// configuration being parsed (which may include credentials).
type ParseError struct {
	Line    int
	Column  int
	Message string
}

func (e ParseError) Error() string {
	return fmt.Sprintf("line %d, column %d", e.Line, e.Column)
}

// maxParseDepth caps recursive-descent block nesting. parseStatement recurses
// into parseStatements for every `{ ... }` block, so a payload of deeply nested
// braces (`a{a{a{…}`) would otherwise grow the goroutine stack past Go's 1 GiB
// maxstacksize and abort xpfd with an unrecoverable `fatal error: stack
// overflow` (fable-review-164 H-2). 256 levels is far above any real Junos
// configuration; past it the parser records a ParseError and stops descending
// rather than recursing.
const maxParseDepth = 256

// maxParseErrors bounds the number of ParseError diagnostics a single parse
// RETAINS (#5827). The parser records one ParseError per bad token
// (parseStatements' TokenError branch, plus the statement-recovery / stray-brace
// / depth-cap paths); a hostile or corrupt payload — e.g. a run of invalid
// bytes up to the 16 MiB MaxConfigSize ceiling — otherwise produces MILLIONS of
// ParseError structs, each pinning a formatted message string, all held LIVE
// simultaneously until the parse returns. That is an unbounded-heap DoS on every
// entry point that parses a config blob: config load/commit, HA config-sync, and
// the CheckText validation path. Past the cap, addError/addErrorf stop retaining
// (and stop formatting) diagnostics and bump `suppressed`; Parse appends a single
// deterministic trailing "additional parse errors suppressed (N)" summary, so the
// retained diagnostic set — and thus the retained heap — is bounded to O(cap)
// regardless of input size. 64 is large enough to surface a useful set of real
// errors in a genuinely-broken config while keeping the bound tight. The lexer
// still drains the whole input in O(input) for deterministic termination; only
// the parser's RETENTION is capped. This mirrors the depth-cap suppression
// (skipToBlockClose) that already records one error for a pathological payload.
const maxParseErrors = 64

// maxParseNodes bounds the number of AST nodes a single parse BUILDS (#8597,
// muse-004 K14).
//
// #5827 capped the retained DIAGNOSTICS and said so precisely — "only the
// parser's RETENTION is capped". The tree itself was not capped, and a
// valid-syntax payload produces zero diagnostics, so it sails past that cap by
// construction.
//
// Measured (runtime.MemStats.HeapAlloc after GC, tree kept alive):
//
//	stmts=10000   live heap 1,824,960   -> 182 B/statement
//	stmts=100000  live heap 18,589,296  -> 185 B/statement
//	stmts=500000  live heap 92,647,960  -> 185 B/statement
//
// Linear, at roughly 60x the input bytes for the minimal `a;\n` statement. The
// 16 MiB MaxConfigSize ceiling therefore admits ~5.6M statements and about a
// GIGABYTE of live AST — built before any gate runs, on entry points that take
// untrusted input: configstore.CheckText validates a day-0 config-drive blob on
// first boot with no operator involved, and the same parser sits behind
// load/commit and HA config-sync.
//
// Neither existing cap covers it. maxParseDepth bounds STACK, and a flat
// `a;a;a;...` payload never nests. The group-expansion budget bounds EXPANSION
// and runs after the tree already exists.
//
// 200,000 is chosen against real configurations, not against the input ceiling.
// The largest configuration in this repository — test/incus/xpf-test.conf — is
// 250 statements, and the largest shipped one (docs/ha-cluster-userspace.conf)
// is 120. The cap is ~800x the former, bounds the live AST to about 37 MB at
// the measured 185 B/node, and sits in the same order as the existing
// 100,000-unit group-expansion budget. Deriving it from MaxConfigSize would
// defeat the purpose: 16 MiB of minimal statements IS 5.6M nodes.
const maxParseNodes = 200_000

// Parser implements a recursive descent parser for Junos configuration syntax.
type Parser struct {
	lexer  *Lexer
	errors []ParseError
	depth  int // current block-nesting depth (bounded by maxParseDepth)
	// nodes counts AST nodes built by this parse, bounded by maxParseNodes
	// (#8597). nodeBudgetExceeded latches once the cap is hit so every nesting
	// level unwinds immediately and Parse's stray-token loop stops rather than
	// re-entering parseStatements once per remaining token.
	nodes              int
	nodeBudgetExceeded bool
	// suppressed counts ParseError diagnostics dropped once errors reached
	// maxParseErrors (#5827). Parse folds it into a single trailing summary.
	suppressed int
}

// NewParser creates a new Parser for the given configuration text.
func NewParser(input string) *Parser {
	return &Parser{
		lexer: NewLexer(input),
	}
}

// Parse parses the input and returns the configuration tree.
//
// After the top-level statement list, the lexer MUST be at EOF. parseStatements
// breaks on a top-level TokenRBrace (a stray unmatched '}') identically to EOF,
// so historically a single stray brace made Parse return the partial tree with
// ZERO errors and silently drop every statement after the brace — a fail-open
// config-acceptance path (#4862): LoadOverride / CheckText only gate on
// len(errs)==0, so a truncated config (missing its security/default-policy
// tail) committed as if it were the authored file. Assert EOF here. A leftover
// '}' (or any other stray token) is a ParseError naming its position; rather
// than discard the trailing config on the floor we consume the stray token and
// resume parsing so BOTH the error and the remaining statements surface (the
// error still fails the commit — the tree is never silently truncated). Every
// iteration consumes at least the one stray token, so the loop always
// terminates. Correctly nested '{ ... }' blocks are unaffected: parseStatement
// consumes each block's own closing '}', so only an unmatched top-level '}'
// reaches this check.
func (p *Parser) Parse() (*ConfigTree, []ParseError) {
	children := p.parseStatements()
	for {
		tok := p.lexer.Peek()
		if tok.Type == TokenEOF {
			break
		}
		if p.nodeBudgetExceeded {
			// #8597: the budget error is already recorded; consuming the rest
			// of a hostile payload one stray token at a time would be O(input)
			// work for a parse that is already going to be rejected.
			break
		}
		p.addErrorf(tok.Line, tok.Column, "unexpected %s at top level (unmatched '}'?)", tok)
		p.lexer.Next() // consume the stray token to guarantee forward progress
		children = append(children, p.parseStatements()...)
	}
	// #5827: fold the suppressed-diagnostic count into a single deterministic
	// trailing summary. Appended DIRECTLY (bypassing the cap) so it always
	// surfaces exactly once even when the error set is at maxParseErrors, giving
	// a bounded len(errors) <= maxParseErrors+1. The first maxParseErrors errors
	// keep their parse order + line/column; this summary always sorts last.
	if p.suppressed > 0 {
		p.errors = append(p.errors, ParseError{
			Message: fmt.Sprintf("additional parse errors suppressed (%d)", p.suppressed),
		})
	}
	tree := &ConfigTree{Children: children}
	return tree, p.errors
}

// Config-edit verbs recognized at the start of a flat command line
// (ParseSetVerb). `set`/`delete` are the historical verbs; `deactivate`/
// `activate` (#2008 H1) toggle Node.Inactive so that `show | display set`
// output — which emits a `deactivate <path>` line for every inactive node
// (ast_format.go) — round-trips back to an inactive node on reload. A line
// with no recognized verb is treated as a bare path (verb "set").
const (
	verbSet        = "set"
	verbDelete     = "delete"
	verbDeactivate = "deactivate"
	verbActivate   = "activate"
)

// ParseSetCommand parses a single flat command and returns the path
// components, discarding the verb. Input: "set security zones
// security-zone trust interfaces eth0" returns ["security", "zones",
// "security-zone", "trust", "interfaces", "eth0"]. It accepts a `set`,
// `delete`, `deactivate`, or `activate` prefix (or no prefix). Callers that
// must apply the correct edit for a `deactivate`/`activate` line MUST use
// ParseSetVerb instead — ParseSetCommand collapses every verb to its path,
// so feeding it a `deactivate ...` line and then calling SetPath would
// re-add the node as ACTIVE.
func ParseSetCommand(input string) ([]string, error) {
	_, path, err := ParseSetVerb(input)
	return path, err
}

// ParseSetCommandQuoted is ParseSetCommand plus the per-token quote provenance
// SetPathQuoted needs (#6673). See ParseSetVerbQuoted.
func ParseSetCommandQuoted(input string) ([]string, []bool, error) {
	_, path, quoted, err := ParseSetVerbQuoted(input)
	return path, quoted, err
}

// ParseSetCommandGrouped is ParseSetCommandQuoted plus the per-token BRACKET
// GROUPING SetPathQuotedGrouped needs (#6668). See ParseSetVerbGrouped.
func ParseSetCommandGrouped(input string) (path []string, quoted, grouped []bool, err error) {
	_, path, quoted, grouped, err = ParseSetVerbGrouped(input)
	return path, quoted, grouped, err
}

// ParseSetVerb parses a single flat command into its verb and path. The
// verb is one of "set", "delete", "deactivate", or "activate"; a line with
// no recognized leading verb is reported as "set" with the whole line as
// the path (preserving the historical ParseSetCommand behavior where an
// unprefixed line is a bare path). #2008 H1: the `deactivate`/`activate`
// verbs make `show | display set` output round-trippable — the replay
// callers (configstore LoadSet / LoadMerge) switch on the returned verb to
// flip Node.Inactive instead of re-adding an active node.
func ParseSetVerb(input string) (verb string, path []string, err error) {
	verb, path, _, err = ParseSetVerbQuoted(input)
	return verb, path, err
}

// ParseSetVerbQuoted is ParseSetVerb plus per-token QUOTE PROVENANCE: quoted[i]
// reports whether path[i] was authored as a quoted string rather than a bare
// word (#6673).
//
// The flat-set path is one of the two ways an operator authors a bracketed
// list, and it is the one where the bracket lands on a CHILD node's keys
// (SetPath), so it must carry the same bit the hierarchical parser records in
// parseKeys — otherwise `set … commands [ "set" "system host-name x" ]` reaches
// the compiler indistinguishable from the single unquoted command
// `set … commands set system host-name x`, and the two members FUSE into a
// command the operator never wrote. Callers that do not care keep using
// ParseSetVerb / ParseSetCommand.
func ParseSetVerbQuoted(input string) (verb string, path []string, quoted []bool, err error) {
	verb, path, quoted, _, err = ParseSetVerbGrouped(input)
	return verb, path, quoted, err
}

// ParseSetVerbGrouped is ParseSetVerbQuoted plus per-token BRACKET GROUPING:
// grouped[i] reports whether path[i] was authored inside a `[ ... ]` list
// (#6668).
//
// The flat-set language re-splits a line into nodes at each keyword's SCHEMA
// ARITY, so it can express a container node carrying exactly `1 + args` keys
// and nothing wider. A bracket list authored at a container position —
//
//	security zones security-zone trust {
//	    interfaces {
//	        [ ge-0/0/0 ge-0/0/1 ] { host-inbound-traffic { system-services ssh; } }
//	    }
//	}
//
// — parses to ONE container with Keys=["ge-0/0/0","ge-0/0/1"], which FormatSet
// flattened to a bare token run. Replaying that run made `ge-0/0/0` the
// container and demoted `ge-0/0/1` to the first key of a LEAF, with the whole
// host-inbound body re-parented under it. The tokens all survived, so nothing
// downstream could notice; the config simply meant something else. Carrying the
// bracket restores the boundary the arity rule cannot infer.
//
// grouped is always the same length as path. A caller that does not need the
// grouping keeps using ParseSetVerbQuoted / ParseSetVerb / ParseSetCommand,
// which discard it — the pre-#6668 behaviour, unchanged.
func ParseSetVerbGrouped(input string) (verb string, path []string, quoted, grouped []bool, err error) {
	lexer := NewLexer(input)

	tok := lexer.Next()
	if tok.Type != TokenIdentifier {
		return "", nil, nil, nil, fmt.Errorf("expected identifier, got %s", tok.Type)
	}

	switch tok.Value {
	case verbSet, verbDelete, verbDeactivate, verbActivate:
		verb = tok.Value
	default:
		// No recognized prefix -- the first token is part of the path and
		// the verb defaults to set (a bare path). It reached here as a
		// TokenIdentifier, so it is bare by construction.
		verb = verbSet
		path = append(path, tok.Value)
		quoted = append(quoted, false)
		grouped = append(grouped, lexer.InBracket())
	}

	// #9881 trailing gap: brackets stripped after the line's last value
	// token precede no recorded token (EOF is not one). Capture the loss at
	// each loop exit and taint the last path element after the loop so the
	// span carries it.
	trailingLoss := false
	for {
		tok = lexer.Next()
		if tok.Type == TokenEOF {
			trailingLoss = lexer.LastGapLoss()
			break
		}
		if tok.Type == TokenSemicolon {
			// #5194 A3-b3-F7: a single trailing semicolon terminates the flat
			// command, but any token AFTER it is a second statement crammed onto
			// one line (e.g. `set system host-name fw; delete security policies`).
			// The pre-fix loop broke on the semicolon and SILENTLY discarded the
			// remainder while the caller (LoadSet applyEditLine) reported the line
			// applied — so the trailing `delete` never ran yet commit reported
			// success. Permit at most one terminating semicolon, then require EOF;
			// reject any subsequent token with its line/column.
			// The span's trailing gap is the one BEFORE this semicolon —
			// read it before the EOF check below scans (and reports) the
			// post-terminator gap instead.
			trailingLoss = lexer.LastGapLoss()
			if next := lexer.Next(); next.Type != TokenEOF {
				return "", nil, nil, nil, fmt.Errorf(
					"unexpected token %s after ';' at line %d, column %d (only one statement per line)",
					next.Type, next.Line, next.Column)
			}
			break
		}
		if tok.Type == TokenIdentifier || tok.Type == TokenString {
			path = append(path, tok.Value)
			quoted = append(quoted, tok.Type == TokenString)
			grouped = append(grouped, lexer.InBracket())
		} else {
			return "", nil, nil, nil, fmt.Errorf("unexpected token %s at line %d, column %d",
				tok.Type, tok.Line, tok.Column)
		}
	}

	if trailingLoss && len(grouped) > 0 {
		grouped[len(grouped)-1] = true
	}
	if len(path) == 0 {
		return "", nil, nil, nil, fmt.Errorf("empty path")
	}
	return verb, path, quoted, grouped, nil
}

// parseStatements parses zero or more statements until EOF or '}'.
func (p *Parser) parseStatements() []*Node {
	// Bound block-nesting recursion (H-2). parseStatement recurses back into
	// parseStatements for every `{` block; without this guard a deeply nested
	// brace payload overflows the goroutine stack (an unrecoverable throw, not
	// a panic). Past the cap we record a ParseError at the current position and
	// stop descending. The caller's error-recovery path then drains the
	// remaining tokens linearly (parseKeys yields nothing on `{`/`}`, so each
	// parseStatement consumes one token), so parsing terminates cleanly with an
	// error instead of crashing.
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > maxParseDepth {
		tok := p.lexer.Peek()
		p.addErrorf(tok.Line, tok.Column,
			"configuration nesting exceeds maximum depth of %d", maxParseDepth)
		// Drain the remainder of this over-deep block iteratively (no
		// recursion) so a pathological payload records exactly one error and
		// leaves the caller's matching '}' in place, rather than spamming one
		// error per leftover token and holding O(N) ParseError structs.
		p.skipToBlockClose()
		return nil
	}

	var nodes []*Node
	for {
		if p.nodeBudgetExceeded {
			// Latched: unwind every nesting level without parsing further.
			break
		}
		tok := p.lexer.Peek()
		if tok.Type == TokenEOF || tok.Type == TokenRBrace {
			break
		}
		if tok.Type == TokenError {
			p.addError(tok.Line, tok.Column, tok.Value)
			p.lexer.Next() // consume error token
			continue
		}
		if p.nodes >= maxParseNodes {
			p.noteNodeBudget(tok.Line, tok.Column)
			break
		}
		node := p.parseStatement()
		if node != nil {
			p.nodes++
			nodes = append(nodes, node)
		}
	}
	return nodes
}

// skipToBlockClose consumes tokens until the '}' that closes the block whose
// opening '{' the caller already consumed (or EOF), tracking brace balance
// iteratively so it never recurses. The closing '}' at balance 0 is left in
// place for the caller to consume. It is used only on the depth-cap path so a
// maliciously deep payload is drained in O(remaining) with no additional
// goroutine-stack growth (H-2).
func (p *Parser) skipToBlockClose() {
	balance := 0
	for {
		tok := p.lexer.Peek()
		switch tok.Type {
		case TokenEOF:
			return
		case TokenLBrace:
			balance++
			p.lexer.Next()
		case TokenRBrace:
			if balance == 0 {
				return // closes the caller's block; leave it for the caller
			}
			balance--
			p.lexer.Next()
		default:
			p.lexer.Next()
		}
	}
}

// inactiveMarker is the Junos `inactive:` statement prefix (#2008 H1).
// Because `:` is an identifier character (lexer.isIdentChar), the lexer
// tokenizes `inactive:` as a single identifier; the parser detects it as
// the leading key of a statement and lifts it into Node.Inactive rather
// than letting it mangle the node's identity (Keys[0]).
//
// The marker is recognized ONLY when the source token is a bare
// TokenIdentifier. A QUOTED `"inactive:"` (TokenString) is a literal value
// that merely equals the marker text (e.g. `description "inactive:";`) and
// must be preserved, so parseStatement gates both the leading and inline
// marker checks on the parallel token-kind slice from parseKeys (#4348).
const inactiveMarker = "inactive:"

// parserMarkers enumerates every bare identifier this parser interprets as
// STRUCTURE rather than as a key. It exists because such a marker is invisible
// to the lexer — it hands the text back as an ordinary identifier — so
// bareKeySafe (ast.go), which otherwise defers to the lexer, cannot discover
// one by re-lexing and must be told (#6523).
//
// CONTRACT: teaching parseStatement to treat a new bare identifier
// structurally REQUIRES adding it here, or the serializer will emit that text
// unquoted and the next Format→Parse will read it back as structure instead of
// as the key it was. Each marker's SEMANTICS stay in parseStatement — this is a
// registry of which texts are load-bearing, not of what they do, because a
// future merge directive would not share `inactive:`'s deactivation behaviour.
//
// TestParserMarkerVocabulary6523 gates the obligation over the realistic
// marker vocabulary: for each candidate word it asserts EITHER that the
// candidate is listed here and gets quoted, OR that the parser still treats it
// as an ordinary key. A parser change that promotes one of those words without
// updating this slice fails the second leg.
//
// LIMIT OF ENFORCEMENT — this is a CONTRACT, not mechanical single-source
// recognition. parseStatement still compares inactiveMarker directly (see the
// two comparisons below), and ast_format.go emits it directly, so the slice is
// not the only place the marker is known; it is the place bareKeySafe consults.
// The vocabulary test therefore only catches a promotion of a word it already
// enumerates. A marker OUTSIDE that candidate list — an unforeseen word — still
// depends on whoever adds it honouring this contract. Widening the candidate
// vocabulary is the cheap way to widen the net.
var parserMarkers = []string{inactiveMarker}

// parseStatement parses one statement: keys followed by ; or { block }.
// A leading `inactive:` marker is stripped from the keys and recorded on
// the returned Node so the statement's real identity (Keys) is unchanged
// and key matching, schema walks, and group merge keep working unmodified.
func (p *Parser) parseStatement() *Node {
	statementStart := p.lexer.Peek()
	keys, kinds, bracketed := p.parseKeys()
	if len(keys) == 0 {
		// Recovery: skip unexpected token
		tok := p.lexer.Next()
		if tok.Type != TokenEOF {
			p.addErrorf(tok.Line, tok.Column, "unexpected %s", tok)
		}
		return nil
	}

	// Detect a leading `inactive:` deactivation marker and lift it off the
	// keys. A lone `inactive:` with no following statement is a parse error
	// (Junos requires a statement to deactivate). The marker is recognized
	// ONLY as a bare identifier token — a QUOTED `"inactive:"` (TokenString)
	// is a literal value (e.g. `description "inactive:";`) and must be
	// preserved, never treated as a deactivation marker (#4348).
	inactive := false
	markerLine, markerCol := statementStart.Line, statementStart.Column
	if kinds[0] == TokenIdentifier && keys[0] == inactiveMarker {
		inactive = true
		keys = keys[1:]
		kinds = kinds[1:]
		bracketed = bracketed[1:]
		if len(keys) == 0 {
			p.addError(markerLine, markerCol,
				"inactive: marker must be followed by a statement")
			// Consume a trailing terminator if present so we don't loop.
			if t := p.lexer.Peek(); t.Type == TokenSemicolon || t.Type == TokenLBrace {
				p.skipStatementBody()
			}
			return nil
		}
	}

	// Detect an INLINE `inactive:` marker (#4335). Junos also collapses a
	// deactivated sub-statement onto its parent statement's line, e.g.
	//   address 2001:db8::7aef/128 inactive: port 32400;
	// where the `inactive:` deactivates the `port 32400` modifier, NOT the
	// address. Because `:` is an identifier character the lexer tokenizes
	// `inactive:` as one identifier, so it lands mid-keys instead of leading.
	// A node carries a single Inactive flag for its whole identity and cannot
	// mark only part of a flat leaf inactive; consistent with the #2008 H1
	// doctrine that a deactivated statement behaves as if it were absent, drop
	// the marker and every token it governs (the remainder of this statement)
	// from the active keys. The parent statement (here the address) stays
	// active; the governed sub-statement (the port) is simply absent, exactly
	// as a deactivated leaf would be for compilation. A leading marker is
	// already lifted above, so any remaining marker is strictly inline (index
	// > 0) and leaves at least the statement's identity key intact.
	// As with the leading marker, only a bare identifier `inactive:` counts;
	// a quoted `"inactive:"` value (TokenString) is preserved (#4348).
	for i, k := range keys {
		if i > 0 && kinds[i] == TokenIdentifier && k == inactiveMarker {
			keys = keys[:i]
			// Truncate the kinds in lockstep. The leading-marker branch above
			// already re-slices both; this one dropped only the keys, which
			// left kinds LONGER than keys for every statement carrying an
			// inline marker — invisible while kinds was consulted by index
			// against keys, but a length mismatch the moment anything derives
			// a per-key slice from it (#6673 quote provenance).
			kinds = kinds[:i]
			bracketed = bracketed[:i]
			// The governed tokens were only on the key line of a leaf; a
			// trailing `{ ... }` cannot follow an inline marker in valid
			// Junos, so nothing more to consume here.
			break
		}
	}

	line := p.lexer.Peek().Line
	col := p.lexer.Peek().Column

	// #6673: carry the source token KINDS onto the node as quote provenance.
	// Both marker paths above re-slice `kinds` in lockstep with `keys`, so it
	// still describes exactly the keys that survived; the loop is written over
	// `keys` (and range-checks `kinds`) so a future divergence degrades to
	// "provenance unknown" rather than panicking on a stale length.
	quoted := make([]bool, len(keys))
	for i := range keys {
		if i < len(kinds) {
			quoted[i] = kinds[i] == TokenString
		}
	}
	// #6668: same lockstep discipline as `kinds` — both marker paths re-slice
	// `bracketed` alongside `keys`, and the copy is range-checked so a future
	// divergence degrades to "provenance unknown" rather than panicking.
	brackets := make([]bool, len(keys))
	for i := range keys {
		if i < len(bracketed) {
			brackets[i] = bracketed[i]
		}
	}

	tok := p.lexer.Peek()
	switch tok.Type {
	case TokenLBrace:
		// Block: { children }
		p.lexer.Next() // consume {
		children := p.parseStatements()
		closeTok := p.lexer.Peek()
		if closeTok.Type == TokenRBrace {
			p.lexer.Next() // consume }
		} else {
			p.addErrorf(closeTok.Line, closeTok.Column, "expected '}', got %s", closeTok)
		}
		n := &Node{
			Keys:     keys,
			Children: children,
			Inactive: inactive,
			Line:     line,
			Column:   col,
		}
		n.setKeysQuoted(quoted)
		n.setKeysBracketed(brackets)
		return n

	case TokenSemicolon:
		// Leaf: keys ;
		p.lexer.Next() // consume ;
		n := &Node{
			Keys:     keys,
			IsLeaf:   true,
			Inactive: inactive,
			Line:     line,
			Column:   col,
		}
		n.setKeysQuoted(quoted)
		n.setKeysBracketed(brackets)
		return n

	default:
		// No semicolon or brace -- treat as implicit leaf, except at EOF
		// (#9899 F099). A top-level leaf missing its ';' at EOF is unfinished,
		// not tolerated: record the error and still carry the node for
		// recovery, like the missing-brace path above. Omission immediately
		// before '}' stays tolerated (scope only EOF).
		if tok.Type == TokenEOF {
			p.addErrorf(tok.Line, tok.Column, "expected ';', got %s", tok)
		}
		n := &Node{
			Keys:     keys,
			IsLeaf:   true,
			Inactive: inactive,
			Line:     line,
			Column:   col,
		}
		n.setKeysQuoted(quoted)
		n.setKeysBracketed(brackets)
		return n
	}
}

// skipStatementBody consumes a `;` or a balanced `{ ... }` block so error
// recovery after a malformed `inactive:` marker does not desync the parser.
func (p *Parser) skipStatementBody() {
	tok := p.lexer.Peek()
	switch tok.Type {
	case TokenSemicolon:
		p.lexer.Next()
	case TokenLBrace:
		p.lexer.Next() // consume {
		p.parseStatements()
		if p.lexer.Peek().Type == TokenRBrace {
			p.lexer.Next() // consume }
		}
	}
}

// parseKeys reads one or more identifiers/strings until { or ; or } or EOF.
// It returns the token VALUES and a parallel slice of the source token KINDS
// (TokenIdentifier vs TokenString). The kinds let the caller distinguish a
// bare identifier `inactive:` (a deactivation marker) from a quoted
// `"inactive:"` value that happens to equal the marker text (#4348) — the
// []string alone flattens the two into an indistinguishable string.
func (p *Parser) parseKeys() ([]string, []TokenType, []bool) {
	var keys []string
	var kinds []TokenType
	var bracketed []bool
	for {
		tok := p.lexer.Peek()
		if tok.Type == TokenIdentifier || tok.Type == TokenString {
			p.lexer.Next()
			keys = append(keys, tok.Value)
			kinds = append(kinds, tok.Type)
			// #6668: sampled AFTER Next, so it describes the token just
			// consumed. Peek restores the lexer's bracket state, so the
			// lookahead above cannot leak a '[' it stepped over into this bit.
			bracketed = append(bracketed, p.lexer.InBracket())
		} else {
			break
		}
	}
	// #9881 trailing gap: brackets stripped after the span's last value
	// token (`as-path AP1 .* []`) precede no recorded token, so the
	// per-token bit above never sees them. The breaking Peek just scanned
	// that gap (Peek lets gapLoss leak for exactly this read) — taint the
	// last key with it so the span carries the delimiter loss.
	if p.lexer.LastGapLoss() && len(bracketed) > 0 {
		bracketed[len(bracketed)-1] = true
	}
	return keys, kinds, bracketed
}

func (p *Parser) addError(line, col int, msg string) {
	// #5827: cap the retained diagnostic set. Past maxParseErrors, count the
	// drop and return WITHOUT appending — so a pathological all-error payload
	// never pins O(input) ParseError structs. Parse emits a single trailing
	// summary of the suppressed count.
	if len(p.errors) >= maxParseErrors {
		p.suppressed++
		return
	}
	p.errors = append(p.errors, ParseError{
		Line:    line,
		Column:  col,
		Message: msg,
	})
}

// addErrorf is addError with a lazily-formatted message: the fmt.Sprintf is
// evaluated ONLY when the diagnostic is actually retained (#5827). Past the cap
// it just bumps `suppressed`, so a hot error path (e.g. the stray-brace or
// statement-recovery loops) does not allocate a per-token message string it
// would immediately discard. The TokenError branch passes the lexer's
// already-materialized tok.Value through addError; every call site that would
// otherwise fmt.Sprintf a message uses addErrorf.
func (p *Parser) addErrorf(line, col int, format string, args ...any) {
	if len(p.errors) >= maxParseErrors {
		p.suppressed++
		return
	}
	p.errors = append(p.errors, ParseError{
		Line:    line,
		Column:  col,
		Message: fmt.Sprintf(format, args...),
	})
}

// noteNodeBudget records the single deterministic diagnostic for a parse that
// hit maxParseNodes, and latches so no further statements are parsed (#8597).
//
// Appended DIRECTLY, bypassing the maxParseErrors cap, for the same reason the
// #5827 suppressed-count summary is: a payload that exhausts the node budget
// may also have exhausted the diagnostic budget, and the ONE error that
// explains why the tree is truncated must never be the one that gets dropped.
// A truncated tree with no error would be silently accepted as the whole
// configuration.
func (p *Parser) noteNodeBudget(line, col int) {
	if p.nodeBudgetExceeded {
		return
	}
	p.nodeBudgetExceeded = true
	p.errors = append(p.errors, ParseError{
		Line:   line,
		Column: col,
		Message: fmt.Sprintf(
			"configuration exceeds the %d-statement parse budget; parsing stopped "+
				"(the largest configuration this product ships is under 300 statements — "+
				"a payload this large is corrupt or hostile, and building its tree would "+
				"cost roughly %d MB of live heap)",
			maxParseNodes, (maxParseNodes*185)/(1<<20)),
	})
}
