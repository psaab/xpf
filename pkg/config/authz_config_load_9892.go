package config

import (
	"fmt"
	"strings"
)

// #9892: `load` BYPASSED THE deny-configuration REGEXES ON TWO OF THREE
// SURFACES, AND THE CLI'S BYPASS WAS THE QUIET ONE.
//
// A `*-configuration` regex is an authorization control over configuration
// mutation, so a denied path must stay denied whatever verb carries it. `load`
// is the verb that can carry EVERY denied path at once — `load override`
// replaces the whole candidate and `load merge` can bring a whole denied
// subtree in one call (up to 16 MiB on REST).
//
// State before this file:
//
//   - gRPC: CLOSED by #9633, which evaluated set/merge content line by line and
//     refused override for a restricted class.
//   - REST: `load` was absent from restConfigMutationRoutes, recorded there as a
//     stated remaining gap.
//   - CLI: worse than absent. cli_dispatch.go DOES call checkConfigRegex on
//     every config-mode line INCLUDING `load` — the gate runs. It delegates to
//     configMutationPath, which returns ok=false for any verb not in
//     configMutationVerbs, and `load` is not in that map. So the gate executed,
//     declined to adjudicate, and returned nil. A reader auditing that path
//     sees a gate on it.
//
// ONE EVALUATOR, THREE CALLERS. The content parsing lives here rather than in
// each surface because two copies of "render hierarchical content as set lines"
// drift, and the drift is invisible: each copy looks right on its own. This is
// also why the gRPC implementation moved here rather than being duplicated —
// #9633's logic is the reference, and there is now exactly one of it.

// loadMutationVerbs are the first words whose lines can carry a mutation in
// a set-format body. They are collected verbatim only after IsFlatLoadLine
// has classified the WHOLE body using the store's routing predicate.
var loadMutationVerbs = map[string]bool{
	"set": true, "delete": true, "deactivate": true, "activate": true,
	"copy": true, "rename": true, "insert": true, "annotate": true,
}

// IsFlatLoadLine is the single flat-vs-hierarchical predicate shared by the
// load authorization gate and the config store (#10305).
//
// A load body is routed to the flat replay branch only when at least one line
// begins with a verb that applyEditLine can replay AND carries a path token.
// Keep this in pkg/config rather than copying the rule at either ingress: the
// gate must adjudicate the representation the store will actually apply.
func IsFlatLoadLine(line string) bool {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return false
	}
	switch fields[0] {
	case "set", "delete", "deactivate", "activate":
		return true
	default:
		return false
	}
}

// ClassifyLoadContent returns whether a load body routes to flat replay and
// the input with lexer-recognized comments replaced by whitespace. Comment
// removal is shared with authorization so a verb in comment prose cannot
// change which representation the store applies. An unterminated block
// comment is rejected instead of allowing a partial import.
//
// The token model here MUST mirror the real lexer (lexer.go). That lexer
// only recognizes a comment opener in its gap scanner
// (skipWhitespaceAndComments), i.e. where a token could START — never
// inside readIdentifier, which consumes '/', '*', '[' and ']' as ordinary
// identifier characters once a token has begun (#8453: a '[' met
// mid-token at bracket depth 0 is literal). This classifier therefore
// opens a comment only when NOT inside a bare token, and a '[' or ']'
// met mid-token does NOT end the token: `set ... host-name a[/*` is one
// identifier to both lexers, so no comment opens (#14145). Within a gap,
// the real lexer tries tryBracketedEndpointLiteral BEFORE consuming a
// token-initial '[' as list sugar (#5182): '['+identrun+']'+':'+identrun
// is ONE identifier, and since '/' and '*' are identifier characters a
// token-initial `[/*x]:1` (or `[//x]:1`) is such a literal, so no comment
// opens there either (#14572). Only a '[' that does not form an endpoint
// literal is list sugar the skip loop consumes, so the scanner stays at
// a token boundary and a '/*' after it is a comment.
func ClassifyLoadContent(content string) (flat bool, uncommented string, err error) {
	var b strings.Builder
	b.Grow(len(content))
	inBlock, inQuote, escaped, inToken := false, false, false, false
	for i := 0; i < len(content); i++ {
		ch := content[i]
		if ch == '\n' {
			b.WriteByte(ch)
			if !inQuote {
				inToken = false
			}
			continue
		}
		if inBlock {
			if ch == '*' && i+1 < len(content) && content[i+1] == '/' {
				b.WriteString("  ")
				i++
				inBlock = false
				inToken = false
				continue
			}
			b.WriteByte(' ')
			continue
		}
		if inQuote {
			b.WriteByte(ch)
			if escaped {
				escaped = false
			} else if ch == '\\' {
				escaped = true
			} else if ch == '"' {
				inQuote = false
				inToken = false
			}
			continue
		}
		if ch == '"' {
			inToken = false
			inQuote = true
			b.WriteByte(ch)
			continue
		}
		if ch == '#' || (!inToken && ch == '/' && i+1 < len(content) && content[i+1] == '/') {
			for i < len(content) && content[i] != '\n' {
				b.WriteByte(' ')
				i++
			}
			if i < len(content) {
				b.WriteByte('\n')
			}
			inToken = false
			continue
		}
		if !inToken && ch == '/' && i+1 < len(content) && content[i+1] == '*' {
			b.WriteString("  ")
			i++
			inBlock = true
			continue
		}
		// A token-initial '[' that forms a bracketed endpoint literal is
		// one identifier to the real lexer (#5182, modelled above): the
		// whole literal is token text, so no '/' inside it can open a
		// comment. A ']' met at a token boundary (list close or stray)
		// can likewise be immediately followed by such a literal.
		if !inToken && (ch == '[' || (ch == ']' && i+1 < len(content) && content[i+1] == '[')) {
			start := i
			if ch == ']' {
				start = i + 1
			}
			if end, ok := bracketedEndpointLiteralEnd(content, start); ok {
				for ; i < end; i++ {
					b.WriteByte(content[i])
				}
				i-- // the loop's i++ lands on the first byte past the literal
				inToken = true
				continue
			}
		}
		b.WriteByte(ch)
		switch ch {
		case ' ', '\t', '\r', '{', '}', ';', '|':
			inToken = false
		case '[', ']':
			// A bracket that BEGINS a token (and is not an endpoint
			// literal, handled above) is list sugar the real lexer's
			// skip loop consumes, so the scanner stays at a token
			// boundary (inToken stays false) and a following '/*' is
			// a comment. A bracket met MID-token was consumed by
			// readIdentifier as a literal character (#8453), so the
			// token continues and inToken stays true. The pre-fix code
			// reset inToken on every bracket, which is how `a[/*`
			// opened a fictitious comment (#14145).
		default:
			inToken = true
		}
	}
	uncommented = b.String()
	if inBlock {
		return false, uncommented, fmt.Errorf("unterminated block comment")
	}
	for _, line := range strings.Split(uncommented, "\n") {
		if IsFlatLoadLine(strings.TrimSpace(line)) {
			flat = true
			break
		}
	}
	return flat, uncommented, nil
}

// bracketedEndpointLiteralEnd mirrors the real lexer's
// tryBracketedEndpointLiteral (lexer.go): content[start] must be '[',
// immediately followed by a run of identifier characters, a ']', a ':',
// and a further run of identifier characters. On a match it returns the
// index just past the literal. The identifier-character set is the
// lexer's own isIdentChar, so the two models cannot drift on what the
// runs may contain ('/', '*' and ':' included).
func bracketedEndpointLiteralEnd(content string, start int) (int, bool) {
	j := start + 1
	if j >= len(content) || !isIdentChar(content[j]) {
		return 0, false
	}
	for j < len(content) && isIdentChar(content[j]) {
		j++
	}
	if j >= len(content) || content[j] != ']' {
		return 0, false
	}
	j++
	if j >= len(content) || content[j] != ':' {
		return 0, false
	}
	for j < len(content) && isIdentChar(content[j]) {
		j++
	}
	return j, true
}

// LoadMutationLines returns the set-form mutation lines a load body writes,
// or an error when the shared classifier cannot classify the body at all
// (an unterminated block comment). Authorization MUST refuse on that error:
// adjudicating an unclassifiable body as zero mutations is a fail-open
// (#14145).
//
// Set-format content is taken line by line. Hierarchical content is parsed
// and rendered as set lines, so every leaf path it writes is checked.
// Hierarchical content is parsed from the same comment-free form the
// store's hierarchical branches parse (#14572), so the gate adjudicates
// exactly the representation the store applies.
// Content that does not parse yields its parsed part; the store's own Load
// refuses what it cannot parse, and adjudicating the parsable part is
// strictly better than adjudicating nothing.
func LoadMutationLines(content string) ([]string, error) {
	flat, uncommented, err := ClassifyLoadContent(content)
	if err != nil {
		return nil, err
	}
	if flat {
		var lines []string
		for _, raw := range strings.Split(uncommented, "\n") {
			line := strings.TrimSpace(raw)
			if fields := strings.Fields(line); len(fields) > 0 && loadMutationVerbs[fields[0]] {
				lines = append(lines, line)
			}
		}
		return lines, nil
	}
	tree, _ := NewParser(uncommented).Parse()
	if tree == nil {
		return nil, nil
	}
	var lines []string
	for _, line := range strings.Split(tree.FormatSet(), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	return lines, nil
}

// AuthorizeConfigLoad adjudicates a `load` against the caller's configuration
// regexes. mode is "override", "merge", "set" or "rescue"; content is the body.
//
// `override` and `rescue` are REFUSED for a restricted class rather than
// adjudicated, and that distinction is deliberate: they replace the entire
// candidate, so the paths they DELETE cannot be enumerated one by one. Refusal
// is the honest answer, and the docs must say refusal rather than implying
// coverage.
func AuthorizeConfigLoad(cfg *Config, class, mode, content string) error {
	if class == "" {
		return nil
	}
	_, restricted, err := ConfigurationLoginRegexesFor(cfg, class)
	if err != nil {
		return fmt.Errorf("permission denied: login class %q has an invalid configuration regex: %w", class, err)
	}
	if !restricted {
		return nil
	}
	if mode == "override" || mode == "rescue" {
		return fmt.Errorf("permission denied: login class %q restricts configuration paths, and "+
			"load %s replaces the whole candidate, so the paths it deletes cannot be "+
			"adjudicated one by one; use load merge or load set (#9892)", class, mode)
	}
	mutationLines, err := LoadMutationLines(content)
	if err != nil {
		// Fail closed (#14145): a body the shared classifier cannot
		// classify must not be adjudicated as zero mutations. The
		// store rejects the same body, so refusing here refuses no
		// load the store would have applied.
		return fmt.Errorf("permission denied: login class %q restricts configuration paths, and "+
			"the load content cannot be classified for adjudication: %w", class, err)
	}
	for _, line := range mutationLines {
		if err := AuthorizeConfigMutation(cfg, class, nil, line); err != nil {
			return err
		}
	}
	return nil
}

// AuthorizeConfigRollback adjudicates `rollback n` for a restricted class.
//
// Same shape as load override and closed here for the same reason: `rollback n`
// for n>0 replaces the candidate with an older configuration whose paths cannot
// be adjudicated individually. `rollback 0` returns the candidate to the
// COMMITTED configuration — every path in which was adjudicated when it was
// written — and stays available.
//
// Included with #9892 because it is the identical mechanism on the identical
// surfaces: #9633 closed it on gRPC, and the REST route table's own exemption
// text already said rollback was "the same class as load". Closing one and not
// the other would leave a gap whose own documentation admits it.
func AuthorizeConfigRollback(cfg *Config, class string, n int) error {
	if class == "" || n == 0 {
		return nil
	}
	_, restricted, err := ConfigurationLoginRegexesFor(cfg, class)
	if err != nil {
		return fmt.Errorf("permission denied: login class %q has an invalid configuration regex: %w", class, err)
	}
	if !restricted {
		return nil
	}
	return fmt.Errorf("permission denied: login class %q restricts configuration paths, and "+
		"rollback %d replaces the candidate with an older configuration whose paths cannot "+
		"be adjudicated one by one; rollback 0 remains available (#9892)", class, n)
}
