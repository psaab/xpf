package config

import (
	"fmt"
	"strconv"
	"strings"
)

// #9154: THE CONFIGURATION REGEXES WERE ENFORCED ON EXACTLY ONE OF THREE
// DISPATCH SURFACES.
//
// `allow-configuration` / `deny-configuration` were evaluated only by the on-box
// CLI. The gRPC listener the shipped `cli` binary speaks to, and the REST API,
// both performed config mutations without ever consulting them -- so an operator
// who withheld configuration authority from a class saw it withheld only if that
// person happened to log in at the console. The documented way to administer the
// box bypassed it.
//
// Measured, with the control that makes it a finding rather than a guess:
//
//	deny-configuration-only : authorizeRPCCommand(Set) -> nil       ALLOWED
//	deny-commands-only      : authorizeRPCCommand(Set) -> denied    the gate IS live
//
// The second row is what proves the machinery works and simply was not asked
// this question.
//
// SO THE DECISION LIVES HERE, in pkg/config, beside
// ConfigurationLoginRegexesFor. #7172 cut 6 moved the RESOLUTION here for
// exactly this reason -- "so this gate, the operational gate and the gRPC gate
// all read one implementation" -- and the decision stayed behind in pkg/cli,
// where the other two surfaces cannot reach it. A rule enforced by whichever
// caller remembers to call it is the shape that produced this defect.

// configMutationVerbs are the dispatchConfig verbs that CHANGE the candidate
// configuration and therefore carry a path to match.
//
// `edit`, `top` and `up` are deliberately absent: they move the cursor and
// change nothing. Entering a denied subtree is harmless because every mutation
// inside it is denied on its own, and gating navigation would also stop an
// operator merely LOOKING at a subtree they cannot edit.
//
// `commit`, `rollback` and `load` are absent for a different reason and are NOT
// covered by this gate — see configMutationPath.
var configMutationVerbs = map[string]bool{
	"set":        true,
	"delete":     true,
	"deactivate": true,
	"activate":   true,
	"copy":       true,
	"rename":     true,
	"insert":     true,
	"annotate":   true,
}

// configMutationPath returns the configuration path a verb will act on,
// resolved against the current edit path, and whether this verb is gated here.
//
// NOT GATED, and each for a stated reason rather than by omission:
//
//   - `edit`, bare `top`/`up` — navigation, no change (see
//     configMutationVerbs). A `top`/`up` PREFIX carrying a command
//     (#15082) is gated as that command at the target level.
//   - `commit`/`rollback` — they act on the candidate as a whole, not on a
//     path, so there is nothing for a path regex to match. A deny that stopped
//     `commit` would be denying the operator's own already-authorized edits.
//   - `load` — applies arbitrary config whose content is not known until it is
//     parsed, so enforcing deny-configuration against it means matching every
//     path the loaded content touches, which is a different mechanism from a
//     verb gate. Explicitly a REMAINING GAP rather than something this gate
//     quietly covers.
func configMutationPaths(editPath, parts []string, quoted []bool) ([]string, bool) {
	if len(parts) == 0 {
		return nil, false
	}
	// #15082: `top <cmd>` / `up [n] <cmd>` execute cmd at the target
	// level. Adjudicate the inner command against the TARGET cursor,
	// not the navigation verb against the current cursor — otherwise
	// a denied delete rides through ungated while the dispatcher
	// (now) executes it.
	if parts[0] == "top" || parts[0] == "up" {
		target, inner, innerQuoted, ok := ResolveTopUpPrefix15082(editPath, parts, quoted)
		if !ok || len(inner) == 0 {
			return nil, false
		}
		return configMutationPaths(target, inner, innerQuoted)
	}
	verb := parts[0]
	if !configMutationVerbs[verb] {
		return nil, false
	}
	if len(parts) < 2 {
		// The verb's own arity error is a better message than a permission
		// denial, and an empty path cannot match a meaningful deny anyway.
		return nil, false
	}
	// THE RESOLVED PATH, not the typed remainder. See the edit-path bypass note
	// above: matching parts[1:] alone lets `edit system` walk a deny.
	resolve := func(rel []string) string {
		full := make([]string, 0, len(editPath)+len(rel))
		full = append(full, editPath...)
		full = append(full, rel...)
		return strings.Join(full, " ")
	}

	// #9938 F-029: copy and rename act on TWO paths, and the gate used to join
	// them into one string (`<verb> <src> to <dst>`) that the dispatcher never
	// acts on. handleCopyRename / handleCopyRename's gRPC twin split at `to`
	// and call Copy/Rename with two REAL paths, so both endpoints are
	// adjudicated here, separately.
	//
	// It matters under an ANCHORED deny, which is the idiom Junos documents for
	// complex expressions: `^security policies p1$` does not match the joined
	// string in either direction, so `rename <denied> to <allowed>` and
	// `rename <allowed> to <denied>` were both permitted. An UNANCHORED deny
	// caught them incidentally, which is why this survived — the common case
	// hid the mechanism.
	switch verb {
	case "copy", "rename":
		// #14147: only a BARE `to` separates the endpoints. A quoted
		// "to" is a path element (the lexer unquotes it to the same
		// value), and the executors now split with the same canonical
		// parser, so the endpoints adjudicated here are the endpoints
		// acted on. Splitting at a quoted token adjudicated a source/
		// destination pair no executor ever used.
		src, dst, toOK := splitCopyRenameTokens(parts, quoted)
		if !toOK {
			// MALFORMED — and the answer is the WHOLE REMAINDER, not "ungated".
			//
			// The dispatcher does print its own usage and act on nothing, so
			// "there is nothing to adjudicate" is a true statement about this
			// line. It is still the wrong answer, because it makes the gate's
			// coverage depend on the line PARSING, and the pre-#9938 gate
			// covered it. A change that adds precision must not remove
			// coverage: falling back keeps the old behaviour as a floor and
			// adds the two-endpoint split above it. Caught by
			// TestEveryFlatVerbIsTakenVerbatimNotReparsed9892, which is exactly
			// what that cell exists for.
			break
		}
		return []string{resolve(src), resolve(dst)}, true

	case "insert":
		// `insert <element-path> before|after <ref>` moves the element; the ref
		// is a SIBLING identifier that is not itself mutated, and it lives under
		// the same parent, so a deny covering the element covers it.
		// #14147: only a BARE keyword separates, for the same reason as
		// copy/rename above — a quoted "before" is an element token.
		elem, _, _, kwOK := splitInsertTokens(parts, quoted)
		if !kwOK {
			break // malformed: fall back to the whole remainder, see above
		}
		return []string{resolve(elem)}, true

	case "annotate":
		// `annotate <path> "comment"`. The comment is dropped from the path, but
		// ONLY when it was actually written as a quoted string.
		//
		// Trimming the last token unconditionally is wrong and fails in the
		// silent direction: `annotate system root-authentication` has no comment,
		// so the trim leaves `system` and an anchored deny on
		// `^system root-authentication` stops matching. That is a coverage LOSS
		// introduced by a precision gain, which is why quote provenance is
		// carried out of the lexer rather than inferred from position.
		// #14717: the split itself is splitAnnotateTokens, shared with every
		// annotate executor via ParseAnnotateCommand, so the path adjudicated
		// here is the path acted on by construction.
		if path, _, ok := splitAnnotateTokens(parts, quoted); ok {
			return []string{resolve(path)}, true
		}
		break // no comment token: the whole remainder is the path
	}

	return []string{resolve(parts[1:])}, true
}

// lexConfigMutationLine9938 tokenizes a config-mode line THE WAY THE STORE DOES,
// with quotes consumed.
//
// #9938 F-020: this was `strings.Fields`, which keeps quote characters. The
// store lexes them away (`readString` returns the unquoted body, reached through
// ParseSetVerbGrouped -> SetPathQuotedGrouped), so `deactivate security "policies" p1`
// was GATED as `security "policies" p1` and APPLIED as `security policies p1`.
// A deny on the real path did not match the string the gate judged.
//
// Using the lexer rather than a quote-stripping pass is deliberate: the defect
// is that the gate had its own idea of tokenization, and a second
// almost-the-same tokenizer is the same defect with a smaller diff. It also
// makes `annotate`'s trailing comment one token, which is what lets the path be
// extracted without a second parse.
func lexConfigMutationLine9938(line string) (tokens []string, quoted []bool) {
	tokens, quoted, _ = lexConfigMutationLineStrict15167(line)
	return tokens, quoted
}

// lexConfigMutationLineStrict15167 is lexConfigMutationLine9938 reporting
// whether the WHOLE line lexed cleanly. ok is false when the lexer stopped
// early: a TokenError (a non-ASCII byte such as a Unicode space, an
// unterminated string/comment), or a structural token ({ } ; |) that has
// no place in a flat config-mode line.
//
// #15167 (V47-S1, shared with B23-01): the lenient lexer returns only a
// PREFIX on such input. An executor that splits with strings.Fields
// (unicode-aware) acts on the FULL path, so a gate judging the prefix
// admits a mutation it never saw — `set<NBSP>system login ...` lexes to
// just `set` here (ungated) while Fields executes `system login ...`.
// AuthorizeConfigMutation therefore fails closed on !ok for a gated verb,
// and executors use ParseConfigMutationLine so they act on exactly the
// tokens the gate judged.
func lexConfigMutationLineStrict15167(line string) (tokens []string, quoted []bool, ok bool) {
	lex := NewLexer(line)
	for {
		tok := lex.Next()
		switch tok.Type {
		case TokenEOF:
			return tokens, quoted, true
		case TokenIdentifier, TokenString:
			tokens = append(tokens, tok.Value)
			quoted = append(quoted, tok.Type == TokenString)
		default:
			return tokens, quoted, false
		}
	}
}

// ParseConfigMutationLine lexes a full config-mode line the way the
// authorization gate does (#15167): quotes are consumed and comments are
// skipped, exactly as lexConfigMutationLine9938 tokenizes for
// AuthorizeConfigMutation. ok is false when the line does not lex cleanly
// end to end (see lexConfigMutationLineStrict15167), so an executor can
// refuse it instead of re-splitting the raw text with strings.Fields and
// acting on tokens the gate never judged. Executors of the flat verbs
// (set/delete/deactivate/activate) must derive their path from this parse,
// never from strings.Fields on the raw line.
func ParseConfigMutationLine(line string) (tokens []string, quoted []bool, ok bool) {
	return lexConfigMutationLineStrict15167(line)
}

// ParseDeactivateActivateCommand lexes a full deactivate/activate line and
// returns the verb and the lexed remainder path (#15166). It is the split
// every deactivate/activate executor must use, so the path acted on is the
// path the gate adjudicated: routing on strings.Fields splits on Unicode
// whitespace the config lexer rejects, acting on a path nobody authorized.
// ok=false when the line is not a well-formed `<verb> <path...>` lexing.
func ParseDeactivateActivateCommand(line string) (verb string, path []string, ok bool) {
	tokens, _, lexOK := lexConfigMutationLineStrict15167(line)
	if !lexOK || len(tokens) < 2 {
		return "", nil, false
	}
	if tokens[0] != "deactivate" && tokens[0] != "activate" {
		return "", nil, false
	}
	return tokens[0], tokens[1:], true
}

// ParseConfigPath lexes a typed configuration-path fragment (for example
// the argument of an interactive `edit` command) the way the store lexer
// does: block and line comments are skipped and quoted strings are
// unquoted (#14716). ok is false when the fragment is lexically malformed
// — an unterminated string or block comment, a brace/semicolon/pipe, or
// any other non-path token — so callers can refuse it instead of storing
// raw text the executor would re-parse differently. A comment-only
// fragment is well-formed and yields no tokens.
func ParseConfigPath(fragment string) (tokens []string, ok bool) {
	tokens, _, ok = lexConfigPath14716(fragment)
	return tokens, ok
}

// ParseEditFragment lexes a full `edit ...` config-mode line and returns
// the lexed path fragment after the verb (#14716). ok is false when the
// line is not an edit line or the fragment is lexically malformed.
func ParseEditFragment(line string) (tokens []string, ok bool) {
	lexed, _, lexOK := lexConfigPath14716(line)
	if !lexOK || len(lexed) == 0 || lexed[0] != "edit" {
		return nil, false
	}
	return lexed[1:], true
}

// lexConfigPath14716 is ParseConfigPath carrying quote provenance.
func lexConfigPath14716(fragment string) (tokens []string, quoted []bool, ok bool) {
	lex := NewLexer(fragment)
	for {
		tok := lex.Next()
		switch tok.Type {
		case TokenEOF:
			return tokens, quoted, true
		case TokenIdentifier, TokenString:
			tokens = append(tokens, tok.Value)
			quoted = append(quoted, tok.Type == TokenString)
		default:
			return nil, nil, false
		}
	}
}

// NormalizeEditPathTokens lexes an already-stored edit cursor token by
// token, dropping tokens that are lexically invisible on their own
// (comment-only or malformed fragments such as a stray `*/`) and
// expanding tokens that lex to more than one path element (#14716).
// Plain identifiers and quoted strings map to their lexed values, so a
// cursor minted before the fix — or by any writer that stored raw
// strings.Fields output — is adjudicated and executed as the path the
// store lexer produces, never as the raw spelling.
func NormalizeEditPathTokens(editPath []string) []string {
	if len(editPath) == 0 {
		return nil
	}
	// A comment may span several stored tokens (`/*`, `interfaces`,
	// `*/`), which no per-token lex can see. Lex the re-joined cursor
	// first — that is the string the executor re-joins and the store
	// re-lexes — and fall back to per-token lexing only when the joined
	// form is malformed (an unterminated comment opened by the cursor
	// and not yet closed, whose opener is lexically invisible anyway).
	if lexed, ok := ParseConfigPath(strings.Join(editPath, " ")); ok {
		return lexed
	}
	out := make([]string, 0, len(editPath))
	for _, tok := range editPath {
		lexed, ok := ParseConfigPath(tok)
		if !ok {
			continue
		}
		out = append(out, lexed...)
	}
	return out
}

// normalizeEditPath14716 resolves a stored cursor against a mutation
// line's leading tokens for the split-comment case (#14716): when the
// cursor's trailing tokens open a block comment that the line's leading
// tokens close (`edit system /*` then `set */ ...`), re-lexing the
// joined raw text drops the comment exactly as the store lexer does on
// the re-joined execution string. Plain cursors (and lines whose leading
// tokens do not complete a comment) keep the per-token normalization.
// lineQuoted carries the line tokens' quote provenance so the returned
// line slice stays aligned with it.
func normalizeEditPath14716(editPath, lineTokens []string, lineQuoted []bool) ([]string, []string, []bool) {
	base := NormalizeEditPathTokens(editPath)
	if len(editPath) == 0 || len(lineTokens) == 0 {
		return base, lineTokens, lineQuoted
	}
	joined := strings.Join(editPath, " ") + " " + strings.Join(lineTokens, " ")
	lexed, lexedQuoted, ok := lexConfigPath14716(joined)
	if !ok {
		return base, lineTokens, lineQuoted
	}
	// The joined re-lex is meaningful only when it yields exactly the
	// lexed cursor as a prefix; then its suffix is the lexed line (this
	// drops a block comment spanning the cursor/line boundary). A verb
	// consumed into a spanning comment (`set */ ...` after `edit
	// system /*`) means no mutation verb survives, so nothing is gated
	// here — the executor's equally verb-less string errors without
	// mutating, and returning the unchanged line keeps the gate from
	// inventing a path. Otherwise the per-token view is authoritative.
	if len(lexed) < len(base) {
		return base, lineTokens, lineQuoted
	}
	for i := range base {
		if lexed[i] != base[i] {
			return base, lineTokens, lineQuoted
		}
	}
	suffix := lexed[len(base):]
	if len(suffix) == 0 {
		return base, lineTokens, lineQuoted
	}
	if suffix[0] != lineTokens[0] {
		// The line's verb was consumed by a comment spanning the
		// cursor/line boundary (`edit system /*` + `set */ ...`).
		// Execution re-joins the same raw text, so the store acts on
		// exactly `base + suffix`; adjudicate that by re-presenting it
		// under the original verb. If no verb survives at all there is
		// no gated mutation (handled by the empty-suffix return above
		// when the whole line was comment).
		if len(lineTokens) > 0 && configMutationVerbs[lineTokens[0]] {
			syn := make([]string, 0, len(suffix)+1)
			syn = append(syn, lineTokens[0])
			syn = append(syn, suffix...)
			synQuoted := make([]bool, len(syn))
			if len(lexedQuoted) >= len(base) {
				copy(synQuoted[1:], lexedQuoted[len(base):])
			}
			return base, syn, synQuoted
		}
		return base, lineTokens, lineQuoted
	}
	// Align suffix provenance with the lexed joined tokens.
	suffixQuoted := lexedQuoted[len(base):]
	if len(suffixQuoted) != len(suffix) {
		suffixQuoted = make([]bool, len(suffix))
	}
	return base, suffix, suffixQuoted
}

// AuthorizeConfigMutation adjudicates one config-mode line against a class's
// `*-configuration` regexes, returning nil when the mutation is permitted.
//
// editPath is the operator's current `edit` cursor, or nil where the caller has
// already resolved it -- the remote CLI prepends its own edit path before
// sending, so the gRPC and REST surfaces pass nil and gate the line they will
// actually act on.
func AuthorizeConfigMutation(cfg *Config, class string, editPath []string, line string) error {
	return authorizeConfigMutationDepth9939(cfg, class, editPath, line, 0)
}

func authorizeConfigMutationDepth9939(cfg *Config, class string, editPath []string, line string, depth int) error {
	if class == "" {
		return nil
	}
	parts, quoted, lexOK := lexConfigMutationLineStrict15167(line)
	// #14716: the stored cursor may carry raw, un-lexed tokens (quotes,
	// comment fragments) from a writer that split with strings.Fields.
	// Normalize it — including a block comment split across the cursor
	// and this line — so the adjudicated path is the path the store
	// lexer will execute, never the raw spelling.
	editPath, parts, quoted = normalizeEditPath14716(editPath, parts, quoted)
	// #15082: unwrap a top/up prefix so the embedded-payload scan
	// below sees the inner command at its target cursor, exactly
	// as configMutationPaths adjudicated it.
	if len(parts) > 0 && (parts[0] == "top" || parts[0] == "up") {
		if target, inner, innerQuoted, ok := ResolveTopUpPrefix15082(editPath, parts, quoted); ok && len(inner) > 0 {
			editPath, parts, quoted = target, inner, innerQuoted
		}
	}
	// #15167: a prefix that is exactly a gated verb (`set<NBSP>system ...`
	// lexes to just `set`) carries no adjudicable path, so
	// configMutationPaths declines it — but a Fields-splitting executor
	// would act on the remainder. Treat a bare gated verb on a
	// non-lexing line as gated here; the restricted-class arm below
	// refuses it. Clean bare verbs (`set` alone) keep the arity error.
	// #15166 is the deactivate/activate instance of the same mechanism on
	// the gRPC surface; the arm below covers it via the shared decision.
	verbOnly15167 := !lexOK && len(parts) == 1 && configMutationVerbs[parts[0]]
	paths, gated := configMutationPaths(editPath, parts, quoted)
	if !gated && verbOnly15167 {
		paths, gated = []string{strings.Join(editPath, " ")}, true
	}
	if !gated {
		return nil
	}
	rules, ok, err := ConfigurationLoginRegexesFor(cfg, class)
	if err != nil {
		return fmt.Errorf(
			"permission denied: login class %q has an invalid configuration regex: %w",
			class, err)
	}
	if !ok {
		return nil
	}
	// #15167 (V47-S1, shared with B23-01): the line did not lex cleanly end
	// to end — a Unicode space or other non-ASCII byte, an unterminated
	// string/comment, or a structural token stopped the lexer, so `paths`
	// above was resolved from a PREFIX of the line. A Fields-splitting
	// executor acts on the full path, which this gate never saw. For a
	// class that configured *-configuration regexes, fail closed rather
	// than adjudicate a shorter mutation than the one that will run.
	// Unrestricted classes returned above, so their malformed lines keep
	// the executor's ordinary error.
	if !lexOK {
		return fmt.Errorf("permission denied: login class %q denies %s under %q (%s)",
			class, parts[0], configAuditRoot(paths[0]),
			"the line does not lex cleanly, so the path it acts on cannot be adjudicated")
	}
	// #9938 F-029: EVERY acted-upon path is adjudicated, and the FIRST denial
	// refuses the whole command. A copy or rename that is permitted at one
	// endpoint and denied at the other must not run at all — half of it is
	// still a mutation of a path the class was denied.
	for _, path := range paths {
		decision := rules.Evaluate(path)
		if decision.Allowed {
			continue
		}
		// AUDIT: the VERB and the resolved path's leading element only. A config
		// path's trailing tokens are operator data — `set system root-authentication
		// plain-text-password <secret>` puts the secret in the path itself — so the
		// full path must never reach a log line. Cut 3's canonicalPrefix cannot be
		// reused: it walks the operational cmdtree, which config paths do not use.
		return fmt.Errorf("permission denied: login class %q denies %s under %q (%s)",
			class, parts[0], configAuditRoot(path), decision.Reason)
	}
	// #9939/#9984: a `then change-configuration commands` PAYLOAD is data on
	// the path above. The planting class is stamped into the effective policy
	// record, and the event engine later rechecks every embedded target under
	// that class before touching a candidate; missing or denied metadata
	// quarantines the payload rather than executing it with root authority.
	// The line that PLANTS it is therefore still the first adjudication point,
	// while fire-time revalidation closes the persistence and policy-churn gap.
	//
	// #14981: a line that creates a group body or triggers inheritance is
	// adjudicated above only on its literal `groups …` / `apply-groups …`
	// spelling, which is not a path that ever takes effect. The effective
	// paths exist only after expansion of the whole candidate, so the
	// expanded adjudication runs where the candidate is held
	// (AuthorizeExpandedTree at commit, the load-body expansion arm in
	// AuthorizeConfigLoad, and the surfaces' candidate-after-mutation
	// replay for group-touching Set lines).
	return authorizeEmbeddedChangeConfig9939(cfg, class, editPath, parts, quoted, depth)
}

// configAuditRoot renders only the first element of a configuration path.
//
// One element is a deliberate floor rather than a tuned depth: any deeper and
// the rendering depends on knowing which level of which hierarchy holds a
// secret, and that knowledge does not exist here. `system` tells an operator
// which tree they were denied in without revealing what they set.
func configAuditRoot(path string) string {
	fields := strings.Fields(path)
	if len(fields) == 0 {
		return "<empty>"
	}
	return fields[0]
}

// ResolveTopUpPrefix15082 splits a Junos `top <cmd>` / `up [n] <cmd>`
// config-mode prefix (#15082). target is the edit cursor the inner
// command runs against (root for top; n levels up for up, default 1,
// clamped to root), inner/innerQuoted the remaining command tokens
// (nil for bare navigation), and ok=false when the prefix is
// malformed (a non-numeric or out-of-range up count, or a count with
// no following command token to consume it as a count). Callers
// that execute must fail closed on !ok with trailing tokens present;
// bare `top`/`up` (no trailing tokens) returns inner=nil, ok=true.
func ResolveTopUpPrefix15082(editPath, parts []string, quoted []bool) (target, inner []string, innerQuoted []bool, ok bool) {
	if len(parts) == 0 || (parts[0] != "top" && parts[0] != "up") {
		return nil, nil, nil, false
	}
	quoteAt := func(i int) bool {
		return i < len(quoted) && quoted[i]
	}
	if parts[0] == "top" {
		if len(parts) == 1 {
			return nil, nil, nil, true
		}
		innerQuoted = nil
		if len(quoted) == len(parts) {
			innerQuoted = quoted[1:]
		}
		return nil, parts[1:], innerQuoted, true
	}
	// up [n] [cmd...]
	n := 1
	rest := 1
	if len(parts) >= 2 && !quoteAt(1) {
		if v, err := parseUpCount15082(parts[1]); err == nil {
			// A bare number is a count only when a command follows
			// or it is the whole line (`up 2`); `up 1` alone is
			// navigation. With a command, consume it.
			n = v
			rest = 2
		} else if isAllDigits15082(parts[1]) {
			// Numeric but out of range: malformed, never guess.
			return nil, nil, nil, false
		}
		// Non-numeric: it is the inner command's verb.
	}
	if rest >= len(parts) {
		// Bare navigation: `up` or `up n` (count clamped to root).
		if n > len(editPath) {
			return nil, nil, nil, true
		}
		if n == 0 {
			return append([]string{}, editPath...), nil, nil, true
		}
		return append([]string{}, editPath[:len(editPath)-n]...), nil, nil, true
	}
	if n > len(editPath) {
		return nil, nil, nil, false
	}
	target = append([]string{}, editPath[:len(editPath)-n]...)
	innerQuoted = nil
	if len(quoted) == len(parts) {
		innerQuoted = quoted[rest:]
	}
	return target, parts[rest:], innerQuoted, true
}

func parseUpCount15082(tok string) (int, error) {
	if tok == "" {
		return 0, strconv.ErrSyntax
	}
	for _, r := range tok {
		if r < '0' || r > '9' {
			return 0, strconv.ErrSyntax
		}
	}
	v, err := strconv.Atoi(tok)
	if err != nil {
		return 0, err
	}
	return v, nil
}

func isAllDigits15082(tok string) bool {
	if tok == "" {
		return false
	}
	for _, r := range tok {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// ParseTopUpPrefix15082 lexes a full config-mode line and splits a
// leading top/up prefix, for executors that tokenize with
// strings.Fields but must consume the prefix exactly as the
// authorization gate does (#15082). ok=false means the line is not
// a well-formed top/up line; bare navigation yields inner=nil.
func ParseTopUpPrefix15082(editPath []string, line string) (target, inner []string, ok bool) {
	parts, quoted := lexConfigMutationLine9938(line)
	if len(parts) == 0 || (parts[0] != "top" && parts[0] != "up") {
		return nil, nil, false
	}
	target, inner, _, ok = ResolveTopUpPrefix15082(editPath, parts, quoted)
	return target, inner, ok
}
