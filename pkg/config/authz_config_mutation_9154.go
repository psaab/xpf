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

// credentialConfigPrefixes16080 are the configuration path PREFIXES whose
// mutation rewrites a login, root, or API credential (#16080). A class
// holding PermConfig without PermAll may not mutate at or below any of
// them — not even when it authored no *-configuration regexes, and not
// even when its regexes would allow the path. Only PermAll (the built-in
// super-user, or a custom class whose authored tokens include all /
// super-user, which mapJunosPermissions folds to PermAll) may do so; the
// empty (no-RBAC) class bypass retains its existing meaning because
// authorizeConfigMutationDepth9939 returns before this check for
// class == "".
//
// Matching is on lexed PATH TOKENS so a user or stanza merely NAMED like
// a credential container cannot widen or narrow the fence: `system login
// user root-authentication ...` is the `root-authentication` login USER,
// still below `system login` and therefore still fenced; `system services
// web-management api-authentication ...` is not the api-auth stanza.
//
// Both api-auth spellings are fenced: the current
// `system services web-management api-auth` and the legacy
// `system services rest api-auth` shape the redaction census still carries.
var credentialConfigPrefixes16080 = [][]string{
	{"system", "login"},
	{"system", "root-authentication"},
	{"system", "services", "web-management", "api-auth"},
	{"system", "services", "rest", "api-auth"},
}

// credentialConfigPathHit16080 reports the fence prefix the (space-joined,
// lexed) mutation path falls at or below, or "" when it is outside every
// credential fence. Token-boundary matching, never substring.
func credentialConfigPathHit16080(path string) string {
	fields := strings.Fields(path)
	for _, prefix := range credentialConfigPrefixes16080 {
		if len(fields) < len(prefix) {
			continue
		}
		match := true
		for i, tok := range prefix {
			if fields[i] != tok {
				match = false
				break
			}
		}
		if match {
			return strings.Join(prefix, " ")
		}
	}
	return ""
}

// credentialConfigPathsHit16080 returns the first credential fence any of
// paths falls at or below — copy/rename adjudicate two endpoints, and a
// credential hit on EITHER must refuse the whole command (#16080).
func credentialConfigPathsHit16080(paths []string) string {
	for _, p := range paths {
		if hit := credentialConfigPathHit16080(p); hit != "" {
			return hit
		}
	}
	return ""
}

// CredentialPathTouches16080 reports whether mutating `path` can reach a
// credential stanza: the path is at/below a fence prefix, OR it is a
// proper ANCESTOR of one (`system`, `system services`,
// `system services web-management`, `system services rest`). An ancestor
// mutation — `delete system`, `deactivate system login`,
// `rename system to …`, `copy … to system` — rewrites or removes the
// credential subtree beneath it even though the typed path itself never
// names the fence. The direct-path check alone missed that leg
// (#16080 fold). Exported for candidate-diff scoping in
// authorizeExpandedTree14981.
func CredentialPathTouches16080(path string) bool {
	if credentialConfigPathHit16080(path) != "" {
		return true
	}
	fields := strings.Fields(path)
	for _, prefix := range credentialConfigPrefixes16080 {
		if len(fields) >= len(prefix) {
			continue
		}
		match := true
		for i, tok := range fields {
			if prefix[i] != tok {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func credentialConfigPathsTouch16080(paths []string) bool {
	for _, p := range paths {
		if CredentialPathTouches16080(p) {
			return true
		}
	}
	return false
}

// CredentialSurchargeCheck16080 reports whether class is priced out of
// credential mutations by #16080: a non-empty class that does not hold
// PermAll. Whole-candidate operations (load override/rescue, rollback
// n>0, expanded-tree commit adjudication) cannot enumerate per-path
// credential writes, so their existing restricted-class refusals consult
// this instead of only ConfigurationLoginRegexesFor: a PermConfig class
// with no regexes is `restricted` for credential purposes even though it
// is unrestricted in the regex sense. The empty class is the legacy
// no-RBAC bypass and stays exempt, as in AuthorizeConfigMutation.
func CredentialSurchargeCheck16080(cfg *Config, class string) (fenced bool, err error) {
	if class == "" {
		return false, nil
	}
	if _, _, err := ConfigurationLoginRegexesFor(cfg, class); err != nil {
		return false, fmt.Errorf("permission denied: login class %q has an invalid configuration regex: %w", class, err)
	}
	return !ClassHasPermission(cfg, class, PermAll), nil
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
		// #15757: a BARE destination (identity-only, #15237) is placed
		// under the SOURCE parent by CopyPath/RenamePath
		// (BareDestinationParent), not under the edit cursor.
		// #16825: a NON-bare destination IS cursor-prepended by the
		// executors (PrependEditPathForCopyDst in pkg/cli and
		// cmd/cli), so adjudicating the raw typed dst missed an
		// anchored deny on the cursor-expanded destination
		// (fail-open) and false-denied anchored allows. Resolve the
		// destination exactly as the executor does, via the one
		// shared helper: cursor-prepend (unless bare), then
		// bare-resolve under the source parent.
		resolvedSrc := resolve(src)
		resolvedDst := strings.Join(ResolveCopyRenameDestination(editPath, src, dst), " ")
		return []string{resolvedSrc, resolvedDst}, true

	case "insert":
		// #16786: `insert <element-path> before|after <ref>` moves the
		// element RELATIVE TO the reference, and in a first-match list
		// (security policies, firewall terms) that reorder changes the
		// reference's effective position even though its statement is
		// untouched. Adjudicate BOTH endpoints, as copy/rename do: the
		// resolved reference path is built exactly as the executors
		// build it (InsertRefPath over the edit-resolved element, the
		// ref tokens replacing the element's trailing identifier under
		// the same parent), so the path judged is the path reordered.
		//
		// The pre-#16786 rationale — "the ref is a SIBLING identifier
		// that is not itself mutated, so a deny covering the element
		// covers it" — holds only for a deny on the common parent. A
		// deny on the reference itself (anchored `^security policies
		// p1$` or plain) never matched the element-only string, so a
		// restricted class could move a permitted permit ahead of a
		// protected deny policy and the set-line multiset the commit
		// gate compares stayed identical.
		// #14147: only a BARE keyword separates, for the same reason as
		// copy/rename above — a quoted "before" is an element token.
		elem, refTokens, _, kwOK := splitInsertTokens(parts, quoted)
		if !kwOK {
			break // malformed: fall back to the whole remainder, see above
		}
		resolvedElem := make([]string, 0, len(editPath)+len(elem))
		resolvedElem = append(resolvedElem, editPath...)
		resolvedElem = append(resolvedElem, elem...)
		paths := []string{strings.Join(resolvedElem, " ")}
		// A ref longer than the resolved element is refused by every
		// executor (ParseInsertCommand / handleInsert arity check), so
		// there is no reference path to adjudicate; the element verdict
		// above still stands.
		if len(refTokens) <= len(resolvedElem) {
			paths = append(paths, strings.Join(insertRefPath(resolvedElem, refTokens), " "))
		}
		return paths, true

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

// subtreeMutationVerbs16784 are the verbs whose named path is a SUBTREE
// root: the executor destroys, relocates, overwrites, or (for
// deactivate/activate) toggles the whole subtree beneath it, not only
// the statement the path spells. `set`/`insert`/`annotate` name the
// statement they write and stay single-path.
var subtreeMutationVerbs16784 = map[string]bool{
	"delete": true, "deactivate": true, "activate": true,
	"copy": true, "rename": true,
}

// authorizeSubtreeMutation16784 prices every descendant a subtree verb
// will destroy, relocate, overwrite, or toggle (#16784). Candidate lines
// are re-lexed exactly as config paths so authorization sees the same
// unquoted token values as the mutation gate, not display-set spelling.
// tree is the candidate BEFORE the mutation. Groups are expanded too, so
// a denied inherited leaf is not cheaper than a literal one.
func authorizeSubtreeMutation16784(cfg *Config, class string, tree *ConfigTree, verb string, resolvedPaths [][]string) error {
	if tree == nil || class == "" || !subtreeMutationVerbs16784[verb] {
		return nil
	}
	rules, restricted, err := ConfigurationLoginRegexesFor(cfg, class)
	if err != nil {
		return fmt.Errorf("permission denied: login class %q has an invalid configuration regex: %w", class, err)
	}
	if !restricted {
		return nil
	}
	for _, path := range resolvedPaths {
		if len(path) == 0 {
			continue
		}
		for _, line := range subtreeSetLines16784(tree, path) {
			if err := authorizeSetLineDescendant16784(cfg, class, rules, line); err != nil {
				return err
			}
		}
		// Expanded (group-inherited) descendants of this subtree.
		lines, err := ExpandedMutationLines(tree)
		if err != nil {
			return fmt.Errorf("permission denied: login class %q restricts configuration paths, and "+
				"the group expansion cannot be resolved for adjudication: %w", class, err)
		}
		for _, line := range lines {
			descendant, ok := canonicalConfigPathTokens17830(line)
			if !ok {
				return fmt.Errorf("permission denied: login class %q restricts configuration paths, and "+
					"an expanded descendant cannot be lexed for adjudication (#17830)", class)
			}
			if !configPathTokensHavePrefix17830(descendant, path) {
				continue
			}
			if expandedLineIsGroupDefinition14981(line) {
				continue
			}
			if err := AuthorizeConfigMutation(cfg, class, nil, line); err != nil {
				return err
			}
		}
	}
	return nil
}

// authorizeSetLineDescendant16784 adjudicates one enumerated set line
// against the same unquoted path tokens produced by the mutation lexer.
func authorizeSetLineDescendant16784(cfg *Config, class string, rules CompiledLoginRegexes, setLine string) error {
	tokens, ok := canonicalConfigPathTokens17830(setLine)
	if !ok {
		return fmt.Errorf("permission denied: login class %q restricts configuration paths, and "+
			"a descendant cannot be lexed for adjudication (#17830)", class)
	}
	path := strings.Join(tokens, " ")
	if decision := rules.Evaluate(path); !decision.Allowed {
		return fmt.Errorf("permission denied: login class %q denies mutation under %q (%s); "+
			"the subtree it acts on contains that descendant (#16784)",
			class, configAuditRoot(path), decision.Reason)
	}
	return nil
}

// canonicalConfigPathTokens17830 returns the unquoted path tokens in a
// rendered config mutation. FormatSet preserves authored quotes for display;
// authorization must use the same lexed token values as the mutation gate.
func canonicalConfigPathTokens17830(line string) ([]string, bool) {
	parts, quoted, ok := lexConfigMutationLineStrict15167(line)
	if !ok || len(parts) < 2 {
		return nil, false
	}
	switch parts[0] {
	case "set", "deactivate", "activate":
		return parts[1:], true
	case "annotate":
		path, _, ok := splitAnnotateTokens(parts, quoted)
		return path, ok
	default:
		return nil, false
	}
}

func configPathTokensHavePrefix17830(path, prefix []string) bool {
	if len(path) < len(prefix) {
		return false
	}
	for i := range prefix {
		if path[i] != prefix[i] {
			return false
		}
	}
	return true
}

// subtreeMutationPathTokens17830 constructs the exact token path used to
// navigate the candidate. Keeping token boundaries matters for quoted
// identities with interior whitespace; joining then strings.Fields-splitting
// the display path would turn one identity into multiple path elements.
func subtreeMutationPathTokens17830(editPath, parts []string, quoted []bool) [][]string {
	if len(parts) < 2 || !subtreeMutationVerbs16784[parts[0]] {
		return nil
	}
	rel := parts[1:]
	if parts[0] == "copy" || parts[0] == "rename" {
		src, _, ok := splitCopyRenameTokens(parts, quoted)
		if !ok {
			return nil
		}
		rel = src
	}
	path := make([]string, 0, len(editPath)+len(rel))
	path = append(path, editPath...)
	path = append(path, rel...)
	return [][]string{path}
}

// subtreeSetLines16784 renders the candidate subtree rooted at path
// as set lines: the rooted node's own line plus every descendant,
// formatted exactly as FormatPathSet renders them (inactive nodes
// also emit their set lines, so a denied leaf inside a deactivated
// subtree is still priced — delete destroys it either way).
func subtreeSetLines16784(tree *ConfigTree, path []string) []string {
	if tree == nil || len(path) == 0 {
		return nil
	}
	out := tree.FormatPathSet(path)
	if strings.TrimSpace(out) == "" {
		return nil
	}
	var lines []string
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "deactivate ") || strings.HasPrefix(l, "annotate ") {
			// The set lines already carry every node's path; the
			// deactivate/annotate renderings repeat a priced path.
			continue
		}
		lines = append(lines, l)
	}
	return lines
}

// AuthorizeConfigMutationOnCandidate is AuthorizeConfigMutation plus
// subtree pricing against candidate (#16784): a delete / deactivate /
// activate / copy / rename whose resolved path roots a candidate
// subtree is refused when any descendant of that subtree is denied.
// The rooted path remains lexed tokens for candidate navigation, while
// enumerated display-set descendants are re-lexed before authorization.
func AuthorizeConfigMutationOnCandidate(cfg *Config, class string, editPath []string, line string, candidate *ConfigTree) error {
	if err := AuthorizeConfigMutation(cfg, class, editPath, line); err != nil {
		return err
	}
	if candidate == nil || class == "" {
		return nil
	}
	parts, quoted, lexOK := lexConfigMutationLineStrict15167(line)
	if !lexOK {
		return nil
	}
	editPath, parts, quoted = normalizeEditPath14716(editPath, parts, quoted)
	if len(parts) > 0 && (parts[0] == "top" || parts[0] == "up") {
		if target, inner, innerQuoted, ok := ResolveTopUpPrefix15082(editPath, parts, quoted); ok && len(inner) > 0 {
			editPath, parts, quoted = target, inner, innerQuoted
		}
	}
	if len(parts) == 0 {
		return nil
	}
	verb := parts[0]
	// Copy/rename price only the source subtree: an existing destination
	// is refused by the executor, and the destination's own per-line
	// verdict already ran inside AuthorizeConfigMutation.
	paths := subtreeMutationPathTokens17830(editPath, parts, quoted)
	return authorizeSubtreeMutation16784(cfg, class, candidate, verb, paths)
}

// #16598: a flat `set` line is not necessarily ONE statement. The store
// (SetPathQuotedGrouped) re-splits the token run at schema arity, so a
// multi-value leaf closes after its value and the next keyword becomes a
// SIBLING statement: `set system domain-search x login user evil class
// super-user` writes both `system domain-search x` AND `system login user
// evil class super-user`. Adjudicating only the joined path
// `system domain-search x login user evil ...` matched neither an anchored
// `^system login` nor the plain substring `system login`, so a restricted
// class committed a super-user account past its deny-configuration fence.
//
// executedMutationPaths16598 returns the paths the store will actually
// act on for a `set` line: apply the parsed line (edit-path resolved,
// exactly as the store applies it) to a scratch tree and render it back
// with FormatSet. nil means the decomposition did not apply (not a set
// verb, or the tokens cannot be faithfully re-parsed) and the caller
// keeps the joined path as its floor.
func executedMutationPaths16598(editPath, parts []string, quoted []bool) []string {
	if len(parts) == 0 || parts[0] != "set" {
		return nil
	}
	full := make([]string, 0, len(editPath)+len(parts)-1)
	full = append(full, editPath...)
	full = append(full, parts[1:]...)
	var b strings.Builder
	b.WriteString("set")
	for i, tok := range full {
		b.WriteByte(' ')
		q := false
		if i >= len(editPath) && quoted != nil {
			idx := i - len(editPath) + 1
			if idx >= 0 && idx < len(quoted) {
				q = quoted[idx]
			}
		}
		if strings.Contains(tok, `"`) {
			return nil
		}
		if q || strings.ContainsAny(tok, " \t\n") {
			b.WriteByte('"')
			b.WriteString(tok)
			b.WriteByte('"')
		} else {
			b.WriteString(tok)
		}
	}
	_, path, pq, grouped, closed, err := ParseSetVerbGroupedClosed(b.String())
	if err != nil || len(path) == 0 {
		return nil
	}
	tree := &ConfigTree{}
	if err := tree.SetPathQuotedGrouped(path, pq, grouped, closed); err != nil {
		return nil
	}
	rendered := strings.TrimSpace(tree.FormatSet())
	if rendered == "" {
		return nil
	}
	var out []string
	for _, line := range strings.Split(rendered, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "set" {
			continue
		}
		out = append(out, strings.TrimSpace(strings.TrimPrefix(line, "set ")))
	}
	if len(out) <= 1 {
		return nil
	}
	return out
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
	tokens, quoted, ok, _ = lexConfigMutationLineStrict15167WithComments(line)
	return tokens, quoted, ok
}

// lexConfigMutationLineStrict15167WithComments also reports whether the
// lexer skipped a comment in a token gap, without scanning the input twice.
func lexConfigMutationLineStrict15167WithComments(line string) (tokens []string, quoted []bool, ok, comments bool) {
	lex := NewLexer(line)
	previousEnd, lineStart, currentLine := 0, 0, 1
	for {
		tok := lex.Next()
		for currentLine < tok.Line {
			for lineStart < len(line) && line[lineStart] != '\n' {
				lineStart++
			}
			if lineStart < len(line) {
				lineStart++
			}
			currentLine++
		}
		tokenStart := lineStart + tok.Column - 1
		if tokenStart > len(line) {
			tokenStart = len(line)
		}
		if tokenStart >= previousEnd {
			gap := line[previousEnd:tokenStart]
			comments = comments || strings.Contains(gap, "#") ||
				strings.Contains(gap, "/*") || strings.Contains(gap, "//")
		}
		switch tok.Type {
		case TokenEOF:
			return tokens, quoted, true, comments
		case TokenIdentifier, TokenString:
			tokens = append(tokens, tok.Value)
			quoted = append(quoted, tok.Type == TokenString)
			previousEnd = lex.Position()
		default:
			return tokens, quoted, false, comments
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
//
// #16608: a stored token bearing interior whitespace (`lan in`, from
// `edit ... filter "lan in"`) is already ONE lexed element, so the cursor
// must be re-lexed from its QUOTED join (JoinConfigPathTokens) — the
// space-joined form splits it into two tokens and every later mutation
// silently lands on `filter lan` while commit check passes. A cursor with
// NO whitespace-bearing token keeps the raw joined lex #14716 requires:
// raw decorated tokens (`"system"`, a `/*`…`*/` pair split across stored
// tokens) only collapse when re-lexed as typed, and quoting them would
// turn them into inert data. The two spellings cannot coexist in one real
// cursor — a raw Fields writer could never store a whitespace token, and
// a lexing writer never stores comment/quote decoration — so the branch
// is unambiguous for every cursor either writer can mint.
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
	joined := strings.Join(editPath, " ")
	for _, tok := range editPath {
		if strings.ContainsAny(tok, " \t\r\n") {
			joined = JoinConfigPathTokens(editPath)
			break
		}
	}
	if lexed, ok := ParseConfigPath(joined); ok {
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
	// #16608: re-lex the RAW joined text only while it still yields the
	// normalized cursor as a prefix (the split-comment case below). A
	// whitespace-bearing cursor element would split there and fail the
	// prefix check, so the plain return keeps the lexed cursor intact;
	// joining with JoinConfigPathTokens instead would quote a stored
	// split-comment `/*` opener into an inert token and the spanning
	// comment would never collapse. Raw join + prefix guard is therefore
	// the correct joined form here, unlike NormalizeEditPathTokens.
	joined := strings.Join(editPath, " ") + " " + JoinConfigPathTokens(lineTokens)
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
	// #16598: a `set` line the store splits into several statements is
	// several acted-upon paths (#9938 F-029). Decompose it on a scratch
	// tree and adjudicate every executed statement in addition to the
	// joined path, which stays as a floor so a deny matching only the
	// joined spelling keeps its verdict. The credential surcharge below
	// likewise sees every executed statement.
	splitPaths16598 := executedMutationPaths16598(editPath, parts, quoted)
	if len(splitPaths16598) > 0 {
		gated = true
	}
	adjudicatedPaths16598 := append(append([]string{}, paths...), splitPaths16598...)
	if !gated {
		return nil
	}
	rules, ok, err := ConfigurationLoginRegexesFor(cfg, class)
	if err != nil {
		return fmt.Errorf(
			"permission denied: login class %q has an invalid configuration regex: %w",
			class, err)
	}
	// #16080 (MGMT-01): credential paths are priced above PermConfig.
	// This runs BEFORE the no-regexes return below: a configure class
	// that authored no *-configuration regexes (rules not ok) is exactly
	// the limited class the issue names, and the old `if !ok { return
	// nil }` let it rewrite root / login / api credentials silently.
	// Only PermAll may mutate a credential path; the resolved path's
	// fence prefix is safe to name (it is a fixed stanza name, never
	// operator secret data).
	//
	// Fold (2): the check is SUBTREE-aware. `delete system`,
	// `deactivate system login`, `rename system to …` and
	// `copy … to system` carry an endpoint that is an ANCESTOR of a
	// fence (or the destination half of one); mutating that endpoint
	// rewrites/removes the credential subtree beneath it, so it is
	// fenced even though the typed path never names the fence.
	if hit := credentialConfigPathsHit16080(adjudicatedPaths16598); hit != "" &&
		!ClassHasPermission(cfg, class, PermAll) {
		return fmt.Errorf("permission denied: login class %q denies %s under %q (%s)",
			class, parts[0], configAuditRoot(adjudicatedPaths16598[0]),
			"credential path "+hit+" requires the super-user permission (all), not merely configure (#16080)")
	}
	if credentialConfigPathsTouch16080(adjudicatedPaths16598) &&
		!ClassHasPermission(cfg, class, PermAll) {
		return fmt.Errorf("permission denied: login class %q denies %s under %q (%s)",
			class, parts[0], configAuditRoot(adjudicatedPaths16598[0]),
			"mutation of a credential ancestor can rewrite login/root/api credentials and requires the super-user permission (all), not merely configure (#16080)")
	}
	if !ok {
		// #16080: still adjudicate an embedded change-configuration
		// payload below — the fence applies to the payload's targets
		// even for a class with no *-configuration regexes, which the
		// old early return skipped entirely.
		return authorizeEmbeddedChangeConfig9939(cfg, class, editPath, parts, quoted, depth)
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
	for _, path := range adjudicatedPaths16598 {
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
	// Identity counting needs schema-known tokens. A cursor the
	// schema cannot segment at all (synthetic/test cursors) falls
	// back to token-level counting so those cursors keep their
	// established level semantics.
	ids := len(editIdentityStarts(editPath))
	tokenLevel := ids == 0
	if tokenLevel {
		ids = len(editPath)
	}
	if rest >= len(parts) {
		// Bare navigation: `up` or `up n`. Pop whole schema
		// identities (#15237 A53-02): from `[edit security zones
		// security-zone trust]`, one up lands at `[edit security
		// zones]`, not at the dangling keyword `security-zone`.
		// A count past the top clamps to the root.
		if n >= ids {
			return nil, nil, nil, true
		}
		if n == 0 {
			return append([]string{}, editPath...), nil, nil, true
		}
		if tokenLevel {
			return append([]string{}, editPath[:len(editPath)-n]...), nil, nil, true
		}
		return TruncateEditPathIdentities(editPath, ids-n), nil, nil, true
	}
	// Prefixed form: the count is in LEVELS (identities), not tokens.
	// An identity count past the cursor height cannot run — fail
	// closed rather than silently running at the root.
	if n > ids {
		return nil, nil, nil, false
	}
	if tokenLevel {
		target = append([]string{}, editPath[:len(editPath)-n]...)
	} else {
		target = TruncateEditPathIdentities(editPath, ids-n)
	}
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
//
// innerLine is the unconsumed tail of the ORIGINAL line, sliced
// after the consumed prefix tokens (#15759): quoted strings keep
// their quotes and interior spacing, bracket lists keep their
// brackets, and pipe modifiers (`| compare`, `| display set`)
// survive, because the strict gate lexer (which stops at the
// first pipe/bracket) never tokenizes them and a
// strings.Join(inner, " ") round-trip destroys all three.
// Executors must dispatch innerLine, never a re-join of inner;
// inner/innerQuoted remain for callers that need token views.
func ParseTopUpPrefix15082(editPath []string, line string) (target, inner []string, innerLine string, ok bool) {
	// Validate the prefix with the SAME lexer the gate uses so a
	// quoted "top"/"up" (a string token whose value coincides) is
	// never consumed as the prefix verb, exactly as
	// lexConfigMutationLine9938 sees it.
	parts, quoted := lexConfigMutationLine9938(line)
	if len(parts) == 0 || (parts[0] != "top" && parts[0] != "up") {
		return nil, nil, "", false
	}
	if len(quoted) > 0 && quoted[0] {
		return nil, nil, "", false
	}
	// Consume exactly the prefix tokens the shared resolver will
	// consume and slice the raw tail at that byte offset. The count
	// classification replicates ResolveTopUpPrefix15082: an
	// unquoted numeric token after `up` is a count only when it
	// parses (a numeric-but-out-of-range token is malformed and
	// fails closed in the resolver, so slicing is never reached
	// for a dispatchable line — the resolver still adjudicates).
	consume := 1
	if parts[0] == "up" && len(parts) >= 2 && !(len(quoted) > 1 && quoted[1]) {
		if _, err := parseUpCount15082(parts[1]); err == nil {
			consume = 2
		}
	}
	innerLine = rawTailAfterLexerTokens15759(line, consume)
	target, inner, _, ok = ResolveTopUpPrefix15082(editPath, parts, quoted)
	if !ok {
		return nil, nil, "", false
	}
	if len(inner) == 0 {
		return target, nil, "", true
	}
	return target, inner, innerLine, true
}

// rawTailAfterLexerTokens15759 returns the raw remainder of line
// after the first n lexer tokens (identifier/string), trimmed of
// surrounding whitespace. Brackets and pipes are structural to the
// lexer (stripped or tokenized, never part of a token value), so
// they survive in the tail exactly as typed (#15759). It returns ""
// when fewer than n tokens lex or a structural token intervenes,
// matching the gate's token view.
func rawTailAfterLexerTokens15759(line string, n int) string {
	lex := NewLexer(line)
	for range n {
		tok := lex.Next()
		if tok.Type != TokenIdentifier && tok.Type != TokenString {
			return ""
		}
	}
	if lex.Position() > len(line) {
		return ""
	}
	return strings.TrimSpace(line[lex.Position():])
}
