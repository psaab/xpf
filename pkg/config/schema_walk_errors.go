package config

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// schemaErrorf is the single construction choke point for schema-walk
// errors (#16066 fold 2). SchemaValidate's return value is logged
// verbatim by tolerant ingress (configstore compileTreeLenient) and
// copied into compiled warnings, so an error built anywhere in this
// walker can reach journal/syslog. Before this helper, each formatter
// redacted ad hoc — typedLeafInvalidErrorf (#8434), then
// typedLeafErrorf (fold 1) — and the class kept recurring per-helper
// (the #8437 fused-statement formatter quoted an extra token under
// the untyped `password`/`tsig-secret` DDNS leaves). Now EVERY schema
// error is constructed here: callers pass the leaf's full key path
// (path tokens plus the node's own Keys) and the already-formatted
// message; secret-indexed tokens are scrubbed from the formatted message,
// and paths are rendered through redactSecretPath (including URL
// userinfo/query/fragment redaction). Paths without classified secrets or
// URLs and their messages pass through byte-identical. Validators that
// return their own errors (ValidateCryptHash, #16066) must still be
// value-free at the source; this is the walker-level net for
// formatter-built text.
// pathHasSecretIndex reports whether fullPath carries any
// secret-indexed token (fold 6): the CONSTRUCTION-TIME test for
// "this error's operands sit ON a known secret leaf". Unlike the
// belt, it has no length/vocabulary exception — on a secret leaf,
// operands are operator values and are dropped unconditionally.
func pathHasSecretIndex(fullPath []string) bool {
	return len(secretIndices(fullPath)) > 0
}

// redactedPathArg marks a path string that is ALREADY rendered through
// redactSecretPath / redactedLocName. Secret operands are masked and
// URL-classified values are transformed; no credential bytes remain.
// redactArgsOnSecretLeaf exempts marked args (fold 7, GLM F2 — unmarked,
// the #8437 site's path prefix and every schemaPathErrorf joined prefix
// were redacted as if operands, collapsing locations to <redacted>).
type redactedPathArg string

// redactArgsOnSecretLeaf replaces EVERY string argument with
// SecretRedacted when fullPath is secret-indexed (fold 6), EXCEPT
// redactedPathArg-marked ones. String args on a secret leaf are
// operator operands (extra/trailing/modifier tokens); non-string
// args (counts, args-arity) are kept. Defect-class format text is
// untouched, so diagnostics keep their class.
func redactArgsOnSecretLeaf(fullPath []string, args []interface{}) []interface{} {
	if !pathHasSecretIndex(fullPath) {
		return args
	}
	out := make([]interface{}, len(args))
	for i, a := range args {
		switch v := a.(type) {
		case redactedPathArg:
			out[i] = string(v)
		case string:
			out[i] = SecretRedacted
		default:
			out[i] = a
		}
	}
	return out
}

func schemaErrorf(fullPath []string, format string, args ...interface{}) error {
	args = redactArgsOnSecretLeaf(fullPath, args)
	msg := fmt.Sprintf(format, args...)
	return fmt.Errorf("%s", scrubSecretTokens(fullPath, msg))
}

// schemaPathErrorf is schemaErrorf for the common walker shape: the
// message is "<joined redacted path>: <formatted detail>". The
// joined prefix is safely pre-rendered (secret operands masked and URL
// values transformed by redactSecretPath), so it is not operand-redacted.
func schemaPathErrorf(fullPath []string, format string, args ...interface{}) error {
	joined := strings.Join(redactSecretPath(fullPath), " ")
	args = redactArgsOnSecretLeaf(fullPath, args)
	detail := fmt.Sprintf(format, args...)
	return schemaErrorf(fullPath, "%s: %s", redactedPathArg(joined), detail)
}

// unknownTopLevelStanzaSchemaError marks the deliberate, one-level closed-world
// check for root keywords the compiler cannot consume. Tolerant ingress records
// this class on Config.Warnings without treating it as a typed-leaf violation.
type unknownTopLevelStanzaSchemaError struct{ msg string }

func (e *unknownTopLevelStanzaSchemaError) Error() string { return e.msg }

func unknownTopLevelStanzaSchemaErrorForKeyword(kw string) error {
	return &unknownTopLevelStanzaSchemaError{
		msg: fmt.Sprintf("unknown configuration stanza %q: it is not a recognised top-level keyword, "+
			"so everything configured under it would be silently discarded", kw),
	}
}

// IsUnknownTopLevelStanzaSchemaError reports whether err is the schema
// rejection for an unmodeled root stanza, including when wrapped.
func IsUnknownTopLevelStanzaSchemaError(err error) bool {
	var unknown *unknownTopLevelStanzaSchemaError
	return errors.As(err, &unknown)
}

// typedLeafSchemaError marks an ordinary schema rejection from a typed
// validator or typed-value structure, including validated keys, multi/tail
// values, and modifiers. The tolerant configstore path may persist this
// class as a queryable typed-leaf warning. The separate nested-list-content
// error class is not classified as typed for ordinary warning collection;
// its dedicated hard-error path is enforced by schema-aware fallback scanning
// and compileTreeLenient.
type typedLeafSchemaError struct{ msg string }

func (e *typedLeafSchemaError) Error() string { return e.msg }

// nestedListContentSchemaError marks a hard nested-content refusal for a
// block-list child under a refuseNonLeafBlockChildren leaf that is not a
// plain leaf value. Such a reader does not consume grandchildren
// (firewallMatchValues reads only the child's Keys), so tolerating the
// content on Store.Load or Store.SyncApply would install a silently truncated
// config. Introduced for VRRP virtual-address/virtual-inet6-address and
// WireGuard allowed-ips (#17241), this class also covers other direct-child
// value-list readers. configstore's compileTreeLenient promotes it to a hard
// error; other schema errors keep their tolerant downgrade.
type nestedListContentSchemaError struct{ msg string }

func (e *nestedListContentSchemaError) Error() string { return e.msg }

// IsNestedListContentSchemaError reports whether err is the dedicated
// nested-content refusal, including when wrapped.
func IsNestedListContentSchemaError(err error) bool {
	var nested *nestedListContentSchemaError
	return errors.As(err, &nested)
}

func nestedListContentErrorf(path []string, leafName, value string) error {
	return &nestedListContentSchemaError{msg: typedLeafErrorf(path,
		"nested content under %s value %q is not supported; write values as separate statements (%s { %s; }) or a bracket list (%s [ %s ])",
		leafName, value, leafName, value, leafName, value).Error()}
}

// IsTypedLeafSchemaError reports whether err (including wrapped errors) came
// from the typed-validator/typed-value partition. It deliberately excludes
// top-level stanza, closed-world keyword, node-validator/scalar-arity,
// midKeyword structural, and the dedicated nested-content refusal errors.
func IsTypedLeafSchemaError(err error) bool {
	var typed *typedLeafSchemaError
	return errors.As(err, &typed)
}

// typedLeafErrorf builds a commit-check error scoped to the leaf's
// consumed config path, e.g. "class-of-service schedulers be
// transmit-rate: missing value". path already includes the leaf keyword.
//
// It delegates to schemaPathErrorf (the #16066 shared choke point):
// call sites format an operator token with %q — the additional-token
// arms ("unknown modifier %q") in validateTypedLeaf /
// validateModifierChild quote whatever follows a VALID first value,
// so a plaintext pasted as an extra token of `encrypted-password`
// reached tolerant-ingress logs verbatim even though the validator
// itself never echoes. The choke point scrubs every secret-indexed
// token of the leaf path from the formatted text while the defect
// class ("unknown modifier") survives; non-secret leaves keep
// quoting the token — that diagnostic is the point there.
func typedLeafErrorf(path []string, format string, args ...interface{}) error {
	// Fold 6: operands ON a secret leaf are dropped unconditionally.
	// The caller passes only the leaf PATH (the extra token is not
	// in it), so when isSecretLeaf holds for the leaf keyword, every
	// string arg is an operand of this leaf and is replaced. The
	// belt exit scrub cannot see short/vocabulary tokens (`abc`,
	// `password`) — construction is the only sound layer for them.
	if len(path) > 0 && isSecretLeaf(strings.Join(redactSecretPath(path), " "), path[len(path)-1:]) {
		// Copy before mutating (GLM residual): never corrupt a
		// caller's spread slice. redactedPathArg args pass through.
		cp := make([]interface{}, len(args))
		for i, a := range args {
			if _, isPath := a.(redactedPathArg); isPath {
				cp[i] = a
			} else if _, ok := a.(string); ok {
				cp[i] = SecretRedacted
			} else {
				cp[i] = a
			}
		}
		args = cp
	}
	detail := fmt.Sprintf(format, args...)
	return &typedLeafSchemaError{
		msg: schemaPathErrorf(path, "%s", detail).Error(),
	}
}

// typedLeafInvalidErrorf builds the "invalid value" variant which quotes
// the offending token and the validator's own message.
//
// #8434: EXCEPT when the leaf carries a credential. This path echoed the value
// of `encrypted-password` (both `system login user ... authentication` and
// `system root-authentication`) straight back into a commit error an operator
// sees, logs, and pastes into a bug report.
//
// The project had already decided this leaf is a secret — it is in
// `secretLeafKeywords` (secret.go) — and the redaction machinery is live: the
// same value under `security ike policy pre-shared-key` renders `<redacted>`.
// This was one path not consulting a registry the project maintains and other
// paths honour, which is why keying on the REGISTRY rather than on a list of
// leaves is the fix: the next typed secret leaf is covered by construction.
//
// `isSecretLeaf` rather than `IsSecretLeafKeyword` because dual-use keywords
// are resolved by their root — `community` is a credential under `snmp` and a
// BGP route-target name under `policy-options`, and #4097 exists to show the
// operator WHICH community member was bad. Blanket keyword-keying broke that
// diagnostic once already.
//
// The validator's own message is redacted too when it contains the token:
// schema_validators.go's "invalid value %q (expected one of: ...)" echoes it a
// SECOND time, so redacting only the wrapper leaves the leak intact. The
// containment test can over-redact for a very short token; that is the safe
// direction and it is preferred to reasoning about which validators echo.
//
// #16066 fold 2: the final text additionally passes through
// schemaPathErrorf, so any secret token of the leaf (not just tok)
// appearing anywhere in the message is scrubbed at the shared choke
// point.
// scrubSecretTokens replaces secret-indexed tokens of fullPath
// occurring in msg. Fold 5 restricts it to the belt remit, same as
// the exit scrub: values shorter than 4 chars or equal to public
// vocabulary (leaf/keyword names) are NOT substituted — the
// plaintext "password" pasted as a value must not mangle the public
// word `password` in diagnostics (the validator's value-free text
// is the guarantee there; see beltSecretValues). Longer values are
// replaced in raw and strconv.Quote forms (fold 3, formatting-aware:
// %q escapes quote/backslash/control, hiding the raw form).
func scrubSecretTokens(fullPath []string, msg string) string {
	if idx := secretIndices(fullPath); len(idx) > 0 {
		seen := make(map[string]bool, len(idx))
		var vals []string
		for _, i := range idx {
			if i < 0 || i >= len(fullPath) {
				continue
			}
			tok := fullPath[i]
			if tok == "" || seen[tok] {
				continue
			}
			seen[tok] = true
			vals = append(vals, tok)
		}
		for _, tok := range beltSecretValues(vals) {
			msg = strings.ReplaceAll(msg, tok, SecretRedacted)
			if q := strconv.Quote(tok); q != tok {
				msg = strings.ReplaceAll(msg, q, strconv.Quote(SecretRedacted))
			}
		}
	}
	return msg
}

// quotedInterior returns tok as it appears INSIDE a %q-quoted larger
// string: strconv.Quote without the surrounding quote bytes (fold 4,
// F1). A formatter that quotes a whole space-joined path escapes the
// secret token in place; neither the raw token nor Quote(tok) (which
// carries surrounding quotes) occurs there, but this interior form
// does — byte-identical to what %q emits for those characters.
func quotedInterior(tok string) string {
	q := strconv.Quote(tok)
	if len(q) >= 2 && q[0] == '"' && q[len(q)-1] == '"' {
		return q[1 : len(q)-1]
	}
	return q
}

// collectSecretValues returns every secret VALUE and every URL-classified
// value that RedactURL actually transforms in the candidate: for each node,
// the secret-indexed tokens and transformable URL tokens of its flattened
// path, PLUS the inner secret and transformable URL tokens of any embedded
// `change-configuration commands` payload (fold 4, F2 — the outer AST sees
// the quoted command as one token, so its inner credentials are collected
// by lexing it exactly as the ingest guard does). Deduplicated, longest
// first so a longer value is replaced before any shorter value it contains.
func collectSecretValues(tree *ConfigTree) []string {
	if tree == nil {
		return nil
	}
	seen := make(map[string]bool)
	var values []string
	add := func(tok string) {
		if tok != "" && !seen[tok] {
			seen[tok] = true
			values = append(values, tok)
		}
	}
	var walk func(nodes []*Node, base []string)
	walk = func(nodes []*Node, base []string) {
		for _, n := range nodes {
			if n == nil {
				continue
			}
			full := append(append([]string(nil), base...), n.Keys...)
			for _, i := range secretIndices(full) {
				if i >= 0 && i < len(full) {
					add(full[i])
				}
			}
			for _, i := range urlLeafIndices(full) {
				if i >= 0 && i < len(full) && RedactURL(full[i]) != full[i] {
					add(full[i])
				}
			}
			// Embedded commands payload: lex each candidate payload
			// token (any token after a change-configuration/commands
			// pair in this node's flattened path) and collect its
			// inner secret values.
			for i := 0; i+1 < len(full); i++ {
				if full[i] != "change-configuration" || full[i+1] != "commands" {
					continue
				}
				for _, payload := range full[i+2:] {
					tokens, _ := lexConfigMutationLine9938(payload)
					if len(tokens) < 2 || tokens[0] != "set" {
						continue
					}
					for _, idx := range secretIndices(tokens) {
						if idx >= 0 && idx < len(tokens) {
							add(tokens[idx])
						}
					}
					for _, idx := range urlLeafIndices(tokens) {
						if idx >= 0 && idx < len(tokens) && RedactURL(tokens[idx]) != tokens[idx] {
							add(tokens[idx])
						}
					}
				}
			}
			walk(n.Children, full)
		}
	}
	walk(tree.Children, nil)
	// Longest first: replacing a contained shorter value first would
	// corrupt the longer one's match.
	for i := range values {
		for j := i + 1; j < len(values); j++ {
			if len(values[j]) > len(values[i]) {
				values[i], values[j] = values[j], values[i]
			}
		}
	}
	return values
}

// collectURLValues returns the URL-classified tokens of the tree that
// RedactURL actually changes (direct urlLeafIndices positions plus the
// same positions inside embedded change-configuration/commands payloads),
// deduplicated. It exists beside collectSecretValues because the exit
// scrub's needle set is beltSecretValues-filtered (values shorter than
// 4 bytes and public vocabulary are dropped): a short credential-bearing
// URL token such as "a@b" or ":p@" is RedactURL-transformed yet below
// the belt floor, so it must reach the scrub unbelted (#18997).
// Credential-free URLs are no-ops under RedactURL and never returned,
// so no legitimate URL spelling becomes a scrub needle.
func collectURLValues(tree *ConfigTree) []string {
	if tree == nil {
		return nil
	}
	seen := make(map[string]bool)
	var values []string
	add := func(tok string) {
		if tok != "" && !seen[tok] {
			seen[tok] = true
			values = append(values, tok)
		}
	}
	var walk func(nodes []*Node, base []string)
	walk = func(nodes []*Node, base []string) {
		for _, n := range nodes {
			if n == nil {
				continue
			}
			full := append(append([]string(nil), base...), n.Keys...)
			for _, i := range urlLeafIndices(full) {
				if i >= 0 && i < len(full) && RedactURL(full[i]) != full[i] {
					add(full[i])
				}
			}
			for i := 0; i+1 < len(full); i++ {
				if full[i] != "change-configuration" || full[i+1] != "commands" {
					continue
				}
				for _, payload := range full[i+2:] {
					tokens, _ := lexConfigMutationLine9938(payload)
					if len(tokens) < 2 || tokens[0] != "set" {
						continue
					}
					for _, idx := range urlLeafIndices(tokens) {
						if idx >= 0 && idx < len(tokens) && RedactURL(tokens[idx]) != tokens[idx] {
							add(tokens[idx])
						}
					}
				}
			}
			walk(n.Children, full)
		}
	}
	walk(tree.Children, nil)
	return values
}

// scrubSecretValuesText is the FINAL-string-level scrub (fold 4):
// given the candidate's secret values, replace every occurrence in
// text in raw, strconv.Quote, and quoted-interior forms. This is the
// level token substitution kept losing to embedding — a value quoted
// inside a larger %q string, or carried inside a quoted embedded
// command, is still found because matching is on the final rendered
// bytes, not on which formatter produced them.
func scrubSecretValuesText(values []string, text string) string {
	// Span-merging over the ORIGINAL text is the mechanism: sequential
	// ReplaceAll lets an earlier needle destroy a partially overlapping
	// later one's match and leaves a credential half standing, in
	// either order, for raw, strconv.Quote, and quoted-interior forms
	// alike (Kimi folds). Occurrences of every form become spans;
	// overlapping spans merge into one sentinel.
	//
	// Sentinel-containing values ("only<redacted>credential" is a real
	// password SchemaValidate accepts) join the SAME span pass, but
	// their inserted replacement cannot be SecretRedacted itself: a
	// later needle ("redacted") would match inside it. Their spans are
	// instead emitted as a NUL-wrapped PIVOT (the pivot string never
	// appears in a rendered diagnostic; the lexer tolerates NUL bytes
	// inside quoted values but no producer emits this exact token), rewritten to
	// SecretRedacted once, after all spanning. Because the pivot
	// substitution happens in the span pass itself (not as a text
	// pre-pass), an ordinary needle partially overlapping a
	// sentinel-containing value still merges with its span instead of
	// being destroyed before matching (Sol fold at f33328217a). The
	// quoted pivot's final rewrite covers both raw and Quote forms.
	// Collision residual (accepted): a diagnostic literally containing
	// the pivot string itself would be rewritten — config text cannot
	// practically carry it (it would have to be planted as an exact
	// NUL-wrapped token in a quoted value, which the lexer tolerates
	// but no producer emits), and the rewrite fails toward redaction,
	// never toward disclosure.
	const pivot = "\x00xpf-redacted-pivot\x00"
	ordered := append([]string(nil), values...)
	sort.SliceStable(ordered, func(i, j int) bool {
		return len(ordered[i]) > len(ordered[j])
	})
	type span struct {
		lo, hi int
		pivot  bool
	}
	var spans []span
	addSpans := func(needle string, pivot bool) {
		if needle == "" {
			return
		}
		for at := 0; ; {
			i := strings.Index(text[at:], needle)
			if i < 0 {
				break
			}
			spans = append(spans, span{at + i, at + i + len(needle), pivot})
			at += i + 1
		}
	}
	for _, v := range ordered {
		if v == "" {
			continue
		}
		pivotValue := strings.Contains(v, SecretRedacted)
		addSpans(v, pivotValue)
		if q := strconv.Quote(v); q != v {
			addSpans(q, pivotValue)
		}
		if in := quotedInterior(v); in != v && len(in) >= 2 {
			addSpans(in, pivotValue)
		}
	}
	if len(spans) == 0 {
		return text
	}
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].lo != spans[j].lo {
			return spans[i].lo < spans[j].lo
		}
		return spans[i].hi > spans[j].hi
	})
	var b strings.Builder
	pos, end := 0, -1
	pivotSpan := false
	flush := func() {
		if pivotSpan {
			b.WriteString(pivot)
		} else {
			b.WriteString(SecretRedacted)
		}
		pos = end
	}
	for _, sp := range spans {
		if end >= 0 && sp.lo < end {
			if sp.hi > end {
				end = sp.hi
			}
			pivotSpan = pivotSpan || sp.pivot
			continue
		}
		if end >= 0 {
			flush()
		}
		b.WriteString(text[pos:sp.lo])
		pos, end, pivotSpan = sp.lo, sp.hi, sp.pivot
	}
	flush()
	b.WriteString(text[end:])
	out := b.String()
	out = strings.ReplaceAll(out, strconv.Quote(pivot), strconv.Quote(SecretRedacted))
	return strings.ReplaceAll(out, pivot, SecretRedacted)
}
func typedLeafInvalidErrorf(path []string, tok string, err error) error {
	joined := strings.Join(redactSecretPath(path), " ")
	fullPath := append(append([]string(nil), path...), tok)
	if len(path) > 0 && isSecretLeaf(joined, path[len(path)-1:]) {
		// Fold 6: keep only the validator reason's FIXED PREFIX —
		// the text before its first operand-bearing word — rather
		// than substring-masking with the raw token. Masking rewrote
		// the validator's own fixed words when the token equaled
		// one (`password` in "encrypted password hash", `plaintext`
		// in "plaintext is not allowed"). The crypt validator's
		// sentence shape is "not an encrypted password hash — ...";
		// everything from the first secret-equal word onward is
		// dropped, so no operand (short, vocabulary, or otherwise)
		// can ride the reason, and the fixed head survives verbatim.
		// (If the sentence has no secret-equal word, it is kept
		// whole: it cannot contain the token as a word.)
		reason := "<redacted>"
		if err != nil {
			reason = fixedReasonPrefix(err.Error(), tok)
		}
		detail := fmt.Sprintf("invalid value <redacted>: %s", reason)
		return &typedLeafSchemaError{
			msg: fmt.Sprintf("%s: %s", joined, scrubSecretTokens(fullPath, detail)),
		}
	}
	detail := fmt.Sprintf("invalid value %q: %v", tok, err)
	return &typedLeafSchemaError{
		msg: fmt.Sprintf("%s: %s", joined, scrubSecretTokens(fullPath, detail)),
	}
}

// fixedReasonPrefix returns the prefix of a validator sentence up to
// (excluding) the first occurrence of tok as a standalone word, or
// the whole sentence when tok never occurs as a word. On secret
// leaves this keeps a validator's fixed head ("not an encrypted
// password hash") verbatim while no operand — including the token
// itself when it coincides with a fixed word — rides the tail.
func fixedReasonPrefix(sentence, tok string) string {
	if tok == "" || sentence == "" {
		return sentence
	}
	for _, w := range strings.Fields(sentence) {
		if w == tok {
			idx := strings.Index(sentence, tok)
			if idx > 0 {
				return strings.TrimRight(sentence[:idx], " —-")
			}
			return "<redacted>"
		}
	}
	return sentence
}

// checkUnknownTopLevelStanza rejects a root keyword the schema does not model
// (issue 8882).
//
// It closes exactly one level and inherits nothing: a keyword is checked
// against setSchema's own children, and every subtree keeps whatever
// closed-world posture it already had. That is the difference between this and
// setting setSchema.closedWorld, which would close the entire tree.
//
// Scope, stated because the asymmetry is deliberate: a typo at the ROOT
// discards an entire stanza, while a typo deeper down discards one subtree of
// whatever already-modeled parent it sits under. The root case is both the
// worst consequence and the one the schema can adjudicate with certainty --
// the 19 top-level stanzas are exhaustively modeled, which is not true at
// every depth.
func checkUnknownTopLevelStanza(tree *ConfigTree) error {
	if tree == nil {
		return nil
	}
	for _, child := range tree.Children {
		if child == nil || len(child.Keys) == 0 {
			continue
		}
		kw := child.Keys[0]
		if resolveSchemaChild(setSchema, kw) == nil {
			return unknownTopLevelStanzaSchemaErrorForKeyword(kw)
		}
	}
	return nil
}
