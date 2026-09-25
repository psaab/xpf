package config

import (
	"fmt"
	"strings"
)

// #1798: free-text config values (interface/zone/policy descriptions,
// annotations, auth keys, IKE secrets) flow verbatim into generated
// config files — systemd-networkd units, frr.conf, swanctl.conf. The
// lexer maps the `\n` escape inside a quoted string to a real newline
// (lexer.go readString), so a value like "lan\nDHCP=ipv4" injects an
// arbitrary directive into the generated file. Two config-level layers
// defend against this:
//
//   - The STRICT compile path (CompileConfig / CompileConfigForNode,
//     reached only via commit / commit-check — Store.compileTree)
//     hard-rejects any tree value or annotation containing an ASCII
//     control character, so a new operator edit fails loudly at commit
//     time. This check deliberately does NOT live in SchemaValidate:
//     the lenient boot/peer-sync paths need the value scrubbed IN
//     PLACE, which the read-only schema walk cannot do. (Since #1319
//     PR 2, SchemaValidate violations are themselves downgraded to a
//     warning on those tolerant paths — configstore.compileTreeLenient
//     — so a bad persisted typed leaf cannot fail boot either.)
//
//   - The LENIENT compile path (CompileConfigLenient /
//     CompileConfigForNodeLenient — Store.Load, Store.SyncApply, and
//     read-only peer-interface display) sanitizes the values in place
//     with a warning instead, and the configstore migration helper
//     SanitizeTreeControlChars cleans the stored tree itself so an
//     already-persisted bad value can neither fail boot nor make the
//     operator's next unrelated commit fail mysteriously.
//
// The RENDER-SIDE layer is independent of both: networkd sanitizes controls
// and trailing-backslash continuations only in free-text Description= fields,
// and refuses unsafe single-token structured values (#10718); FRR and IPsec
// apply their own consumer-grammar sanitizers and guards at render time.
//
// #3900: a second, annotation-only injection class rides the same two
// layers. Node annotations (the `annotate` command) are emitted VERBATIM
// into `/* ... */` block comments by ast_format.go. An annotation
// containing the sequence `*/` closes the comment early, so every token
// after it is re-lexed as real configuration on the next Format→Parse
// round-trip — HA config sync (the primary formats, the secondary
// re-parses) and rollback/archive reload. `/*` is neutralized on the
// same footing (a stray open would swallow following statements as an
// unterminated comment). The strict commit path REJECTS a comment
// delimiter in an annotation; the lenient load/peer-sync path scrubs it
// in place (breaking the pair with a space). The comment-delimiter guard
// is applied to annotations only, because config VALUES cannot open a
// comment: quoteKey quotes any value that would, and the lexer never
// starts a comment inside a quoted string.
//
// #6523 corrected the justification for that last clause. The original
// #3900 wording was "values are emitted quoted", which was never true:
// quoteKey emitted a value bare whenever every byte satisfied
// isIdentChar, and isIdentChar admits `/`, `*` and `:` — so a value of
// `//x`, `/*x*/` or `inactive:` went out unquoted and was re-read as a
// comment or as the parser's deactivation marker on the next Parse. The
// premise holds now, for a narrower reason: quoteKey's predicate was
// tightened (bareKeySafe, ast.go) so that bare emission requires the
// text to re-lex through the REAL lexer as exactly one identifier equal
// to itself, and to not be a parser-level marker. Values still need no
// scrubbing here — but because the serializer quotes SPECIFICALLY WHAT
// IS UNSAFE, not because all values are quoted. Most still go bare.

// hasControlChars reports whether s contains any ASCII control
// character: the full C0 set (0x00–0x1F, which includes \n, \r and \t)
// or DEL (0x7F). The byte-wise scan is correct for UTF-8 input because
// multi-byte sequences never contain bytes below 0x80.
func hasControlChars(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}

// sanitizeControlChars returns s with every ASCII control character
// (C0 set and DEL) replaced by a single space. Replacing rather than
// deleting keeps adjacent words readable ("lan\nDHCP=ipv4" becomes
// "lan DHCP=ipv4", not "lanDHCP=ipv4").
func sanitizeControlChars(s string) string {
	if !hasControlChars(s) {
		return s
	}
	b := []byte(s)
	for i := range b {
		if b[i] < 0x20 || b[i] == 0x7f {
			b[i] = ' '
		}
	}
	return string(b)
}

// ValidateAnnotationText returns a non-nil error if the annotation text
// contains an ASCII control character or a `*/`/`/*` block-comment
// delimiter (#3900). It is the single validation entry point for the
// `annotate` command path (configstore.Store.Annotate), giving the
// operator immediate feedback instead of deferring the rejection to
// commit. The strict commit path (validateNodesControlChars) applies the
// same rule as a backstop for annotations introduced by any other route.
func ValidateAnnotationText(annotation string) error {
	if hasControlChars(annotation) {
		return fmt.Errorf("annotation %q contains control characters (newlines and other control characters are not allowed in annotations)", annotation)
	}
	if hasCommentDelim(annotation) {
		return fmt.Errorf("annotation %q contains a comment delimiter (the sequences '*/' and '/*' are not allowed in annotations — they would close the comment and inject the remaining text as configuration on reload)", annotation)
	}
	return nil
}

// hasCommentDelim reports whether s contains a block-comment delimiter
// (`*/` or `/*`). Annotations are emitted verbatim between `/* */`, so
// either sequence lets annotation text escape the comment on the next
// Format→Parse round-trip (#3900). Values never need this check — a value
// carrying a comment delimiter is emitted QUOTED by quoteKey/bareKeySafe
// (#6523), and the lexer does not start a comment inside a quoted string, so
// the delimiter cannot escape. Most values are still emitted BARE; it is
// specifically the unsafe ones that get quoted. The guard is therefore used on
// annotations only, which are emitted verbatim between `/* */` and so have no
// equivalent protection.
func hasCommentDelim(s string) bool {
	for i := 0; i+1 < len(s); i++ {
		if s[i] == '*' && s[i+1] == '/' {
			return true
		}
		if s[i] == '/' && s[i+1] == '*' {
			return true
		}
	}
	return false
}

// sanitizeCommentDelim breaks every block-comment delimiter (`*/`, `/*`)
// in s by inserting a single space between the two characters, so the
// text can no longer close or open a `/* */` comment. The single
// left-to-right pass also splits chained delimiters such as `*/*` and
// `/*/` (a delimiter created by a preceding split is re-examined on the
// next byte), so the result is guaranteed free of both sequences.
// Replacing rather than deleting keeps the annotation readable.
func sanitizeCommentDelim(s string) string {
	if !hasCommentDelim(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 4)
	for i := 0; i < len(s); i++ {
		b.WriteByte(s[i])
		if i+1 < len(s) {
			if (s[i] == '*' && s[i+1] == '/') || (s[i] == '/' && s[i+1] == '*') {
				b.WriteByte(' ')
			}
		}
	}
	return b.String()
}

// joinNodePath builds a human-readable config path for error/warning
// messages. Key values are sanitized for display so a path containing
// the offending newline does not itself produce a multi-line message.
func joinNodePath(prefix string, keys []string) string {
	clean := make([]string, len(keys))
	for i, k := range keys {
		clean[i] = sanitizeControlChars(k)
	}
	joined := strings.Join(clean, " ")
	if prefix == "" {
		return joined
	}
	return prefix + " " + joined
}

// renderNodePathFlat builds the human-readable path from a FLATTENED key path,
// masking every secret VALUE token (#7395).
//
// It resolves secrecy through secretIndices (ast_redact.go) — the SAME
// resolution the raw-AST display paths use, and the only one in the tree that is
// AST-SHAPE INDEPENDENT. That is the whole point: `authentication-key <PSK>`
// arrives either as ONE node whose Keys are ["authentication-key", "<PSK>"]
// (flat-set) or as TWO chained nodes (hierarchical parse), and a predicate that
// reads keys[0] matches the keyword in the first shape and the VALUE in the
// second. secretIndices sees the flattened path, so both shapes resolve
// identically.
func renderNodePathFlat(fp []string) string {
	clean := make([]string, len(fp))
	for i, k := range fp {
		clean[i] = sanitizeControlChars(k)
	}
	for idx := range secretValueIndicesFlat(fp) {
		if idx >= 0 && idx < len(clean) {
			clean[idx] = SecretRedacted
		}
	}
	return strings.Join(clean, " ")
}

// secretValueIndicesFlat returns the positions of the flattened key path that
// hold a secret VALUE, as the UNION of the tree's two secret-leaf resolutions.
//
// There are two because #6625 added one (secretLeafKeywords / isSecretLeaf, in
// secret.go) beside the one the raw-AST display paths already used
// (secretIndices, in ast_redact.go), and they do not agree: `password` is
// unconditional in the first and gated to `api-auth`/`dynamic-dns` in the
// second, while the second additionally knows authentication-password,
// privacy-password, simple-password, api-token, aws-secret-key,
// `community` under snmp and `key` under `authentication md5`.
//
// Taking the union rather than picking one is deliberate. Each list is a claim
// that something IS a credential; disagreement means one of them has a leaf the
// other has not learned about yet, and in a redactor the safe resolution of
// "one says secret" is secret. The cost of over-redacting is a lost diagnostic;
// the cost of under-redacting is a published credential.
//
// It is evaluated over the FLATTENED path, which is what makes it independent
// of AST shape: `authentication-key <PSK>` arrives either as ONE node whose Keys
// are ["authentication-key", "<PSK>"] (flat-set) or as TWO chained nodes
// (hierarchical parse). A predicate reading keys[0] matches the keyword in the
// first and the VALUE in the second — which is why #6625's fix covered only the
// flat shape (#7395).
//
// Both root-gated cases survive the union intact: a policy-options `community`
// is a BGP route-target name and stays legible in BOTH resolutions, so #4097's
// diagnostic is not broken.
func secretValueIndicesFlat(fp []string) map[int]bool {
	out := map[int]bool{}
	for _, i := range secretIndices(fp) {
		out[i] = true
	}
	for i, k := range fp {
		if !IsSecretLeafKeyword(k) {
			continue
		}
		// Every token after the keyword is its value (covers a multi-token or
		// bracketed-list value), matching redactSecretKeys' keys[1:] rule.
		for j := i + 1; j < len(fp); j++ {
			out[j] = true
		}
	}
	return out
}

// isSecretValueIndex reports whether position idx of the flattened key path is a
// secret VALUE token.
func isSecretValueIndex(fp []string, idx int) bool {
	return secretValueIndicesFlat(fp)[idx]
}

// splitNodePathPrefix recovers the flattened key path from the joined string
// form the exported entry points still accept. Empty prefix is the root.
func splitNodePathPrefix(prefix string) []string {
	if prefix == "" {
		return nil
	}
	return strings.Split(prefix, " ")
}

// validateNodesControlChars walks the (group-expanded) AST and returns
// an error for the first value or annotation containing a control
// character, or the first annotation containing a `*/`/`/*` comment
// delimiter (#3900). Strict commit-path only — see the package comment
// above.
func validateNodesControlChars(nodes []*Node, prefix string) error {
	return validateNodesControlCharsAt(nodes, splitNodePathPrefix(prefix))
}

// validateNodesControlCharsAt is the recursion, carrying the path as a SLICE.
//
// The slice is what makes shape-independent secrecy possible: secretIndices
// resolves a keyword to the positions of its value tokens, so it needs the
// components. Re-splitting the joined form per level would also split a string
// built from SANITIZED components, and a sanitized token can contain the space
// being split on — silently shifting every index after it.
func validateNodesControlCharsAt(nodes []*Node, base []string) error {
	for _, n := range nodes {
		// #6625/#7395: a credential leaf must never have its VALUE rendered,
		// and the path renders every key — so for `authentication-key <PSK>`
		// an un-redacted path published the secret a SECOND time, alongside
		// the quoted value below.
		fp := append(append([]string(nil), base...), n.Keys...)
		nodePath := renderNodePathFlat(fp)
		for i, k := range n.Keys {
			if hasControlChars(k) {
				if isSecretValueIndex(fp, len(base)+i) {
					// Report WHERE and WHAT, never the value. The offset plus
					// the byte is enough to fix the input — a leading tab from
					// a password manager is offset 0, a trailing CR is the last
					// offset — and discloses nothing. Rendering it would put the
					// credential into commit output, the daemon log and the
					// audit journal, which is exactly what the operator was
					// trying to set privately.
					return fmt.Errorf("%s: value contains %s (newlines and other control characters are not allowed in configuration values; the value is not shown because this statement carries a credential)", nodePath, describeControlChar(k))
				}
				return fmt.Errorf("%s: value %q contains control characters (newlines and other control characters are not allowed in configuration values)", nodePath, k)
			}
		}
		if hasControlChars(n.Annotation) {
			return fmt.Errorf("%s: annotation %q contains control characters (newlines and other control characters are not allowed in annotations)", nodePath, n.Annotation)
		}
		if hasCommentDelim(n.Annotation) {
			return fmt.Errorf("%s: annotation %q contains a comment delimiter (the sequences '*/' and '/*' are not allowed in annotations — they would close the comment and inject the remaining text as configuration on reload)", nodePath, n.Annotation)
		}
		if err := validateNodesControlCharsAt(n.Children, fp); err != nil {
			return err
		}
	}
	return nil
}

// sanitizeNodesControlChars walks the AST replacing control characters
// in values and annotations in place — and breaking any `*/`/`/*`
// comment delimiter in an annotation (#3900) — returning one
// human-readable config path per modified node. Lenient-path
// counterpart of validateNodesControlChars.
func sanitizeNodesControlChars(nodes []*Node, prefix string) []string {
	return sanitizeNodesControlCharsAt(nodes, splitNodePathPrefix(prefix))
}

// sanitizeNodesControlCharsAt is the lenient recursion, carrying the path as a
// slice for the same reason its strict twin does.
func sanitizeNodesControlCharsAt(nodes []*Node, base []string) []string {
	var warnings []string
	for _, n := range nodes {
		changed := false
		for i, k := range n.Keys {
			if hasControlChars(k) {
				n.Keys[i] = sanitizeControlChars(k)
				changed = true
			}
		}
		if hasControlChars(n.Annotation) {
			n.Annotation = sanitizeControlChars(n.Annotation)
			changed = true
		}
		if hasCommentDelim(n.Annotation) {
			n.Annotation = sanitizeCommentDelim(n.Annotation)
			changed = true
		}
		// #7395: the same masking, through the same resolution. The caller LOGS
		// each path this returns, and this walker runs on Store.Load at BOOT and
		// on Store.SyncApply for every HA peer-sync — so an already-persisted
		// key with a stray tab was re-published to the daemon log on every
		// single boot. The strict validator fires once, on a commit; this is the
		// worse of the two surfaces, and #6625 fixed only the other one.
		fp := append(append([]string(nil), base...), n.Keys...)
		if changed {
			warnings = append(warnings, renderNodePathFlat(fp))
		}
		warnings = append(warnings, sanitizeNodesControlCharsAt(n.Children, fp)...)
	}
	return warnings
}

// SanitizeTreeControlChars replaces ASCII control characters (C0 set
// and DEL) with spaces in every value and annotation of the tree, in
// place, and returns one human-readable config path per modified node.
//
// This is the #1798 migration helper for the tolerant ingest paths
// (Store.Load on boot, Store.SyncApply on HA peer-sync): it cleans the
// tree that will become the active/candidate config so an
// already-persisted bad value cannot fail boot now or fail the
// operator's next unrelated strict commit later. Callers should log
// each returned path as a warning.
func SanitizeTreeControlChars(tree *ConfigTree) []string {
	if tree == nil {
		return nil
	}
	return sanitizeNodesControlChars(tree.Children, "")
}
