package config

import (
	"errors"
	"fmt"
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
// message; when any token of that path is secret per secretIndices —
// the same registry the AST redactor uses, so `password` is secret
// only under dynamic-dns/api-auth/... and `community` only under
// snmp — every secret-indexed token is scrubbed from the message
// (all occurrences) before the error is created. The path itself is
// rendered through redactSecretPath as before. Non-secret messages
// pass through byte-identical. Validators that return their own
// errors (ValidateCryptHash, #16066) must still be value-free at the
// source; this is the walker-level net for formatter-built text.
// pathHasSecretIndex reports whether fullPath carries any
// secret-indexed token (fold 6): the CONSTRUCTION-TIME test for
// "this error's operands sit ON a known secret leaf". Unlike the
// belt, it has no length/vocabulary exception — on a secret leaf,
// operands are operator values and are dropped unconditionally.
func pathHasSecretIndex(fullPath []string) bool {
	return len(secretIndices(fullPath)) > 0
}

// nameOnlyArg marks a string argument that is ALREADY a name-only
// rendering (produced by redactSecretPath / redactedLocName): stanza
// and leaf NAMES, never candidate values. redactArgsOnSecretLeaf
// exempts marked args (fold 7, GLM F2 — unmarked, the #8437 site's
// name-only prefix and every schemaPathErrorf `joined` prefix were
// redacted as if operands, collapsing locations to <redacted>).
type nameOnlyArg string

// redactArgsOnSecretLeaf replaces EVERY string argument with
// SecretRedacted when fullPath is secret-indexed (fold 6), EXCEPT
// nameOnlyArg-marked ones. String args on a secret leaf are
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
		case nameOnlyArg:
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
// joined prefix is name-only by construction (redactSecretPath),
// so it is marked and never operand-redacted.
func schemaPathErrorf(fullPath []string, format string, args ...interface{}) error {
	joined := strings.Join(redactSecretPath(fullPath), " ")
	args = redactArgsOnSecretLeaf(fullPath, args)
	detail := fmt.Sprintf(format, args...)
	return schemaErrorf(fullPath, "%s: %s", nameOnlyArg(joined), detail)
}

// SchemaValidate is the #1319 typed-leaf gate that runs at commit-check
// time, BEFORE the existing compiler. It walks the AST against setSchema
// — the SAME tree the live config-mode `set` completer walks — and, for
// every typed leaf (schemaNode.valueType != ValueAny with a validator),
// invokes the validator on the leaf's value token(s).
//
// Why pre-compile? parseBandwidthLimit / parseBurstSizeLimit silently
// return 0 on garbage input, so `set class-of-service schedulers x
// transmit-rate asd` would otherwise compile to zero bps and commit
// silently. SchemaValidate fails the commit with a human-readable error
// before the compiler ever sees the bad string.
//
// The walker is generic: it descends setSchema recursively against the
// AST and is a no-op for any subtree with no typed leaves. Untyped leaves
// (valueType == ValueAny) are not validated — the gate is opt-in per leaf,
// so the compiler keeps full responsibility for everything not yet typed.
// This is the property that lets per-subsystem typing land incrementally
// (#1319 PR 2..N) without touching this file.
//
// SchemaValidate lives in pkg/config (re-homed from pkg/cmdtree in #1319
// PR 1) because it now walks the pkg/config-owned setSchema. cmdtree no
// longer carries a config-mode typed-leaf overlay.

// SchemaValidate walks the AST against setSchema and invokes each typed
// leaf's validator on its value. It returns the FIRST error encountered
// (matching how the existing compiler surfaces commit-check failures).
//
// Validation runs BEFORE the compiler, so no *Config exists yet and
// validators take only the raw token (#16162). Cross-reference validation
// is TREE-based instead: the walk pre-collects referenceable definitions
// from the candidate tree itself into schemaRefs (collectSchemaRefs
// below) and hands them to treeValidator leaves — atomicity-correct,
// because a definition and its reference added in the same commit
// validate against the same tree.
//
// The tree passed in MUST already be apply-groups-expanded (configstore
// expands before calling), so group bodies are inlined before the walk.
// Cross-reference definitions are collected from this same tree; callers
// that still hold the PRE-expansion candidate should prefer
// SchemaValidateWithDefinitions so definitions living only in un-applied
// groups survive (expansion removes the groups stanza outright).
func SchemaValidate(tree *ConfigTree) error {
	return SchemaValidateWithDefinitions(tree, nil)
}

// SchemaValidateWithDefinitions is SchemaValidate with a separate
// definitions source for the cross-reference sets (#1319 PR 3, AGY r1
// HIGH): apply-groups expansion REMOVES the groups stanza from the
// expanded tree (ast_groups.go "Remove the \"groups\" stanza itself"),
// so a definition living ONLY in an un-applied group — e.g. the peer
// node's `groups node1 { class-of-service ... }` while validating on
// node0 of a "${node}" cluster config — would vanish from the refs
// union and false-reject a shared-section reference that is deliberate
// for the peer. Passing the PRE-expansion candidate as defsSource keeps
// the permissive union the schemaRefs contract documents. defsSource
// may be nil (refs come from tree alone).
func SchemaValidateWithDefinitions(tree, defsSource *ConfigTree) error {
	if tree == nil {
		return nil
	}
	// #2008 H1: do not validate `inactive:`-marked nodes. Junos parks
	// work-in-progress under `inactive:` and accepts a deactivated leaf
	// even when its value would be rejected if active (the whole point of
	// deactivate is reversible, inert garbage). Strip before the typed-leaf
	// walk — and strip the cross-reference definitions source too, so a
	// deactivated definition does not satisfy an active reference and an
	// inactive reference is not itself validated. WithoutInactive is a
	// no-op (no clone) when nothing is deactivated.
	tree = tree.WithoutInactive()
	defsSource = defsSource.WithoutInactive()
	// #6672: expand a PACKED `chassis cluster` body into children before the
	// walk. The walker descends `.Children`, so a statement packed onto the
	// cluster (or chassis) line sits below every modeled depth and no typed-leaf
	// validator fires on it. That was harmless while the packed spelling also
	// compiled to nothing; now that it compiles, the same normalization must
	// happen HERE or the packed spelling would reach the runtime with an ungated
	// `cluster-id` (one byte of the RETH virtual MAC) and an ungated
	// `reth-advertise-interval` (a 12-bit VRRP wire field) while the container
	// spelling stays gated. One splitter, both consumers — the alternative is a
	// second hand-written bounds table that drifts from the schema.
	//
	// No-op (no clone) when nothing is packed, like WithoutInactive above.
	tree = normalizePackedChassisCluster(tree)
	// issue 8867: the SAME reasoning as #6672 above, generalised. That fix
	// un-packs one container (`chassis cluster`) before the walk because the
	// walker descends `.Children`, so a statement packed onto a container line
	// sits below every modelled depth and no typed-leaf validator fires on it.
	// Every pair admitted to compactNormalizeInScope has exactly that property:
	// the compiler normalizes it (compiler.go) and therefore COMPILES its
	// value, while this walk still sees the un-normalized shape and validates
	// nothing. Measured before this change: of 161 validator-bearing typed
	// leaves reachable at an admitted pair, 146 were rejected in the braced
	// spelling and ACCEPTED in the packed one.
	//
	// One splitter, both consumers -- the same conclusion #6672 reached for its
	// single container, applied to the whole admitted population.
	//
	// The clone is required: this tree is the operator's candidate and is
	// persisted by the caller. Normalizing it in place here would rewrite the
	// stored configuration as a side effect of validating it.
	tree = normalizeCompactForValidation(tree)
	if err := validateStaticRouteQNHTails12813(tree.Children); err != nil {
		return scrubSchemaErrorSecrets(tree, err)
	}
	// #4060: reject the raw-AST redaction placeholder ("##SECRET-DATA##") on
	// commit-ingest. This is the symmetric guard for #4051 display redaction:
	// the value is a display artifact, never a valid configured secret.
	// compileTreeLenient preserves this placeholder-specific error while other
	// legacy typed-leaf violations continue to follow the tolerant policy.
	// Fold 3 (F2): this return (and the QNH one above) previously bypassed
	// the exit scrub; findRedactionPlaceholder embeds the raw flattened
	// path, which can carry a PRECEDING secret operand on the same leaf.
	// scrubSchemaErrorSecrets re-wraps the %w sentinel, preserving
	// IsRedactionPlaceholderIngestError / IsRedactedURLIngestError.
	if err := checkRedactionPlaceholder(tree); err != nil {
		return scrubSchemaErrorSecrets(tree, err)
	}
	refs := collectSchemaRefs(tree)
	if defsSource != nil {
		defRefs := collectSchemaRefs(defsSource)
		for name := range defRefs.forwardingClasses {
			refs.forwardingClasses[name] = struct{}{}
		}
		for name := range defRefs.loginClasses {
			refs.loginClasses[name] = struct{}{}
		}
	}
	// issue 8882: reject an unmodeled TOP-LEVEL stanza. A typo'd root keyword
	// (`securty { ... }`) resolves to no schema node, so the walk below simply
	// does not descend, and everything under it is silently discarded on a
	// clean commit -- the whole stanza, not one leaf.
	//
	// This is deliberately NOT setSchema.closedWorld. The closed-world flag
	// INHERITS (`childClosed := closed || childSchema.closedWorld`), so arming
	// it at the root closes every subtree beneath it, and the schema does not
	// model the tree exhaustively. Measured: that rejects 9 of the 10 shipped
	// and example configs -- `chassis cluster redundancy-group interface-monitor`,
	// `system services dhcp-local-server ... pool`, `family inet6 dhcpv6`,
	// `security flow tcp-mss all-tcp`. It would be an operational blackout on
	// the commit path, which is why the gate below closes ONE level and
	// inherits nothing.
	if err := checkUnknownTopLevelStanza(tree); err != nil {
		return scrubSchemaErrorSecrets(tree, err)
	}
	vc := &walkContext{refs: refs}
	// closed=false: the top-level walk is open-world. The per-subtree
	// closed-world flag (#4313) is inherited from schemaNode.closedWorld as
	// the walker descends. No count here — see the keyword-resolution gate
	// below for why prose must not state how many subtrees are armed.
	if err := walkSchemaChildren(tree.Children, setSchema, nil, vc, false); err != nil {
		return scrubSchemaErrorSecrets(tree, err)
	}
	return nil
}

// scrubSchemaErrorSecrets is the exit half of the #16066 shared choke
// point: schemaErrorf scrubs at construction inside schema_walk.go,
// but validators and node/tail validators return errors built in
// other files, and a future formatter can still bypass construction.
// At the SchemaValidate exit, any secret token in the candidate tree
// (per secretIndices over every flattened node path) is scrubbed from
// the returned error text — all occurrences — so no schema error can
// carry a credential operand to tolerant-ingress logs or compiled
// warnings regardless of which helper built it. Cost is rejection-
// path only: the tree is walked once per failed validation.
func scrubSchemaErrorSecrets(tree *ConfigTree, err error) error {
	if err == nil || tree == nil {
		return err
	}
	allValues := collectSecretValues(tree)
	values := beltSecretValues(allValues)
	msg := err.Error()
	// Whole-string equality (reviewer cross-field shape): if the
	// entire rendered error EQUALS a secret value, no substring
	// needle can fire. Compute the neutralized text but DO NOT
	// return it bare (fold 6): classification below must preserve
	// the wrapper/sentinel even on an exact match.
	wholeEq := false
	for _, v := range allValues {
		if v != "" && (msg == v || msg == strconv.Quote(v)) {
			wholeEq = true
			break
		}
	}
	// (Cross-field completion is handled in the wrapper arms via
	// fieldCompletesValue: a rebuilt field can complete a secret
	// value across the path/keyword boundary even when the value
	// never occurs as one substring of the rendered text.)
	scrubbed := scrubSecretValuesText(values, msg)
	if wholeEq {
		scrubbed = SecretRedacted
	}
	scrubText := func(s string) string { return scrubSecretValuesText(values, s) }
	fieldScrub := func(s string) string {
		out := scrubText(s)
		for _, v := range allValues {
			if out == v {
				return SecretRedacted
			}
		}
		return out
	}
	// Classify FIRST (fold 5): wrapper fields are rebuilt from
	// scrubbed parts even when the rendered message happens to be
	// unchanged — an unscrubbed field (keyword/content/at-path) can
	// re-print a secret the message scrub never saw as free text,
	// including a complete secret value spanning the whole rendered
	// string. Only the fallthrough plain-text case may return err
	// unchanged.
	// Classify FIRST (fold 5/6): wrapper fields are rebuilt from
	// scrubbed parts even when the rendered message happens to be
	// unchanged — an unscrubbed field can re-print a secret the
	// message scrub never saw as free text. Whole-string-equality
	// neutralization (above) only sets the scrubbed TEXT; it never
	// returns early, so classification survives an exact match.
	// GLM F1: each rebuilt wrapper's rendered Error() is re-scrubbed
	// per-arm below — path+template+keyword can reassemble a secret
	// verbatim across field boundaries even when each field alone
	// was clean.
	if IsTypedLeafSchemaError(err) {
		if scrubbed == msg {
			return err
		}
		return &typedLeafSchemaError{msg: scrubbed}
	}
	var zoneErr *unknownSecurityZoneChildSchemaError
	if errors.As(err, &zoneErr) {
		rebuilt := &unknownSecurityZoneChildSchemaError{
			path: scrubText(zoneErr.path),
			keyword: func() string {
				if fieldCompletesValue(allValues, msg, zoneErr.keyword) {
					return SecretRedacted
				}
				return fieldScrub(zoneErr.keyword)
			}(),
		}
		// Fold 7 (GLM B1): ALWAYS carry the scrubbed FINAL render.
		// Field-wise neutralization cannot repair a secret spanning
		// path-suffix + fixed template head (the keyword is innocent
		// there); carrying scrubSecretValuesText(rebuilt.Error())
		// in render makes reassembly impossible by construction,
		// while errors.As classification is preserved by the type.
		rebuilt.render = scrubSecretValuesText(values, rebuilt.Error())
		if wholeEq {
			rebuilt.render = SecretRedacted
		}
		return rebuilt
	}
	var polErr *unknownSecurityPoliciesChildSchemaError12217
	if errors.As(err, &polErr) {
		rebuilt := &unknownSecurityPoliciesChildSchemaError12217{
			path: scrubText(polErr.path),
			keyword: func() string {
				if fieldCompletesValue(allValues, msg, polErr.keyword) {
					return SecretRedacted
				}
				return fieldScrub(polErr.keyword)
			}(),
			content: func() string {
				if fieldCompletesValue(allValues, msg, polErr.content) {
					return SecretRedacted
				}
				return fieldScrub(polErr.content)
			}(),
		}
		rebuilt.render = scrubSecretValuesText(values, rebuilt.Error())
		if wholeEq {
			rebuilt.render = SecretRedacted
		}
		return rebuilt
	}
	var topErr *unknownTopLevelStanzaSchemaError
	if errors.As(err, &topErr) {
		if scrubbed == msg {
			return err
		}
		return &unknownTopLevelStanzaSchemaError{msg: scrubbed}
	}
	if IsRedactionPlaceholderIngestError(err) {
		return fmt.Errorf("%w (at %s)", errRedactionPlaceholderIngest,
			neutralizeLoc(allValues, extractLocName(err)))
	}
	if errors.Is(err, errRedactedURLIngest) {
		return fmt.Errorf("%w (at %s)", errRedactedURLIngest,
			neutralizeLoc(allValues, extractLocName(err)))
	}
	if scrubbed == msg {
		return err
	}
	return fmt.Errorf("%s", scrubbed)
}

// fieldCompletesValue reports whether printing field (a wrapper's
// keyword/content) would complete a secret value: the value contains
// the field, and the remainder of the value shares a verbatim run
// of >= 8 chars with the rendered message — the rest of the value
// is already on the page and this field is the missing piece
// (reviewer cross-field shape: secret `trust: unknown configuration
// keyword "bogus"` completed by path `... trust` + keyword `bogus`).
// Narrow by construction: wrapper fields only, never free text.
func fieldCompletesValue(allValues []string, msg, field string) bool {
	if field == "" {
		return false
	}
	for _, v := range allValues {
		i := strings.Index(v, field)
		if i < 0 {
			continue
		}
		rest := v[:i] + v[i+len(field):]
		for start := range rest {
			if start+8 <= len(rest) && strings.Contains(msg, rest[start:start+8]) {
				return true
			}
		}
	}
	return false
}

// neutralizeLoc scrubs a guard "(at ...)" location: belt-scrub its
// text, and if the (unquoted) location equals or contains a secret
// value, drop the value-bearing part. Guard locations built by the
// current code are name-only, so this fires only for foreign/old
// error shapes.
func neutralizeLoc(allValues []string, loc string) string {
	out := scrubSecretValuesText(beltSecretValues(allValues), loc)
	inner := out
	if unq, err := strconv.Unquote(inner); err == nil {
		inner = unq
	}
	for _, v := range allValues {
		if v != "" && strings.Contains(inner, v) {
			// Keep only the name prefix before the value.
			if i := strings.Index(inner, v); i > 0 {
				return strings.TrimSpace(inner[:i])
			}
			return ""
		}
	}
	return out
}

// beltSecretValues filters collected values to the belt's remit
// (fold 5): raw values of length >= 4 that are not public vocabulary.
// A secret whose literal IS a common word or a leaf/keyword name
// (e.g. the plaintext "password" pasted into encrypted-password)
// must not mangle every public diagnostic containing that word —
// construction-time value-freedom is the guarantee for those; the
// belt exists for high-entropy operands that escaped construction.
// "Public vocabulary" = every keyword in the schema grammar plus
// the secret-registry keywords: a value equal to any of them is a
// word the diagnostics legitimately print.
func beltSecretValues(values []string) []string {
	// Fresh slice (GLM F3): values[:0] would alias and corrupt the
	// caller's collectSecretValues result, which wrapper arms still
	// read via allValues after this call.
	out := make([]string, 0, len(values))
	for _, v := range values {
		if len(v) < 4 {
			continue
		}
		if isPublicVocabulary(v) {
			continue
		}
		out = append(out, v)
	}
	return out
}

// (Vocabulary derivation is documented at isPublicVocabulary.)

// isPublicVocabulary reports whether s is public vocabulary for the
// belt: a secret-registry keyword or a schema-grammar keyword (from
// schemaGrammarKeywords, populated in schema.go init — never walked
// from here; setSchema references would be an init cycle). NOTE
// (fold 6): validator fixed-sentence words are NOT vocabulary —
// exempting them let operands equal to those words (e.g. the
// plaintext `plaintext` itself) slip through scrubSecretTokens.
// The one place a validator sentence appears for a secret leaf,
// typedLeafInvalidErrorf's reason, is fully masked on its secret
// branch before the belt ever sees it.
func isPublicVocabulary(s string) bool {
	if secretLeafKeywords[s] {
		return true
	}
	if _, ok := secretLeafKeywordsByRoot[s]; ok {
		return true
	}
	return schemaGrammarKeywords[s]
}

// extractLocName returns the name-only "(at ...)" location from a
// guard error built by checkRedactionPlaceholder, for re-wrapping
// without re-embedding any rendered path. Guard errors built by the
// current code already carry names only; the fallback is empty.
func extractLocName(err error) string {
	msg := err.Error()
	const marker = "(at "
	i := strings.LastIndex(msg, marker)
	if i < 0 {
		return ""
	}
	return strings.TrimSuffix(msg[i+len(marker):], ")")
}

// walkContext carries the per-walk validation inputs: the tree-derived
// cross-reference sets for treeValidator leaves (#16162: the former
// always-nil cfg ferry is retired; LeafValidator takes only the token).
type walkContext struct {
	refs *schemaRefs
}

// collectedRefs is a nil-receiver-safe accessor: the white-box walker
// tests drive walkSchemaNode with a nil context.
func (vc *walkContext) collectedRefs() *schemaRefs {
	if vc == nil {
		return nil
	}
	return vc.refs
}

// treeLeafValidator is the TREE-based counterpart of LeafValidator for
// cross-reference leaves: it receives the definitions collected from
// the candidate tree by collectSchemaRefs, so a definition and its
// reference added in the same commit validate atomically.
type treeLeafValidator func(raw string, refs *schemaRefs) error

// leafNodeValidator validates a complete leaf node, retaining AST provenance
// such as bracketed-list masks and hierarchical block children. The resolved
// parent schema is supplied so validators can reuse schema-aware ownership
// predicates without referring to globals during schema initialization.
type leafNodeValidator func(node *Node, parent *schemaNode) error

// leafTailValidator validates the whole value/modifier tail of a leaf as a
// unit (#4228 Gap 2). tokens are the flattened tail of the leaf node;
// siblingTails are the flattened tails of the same-keyword sibling nodes at
// the same level (so a modifier-only split-set line can look across to a
// sibling that supplies the value). See schemaNode.tailValidator.
type leafTailValidator func(tokens []string, siblingTails [][]string) error

// checkToken validates one token against a typed leaf directly: the
// scalar LeafValidator when set, else the tree-based cross-reference
// validator bound to the walk's collected refs. A typed leaf sets
// exactly one of the two (walkSchemaNode gates on either).
func (n *schemaNode) checkToken(vc *walkContext, tok string) error {
	if n.validator != nil {
		return n.validator(tok)
	}
	if n.treeValidator != nil {
		return n.treeValidator(tok, vc.collectedRefs())
	}
	return nil
}

// schemaRefs holds the referenceable definitions collected from the
// candidate tree before the walk (#1319 PR 3). Extend with new sets as
// more cross-reference validators land.
type schemaRefs struct {
	// forwardingClasses are the names defined via `class-of-service
	// forwarding-classes queue <n> <name>` anywhere in the tree —
	// including group bodies, applied or not. Collecting from group
	// definitions errs permissive: after apply-groups expansion the
	// applied bodies are inlined at top level anyway, and a reference
	// satisfied only by an UN-applied group must not be rejected (the
	// compiler ignores both the definition and any reference inside
	// that group, and node0/node1-variable configs legitimately keep
	// peer-node definitions un-applied locally).
	forwardingClasses map[string]struct{}
	// loginClasses are the custom names defined via `system login class
	// <name>` anywhere in the tree (including group bodies, applied or
	// not — same permissive rationale as forwardingClasses). The
	// `system login user <n> class <c>` leaf validates against the
	// built-in classes UNION this set (#4304 S-2).
	loginClasses map[string]struct{}
}

// collectSchemaRefs walks the tree for cross-referenceable definitions.
// The forwarding-class collection mirrors compileClassOfService exactly
// (compiler_class_of_service.go:82-89): `queue` leaves under a
// `forwarding-classes` node, Keys = ["queue", <int>, <name>]; entries
// whose queue number does not parse are skipped, as the compiler skips
// them.
func collectSchemaRefs(tree *ConfigTree) *schemaRefs {
	refs := &schemaRefs{
		forwardingClasses: map[string]struct{}{},
		loginClasses:      map[string]struct{}{},
	}
	if tree == nil {
		return refs
	}
	// collectCoS records forwarding-class names under EVERY sibling
	// `class-of-service` block of node (#15717: singular FindChild missed
	// classes defined in a second sibling block).
	var collectCoS func(node *Node)
	collectCoS = func(node *Node) {
		for _, cosNode := range node.FindChildren("class-of-service") {
			for _, fcNode := range cosNode.FindChildren("forwarding-classes") {
				for _, queueNode := range fcNode.FindChildren("queue") {
					if len(queueNode.Keys) < 3 {
						continue
					}
					if _, err := strconv.Atoi(queueNode.Keys[1]); err != nil {
						continue
					}
					refs.forwardingClasses[queueNode.Keys[2]] = struct{}{}
				}
			}
		}
	}
	// collectLoginClasses records custom `login class <name>` names under
	// EVERY sibling `system` block of parent (#4304 S-2; #15717: singular
	// FindChild("system") missed classes in a second sibling `system`
	// block). Mirrors the compiler's namedInstances over every sibling
	// `system login` block: each class name is the leading Keys arg.
	collectLoginClasses := func(parent *Node) {
		for _, sysNode := range parent.FindChildren("system") {
			for _, loginNode := range sysNode.FindChildren("login") {
				for _, classNode := range loginNode.FindChildren("class") {
					if len(classNode.Keys) >= 2 && classNode.Keys[1] != "" {
						refs.loginClasses[classNode.Keys[1]] = struct{}{}
						continue
					}
					// Hierarchical shape: `class { noc-admin { ... } }` — the name
					// is a child of the bare `class` node.
					for _, c := range classNode.Children {
						if len(c.Keys) > 0 && c.Keys[0] != "" {
							refs.loginClasses[c.Keys[0]] = struct{}{}
						}
					}
				}
			}
		}
	}
	// A synthetic parent lets the top level share the sibling-aware
	// collectors: tree.Children are the siblings of a virtual root.
	root := &Node{Children: tree.Children}
	collectCoS(root)
	collectLoginClasses(root)
	for _, top := range tree.Children {
		if top == nil || len(top.Keys) == 0 || top.Name() != "groups" {
			continue
		}
		for _, group := range top.Children {
			if group == nil {
				continue
			}
			collectCoS(group)
			collectLoginClasses(group)
		}
	}
	return refs
}

// walkSchemaChildren validates a slice of AST sibling nodes against the
// schema level `parent`. Siblings are processed together so a typed leaf's
// modifier-only sibling (e.g. flat-set `transmit-rate exact` next to
// `transmit-rate 1g`) can be recognized as valid only when a sibling
// supplies the value.
func walkSchemaChildren(nodes []*Node, parent *schemaNode, path []string, vc *walkContext, closed bool) error {
	if parent == nil {
		return nil
	}
	for _, node := range nodes {
		if node == nil || len(node.Keys) == 0 {
			continue
		}
		if err := walkSchemaNode(node, parent, path, vc, nodes, closed); err != nil {
			return err
		}
	}
	return nil
}

// walkSchemaNode matches a single AST node against the current schema
// level (parent), validates it if it resolves to a typed leaf, then
// recurses into its children.
//
//   - node:     the AST node. node.Keys packs flat-set tokens
//     (e.g. ["from-zone","trust","to-zone","untrust"] or
//     ["transmit-rate","1g"]); node.Children holds nested AST.
//   - parent:   the schema level node.Keys[0] is looked up in.
//   - path:     consumed keyword path for error context.
//   - siblings: the AST nodes at this level (for cross-sibling
//     modifier-only recognition).
//   - closed:   closed-world enforcement flag (#4313). When true, an
//     unmodeled child keyword is REJECTED instead of silently accepted.
//     Inherited from any ancestor subtree whose schemaNode.closedWorld is
//     set; false (open-world) for any subtree that has not opted in.
func walkSchemaNode(node *Node, parent *schemaNode, path []string, vc *walkContext, siblings []*Node, closed bool) error {
	keyword := node.Keys[0]

	// Resolve the schema child for this keyword. Exact match first, then
	// wildcard (instance-name slot).
	childSchema := resolveSchemaChild(parent, keyword)
	// Junos permits apply statements at any hierarchy level (#7029). The
	// shared resolver handles wildcard slots, but the strict schema walk must
	// also recognize them beneath inherited closed-world subtrees.
	if childSchema == nil && closed && isApplyStatementKeyword(keyword) {
		childSchema = applyStatementSchema
	}
	if childSchema == nil {
		// Closed-world subtree (#4313): an unmodeled keyword here is operator
		// garbage that would commit clean and be silently dropped. Reject it,
		// mirroring the modifier-level unknown-keyword rejects below. Only a
		// subtree that opted in (schemaNode.closedWorld, inherited via closed)
		// reaches this branch.
		//
		// Deliberately NO count of armed subtrees here — including in this
		// paragraph, which is why it names no number. The previous wording
		// ("no production subtree does so today") was written in the mechanism
		// commit 49fef7174 when it was true, and the first production flip
		// landed the SAME DAY; it was never updated as the rollout proceeded,
		// so a month later it still described a mechanism that had not been
		// dormant since the day the sentence was written, and it mis-scoped a
		// lane that trusted it. A comment stating
		// how much of a mechanism is in use is a coverage claim, and it rots
		// silently. The armed set is exactly whatever sets the closedWorld
		// field to true in a schema_*.go node — count those, or read the
		// schema_closedworld_*_4313_test.go files, each of which pins one
		// subtree. Do not restate the number here.
		//
		// This paragraph deliberately does not spell that field-and-value as a
		// contiguous literal: doing so made this comment a false positive in
		// the very grep it tells you to run, inflating the count by one. An
		// instruction that corrupts its own measurement is worse than none.
		//
		// Strict-vs-tolerant, since it is asked every round and is written
		// nowhere else: this rejects at the OPERATOR boundary, where the
		// alternative is a silent drop. It is NOT a reject on the paths where
		// refusing would mean an outage — configstore's Store.Load (boot) and
		// Store.SyncApply (HA peer sync) downgrade schema violations to a
		// warning (pkg/configstore/store.go), so a config an older build
		// persisted, or a peer sends, still loads. Strict where the operator
		// can fix it, tolerant where refusing would brick the node.
		// #12628: accept only the known non-enforcement shapes. A name-only
		// exemption would also admit a fused policy/default-policy subtree.
		if parent == securityPoliciesSchema12217() && nonEnforcementSecurityPoliciesChild12628(node) {
			return nil
		}
		if closed {
			if parent == securityZoneSchema9792() && len(path) > 0 {
				return &unknownSecurityZoneChildSchemaError{
					path:    strings.Join(redactSecretPath(path), " "),
					keyword: keyword,
				}
			}
			if parent == securityPoliciesSchema12217() && len(path) > 0 {
				return &unknownSecurityPoliciesChildSchemaError12217{
					path:    strings.Join(redactSecretPath(path), " "),
					keyword: keyword,
					content: securityPoliciesChildContentShape12819(node),
				}
			}
			return schemaErrorf(append(append([]string(nil), path...), keyword), "%s: unknown configuration keyword %q under closed-world subtree",
				strings.Join(redactSecretPath(path), " "), keyword)
		}
		// Open-world — the default for a subtree that has NOT opted in, which
		// is most of them and emphatically not all. Unknown keywords are not
		// our concern here; the gate is opt-in, so leave reporting to the
		// compiler.
		//
		// "BYTE-IDENTICAL TO PRE-#4313" IS TRUE OF THIS BRANCH AND OF NOTHING
		// WIDER, and saying which is the whole correction. The FUNCTION's
		// behaviour did change: a typo'd leaf under an armed subtree is
		// rejected at commit where it used to commit clean and be silently
		// dropped. The unscoped form of this sentence was read as a claim
		// about the MECHANISM — #6725 quoted it to conclude the gate was inert
		// — which is the same misreading the keyword-resolution gate above was
		// corrected for, surviving here because that correction did not reach
		// this branch. A scope-free "behaviour is unchanged" sitting next to
		// an opt-in gate always reads as the wider claim.
		//
		// Bound, not merely asserted: each schema_closedworld_*_4313_test.go
		// commits a typo under one armed subtree and requires a REJECT, so if
		// open-world ever did become universal they would red rather than this
		// prose quietly becoming true again.
		return nil
	}

	// Apply statements are metadata rather than schema-owned containers.
	// Their leaf-list names and apply-macro body are opaque to schema walk.
	if childSchema == applyStatementSchema {
		if len(node.Keys) < 2 && len(node.Children) == 0 {
			return schemaPathErrorf(append(append([]string(nil), path...), keyword), "`%s` requires at least one value", keyword)
		}
		return nil
	}

	// Whole-tail leaf (#4228 Gap 2): an irregular grammar (CoS transmit-rate /
	// shaping-rate) whose heterogeneous value/modifier tail is validated as a
	// unit rather than token-by-token. Takes precedence over the generic
	// typed-leaf / container paths.
	if childSchema.tailValidator != nil {
		return validateTailLeaf(node, childSchema, path, siblings)
	}

	exactMatch := parent.children != nil && parent.children[keyword] == childSchema

	if childSchema.nodeValidator != nil && exactMatch {
		if err := childSchema.nodeValidator(node, parent); err != nil {
			leafPath := append(append([]string(nil), path...), keyword)
			return schemaPathErrorf(leafPath, "%v", err)
		}
	}
	// exactMatch is computed here rather than at its original site further
	// down, because the TYPED-LEAF branch below now needs it too and that
	// branch returns before the old declaration was reached. Same single
	// computation, three readers (#6844).
	if childSchema.isTypedLeaf() && (childSchema.validator != nil || childSchema.treeValidator != nil) {
		// #6844: a typed leaf reached through a WILDCARD has its identity in
		// the KEYWORD, and that keyword was never key-validated. #6834 closed
		// the same gap for wildcard CONTAINERS but this branch returns first,
		// so a wildcard TYPED LEAF -- `system syslog file <name> <facility>
		// <severity>`, where the facility is the wildcard key and the severity
		// is the value -- validated its value and not its identity.
		//
		// Gated on !exactMatch for the same reason as the container rule: on an
		// exact match the keyword is a schema keyword, not an operator-supplied
		// identity, and validating it would reject the schema's own vocabulary.
		//
		// Stated plainly because a mutation cell measured it: deleting this
		// guard today changes NOTHING. No named typed leaf currently carries a
		// keyValidator, so the guard has no instance and no test exercises it.
		// It is kept as the mirror of the container rule rather than as a
		// load-bearing check -- adding a keyValidator to a NAMED typed leaf
		// would otherwise validate the schema's own keyword and reject it. The
		// inventory test is what surfaces such a leaf when one appears.
		if !exactMatch && childSchema.keyValidator != nil {
			if err := validateKeySlot(childSchema, 0, keyword, vc); err != nil {
				return typedLeafInvalidErrorf(path, keyword, err)
			}
		}
		// Multi value-tail leaf (`multi && children == nil`): values can
		// live in the packed Keys (`name-server 1.1.1.1`, bracketed
		// lists, `destination-port 20000 to 20003`) AND/OR one-per-child
		// in the hierarchical block-list shape (`name-server { 1.1.1.1;
		// 8.8.8.8; }`, `virtual-address { a; b; }`) — the compilers read
		// both (compiler_system.go name-server, compiler_interfaces.go
		// virtual-address). Children here are VALUES, not modifiers, so
		// this path replaces both validateTypedLeaf and the modifier
		// loop below.
		if childSchema.multi && childSchema.children == nil {
			return validateMultiValueLeaf(node, childSchema, path, vc)
		}
		// Typed leaf: node.Keys[1:] are the value/modifier tokens. The leaf
		// keyword is the only identity token.
		if err := validateTypedLeaf(node, childSchema, path, siblings, vc); err != nil {
			return err
		}
		// #6774: for a blockValue leaf written in the BLOCK spelling
		// (`default-policy { deny-all; }`) the single child is the VALUE —
		// already validated by validateTypedLeaf just above — not a modifier.
		// Without this the modifier loop below rejects it as
		// `unknown modifier "deny-all"`, because the leaf declares no
		// children. This mirrors the multi-leaf branch earlier in this
		// function, where block children are likewise values and that path
		// therefore replaces the modifier loop too.
		if childSchema.blockValue && len(node.Keys) == 1 {
			if _, ok := singleBlockValue(node); ok {
				return nil
			}
		}
		// #15270: braced host children are bare address + port, already
		// validated by nodeValidator; they are not typed-leaf modifiers.
		// The grouped flat form `host port` -> [514] is likewise owned by
		// validateTypedLeaf's host-port arm.
		if len(node.Keys) == 1 && len(node.Children) > 0 && childSchema.nodeValidator != nil {
			return nil
		}
		if keyword == "host" && len(node.Keys) == 2 && node.Keys[1] == "port" && len(node.Children) > 0 {
			return nil
		}
		// Validate modifier CHILDREN. The flat-set grouping and hierarchical
		// blocks both nest trailing modifier tokens as children
		// (`transmit-rate 1g { exact; }` → child Keys=["exact"];
		// `transmit-rate 1g exact bogus` → child exact → child bogus). Each
		// modifier child must be a known modifier keyword with NO extra
		// tokens packed in its Keys and NO unexpected descendants.
		leafPath := append(append([]string(nil), path...), keyword)
		for _, c := range node.Children {
			if err := validateModifierChild(c, childSchema, leafPath, vc); err != nil {
				return err
			}
		}
		return nil
	}

	// Fixed-arity scalar value leaf (#3332): a keyword that consumes exactly
	// `args` value token(s) and models no sub-structure. Reject any token or
	// AST child beyond that span — in the flat-set grammar a recognized
	// non-multi leaf parks trailing garbage as a CHILD node (SetPath:
	// `description hello bogus` → Keys=["description","hello"] with child
	// Keys=["bogus"]), which the compiler never reads and silently drops.
	// Only applies on an EXACT keyword match: a wildcard match means keyword
	// is a dynamic instance NAME, not this leaf's value slot.
	//
	// exactMatch is computed ONCE and read by both rules that need it (#6834).
	// It used to be open-coded here and nowhere else; the wildcard-identity
	// gate below needs the same distinction, and two copies of "was this an
	// exact match?" can only ever disagree by mistake — if they drifted, one
	// rule would treat a match as a dynamic instance name and the other as a
	// value slot.
	//
	// PRECONDITION, verified rather than assumed: no schema parent registers
	// the same *schemaNode as both a named child AND its wildcard. Pointer
	// equality would report "exact" for a wildcard match if one did, silently
	// disabling the identity gate. TestNoSchemaNodeIsBothChildAndWildcard_6834
	// walks the whole schema and keeps that true.
	if childSchema.isScalarValueLeaf() && exactMatch {
		return validateScalarValueLeaf(node, childSchema, path)
	}

	// Container / named-instance node. Consume this node's identity tokens
	// (keyword + args + compoundKey), then validate its BLOCK CHILDREN at the
	// resolved child schema.
	//
	// Compiler-faithful model (verified against compileClassOfService +
	// namedInstances): a named-instance container is compiled by reading its
	// instance node's CHILDREN as leaves. Tokens packed into the instance
	// node's own Keys BEYOND the identity (e.g. the `transmit-rate 1g` in
	// `schedulers { be transmit-rate 1g; }`, or a stray `surplus-sharing` /
	// `extra` token) are NOT compiled as leaves — the per-instance compiler
	// never inspects them — so the gate must NOT validate them either, and
	// crucially must NOT mis-attribute the block children to such a token.
	// We therefore IGNORE leftover Keys here and always walk node.Children at
	// the child schema. (The flat-set `set ... transmit-rate asd` shape lands
	// the typed leaf as a CHILD of `schedulers be`, where it IS compiled and
	// IS validated by the typed-leaf branch above.)
	declaredKeyTokens := 1 + childSchema.args
	consumed, descendSchema := consumeNodeKeys(node.Keys, childSchema)
	newPath := append(append([]string(nil), path...), node.Keys[:consumed]...)
	// #9878 (spark-F1): a midKeyword is structural, not a value. `from-zone
	// trust to-zon untrust` packs Keys[2]="to-zon" while the compiler reads
	// Keys[1],Keys[3] and ignores Keys[2], so the typo commits clean and the
	// policy attaches to a pair the operator misspelled. Validate the mid
	// position whenever it is present in this node's Keys; the hierarchical
	// peel (walkInstanceChildren) enforces the same position when the name
	// levels arrive as nested children.
	if childSchema.midKeyword != "" && len(node.Keys) > childSchema.midKeywordAt &&
		node.Keys[childSchema.midKeywordAt] != childSchema.midKeyword {
		return schemaPathErrorf(newPath, "unexpected keyword %q — expected %q (`%s <a> %s <b>` names a zone pair, and the middle keyword is fixed)",
			node.Keys[childSchema.midKeywordAt], childSchema.midKeyword, node.Keys[0], childSchema.midKeyword)
	}

	// Typed KEY slot (#1319 PR 3): a named-instance container with a
	// keyValidator validates the identity arg token(s) packed into this
	// node's Keys (e.g. the 10.0.1.10/24 in `address 10.0.1.10/24 {
	// primary; }`). Only the declared arg span is validated — a compound
	// sub-token is a keyword, not a value, and tokens past the identity
	// are ignored per the compiler-faithful contract. A POSITION-AWARE
	// keyValidatorPos (#5576, route-filter) takes precedence and receives
	// each token's 0-based arg index so a multi-arg slot can enforce a
	// distinct grammar per position (prefix slot vs match-type slot).
	// #8437: a missing semicolon FUSES two hierarchical statements. The lexer
	// has no statement terminator to stop at, so the next statement's keyword
	// and its value are absorbed onto THIS node's Keys — and the compiler,
	// which reads only the tokens its own grammar declares, silently drops the
	// second statement. `show configuration` still renders the fused line, so
	// the operator's verification step confirms a constraint the dataplane
	// does not enforce.
	//
	// The signature is precise: an absorbed token NAMES A SIBLING of this leaf
	// in the enclosing container. That is what distinguishes a fused statement
	// from the trailing tokens a leaf legitimately carries — several leaves are
	// under-declared in setSchema and keep their grammar in the compiler
	// (`then static-nat prefix <cidr>` is the worked example), and a plain
	// arity check condemns those. Same discriminator #3673 already uses for
	// `security policies ... match` (emitSwallowed); this generalises it to
	// every container.
	//
	// Only tokens PAST the declared identity span are considered, so a leaf
	// whose own args legitimately consume a token that happens to share a
	// sibling's name is untouched.
	if parent != nil && parent.children != nil && len(node.Keys) > declaredKeyTokens {
		// #9635: the same authored-value rule the packed splitter applies. A
		// `multi` / `valueList` leaf keeps the tokens the operator wrote as
		// values -- quoted, or inside the same `[ ... ]` list -- even when one
		// spells a sibling keyword, because `proposals [ P "proposal-set" ]` is
		// a reference to a proposal merely NAMED like a statement. Without this
		// the splitter declines the split and THIS gate refuses the config, so
		// the two passes disagree about one input and the spelling is
		// unusable either way.
		//
		// A fixed-arity leaf is saturated past its args, so a quoted token
		// there still fuses: `pre-shared-key ascii-text "s" "mode" aggressive`
		// keeps being two statements.
		values := authoredValueMask9635(node.KeysQuoted, node.KeysBracketed, len(node.Keys))
		for i := declaredKeyTokens; i < len(node.Keys); i++ {
			tok := node.Keys[i]
			if _, isSibling := parent.children[tok]; !isSibling {
				continue
			}
			// A packed sibling may be rendered on the same statement as a
			// preceding token-packed leaf. Admit only the exact suffix arity;
			// SetPath leaves any remainder as a separate node for the
			// closed-world walk below to reject.
			if tok == parent.packedValueSibling && childSchema.groupReplace {
				if sibling := parent.children[tok]; sibling != nil &&
					len(node.Keys) == declaredKeyTokens+1+sibling.args {
					continue
				}
			}
			if tok == keyword {
				continue // a repeat of this leaf, not a foreign statement
			}
			if values != nil && values[i] && leafOwnsMoreValues9635(childSchema) {
				continue // authored as a value of a leaf that can own another
			}
			// A token that also names a CHILD of this node is ambiguous: it may
			// be a PACKED spelling (`system login user bob class super-user`)
			// rather than a fused statement, and packing has its own dedicated
			// gate with a more specific message (#6706). Defer to it — a second
			// gate firing first on the same input replaces a targeted diagnostic
			// with a generic one.
			if childSchema.children != nil {
				if _, isOwnChild := childSchema.children[tok]; isOwnChild {
					continue
				}
			}
			return schemaErrorf(append(append([]string(nil), path...), node.Keys...), "%s: the token %q follows `%s` but names a SIBLING "+
				"statement — a missing semicolon after `%s` fuses the two, and the "+
				"`%s` statement is then silently dropped from the compiled config "+
				"while `show configuration` still displays it. Add the missing `;` "+
				"(#8437)",
				nameOnlyArg(strings.Join(redactSecretPath(append(append([]string(nil), path...), keyword)), " ")),
				tok, keyword, keyword, tok)
		}
	}

	if childSchema.keyValidatorPos != nil || childSchema.keyValidator != nil {
		keyPath := append(append([]string(nil), path...), keyword)
		// #6834: a WILDCARD's identity IS the keyword — Keys[0] — not an arg
		// token. The declared-arg span below is Keys[1:1+args], and a wildcard
		// declares no args, so that span is EMPTY and a wildcard's identity was
		// never validated at all. Every keyValidator in the schema was on a
		// `<keyword> <arg>` slot, so the gap had no instance until an interface
		// name needed gating (the name is interpolated into the generated
		// .network file's [Match] Name=, which systemd reads as a
		// whitespace-separated glob list, so an unvalidated name can claim
		// several devices).
		//
		// Validated as identity slot 0, which is what it is positionally.
		if !exactMatch {
			if err := validateKeySlot(childSchema, 0, keyword, vc); err != nil {
				return typedLeafInvalidErrorf(path, keyword, err)
			}
		}
		if childSchema.valueList && childSchema.keyValidator != nil {
			// #5726: a VALUE-LIST container leaf (only the static-route
			// `next-hop`: multi + valueList + keyValidator + an `interface`
			// modifier child) packs its whole homogeneous value LIST onto
			// Keys beyond the identity: `next-hop [ gw1 gw2 ]` collapses to
			// Keys=["next-hop", gw1, gw2] (#2419). Validate EVERY packed
			// gateway, not just the first — the pre-#5726 argEnd=1+args span
			// left gw2.. UNVALIDATED, so a typo'd ECMP member committed clean
			// and FRR then silently dropped it (fail-open). Gated on valueList
			// (NOT multi) so a POSITIONAL multi leaf like `route-filter`
			// (keyValidatorPos, per-position grammar + a value tail) keeps the
			// old declared-arg span — the else branch below. Mirror the
			// compiler's keyword-bounded gateway scan (compiler_routing.go
			// isRouteInlineKeyword / #3881): a token that names a declared
			// modifier CHILD (`interface`) AFTER at least one gateway is the
			// egress modifier — it and its argument are NOT validated as
			// gateways (an ifname like ge-0/0/0 is not a valid gateway
			// literal). A LEADING such token is itself a gateway value.
			valuesSeen := 0
			for j := 1; j < len(node.Keys); j++ {
				tok := node.Keys[j]
				if valuesSeen > 0 && childSchema.children != nil {
					if _, isModifier := childSchema.children[tok]; isModifier {
						j++ // skip the modifier keyword AND its value token
						continue
					}
				}
				if err := validateKeySlot(childSchema, valuesSeen, tok, vc); err != nil {
					return typedLeafInvalidErrorf(keyPath, tok, err)
				}
				valuesSeen++
			}
		} else {
			// Non-multi container: only the declared identity-arg span is a
			// value slot; tokens past it are keywords/ignored per the
			// compiler-faithful contract.
			argEnd := declaredKeyTokens
			if argEnd > len(node.Keys) {
				argEnd = len(node.Keys)
			}
			for argIdx, tok := range node.Keys[1:argEnd] {
				if err := validateKeySlot(childSchema, argIdx, tok, vc); err != nil {
					return typedLeafInvalidErrorf(keyPath, tok, err)
				}
			}
		}
	}

	// Dual AST shape: a schema node with args>0 packs the instance name(s)
	// into Keys in flat-set form (`schedulers be` → Keys=["schedulers",
	// "be"]) but presents them as nested AST children in hierarchical form
	// (`schedulers { be { ... } }` → node Keys=["schedulers"], child
	// Keys=["be"]). When fewer key tokens were available than the schema
	// declares, the missing instance-name args are supplied by nested AST
	// children: peel those name levels (the compiler's namedInstances
	// does the same) and validate each instance's children at the child schema.
	// Inherit closed-world enforcement into this container's descent (#4313):
	// a subtree that opts in (childSchema.closedWorld) closes every level
	// below it, and an already-closed ancestor keeps it closed.
	childClosed := closed || childSchema.closedWorld
	// #8430: closed-world must NOT descend into a multi-value LEAF. A
	// `multi: true` leaf with no schema children carries VALUES, and the
	// hierarchical mixed shape `source-address <v1> { <v2>; }` (#6693, a
	// spelling the compiler reads and accumulates) presents <v2> as an AST
	// CHILD. Inheriting closed-world there reads that value as an unknown
	// KEYWORD and rejects a valid configuration.
	//
	// Found by a control, not by review: flipping the three NAT `match`
	// subtrees closed-world left the entire pkg/config and pkg/configstore
	// suites GREEN while false-rejecting the mixed shape, because no existing
	// cell authors it under a closed subtree.
	if childSchema.multi && childSchema.children == nil {
		childClosed = false
	}
	// #10078 / #1979: tcp-mss is a deliberately opaque compiler-owned
	// grammar. Its child tokens are value/kind positions (`all-tcp 1396`,
	// `all-tcp { mss 1396; }`), not schema keywords. End inherited
	// closed-world enforcement exactly at this node; the tcp-mss keyword
	// itself remains closed by its declared parent (`flow`).
	if childSchema.closedWorldOpaque {
		childClosed = false
	}

	missingArgs := declaredKeyTokens - consumed
	if missingArgs > 0 && !childSchema.compoundKey && len(node.Children) == 0 {
		// #8597 (muse-004 K15): a LEAF that declares an argument, carries no
		// value token, and has no AST children has nowhere left for the value
		// to come from. The branch below exists for the dual-AST shape, where
		// the missing name/arg levels arrive as nested children; with zero
		// children it iterates nothing and returns nil, so a valueless leaf
		// walked out of the gate entirely.
		//
		// Measured at HEAD, `next-hop fe80::1 interface` (no interface name)
		// committed clean and compiled to Interface = "" — an UNSCOPED
		// link-local gateway, which is the one route an operator can least
		// afford to mis-scope.
		//
		// The discriminator is the AST node having NO CHILDREN, not the schema
		// node being a leaf. A container legitimately takes its missing name
		// level from nested children — that is what the branch below is for —
		// and a leaf with modifier children (`family inet address <p> {
		// primary; }`) is the same shape. With zero children there is nowhere
		// left for the value to come from, whichever it is.
		// A small number of Junos leaves accept a presence-only form in
		// addition to their value form. That capability is explicit on the
		// schema node; every other value-taking leaf retains this refusal.
		if !childSchema.allowEmptyValue {
			return schemaPathErrorf(newPath, "`%s` declares a value and none was given — the compiler "+
				"drops a valueless statement, so this commits clean and the configuration "+
				"silently does not carry it", keyword)
		}
	}
	if missingArgs > 0 && !childSchema.compoundKey {
		// The already-consumed identity tokens are Keys[1:consumed]; the
		// name levels peeled below supply args starting at 0-based index
		// consumed-1 (arg 0 == Keys[1]). Thread that base so a
		// position-aware keyValidatorPos sees the correct slot (#5576).
		baseArgIdx := consumed - 1
		for _, c := range node.Children {
			if err := walkInstanceChildren(c, childSchema, missingArgs, baseArgIdx, newPath, vc, childClosed); err != nil {
				return err
			}
		}
		return nil
	}

	// #6821: a container that OPTS IN to packedTail has its packed tail
	// validated, because a compiler reads it. The expansion is the SAME one
	// `packedBodyChildren` hands that compiler, so the gate and the compiler
	// cannot disagree about what the tokens mean.
	//
	// Default-off is deliberate: validating a tail that no compiler reads would
	// reject configuration that behaves identically either way. The feed-server
	// shrink-guard exception below validates only the three newly consumed
	// leaves, without widening the legacy tail contract.
	walkChildren := node.Children
	// #12184: the compiler expands this SetPath flat-run chain before
	// reading per-next-hop modifiers. Validate the same view so a metric
	// nested under `interface` or `preference` cannot bypass its leaf gate.
	// Keep this keyword-specific: the packedTail and packedFlatRun branches
	// below rebuild walkChildren from the node and would silently discard the
	// #9235 view, so QNH must be folded into either branch if it opts in.
	if keyword == "qualified-next-hop" {
		walkChildren = expandRunChildren9235(walkChildren, childSchema)
	}
	if childSchema.packedTail && len(node.Keys) > consumed {
		// The packed body is authored on the container line.
		walkChildren = packedBodyChildren(node, childSchema)
	} else {
		if childSchema.packedFlatRun && len(node.Children) > 0 {
			// `stream s1 port 5514 category policy` as a child chain
			// (`port` -> `category`). Use the same expansion as compileLog
			// before walking under the inherited closed-world arm.
			walkChildren = expandFlatRun(node.Children, childSchema)
		}
		// #11059: compileDynamicAddress reads only these three fields from a
		// compact feed-server tail. Validate exactly that consumed subset, not
		// the unrelated legacy tail that remains intentionally uncompiled.
		if childSchema == feedServerSchema9792() && len(node.Keys) > consumed {
			inlineProps := dynamicAddressShrinkGuardCompactProps(node.Keys[consumed:])
			walkChildren = append(inlineProps, walkChildren...)
		}
	}
	// #14412 (DR13-H5): a credential token packed past the identity that
	// is NOT a child of this container (misplaced one level up, or spelled
	// case-variant) is consumed by no reader: the compiler's packed
	// expansion bails on it and the nested reader never sees it, so the
	// adjacency forms unauthenticated while `show configuration` displays
	// the credential. packedTail containers are exempt — a reader consumes
	// their tails. The path is rendered through redactSecretPath so the
	// error names the dropped keyword, never its value.
	if !childSchema.packedTail && len(node.Keys) > consumed {
		if tok, _ := packedTailCredential14412(node, descendSchema, consumed); tok != "" {
			return schemaPathErrorf(newPath, "packed configuration keyword %q is not a child of this stanza and would be silently dropped — the credential it carries would not take effect; author it under the stanza that declares it, with its exact spelling (#14412)", tok)
		}
	}
	return walkSchemaChildren(walkChildren, descendSchema, newPath, vc, childClosed)
}

// walkInstanceChildren peels the missing instance-name level(s) off a
// hierarchical named-instance node and validates the instance's block
// children at the container schema. It mirrors the compiler's namedInstances
// + per-instance child walk: the instance name comes from the node's leading
// Keys; the leaves are the node's CHILDREN. Any extra tokens packed into the
// instance node's Keys beyond the name are ignored (the compiler does not
// compile them; see walkSchemaNode's container comment, Codex r7), except for
// the narrow #11059 feed-server shrink-guard subset the compiler DOES consume
// via instanceValueTail in both flat and nested shapes.
func walkInstanceChildren(node *Node, containerSchema *schemaNode, remaining, baseArgIdx int, path []string, vc *walkContext, closed bool) error {
	if node == nil || len(node.Keys) == 0 {
		return nil
	}
	consume := len(node.Keys)
	if consume > remaining {
		consume = remaining
	}
	// Typed KEY slot (#1319 PR 3): the peeled tokens ARE the instance
	// name the compiler reads (namedInstances handles this nested shape
	// too), so a key-typed container validates them here as well. A
	// position-aware keyValidatorPos (#5576) takes precedence; baseArgIdx
	// is the 0-based arg index of node.Keys[0] in this peel.
	if containerSchema.keyValidatorPos != nil || containerSchema.keyValidator != nil {
		for i, tok := range node.Keys[:consume] {
			if err := validateKeySlot(containerSchema, baseArgIdx+i, tok, vc); err != nil {
				return typedLeafInvalidErrorf(path, tok, err)
			}
		}
	}
	// #9878 (spark-F1): the midKeyword position is structural even when it
	// arrives as a peeled name level in hierarchical form (`from-zone {
	// trust { to-zon { ... }}}` consumes "to-zon" as the arg-1 name level
	// the same way flat Keys[2] does). Whenever the peel covers the
	// 0-based mid index (midKeywordAt-1), the token there must equal the
	// fixed keyword. Only midKeyword nodes take this branch (one today).
	if containerSchema.midKeyword != "" {
		for i, tok := range node.Keys[:consume] {
			if baseArgIdx+i == containerSchema.midKeywordAt-1 && tok != containerSchema.midKeyword {
				return schemaErrorf(append(append([]string(nil), path...), node.Keys[:consume]...), "%s: unexpected keyword %q — expected %q (the middle keyword of this stanza is fixed)",
					strings.Join(redactSecretPath(path), " "), tok, containerSchema.midKeyword)
			}
		}
	}
	newPath := append(append([]string(nil), path...), node.Keys[:consume]...)
	if stillMissing := remaining - consume; stillMissing > 0 {
		// This node supplied only part of the name; keep peeling. closed is
		// inherited unchanged: containerSchema.closedWorld was already folded
		// into it by the caller in walkSchemaNode (#4313).
		for _, c := range node.Children {
			if err := walkInstanceChildren(c, containerSchema, stillMissing, baseArgIdx+consume, newPath, vc, closed); err != nil {
				return err
			}
		}
		return nil
	}
	// Name fully consumed. The instance's leaves are its block children;
	// any leftover Keys past the name are not compiled and are ignored,
	// except the consumed #11059 shrink-guard tail on a feed-server instance.
	walkChildren := node.Children
	if containerSchema == feedServerSchema9792() && len(node.Keys) > consume {
		inlineProps := dynamicAddressShrinkGuardCompactProps(node.Keys[consume:])
		walkChildren = append(inlineProps, walkChildren...)
	}
	// #15064: a container that opts into packedTail (the CoS named-instance
	// containers) HAS a compiler reading its packed tail, so validate the
	// same expansion the compiler descends. The tail lives on THIS peeled
	// instance node (`[be priority bogus]`), one level below where the
	// flat-shape packedTail branch in walkSchemaNode looks, so without
	// this the packed spelling validated nothing while compiling the
	// value (#6821's bidirectional contract). Re-anchor the tail behind
	// a synthetic container node in this node's own shape — keyword when
	// the name rode at Keys[1] (flat), name-only otherwise (hierarchical
	// peel) — and let packedBodyChildren divide it by the same schema.
	// It declines (returns the authored children) outside the modelled
	// grammar, so a non-CoS packedTail container keeps its prior walk.
	if containerSchema.packedTail && len(node.Keys) > consume {
		wrapper := node
		if len(node.Keys) >= 2 && consume >= 1 {
			// Hierarchical peel: Keys[0] is the name itself, so the
			// wrapper must carry ONLY the name as identity; the tail
			// follows it. Synthesize that shape so consumeNodeKeys
			// (keyword + args) divides the tail correctly: use a
			// one-key identity node whose schema is the container
			// viewed through a zero-arg lens is NOT the container —
			// instead expand directly: the tail tokens are the body.
			// Build [name tail...] and expand with a schema whose
			// identity is exactly the name slot. packedBodyChildren
			// consumes 1+args from the FRONT, so prepend nothing:
			// Keys[0]=name acts as the keyword slot and the first
			// tail token must not be eaten as an arg. The container
			// declares args for its KEYWORD form; in peel form the
			// name already filled that slot, so a shallow schema copy
			// with args=0 (same children) divides the tail as body
			// statements.
			shallow := *containerSchema
			shallow.args = 0
			wrapper = &Node{
				Keys:          append([]string(nil), node.Keys...),
				Children:      node.Children,
				InheritedFrom: node.InheritedFrom,
			}
			if expanded := packedBodyChildren(wrapper, &shallow); len(expanded) != len(node.Children) || len(expanded) == 0 || (len(expanded) > 0 && len(node.Children) > 0 && &expanded[0] != &node.Children[0]) {
				walkChildren = expanded
			}
		}
	}
	return walkSchemaChildren(walkChildren, containerSchema, newPath, vc, closed)
}

// validateKeySlot runs a named-instance container's identity-arg
// validator on one token. It prefers the POSITION-AWARE keyValidatorPos
// (#5576) — passing argIdx, the token's 0-based position within the
// node's declared arg span — and falls back to the position-agnostic
// keyValidator when only that is set. A node sets at most one of the two;
// callers invoke this only when at least one is non-nil.
func validateKeySlot(schema *schemaNode, argIdx int, tok string, vc *walkContext) error {
	if schema.keyValidatorPos != nil {
		return schema.keyValidatorPos(argIdx, tok)
	}
	return schema.keyValidator(tok)
}

// validateModifierChild validates one AST child of a typed leaf (e.g.
// `exact` under `transmit-rate 1g`). The modifier must be a known child
// keyword of the leaf and have NO unexpected descendants of its own
// (`exact { bogus; }`). A presence-only modifier (args == 0) carries NO
// extra tokens in its Keys (`exact bogus` → leftover `bogus` is unknown);
// a VALUED modifier (#9880) carries exactly its declared args as value
// tokens (`key 5`), each validated against the modifier's own
// validator/treeValidator — the same checkToken the leaf's own value
// goes through. Untyped modifiers (no validator) accept any token in
// the value slot; the arity check still rejects a missing or trailing
// one. Before #9880 every trailing token was refused as `unknown
// modifier`, so valid Junos (`server <addr> key <n>`, `threshold <n>
// action <a>`) could not commit while the lenient path compiled it.
func validateModifierChild(node *Node, leafSchema *schemaNode, leafPath []string, vc *walkContext) error {
	if node == nil || len(node.Keys) == 0 {
		return nil
	}
	mod := node.Keys[0]
	if leafSchema.children == nil {
		return typedLeafErrorf(leafPath, "unknown modifier %q", mod)
	}
	modSchema, ok := leafSchema.children[mod]
	if !ok {
		return typedLeafErrorf(leafPath, "unknown modifier %q", mod)
	}
	nargs := 0
	if modSchema != nil {
		nargs = modSchema.args
	}
	trailing := node.Keys[1:]
	// Fewer tokens than the modifier declares is a missing value (`key`
	// with no id compiles to unset and is silently dropped); more is
	// unknown trailing garbage, reported as the first excess token — the
	// same `unknown modifier` family as before, still naming the leaf.
	if len(trailing) < nargs {
		return typedLeafErrorf(leafPath, "modifier %q requires a value", mod)
	}
	if len(trailing) > nargs {
		return typedLeafErrorf(leafPath, "unknown modifier %q", trailing[nargs])
	}
	modPath := append(append([]string(nil), leafPath...), mod)
	if modSchema != nil && nargs > 0 {
		for _, tok := range trailing {
			if err := modSchema.checkToken(vc, tok); err != nil {
				return typedLeafInvalidErrorf(modPath, tok, err)
			}
		}
	}
	// No descendants may hang off a modifier that declares no children of
	// its own. In particular a value-as-block spelling (`key { 5; }`) stays
	// rejected: a Junos valued leaf takes its value on the statement, not
	// as a block member — the block-value exception (#6774) is an explicit
	// per-leaf opt-in, and no modifier takes it.
	for _, c := range node.Children {
		if len(c.Keys) == 0 {
			continue
		}
		// If the modifier schema itself declares children (future nested
		// modifiers), recurse; otherwise any descendant is unknown.
		if modSchema != nil && modSchema.children != nil {
			if err := validateModifierChild(c, modSchema, modPath, vc); err != nil {
				return err
			}
			continue
		}
		return typedLeafErrorf(modPath, "unknown modifier %q", c.Keys[0])
	}
	return nil
}

// validateScalarValueLeaf enforces the fixed value-arity of a scalar value
// leaf (#3332): the leaf legitimately carries its keyword plus exactly
// leafSchema.args value token(s) on Keys and NO sub-statement. The compiler
// reads only that span (e.g. compiler_interfaces.go reads description's
// single value token), so any extra Keys token or AST child is operator
// garbage that today commits silently and is dropped. We reject the FIRST
// offending token with a value-arity message distinct from the #3318
// unknown-KEYWORD gate — here the leaf keyword itself IS supported, only the
// trailing token is not.
//
// Minimum arity is enforced for fixed-arity leaves; allowEmptyValue is the
// explicit exception for a Junos leaf that also accepts a presence-only form.
// The gate remains scoped to the same silent-drop bug class.
func validateScalarValueLeaf(node *Node, leafSchema *schemaNode, parentPath []string) error {
	leafName := node.Keys[0]
	leafPath := append(append([]string(nil), parentPath...), leafName)
	allowed := 1 + leafSchema.args
	// #8597 (muse-004 K15): the TOO-FEW half. This validator has rejected a
	// trailing token since #3332 with the reasoning "the extra token would be
	// silently dropped" — and a MISSING token is silently dropped in exactly
	// the same sense: `set system host-name` with no name commits clean and
	// the system carries no host-name. One arity check, both directions.
	if len(node.Keys) < allowed && len(node.Children) == 0 && !leafSchema.allowEmptyValue {
		return schemaPathErrorf(leafPath, "`%s` declares a value and none was given (this leaf takes %d value token(s)); "+
			"the compiler drops a valueless statement, so this commits clean and the "+
			"configuration silently does not carry it", leafName, leafSchema.args)
	}
	if len(node.Keys) > allowed {
		return schemaPathErrorf(append(append([]string(nil), leafPath...), node.Keys[allowed]), "unexpected trailing token %q (this leaf takes %d value token(s); the extra token would be silently dropped)", node.Keys[allowed], leafSchema.args)
	}
	// #12093: a scalar leaf that opts into blockValue also accepts the
	// single-child block spelling `keyword { value; }` — the same
	// singleBlockValue() shape as the #6774 typed-leaf exception (exactly
	// one child token, non-empty, no grandchildren, no trailing keys).
	// The compiler deliberately honours `input { f1; }` on the interface
	// filter bindings (#10293 pins it compiling to f1), so strict commit
	// must accept what compiles. Other scalar leaves stay rejected: the
	// opt-in is scoped to the four filter bindings, and — unlike
	// `default-policy { deny-all; }` — this spelling is not verified as
	// Junos-emitted, so it must not spread by default.
	if leafSchema.blockValue && len(node.Keys) == 1 {
		if _, ok := singleBlockValue(node); ok {
			return nil
		}
	}
	for _, c := range node.Children {
		if c == nil || len(c.Keys) == 0 {
			continue
		}
		return schemaPathErrorf(append(append([]string(nil), leafPath...), c.Keys[0]), "unexpected trailing token %q (this leaf takes %d value token(s) and no sub-statement; the extra token would be silently dropped)", c.Keys[0], leafSchema.args)
	}
	return nil
}

// resolveSchemaChild returns the schema node for keyword under parent:
// an exact child match, else the wildcard (dynamic instance name slot),
// else nil. An apply statement at a wildcard slot resolves to the statement,
// not to an instance name (#9685, schemaChildFor).
func resolveSchemaChild(parent *schemaNode, keyword string) *schemaNode {
	return schemaChildFor(parent, keyword)
}

// consumeNodeKeys computes how many leading tokens of keys belong to a
// non-typed node's identity (keyword + args, plus a compoundKey
// sub-token). It returns that count and the possibly-refined child schema
// (compoundKey descends one level). midKeyword sits within the arg span
// and is consumed there, so it needs no separate accounting. This is only
// used for container/untyped nodes; typed leaves treat Keys[1:] as value.
// effectiveArgs15752 returns the token arity of s for the concrete keys
// in a sibling context (container may be nil when unknown): a bare
// distinguished-name identity consumes 1 — the token after it, when it
// spells a sibling leaf of container (or when there is none), is the
// next statement, never the DN value. container/wildcard + DN and a
// direct DN consume the full declared arity. Splitters that pre-skip
// value slots (flat-run, packed, SetPath) must use this, not s.args,
// or a bare DN steals the following statement (#15752).
func effectiveArgs15752(s *schemaNode, keys []string, container *schemaNode) int {
	if s == nil {
		return 0
	}
	if !s.identityBareDN {
		return s.args
	}
	// Gateway identity leaf (#15752): a non-DN type takes exactly the
	// type + one value (args:2 worth); DN takes type + optional
	// qualifier + DN, and a bare DN takes the type alone.
	if len(keys) < 2 || keys[1] != "distinguished-name" {
		return 2
	}
	if len(keys) == 2 {
		return 1
	}
	if keys[2] == "container" || keys[2] == "wildcard" {
		return s.args
	}
	if container != nil && resolveSchemaChild(container, keys[2]) != nil {
		return 1
	}
	return s.args
}

func consumeNodeKeys(keys []string, childSchema *schemaNode) (int, *schemaNode) {
	consumed := 1 + effectiveArgs15752(childSchema, keys, nil)
	if consumed > len(keys) {
		consumed = len(keys)
	}
	// Compound key: the next token is part of this node's key and selects
	// a sub-child (e.g. "family inet6" → consume "inet6", descend into it).
	if childSchema.compoundKey && consumed < len(keys) {
		if sub, ok := childSchema.children[keys[consumed]]; ok {
			consumed++
			return consumed, sub
		}
	}
	return consumed, childSchema
}

// singleBlockValue returns the lone value token of a hierarchical block-form
// leaf — `keyword { value; }` parses to a node with no trailing keys and one
// childless child whose sole key is the value (#6774).
//
// It is deliberately strict. More than one child is reported as an ambiguous
// choice by validateTypedLeaf; malformed single children return false and the
// leaf then fails through the ordinary missing-value rejection.
func singleBlockValue(node *Node) (string, bool) {
	if len(node.Children) != 1 {
		return "", false
	}
	c := node.Children[0]
	if c == nil || len(c.Keys) != 1 || len(c.Children) != 0 || c.Keys[0] == "" {
		return "", false
	}
	return c.Keys[0], true
}

// validateSecurityLogHostNode15270 validates the braced value-or-container
// spelling of `security log stream <s> host` (#15270):
//
//	host { 192.0.2.1; port 514; }
//
// The flat spelling (`host 192.0.2.1`) is owned by validateTypedLeaf. This
// validator runs first (nodeValidator dispatch) and returns nil for that
// shape. For a child-bearing host it requires exactly one bare address child
// (validated with the same ValidateSyslogHost as the flat value) plus only
// `port` children, each carrying exactly one integer in [1..65535]. Port
// range-checking here mirrors validateSecurityLogStreamPortsAST so the
// braced shape fails closed at SchemaValidate even before strict compile.
func validateSecurityLogHostNode15270(node *Node, _ *schemaNode) error {
	if node == nil || len(node.Children) == 0 {
		return nil
	}
	if len(node.Keys) > 1 {
		// Flat/packed value present: validateTypedLeaf owns Keys[1:] and the
		// modifier children. Returning nil preserves that path exactly.
		return nil
	}
	var addrs []string
	for _, c := range node.Children {
		if c == nil || len(c.Keys) == 0 {
			continue
		}
		switch c.Keys[0] {
		case "port":
			if len(c.Keys) != 2 || len(c.Children) != 0 {
				return schemaErrorf(nil, "host port requires exactly one value")
			}
			if err := ValidateInteger(1, 65535)(c.Keys[1]); err != nil {
				return schemaErrorf(nil, "host port: %v", err)
			}
		default:
			if len(c.Keys) != 1 || len(c.Children) != 0 {
				return schemaErrorf(nil, "unknown modifier %q under host (only a bare address and port are allowed)", c.Keys[0])
			}
			addrs = append(addrs, c.Keys[0])
		}
	}
	if len(addrs) == 0 {
		return schemaErrorf(nil, "missing value (host requires exactly one address)")
	}
	if len(addrs) > 1 {
		return schemaErrorf(nil, "host requires exactly one address, found %d", len(addrs))
	}
	if err := ValidateSyslogHost(addrs[0]); err != nil {
		return err
	}
	return nil
}

// validateTypedLeaf validates the value token(s) of a typed leaf.
//
// Value/modifier tokens come from node.Keys[1:] (flat-set + hierarchical
// `keyword value` both pack the value into Keys[1]) plus, for the
// hierarchical `keyword value { modifier; }` shape, the value is still in
// Keys[1] and the modifier is an AST child (not a value).
//
// Contract (mirrors the schema-feature→AST-match table in the #1319 plan):
//   - standard typed leaf: the FIRST token is the value → run validator on
//     it; any subsequent token must match a child keyword (e.g. `exact`),
//     and a VALUED modifier (#9880) consumes its declared args as further
//     value tokens, each run through the modifier's own validator.
//   - multi && children==nil value-tail/range leaves are NOT handled
//     here — walkSchemaNode dispatches them to validateMultiValueLeaf,
//     which also accepts the hierarchical block-list spelling.
//   - modifier-headed line: the FIRST token is itself a known modifier
//     keyword, so the statement carries NO value on this node (modifiers
//     match before values, as in the compilers). A lone presence-only
//     modifier (e.g. `transmit-rate exact`) is the sibling-rule case below;
//     anything else modifier-headed fails — a lone valued modifier as a
//     missing modifier value, a multi-token run as a missing leaf value.
//   - modifier-only sibling: a flat-set leaf carrying ONLY a known
//     presence-only modifier is accepted IFF a sibling node supplies a
//     valid value (`transmit-rate 1g`); otherwise it fails. This preserves
//     the pre-#1319 schedulerHasTypedTransmitRate behaviour.
//   - missing value: a typed leaf with no value token fails.
//
// siblingSuppliesHostPort15270 reports whether a sibling `host port <n>`
// node supplies the port for a modifier-only `host <addr>` sibling (#15270).
// FormatSet renders braced `host { <addr>; port <n>; }` as two set lines.
func siblingSuppliesHostPort15270(siblings []*Node) bool {
	for _, s := range siblings {
		if s == nil || len(s.Keys) != 3 || s.Keys[0] != "host" || s.Keys[1] != "port" {
			continue
		}
		if ValidateInteger(1, 65535)(s.Keys[2]) == nil {
			return true
		}
	}
	return false
}

func validateTypedLeaf(node *Node, leafSchema *schemaNode, parentPath []string, siblings []*Node, vc *walkContext) error {
	leafName := node.Keys[0]
	path := append(append([]string(nil), parentPath...), leafName)
	values := node.Keys[1:]
	// #6774: the hierarchical BLOCK spelling `keyword { value; }`, for the
	// leaves that opt in via blockValue. Junos displays a choice container
	// (`default-policy`) that way, and the compiler reads it deliberately, so
	// without this the strict commit path rejects canonical Junos that the
	// compiler compiles correctly and the tolerated load path applies.
	//
	// EXACTLY ONE child carrying EXACTLY ONE token is accepted. More than one
	// child returns the cardinality diagnostic: strict commit/commit-check
	// rejects, while tolerant Load/SyncApply logs it and continues. The #11367
	// compiler prewalk also warns and forces the no-match default to deny.
	if len(values) == 0 && leafSchema.blockValue {
		if len(node.Children) > 1 {
			return typedLeafErrorf(path, defaultPolicyAmbiguousBlockDiagnostic, len(node.Children))
		}
		if v, ok := singleBlockValue(node); ok {
			values = []string{v}
		}
	}

	// #15270: braced `host { <addr>; port <n>; }` — nodeValidator already
	// validated the bare address/port; there is no Keys[1] value.
	if len(values) == 0 && len(node.Children) > 0 && leafSchema.nodeValidator != nil {
		return nil
	}

	if len(values) == 0 {
		return typedLeafErrorf(path, "missing value")
	}

	first := values[0]

	// Modifier-headed line: the FIRST token is itself a known child keyword,
	// so per the compiler's grammar — modifiers match before values (cf.
	// ntpServerValues, which consults the modifiers table before reading a
	// server, and the skip-modifiers rule in siblingSuppliesTypedValue) —
	// this statement carries NO value on this node. Reading the head as the
	// value instead admits statements that compile to nothing: `server
	// prefer key 5` passes `prefer` as a hostname here while the compiler
	// reads every token as a modifier with no address and yields no server.
	// A lone presence-only modifier keeps the historical sibling rule (a
	// flat-set `transmit-rate exact` beside `transmit-rate 1g`); a lone
	// valued modifier is a missing modifier value on its face; a
	// multi-token run is a missing leaf value. This preserves the pre-#1319
	// schedulerHasTypedTransmitRate behaviour.
	if leafSchema.children != nil {
		if modSchema, isMod := leafSchema.children[first]; isMod {
			// #15270: SetPath groups `host port 514` as host->[514] under a
			// `host port` node; the braced sibling supplies the address.
			if leafName == "host" && first == "port" {
				var portTok string
				if len(values) == 2 {
					portTok = values[1]
				} else if len(values) == 1 && len(node.Children) == 1 && len(node.Children[0].Keys) == 1 {
					portTok = node.Children[0].Keys[0]
				}
				if portTok != "" {
					if err := ValidateInteger(1, 65535)(portTok); err != nil {
						return typedLeafInvalidErrorf(append(append([]string(nil), path...), "port"), portTok, err)
					}
					if siblingSuppliesTypedValue(siblings, leafName, leafSchema, vc) {
						return nil
					}
				}
				return typedLeafErrorf(path, "modifier %q requires a value (e.g. a sibling %s <value>)", first, leafName)
			}
			if len(values) == 1 && (modSchema == nil || modSchema.args == 0) {
				if siblingSuppliesTypedValue(siblings, leafName, leafSchema, vc) {
					return nil
				}
				return typedLeafErrorf(path, "modifier %q requires a value (e.g. a sibling %s <value>)", first, leafName)
			}
			if len(values) == 1 {
				return typedLeafErrorf(path, "modifier %q requires a value", first)
			}
			return typedLeafErrorf(path, "missing value")
		}
	}

	// Standard typed leaf: first token is the value.
	if err := leafSchema.checkToken(vc, first); err != nil {
		return typedLeafInvalidErrorf(path, first, err)
	}
	// Remaining tokens must be known child-keyword modifiers (e.g. `exact`).
	// A valued modifier (#9880) consumes its declared args as value tokens
	// (`server 1.1.1.1 key 5 version 4`), each validated against the
	// modifier's own validator — the packed-Keys twin of the
	// validateModifierChild rule, so both spellings accept and reject
	// identically.
	for i := 1; i < len(values); {
		tok := values[i]
		if leafSchema.children == nil {
			return typedLeafErrorf(path, "unknown modifier %q", tok)
		}
		modSchema, ok := leafSchema.children[tok]
		if !ok {
			return typedLeafErrorf(path, "unknown modifier %q", tok)
		}
		nargs := 0
		if modSchema != nil {
			nargs = modSchema.args
		}
		if len(values)-i-1 < nargs {
			return typedLeafErrorf(path, "modifier %q requires a value", tok)
		}
		if modSchema != nil && nargs > 0 {
			modPath := append(append([]string(nil), path...), tok)
			for _, vtok := range values[i+1 : i+1+nargs] {
				if err := modSchema.checkToken(vc, vtok); err != nil {
					return typedLeafInvalidErrorf(modPath, vtok, err)
				}
			}
		}
		i += 1 + nargs
	}
	return nil
}

// validateMultiValueLeaf validates a `multi && children == nil` typed
// leaf (the value-tail/range row of the walker contract). Value tokens
// come from BOTH spellings the compilers read:
//
//   - packed Keys (`name-server 1.1.1.1`, bracketed `[ a b ]` lists,
//     and — only on a leaf that opts in via rangeSeparator — ranges
//     where the fixed mid-token `to` is a separator:
//     `destination-port 20000 to 20003`. On every other typed multi
//     leaf `to` is validated as an ordinary value, #4556 L-01), and
//   - the hierarchical block-list shape, one child node per value
//     (`name-server { 1.1.1.1; 8.8.8.8; }`). By default only each child's
//     FIRST token is validated, matching leaves whose compiler reads only
//     the child name (e.g. name-server / virtual-address). A leaf can opt in
//     via allChildKeysAreValues when its compiler consumes the full child
//     Keys tail; `as-path-prepend` does because it uses firewallMatchValues.
//
// A leaf with no value in either position fails, as do dangling /
// separator-only tails (["to"], ["20000","to"]).
func validateMultiValueLeaf(node *Node, leafSchema *schemaNode, parentPath []string, vc *walkContext) error {
	leafName := node.Keys[0]
	path := append(append([]string(nil), parentPath...), leafName)

	validatedAny := false
	lastWasSeparator := false
	for _, tok := range node.Keys[1:] {
		// #4556 L-01: the fixed mid-token `to` is only a RANGE separator
		// for a leaf that opts in via rangeSeparator (port-range /
		// NAT-pool-address). For every other typed multi leaf — the
		// IP/CIDR and session-log-flag leaves that actually reach this
		// walker — `to` is an ordinary value token and is validated (and
		// rejected) as such, not silently skipped.
		if leafSchema.rangeSeparator && tok == "to" {
			if !validatedAny || lastWasSeparator {
				return typedLeafErrorf(path, "missing value")
			}
			lastWasSeparator = true
			continue
		}
		if err := leafSchema.checkToken(vc, tok); err != nil {
			return typedLeafInvalidErrorf(path, tok, err)
		}
		validatedAny = true
		lastWasSeparator = false
	}
	if lastWasSeparator {
		return typedLeafErrorf(path, "missing value")
	}

	// Block-list children default to one compiler-consumed value per child.
	// Opt-in leaves like as-path-prepend validate every key they compile.
	for _, c := range node.Children {
		if c == nil || len(c.Keys) == 0 {
			continue
		}
		keys := c.Keys[:1]
		if leafSchema.allChildKeysAreValues {
			keys = c.Keys
		}
		for _, tok := range keys {
			if err := leafSchema.checkToken(vc, tok); err != nil {
				return typedLeafInvalidErrorf(path, tok, err)
			}
			validatedAny = true
		}
	}

	if !validatedAny {
		return typedLeafErrorf(path, "missing value")
	}
	return nil
}

// validateTailLeaf validates a whole-tail leaf (#4228 Gap 2) — a leaf whose
// schema carries a tailValidator. It gathers the leaf's flattened value/
// modifier tail and the flattened tails of its same-keyword siblings, then
// hands them to the leaf's tailValidator. Any returned error is scoped to the
// leaf's config path so commit-check output reads the same as the other
// typed-leaf errors.
func validateTailLeaf(node *Node, leafSchema *schemaNode, parentPath []string, siblings []*Node) error {
	leafName := node.Keys[0]
	path := append(append([]string(nil), parentPath...), leafName)
	tokens := gatherLeafTailTokens(node)
	var siblingTails [][]string
	for _, s := range siblings {
		if s == nil || s == node || len(s.Keys) == 0 || s.Keys[0] != leafName {
			continue
		}
		siblingTails = append(siblingTails, gatherLeafTailTokens(s))
	}
	if err := leafSchema.tailValidator(tokens, siblingTails); err != nil {
		return &typedLeafSchemaError{
			msg: schemaErrorf(append(append([]string(nil), path...), tokens...), "%s: %v", strings.Join(redactSecretPath(path), " "), err).Error(),
		}
	}
	return nil
}

// gatherLeafTailTokens returns every value/modifier token belonging to a leaf
// node, normalizing the two AST shapes a flat-set vs hierarchical parse can
// produce for the same statement. The hierarchical parser packs
// `transmit-rate percent 50 exact;` onto ONE node's Keys
// (["transmit-rate","percent","50","exact"]); flat-set SetPath groups it as a
// container Keys=["transmit-rate","percent"] with a child leaf ["50","exact"].
// Collecting node.Keys[1:] plus every descendant leaf's Keys yields the same
// flattened tail (["percent","50","exact"]) for both. Shared by the walker's
// validateTailLeaf and the compiler's parseCoSTransmitRate / parseCoSShapingRate
// so validation and compilation read an identical token stream.
func gatherLeafTailTokens(node *Node) []string {
	if node == nil {
		return nil
	}
	tokens := append([]string(nil), node.Keys[1:]...)
	var walk func(children []*Node)
	walk = func(children []*Node) {
		for _, c := range children {
			if c == nil {
				continue
			}
			tokens = append(tokens, c.Keys...)
			walk(c.Children)
		}
	}
	walk(node.Children)
	return tokens
}

// siblingSuppliesTypedValue reports whether any sibling node with the same
// leaf keyword carries a value token that the leaf's validator accepts.
// Used to allow a flat-set modifier-only line (`transmit-rate exact`) when
// the rate is set on a separate sibling node.
func siblingSuppliesTypedValue(siblings []*Node, leafName string, leafSchema *schemaNode, vc *walkContext) bool {
	for _, s := range siblings {
		if s == nil || len(s.Keys) == 0 || s.Keys[0] != leafName {
			continue
		}
		for _, tok := range s.Keys[1:] {
			// Skip known modifier keywords; only a real value counts.
			if leafSchema.children != nil {
				if _, isMod := leafSchema.children[tok]; isMod {
					continue
				}
			}
			if leafSchema.checkToken(vc, tok) == nil {
				return true
			}
		}
		// #15270: the braced-host bare address lives as a child, not Keys[1:].
		for _, c := range s.Children {
			if c == nil || len(c.Keys) != 1 {
				continue
			}
			if _, isMod := leafSchema.children[c.Keys[0]]; isMod {
				continue
			}
			if leafSchema.checkToken(vc, c.Keys[0]) == nil {
				return true
			}
		}
	}
	return false
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

// typedLeafSchemaError marks a schema rejection from a typed validator or
// typed-value structure, including validated keys, multi/tail values, and
// modifiers. The tolerant configstore path persists only this class as a
// queryable typed-leaf warning. Top-level stanza, closed-world keyword,
// node-validator/scalar-arity, and flat/peeled midKeyword structural errors
// remain ordinary tolerated schema diagnostics.
type typedLeafSchemaError struct{ msg string }

func (e *typedLeafSchemaError) Error() string { return e.msg }

// IsTypedLeafSchemaError reports whether err (including wrapped errors) came
// from the typed-validator/typed-value partition. It deliberately excludes
// top-level stanza, closed-world keyword, node-validator, scalar-arity, and
// midKeyword structural errors.
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
		// caller's spread slice. nameOnlyArg args pass through.
		cp := make([]interface{}, len(args))
		for i, a := range args {
			if _, isName := a.(nameOnlyArg); isName {
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

// collectSecretValues returns every secret VALUE in the candidate:
// for each node, the secret-indexed tokens of its flattened path,
// PLUS the inner secret tokens of any embedded
// `change-configuration commands` payload (fold 4, F2 — the outer AST
// sees the quoted command as one token, so its inner credential
// operands are collected by lexing it exactly as the ingest guard
// does). Deduplicated, longest first so a longer value is replaced
// before any shorter value it contains.
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
						if idx >= 0 && idx < len(tokens) {
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

// scrubSecretValuesText is the FINAL-string-level scrub (fold 4):
// given the candidate's secret values, replace every occurrence in
// text in raw, strconv.Quote, and quoted-interior forms. This is the
// level token substitution kept losing to embedding — a value quoted
// inside a larger %q string, or carried inside a quoted embedded
// command, is still found because matching is on the final rendered
// bytes, not on which formatter produced them.
func scrubSecretValuesText(values []string, text string) string {
	for _, v := range values {
		if v == "" {
			continue
		}
		text = strings.ReplaceAll(text, v, SecretRedacted)
		if q := strconv.Quote(v); q != v {
			text = strings.ReplaceAll(text, q, strconv.Quote(SecretRedacted))
		}
		if in := quotedInterior(v); in != v && len(in) >= 2 {
			text = strings.ReplaceAll(text, in, SecretRedacted)
		}
	}
	return text
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
