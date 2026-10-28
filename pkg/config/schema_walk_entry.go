package config

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

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
	_, err := schemaValidateCollect(tree, nil, false)
	return err
}

// MaxCollectedTypedLeafViolations16012 bounds the #16012 collect-all walk.
const MaxCollectedTypedLeafViolations16012 = 16

// SchemaValidateCollectTypedLeaves returns up to
// MaxCollectedTypedLeafViolations16012 independent typed-leaf violations
// (#16012) and, separately, the first non-typed schema error if one stopped
// the walk. A nested-list refusal is the #17241 hard exception: when the
// normal walk is stopped by an earlier structural error or the typed-error
// cap, opted-in leaves are rescanned, and any earlier structural diagnostic
// is preserved alongside the hard refusal.
// Strict callers keep SchemaValidate (first error, unchanged); the tolerant
// configstore path uses this to persist ordinary typed-leaf warnings without
// allowing a truncated nested list through.
func SchemaValidateCollectTypedLeaves(tree, defsSource *ConfigTree) ([]error, error) {
	return schemaValidateCollect(tree, defsSource, true)
}

func schemaValidateCollect(tree, defsSource *ConfigTree, collect bool) ([]error, error) {
	return schemaValidateImpl(tree, defsSource, collect)
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
	_, err := schemaValidateImpl(tree, defsSource, false)
	return err
}

func schemaValidateImpl(tree, defsSource *ConfigTree, collect bool) ([]error, error) {
	if tree == nil {
		return nil, nil
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
		if collect {
			if nestedErr := findNestedListContentError(tree.Children, setSchema, nil); nestedErr != nil {
				return nil, scrubSchemaErrorSecrets(tree, errors.Join(err, nestedErr))
			}
		}
		return nil, scrubSchemaErrorSecrets(tree, err)
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
		return nil, scrubSchemaErrorSecrets(tree, err)
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
		if collect {
			if nestedErr := findNestedListContentError(tree.Children, setSchema, nil); nestedErr != nil {
				return nil, scrubSchemaErrorSecrets(tree, errors.Join(err, nestedErr))
			}
		}
		return nil, scrubSchemaErrorSecrets(tree, err)
	}
	vc := &walkContext{refs: refs}
	// closed=false: the top-level walk is open-world. The per-subtree
	// closed-world flag (#4313) is inherited from schemaNode.closedWorld as
	// the walker descends. No count here — see the keyword-resolution gate
	// below for why prose must not state how many subtrees are armed.
	if collect {
		var errs []error
		cvc := &walkContext{refs: refs, collectErrs: &errs, collectMax: MaxCollectedTypedLeafViolations16012}
		walkErr := walkSchemaChildren(tree.Children, setSchema, nil, cvc, false)
		// #17241: the collect cap and a non-typed structural error can stop
		// the ordinary walk before it reaches a nested-list refusal. On those
		// error paths only, run the narrow schema-aware scan so neither a
		// flood of unrelated typed errors nor a tolerated structural finding
		// can hide values that the compiler will silently drop.
		if walkErr != nil || len(errs) >= MaxCollectedTypedLeafViolations16012 {
			if nestedErr := findNestedListContentError(tree.Children, setSchema, nil); nestedErr != nil {
				if walkErr == nil || IsNestedListContentSchemaError(walkErr) {
					walkErr = nestedErr
				} else {
					walkErr = errors.Join(walkErr, nestedErr)
				}
			}
		}
		for i, e := range errs {
			errs[i] = scrubSchemaErrorSecrets(tree, e)
		}
		if walkErr != nil {
			// #16012 fold: a later non-typed structural error ends the
			// ordinary walk, but does not erase independent typed-leaf
			// violations already collected. The #17241 nested-list refusal
			// is found by the bounded fallback scan above and is joined with
			// an earlier structural error when both are present.
			return errs, scrubSchemaErrorSecrets(tree, walkErr)
		}
		return errs, nil
	}
	if err := walkSchemaChildren(tree.Children, setSchema, nil, vc, false); err != nil {
		return nil, scrubSchemaErrorSecrets(tree, err)
	}
	return nil, nil
}

// scrubSchemaErrorSecrets is the exit half of the #16066 shared choke
// point: schemaErrorf scrubs at construction inside
// schema_walk_errors.go, but validators and node/tail validators
// return errors built in other files, and a future formatter can
// still bypass construction.
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
	if IsNestedListContentSchemaError(err) {
		if scrubbed == msg {
			return err
		}
		return &nestedListContentSchemaError{msg: scrubbed}
	}
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
