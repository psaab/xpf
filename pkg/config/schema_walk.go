package config

import (
	"strings"
)

// schema_walk.go is the traversal shell for the #1319 typed-leaf
// gate; the entry point and the helpers it dispatches to live in the
// sibling files of the schema_walk_* family (#16152):
//
//   - schema_walk_entry.go — SchemaValidate*, schemaValidateImpl, and
//     the exit secret-scrub (scrubSchemaErrorSecrets and its helpers).
//   - schema_walk_refs.go — walkContext and the tree-derived
//     cross-reference sets (schemaRefs, collectSchemaRefs).
//   - schema_walk_leaf.go — the typed-leaf validators:
//     validateTypedLeaf, validateMultiValueLeaf, validateTailLeaf,
//     validateScalarValueLeaf, and their token/modifier helpers.
//   - schema_walk_errors.go — the typed / unknown-stanza error types
//     and every error constructor, including the #16066 shared
//     construction choke point (schemaErrorf / schemaPathErrorf) and
//     the secret-scrubbing it applies.
//
// This file keeps the walk itself: walkSchemaChildren,
// walkSchemaNode, and walkInstanceChildren, plus the small
// schema-resolution helpers they share with the leaf validators
// (resolveSchemaChild, effectiveArgs15752, consumeNodeKeys,
// singleBlockValue).

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
		if vc.collecting() && len(*vc.collectErrs) >= vc.collectMax {
			return nil
		}
		if err := walkSchemaNode(node, parent, path, vc, nodes, closed); err != nil {
			if vc.recordTypedLeaf(err) {
				continue
			}
			return err
		}
	}
	return nil
}
// nestedMultiValueContentErrorf rejects a child block under a multi-value
// leaf. Such a leaf has no declared children, and its readers consume only
// each direct child's keys; accepting a block there would silently discard
// every grandchild. This follows the same fail-closed value-list convention
// as validateMultiValueLeaf's refusal of ambiguous multi-token block rows.
func nestedMultiValueContentErrorf(path []string, leafName, value string) error {
	return typedLeafErrorf(path,
		"nested content under %s value %q is unsupported; the value-list reader does not descend into child blocks, so the nested statement would be silently dropped",
		leafName, value)
}

// findNestedMultiValueContentError scans the schema-recognized portions of an
// expanded tree for nested blocks under multi-value leaves. It is also called
// from compileTree, which must reject this one data-loss shape even on direct
// and lenient compiler entry points that do not make SchemaValidate fatal.
func findNestedMultiValueContentError(nodes []*Node, parent *schemaNode, path []string) error {
	if parent == nil {
		return nil
	}
	for _, node := range nodes {
		if node == nil || len(node.Keys) == 0 {
			continue
		}
		keyword := node.Keys[0]
		childSchema := resolveSchemaChild(parent, keyword)
		if childSchema == nil {
			continue
		}
		if childSchema.refuseNonLeafBlockChildren {
			leafPath := append(path, keyword)
			for _, child := range node.Children {
				if child == nil || len(child.Keys) == 0 || (len(child.Children) == 0 && child.IsLeaf) {
					continue
				}
				return nestedMultiValueContentErrorf(leafPath, keyword, child.Keys[0])
			}
			continue
		}

		pathLen := len(path)
		consumed, descendSchema := consumeNodeKeys(node.Keys, childSchema)
		path = append(path, node.Keys[:consumed]...)
		missingArgs := 1 + childSchema.args - consumed
		if missingArgs > 0 && !childSchema.compoundKey {
			err := findNestedMultiValueContentInInstances(node.Children, childSchema, missingArgs, path)
			path = path[:pathLen]
			if err != nil {
				return err
			}
			continue
		}

		walkChildren := node.Children
		if keyword == "qualified-next-hop" {
			walkChildren = expandRunChildren9235(walkChildren, childSchema)
		}
		if childSchema.packedTail && len(node.Keys) > consumed {
			walkChildren = packedBodyChildren(node, childSchema)
		} else if childSchema.packedFlatRun && len(node.Children) > 0 {
			walkChildren = expandFlatRun(node.Children, childSchema)
		}
		err := findNestedMultiValueContentError(walkChildren, descendSchema, path)
		path = path[:pathLen]
		if err != nil {
			return err
		}
	}
	return nil
}

// findNestedMultiValueContentInInstances peels hierarchical named-instance
// keys before resuming the schema scan at that instance's child statements.
func findNestedMultiValueContentInInstances(nodes []*Node, containerSchema *schemaNode, remaining int, path []string) error {
	if containerSchema == nil || remaining <= 0 {
		return nil
	}
	for _, node := range nodes {
		if node == nil || len(node.Keys) == 0 {
			continue
		}
		pathLen := len(path)
		consumed := len(node.Keys)
		if consumed > remaining {
			consumed = remaining
		}
		path = append(path, node.Keys[:consumed]...)
		var err error
		if stillMissing := remaining - consumed; stillMissing > 0 {
			err = findNestedMultiValueContentInInstances(node.Children, containerSchema, stillMissing, path)
		} else {
			err = findNestedMultiValueContentError(node.Children, containerSchema, path)
		}
		path = path[:pathLen]
		if err != nil {
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
		if err := validateTailLeaf(node, childSchema, path, siblings); err != nil {
			if vc.recordTypedLeaf(err) {
				return nil
			}
			return err
		}
		return nil
	}

	exactMatch := parent.children != nil && parent.children[keyword] == childSchema

	if childSchema.nodeValidator != nil && exactMatch {
		if err := childSchema.nodeValidator(node, parent); err != nil {
			leafPath := append(append([]string(nil), path...), keyword)
			return schemaPathErrorf(leafPath, "%v", err)
		}
	}
	// #16679: `multihop` is a Junos presence container typed as a leaf
	// with modifiers. Three authored shapes carry no packed TTL value
	// for validateTypedLeaf to check and must not fall into its
	// "missing value" refusal:
	//   - bare `multihop;` / `set ... multihop` (no tokens, no
	//     children): the Junos presence form; the compiler applies
	//     the Junos default TTL 64.
	//   - `multihop { ttl N; }` (blocked): the TTL rides a CHILD
	//     node, where the modifier-child loop would read the value
	//     as an unmodeled keyword. validateBGPMultihop16679
	//     (nodeValidator above) already range-checked it.
	//   - `multihop { no-nexthop-change; }`: already refused by name
	//     by the nodeValidator above; reaching here means it passed.
	// A multihop node whose ONLY children are `ttl` /
	// `no-nexthop-change` therefore returns here, in every child
	// shape (blocked `ttl 2`, flat-set `ttl` -> value grandchild):
	// the ttl value, when present, was already range-checked by
	// validateBGPMultihop16679. The flat-set packed shape
	// (`multihop ttl` with the value as its sole child) returns
	// here too, as does the fused variant (`multihop ttl` -> child
	// ["3","passive"]: the ttl was range-checked; the fused tail
	// token is a compiler-owned packed-run concern, strictly
	// rejected only where the schema gate can segment it). Any
	// other packed token, or any other child, re-enters the
	// ordinary typed-leaf validation below (scalar TTL range,
	// packed `ttl` modifier, unknown-modifier rejection).
	// #17833: on the `multihop ttl` arm (len(Keys)==2) the value child
	// is REQUIRED: `multihop ttl` with no keyed child is a missing
	// value (the bare presence form is `multihop;`), so it falls
	// through to the typed-leaf branch, which refuses it as `modifier
	// "ttl" requires a value` instead of the old silent accept that
	// the extractor then defaulted to TTL 64.
	if keyword == "multihop" && exactMatch && (len(node.Keys) == 1 || (len(node.Keys) == 2 && node.Keys[1] == "ttl")) {
		onlyModifierChildren := true
		hasValueChild := false
		for _, c := range node.Children {
			if len(node.Keys) == 2 {
				// Value child of the flat-set ttl shape — not a
				// modifier child to judge here.
				if c != nil && len(c.Keys) > 0 {
					hasValueChild = true
				}
				continue
			}
			if c == nil || len(c.Keys) == 0 || (c.Keys[0] != "ttl" && c.Keys[0] != "no-nexthop-change") {
				onlyModifierChildren = false
				break
			}
		}
		if onlyModifierChildren && (len(node.Keys) == 1 || hasValueChild) {
			return nil
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
			if err := validateMultiValueLeaf(node, childSchema, path, vc); err != nil {
				if vc.recordTypedLeaf(err) {
					return nil
				}
				return err
			}
			return nil
		}
		// Typed leaf: node.Keys[1:] are the value/modifier tokens. The leaf
		// keyword is the only identity token.
		if err := validateTypedLeaf(node, childSchema, path, siblings, vc); err != nil {
			if vc.recordTypedLeaf(err) {
				return nil
			}
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
				if vc.recordTypedLeaf(err) {
					continue
				}
				return err
			}
		}
		return nil
	}

	// #16535: an UNTYPED multi leaf (no validator — e.g. proxy-arp
	// `address`, whose values are checked by the compiler's own strict
	// gate) never reaches validateMultiValueLeaf above, so the sixth
	// spelling `leaf { v1 v2; }` would pass the walk unchecked and the
	// compiler's Keys[0]-per-child read would silently drop v2. Refuse
	// a multi-token block child here too: one value per statement.
	// Typed leaves are handled inside validateMultiValueLeaf; scalar
	// (non-multi) leaves keep their own arity handling below. The
	// refusal is structural only — no token is value-validated here,
	// because this leaf has no validator to validate it with.
	if childSchema.multi && childSchema.children == nil && exactMatch {
		for _, c := range node.Children {
			if c == nil || len(c.Keys) == 0 {
				continue
			}
			if childSchema.refuseNonLeafBlockChildren && (len(c.Children) > 0 || !c.IsLeaf) {
				leafPath := append(append([]string(nil), path...), keyword)
				err := nestedMultiValueContentErrorf(leafPath, keyword, c.Keys[0])
				if vc.recordTypedLeaf(err) {
					continue
				}
				return err
			}
			if len(c.Keys) <= 1 {
				continue
			}
			leafPath := append(append([]string(nil), path...), keyword)
			err := typedLeafErrorf(leafPath, "only one value per statement inside a value block; write %q as separate statements (%s { %s; %s; }) or a bracket list (%s [ %s %s ])", strings.Join(c.Keys, " "), keyword, c.Keys[0], c.Keys[1], keyword, c.Keys[0], c.Keys[1])
			if vc.recordTypedLeaf(err) {
				continue
			}
			return err
		}
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
	// #16749: a valueless flag (passive, remove-private, log-updown, ...)
	// inside a BGP container whose compiler expands flat runs carries
	// chained children the compiler hoists to the parent and applies.
	// Validate those children at the parent schema — the compiler's own
	// expanded view — so a chained typed leaf (hold-time 1) is rejected
	// exactly as its separate-line spelling is. Unresolvable chained
	// children stay open-world here and are warned by #10707.
	if isValuelessFlag16749(childSchema) && len(node.Children) > 0 && isBGPFlatRunContainer16749(parent) {
		flagPath := append(append([]string(nil), path...), keyword)
		if err := validateChainedUnderFlag16749(node, parent, path, vc, closed); err != nil {
			wrapped := chainedFlagError16749(flagPath, keyword, err)
			if vc.recordTypedLeaf(wrapped) {
				return nil
			}
			// In collect mode a wrapped non-typed error is returned by
			// walkSchemaChildren's recordTypedLeaf handling; preserve
			// the original typed error when not collected so type
			// classification upstream is unchanged.
			if vc.collecting() {
				return wrapped
			}
			return err
		}
		return nil
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
				if vc.recordTypedLeaf(err) {
					continue
				}
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
		// #16662: packedBodyChildren declines (returns the authored
		// Children) when the tail leaves the modelled grammar, so a
		// bogus packed leaf would validate nothing while the compiler
		// now reads the same expansion. A non-empty tail that expands
		// to exactly the authored children is that declined case:
		// under a closed-world container the tail token is an unknown
		// keyword and must reject, mirroring the braced spelling.
		if expanded := packedBodyChildren(node, childSchema); len(expanded) == len(node.Children) && (len(expanded) == 0 || (len(node.Children) > 0 && &expanded[0] == &node.Children[0])) {
			if childClosed {
				return schemaErrorf(newPath, "%s: unknown configuration keyword %q under closed-world subtree",
					strings.Join(redactSecretPath(newPath), " "), node.Keys[consumed])
			}
		}
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
				if vc.recordTypedLeaf(err) {
					continue
				}
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
