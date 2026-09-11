package config

import (
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
// cfg is ALWAYS nil in production: both call sites
// (configstore.compileTree / compileTreeLenient via
// schemaValidateExpandedTree, pkg/configstore/store.go) run the gate
// BEFORE the compiler, so no *Config exists yet. Validators must not
// depend on it. Cross-reference validation is TREE-based instead: the
// walk pre-collects referenceable definitions from the candidate tree
// itself into schemaRefs (collectSchemaRefs below) and hands them to
// treeValidator leaves — atomicity-correct, because a definition and its
// reference added in the same commit validate against the same tree.
// Removing the cfg parameter outright is a possible follow-up once we
// are confident no post-compile consumer will ever appear; it is kept
// for now because the LeafValidator signature is mirrored in cmdtree.
//
// The tree passed in MUST already be apply-groups-expanded (configstore
// expands before calling), so group bodies are inlined before the walk.
// Cross-reference definitions are collected from this same tree; callers
// that still hold the PRE-expansion candidate should prefer
// SchemaValidateWithDefinitions so definitions living only in un-applied
// groups survive (expansion removes the groups stanza outright).
func SchemaValidate(tree *ConfigTree, cfg *Config) error {
	return SchemaValidateWithDefinitions(tree, nil, cfg)
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
func SchemaValidateWithDefinitions(tree, defsSource *ConfigTree, cfg *Config) error {
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
	// #4060: reject the raw-AST redaction placeholder ("##SECRET-DATA##") on
	// commit-ingest. This is the symmetric guard for the #4051 display
	// redaction — re-applying a secret-redacted REST export must not silently
	// commit the placeholder as a literal secret (breaking IPsec/auth with a
	// nonsense key). Strict on the operator commit path (fails the commit),
	// downgraded to a warning on the tolerant Load / SyncApply path
	// (compileTreeLenient), the same doctrine as the typed-leaf gate below.
	if err := checkRedactionPlaceholder(tree); err != nil {
		return err
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
		return err
	}
	vc := &walkContext{cfg: cfg, refs: refs}
	// closed=false: the top-level walk is open-world. The per-subtree
	// closed-world flag (#4313) is inherited from schemaNode.closedWorld as
	// the walker descends. No count here — see the keyword-resolution gate
	// below for why prose must not state how many subtrees are armed.
	return walkSchemaChildren(tree.Children, setSchema, nil, vc, false)
}

// walkContext carries the per-walk validation inputs: the (always-nil in
// production) cfg pointer for the legacy LeafValidator signature, and
// the tree-derived cross-reference sets for treeValidator leaves.
type walkContext struct {
	cfg  *Config
	refs *schemaRefs
}

// config / collectedRefs are nil-receiver-safe accessors: the white-box
// walker tests drive walkSchemaNode with a nil context, matching the
// production reality that cfg is nil anyway.
func (vc *walkContext) config() *Config {
	if vc == nil {
		return nil
	}
	return vc.cfg
}

func (vc *walkContext) collectedRefs() *schemaRefs {
	if vc == nil {
		return nil
	}
	return vc.refs
}

// treeLeafValidator is the TREE-based counterpart of LeafValidator for
// cross-reference leaves: instead of the (always-nil in production)
// *Config it receives the definitions collected from the candidate tree
// by collectSchemaRefs, so a definition and its reference added in the
// same commit validate atomically.
type treeLeafValidator func(raw string, refs *schemaRefs) error

// leafTailValidator validates the whole value/modifier tail of a leaf as a
// unit (#4228 Gap 2). tokens are the flattened tail of the leaf node;
// siblingTails are the flattened tails of the same-keyword sibling nodes at
// the same level (so a modifier-only split-set line can look across to a
// sibling that supplies the value). See schemaNode.tailValidator.
type leafTailValidator func(tokens []string, siblingTails [][]string) error

// checkValue returns the per-token validation function for a typed
// leaf: the scalar validator when set, else the tree-based
// cross-reference validator bound to the walk's collected refs. A typed
// leaf sets exactly one of the two (walkSchemaNode gates on either).
func (n *schemaNode) checkValue(vc *walkContext) func(string) error {
	if n.validator != nil {
		return func(tok string) error { return n.validator(tok, vc.config()) }
	}
	if n.treeValidator != nil {
		return func(tok string) error { return n.treeValidator(tok, vc.collectedRefs()) }
	}
	return func(string) error { return nil }
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
	var collectCoS func(node *Node)
	collectCoS = func(node *Node) {
		fcNode := node.FindChild("forwarding-classes")
		if fcNode == nil {
			return
		}
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
	// collectLoginClasses records custom `login class <name>` names under a
	// `system` node (#4304 S-2). Mirrors the compiler's namedInstances over
	// `system login class`: the class name is the leading Keys arg.
	collectLoginClasses := func(sysNode *Node) {
		loginNode := sysNode.FindChild("login")
		if loginNode == nil {
			return
		}
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
	for _, top := range tree.Children {
		if top == nil || len(top.Keys) == 0 {
			continue
		}
		switch top.Name() {
		case "class-of-service":
			collectCoS(top)
		case "system":
			collectLoginClasses(top)
		case "groups":
			for _, group := range top.Children {
				if group == nil {
					continue
				}
				if cos := group.FindChild("class-of-service"); cos != nil {
					collectCoS(cos)
				}
				if sys := group.FindChild("system"); sys != nil {
					collectLoginClasses(sys)
				}
			}
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
		if closed {
			return typedLeafErrorf(path, "unknown configuration keyword %q under closed-world subtree", keyword)
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

	// Whole-tail leaf (#4228 Gap 2): an irregular grammar (CoS transmit-rate /
	// shaping-rate) whose heterogeneous value/modifier tail is validated as a
	// unit rather than token-by-token. Takes precedence over the generic
	// typed-leaf / container paths.
	if childSchema.tailValidator != nil {
		return validateTailLeaf(node, childSchema, path, siblings)
	}

	exactMatch := parent.children != nil && parent.children[keyword] == childSchema

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
		for _, tok := range node.Keys[declaredKeyTokens:] {
			if _, isSibling := parent.children[tok]; !isSibling {
				continue
			}
			if tok == keyword {
				continue // a repeat of this leaf, not a foreign statement
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
			return fmt.Errorf("%s: the token %q follows `%s` but names a SIBLING "+
				"statement — a missing semicolon after `%s` fuses the two, and the "+
				"`%s` statement is then silently dropped from the compiled config "+
				"while `show configuration` still displays it. Add the missing `;` "+
				"(#8437)",
				strings.Join(append(append([]string(nil), path...), keyword), " "),
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
	// children: peel those name levels (the compiler's namedInstances does
	// the same) and validate each instance's children at the child schema.
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
		return fmt.Errorf("%s: `%s` declares a value and none was given — the compiler "+
			"drops a valueless statement, so this commits clean and the configuration "+
			"silently does not carry it",
			strings.Join(newPath, " "), keyword)
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
	// Default-off is deliberate and is the compiler-faithful contract above:
	// for every other container the tail is not compiled, so validating it
	// would reject a configuration that behaves identically either way.
	walkChildren := node.Children
	if childSchema.packedTail && len(node.Keys) > consumed {
		walkChildren = packedBodyChildren(node, childSchema)
	}
	return walkSchemaChildren(walkChildren, descendSchema, newPath, vc, childClosed)
}

// walkInstanceChildren peels the missing instance-name level(s) off a
// hierarchical named-instance node and validates the instance's block
// children at the container schema. It mirrors the compiler's namedInstances
// + per-instance child walk: the instance name comes from the node's leading
// Keys; the leaves are the node's CHILDREN. Any extra tokens packed into the
// instance node's Keys beyond the name are ignored (the compiler does not
// compile them; see walkSchemaNode's container comment, Codex r7).
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
	// any leftover Keys past the name are not compiled and are ignored.
	return walkSchemaChildren(node.Children, containerSchema, newPath, vc, closed)
}

// validateKeySlot runs a named-instance container's identity-arg
// validator on one token. It prefers the POSITION-AWARE keyValidatorPos
// (#5576) — passing argIdx, the token's 0-based position within the
// node's declared arg span — and falls back to the position-agnostic
// keyValidator when only that is set. A node sets at most one of the two;
// callers invoke this only when at least one is non-nil.
func validateKeySlot(schema *schemaNode, argIdx int, tok string, vc *walkContext) error {
	if schema.keyValidatorPos != nil {
		return schema.keyValidatorPos(argIdx, tok, vc.config())
	}
	return schema.keyValidator(tok, vc.config())
}

// validateModifierChild validates one AST child of a typed leaf (e.g.
// `exact` under `transmit-rate 1g`). A modifier is presence-only: it must
// be a known child keyword of the leaf, carry NO extra tokens in its Keys
// (`exact bogus` → leftover `bogus` is unknown), and have NO unexpected
// descendants of its own (`exact { bogus; }`). Modifiers themselves carry
// no typed value, so we only assert the keyword is recognized and nothing
// trails it.
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
	// No tokens may trail the modifier keyword in its Keys.
	if len(node.Keys) > 1 {
		return typedLeafErrorf(leafPath, "unknown modifier %q", node.Keys[1])
	}
	// No descendants may hang off a presence-only modifier.
	modPath := append(append([]string(nil), leafPath...), mod)
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
// Minimum arity is NOT enforced (a missing value is left to the compiler, as
// before) — the gate is scoped strictly to EXCESS trailing tokens, the
// silent-drop bug class.
func validateScalarValueLeaf(node *Node, leafSchema *schemaNode, parentPath []string) error {
	leafName := node.Keys[0]
	leafPath := append(append([]string(nil), parentPath...), leafName)
	allowed := 1 + leafSchema.args
	// #8597 (muse-004 K15): the TOO-FEW half. This validator has rejected a
	// trailing token since #3332 with the reasoning "the extra token would be
	// silently dropped" — and a MISSING token is silently dropped in exactly
	// the same sense: `set system host-name` with no name commits clean and
	// the system carries no host-name. One arity check, both directions.
	if len(node.Keys) < allowed && len(node.Children) == 0 {
		return typedLeafErrorf(leafPath,
			"`%s` declares a value and none was given (this leaf takes %d value token(s)); "+
				"the compiler drops a valueless statement, so this commits clean and the "+
				"configuration silently does not carry it",
			leafName, leafSchema.args)
	}
	if len(node.Keys) > allowed {
		return typedLeafErrorf(leafPath,
			"unexpected trailing token %q (this leaf takes %d value token(s); the extra token would be silently dropped)",
			node.Keys[allowed], leafSchema.args)
	}
	for _, c := range node.Children {
		if c == nil || len(c.Keys) == 0 {
			continue
		}
		return typedLeafErrorf(leafPath,
			"unexpected trailing token %q (this leaf takes %d value token(s) and no sub-statement; the extra token would be silently dropped)",
			c.Keys[0], leafSchema.args)
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
func consumeNodeKeys(keys []string, childSchema *schemaNode) (int, *schemaNode) {
	consumed := 1 + childSchema.args
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
// It is deliberately strict. More than one child, a child carrying more than
// one token, or a child carrying its own block all return false, so the leaf
// falls through to the ordinary "missing value" rejection rather than silently
// binding the first token of an ambiguous block — which is exactly what the
// compiler would then discard.
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

// validateTypedLeaf validates the value token(s) of a typed leaf.
//
// Value/modifier tokens come from node.Keys[1:] (flat-set + hierarchical
// `keyword value` both pack the value into Keys[1]) plus, for the
// hierarchical `keyword value { modifier; }` shape, the value is still in
// Keys[1] and the modifier is an AST child (not a value).
//
// Contract (mirrors the schema-feature→AST-match table in the #1319 plan):
//   - standard typed leaf: the FIRST token is the value → run validator on
//     it; any subsequent token must match a child keyword (e.g. `exact`).
//   - multi && children==nil value-tail/range leaves are NOT handled
//     here — walkSchemaNode dispatches them to validateMultiValueLeaf,
//     which also accepts the hierarchical block-list spelling.
//   - modifier-only sibling: a flat-set leaf carrying ONLY a known modifier
//     (e.g. `transmit-rate exact`) is accepted IFF a sibling node supplies
//     a valid value (`transmit-rate 1g`); otherwise it fails. This
//     preserves the pre-#1319 schedulerHasTypedTransmitRate behaviour.
//   - missing value: a typed leaf with no value token fails.
//   - unknown modifier: a non-value token matching no child keyword fails.
func validateTypedLeaf(node *Node, leafSchema *schemaNode, parentPath []string, siblings []*Node, vc *walkContext) error {
	leafName := node.Keys[0]
	path := append(append([]string(nil), parentPath...), leafName)
	values := node.Keys[1:]
	check := leafSchema.checkValue(vc)

	// #6774: the hierarchical BLOCK spelling `keyword { value; }`, for the
	// leaves that opt in via blockValue. Junos displays a choice container
	// (`default-policy`) that way, and the compiler reads it deliberately, so
	// without this the strict commit path rejects canonical Junos that the
	// compiler compiles correctly and the tolerated load path applies.
	//
	// EXACTLY ONE child carrying EXACTLY ONE token is accepted. Two children
	// is NOT "the first one wins": the compiler reads Children[0] and
	// silently discards the rest, so `default-policy { deny-all; permit-all; }`
	// does not do what it reads as and must still be rejected.
	if len(values) == 0 && leafSchema.blockValue {
		if v, ok := singleBlockValue(node); ok {
			values = []string{v}
		}
	}

	if len(values) == 0 {
		return typedLeafErrorf(path, "missing value")
	}

	first := values[0]

	// Modifier-only line: the sole token is a known child keyword (e.g.
	// `transmit-rate exact`). Accept only if a sibling supplies a valid
	// value; else fail. This is the cross-sibling rule from the plan.
	if len(values) == 1 && leafSchema.children != nil {
		if _, isMod := leafSchema.children[first]; isMod {
			if siblingSuppliesTypedValue(siblings, leafName, leafSchema, vc) {
				return nil
			}
			return typedLeafErrorf(path, "modifier %q requires a value (e.g. a sibling %s <value>)", first, leafName)
		}
	}

	// Standard typed leaf: first token is the value.
	if err := check(first); err != nil {
		return typedLeafInvalidErrorf(path, first, err)
	}
	// Remaining tokens must be known child-keyword modifiers (e.g. `exact`).
	for _, tok := range values[1:] {
		if leafSchema.children == nil {
			return typedLeafErrorf(path, "unknown modifier %q", tok)
		}
		if _, ok := leafSchema.children[tok]; !ok {
			return typedLeafErrorf(path, "unknown modifier %q", tok)
		}
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
//     (`name-server { 1.1.1.1; 8.8.8.8; }`). Only each child's FIRST
//     token is validated — the compilers read exactly that
//     (compiler_system.go name-server reads ns.Keys[0],
//     compiler_interfaces.go virtual-address reads child.Name()) and
//     the compiler-faithful contract forbids validating tokens the
//     compiler ignores.
//
// A leaf with no value in either position fails, as do dangling /
// separator-only tails (["to"], ["20000","to"]).
func validateMultiValueLeaf(node *Node, leafSchema *schemaNode, parentPath []string, vc *walkContext) error {
	leafName := node.Keys[0]
	path := append(append([]string(nil), parentPath...), leafName)
	check := leafSchema.checkValue(vc)

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
		if err := check(tok); err != nil {
			return typedLeafInvalidErrorf(path, tok, err)
		}
		validatedAny = true
		lastWasSeparator = false
	}
	if lastWasSeparator {
		return typedLeafErrorf(path, "missing value")
	}

	// Block-list children: one value per child, first token only.
	for _, c := range node.Children {
		if c == nil || len(c.Keys) == 0 {
			continue
		}
		if err := check(c.Keys[0]); err != nil {
			return typedLeafInvalidErrorf(path, c.Keys[0], err)
		}
		validatedAny = true
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
		return fmt.Errorf("%s: %v", strings.Join(path, " "), err)
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
	check := leafSchema.checkValue(vc)
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
			if check(tok) == nil {
				return true
			}
		}
	}
	return false
}

// typedLeafErrorf builds a commit-check error scoped to the leaf's
// consumed config path, e.g. "class-of-service schedulers be
// transmit-rate: missing value". path already includes the leaf keyword.
func typedLeafErrorf(path []string, format string, args ...interface{}) error {
	return fmt.Errorf("%s: %s", strings.Join(path, " "), fmt.Sprintf(format, args...))
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
func typedLeafInvalidErrorf(path []string, tok string, err error) error {
	joined := strings.Join(path, " ")
	if len(path) > 0 && isSecretLeaf(joined, path[len(path)-1:]) {
		// Redact the value INSIDE the reason rather than discarding the
		// reason. The validators echo it themselves — ValidateCryptHash says
		// "not an encrypted password hash (got %q) — plaintext is not ..." —
		// so they are a second leak site, but the sentence after the value is
		// the whole diagnostic. Dropping it told the operator only that
		// something was invalid, and TestLoginUserEncryptedPasswordSchemaGate
		// caught that: it asserts the reason still says "plaintext".
		reason := "<redacted>"
		if err != nil {
			reason = err.Error()
			if tok != "" {
				reason = strings.ReplaceAll(reason, tok, "<redacted>")
			}
		}
		return fmt.Errorf("%s: invalid value <redacted>: %s", joined, reason)
	}
	return fmt.Errorf("%s: invalid value %q: %v", joined, tok, err)
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
			return fmt.Errorf("unknown configuration stanza %q: it is not a recognised top-level keyword, "+
				"so everything configured under it would be silently discarded", kw)
		}
	}
	return nil
}
