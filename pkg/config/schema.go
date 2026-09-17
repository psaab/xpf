package config

// schema.go owns the config-mode `set`/`delete`/`show`/`edit` grammar
// definition — the single source of truth (SSOT) for the Junos
// configuration hierarchy. It defines the `schemaNode` container type and
// the `setSchema` literal that drives four things off one tree: structural
// completion, flat-set token grouping (SetPath, ast_edit.go), value-slot
// `?` completion (schema_complete.go), and commit-check typed-leaf
// validation (SchemaValidate, schema_walk.go). See docs/config-schema.md.
//
// This file was split out of ast.go in #1699: the AST node types and tree
// navigation (the parser's data model) stay in ast.go; the grammar SSOT
// lives here alongside the rest of the schema_* family (schema_walk.go,
// schema_validators.go, value_type.go); the procedural completion / path
// resolution helpers live in schema_complete.go.
//
// #1891 domain split: schema.go keeps the schemaNode type, the setSchema
// root composition, and the groups-wildcard init() wiring; the per-domain
// subtrees live in sibling aspect files in this package — NOT a
// subpackage, because setSchema is unexported and consumed in-package by
// schema_complete.go / schema_walk.go (two-SSOT doctrine, #1319):
//
//	schema_security.go    security, applications
//	schema_interfaces.go  interfaces (+ tunnel/wireguard constructors)
//	schema_routing.go     routing-options, policy-options, protocols,
//	                      forwarding-options, bridge-domains,
//	                      routing-instances
//	schema_system.go      system, services, snmp, event-options
//	schema_chassis.go     chassis
//	schema_cos.go         class-of-service, firewall

// schemaNode defines a container keyword in the Junos config hierarchy.
// It tells SetPath how to group flat path tokens into the correct tree structure.
type schemaNode struct {
	args     int                    // extra tokens consumed as part of this node's key
	children map[string]*schemaNode // known container children
	wildcard *schemaNode            // matches any keyword not in children (for dynamic names)
	multi    bool                   // true = multiple leaf values allowed (e.g. source-address); false = replace on set
	// valueList opts a multi leaf that ALSO declares modifier children into
	// bracket-list value absorption (#3872 static `next-hop [ a b ]`). By
	// default the SetPath absorber only collapses a trailing value list onto a
	// multi leaf when children == nil (ast_edit.go); a multi leaf WITH children
	// (e.g. the CoS named containers) stays a container. valueList lets such a
	// node absorb trailing tokens that are neither a sibling NOR a known child
	// (the bracket list) while STILL descending into the container when the
	// next token names a known child (the `interface` modifier). Only next-hop
	// sets it; every other multi+children node is unchanged.
	valueList bool

	// packedTail opts a CONTAINER into having its packed tail VALIDATED
	// (#6821).
	//
	// The gate's default for a container is to IGNORE tokens packed past the
	// identity, and that default is not laziness — it is a compiler-faithful
	// contract (see the long note in schema_walk.go). The gate must not
	// validate what no compiler reads, or a stray token becomes a commit
	// error for a configuration that behaves identically with or without it.
	//
	// The contract is BIDIRECTIONAL, and that is the half #6821 turns on: the
	// moment a compiler DOES read a container's packed tail, ignoring it here
	// turns "not compiled" into "compiled, UNVALIDATED". Measured on
	// `security log stream <s> transport` before this flag existed:
	//
	//	transport { protocol tpc; }   gate REJECTS (enum)
	//	transport protocol tpc;       gate ACCEPTS  <- the hole
	//
	// So this flag is the explicit pairing. Setting it says "a compiler reads
	// this container's packed tail", and the walker then validates the same
	// expansion `packedBodyChildren` hands that compiler — one schema fact
	// instead of two files agreeing by comment.
	// TestPackedTailContainersValidateBothSpellings6821 holds the pairing.
	packedTail bool

	// packedStatements opts a CONTAINER into having its packed tail split into
	// one child per STATEMENT by the brace-elision fold (#8768), instead of the
	// whole run becoming a single child.
	//
	// It is OPT-IN and defaults off, for two measured reasons.
	//
	// Splitting changes what a packed run lowers to, and at least one container
	// has a gate that depends on the current lowering: the NAT `then` family
	// rejects a packed cross-mode contradiction with a check that exists
	// PRECISELY BECAUSE `pool <p> off` lowers to one action and cannot be
	// counted (#7033). Two earlier attempts to fix that class in the lowering
	// were reverted; splitting `source-nat` would be a third.
	//
	// And splitting is only possible where the schema models the tail. The fold
	// consumes each statement with consumeNodeKeys and stops the moment a token
	// leaves the modelled grammar, so a container whose leaves take values the
	// schema does not describe cannot be split even if it opts in — `ike policy
	// <p> pre-shared-key ascii-text <v> mode main` is one: `ascii-text` is not
	// modelled, so the tail is returned whole and `mode main` stays swallowed.
	//
	// So a container opts in after someone measures that its packed and braced
	// spellings compile identically once split, one container at a time. That
	// is the same discipline the #8690 scope list arrived at.
	packedStatements bool

	// blockValue opts a single-value typed leaf into the HIERARCHICAL BLOCK
	// spelling `keyword { value; }`, in addition to the ordinary
	// `keyword value` (#6774).
	//
	// This is an OPT-IN, not a general relaxation, because the two spellings
	// are not interchangeable in Junos. `default-policy` is a CHOICE
	// CONTAINER in the Junos schema — `permit-all` / `deny-all` /
	// `reject-all` are alternative sub-statements, which is why Junos itself
	// DISPLAYS it as `default-policy { deny-all; }` — while this schema
	// models it as a valued leaf so the flat-set spelling works. The compiler
	// accommodates both deliberately (compiler_security_policy.go). Without
	// the opt-in the strict commit path rejects a configuration that is
	// canonical Junos, that the compiler compiles correctly, and that the
	// tolerated Load/SyncApply path already applies.
	//
	// Most typed leaves must NOT set this. `mtu { 1500; }` is not Junos, and
	// the rejection there is correct; the compiler tolerates it only
	// incidentally, through the generic nodeVal helper. A census of setSchema
	// found 42 distinct leaves where the compiler accepts a block form the
	// schema rejects, and `default-policy` is the only one where the block
	// form is the shape Junos actually emits.
	blockValue bool

	// groupReplace opts a multi leaf OUT of apply-groups leaf-list UNION
	// (#4070). By default a `multi:true && children==nil && args<=1` leaf is a
	// pure single-token value-list whose group + inline members UNION under
	// apply-groups (name-server, match application/source-address, from
	// protocol, export chains). A multi leaf that instead packs a SEPARATOR or
	// OPERATION keyword onto its value list — a port RANGE (`3000 to 4000`
	// packs `to`), `then community add|delete|set|none <value>`, or
	// `then as-path-prepend` (order + repetition are the mechanism) — is NOT a
	// set: token-level union/dedup would corrupt it (a discard/reject port term
	// would fail OPEN). Setting groupReplace makes such a leaf REVERT to the
	// safe pre-#4070 OVERRIDE (inline wins, group value dropped). Multi leaves
	// with args>=2 (route-filter, address-book `address <name> <prefix>`,
	// as-path `<name> <regex>`, CoS `queue`) are multi-token by nature and are
	// excluded by the args<=1 gate in isLeafListSchema without a flag.
	groupReplace bool
	//
	// THE DECIDING QUESTION, stated because it is now load-bearing in two
	// places and the next person will not re-derive it: is this leaf a PURE
	// SINGLE-TOKEN VALUE LIST, or does it PACK A SEPARATOR onto its values?
	//
	//   pure list  -- `application-set <s> application [ a b c ]` (#8825).
	//                 Every token is a member and order carries no meaning, so
	//                 group+inline UNION is exactly right and this flag must
	//                 NOT be set. Setting it would silently drop an inherited
	//                 member.
	//   packs one  -- `nat source pool <p> address <lo> to <hi>` and the
	//                 destination pool address, which carries `port <n>` on the
	//                 same statement (#8816, #8817). Token-level union splices
	//                 two statements and corrupts the value: inheriting
	//                 `address 10.0.0.2/32 port 8080;` over an inline
	//                 `address 10.0.0.1/32 port 80;` compiled the ADDRESS as
	//                 "8080". This flag is required there.
	//
	// Both were measured rather than reasoned about, and getting it backwards
	// is silent in both directions -- a dropped inherited member, or a spliced
	// value that still looks like a value.

	// rangeSeparator opts a `multi && children == nil` typed leaf in to
	// treating the fixed mid-token `to` as a RANGE separator in
	// validateMultiValueLeaf (`<a> to <b>`), rather than validating it as
	// an ordinary value token (#4556 L-01). The `to` separator is only
	// meaningful for a leaf whose value domain is a numeric range —
	// port-range and NAT-pool-address. Those production leaves are
	// COMPILER-validated (no schema validator), so they never reach
	// validateMultiValueLeaf; every typed multi leaf that DOES reach it
	// today is an IP/CIDR (name-server, virtual-address,
	// dns-server-address) or session-log-flag leaf where `to` is never a
	// valid member. Leaving this false on those leaves makes a literal
	// `to` fail validation with a clear "invalid value" message instead
	// of being silently skipped as a separator. Only the white-box walker
	// test's synthetic port-range leaf sets it today.
	rangeSeparator bool

	scalar       bool      // true = fixed-arity scalar value leaf (keyword + exactly `args` value tokens, NO body); rejects trailing tokens at commit (#3332). Opt-in; see isScalarValueLeaf.
	valueHint    ValueHint // hint for dynamic value completion (when args > 0)
	desc         string    // description shown in completion help
	placeholder  string    // Junos-style placeholder (e.g., "<interface-name>")
	midKeyword   string    // fixed keyword in the middle of args (e.g., "to-zone")
	midKeywordAt int       // 1-based arg position where midKeyword appears (e.g., 2 for "from-zone X to-zone Y")
	compoundKey  bool      // children form compound key (e.g., "family inet6" → Keys=["family","inet6"])

	// closedWorld opts this subtree in to closed-world validation: when
	// true, an unmodeled child keyword under this subtree is REJECTED at
	// strict commit instead of silently dropped (opt-in per subtree,
	// #4313). The default (false) preserves the legacy opt-in behaviour —
	// SchemaValidate leaves unmodeled keywords to the compiler and never
	// rejects them, so a leaf the schema does not model commits clean and
	// is silently discarded. Flipping this on a subtree is only safe once
	// that subtree is LEAF-COMPLETE (every valid Junos keyword under it is
	// modeled), otherwise it false-rejects a valid-but-not-yet-modeled
	// config. The flag is threaded down the walker (walkSchemaNode's
	// `closed` param): once a subtree sets it, every descendant level
	// inherits closed-world enforcement.
	//
	// Production subtrees DO set this — it is not an inert mechanism, and
	// this comment used to say otherwise. Do not deduce the armed set from
	// prose that rots; find it with
	//
	//	git grep -n 'closedWorld: true' -- 'pkg/config/schema_*.go'
	//
	// The `schema_*.go` glob is deliberate: it excludes THIS file, so the
	// command does not match the line you are reading. Dropping it returns
	// one extra hit — this comment — and a reader counting results would be
	// off by one against any number stated elsewhere.
	//
	// The armed set is deliberately NOT enumerated here for the same reason
	// walkSchemaNode declines to state a count: a list in a comment drifts
	// away from the flags it describes, and the next reader trusts the list.
	// Remaining flips stay gated on a per-subtree leaf-completeness audit
	// (see docs/config-schema.md); each is driven per-domain, not as a
	// blanket change — a blanket flip would break the deliberate
	// accept-with-advisory knobs (#2078/#4231).
	closedWorld bool

	// Typed-leaf metadata (#1319). The zero value (valueType==ValueAny,
	// validator==nil) is the legacy behaviour: any string accepted, no
	// schema-time validation, no value-slot examples in `?` completion.
	// Setting valueType to a non-ValueAny value opts this leaf in to both
	// the completion path (CompleteSetPathWithValues surfaces valueDesc +
	// valueExamples + the placeholder) and the validation path
	// (SchemaValidate invokes validator at commit-check time). Because the
	// completion path and the validation path read the SAME node, the two
	// cannot drift — that is the central design property of Option A.
	//
	// IMPORTANT: adding these fields is additive and does not affect
	// SetPath grouping, which keys only on args/children/compoundKey/multi
	// (ast_edit.go). A schemaNode MUST NOT gain a children map purely to
	// carry typed-leaf metadata: SetPath's replace-vs-container decision
	// keys on children==nil (ast_edit.go:196), so flipping a leaf to a
	// container is a grouping regression. Type the value via these fields,
	// not via new children.
	valueType     ValueType     // non-ValueAny marks a typed value slot
	valueDesc     string        // one-line value-slot description for `?` help
	valueExamples []string      // illustrative values surfaced in `?` help
	validator     LeafValidator // commit-check validator for the value slot

	// treeValidator is the TREE-based cross-reference alternative to
	// validator (#1319 PR 3): it validates the value against
	// definitions collected from the candidate tree itself
	// (collectSchemaRefs → schemaRefs), because SchemaValidate's cfg is
	// always nil in production — validation runs BEFORE compile. A
	// typed leaf sets EITHER validator OR treeValidator, never both.
	treeValidator treeLeafValidator
	// nodeValidator validates a leaf's complete AST node when a grammar needs
	// provenance (for example, a bracketed list or a hierarchical block) that
	// leafTailValidator's flattened token slice cannot retain. It runs only on
	// an exact schema-key match and is also reused by routing-instance's
	// closed-world prewalk (#9736).
	nodeValidator leafNodeValidator

	// tailValidator, when non-nil, validates the ENTIRE value/modifier tail
	// of a leaf as a unit instead of token-by-token (#4228 Gap 2). It exists
	// for irregular Junos grammars whose tail is heterogeneous and cannot be
	// checked by the standard typed-leaf path — CoS `transmit-rate (rate |
	// percent <n> | remainder) [exact]` and `shaping-rate (rate | percent
	// <n>)`, where the first token is EITHER a value (10m) or a keyword
	// (percent/remainder). walkSchemaNode dispatches such a leaf to
	// validateTailLeaf, which gathers every tail token (Keys[1:] plus any
	// hierarchical child-leaf tokens, since flat-set groups `percent 90` as a
	// container + child) and hands the flattened slice — with the same-keyword
	// sibling tails, so a split-set modifier-only line (`transmit-rate exact`
	// beside `transmit-rate 1g`) is still accepted — to this function.
	// valueType/valueExamples may still be set for `?` completion; validator
	// MUST be nil so the tail path owns acceptance.
	tailValidator leafTailValidator

	// Typed KEY slot (#1319 PR 3). A named-instance CONTAINER (args > 0
	// with a children map, e.g. `family inet address <cidr> { primary; }`)
	// carries its value in the IDENTITY token, not in a leaf value slot —
	// the walker consumes identity tokens without validation by default
	// (the compiler-faithful contract from PR 2). Setting keyValidator
	// opts the identity arg token(s) in to commit-check validation, and
	// keyValueType/keyValueDesc/keyValueExamples surface in `?` completion
	// for the empty key slot. The regular valueType/validator fields MUST
	// stay unset on such a node: setting valueType would flip the walker
	// into the typed-LEAF branch, which treats children as modifiers and
	// would mis-validate the container's real block children. Not
	// supported on midKeyword nodes (no current need).
	keyValueType     ValueType     // non-ValueAny marks a typed identity-arg slot
	keyValueDesc     string        // one-line key-slot description for `?` help
	keyValueExamples []string      // illustrative key values surfaced in `?` help
	keyValidator     LeafValidator // commit-check validator for identity arg tokens

	// keyValidatorPos is the POSITION-AWARE alternative to keyValidator
	// (#5576). When set, the walker validates each identity arg token with
	// its 0-based arg index instead of the position-AGNOSTIC keyValidator,
	// so a multi-arg key slot (args >= 2) can enforce a DISTINCT grammar
	// per position. A node sets EITHER keyValidator OR keyValidatorPos,
	// never both. route-filter (`from route-filter <prefix> <match-type>`,
	// args:2) uses it: arg 0 (the prefix slot) must be a CIDR and arg 1
	// (the match-type slot) must be a supported match-type keyword. The
	// prior position-agnostic keyValidator accepted the union of CIDRs and
	// match-type keywords in EITHER slot, so `route-filter longer exact`
	// committed with the match keyword `longer` in the CIDR slot; the FRR
	// renderer's malformed-prefix belt then emitted no prefix-list entry
	// but kept the route-map match reference, turning an authored accept
	// into an operational match-none (a silent false-deny).
	keyValidatorPos PositionalKeyValidator
}

// isTypedLeaf reports whether the node carries typed-value metadata
// (a non-default valueType), i.e. it expects exactly one typed value at
// its first non-modifier slot.
func (n *schemaNode) isTypedLeaf() bool {
	return n != nil && n.valueType != ValueAny
}

// isScalarValueLeaf reports whether the node is a fixed-arity scalar value
// leaf: a keyword that consumes EXACTLY `args` value token(s), models no
// sub-structure, and whose schema node is explicitly tagged `scalar: true`
// (#3332). For such a leaf the compiler reads only Keys[1:1+args]; any token
// or AST child beyond that span is operator garbage the schema walk must
// reject rather than silently drop (the flat-set trailing-token leakage the
// screen subset, #3411, fixed only for the screen subtree).
//
// Why an EXPLICIT `scalar` opt-in rather than structural inference? An
// `args > 0, children: nil` node is NOT reliably a value leaf: several are
// deliberately-OPAQUE CONTAINERS whose body is left to the compiler and
// parsed off the node's AST children (`applications application-set <name> {
// application <member>; }`, `applications application <name> { ... }`,
// `system syslog file <name> { ... }`). Their legitimate body lands on
// Keys/Children exactly like a typo would, so a structural gate would
// false-reject real config. The `scalar` tag is asserted only on leaves
// audited to take a fixed value and NO body — the marker is the design pass
// the #3332 body called for, and the gate is additive per-leaf.
//
// The structural guards below are belt-and-braces: a `scalar` tag is only
// honored on a leaf that is genuinely fixed-arity and bodyless, so a future
// mis-tag on a multi/typed/container node degrades to a no-op rather than a
// surprise rejection.
//
//   - multi (bracketed lists / value tails, #2419): a multi leaf absorbs
//     every trailing value onto its Keys by design — exempt.
//   - children != nil / wildcard != nil (named-instance / modifier
//     containers, e.g. `address <cidr> { primary; }`): the trailing tokens
//     are real sub-structure the container path validates — exempt.
//   - compoundKey / midKeyword: the trailing token is part of the node key
//     (`family inet6`, `from-zone X to-zone Y`) — exempt.
//   - isTypedLeaf: validateTypedLeaf already rejects unknown trailing
//     tokens AND unexpected children, so the typed path owns the arity check.
//   - args == 0: ambiguous between a presence-only flag (`dhcp`) and an
//     opaque leaf whose subtree the compiler reads (`tcp-mss <mode>
//     <value>`, #1979); the screen flag subset is handled by #3411.
func (n *schemaNode) isScalarValueLeaf() bool {
	return n != nil &&
		n.scalar &&
		n.args > 0 &&
		n.children == nil &&
		n.wildcard == nil &&
		!n.multi &&
		!n.compoundKey &&
		n.midKeyword == "" &&
		!n.isTypedLeaf()
}

// setSchema defines the Junos configuration tree structure.
// Keywords present in the schema at a given depth are treated as containers.
// Keywords NOT in the schema become leaf nodes (all remaining tokens form the leaf's Keys).
var setSchema = &schemaNode{children: map[string]*schemaNode{
	"groups":             {desc: "Configuration groups", wildcard: &schemaNode{desc: "Group name", placeholder: "<group-name>"}}, // wildcard children set in init()
	"apply-groups":       {desc: "Groups from which to inherit configuration data", args: 1, multi: true, placeholder: "<group-name>", children: nil},
	"security":           schemaSecurity,
	"schedulers":         schemaSchedulers,
	"interfaces":         schemaInterfaces,
	"applications":       schemaApplications,
	"routing-options":    schemaRoutingOptions,
	"snmp":               schemaSNMP,
	"policy-options":     schemaPolicyOptions,
	"protocols":          schemaProtocols,
	"event-options":      schemaEventOptions,
	"chassis":            schemaChassis,
	"class-of-service":   schemaClassOfService,
	"firewall":           schemaFirewall,
	"system":             schemaSystem,
	"services":           schemaServices,
	"forwarding-options": schemaForwardingOptions,
	"bridge-domains":     schemaBridgeDomains,
	"routing-instances":  schemaRoutingInstances,
}}

func init() {
	// Wire groups wildcard to mirror top-level schema children.
	// This allows "set groups <name> security ..." etc. to parse correctly.
	groupWild := setSchema.children["groups"].wildcard
	groupWild.children = make(map[string]*schemaNode)
	for k, v := range setSchema.children {
		if k == "groups" || k == "apply-groups" {
			continue
		}
		groupWild.children[k] = v
	}
}
