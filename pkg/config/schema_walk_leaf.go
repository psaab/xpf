package config

import (
	"strings"
)

// validateKeySlot runs a named-instance container's identity-arg
// validator on one token. It prefers the POSITION-AWARE keyValidatorPos
// (#5576) — passing argIdx, the token's 0-based position within the
// node's declared arg span — and falls back to the position-agnostic
// keyValidator when only that is set. A node sets at most one of the two;
// callers invoke this only when at least one is non-nil.
func validateKeySlot(schema *schemaNode, argIdx int, tok string, vc *walkContext) error {
	if !schema.allowEdgeWhitespace {
		if err := refuseEdgeWhitespace(tok); err != nil {
			return err
		}
	}
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
		// #16679: `multihop ttl 2` packed onto ONE node (the hierarchical
		// lexer packs the whole statement) — the modifier-headed arm below
		// would refuse it as a missing leaf value, but for multihop the
		// `ttl` modifier IS the value carrier: Junos spells the pinned
		// TTL only that way (or blocked). Accept exactly `ttl <v>` (plus
		// a trailing refused-by-nodeValidator `no-nexthop-change`, which
		// never reaches here), validating <v> against the modifier's own
		// validator. Anything longer is a packed run the compiler
		// expansions own, and stays refused here.
		if leafName == "multihop" && first == "ttl" {
			modSchema := leafSchema.children["ttl"]
			// Flat-set child shape: `multihop ttl` with the value as
			// a CHILD node (SetPath grouped only `ttl`); the sibling
			// supplying the leaf VALUE is the value child itself,
			// already range-checked by validateBGPMultihop16679.
			if len(values) == 1 && len(node.Children) == 1 && len(node.Children[0].Keys) == 1 {
				if modSchema != nil {
					if err := modSchema.checkToken(vc, node.Children[0].Keys[0]); err != nil {
						return typedLeafInvalidErrorf(append(append([]string(nil), path...), "ttl"), node.Children[0].Keys[0], err)
					}
				}
				return nil
			}
			if len(values) == 2 && modSchema != nil {
				if err := modSchema.checkToken(vc, values[1]); err != nil {
					return typedLeafInvalidErrorf(append(append([]string(nil), path...), "ttl"), values[1], err)
				}
				return nil
			}
			// Packed run (hierarchical `neighbor ... multihop ttl 7
			// passive`): the `ttl` value rides this node and the run
			// continues with sibling statements the compiler
			// expansions split. Accept when a valid TTL follows;
			// the remaining tokens are validated where the expansion
			// lands them.
			if len(values) > 2 && modSchema != nil {
				if err := modSchema.checkToken(vc, values[1]); err == nil {
					return nil
				}
				return typedLeafInvalidErrorf(append(append([]string(nil), path...), "ttl"), values[1], modSchema.checkToken(vc, values[1]))
			}
			if len(values) == 1 {
				return typedLeafErrorf(path, "modifier %q requires a value", first)
			}
			return typedLeafErrorf(path, "missing value")
		}
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
//     (`name-server { 1.1.1.1; 8.8.8.8; }`).
//
// #16535: the parser also admits a SIXTH spelling — one block child
// carrying several tokens (`leaf { v1 v2; }`, child Keys=[v1 v2]).
// Junos writes one value per statement inside a block, so the walker
// REFUSES a multi-token block child rather than guessing which tokens
// the compiler will use: compilers legitimately differ there (some
// read every child key, some read Names/[Keys[0]] only), so validating
// every token would bless a spelling whose second value is silently
// dropped, and validating only the first lets a rejected second value
// escape into compilers that read every key. One refusal covers both
// directions. Leaves whose compiler reads every child key opt in via
// allChildKeysAreValues; there every token IS a value, so every token
// is validated and nothing is refused.
//
// A leaf with no value in either position fails, as do dangling /
// separator-only tails (["to"], ["20000","to"]).
func validateMultiValueLeaf(node *Node, leafSchema *schemaNode, parentPath []string, vc *walkContext) error {
	leafName := node.Keys[0]
	path := append(append([]string(nil), parentPath...), leafName)

	validatedAny := false
	attemptedAny := false
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
				err := typedLeafErrorf(path, "missing value")
				if vc.recordTypedLeaf(err) {
					continue
				}
				return err
			}
			lastWasSeparator = true
			continue
		}
		attemptedAny = true
		if err := leafSchema.checkToken(vc, tok); err != nil {
			verr := typedLeafInvalidErrorf(path, tok, err)
			if vc.recordTypedLeaf(verr) {
				continue
			}
			return verr
		}
		validatedAny = true
		lastWasSeparator = false
	}
	if lastWasSeparator {
		err := typedLeafErrorf(path, "missing value")
		if !vc.recordTypedLeaf(err) {
			return err
		}
	}

	// Block-list children (#16535): one value per statement. A
	// multi-token child is refused unless the leaf opts in via
	// allChildKeysAreValues, in which case every token is validated
	// (and compiled — see firewallMatchValues / the opt-in readers).
	for _, c := range node.Children {
		if c == nil || len(c.Keys) == 0 {
			continue
		}
		// Multi-value readers consume child Keys but never recurse into the
		// child's Children. Refuse both non-empty and empty child blocks so
		// the gate cannot accept content that compilation silently drops.
		if leafSchema.refuseNonLeafBlockChildren && (len(c.Children) > 0 || !c.IsLeaf) {
			err := nestedMultiValueContentErrorf(path, leafName, c.Keys[0])
			if vc.recordTypedLeaf(err) {
				continue
			}
			return err
		}
		if len(c.Keys) > 1 && !leafSchema.allChildKeysAreValues {
			err := typedLeafErrorf(path, "only one value per statement inside a value block; write %q as separate statements (%s { %s; %s; }) or a bracket list (%s [ %s %s ])", strings.Join(c.Keys, " "), leafName, c.Keys[0], c.Keys[1], leafName, c.Keys[0], c.Keys[1])
			if vc.recordTypedLeaf(err) {
				continue
			}
			return err
		}
		keys := c.Keys[:1]
		if leafSchema.allChildKeysAreValues {
			keys = c.Keys
		}
		for _, tok := range keys {
			attemptedAny = true
			// #18049: a leaf with blockChildValidator validates block-list
			// children with it instead of the packed validator (VRRP
			// virtual-address: packed bare Junos form accepts, block-list
			// bare rejects with the CIDR diagnostic). Leaves without it
			// keep checkToken (validator/treeValidator) for every token.
			var err error
			if leafSchema.blockChildValidator != nil {
				if !leafSchema.allowEdgeWhitespace {
					err = refuseEdgeWhitespace(tok)
				}
				if err == nil {
					err = leafSchema.blockChildValidator(tok)
				}
			} else {
				err = leafSchema.checkToken(vc, tok)
			}
			if err != nil {
				verr := typedLeafInvalidErrorf(path, tok, err)
				if vc.recordTypedLeaf(verr) {
					continue
				}
				return verr
			}
			validatedAny = true
		}
	}

	if !validatedAny && !attemptedAny {
		err := typedLeafErrorf(path, "missing value")
		if vc.recordTypedLeaf(err) {
			return nil
		}
		return err
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
	// #17177: tail validators own their whole tail, so the central
	// checkToken gate never sees these tokens. Apply the same
	// edge-whitespace refusal here before the tail validator runs.
	if !leafSchema.allowEdgeWhitespace {
		for _, tok := range tokens {
			if err := refuseEdgeWhitespace(tok); err != nil {
				return typedLeafInvalidErrorf(path, tok, err)
			}
		}
		for _, s := range siblings {
			if s == nil || s == node || len(s.Keys) == 0 || s.Keys[0] != leafName {
				continue
			}
			for _, tok := range gatherLeafTailTokens(s) {
				if err := refuseEdgeWhitespace(tok); err != nil {
					return typedLeafInvalidErrorf(path, tok, err)
				}
			}
		}
	}
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
