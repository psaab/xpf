package config

import (
	"fmt"
)

// #15691 (V37-01): the DHCP pool leaves subnet / address-range / router /
// lease-time / domain-name were undeclared in dhcpLocalServerGroupSchema,
// so SetPath produced AST shapes compileDHCPLocalServer only half read:
//
//   - two-line set `address-range low <ip>` + `address-range high <ip>`
//     landed as two 3-token leaves and the packed len>=5 check dropped both;
//   - braced `address-range { low <ip>; high <ip>; }` carries the bounds as
//     child leaves, which the packed check also dropped;
//   - a compact `pool p1 subnet ... router ...;` line packed every leaf
//     onto the pool node's tail, where the children-only loop saw none of
//     them and each leaf became its own empty pool.
//
// The helpers here give the schema walk and the compiler ONE reading of an
// address-range tail, and give the compiler a resolver for the pool
// container schema so the compact tail is expanded with the same grammar
// SetPath walked.

// validateDHCPAddressRangeTail15691 validates one address-range statement
// across every spelling (leafTailValidator contract):
//
//	flat packed   tokens = [low <ip> high <ip>]  (either keyword order)
//	flat partial  tokens = [low <ip>]            (sibling supplies high)
//	child leaves  tokens = [low <ip> high <ip>]  (gatherLeafTailTokens
//	                                             flattens the braced /
//	                                             two-line child shape)
//
// A partial tail is accepted only when a sibling address-range statement
// supplies the missing bound with a valid address — the same sibling rule
// validateTypedLeaf applies to modifier-only lines. Bounds are checked
// with ValidateIPAddress; family, subnet containment and low<=high stay
// with validateDHCPPoolValuesStrict, which sees the compiled pool.
func validateDHCPAddressRangeTail15691(tokens []string, siblingTails [][]string) error {
	low, high, err := parseDHCPAddressRangeTokens15691(tokens)
	if err != nil {
		return err
	}
	if low != "" && high != "" {
		return nil
	}
	// Partial tail: merge every sibling tail; a sibling may itself be
	// partial (the two-line set spelling) or complete.
	for _, sib := range siblingTails {
		sLow, sHigh, sErr := parseDHCPAddressRangeTokens15691(sib)
		if sErr != nil {
			return sErr
		}
		if low == "" {
			low = sLow
		}
		if high == "" {
			high = sHigh
		}
	}
	if low == "" || high == "" {
		return fmt.Errorf("address-range requires both `low <address>` and `high <address>` (got low=%q high=%q)", low, high)
	}
	return nil
}

// parseDHCPAddressRangeTokens15691 extracts the low/high bounds from one
// address-range tail. Tokens must be keyword/value pairs with keywords
// `low` and `high` in either order; each bound must be a valid IP address.
func parseDHCPAddressRangeTokens15691(tokens []string) (low, high string, err error) {
	if len(tokens) == 0 {
		return "", "", fmt.Errorf("address-range requires `low <address> high <address>`")
	}
	if len(tokens)%2 != 0 {
		return "", "", fmt.Errorf("address-range %v is malformed (expected `low <address> high <address>` pairs)", tokens)
	}
	for i := 0; i < len(tokens); i += 2 {
		kw, val := tokens[i], tokens[i+1]
		if kw != "low" && kw != "high" {
			return "", "", fmt.Errorf("address-range: unexpected token %q (expected `low` or `high`)", kw)
		}
		if err := ValidateIPAddress(val, nil); err != nil {
			return "", "", fmt.Errorf("address-range %s: %v", kw, err)
		}
		if kw == "low" {
			low = val
		} else {
			high = val
		}
	}
	return low, high, nil
}

// applyDHCPAddressRange15691 folds one address-range AST node into pool.
// It reads every shape the schema admits:
//
//   - packed flat leaf: Keys = [address-range low <ip> high <ip>] in
//     either keyword order, including a packed tail still carrying the
//     next statement (only this node's pairs are consumed);
//   - partial flat leaves: Keys = [address-range low <ip>] (the two-line
//     set spelling — each call sets only its own bound, so the pair
//     accumulates across the two nodes);
//   - child leaves: `address-range { low <ip>; high <ip>; }`, where the
//     bounds are child nodes (also the shape a compact tail expansion
//     produces for a braced range).
func applyDHCPAddressRange15691(pool *DHCPPool, pp *Node) {
	if pool == nil || pp == nil {
		return
	}
	// Bounds are copied VERBATIM, not validation-gated: the strict
	// #14601 gate (validateDHCPPoolValuesStrict) must see a malformed
	// bound to refuse it, and the tolerant path warns on it. Dropping
	// an unparseable bound here would compile the pool with an empty
	// range and the gate would never fire. The pairs are consumed
	// keyword by keyword so a packed tail carrying a following
	// statement stops at the first non-bound keyword.
	toks := pp.Keys[1:]
	for i := 0; i+1 < len(toks); i += 2 {
		switch toks[i] {
		case "low":
			pool.RangeLow = toks[i+1]
		case "high":
			pool.RangeHigh = toks[i+1]
		default:
			i = len(toks) // not a bound pair: stop consuming this tail
		}
	}
	for _, c := range pp.Children {
		if c == nil || len(c.Keys) == 0 {
			continue
		}
		switch c.Keys[0] {
		case "low":
			if v := nodeVal(c); v != "" {
				pool.RangeLow = v
			}
		case "high":
			if v := nodeVal(c); v != "" {
				pool.RangeHigh = v
			}
		}
	}
}

// dhcpPoolSchema15691 resolves the live `pool` container schema under
// either DHCP local-server family, so compileDHCPLocalServer expands a
// compact pool tail with exactly the grammar SetPath and SchemaValidate
// walked. Returns nil when the schema does not resolve (expansion is then
// a no-op, matching expandRunChildren9235's nil contract).
func dhcpPoolSchema15691(isV6 bool) *schemaNode {
	server := "dhcp-local-server"
	if isV6 {
		server = "dhcpv6-local-server"
	}
	return resolveSchemaPath9235("system", "services", server, "group", "pool")
}
