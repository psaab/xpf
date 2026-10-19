package config

import (
	"fmt"
	"strings"
)

// #15257 (A88-03, #14343 family): the RA caller of
// bracketedGroupInstances8794 fans out every Keys[1:] token of a braced
// `interface` node as an interface name. For the mixed spelling
//
//	protocols { router-advertisement { interface ge-0/0/0 managed-configuration default-lifetime 0 { prefix 2001:db8::/64; } } }
//
// the parser gives Keys=[interface ge-0/0/0 managed-configuration
// default-lifetime 0] with Children=[prefix ...]. That is a packed header
// (an RA-interface child keyword tail beside a braced body), not a bracketed
// group, but bracketedGroupInstances8794 cannot tell the two apart and
// mints phantom RA entries named `managed-configuration`, `default-lifetime`
// and `0` — each sharing the real body, so pkg/daemon keys RA senders for
// nonexistent interfaces. The real interface happens to compile correctly
// (packedBodyChildren expands the tail for Keys[1]'s entry), which made the
// phantoms silent config-integrity noise on a strict-clean commit.
//
// This mirrors zoneUnbracketedHeaderToken14343 for the RA slot: an
// unbracketed Keys[2:] token that is a declared RA-interface child keyword
// is a header token, not an interface name. Bracketed members keep their
// names even when they collide, and the bracket-stripped form Format emits
// for `interface [ a b ] { ... }` (bare interface names as Keys[1:]) keeps
// fanning out, because real interface names are not RA child keywords.
//
// Strict commit refuses; the tolerant load / peer-sync paths warn and
// compile as before so a persisted configuration still boots (#1960).
func validateRAInterfacePackedHeaders15257(nodes []*Node, lenient bool) ([]string, error) {
	var warnings []string
	for _, top := range nodes {
		if top == nil || len(top.Keys) != 1 || top.Keys[0] != "protocols" {
			continue
		}
		for _, ra := range top.Children {
			if ra == nil || len(ra.Keys) != 1 || ra.Keys[0] != "router-advertisement" {
				continue
			}
			for _, ch := range ra.Children {
				if ch == nil || len(ch.Keys) < 3 || ch.Keys[0] != "interface" || len(ch.Children) == 0 {
					continue
				}
				msg := raUnbracketedHeaderToken15257(ch)
				if msg == "" {
					continue
				}
				if !lenient {
					return nil, fmt.Errorf("%s", msg)
				}
				warnings = append(warnings, msg)
			}
		}
	}
	return warnings, nil
}

// raUnbracketedHeaderToken15257 reports a braced RA `interface` header whose
// unbracketed tail token is a declared RA-interface child rather than an
// interface name, or "" when the header is a legitimate group.
//
// Every Keys[2:] token of a legitimate group is an interface name, so any
// unbracketed token colliding with a declared RA-interface child keyword
// marks the header as packed. Direct children-map lookup, NOT
// resolveSchemaChild: the latter falls back to the wildcard (the
// interface-name slot itself), which would resolve every name as a "child".
// Bracketed members keep their names even when they collide.
func raUnbracketedHeaderToken15257(ch *Node) string {
	if ch == nil || len(ch.Keys) < 3 || len(ch.Children) == 0 {
		return ""
	}
	ifaceSchema := raInterfaceSchema8939()
	if ifaceSchema == nil {
		return ""
	}
	for i := 2; i < len(ch.Keys); i++ {
		if ch.KeyBracketed(i) {
			continue
		}
		tok := ch.Keys[i]
		if _, isChild := ifaceSchema.children[tok]; isChild {
			return fmt.Sprintf("protocols router-advertisement interface %s: header token %q is a router-advertisement interface child keyword, not an interface name, so it must not fan out phantom RA interfaces or carry the braced body. Write interface %s { %s ...; } inside the interface body, interface [ a b ] { ... } for an interface group, or each interface as its own statement (#15257)",
				ch.Keys[1], tok, ch.Keys[1], strings.Join(ch.Keys[2:], " "))
		}
	}
	return ""
}
