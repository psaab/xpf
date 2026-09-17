package config

import (
	"fmt"
	"sort"
	"strconv"
)

// MinRethRedundancyGroupID is the smallest redundancy-group id a RETH
// interface may carry. Group 0 is the chassis-cluster CONTROL-PLANE group in
// Junos (the Routing Engine group); data-plane RETH interfaces are assigned to
// group 1 and up. A reth carrying group 0 is therefore not "RG 0" — it is a
// reth with no usable data-plane group, and every downstream consumer reads it
// as "not RG-scoped" (see validateRethRedundancyGroupTokensAST).
const MinRethRedundancyGroupID = 1

// MaxRethRedundancyGroupOctet is the largest redundancy-group id that still
// yields a well-formed RETH link-local base address. pkg/dataplane
// compiler_iface.go substitutes the VIP addresses of a VRRP-backed RETH with
// `169.254.<redundancy-group>.<node+1>/32`, so the id occupies the THIRD OCTET
// of an IPv4 address and cannot exceed 255. It is also the ceiling the chassis
// redundancy-group id gate already enforces on the group declarations
// themselves (MaxHeartbeatRedundancyGroupID), so no id above it can ever name
// a declared group.
//
// This is a DIFFERENT and looser bound than MaxRethRedundancyGroupID (155),
// which exists for the RFC 5798 VRID range and is enforced by
// validateRethVRRPGroupIDStrict ONLY when a reth-derived VRRP instance is
// actually synthesized. That gate deliberately returns early under
// `no-reth-vrrp` / `private-rg-election` (the DEFAULT), where no VRID is
// derived — but the link-local substitution above is NOT mode-gated, so the
// octet ceiling has to be enforced independently of the VRRP mode. The two
// compose: in a VRRP mode the stricter 155 applies, otherwise this 255 does.
const MaxRethRedundancyGroupOctet = MaxHeartbeatRedundancyGroupID

// validateRethRedundancyGroupTokensAST rejects, at commit / commit-check, an
// `interfaces <name> redundant-ether-options redundancy-group <id>` whose raw
// token is PRESENT but does not denote a usable data-plane redundancy group
// (#6782).
//
// The fail-open this closes: compileInterfaces reads the token with
// `if v, err := strconv.Atoi(...); err == nil { ifc.RedundancyGroup = v }`, so a
// non-numeric token leaves the field at its 0 default and a NEGATIVE token is
// stored verbatim. Every downstream consumer decides "is this a RETH?" with
// `RedundancyGroup > 0` — pkg/dataplane compiler_iface.go sets both `isReth`
// and `isVRRPReth` that way. With a non-positive group the interface is
// therefore treated as an ORDINARY interface: the `169.254.RG.NODE/32`
// link-local substitution does not fire, and the reth's real service address is
// written onto the physical device with `KeepAddresses:false`. Both nodes run
// the same synced config, so BOTH nodes configure that address — a
// duplicate-address / split-brain condition on the data path, from a config
// that commits without a word of complaint.
//
// Why the AST and not the compiled *Config: by the time the typed
// InterfaceConfig exists, a malformed token has already collapsed to 0 and is
// indistinguishable from a reth that simply has no redundant-ether-options
// stanza at all. Only the raw AST can tell "the operator wrote something and we
// could not use it" from "the operator wrote nothing". This is the same
// raw-AST pre-walk principle used by validateChassisClusterIdentitiesAST
// (#5694), although the chassis identity compiler now drops non-numeric
// identities instead of retaining its old zero coercion.
//
// Scope — deliberately NOT extended, each measured rather than assumed:
//
//   - A reth with NO redundant-ether-options stanza is not flagged. That is an
//     ABSENT token, not an invalid one, and several in-tree configs legitimately
//     touch a reth without redeclaring its group as a partial/overlay fragment
//     (test/incus/sqm-cookbook-config.set even sets an address that way).
//     Requiring presence is a separate policy question with a real
//     over-rejection surface.
//   - A positive id that names no DECLARED `chassis cluster redundancy-group`
//     is not flagged. It does not trigger this fail-open at all — it still reads
//     as RG-scoped and still takes the link-local substitution — so rejecting it
//     would be a new restriction rather than a fix for the reported failure.
//   - The 1..155 VRID ceiling stays owned by validateRethVRRPGroupIDStrict,
//     which is correctly scoped to the modes that actually derive a VRID.
//
// Strict (commit / commit-check): the first offending token hard-rejects, naming
// the interface and the token. Lenient (load / peer-sync): warn, so an
// already-persisted or peer-synced config an older binary silently accepted
// still BOOTS (#1960) — compileInterfaces then SUPPRESSES that reth's unit
// addresses so the tolerant path cannot do the very thing this gate exists to
// prevent, namely configure the address on both nodes.
func validateRethRedundancyGroupTokensAST(nodes []*Node, lenient bool) ([]string, error) {
	var warnings []string
	// Deterministic order so the first-error commit message is stable across
	// map-ordered runs, matching the sibling AST gates.
	type offence struct{ iface, token, why string }
	var found []offence
	// The descent mirrors compileInterfaces EXACTLY — the "interfaces" section
	// node, its interface children, then FindChild + nodeVal for the two levels
	// below. Binding to the same reads is what keeps the gate and the compiler
	// from disagreeing about which token is in play across the dual
	// hierarchical / flat-set AST shapes.
	err := forEachChild(nodes, "interfaces", func(ifacesNode *Node) error {
		for _, ifNode := range ifacesNode.Children {
			name := ifNode.Name()
			if name == "" {
				continue
			}
			reo := ifNode.FindChild("redundant-ether-options")
			if reo == nil {
				continue
			}
			rg := reo.FindChild("redundancy-group")
			if rg == nil {
				continue
			}
			tok := nodeVal(rg)
			if why, bad := rethRGTokenProblem(tok); bad {
				found = append(found, offence{iface: name, token: tok, why: why})
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(found, func(i, j int) bool { return found[i].iface < found[j].iface })
	for _, o := range found {
		msg := fmt.Sprintf(
			"interface %s redundant-ether-options redundancy-group %q %s; a "+
				"redundancy-group that is not a usable data-plane group leaves the "+
				"interface reading as NON-redundant everywhere downstream "+
				"(isReth/isVRRPReth are both `redundancy-group > 0`), so its "+
				"service address is written as an ordinary static address — and "+
				"because both nodes share the synced configuration, BOTH nodes "+
				"configure it. Use a group in %d..%d (#6782)",
			o.iface, o.token, o.why,
			MinRethRedundancyGroupID, MaxRethRedundancyGroupOctet)
		if !lenient {
			return nil, fmt.Errorf("%s", msg)
		}
		warnings = append(warnings, msg)
	}
	return warnings, nil
}

// rethRGTokenProblem classifies a raw redundancy-group token, returning a
// human-readable reason and whether it is unusable. It mirrors
// compileInterfaces' Atoi-then-default read exactly: whatever Atoi accepts is
// what the compiler stores, so anything Atoi rejects has silently become 0.
func rethRGTokenProblem(tok string) (string, bool) {
	if tok == "" {
		return "is empty", true
	}
	n, err := strconv.Atoi(tok)
	if err != nil {
		// Non-numeric, fractional, or out of int range. compileInterfaces
		// discards this error and leaves the group at its 0 default.
		return "is not an integer (the compiler discards the parse error and " +
			"silently leaves the group at 0)", true
	}
	if n < MinRethRedundancyGroupID {
		if n == 0 {
			return "is 0, which is the chassis-cluster control-plane group, not a " +
				"data-plane group", true
		}
		return "is negative", true
	}
	if n > MaxRethRedundancyGroupOctet {
		return fmt.Sprintf("exceeds %d, so the derived RETH link-local base "+
			"address 169.254.<group>.<node+1>/32 is not a valid IPv4 address",
			MaxRethRedundancyGroupOctet), true
	}
	return "", false
}
