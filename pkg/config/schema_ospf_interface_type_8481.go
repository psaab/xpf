package config

import (
	"fmt"
	"strings"
)

// #8481: `protocols ospf ... interface <n> interface-type <type>` was declared
// with an arity and a placeholder but NO valueType and NO validator, so
// SchemaValidate accepted any string.
//
// The issue reported the consequence as "commits green and leaves the interface
// on the default broadcast type — adjacency behaviour silently different from
// what was authored". That premise is wrong, and wrong in the DANGEROUS
// direction. `compiler_protocols.go` stores the token verbatim into
// `OSPFInterface.NetworkType`, and `pkg/frr/protocols_render.go` writes it
// verbatim into the managed section:
//
//	fmt.Fprintf(&b, " ip ospf network %s\n", iface.NetworkType)
//
// Measured by rendering the managed section directly, one row per value:
//
//	interface-type "point-to-point"  ->  ip ospf network point-to-point
//	interface-type "p2p"             ->  ip ospf network p2p
//	interface-type "bogus value"     ->  ip ospf network bogus value
//	interface-type ""                ->  (no line)
//
// vtysh rejects a network type it does not know, and ONE rejected line fails
// the ENTIRE managed-section reload (#1880/#2223) — taking down all dynamic
// routing, not just OSPF. That is the same consequence #8443's empty-key guard
// was written for, three lines below this render site in the same file. So the
// leaf is not inert; it is a way to break FRR from a clean commit.
//
// OSPFNetworkTypes is the set vtysh accepts, and it is the set this leaf is
// validated against — the constraint is the CONSUMER's grammar, not anything
// the xpf compiler itself checks (it checks nothing; it passes the token
// through).
var OSPFNetworkTypes = []string{
	"broadcast",
	"non-broadcast",
	"point-to-multipoint",
	"point-to-point",
}

// junosOSPFInterfaceTypeAliases maps the JUNOS spellings of `interface-type` to
// the FRR network type they mean.
//
// This is a deliberate scope choice beyond the issue's suggested shape, and it
// is stated here so it is reviewable rather than incidental. xpf's product
// claim is native Junos configuration syntax, and `interface-type p2p` is what
// Juniper's documentation tells an operator to write. Validating against the
// FRR set ALONE would take today's broken-reload and turn it into a hard
// rejection of valid Junos syntax — better than breaking FRR, but still a
// refusal of the exact spelling the product claims to accept. Translating them
// is what makes the leaf behave the way the rest of the tree does.
//
// The three aliases are the complete Junos set for this statement. Junos also
// spells `broadcast` and `point-to-point` the FRR way, so those need no entry
// and deliberately have none — an alias table that repeats identity mappings
// invites a later reader to treat absence as an oversight.
var junosOSPFInterfaceTypeAliases = map[string]string{
	"p2p":  "point-to-point",
	"nbma": "non-broadcast",
	"p2mp": "point-to-multipoint",
}

// CanonicalOSPFNetworkType resolves an authored `interface-type` value to the
// token that goes on the `ip ospf network` line, or reports that it is not one.
// It is the SSOT the schema validator and the compiler both consult, so the
// accepted set and the rendered set cannot drift — which is the specific defect
// shape #8443 called out: a per-leaf allowlist authored independently of what
// the renderer recognises drifts right back open.
func CanonicalOSPFNetworkType(raw string) (string, bool) {
	if canon, ok := junosOSPFInterfaceTypeAliases[raw]; ok {
		return canon, true
	}
	for _, t := range OSPFNetworkTypes {
		if raw == t {
			return raw, true
		}
	}
	return "", false
}

// ValidateOSPFInterfaceType is the schema leaf validator. It accepts exactly
// what CanonicalOSPFNetworkType resolves, so a value that commits is a value
// that renders a line vtysh accepts.
func ValidateOSPFInterfaceType(raw string) error {
	if _, ok := CanonicalOSPFNetworkType(raw); ok {
		return nil
	}
	return newOSPFInterfaceTypeError(raw)
}

// newOSPFInterfaceTypeError builds the rejection. It lists both spellings
// because an operator arriving here came from one of two documents, and saying
// only "expected one of: broadcast, non-broadcast, ..." to someone who typed
// the Junos `p2p` tells them the product does not support what it claims to.
func newOSPFInterfaceTypeError(raw string) error {
	return fmt.Errorf(
		"invalid OSPF interface-type %q: expected one of %s (the Junos "+
			"spellings p2p, nbma and p2mp are accepted and translated). This "+
			"value is written verbatim into the FRR managed section as "+
			"`ip ospf network %s`, and one line vtysh rejects fails the entire "+
			"managed-section reload — taking down all dynamic routing, not just "+
			"OSPF (#8481)",
		raw, strings.Join(OSPFNetworkTypes, ", "), raw)
}
