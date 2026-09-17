package config

import (
	"net"
	"strconv"
	"strings"
)

// canonicalAlias9859 is the explicit set of schema child nodes whose identity
// keys are canonicalised by a downstream compiler. The selector compares the
// canonical identity for these sites: aliases merge with inline precedence,
// while unequal instances remain separate.
var canonicalAlias9859 = map[*schemaNode]bool{
	schemaProtocols.children["ospf"].children["area"]:                                                                          true,
	schemaProtocols.children["ospf3"].children["area"]:                                                                         true,
	schemaInterfaces.wildcard.children["unit"].children["family"].children["inet"].children["address"].children["vrrp-group"]:  true,
	schemaInterfaces.wildcard.children["unit"].children["family"].children["inet6"].children["address"].children["vrrp-group"]: true,
	// #10234 P1: chassis RG IDs fold by Atoi int with last-wins (compileChassis
	// byID), so 01 and 1 share one identity while different IDs remain distinct.
	schemaChassis.children["cluster"].children["redundancy-group"]: true,
	// #10234 P1: logical units fold by CanonicalLogicalUnit (01==1) into
	// int-keyed Units maps with last-wins, plus the #5631/#5878 alias gate.
	schemaInterfaces.wildcard.children["unit"]:                   true,
	schemaClassOfService.children["interfaces"].children["unit"]: true,
	// #10234 P1: WireGuard peer pubkeys lowercase in parseTunnelWireguardPeer
	// and dup-canonical is a strict error (validateWireguardPeersStrict).
	// Tunnel appears at interface and unit level with distinct subtrees; equal
	// lowercase identities merge and different keys remain separate.
	schemaInterfaces.wildcard.children["tunnel"].children["wireguard"].children["peer"]:                  true,
	schemaInterfaces.wildcard.children["unit"].children["tunnel"].children["wireguard"].children["peer"]: true,
}

// canonicalIdentity9859 returns the compiler-facing identity for a registered
// keyed schema site. The registry is an admission list; equality still uses
// this canonical identity so different instances remain distinct.
func canonicalIdentity9859(leafSchema *schemaNode, keys []string) (string, bool) {
	if !canonicalAlias9859[leafSchema] || len(keys) < 2 {
		return "", false
	}
	raw := keys[1]
	switch leafSchema {
	case schemaProtocols.children["ospf"].children["area"],
		schemaProtocols.children["ospf3"].children["area"]:
		return canonicalAreaID9859(raw), true
	case schemaInterfaces.wildcard.children["tunnel"].children["wireguard"].children["peer"],
		schemaInterfaces.wildcard.children["unit"].children["tunnel"].children["wireguard"].children["peer"]:
		return strings.ToLower(raw), true
	default:
		// Chassis RGs, regular/CoS units, and VRRP group IDs are all
		// consumed by strconv.Atoi/int-keyed compiler maps.
		if n, err := strconv.Atoi(raw); err == nil {
			return strconv.Itoa(n), true
		}
		return raw, true
	}
}

// canonicalAreaID9859 mirrors the 32-bit OSPF area spelling accepted by the
// compiler: decimal and dotted IPv4 forms denote the same identity.
func canonicalAreaID9859(raw string) string {
	if n, err := strconv.ParseUint(raw, 10, 32); err == nil {
		return canonicalAreaUint9859(n)
	}
	if ip := net.ParseIP(raw).To4(); ip != nil {
		return strings.Join([]string{
			strconv.Itoa(int(ip[0])), strconv.Itoa(int(ip[1])),
			strconv.Itoa(int(ip[2])), strconv.Itoa(int(ip[3])),
		}, ".")
	}
	return raw
}

func canonicalAreaUint9859(n uint64) string {
	return strings.Join([]string{
		strconv.FormatUint((n>>24)&0xff, 10),
		strconv.FormatUint((n>>16)&0xff, 10),
		strconv.FormatUint((n>>8)&0xff, 10),
		strconv.FormatUint(n&0xff, 10),
	}, ".")
}
func canonicalAliasLeaf9859(ancestorPath [][]string, s *Node) bool {
	if s == nil || len(s.Keys) == 0 {
		return false
	}
	parent := schemaAtAncestorPath(ancestorPath)
	if parent == nil {
		return false
	}
	return canonicalAlias9859[resolveSchemaChild(parent, s.Keys[0])]
}

// bracketedAddress9859 is limited to the two interface-family address
// containers. Their children (primary/preferred/vrrp-group) make an address
// look like a named container, but a bracketed value tail denotes several
// address instances rather than one identity.
var bracketedAddress9859 = map[*schemaNode]bool{
	schemaInterfaces.wildcard.children["unit"].children["family"].children["inet"].children["address"]:  true,
	schemaInterfaces.wildcard.children["unit"].children["family"].children["inet6"].children["address"]: true,
}

type addressMember9859 struct {
	value     string
	quoted    bool
	bracketed bool
}

func addressSchema9859(ancestorPath [][]string, key string) *schemaNode {
	parent := schemaAtAncestorPath(ancestorPath)
	if parent == nil {
		return nil
	}
	schema := resolveSchemaChild(parent, key)
	if !bracketedAddress9859[schema] {
		return nil
	}
	return schema
}

// addressMembers9859 accepts only address-only nodes: a pure address leaf,
// or a node whose extra keys/children are all valid address values. A child
// such as primary or vrrp-group therefore keeps the packed/container merge
// path instead of being mistaken for another list member.
func addressMembers9859(schema *schemaNode, n *Node) ([]addressMember9859, bool, bool) {
	if schema == nil || n == nil || len(n.Keys) == 0 || schema.keyValidator == nil {
		return nil, false, false
	}
	var members []addressMember9859
	add := func(value string, quoted, bracketed bool) bool {
		if schema.keyValidator(value, nil) != nil {
			return false
		}
		members = append(members, addressMember9859{value: value, quoted: quoted, bracketed: bracketed})
		return true
	}
	if len(n.Keys) > 1 {
		for i := 1; i < len(n.Keys); i++ {
			if !add(n.Keys[i], n.KeyQuoted(i), n.KeyBracketed(i)) {
				return nil, false, false
			}
		}
	}
	var collect func(*Node) bool
	collect = func(child *Node) bool {
		if child == nil || len(child.Keys) == 0 {
			return false
		}
		for i, key := range child.Keys {
			if !add(key, child.KeyQuoted(i), child.KeyBracketed(i)) {
				return false
			}
		}
		for _, nested := range child.Children {
			if !collect(nested) {
				return false
			}
		}
		return true
	}
	for _, child := range n.Children {
		if !collect(child) {
			return nil, false, false
		}
	}
	if len(members) == 0 {
		return nil, false, false
	}
	isSingle := len(n.Keys) == 2 && len(n.Children) == 0
	isList := len(members) > 1 || len(n.Children) > 0
	return members, isList, isSingle
}

// bracketedAddressPeer9859 chooses an address node whenever either side is a
// value list. The member union then handles overlap and missing values; raw
// identity matching on Keys[1] alone would treat address B beside [A B] as a
// different named container and duplicate B.
func bracketedAddressPeer9859(ancestorPath [][]string, dst []*Node, s *Node) *Node {
	schema := addressSchema9859(ancestorPath, firstKey9859(s))
	if schema == nil {
		return nil
	}
	_, sourceList, sourceSingle := addressMembers9859(schema, s)
	if !sourceList && !sourceSingle {
		return nil
	}
	for _, d := range dst {
		if d == nil || firstKey9859(d) != firstKey9859(s) {
			continue
		}
		_, destinationList, destinationSingle := addressMembers9859(schema, d)
		if !destinationList && !destinationSingle {
			continue
		}
		if sourceList || destinationList {
			return d
		}
	}
	return nil
}

func firstKey9859(n *Node) string {
	if n == nil || len(n.Keys) == 0 {
		return ""
	}
	return n.Keys[0]
}

// mergeBracketedAddressInto9859 appends only address members absent from every
// destination address node. It preserves the selected destination shape and
// keeps bracket provenance aligned when a value is appended to Keys.
func mergeBracketedAddressInto9859(ancestorPath [][]string, dst []*Node, peer, s *Node) bool {
	schema := addressSchema9859(ancestorPath, firstKey9859(s))
	if schema == nil || peer == nil {
		return false
	}
	sourceMembers, sourceList, sourceSingle := addressMembers9859(schema, s)
	_, peerList, peerSingle := addressMembers9859(schema, peer)
	if (!sourceList && !sourceSingle) || (!peerList && !peerSingle) ||
		(!sourceList && !peerList) {
		return false
	}
	// Once members from multiple contributors share one node, ownership of
	// individual values is uncertain. Clear node and chained-member tags just
	// as the generic leaf-list union does; exclusion then keeps the surviving
	// union rather than over-excluding a nested contributor.
	clearAddressProvenance9859(peer)
	seen := map[string]bool{}
	for _, d := range dst {
		if d == nil || firstKey9859(d) != firstKey9859(s) {
			continue
		}
		members, _, _ := addressMembers9859(schema, d)
		for _, member := range members {
			seen[member.value] = true
		}
	}
	for _, member := range sourceMembers {
		if seen[member.value] {
			continue
		}
		appendAddressMember9859(peer, s, member)
		seen[member.value] = true
	}
	return true
}

func clearAddressProvenance9859(n *Node) {
	if n == nil {
		return
	}
	n.fromGroups = nil
	for _, child := range n.Children {
		clearAddressProvenance9859(child)
	}
}
func appendAddressMember9859(dst, src *Node, member addressMember9859) {
	if dst.IsLeaf {
		dst.Keys = append(dst.Keys, member.value)
		appendKeyQuoted9627(dst, member.quoted)
		appendKeyBracketed9859(dst, member.bracketed)
		return
	}
	child := &Node{
		Keys:          []string{member.value},
		IsLeaf:        true,
		InheritedFrom: src.InheritedFrom,
	}
	child.setKeysQuoted([]bool{member.quoted})
	if member.bracketed {
		child.setKeysBracketed([]bool{true})
	}
	dst.Children = append(dst.Children, child)
}

func appendKeyBracketed9859(n *Node, bracketed bool) {
	if n == nil {
		return
	}
	oldLen := len(n.Keys) - 1
	if len(n.KeysBracketed) == oldLen {
		n.KeysBracketed = append(n.KeysBracketed, bracketed)
		return
	}
	if !bracketed {
		n.KeysBracketed = nil
		return
	}
	mask := make([]bool, len(n.Keys))
	if len(n.KeysBracketed) > 0 && len(n.KeysBracketed) <= oldLen {
		copy(mask, n.KeysBracketed)
	}
	mask[oldLen] = true
	n.KeysBracketed = mask
}

// legacyScalar9859 lists children-bearing schema nodes whose first argument is
// still a scalar value. CoS shaping-rate has an optional burst-size child for
// one statement's modifiers, but its rate remains the scalar identity/value;
// different rates must retain ordinary inline-wins override semantics.
var legacyScalar9859 = map[*schemaNode]bool{
	schemaClassOfService.children["interfaces"].children["unit"].children["shaping-rate"]: true,
	schemaClassOfService.children["interfaces"].children["shaping-rate"]:                  true,
}

// legacyScalarContainerOverride9859 keeps a different-valued scalar container
// on the existing inline-wins path. CoS shaping-rate acquires a container
// body when burst-size is present, but the rate token remains scalar.
func legacyScalarContainerOverride9859(ancestorPath [][]string, dst []*Node, s *Node) bool {
	if s == nil || s.IsLeaf || len(s.Keys) == 0 {
		return false
	}
	parent := schemaAtAncestorPath(ancestorPath)
	if parent == nil {
		return false
	}
	leafSchema := resolveSchemaChild(parent, s.Keys[0])
	if !legacyScalar9859[leafSchema] {
		return false
	}
	for _, d := range dst {
		if d == nil || len(d.Keys) == 0 || d.Keys[0] != s.Keys[0] {
			continue
		}
		// Legacy scalar override is keyword-based for both inline and prior
		// group destinations; unrelated apply-groups-except provenance must not
		// change whether a different rate is suppressed.
		if !keysEqual(d.Keys, s.Keys) {
			return true
		}
	}
	return false
}

// namedLeafPeer9859 selects the peer for a group leaf that names a schema
// container instance. It returns identity=true only for the narrow admission
// gate: the schema resolves, it is a children-bearing non-valueList node, the
// source carries a keyword plus an identity span of at least two keys, and the
// site is not a zone. Bare identity-only and unexpandable-tail sources scan
// leaf and braced destinations so same-instance spellings stay on the existing
// merge path; only expandable packed tails defer braced peers to #9855's
// fallback, which marks packed terminals before merging. Registered canonical
// sites compare compiler-facing identities rather than raw aliases. A nil peer
// with identity=true means the group leaf is a different instance and must be
// adopted.
//
// identity=false preserves the existing leafListPeer path. In particular,
// valueList leaves, explicitly legacy scalar leaves, and unknown/unresolvable
// schema keep the legacy keyword override instead of guessing an identity.
func namedLeafPeer9859(ancestorPath [][]string, dst []*Node, s *Node) (peer *Node, identity bool) {
	if s == nil || len(s.Keys) == 0 || groupZoneLeaf9831(ancestorPath, s) {
		return nil, false
	}
	parent := schemaAtAncestorPath(ancestorPath)
	if parent == nil {
		return nil, false
	}
	leafSchema := resolveSchemaChild(parent, s.Keys[0])
	if leafSchema == nil || leafSchema.children == nil || leafSchema.valueList {
		return nil, false
	}
	span, ok := identitySpan9855(leafSchema, s.Keys, s.Keys)
	if !ok {
		return nil, false
	}
	if legacyScalar9859[leafSchema] {
		// Tell the caller to use the legacy leafListPeer fallback. Scalar
		// containers keep their existing keyword/value semantics.
		return nil, false
	}
	if peer := bracketedAddressPeer9859(ancestorPath, dst, s); peer != nil {
		return peer, true
	}
	canonical := canonicalAlias9859[leafSchema]
	var canonicalID string
	if canonical {
		var ok bool
		canonicalID, ok = canonicalIdentity9859(leafSchema, s.Keys)
		if !ok {
			return nil, false
		}
	}
	var same *Node
	for _, d := range dst {
		if d == nil || len(d.Keys) == 0 || d.Keys[0] != s.Keys[0] {
			continue
		}
		if canonical {
			dID, ok := canonicalIdentity9859(leafSchema, d.Keys)
			if ok && dID == canonicalID && same == nil {
				same = d
			}
			continue
		}
		if !d.IsLeaf && span != len(s.Keys) {
			// Expandable packed tails use #9855's fallback, which marks
			// synthesized terminals before merging. An unexpandable tail
			// keeps the conservative keyword override against a braced peer.
			if groupPackedLeafBody(ancestorPath, s) != nil {
				continue
			}
		}

		if _, ok := identitySpan9855(leafSchema, s.Keys, d.Keys); ok && same == nil {
			same = d
		}
	}
	return same, true
}

// namedLeafCanAdopt9859 reports whether the source is admitted to the new
// different-instance path. It is used by the #9855 successive-merge guard so
// a promoted same-keyword sibling does not erase a distinct named instance.
func namedLeafCanAdopt9859(ancestorPath [][]string, dst []*Node, s *Node) bool {
	peer, identity := namedLeafPeer9859(ancestorPath, dst, s)
	return identity && peer == nil
}
