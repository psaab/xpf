package config

// #15017 (A12-05): packed-body expansion for the `protocols <p>` TOP nodes.
//
// The OSPF top loop (#14427) and the IS-IS top loop (#14426) already read
// their body through packedBodyChildren plus the tail-only fallback
// below. RIP and OSPFv3 did not, so a hierarchical line that packs a
// leaf tail beside a braced body silently dropped the tail:
//
//	rip authentication-key secret authentication-type md5 { neighbor ge-0/0/0.0; }
//	    compiled AuthKey="" AuthType="" — RIP unauthenticated — while
//	    the braced neighbor survived, so the commit reported success.
//
//	ospf3 router-id 1.1.1.1 export connected { area 0.0.0.0 { ... } }
//	    compiled RouterID="" Export=[] while the area survived.
//
// The plain packed line with NO braced body (`rip authentication-key
// secret authentication-type md5;`) was already rescued before the
// compiler by the #8662 compact normalizer (`rip authentication-key` /
// `rip authentication-type` are in its scope), and the same holds for
// `ospf3 router-id ...;`. The surviving hole is exactly the mixed
// tail+braced shape: packedBodyChildren declines to expand a tail that
// ends in a leaf beside a braced body (compact_tail.go's do-not-guess
// guard), returning the braced Children alone. This helper expands the
// tail from a childless view of the same node and reads both halves,
// mirroring the IS-IS top/interface readers token for token. An
// unmodelled tail still expands to nothing there.
//
// BGP and LLDP top nodes also iterate Children only, but they are NOT
// read here: their divergent packed census rows are the flat-set heads
// (`bgp graceful-restart`, `bgp log-updown`, `bgp multipath ...`,
// `lldp disable`), which the existing expandFlatRun /
// flattenChainedChildren chain readers already cover, and the mixed
// tail+braced shape at those tops is not reachable through the strict
// gate today. Router-advertisement's top node carries no leaves of its
// own. Adding reads there without a failing case would be untested
// widening; the regression below censuses every `protocols <p>` top
// that has top-level leaves so a future gap fails loudly instead.

// packedTopChildren returns the body a protocols top loop should descend
// for node: packedBodyChildren's expansion, plus — when node carries
// BOTH a packed tail (Keys past its identity) and a braced body, and
// packedBodyChildren declined (returned the braced Children alone) —
// the tail expanded from a childless view, followed by the braced
// Children. Returns Children unchanged when there is no packed tail.
func packedTopChildren(node *Node, schema *schemaNode) []*Node {
	if node == nil || schema == nil {
		return nodeChildren(node)
	}
	body := packedBodyChildren(node, schema)
	if len(node.Keys) > 1 && len(node.Children) > 0 && len(body) == len(node.Children) &&
		(len(body) == 0 || &body[0] == &node.Children[0]) {
		tailOnly := *node
		tailOnly.Children = nil
		body = append(packedBodyChildren(&tailOnly, schema), node.Children...)
	}
	return body
}
