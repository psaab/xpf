package config

import "strings"

// compiler_ipsec_trafficselector_run_16759.go carries the run-aware
// traffic-selector discovery shared by compileIPsec and
// validateIPsecTrafficSelectorsStrict (#16759).
//
// A traffic-selector chained after other VPN leaves in one flat set
// command --
//
//	set security ipsec vpn v1 gateway gw1 ipsec-policy epol1
//	    bind-interface st0.0 traffic-selector ts1 local-ip 10.1.0.0/24
//	    remote-ip 10.2.0.0/24
//
// is segmented by expandIPsecVPNRun9088 into a synthesized node with
// Keys=[traffic-selector ts1 local-ip <l> remote-ip <r>] and no
// children: the schema declares traffic-selector with children, so
// expandFlatRun cannot descend into it. Reading only direct
// FindChildren("traffic-selector") therefore lost the selector with
// no error, while EffectiveTrafficSelectors widened the SA to
// any<->any and the #4098/#5692 shape gate was bypassed. Both readers
// must discover selectors through this one helper so they cannot
// diverge (#9088).

// trafficSelectorInstances16759 returns every traffic-selector
// instance under a vpn node, in authoring order, across both parser
// shapes: direct children (braced / split set commands) and
// synthesized segments of a packed flat run (chained set commands,
// including the compact hierarchical tail carried on the VPN node's
// own Keys).
//
// Each instance's body is normalized to a node whose Keys are
// [traffic-selector <name>] and whose Children are the selector's
// local-ip / remote-ip leaves, so callers segment the leaves with
// expandFlatRun(..., ipsecTrafficSelectorSchema8939()) exactly as
// they did for the direct spelling. A synthesized instance carrying
// no leaves yields empty children (a name-only selector). Instances
// recovered more than once (for example a braced selector also
// re-emitted by the tail expansion) keep first-occurrence order by
// deduping on the node pointer where possible and by name otherwise.
func trafficSelectorInstances16759(vpn *Node) []struct {
	name string
	node *Node
} {
	var out []struct {
		name string
		node *Node
	}
	seenPtr := map[*Node]bool{}
	seenName := map[string]bool{}
	add := func(name string, node *Node) {
		if name == "" || node == nil {
			return
		}
		key := name + "\x00" + strings.Join(node.Keys, "\x00")
		// Dedup repeated sightings of the same selector: the same
		// pointer (direct child re-surfaced by run expansion) or the
		// same name with the same keys. Duplicate named blocks are
		// rejected elsewhere (#8704); last-wins accumulation in the
		// compiler keeps that behaviour, so collapsing an identical
		// re-sighting only avoids double-counting its leaves.
		if seenPtr[node] {
			return
		}
		if seenName[key] {
			return
		}
		seenPtr[node] = true
		seenName[key] = true
		out = append(out, struct {
			name string
			node *Node
		}{name, node})
	}

	// Direct children: braced blocks and split set commands. These
	// nodes keep their authored children.
	for _, inst := range namedInstances(vpn.FindChildren("traffic-selector")) {
		add(inst.name, inst.node)
	}

	// Run segments: chained set commands and the compact tail. A
	// direct child also appears here unchanged (same pointer) and is
	// deduped above; a nested/chained selector arrives as a flat
	// synthesized node that must be reconstructed.
	for _, seg := range expandIPsecVPNRun9088(vpn) {
		if seg == nil || len(seg.Keys) == 0 || seg.Keys[0] != "traffic-selector" {
			continue
		}
		if seenPtr[seg] {
			continue
		}
		name, body := trafficSelectorFromRunSegment16759(seg)
		add(name, body)
	}
	return out
}

// trafficSelectorFromRunSegment16759 reconstructs a traffic-selector
// instance node from one expanded run segment. Children already in
// selector shape (local-ip / remote-ip nodes, possibly with a packed
// remote-ip nested under local-ip) are kept and re-segmented by the
// caller; flat keys after the selector name are split at the
// local-ip / remote-ip keywords into synthesized leaf nodes.
func trafficSelectorFromRunSegment16759(seg *Node) (string, *Node) {
	if len(seg.Keys) < 2 {
		return "", nil
	}
	name := seg.Keys[1]
	body := &Node{Keys: []string{"traffic-selector", name}}
	// Braced children ride along unchanged.
	body.Children = append(body.Children, seg.Children...)
	// Flat tail: traffic-selector <name> local-ip <l> remote-ip <r>.
	rest := seg.Keys[2:]
	for i := 0; i < len(rest); {
		kw := rest[i]
		if kw != "local-ip" && kw != "remote-ip" {
			// Unknown token: keep it attached to the previous leaf
			// if one exists so trafficSelectorValues still sees
			// every token of a bracketed or malformed value;
			// otherwise drop it (no leaf owns it).
			if n := len(body.Children); n > 0 {
				last := body.Children[n-1]
				last.Keys = append(last.Keys, kw)
				last.IsLeaf = len(last.Children) == 0
			}
			i++
			continue
		}
		leaf := &Node{Keys: []string{kw}, IsLeaf: true}
		i++
		if i < len(rest) {
			leaf.Keys = append(leaf.Keys, rest[i])
			i++
		}
		body.Children = append(body.Children, leaf)
	}
	if len(body.Children) > 0 {
		body.IsLeaf = false
	}
	return name, body
}
