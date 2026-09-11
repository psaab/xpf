package config

// normalizeElidedRoutingInstance9620 rewrites a brace-elided routing instance
// into the braced shape the parser builds for the same statements:
//
//	ri1 instance-type virtual-router routing-options static route 10.9.0.0/16 next-hop 10.0.0.2;
//	ri1 { instance-type virtual-router; routing-options static route 10.9.0.0/16 next-hop 10.0.0.2; }
//
// #9620: the scoped fold cannot do this, because its pair at this site would be
// (instance name, keyword), and no scope entry can name an instance (#8787). So
// the compiler read the Keys run itself (#8787, #9055), AFTER group expansion
// and AFTER SchemaValidate, and a packed body was compiled from a node neither
// of them had seen. Measured through configstore.CheckText at 0e950bd5b:
//
//   - strict accepted `ri1 protocols { bgp { group G { hold-time 1; ... } } }`
//     and compiled HoldTime=1. The braced spelling refuses it, because FRR
//     rejects the timers line.
//   - `apply-groups` under an elided `routing-options` body resolved against
//     the wrong path, and compiled a route with no next-hop.
//
// Both compile cores and the SchemaValidate walk normalize before they read the
// tree, so rewriting here gives every reader the braced shape. The scoped fold
// then folds each statement's own packed tail, as it does inside a braced
// instance.
//
// The run is split by the instance schema, the grammar the braced spelling is
// validated against:
//
//   - A keyword that is not a container takes its declared values, then every
//     further token up to the next declared instance keyword, which is what the
//     same statement means written on one line inside braces. So
//     `vrf-target export target:65000:1` stays one statement, and so does
//     `interface ge-0/0/1.0 ge-0/0/2.0`. Measured: the braced one-line spellings
//     commit, and a split after the declared value refused `target:65000:1` as
//     an undeclared keyword.
//   - An apply statement (apply-groups, apply-groups-except, apply-macro) ends
//     the value statement before it and is a statement of its own, so group
//     expansion sees it as it does inside braces. Absorbed into the value before
//     it, `ri1 instance-type vrf apply-groups MISSING;` committed where the
//     braced spelling refuses the undefined group. apply-macro also owns the
//     rest of the run and its braced body, which are its arguments:
//     `ri1 apply-macro M { interface ge-0/0/1.0; }` must not bind an interface.
//     Inside a container's or an undeclared keyword's run, an apply keyword
//     stays in that run, as it does on the one-line braced spelling.
//   - Quotes and brackets never move a boundary. show configuration, HA sync,
//     `load merge` and rollback files render the tree without them, so a split
//     that read them would bind `interface [ ge-0/0/0.0 protocols ]` into the VRF
//     here and only `ge-0/0/0.0` on a peer that parsed the rendered text. The
//     scoped fold is provenance-blind for the same reason. Whether an authored
//     value that spells a keyword should stay a value is #9635.
//   - A container keyword (routing-options, protocols, interface-routes) takes
//     the rest of the run and the braced body. So does an undeclared keyword,
//     which can only START the run, since any later one extends the statement
//     before it. It arrives as a child named by that keyword, and the #9323 gate
//     refuses it as it refuses the braced spelling. An undeclared token after a
//     declared statement extends that statement, exactly as it does inside
//     braces, where `ri1 { instance-type virtual-router bogus-kw foo; }` also
//     commits (#9736).
//
// A braced body after a value keyword (`ri1 instance-type vrf { interface x; }`)
// has no braced spelling of its own. Its statements stay instance statements,
// after the ones from the Keys run, which is how the compiler read that shape.
//
// Apply statements are not instances and are never rewritten (#9657).
func normalizeElidedRoutingInstance9620(node *Node, instance *schemaNode) int {
	n := len(node.Keys)
	if n < 2 || instance == nil || isApplyStatementNode(node) {
		return 0
	}
	quoted := keyMask8921(node.KeysQuoted, n)
	bracketed := keyMask8921(node.KeysBracketed, n)
	boundary := func(tok string) bool {
		return instance.children[tok] != nil || routingInstanceApplyMetaKeyword9323(tok)
	}

	type span struct{ from, to int }
	var spans []span
	ownsBody := false
	for i := 1; i < n; {
		kw := instance.children[node.Keys[i]]
		apply := routingInstanceApplyMetaKeyword9323(node.Keys[i])
		// apply-macro carries its own arguments and an optional braced body, so it
		// owns the rest of the run as a container does.
		if node.Keys[i] == "apply-macro" || (!apply && (kw == nil || len(kw.children) > 0 || kw.wildcard != nil)) {
			spans = append(spans, span{i, n})
			ownsBody = true
			break
		}
		args := 1 // an apply statement names at least one group or macro
		if kw != nil {
			args = kw.args
		}
		j := i + 1 + args
		if j > n {
			j = n
		}
		for j < n && !boundary(node.Keys[j]) {
			j++
		}
		spans = append(spans, span{i, j})
		i = j
	}

	body := node.Children
	children := make([]*Node, 0, len(spans)+len(body))
	for k, s := range spans {
		c := &Node{
			Keys:   append([]string(nil), node.Keys[s.from:s.to]...),
			IsLeaf: true,
			Line:   node.Line,
			Column: node.Column,
		}
		c.setKeysQuoted(maskSlice8921(quoted, s.from, s.to))
		c.setKeysBracketed(maskSlice8921(bracketed, s.from, s.to))
		if k == len(spans)-1 && ownsBody && len(body) > 0 {
			c.Children = body
			c.IsLeaf = false
		}
		children = append(children, c)
	}
	if !ownsBody {
		children = append(children, body...)
	}
	node.Keys = node.Keys[:1:1]
	node.setKeysQuoted(maskSlice8921(quoted, 0, 1))
	node.setKeysBracketed(maskSlice8921(bracketed, 0, 1))
	node.Children = children
	node.IsLeaf = false
	return 1
}
