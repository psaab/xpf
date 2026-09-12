package config

// #9656 M26 helper: is `want` present under `n`, whether it was written as a
// braced child or packed onto `n`'s own keys?
//
// `area-type stub no-summaries;` puts BOTH tokens on the area-type node's tail,
// so after the first unpack the `stub` node is `Keys=["stub","no-summaries"]`
// with no children — and a `FindChild("no-summaries")` on it returns nil while
// the operator plainly wrote it. That is the same miss as the area-type read
// itself, one level further down, so it gets the same schema-driven unpack
// rather than a second hand-rolled key scan.
//
// parentSchema is the schema of n's PARENT, because n's own schema is reached
// by resolving n's keyword within it — the caller has the parent in hand and
// this keeps the resolution in one place.
func hasPackedChild9656(n *Node, parentSchema *schemaNode, want string) bool {
	if n == nil {
		return false
	}
	if n.FindChild(want) != nil {
		return true
	}
	childSchema := resolveSchemaChild(parentSchema, n.Name())
	if childSchema == nil {
		// Outside the modelled grammar. Do not guess — the direct FindChild
		// above is still authoritative for the braced spelling.
		return false
	}
	for _, c := range packedBodyChildren(n, childSchema) {
		if c.Name() == want {
			return true
		}
	}
	return false
}
