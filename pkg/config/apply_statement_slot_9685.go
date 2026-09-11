package config

// #9685: the apply statements Junos admits at every hierarchy level.
//
// `apply-groups`, `apply-groups-except` and `apply-macro` may appear inside any
// container, but setSchema declares only the top-level `apply-groups`. At a
// schema node with a WILDCARD name slot (routing-instances, interfaces,
// bridge-domains, security-zone interfaces, ...) the walkers used to take the
// keyword as an instance NAME, so a flat `set routing-instances apply-groups g1`
// was stored as Keys=["apply-groups"] with a child ["g1"]. Group expansion
// (ast_groups.go) and the #9422 exclusion read names from the statement's own
// Keys[1:], found none, and stripped the node: the inheritance or exclusion
// silently did not happen on a clean commit, while the hierarchical spelling
// worked.
//
// schemaChildFor is the one lookup every tree walker uses in place of
// "children[keyword], else wildcard": at a wildcard slot an apply statement
// resolves to applyStatementSchema, a multi-value leaf like the top-level
// declaration, before the wildcard can claim it. A declared child still wins, so
// the top-level `apply-groups` entry is untouched.
var applyStatementSchema = &schemaNode{
	desc:        "Groups from which to inherit, or to exclude from inheriting, configuration data",
	args:        1,
	multi:       true,
	placeholder: "<group-name>",
}

func isApplyStatementKeyword(keyword string) bool {
	switch keyword {
	case "apply-groups", "apply-groups-except", "apply-macro":
		return true
	}
	return false
}

func schemaChildFor(schema *schemaNode, keyword string) *schemaNode {
	if schema == nil {
		return nil
	}
	if s, ok := schema.children[keyword]; ok {
		return s
	}
	if schema.wildcard == nil {
		return nil
	}
	if isApplyStatementKeyword(keyword) {
		return applyStatementSchema
	}
	return schema.wildcard
}
