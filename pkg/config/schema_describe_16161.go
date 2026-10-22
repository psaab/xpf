package config

import "strings"

// DescribeSetPath returns the schema description for the node at the
// tail of a consumed `set` path (#16161). tokens are the consumed
// config-path words BELOW `set` (e.g. ["system", "dataplane",
// "coalescence"]); name is the candidate keyword whose description is
// wanted (e.g. "rx-usecs"). It returns ("", false) when the path does
// not resolve or the candidate is not a schema child at that level.
//
// This is the read-only description lookup cmdtree.LookupDesc falls
// back to for config mode after the #16161 deletion of the cmdtree
// `set system dataplane` overlay: setSchema is the single source for
// both completion (CompleteSetPathWithValues) and `?` descriptions,
// so adding or renaming a knob cannot drift help from validation.
//
// Resolution mirrors the schema walkers: exact child keywords win,
// a unique keyword prefix expands (Junos-style abbreviation, the
// same rule ResolveConsumedSetPathTokens applies), wildcard name
// slots consume one value token, and a node's declared args consume
// that many value tokens. Any ambiguity, unknown keyword, stray
// value, or descent past a leaf yields ("", false) — the caller
// renders no description rather than a wrong one.
func DescribeSetPath(tokens []string, name string) (string, bool) {
	schema := setSchema
	i := 0
	for i < len(tokens) {
		if schema == nil {
			return "", false
		}
		if schema.children == nil && schema.wildcard == nil {
			return "", false // at a leaf; tokens remain unconsumed
		}
		keyword := tokens[i]
		child, _ := resolveSchemaKeyword(schema, keyword)
		if child == nil {
			// A wildcard slot consumes the token as a name value.
			child = schema.wildcard
		}
		if child == nil {
			return "", false
		}
		i++
		// Consume the node's declared value/identity tokens.
		i += child.args
		if i > len(tokens) {
			// Path ends inside this node's value slot: the node
			// itself is the deepest resolvable level, and `name`
			// can only be described if it is this node — callers
			// ask for children, so there is nothing to describe.
			return "", false
		}
		if child.compoundKey && i < len(tokens) {
			if sub, _ := resolveSchemaKeyword(child, tokens[i]); sub != nil {
				child = sub
				i++
			}
		}
		if child.multi && child.children == nil {
			continue // multi leaf: stay, siblings may follow
		}
		schema = child
	}
	if schema == nil || name == "" {
		return "", false
	}
	if child, _ := resolveSchemaKeyword(schema, name); child != nil && child.desc != "" {
		return child.desc, true
	}
	// A wildcard name slot describes a candidate instance name.
	if schema.wildcard != nil && schema.wildcard.desc != "" {
		// Only when name is not a known child keyword that simply
		// lacks a description: known keywords handled above return
		// their own desc; an undescribed known keyword must not
		// borrow the wildcard's.
		if _, known := schema.children[name]; !known {
			return schema.wildcard.desc, true
		}
	}
	return "", false
}

// resolveSchemaKeyword resolves keyword against schema's children:
// an exact match wins, otherwise a unique prefix match expands.
// It returns (nil, "") when there is no match or the prefix is
// ambiguous. Wildcards are NOT consulted here; callers decide.
func resolveSchemaKeyword(schema *schemaNode, keyword string) (*schemaNode, string) {
	if schema == nil || schema.children == nil {
		return nil, ""
	}
	if s, ok := schema.children[keyword]; ok {
		return s, keyword
	}
	var match *schemaNode
	resolved := ""
	for k, s := range schema.children {
		if strings.HasPrefix(k, keyword) {
			if match != nil {
				return nil, "" // ambiguous prefix
			}
			match = s
			resolved = k
		}
	}
	return match, resolved
}
