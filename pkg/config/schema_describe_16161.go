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
		child, _, ambiguous := resolveSchemaKeyword(schema, keyword)
		if ambiguous {
			return "", false // ambiguous prefix: never guess (#16161)
		}
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
			if sub, _, ambiguous := resolveSchemaKeyword(child, tokens[i]); !ambiguous && sub != nil {
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
	if child, _, ambiguous := resolveSchemaKeyword(schema, name); ambiguous {
		return "", false // ambiguous candidate prefix: never guess (#16161)
	} else if child != nil && child.desc != "" {
		return child.desc, true
	}
	// A wildcard name slot describes a candidate instance name —
	// only for a name that matches no child keyword at all. An
	// ambiguous prefix (handled above) or an exact known keyword
	// that simply lacks a description must not borrow the
	// wildcard's: `ma` under a level with match/match-strings
	// children describes nothing, not the wildcard's text.
	if schema.wildcard != nil && schema.wildcard.desc != "" {
		if _, known := schema.children[name]; !known && !isKeywordPrefix(schema, name) {
			return schema.wildcard.desc, true
		}
	}
	return "", false
}

// isKeywordPrefix reports whether name is a strict prefix of any
// child keyword of schema (an abbreviation attempt, unique or
// ambiguous), as opposed to a would-be instance name for the
// wildcard slot.
func isKeywordPrefix(schema *schemaNode, name string) bool {
	for k := range schema.children {
		if strings.HasPrefix(k, name) {
			return true
		}
	}
	return false
}

// resolveSchemaKeyword resolves keyword against schema's children:
// an exact match wins, otherwise a unique prefix match expands.
// It returns (nil, "", false) when there is no match or the prefix
// is ambiguous — the ambiguity is reported explicitly so callers
// can tell "no such keyword" (a wildcard slot may still claim the
// token) from "ambiguous prefix" (must describe nothing, per the
// DescribeSetPath contract) (#16161 review fold).
// Wildcards are NOT consulted here; callers decide.
func resolveSchemaKeyword(schema *schemaNode, keyword string) (node *schemaNode, resolved string, ambiguous bool) {
	if schema == nil || schema.children == nil {
		return nil, "", false
	}
	if s, ok := schema.children[keyword]; ok {
		return s, keyword, false
	}
	for k, s := range schema.children {
		if strings.HasPrefix(k, keyword) {
			if node != nil {
				return nil, "", true // ambiguous prefix
			}
			node = s
			resolved = k
		}
	}
	return node, resolved, false
}
