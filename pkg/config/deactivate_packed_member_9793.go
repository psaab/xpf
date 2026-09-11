package config

import (
	"fmt"
	"strings"
)

// refusePackedMemberToggle refuses a deactivate or activate whose path names
// one member of a node that also names other members (#9793).
//
// `security-zone [ zga zgb ] { tcp-rst; }` is ONE node, Keys [security-zone
// zga zgb], and Inactive is a node-level flag. setInactiveAtPath consumes
// `security-zone zga` at the schema arity and markMatchingNodeInactive
// prefix-matches that node, so `deactivate security zones security-zone zga`
// marked the whole statement and took zgb out of the compiled config too,
// with no error. DeletePath refuses the same address (#8992); this is the
// matching refusal for the toggle verbs.
//
// Two addresses are NOT refused, because toggling the whole node is what they
// mean:
//   - a path naming every key of the node. `show | display set` emits
//     `deactivate ... security-zone [ zga zgb ]` for an inactive group, and
//     that line must reload (#6668);
//   - a path that ends at a statement whose own content is packed behind it.
//     `security-zone trust screen edge tcp-rst;` is zone trust and its body,
//     so `deactivate ... security-zone trust` toggles exactly that zone. The
//     test is whether the next key is a schema child of the addressed
//     statement (content) or not (another member's name).
//
// path is the full path, for the message; i is where the walk stands.
func refusePackedMemberToggle(nodes []*Node, path []string, i int, schema *schemaNode, inactive bool) error {
	tail := path[i:]
	keys := elidedPackedRunCarrying(nodes, tail, schema)
	if keys == nil || len(keys) == len(tail) {
		return nil
	}
	if at, ok := addressedSchema9793(tail, schema); ok && len(keys) > len(tail) && resolveSchemaChild(at, keys[len(tail)]) != nil {
		return nil
	}
	verb := "activate"
	if inactive {
		verb = "deactivate"
	}
	return fmt.Errorf("%q is one member of a statement that names others on the same line (%q), and %s would apply to all of them. Re-author that line with braces around %q, then %s it (#9793, #8992)",
		strings.Join(path, " "), strings.Join(keys, " "), verb, path[len(path)-1], verb)
}

// addressedSchema9793 walks tail from schema one statement at a time and
// returns the schema node of the statement it ends on. ok is false when the
// walk leaves the schema or the tail ends inside a statement's key slot.
func addressedSchema9793(tail []string, schema *schemaNode) (*schemaNode, bool) {
	cur := schema
	for j := 0; j < len(tail); {
		child := resolveSchemaChild(cur, tail[j])
		if child == nil {
			return nil, false
		}
		j += 1 + child.args
		if j > len(tail) {
			return nil, false
		}
		if child.compoundKey && j < len(tail) {
			if sub := resolveSchemaChild(child, tail[j]); sub != nil {
				j++
				child = sub
			}
		}
		cur = child
	}
	return cur, true
}
