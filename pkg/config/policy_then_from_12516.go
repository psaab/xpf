package config

import (
	"fmt"
	"slices"
)

// Then-first policy terms on flat replay (#12516).
//
// The hierarchical parser keeps `term T then <actions> from <matches>;` as one
// packed node, and parsePolicyTermInlineKeys reads its `from` tail as the
// term's match clause. Flat replay — direct `set`, LoadSet, and LoadMerge,
// which re-renders hierarchical input through FormatSetForLoadMerge — walks
// the schema instead. `then` is a container and `from` is none of its
// keywords, so the whole match clause landed as an unread node under
// whichever action preceded it: accept or reject, a valued action such as
// `metric 10` or `next-hop self`, or a `community add C1` value list that
// absorbed it. The term then compiled as an unconstrained action, in the
// worst case an accept-all permit.
//
// SetPath therefore replays such a line as the two statements it stands for:
// the `from` clause on the term, then the actions.

// policyTermThenIndex12516 returns the index of a set path's term-level
// `then` token, or -1. It follows the container arity SetPath walks, so every
// mount of the policy-options schema (the root and `groups <name>` share its
// nodes) and a bracket-widened name resolve alike. It never mutates.
func policyTermThenIndex12516(path []string, grouped []bool) int {
	termThen := policyTermThenSchema8939()
	schema := setSchema
	for i := 0; i < len(path); {
		child := schemaChildFor(schema, path[i])
		if child == nil || child.multi || child.compoundKey {
			// SetPath leaves the container walk at such a node, and none
			// lies on the way to a policy term.
			return -1
		}
		if child == termThen {
			return i
		}
		i = widenKeyCountToGroupEnd(grouped, i, i+1+child.args)
		schema = child
	}
	return -1
}

// policyTermThenFromSplit12516 locates the `from` token that starts the match
// clause of a then-first policy term path. thenAt is the index of the
// term-level `then` and fromAt the index of that `from`; fromAt is -1 when the
// path carries no then-first `from`.
//
// The scan steps over each action's declared operands (community add, delete
// and set take the operation plus one value) and decides each `from`:
//
//   - At a clause position, quoted or not, it starts the clause — the reading
//     parsePolicyTermInlineKeys gives the packed spelling.
//   - In a `then community` value slot it is a community name, as the schema
//     walk and the brace spelling read it; the scan continues past it.
//   - Unquoted in another operand slot it starts the clause too: no other
//     action has a value spelled `from`, and commit refuses the action left
//     without its operand.
//   - Quoted in such a slot, or bracketed anywhere, it could be a value or the
//     clause. The error refuses the path rather than guess, because leaving it
//     in place files the clause under the action, where nothing reads it.
func policyTermThenFromSplit12516(path []string, quoted, grouped []bool) (thenAt, fromAt int, err error) {
	if !slices.Contains(path, "from") {
		return -1, -1, nil
	}
	thenAt = policyTermThenIndex12516(path, grouped)
	if thenAt < 0 {
		return -1, -1, nil
	}
	actions := policyTermThenSchema8939()
	owner, operands := "", 0 // the preceding action and the operands still owed to it
	for j := thenAt + 1; j < len(path); j++ {
		operand := operands > 0
		if operand {
			operands--
		}
		if path[j] != "from" {
			if action := actions.children[path[j]]; action != nil && !operand {
				owner, operands = path[j], action.args
				if path[j] == "community" && j+1 < len(path) {
					switch path[j+1] {
					case "add", "delete", "set":
						operands++
					}
				}
			}
			continue
		}
		switch {
		case grouped != nil && grouped[j]:
			return thenAt, -1, fmt.Errorf("%s: a bracketed \"from\" after \"then\" cannot start "+
				"the term's match clause, and replaying it under the action would drop that "+
				"clause (#12516); write the match clause unbracketed",
				joinKeysProvGrouped(path, quoted, grouped))
		case operand && owner == "community":
			continue
		case operand && quoted != nil && quoted[j]:
			return thenAt, -1, fmt.Errorf("%s: the quoted \"from\" fills the operand slot of "+
				"\"then %s\", so it could be that value or the term's match clause (#12516); "+
				"write the match clause as an unquoted from after the complete action",
				joinKeysProvGrouped(path, quoted, grouped), owner)
		}
		return thenAt, j, nil
	}
	return thenAt, -1, nil
}

// setPolicyTermThenFrom12516 replays a then-first policy term path as two
// ordinary set paths: the `from` clause on the term, then the actions. Each
// half keeps the quote and bracket provenance, and the closed bit, of the
// tokens it carries, so validation that reads provenance — the #11779
// unclosed-list refusal among it — sees the clause as authored.
func (t *ConfigTree) setPolicyTermThenFrom12516(path []string, quoted, grouped []bool, thenAt, fromAt int, closed ...bool) error {
	if err := t.SetPathQuotedGrouped(withoutSpan12516(path, thenAt, fromAt),
		withoutSpan12516(quoted, thenAt, fromAt), withoutSpan12516(grouped, thenAt, fromAt), closed...); err != nil {
		return err
	}
	return t.SetPathQuotedGrouped(path[:fromAt], headSpan12516(quoted, fromAt), headSpan12516(grouped, fromAt), closed...)
}

// refusePolicyTermThenFromEdit12516 refuses delete, deactivate, and activate
// of a then-first policy term line that carries a `from` clause. SetPath
// stores the line as two statements, so it names no single node. Applying
// the verb to both halves would not mean the line either: a chained action
// such as `metric 10 accept` reaches only its last link, which would leave a
// match-all `set metric` behind. A line SetPath refuses outright is refused
// here too. Either way the verb fails before any mutation, and the error names
// what to address instead. The verbs carry no quote provenance, so every
// unbracketed `from` reads as written unquoted.
func refusePolicyTermThenFromEdit12516(verb string, path []string, grouped []bool) error {
	_, fromAt, err := policyTermThenFromSplit12516(path, nil, grouped)
	if err != nil {
		return fmt.Errorf("%s %w", verb, err)
	}
	if fromAt < 0 {
		return nil
	}
	return fmt.Errorf("%s %s: a then-first policy term line with a from clause is stored as "+
		"separate from and then statements (#12516), so it names no single statement; %s the "+
		"term, or its from and then statements, instead",
		verb, joinKeysProvGrouped(path, nil, grouped), verb)
}

// withoutSpan12516 returns s without s[from:to] in a new slice; a nil s, an
// absent provenance mask, stays nil.
func withoutSpan12516[T any](s []T, from, to int) []T {
	if s == nil {
		return nil
	}
	out := make([]T, 0, len(s)-(to-from))
	out = append(out, s[:from]...)
	return append(out, s[to:]...)
}

// headSpan12516 returns s[:n]; a nil s stays nil.
func headSpan12516[T any](s []T, n int) []T {
	if s == nil {
		return nil
	}
	return s[:n]
}
