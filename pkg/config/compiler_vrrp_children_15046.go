package config

import (
	"fmt"
	"sort"
	"strings"
)

// #15046 (A05-04) — vrrp-group was open-world at the compiler level: any
// child the compiler does not switch on (Junos `track { interface … }`,
// `no-preempt`, or plain garbage like `zzbogus`) committed clean with
// zero warnings and was silently dropped. In particular the Junos
// tracking container vanished, so the operator-authored failover trigger
// never reached VRRPGroup.TrackInterface and the master kept the VIP
// when the tracked uplink failed.
//
// This gate is the scoped AST pre-walk the fix direction requires
// ("close the vrrp-group schema — strict reject, lenient warn — for
// other children"). It is deliberately NOT `closedWorld: true` on the
// vrrp-group node: that flag INHERITS, and the schema walker consumes
// the group's own Keys run as an unvalidated identity span (so a
// Keys-packed `vrrp-group 1 zzbogus 1;` would still slip past it),
// while this gate sees every spelling — braced children, flat-set
// child chains (via expandFlatRun, the same view parseVRRPGroups
// reads), the Keys-packed run on the group node itself, and the
// Junos `track` container's inner level.
//
// The permitted set is READ FROM THE SCHEMA (vrrpGroupSchemaNode), so
// a child declared later is permitted automatically (#9017's rule).
// Junos `track` and `no-preempt` are declared there and compiled by
// parseVRRPGroups; everything else undeclared is rejected strict /
// warned lenient. Apply statements are skipped (Junos permits them at
// any hierarchy level, #7029). The diagnostic path is built from the
// group identity only (vrrpGroupIDKeys) so a Keys-packed
// authentication-key value can never leak into the message (#5195).

// vrrpGroupChildTokens15046 returns the sorted keywords the vrrp-group
// schema declares.
func vrrpGroupChildTokens15046() []string {
	return vrrpGroupChildTokensFrom(vrrpGroupSchemaNode(false))
}

// vrrpGroupChildTokens15046V6 returns the sorted keywords the Junos
// `vrrp-inet6-group` schema declares (the shared set plus
// `virtual-inet6-address`, #15199).
func vrrpGroupChildTokens15046V6() []string {
	return vrrpGroupChildTokensFrom(vrrpGroupSchemaNode(true))
}

func vrrpGroupChildTokensFrom(node *schemaNode) []string {
	if node == nil {
		return nil
	}
	out := make([]string, 0, len(node.children))
	for k := range node.children {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// vrrpTrackChildTokens15046 returns the sorted keywords declared under
// the Junos `track` container (just `interface`).
func vrrpTrackChildTokens15046() []string {
	node := vrrpGroupSchemaNode(false)
	if node == nil {
		return nil
	}
	track := node.children["track"]
	if track == nil {
		return nil
	}
	out := make([]string, 0, len(track.children))
	for k := range track.children {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// validateVRRPGroupChildrenAST15046 rejects (strict) or warns (lenient)
// on any vrrp-group child the schema does not declare. It also extends
// the #1814 track-shape checks to the Junos `track interface` spelling:
// the shared single-track slot, duplicate counting across spellings,
// and priority-cost range validation.
func validateVRRPGroupChildrenAST15046(nodes []*Node, prefix string, lenient bool) ([]string, error) {
	declared := vrrpGroupChildTokens15046()
	if len(declared) == 0 {
		return nil, nil
	}
	permitted := make(map[string]bool, len(declared))
	for _, tok := range declared {
		permitted[tok] = true
	}
	// #15199 (A05-07): the Junos `vrrp-inet6-group` alias permits the
	// v6-only `virtual-inet6-address` leaf in addition to the shared set.
	declared6 := vrrpGroupChildTokens15046V6()
	permitted6 := make(map[string]bool, len(declared6))
	for _, tok := range declared6 {
		permitted6[tok] = true
	}
	trackDeclared := vrrpTrackChildTokens15046()
	trackPermitted := make(map[string]bool, len(trackDeclared))
	for _, tok := range trackDeclared {
		trackPermitted[tok] = true
	}
	var warnings []string
	seen := map[string]bool{}
	report := func(idPath, tok string, knownSet []string) error {
		msg := fmt.Sprintf("%s: %q is not a vrrp-group statement xpf implements (known: %s) — it compiles to NOTHING: it commits clean, renders in `show configuration`, and has no effect (#15046)",
			idPath, tok, strings.Join(knownSet, ", "))
		if !lenient {
			return fmt.Errorf("%s", msg)
		}
		if !seen[msg] {
			seen[msg] = true
			warnings = append(warnings, msg)
		}
		return nil
	}
	var walk func(nodes []*Node, prefix string) error
	walk = func(nodes []*Node, prefix string) error {
		for _, n := range nodes {
			if n == nil || len(n.Keys) == 0 {
				continue
			}
			nodePath := joinNodePath(prefix, safeVRRPPathKeys(n))
			if n.Name() == "vrrp-group" {
				idPath := joinNodePath(prefix, vrrpGroupIDKeys(n))
				if err := checkVRRPGroupChildren15046(n, idPath, permitted, declared, trackPermitted, trackDeclared, report); err != nil {
					return err
				}
			}
			if n.Name() == "vrrp-inet6-group" {
				idPath := joinNodePath(prefix, vrrpGroupIDKeys(n))
				if err := checkVRRPGroupChildren15046(n, idPath, permitted6, declared6, trackPermitted, trackDeclared, report); err != nil {
					return err
				}
			}
			if err := walk(n.Children, nodePath); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(nodes, prefix); err != nil {
		return warnings, err
	}
	return warnings, nil
}

func checkVRRPGroupChildren15046(vg *Node, idPath string, permitted map[string]bool, declared []string, trackPermitted map[string]bool, trackDeclared []string, report func(string, string, []string) error) error {
	// Keys-packed run on the group node itself: tokens past the
	// identity (`vrrp-group <id>`) are property spellings. A token
	// that is not a declared property and not a declared property's
	// value position is unknown. Value positions are skipped using
	// the schema arity of the preceding property (mirroring how
	// parseVRRPGroups' Keys walk consumes values).
	keys := vg.Keys
	for i := 2; i < len(keys); i++ {
		tok := keys[i]
		if isApplyStatementKeyword(tok) {
			break
		}
		if !permitted[tok] {
			return report(idPath, tok, declared)
		}
		// Skip this property's value span. The v6 node is a superset of
		// the v4 leaf set, so one lookup covers both group spellings.
		if child := vrrpGroupSchemaNode(true).children[tok]; child != nil {
			i += child.args
			// A multi-value leaf (`virtual-address`, args=1, multi)
			// packs a whole bracketed list into the run: skip every
			// bracketed value token so the second address is not
			// misread as a group-level property (#15050). Mirror
			// parseVRRPGroups, which consumes the same run.
			if child.multi {
				for i+1 < len(keys) && vg.KeyBracketed(i+1) {
					i++
				}
			}
			// Container properties pack a nested keyword run
			// (e.g. `preempt hold-time 30`, `track interface
			// ge-0/0/1 priority-cost 150`): consume declared
			// nested keywords and their values so they are not
			// misread as group-level properties.
			i = consumePackedNested15046(keys, i, child)
		}
	}
	// Child-node spellings, in the same expanded view the compiler
	// reads (flat-set chains become one node per property). The v6 node
	// is a superset of the v4 leaf set (#15199), so one expansion covers
	// both group spellings.
	props := expandFlatRun(vg.Children, vrrpGroupSchemaNode(true))
	for _, prop := range props {
		if prop == nil || len(prop.Keys) == 0 {
			continue
		}
		tok := prop.Name()
		if isApplyStatementKeyword(tok) {
			continue
		}
		// Orphan `priority-cost` directly under the group is owned
		// by the #1814 shape gate (warn-only on both paths: "only
		// valid nested under track-interface; this statement has no
		// effect") — do not double-report it as unknown here.
		if tok == "priority-cost" {
			continue
		}
		if !permitted[tok] {
			if err := report(idPath, tok, declared); err != nil {
				return err
			}
			continue
		}
		if tok == "track" {
			if err := checkVRRPTrackContainer15046(prop, idPath, trackPermitted, trackDeclared, report); err != nil {
				return err
			}
		}
	}
	return nil
}

// consumePackedNested15046 advances past declared nested keywords in a
// Keys-packed container property run and returns the new index. Unknown
// nested tokens stop the scan (they stay attached to the container
// property, which the compiler drops — the closedWorld `track` /
// `track-interface` schema arms reject them on the strict commit path,
// and the group-level token after them, if any, is still judged by the
// caller's loop when it resumes).
func consumePackedNested15046(keys []string, i int, child *schemaNode) int {
	for i+1 < len(keys) {
		next := keys[i+1]
		nested, ok := child.children[next]
		if !ok {
			break
		}
		i++
		i += nested.args
		if len(nested.children) > 0 {
			i = consumePackedNested15046(keys, i, nested)
		}
	}
	return i
}

func checkVRRPTrackContainer15046(track *Node, idPath string, trackPermitted map[string]bool, trackDeclared []string, report func(string, string, []string) error) error {
	// Braced spelling: `track { interface …; zzbogus …; }` — children
	// are the container's statements. Keys-packed spelling
	// (`track interface ge-0/0/1 priority-cost 150;` as one statement)
	// packs the first keyword onto Keys[1]; its remaining tokens are
	// the interface value plus nested priority-cost, both declared.
	if len(track.Keys) >= 2 {
		tok := track.Keys[1]
		if !isApplyStatementKeyword(tok) && !trackPermitted[tok] {
			return report(idPath, tok, trackDeclared)
		}
		return nil
	}
	for _, ch := range track.Children {
		if ch == nil || len(ch.Keys) == 0 {
			continue
		}
		tok := ch.Name()
		if isApplyStatementKeyword(tok) {
			continue
		}
		if !trackPermitted[tok] {
			if err := report(idPath, tok, trackDeclared); err != nil {
				return err
			}
		}
	}
	return nil
}
