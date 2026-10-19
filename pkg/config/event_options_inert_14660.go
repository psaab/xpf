package config

import (
	"fmt"
	"sort"
	"strings"
)

// event_options_inert_14660.go carries the #14660 closed-world gate for
// event-options policies: event names the engine can never fire and
// actions / children it can never execute must not commit silently.
//
// Producer/consumer census (origin/master at filing):
//   - pkg/rpm/rpm.go fireEvent is the ONLY producer wired to
//     eventengine.HandleEvent (pkg/daemon/daemon_apply_tail.go), and it
//     emits exactly three names: ping_probe_failed, ping_test_failed,
//     ping_test_completed.
//   - pkg/eventengine executes only `then change-configuration` commands
//     (classifyPlan / runAction); every other Junos `then` action
//     (execute-commands, raise-trap, event-script, ignore,
//     generate-event, ...) is dropped by compileEventOptions, which has
//     no default arm.
//   - compileEventOptions likewise drops every policy child other than
//     events / within / attributes-match / plant-class / then, and every
//     event-options child other than `policy`.
//   - #15134: compileEventOptions reads only `commands` under
//     `change-configuration` (FindChildren("commands")); every other
//     child there (commit-options, user-name, retry, ...) is dropped.
//     The verify-only spelling is the dangerous one: an authored
//     `change-configuration { commit-options { check; } commands "..."; }`
//     intends "verify, do not activate", commits clean, and then
//     performs a LIVE commit when the policy fires.
//
// Before this gate all of the following committed with warnings=[] on
// both the strict (CheckText / CompileConfig) and flat-set paths, so
// remediation the operator believed was armed was silently inert:
//
//	event-options { policy p { events snmp_trap_link_down; } }
//	event-options { policy p { events PING_TEST_FAILED; } }
//	event-options { policy p { then { execute-commands { ... } } } }
//	event-options { bogus-child { ... } }
//
// Case matters: evaluateEvent indexes policies by exact ev.Name, so
// PING_TEST_FAILED never matches ping_test_failed.
//
// Strict (commit / commit-check): hard-reject naming the policy and the
// offending token. Lenient (load / peer-sync): warn so an already-
// persisted or peer-synced config an older binary accepted still BOOTS
// (#1960); the inert policy simply never fires / never executes, which
// is the pre-existing runtime behaviour, now surfaced.

// KnownEventNames is the single source of truth for event names the
// RPM producer can fire. Keep in sync with pkg/rpm fireEvent call
// sites; TestKnownEventNamesMatchesRPMProducers14660 asserts the two
// agree by scanning that file in the configstore suite (this package
// cannot import pkg/rpm without a cycle through daemon wiring docs —
// the rpm package imports pkg/config).
var KnownEventNames = map[string]struct{}{
	"ping_probe_failed":   {},
	"ping_test_failed":    {},
	"ping_test_completed": {},
}

// KnownEventNamesSorted returns the known event names in sorted order
// for diagnostics.
func KnownEventNamesSorted() []string {
	out := make([]string, 0, len(KnownEventNames))
	for k := range KnownEventNames {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// EventNameKnown reports whether name is an event the engine can fire.
func EventNameKnown(name string) bool {
	_, ok := KnownEventNames[name]
	return ok
}

// knownEventPolicyChildren are the policy children compileEventOptions
// consumes. Read from schemaEventOptions so a child declared later is
// permitted automatically (#9017 rule); fall back to this list only if
// the schema lookup fails.
var knownEventPolicyChildrenFallback = []string{
	"attributes-match", "events", "plant-class", "then", "within",
}

// knownEventThenChildren are the `then` children the engine executes.
var knownEventThenChildrenFallback = []string{"change-configuration"}

// knownEventChangeConfigChildren are the `change-configuration` children
// the engine executes (#15134). compileEventOptions reads ONLY `commands`
// under change-configuration; any other Junos child (commit-options,
// user-name, retry, ...) is dropped, so an authored
// `commit-options { check; }` (verify, do not activate) performs a LIVE
// commit when the policy fires.
var knownEventChangeConfigChildrenFallback = []string{"commands"}

func eventPolicyChildTokens14660() []string {
	pol := schemaEventOptions.children["policy"]
	if pol == nil || len(pol.children) == 0 {
		return append([]string(nil), knownEventPolicyChildrenFallback...)
	}
	out := make([]string, 0, len(pol.children))
	for k := range pol.children {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func eventThenChildTokens14660() []string {
	pol := schemaEventOptions.children["policy"]
	if pol == nil {
		return append([]string(nil), knownEventThenChildrenFallback...)
	}
	thenNode := pol.children["then"]
	if thenNode == nil || len(thenNode.children) == 0 {
		return append([]string(nil), knownEventThenChildrenFallback...)
	}
	out := make([]string, 0, len(thenNode.children))
	for k := range thenNode.children {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// eventChangeConfigChildTokens14660 reads the permitted
// `change-configuration` children from the schema (#9017 rule), so a
// child declared under change-configuration later is permitted
// automatically; falls back to `commands` only if the schema lookup fails.
func eventChangeConfigChildTokens14660() []string {
	pol := schemaEventOptions.children["policy"]
	if pol == nil {
		return append([]string(nil), knownEventChangeConfigChildrenFallback...)
	}
	thenNode := pol.children["then"]
	if thenNode == nil {
		return append([]string(nil), knownEventChangeConfigChildrenFallback...)
	}
	ccNode := thenNode.children["change-configuration"]
	if ccNode == nil || len(ccNode.children) == 0 {
		return append([]string(nil), knownEventChangeConfigChildrenFallback...)
	}
	out := make([]string, 0, len(ccNode.children))
	for k := range ccNode.children {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func eventOptionsChildTokens14660() []string {
	if len(schemaEventOptions.children) == 0 {
		return []string{"policy"}
	}
	out := make([]string, 0, len(schemaEventOptions.children))
	for k := range schemaEventOptions.children {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// validateEventOptionsInertAST walks every top-level `event-options`
// block on the group-expanded, inactive-pruned tree and rejects (strict)
// or warns (lenient) about:
//   - an event-options child other than `policy`
//   - a policy child compileEventOptions does not consume
//   - an `events` value outside KnownEventNames (exact, case-sensitive)
//   - a `then` child other than `change-configuration`
//   - a `change-configuration` child other than `commands` (#15134)
//
// It is an AST pre-walk (not a typed-*Config gate) because unknown
// children are gone by the time compileEventOptions has run — there is
// nothing left on EventPolicy to validate. Event names are still
// visible on the typed config, but checking them here keeps all four
// classes in one place with identical strict/lenient handling and
// covers both AST shapes uniformly via namedInstances/plainListValues,
// the same readers the compiler uses.
func validateEventOptionsInertAST(nodes []*Node, lenient bool) ([]string, error) {
	policyChildren := eventPolicyChildTokens14660()
	thenChildren := eventThenChildTokens14660()
	topChildren := eventOptionsChildTokens14660()
	changeConfigChildren := eventChangeConfigChildTokens14660()
	if len(policyChildren) == 0 || len(thenChildren) == 0 || len(topChildren) == 0 || len(changeConfigChildren) == 0 {
		return nil, nil
	}
	permittedPolicy := make(map[string]bool, len(policyChildren))
	for _, k := range policyChildren {
		permittedPolicy[k] = true
	}
	permittedThen := make(map[string]bool, len(thenChildren))
	for _, k := range thenChildren {
		permittedThen[k] = true
	}
	permittedTop := make(map[string]bool, len(topChildren))
	for _, k := range topChildren {
		permittedTop[k] = true
	}
	permittedChangeConfig := make(map[string]bool, len(changeConfigChildren))
	for _, k := range changeConfigChildren {
		permittedChangeConfig[k] = true
	}
	knownEvents := strings.Join(KnownEventNamesSorted(), ", ")

	var warnings []string
	seen := map[string]bool{}
	emit := func(format string, args ...any) error {
		msg := fmt.Sprintf(format, args...)
		if !lenient {
			return fmt.Errorf("%s", msg)
		}
		if !seen[msg] {
			seen[msg] = true
			warnings = append(warnings, msg)
		}
		return nil
	}

	err := forEachChild(nodes, "event-options", func(eo *Node) error {
		// Packed top-level tail: `event-options bogus ...` elided onto
		// the event-options node itself (Keys[1] is the child keyword).
		if len(eo.Keys) >= 2 {
			tok := eo.Keys[1]
			if tok != "" && !permittedTop[tok] && !routingInstanceApplyMetaKeyword9323(tok) {
				if err := emit("event-options: %q is not an event-options statement "+
					"xpf implements (known: %s) — it compiles to NOTHING: it commits clean, "+
					"renders in `show configuration`, and no event policy is created (#14660)",
					tok, strings.Join(topChildren, ", ")); err != nil {
					return err
				}
			}
		}
		for _, child := range eo.Children {
			if child == nil {
				continue
			}
			tok := child.Name()
			if tok == "" || tok == "policy" || routingInstanceApplyMetaKeyword9323(tok) {
				continue
			}
			if !permittedTop[tok] {
				if err := emit("event-options: %q is not an event-options statement "+
					"xpf implements (known: %s) — it compiles to NOTHING: it commits clean, "+
					"renders in `show configuration`, and no event policy is created (#14660)",
					tok, strings.Join(topChildren, ", ")); err != nil {
					return err
				}
			}
		}
		for _, pInst := range namedInstances(eo.FindChildren("policy")) {
			if err := validateEventPolicyInert14660(pInst.name, pInst.node, permittedPolicy, permittedThen, permittedChangeConfig, knownEvents, emit); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return warnings, nil
}

func validateEventPolicyInert14660(policy string, node *Node, permittedPolicy, permittedThen, permittedChangeConfig map[string]bool, knownEvents string, emit func(string, ...any) error) error {
	if node == nil {
		return nil
	}
	for _, child := range node.Children {
		if child == nil {
			continue
		}
		tok := child.Name()
		if tok == "" || routingInstanceApplyMetaKeyword9323(tok) {
			continue
		}
		if !permittedPolicy[tok] {
			if err := emit("event-options policy %q: %q is not an event-options policy statement "+
				"xpf implements (known: %s) — it compiles to NOTHING and the policy's "+
				"remediation never runs for it (#14660)",
				policy, tok, strings.Join(eventPolicyChildTokens14660(), ", ")); err != nil {
				return err
			}
			continue
		}
		switch tok {
		case "events":
			for _, ev := range plainListValues(child) {
				if !EventNameKnown(ev) {
					if err := emit("event-options policy %q: event %q is not an event "+
						"xpf can fire (known events: %s) — the policy will never trigger "+
						"on it; event names are case-sensitive (#14660)",
						policy, ev, knownEvents); err != nil {
						return err
					}
				}
			}
		case "then":
			for _, sub := range thenChildTokens14660(child) {
				if sub == "" || routingInstanceApplyMetaKeyword9323(sub) {
					continue
				}
				if !permittedThen[sub] {
					if err := emit("event-options policy %q then: %q is not an action "+
						"xpf executes (known: %s) — it compiles to NOTHING: the policy "+
						"may trigger, render in `show configuration`, and execute no "+
						"remediation (#14660)",
						policy, sub, strings.Join(eventThenChildTokens14660(), ", ")); err != nil {
						return err
					}
					continue
				}
				if sub != "change-configuration" {
					continue
				}
				// #15134: descend one more level. compileEventOptions
				// reads only `commands` under change-configuration; any
				// other child is dropped. The verify-only spelling is
				// the dangerous one (see header).
				for _, ccTok := range changeConfigChildTokens14660(child) {
					if ccTok == "" || routingInstanceApplyMetaKeyword9323(ccTok) {
						continue
					}
					if !permittedChangeConfig[ccTok] {
						if err := emit("event-options policy %q then change-configuration: %q is not a "+
							"change-configuration statement xpf implements (known: %s) — it compiles to "+
							"NOTHING: the policy may trigger and execute its commands as a LIVE commit, "+
							"ignoring the authored %q (#14660, #15134)",
							policy, ccTok, strings.Join(eventChangeConfigChildTokens14660(), ", "), ccTok); err != nil {
							return err
						}
					}
				}
			}
		}
	}
	return nil
}

// changeConfigChildTokens14660 returns the statement keywords one
// `change-configuration` node under this `then` carries, across both AST
// shapes (#15134). Mirrors thenChildTokens14660 one level down — a packed
// keyword wins and its Children are that keyword's BODY, not siblings:
//
//   - Bare `then` (Keys=[then]): the cc node is a CHILD. Braced
//     (`change-configuration { commit-options { check; } commands ...; }`)
//     -> Keys=[change-configuration], Children are the cc children.
//     Packed (`change-configuration user-name bob;` or
//     `change-configuration commit-options { check; }`)
//     -> Keys=[change-configuration <child> ...], Children (if any) are
//     the packed child's body — only Keys[1] is the child keyword.
//   - Packed `then` (Keys=[then change-configuration ...]): the cc body
//     lives on the then node. Braced (`then change-configuration {
//     commit-options ...; }`) -> Keys[2] absent, Children are the cc
//     children. Packed (`then change-configuration commands "...";` --
//     permitted; `then change-configuration junk-thing foo;` -- rejected)
//     -> Keys[2] is the child keyword; Children, if any, are its body.
//
// Only the child KEYWORD is returned; its value (e.g. `check` under
// commit-options) is never read, matching how compileEventOptions would
// have dropped the whole child.
func changeConfigChildTokens14660(thenNode *Node) []string {
	if thenNode == nil {
		return nil
	}
	if len(thenNode.Keys) >= 2 {
		// Packed then: change-configuration body lives on this node.
		if len(thenNode.Keys) >= 3 {
			return []string{thenNode.Keys[2]}
		}
		out := make([]string, 0, len(thenNode.Children))
		for _, ch := range thenNode.Children {
			if ch != nil && ch.Name() != "" {
				out = append(out, ch.Name())
			}
		}
		return out
	}
	var out []string
	for _, cc := range thenNode.FindChildren("change-configuration") {
		if cc == nil {
			continue
		}
		if len(cc.Keys) >= 2 {
			out = append(out, cc.Keys[1])
			continue
		}
		for _, ch := range cc.Children {
			if ch != nil && ch.Name() != "" {
				out = append(out, ch.Name())
			}
		}
	}
	return out
}

// thenChildTokens14660 returns the statement keywords one `then` node
// carries, across both AST shapes. A brace-elided
// `then execute-commands { ... }` packs the action on Keys[1] and its
// Children are that action's BODY; only a bare `then` node has Children
// that are actions. Mirrors dhcpRelayChildTokensOf9552.
func thenChildTokens14660(thenNode *Node) []string {
	if thenNode == nil {
		return nil
	}
	if len(thenNode.Keys) >= 2 {
		return []string{thenNode.Keys[1]}
	}
	var out []string
	for _, ch := range thenNode.Children {
		if ch != nil && ch.Name() != "" {
			out = append(out, ch.Name())
		}
	}
	return out
}
