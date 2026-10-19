package config

import (
	"fmt"
	"strconv"
)

// event_options_within.go carries the #3751 strict commit-time numeric
// validation for an event-options policy `within <seconds> { trigger
// (on|until) <count>; }` clause.
//
// BEFORE this gate compileEventOptions (compiler_services.go) parsed the
// within time-interval and the trigger count with strconv.Atoi and SILENTLY
// DROPPED the error, leaving the field at its zero value. A typo therefore
// compiled cleanly: `within bogus { trigger on typo; }` became Seconds=0,
// TriggerOn=0, TriggerUntil=0. The engine's withinMatches then skipped both
// (> 0)-guarded trigger tests and returned true — the policy fired on EVERY
// matching event. A typo in a temporal gate silently converted a
// threshold-gated remediation (e.g. "only rewrite the default route after 4
// probe failures in 30s") into an UNCONDITIONAL one (fires on the first
// failure, forever) — the dangerous fail-open direction per the #2124
// doctrine. This gate folds:
//
//   - H11: non-numeric within / trigger count → was coerced to 0 → always-fire.
//   - H12: negative / absurdly-huge within → nonsensical window; a huge value
//     also risks a time.Duration overflow when multiplied by time.Second in
//     the engine (int64 ns overflows past ~9.2e9 s). The [1, 86400] cap
//     forecloses the overflow entirely.
//   - H13: a single within clause carrying BOTH `trigger on` and `trigger
//     until` — the compiler fills both fields and the engine ANDs them into a
//     narrow one-count band that is almost certainly unintended; it is never
//     surfaced as ambiguous.
//
// Like validateDNATRuleSetToScopeAST (#3444) this is an AST pre-walk, not a
// SchemaValidate typed leaf: the constraint spans a whole `within` clause (the
// seconds slot AND the nested trigger keyword/count AND the mutual exclusion of
// on/until), which a per-leaf validator cannot express, and SchemaValidate
// returns nil for keywords it does not know so it cannot REJECT a malformed
// trigger. The walk descends with forEachChild over EVERY top-level
// `event-options` block (the #3562 duplicate-block discipline — event-options
// is a top-level stanza and parseStatements appends a repeated block as a
// sibling). It runs on the group-expanded, inactive-pruned tree, so an
// apply-groups-inherited clause is validated and an `inactive:` clause is
// ignored for free.
//
// Strict path (commit / commit-check, lenient=false): the first offending
// clause is a hard compile error naming the policy and the exact value.
//
// Lenient path (load / peer-sync, lenient=true): every offending clause is
// returned as a warning and compilation continues (#1960 fail-closed-on-load
// doctrine) so an older-binary-persisted or peer-synced config that silently
// accepted a coerced-to-0 clause still BOOTS. On that legacy boot the engine's
// withinMatches fails CLOSED (does not fire) on a clause with no usable
// positive threshold — the mis-arrived 0 no longer over-fires (#3751
// defense-in-depth, pkg/eventengine/engine.go).

const (
	// MinEventWithinSeconds / MaxEventWithinSeconds bound a within
	// time-interval. The upper bound (24h) also caps the time.Duration
	// overflow window (H12): the engine multiplies Seconds by time.Second
	// (1e9 ns), which overflows int64 past ~9.2e9 s — 86400 is far below it.
	//
	// EXPORTED (#8597, muse-004 K35) because that overflow argument only holds
	// where this bound holds, and this bound is enforced on the STRICT commit
	// path alone: the lenient HA-sync / on-disk Load ingress downgrades an
	// out-of-range clause to a warning and keeps the raw int. The engine's
	// runtime belt therefore has to re-check the range, and it must re-check
	// it against THIS constant rather than a copied 86400 — two layers that
	// disagree about where the ceiling is would be the defect, not the fix.
	MinEventWithinSeconds = 1
	MaxEventWithinSeconds = 86400

	// minEventTriggerCount / maxEventTriggerCount bound a trigger event
	// count. A count is a number of matching events in the window; it is not
	// multiplied by a duration, so the upper bound is a sanity cap rather than
	// an overflow guard.
	minEventTriggerCount = 1
	maxEventTriggerCount = 1_000_000
)

// eventTriggerSpec is one parsed `on <count>` or `until <count>` under a
// within clause's `trigger` node.
type eventTriggerSpec struct {
	keyword  string // "on" or "until"
	count    string // the raw count token as authored
	hasCount bool   // false when the keyword carried no value token
}

// parseEventTriggerSpecs extracts every on/until spec from a `trigger` node,
// covering BOTH AST shapes compileEventOptions reads:
//
//   - hierarchical leaf: Keys = ["trigger", "on", "3"] (or a pathological
//     ["trigger", "on", "3", "until", "5"] / ["trigger", "on"] with no count).
//   - flat set:          Keys = ["trigger"], Children = [{Keys:["on","3"]}, …].
//
// It also returns any keyword token that is neither `on` nor `until` (e.g.
// Junos's unsupported `trigger after`) so the caller can reject it rather than
// let the compiler silently drop it (→ TriggerOn/Until stay 0 → always-fire).
func parseEventTriggerSpecs(trigNode *Node) (specs []eventTriggerSpec, unknown []string) {
	// Hierarchical leaf form: keyword/value pairs after the "trigger" key.
	keys := trigNode.Keys
	for i := 1; i < len(keys); {
		kw := keys[i]
		if kw == "on" || kw == "until" {
			if i+1 < len(keys) {
				specs = append(specs, eventTriggerSpec{keyword: kw, count: keys[i+1], hasCount: true})
				i += 2
			} else {
				specs = append(specs, eventTriggerSpec{keyword: kw})
				i++
			}
			continue
		}
		unknown = append(unknown, kw)
		i++
	}

	// Flat set form: each child is a keyword node with the count as its value.
	for _, ch := range trigNode.Children {
		if len(ch.Keys) == 0 {
			continue
		}
		kw := ch.Keys[0]
		if kw != "on" && kw != "until" {
			unknown = append(unknown, kw)
			continue
		}
		if v := nodeVal(ch); v != "" {
			specs = append(specs, eventTriggerSpec{keyword: kw, count: v, hasCount: true})
		} else {
			specs = append(specs, eventTriggerSpec{keyword: kw})
		}
	}
	return specs, unknown
}

// validateEventOptionsWithinAST walks the `event-options policy <name> within`
// subtree of the group-expanded AST and validates each within clause's
// time-interval and trigger count numerics. See the file header for the fail-
// open class this closes and the strict/lenient split.
func validateEventOptionsWithinAST(nodes []*Node, lenient bool) ([]string, error) {
	var warnings []string
	emit := func(format string, args ...any) error {
		msg := fmt.Sprintf(format, args...)
		if !lenient {
			return fmt.Errorf("%s", msg)
		}
		warnings = append(warnings, msg)
		return nil
	}

	// forEachChild descends EVERY top-level event-options block (the #3562
	// duplicate-block discipline) so a within clause in a second appended
	// event-options {} is not bypassed.
	err := forEachChild(nodes, "event-options", func(eo *Node) error {
		for _, pInst := range namedInstances(eo.FindChildren("policy")) {
			for _, w := range pInst.node.FindChildren("within") {
				if err := validateEventWithinClause(pInst.name, w, emit); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return warnings, nil
}

// validateEventWithinClause validates one `within <seconds> { trigger … }`
// clause. emit returns a non-nil error on the strict path (stopping the walk)
// and accumulates a warning on the lenient path (continuing).
func validateEventWithinClause(policy string, w *Node, emit func(string, ...any) error) error {
	// within time-interval — always the second key (nodeVal's child fallback
	// would mis-read the `trigger` child as the value, so read Keys[1]
	// directly).
	secTok := ""
	if len(w.Keys) >= 2 {
		secTok = w.Keys[1]
	}
	if secTok == "" {
		return emit("event-options policy %q within clause: missing time-interval "+
			"<seconds> value", policy)
	}
	sec, err := strconv.Atoi(secTok)
	if err != nil {
		return emit("event-options policy %q within %q: time-interval is not a "+
			"valid integer (expected %d..%d seconds)",
			policy, secTok, MinEventWithinSeconds, MaxEventWithinSeconds)
	}
	if sec < MinEventWithinSeconds || sec > MaxEventWithinSeconds {
		return emit("event-options policy %q within %d: time-interval out of range "+
			"(expected %d..%d seconds)",
			policy, sec, MinEventWithinSeconds, MaxEventWithinSeconds)
	}

	// trigger — a within clause with no trigger gates nothing; the engine
	// would treat it as an unconditional match (fail-open), so require one.
	//
	// #15205 (residual of #6771): read EVERY `trigger` sibling, not just the
	// first. compileEventOptions applies all siblings last-wins
	// (FindChildren("trigger")), so validating only FindChild("trigger") let
	// an invalid or contradictory later sibling commit clean — the compiler
	// silently dropped its bad count or filled the contradictory field from
	// it. Aggregating every sibling's specs subjects the later siblings to
	// exactly the same checks (unknown keyword, both-on-and-until, count
	// range) as if they had been packed into the first sibling, while a
	// same-keyword valid re-set still passes and keeps its #6771 last-wins
	// compiled value.
	trigNodes := w.FindChildren("trigger")
	if len(trigNodes) == 0 {
		return emit("event-options policy %q within %d: missing a `trigger on|until "+
			"<count>` (a within clause with no trigger gates nothing)",
			policy, sec)
	}

	var specs []eventTriggerSpec
	var unknown []string
	for _, trigNode := range trigNodes {
		s, u := parseEventTriggerSpecs(trigNode)
		if len(s) == 0 && len(u) == 0 {
			// A bare `trigger;` sibling carries no spec at all: reject it
			// exactly as a lone empty trigger is rejected below, rather
			// than letting an earlier valid sibling mask it.
			return emit("event-options policy %q within %d: trigger requires `on` or "+
				"`until` with a <count>", policy, sec)
		}
		specs = append(specs, s...)
		unknown = append(unknown, u...)
	}
	for _, kw := range unknown {
		return emit("event-options policy %q within %d: unknown trigger keyword %q "+
			"(expected `on` or `until`)", policy, sec, kw)
	}
	if len(specs) == 0 {
		return emit("event-options policy %q within %d: trigger requires `on` or "+
			"`until` with a <count>", policy, sec)
	}

	var haveOn, haveUntil bool
	for _, s := range specs {
		switch s.keyword {
		case "on":
			haveOn = true
		case "until":
			haveUntil = true
		}
	}
	if haveOn && haveUntil {
		// H13: on and until on one clause AND to a narrow one-count band in
		// the engine — almost certainly unintended, never surfaced.
		return emit("event-options policy %q within %d: trigger specifies both "+
			"`on` and `until` (contradictory) — use exactly one", policy, sec)
	}

	for _, s := range specs {
		if !s.hasCount || s.count == "" {
			return emit("event-options policy %q within %d: trigger %s requires a "+
				"<count> value", policy, sec, s.keyword)
		}
		n, err := strconv.Atoi(s.count)
		if err != nil {
			return emit("event-options policy %q within %d: trigger %s %q count is "+
				"not a valid integer (expected %d..%d)",
				policy, sec, s.keyword, s.count, minEventTriggerCount, maxEventTriggerCount)
		}
		if n < minEventTriggerCount || n > maxEventTriggerCount {
			return emit("event-options policy %q within %d: trigger %s %d count out "+
				"of range (expected %d..%d)",
				policy, sec, s.keyword, n, minEventTriggerCount, maxEventTriggerCount)
		}
	}

	return nil
}
