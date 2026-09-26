package eventengine

import (
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/rpm"
)

// evaluate.go — EVENT EVALUATION (#7636, split out of engine.go).
//
// Which policies a raw event triggers, and why. The within-clause semantics
// (#3751, #3756, #7223, #4423) are a body of rules that reads as one subject
// and was previously separated from itself by the worker and lifecycle code.
//
// LOCK ORDER: everything here runs under e.mu, the evaluation/runtime lock.
// e.mu and enqueueMu (queue.go) are NEVER NESTED — nothing in this file may
// call into queue admission while holding e.mu. See the matching note in
// queue.go and on the Engine struct in engine.go.

// maxThenCommands bounds clone-and-stamp work for each remediation batch.
const maxThenCommands = 8

// classifyPlan pre-parses a policy's ThenCommands into a typed plan WITHOUT
// touching the candidate (#2139 step 1). An unknown command prefix, an
// unparseable set, or an unparseable delete makes the WHOLE plan invalid
// (ok=false) — the cheapest place to reject (no lock taken, no queue slot).
func (e *Engine) classifyPlan(pol *config.EventPolicy) ([]plannedOp, bool) {
	if len(pol.ThenCommands) > maxThenCommands {
		slog.Warn("event-options: remediation batch exceeds command limit",
			"policy", pol.Name, "commands", len(pol.ThenCommands), "limit", maxThenCommands)
		return nil, false
	}
	ops := make([]plannedOp, 0, len(pol.ThenCommands))
	for _, cmd := range pol.ThenCommands {
		cmd = strings.TrimSpace(cmd)
		if cmd == "" {
			continue
		}
		switch {
		case strings.HasPrefix(cmd, "set "):
			input := strings.TrimPrefix(cmd, "set ")
			// Validate it parses now so a typo rejects the batch before any
			// candidate mutation. The parsed path also labels security changes
			// for the worker's critical queue lane.
			path, err := config.ParseSetCommand("set " + input)
			if err != nil {
				slog.Warn("event-options: set parse failed (batch rejected)",
					"policy", pol.Name, "cmd", cmd, "err", err)
				return nil, false
			}
			ops = append(ops, plannedOp{setInput: input, critical: criticalConfigPath(path), raw: cmd})
		case strings.HasPrefix(cmd, "delete "):
			input := strings.TrimPrefix(cmd, "delete ")
			path, err := config.ParseSetCommand("set " + input)
			if err != nil {
				slog.Warn("event-options: delete parse failed (batch rejected)",
					"policy", pol.Name, "cmd", cmd, "err", err)
				return nil, false
			}
			ops = append(ops, plannedOp{isDelete: true, delPath: path, critical: criticalConfigPath(path), raw: cmd})
		default:
			slog.Warn("event-options: unsupported command type (batch rejected)",
				"policy", pol.Name, "cmd", cmd)
			return nil, false
		}
	}
	return ops, true
}

// criticalConfigPath identifies configuration whose queued remediation gets
// priority over ordinary settings while preserving FIFO within each class.
func criticalConfigPath(path []string) bool {
	return len(path) > 0 && (path[0] == "security" || path[0] == "firewall")
}

// evaluateEvent checks policies under lock and returns any that should trigger.
// It records the event in the sliding window (pruning on append so a
// perpetually-cooldown-suppressed event can never grow unbounded — SMR finding
// 1) and CHECKS (does not arm) the cooldown; the cooldown is armed by the
// worker on a successful commit.
func (e *Engine) evaluateEvent(ev rpm.Event) []triggeredPolicy {
	e.mu.Lock()
	defer e.mu.Unlock()

	var triggered []triggeredPolicy
	now := e.now()
	// #4423 M6/M5: scan only the policies that list this event (index built at
	// Apply), not every policy on every event. The index guarantees the event
	// matches, so the per-policy eventMatches scan is gone; the remaining
	// per-matching-policy attributes/within work is inherent and bounded by the
	// pruned window.
	for _, pol := range e.eventIndex[ev.Name] {
		if pol == nil {
			continue
		}

		if !e.attributesMatch(pol, ev) {
			continue
		}

		rt := e.runtime[pol.Name]
		if rt == nil {
			// Defensive: Apply always seeds runtime for every policy, but a
			// policy could be evaluated before its first Apply in a test.
			rt = newPolicyRuntime()
			e.runtime[pol.Name] = rt
		}

		// Record this event, pruning the window on append so a suppressed
		// event cannot grow it unbounded (SMR finding 1).
		rt.windows[ev.Name] = append(rt.windows[ev.Name], now)
		e.pruneWindow(pol, ev.Name, now)

		if !e.withinMatches(pol, rt, ev.Name, now) {
			continue
		}

		// Cooldown CHECK (armed on successful commit, not here): suppress a
		// re-trigger within the cooldown window so a flapping probe does not
		// flood the queue.
		if !rt.lastTrigger.IsZero() && now.Sub(rt.lastTrigger) < policyCooldown {
			continue
		}

		// #3756 M1: arm the edge latch for this crossing so a sustained
		// above-threshold level does not re-fire every cooldown. Set only
		// AFTER the cooldown check passed — a cooldown-suppressed crossing is
		// NOT treated as already-fired, so the next event past the cooldown
		// still fires. Cleared by withinMatches when the count drops back
		// below the trigger-on threshold (re-arm).
		if policyHasTriggerOn(pol) {
			rt.onLatched[ev.Name] = true
		}

		slog.Info("event-options policy triggered",
			"policy", pol.Name,
			"event", ev.Name,
			"test-owner", ev.TestOwner,
			"test-name", ev.TestName)

		// Capture the semantic revision and config order under the same lock.
		// The order lets HandleEvent rotate the global budget across policies
		// instead of repeatedly favoring the first matching actions.
		triggered = append(triggered, triggeredPolicy{
			pol: pol, semRev: e.semRev[pol.Name], order: e.policyOrder[pol.Name],
		})
	}
	return triggered
}

// attributesMatch checks if the event attributes match the policy's filters.
// Format: "ping_test_failed.test-owner matches <pattern>".
//
// Junos `attributes-match ... matches ...` semantics are a REGEX match, not
// literal equality (this was a parity defect, #2008 M7). The operator's
// pattern is treated as an RE2 regular expression compiled once at Apply()
// time and cached here.
//
// #2141 FAIL-CLOSED: a malformed line (no " matches " / no ".") or an unknown
// <field> name is rejected at commit (config.ValidateEventAttributesMatchStrict),
// so it can only reach here on the legacy lenient-LOAD path (a config persisted
// by an older binary). In that case the matcher fails CLOSED — the policy does
// NOT trigger — rather than dropping the constraint and broadening the policy
// (the dangerous direction per #2124). This is a behavior change for legacy
// typo'd configs: they now STOP firing rather than over-fire, and are surfaced
// by the boot-time lenient-compile warning plus the AttributesInvalid counter.
func (e *Engine) attributesMatch(pol *config.EventPolicy, ev rpm.Event) bool {
	for _, attr := range pol.AttributesMatch {
		eventName, field, pattern, ok := config.ParseEventAttributesMatch(attr)
		if !ok {
			// Malformed line that slipped through a lenient load: fail closed.
			e.flagAttributesInvalid(pol.Name, attr, "malformed match expression")
			return false
		}

		// #3753: the constraint is scoped to a specific event name. Only apply
		// it when the CURRENT event IS that event; a constraint written for a
		// DIFFERENT event of a multi-event policy must NOT gate this event
		// (before this the prefix was dropped, so `event_a.test-owner ...`
		// incorrectly gated event_b too — and vice-versa). Commit-time
		// validation guarantees eventName is one of the policy's events, so an
		// out-of-scope prefix here can only be a legacy lenient-load config.
		if eventName != ev.Name {
			continue
		}

		if !config.EventAttributesFieldKnown(field) {
			// Unknown field that slipped through a lenient load: fail closed.
			e.flagAttributesInvalid(pol.Name, attr, "unknown field")
			return false
		}

		var value string
		switch field {
		case "test-owner":
			value = ev.TestOwner
		case "test-name":
			value = ev.TestName
		case "target":
			value = ev.Target
		case "routing-instance":
			value = ev.RoutingInstance
		case "destination-interface":
			value = ev.DestinationInterface
		default:
			// Known to config but not yet resolvable on rpm.Event. The SSOT
			// and this switch are kept identical by a drift-guard test, so
			// this is unreachable; fail closed if it is ever hit.
			e.flagAttributesInvalid(pol.Name, attr, "unresolvable field")
			return false
		}

		re := e.regexCache[pattern]
		if re == nil {
			// Defensive: pattern was not cached (commit validation should
			// have rejected an uncompilable pattern, and Apply caches every
			// valid one). Compile on demand; an uncompilable pattern fails
			// the constraint CLOSED (the policy does not fire).
			compiled, err := regexp.Compile(pattern)
			if err != nil {
				e.flagAttributesInvalid(pol.Name, attr, "uncompilable pattern")
				return false
			}
			re = compiled
			// #4423 M10: back-fill the cache so a pattern that slipped past the
			// Apply-time build (legacy lenient-load path) is compiled ONCE, not
			// on every event. Production callers reach here under e.mu, which
			// also guards the Apply-time rebuild, so the write is serialized.
			if e.regexCache == nil {
				e.regexCache = make(map[string]*regexp.Regexp)
			}
			e.regexCache[pattern] = re
		}

		if !re.MatchString(value) {
			return false
		}
	}
	return true
}

// flagAttributesInvalid bumps the counter and emits a throttled warning when a
// malformed/unknown attributes-match line is hit at runtime (#2141). The
// throttle is PER POLICY (#4423 M11): a flapping bad line on one policy must
// not swallow the first warning about a distinct bad line on another policy.
func (e *Engine) flagAttributesInvalid(policy, attr, reason string) {
	e.counters.attributesInvalid.Add(1)
	now := e.now().UnixNano()
	e.invalidWarnMu.Lock()
	if e.invalidWarnAt == nil {
		e.invalidWarnAt = make(map[string]int64)
	}
	last := e.invalidWarnAt[policy]
	warn := last == 0 || now-last >= int64(10*time.Second)
	if warn {
		e.invalidWarnAt[policy] = now
	}
	e.invalidWarnMu.Unlock()
	if warn {
		slog.Warn("event-options: attributes-match invalid, policy fails closed (will not fire)",
			"policy", policy, "line", attr, "reason", reason)
	}
}

// policyHasTriggerOn reports whether the policy carries any `within { trigger
// on N }` clause. Only such a policy participates in the #3756 M1 edge latch;
// a no-within policy (or a `trigger until` policy) is unaffected.
func policyHasTriggerOn(pol *config.EventPolicy) bool {
	for _, wc := range pol.WithinClauses {
		if wc != nil && wc.TriggerOn > 0 {
			return true
		}
	}
	return false
}

// withinMatches evaluates temporal trigger clauses against the policy's runtime
// window.
// "within N { trigger on M }" — fires when M events happen within N seconds.
// "within N { trigger until M }" — fires until M events happen within N seconds, then stops.
//
// MULTIPLE within clauses are combined with AND (#4423 M3): the policy fires
// only when EVERY within clause passes for this event. A policy that wants
// OR-of-conditions must be written as separate policies. This AND semantics is
// the documented contract (pkg/eventengine/README.md) and is covered by
// TestWithinMultipleClausesAreANDed.
//
// The body is three passes over the clause list rather than one fused loop, so
// no verdict depends on the order the operator wrote the clauses in — see the
// #7223 note on pass 2. One deliberate ordering delta survives: a policy that
// carries BOTH a structurally invalid clause (rejected by pass 1) and a
// below-threshold trigger-on clause no longer clears the edge latch, where the
// fused loop did if the below-threshold clause came first. Such a policy fails
// closed on every event for as long as the invalid clause exists, so the
// latch's value is unobservable until the config is corrected — after which the
// next below-threshold event re-arms it through the normal path.
func (e *Engine) withinMatches(pol *config.EventPolicy, rt *policyRuntime, eventName string, now time.Time) bool {
	if len(pol.WithinClauses) == 0 {
		return true // no temporal filter
	}
	// #9916 F-135: a nil entry in a non-empty clause list is malformed config
	// (missing is len==0 above, which means "no filter"), so fail CLOSED like
	// the #3751 belt below — never treat it as absent (that would silently drop
	// a threshold gate and broaden an autonomous remediation fail-open). No
	// reachable producer today (the compiler always appends non-nil); this is
	// defense-in-depth for a future producer or corrupt ingress.
	for _, wc := range pol.WithinClauses {
		if wc == nil {
			return false
		}
	}

	timestamps := rt.windows[eventName]

	// PASS 1 — structural validity, over every clause.
	//
	// #3751 defense-in-depth: a within clause with no USABLE positive
	// threshold (both trigger on/until absent or <= 0) — or a non-positive
	// window — must fail CLOSED, not always-fire. Commit-time validation
	// (config.validateEventOptionsWithinAST) rejects such a clause outright,
	// so this belt only fires on a config that slipped through a TOLERANT
	// load / peer-sync path (an older binary silently coerced a within/
	// trigger typo to 0). Falling through to `return true` here would treat
	// that mis-arrived 0 as an unconditional match — turning a threshold-
	// gated remediation into an ALWAYS-FIRE one, the original fail-open. A
	// policy with NO within clauses at all is handled above (return true) —
	// that legitimately means "no temporal filter"; this guard is only for
	// a within clause that exists but gates nothing.
	for _, wc := range pol.WithinClauses {
		if _, ok := withinWindow(wc.Seconds); !ok {
			return false
		}
		if wc.TriggerOn <= 0 && wc.TriggerUntil <= 0 {
			return false
		}
	}

	counts := make([]int, len(pol.WithinClauses))
	for i, wc := range pol.WithinClauses {
		window, _ := withinWindow(wc.Seconds)
		for _, ts := range timestamps {
			if now.Sub(ts) <= window {
				counts[i]++
			}
		}
	}

	// PASS 2 — the "trigger on N" edge latch, decided over EVERY trigger-on
	// clause before anything returns.
	//
	// "trigger on N" is EDGE-triggered (#3756 M1): it fires on the threshold
	// CROSSING, not on every event while the level stays at or above N. Junos
	// `trigger on` re-arms only after the count drops back below N; the 30s
	// cooldown alone only THROTTLES a sustained level (re-remediating it every
	// cooldown), which is harmful for a non-idempotent then-batch and spams
	// commit/rollback history.
	//
	// #7223: the re-arm and the latch check are two separate passes
	// over the clause list, and that separation IS the fix. The single fused
	// loop this replaces returned false from inside the walk, so with more
	// than one `within { trigger on N }` clause the outcome depended on the
	// order the operator wrote them in. Clauses are ANDed (below), so consider
	// `within 600 { trigger on 10 }` written BEFORE `within 60 { trigger on 3 }`
	// with the policy already latched: the 600s clause is still at/above 10, so
	// it hit the latch check and returned — and the 60s clause, which had
	// dropped below 3 and was the one that should have RE-ARMED the latch, was
	// never reached. The AND became false and then true again (a real crossing)
	// and the policy stayed silent until the long window decayed. Written in
	// the other order the same config re-arms correctly. Deciding the re-arm
	// across all clauses first makes the result independent of clause order:
	// the latch clears exactly when the ANDed condition is false, which is
	// exactly when any trigger-on clause is below its threshold.
	belowTriggerOn := false
	hasTriggerOn := false
	for i, wc := range pol.WithinClauses {
		if wc.TriggerOn <= 0 {
			continue
		}
		hasTriggerOn = true
		if counts[i] < wc.TriggerOn {
			belowTriggerOn = true
		}
	}
	if belowTriggerOn {
		// Dropped below the threshold: re-arm so the next crossing fires again.
		rt.onLatched[eventName] = false
		return false
	}
	if hasTriggerOn && rt.onLatched[eventName] {
		// Level still at/above N on every clause and this crossing already
		// fired: suppress until some clause's count drops below its threshold
		// (re-arm above). evaluateEvent sets the latch only AFTER the cooldown
		// check passes, so a cooldown-suppressed crossing is not consumed.
		return false
	}

	// PASS 3 — "trigger until N".
	//
	// "trigger until N" fires through the INCLUSIVE N-th event, then stops
	// (#3756 M2). Junos reads it as "trigger UNTIL the event has been received
	// N times" — the N-th occurrence is the LAST that fires. The event is
	// appended to the window BEFORE this check (evaluateEvent), so the N-th
	// matching event already makes count==N; using `>=` here made count==N
	// return false, so the N-th never fired and `until 1` (count==1 on the
	// first event) could NEVER fire at all — a dead-config bug. `>` fires on
	// 1..N and stops at N+1.
	for i, wc := range pol.WithinClauses {
		if wc.TriggerUntil > 0 && counts[i] > wc.TriggerUntil {
			return false
		}
	}

	return true
}

// pruneWindow removes timestamps older than the policy's maximum within window
// (or a 60s default). Called on every append so a cooldown-suppressed event
// can never grow the window unbounded (SMR finding 1).
func (e *Engine) pruneWindow(pol *config.EventPolicy, eventName string, now time.Time) {
	rt := e.runtime[pol.Name]
	if rt == nil {
		return
	}

	maxWindow := time.Duration(0)
	for _, wc := range pol.WithinClauses {
		// #9916 F-135: a nil clause contributes nothing to retention (mirrors
		// the out-of-range continue below) — the window falls through to the
		// 60s default rather than panicking. withinMatches already fails the
		// policy closed; prune must still handle its siblings' history.
		if wc == nil {
			continue
		}
		// An out-of-range clause contributes NOTHING to the retention window,
		// so maxWindow falls through to the 60s default below rather than to a
		// wrapped one (#8597). Retaining 60s of history for a clause the
		// evaluator refuses to fire on is the conservative direction: the
		// alternative, a wrapped sub-second maxWindow, silently discards every
		// timestamp for EVERY event this policy watches — including the
		// well-formed clauses beside it.
		w, ok := withinWindow(wc.Seconds)
		if !ok {
			continue
		}
		if w > maxWindow {
			maxWindow = w
		}
	}
	if maxWindow == 0 {
		maxWindow = 60 * time.Second
	}

	timestamps := rt.windows[eventName]
	pruned := timestamps[:0]
	for _, ts := range timestamps {
		if now.Sub(ts) <= maxWindow {
			pruned = append(pruned, ts)
		}
	}
	// #4423 M4: the in-place compaction above reuses the SAME backing array, so
	// its capacity stays pinned at the burst high-water mark forever — a single
	// storm of a rapidly-flapping probe permanently retains that memory even
	// after the window drains back to a handful of entries. When the retained
	// capacity dwarfs the live length, copy into a right-sized slice so the old
	// backing array can be collected. The threshold keeps steady-state churn
	// cheap (no realloc for a window oscillating near its typical size).
	if cap(pruned) >= 64 && cap(pruned) > 4*len(pruned) {
		shrunk := make([]time.Time, len(pruned))
		copy(shrunk, pruned)
		pruned = shrunk
	}
	rt.windows[eventName] = pruned
}

// withinWindow converts a within clause's `Seconds` to a Duration, reporting
// whether the value is inside the range the config layer promises.
//
// #8597 (muse-004 K35). `within <seconds>` is bounded to
// [config.MinEventWithinSeconds, config.MaxEventWithinSeconds] by
// config.validateEventOptionsWithinAST, and that file's own comment notes the
// 24h ceiling is what keeps `Seconds * time.Second` inside int64 nanoseconds.
// But the bound is enforced on the STRICT commit path only: the lenient
// HA-sync / on-disk Load ingress downgrades an out-of-range clause to a warning
// and the compiler stores the raw strconv.Atoi int (compiler_services.go), so
// a peer-synced or persisted value arrives here unbounded — the same ingress
// the #3751 belt three lines up already exists for.
//
// What the wrap does, and why the existing `<= 0` guard cannot see it: the
// multiply overflows past ~9.2e9 seconds and the residue can be small and
// POSITIVE (gcd(1e9, 2^64) = 512, so the residues are 512ns multiples). Every
// `now.Sub(ts) <= window` comparison then fails, all counts land at 0, and the
// consequence SPLITS by clause shape:
//
//   - trigger-until N: `counts[i] > TriggerUntil` is `0 > N` — false, so the
//     clause PASSES and the policy fires on EVERY event. Event-options is the
//     self-mutating surface (its actions run `set` and `commit`), so this is an
//     unauthorized remediation loop, throttled only by the 30s cooldown. This
//     is the #3751 always-fire class arriving through a numeric path.
//   - trigger-on N: `counts[i] < TriggerOn` — the policy never fires, a dead
//     remediation.
//
// Returning !ok makes both halves fail CLOSED, which is the direction the
// #3751 belt already chose for the same ingress.
func withinWindow(seconds int) (time.Duration, bool) {
	if seconds < config.MinEventWithinSeconds || seconds > config.MaxEventWithinSeconds {
		return 0, false
	}
	return time.Duration(seconds) * time.Second, true
}
