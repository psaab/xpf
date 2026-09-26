package eventengine

import (
	"log/slog"
)

// queue.go — ACTION QUEUE ADMISSION (#7636, split out of engine.go).
//
// A self-contained bounded-channel admission policy: what gets queued, what
// supersedes what, and what happens to a remediation that cannot be admitted.
// Its concurrency contract is its own — #5062 producer serialization, #5853
// early dedup, #2869 FIFO ordering, #6810 the admission verdict and the edge
// latch that depends on it.
//
// LOCK ORDER, and it is the reason this split is safe to make at all:
// e.mu (evaluation and runtime state, engine.go / evaluate.go) and enqueueMu
// (admission, this file) are NEVER NESTED. enqueue returns before anything
// takes e.mu, which is what lets releaseEdgeLatch below take e.mu at all —
// #6810's latch rollback would deadlock against a held enqueueMu.
//
// Splitting these into separate files makes that invariant easier to violate
// by accident, because the two locks are no longer visible on one screen. It
// is therefore stated on BOTH sides: see the matching note in engine.go on the
// Engine struct.

// actionQueueDepth bounds the worker's pending-action channel. Dedup-by-policy
// (a newer trigger supersedes an older queued one) keeps at most one pending
// action per policy, so this is also an upper bound on distinct policies with
// a remediation in flight while the config lock is held.
//
// #5853: dedup runs on EVERY enqueue, not only when full. A flapping policy's
// same-policy burst is a benign replacement rather than 64 redundant slots that
// can starve an unrelated policy into a queue-full drop.
const actionQueueDepth = 64

// enqueue adds an action with dedup-by-policy. A critical security/firewall
// mutation enters ahead of ordinary queued work; FIFO remains stable within
// both classes. When the queue is full, a critical action displaces the newest
// ordinary action so it can still enter the bounded queue.
//
// A displaced action is a real capacity loss, not a supersede. Its edge latch is
// released after enqueueMu is dropped so that the policy can retry on a fresh
// event (#6810). The new critical action remains admitted.
//
// The whole body runs under enqueueMu (#5062) so concurrent producers cannot
// interleave supersede's drain-and-refill. #5062 closed the drain/steal window:
// without producer serialization, a second enqueue could take a drain-freed
// slot and force an already-accepted survivor to drop during refill. The worker
// remains a remove-only consumer, so the serialized refill cannot lose survivors.
//
// #6810: evaluation arms an edge latch before admission. A false verdict means
// no equivalent action will run, so the caller rolls that latch back; a
// same-policy replacement is admitted because its newer action still runs.
// Critical displacement is a real capacity loss, so enqueue releases the
// displaced action's latch only after enqueueMu is dropped.
//
// enqueue reports whether the action now has a queued equivalent. The caller
// rolls back the current action's latch when admission fails; enqueue handles
// the latch for any displaced ordinary action after releasing enqueueMu.
func (e *Engine) enqueue(a plannedAction) bool {
	e.enqueueMu.Lock()
	select {
	case <-e.stopCh:
		e.enqueueMu.Unlock()
		return false
	default:
	}
	admitted, evicted, hasEvicted := e.supersede(a)
	e.enqueueMu.Unlock()
	if hasEvicted {
		e.releaseEdgeLatch(evicted.policyName, evicted.event, evicted.semRev)
		slog.Warn("event-options: critical remediation displaced queued action",
			"policy", evicted.policyName, "critical-policy", a.policyName)
	}
	if admitted {
		return true
	}
	e.counters.droppedQueueFull.Add(1)
	slog.Warn("event-options: action queue full, dropping remediation",
		"policy", a.policyName)
	return false
}

// releaseEdgeLatch clears the edge latch for a queue-capacity loss. The action
// may have been rejected immediately or displaced by critical queued work.
//
// evaluateEvent arms the latch under e.mu and returns; HandleEvent classifies
// and enqueues afterwards, outside that lock. If the queue is full of OTHER
// policies' actions the remediation is dropped — and because withinMatches
// suppresses every later at/above-threshold event while the latch is armed, and
// only re-arms when a clause's count falls BELOW its threshold, a transient
// queue saturation permanently consumed the crossing. For a sustained fault the
// level never drops, so the configured remediation simply never ran.
//
// Rolling the latch back restores the invariant the latch is supposed to
// express: "this crossing already fired". A crossing whose action was dropped
// did not fire.
//
// authRev is the policy's semantic revision as of the evaluate that armed the
// latch, and the guard is the same ABA defence armCooldown uses (#5311): if a
// successor generation was installed (or the policy removed) while this action
// was being classified and rejected, its latch state belongs to the successor
// and must not be cleared by a predecessor's failure. Identity check and clear
// happen in ONE critical section under e.mu so a concurrent Apply cannot swap
// the runtime between them.
//
// Lock order is safe by construction: the caller has already released
// enqueueMu (enqueue returns before this runs), so e.mu is never taken while
// enqueueMu is held.
//
// A concurrent event that lands between the drop and this rollback is still
// suppressed by the armed latch — the window is one classify+enqueue — so the
// crossing costs at most a delay to the next event rather than being consumed
// outright, which is the whole of the defect.
func (e *Engine) releaseEdgeLatch(name, eventName, authRev string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.semRev[name] != authRev {
		// Successor generation installed, or the policy removed, while this
		// action was rejected. Its latch is not ours to clear.
		return
	}
	if rt := e.runtime[name]; rt != nil {
		rt.onLatched[eventName] = false
	}
}

// criticalAction reports whether any operation mutates security/firewall
// configuration. Classification is done once in classifyPlan, before enqueue.
func criticalAction(a plannedAction) bool {
	for _, op := range a.ops {
		if op.critical {
			return true
		}
	}
	return false
}

// supersede rebuilds the bounded queue, replacing an existing same-policy
// action and keeping critical actions before ordinary actions. It returns
// whether the new action was placed and (if so) any ordinary action displaced
// to make room for a critical one. It is the SOLE enqueue path (#5853).
//
// #2869's tail-placement fairness rule still holds within each class: a newer
// ordinary action cannot jump ahead of older ordinary work. #10877 deliberately
// exempts critical actions from global FIFO by placing them first; only a full
// queue can evict work, and then it drops the newest ordinary action and releases
// that action's latch outside enqueueMu.
//
// CALLER MUST HOLD enqueueMu (#5062). No other producer can refill a slot
// during drain->refill; the only concurrent actor is the consumer, which only
// removes entries. A full queue may therefore reject a normal action, or reject
// a critical action only when every queued action is already critical.
func (e *Engine) supersede(a plannedAction) (bool, plannedAction, bool) {
	drained := make([]plannedAction, 0, actionQueueDepth)
	var evicted plannedAction
	hasEvicted := false
	for {
		select {
		case old := <-e.actions:
			e.counters.queueDepth.Add(-1)
			if old.policyName == a.policyName {
				e.counters.superseded.Add(1)
				continue
			}
			drained = append(drained, old)
		default:
			goto refill
		}
	}
refill:
	if e.afterDrainFn != nil {
		e.afterDrainFn()
	}
	priority := criticalAction(a)
	if len(drained) == actionQueueDepth && priority {
		for i := len(drained) - 1; i >= 0; i-- {
			if criticalAction(drained[i]) {
				continue
			}
			evicted = drained[i]
			hasEvicted = true
			copy(drained[i:], drained[i+1:])
			drained = drained[:len(drained)-1]
			e.counters.droppedQueueFull.Add(1)
			break
		}
	}
	placed := len(drained) < actionQueueDepth
	if placed {
		if priority {
			i := 0
			for i < len(drained) && criticalAction(drained[i]) {
				i++
			}
			drained = append(drained, plannedAction{})
			copy(drained[i+1:], drained[i:])
			drained[i] = a
		} else {
			drained = append(drained, a)
		}
	}
	replaced := false
	for _, item := range drained {
		select {
		case e.actions <- item:
			e.counters.queueDepth.Add(1)
			if item.policyName == a.policyName {
				replaced = true
			}
		default:
			if item.policyName != a.policyName {
				e.counters.droppedQueueFull.Add(1)
			}
		}
	}
	return replaced, evicted, hasEvicted
}
