# PLAN-KILL

**Kill the proposed live clear-and-refill architecture, not the issue or chunked transport itself.** The plan requires different enforced FIB contents to share one validation pair, and deliberately removes working routes throughout transfer. These contradict its own security and availability invariants. The kernel-lookup fallback does **not** yet dominate: its miss-rate premise and routing fidelity are unproven.

Read-only plan review against the supplied checkout; no implementation, execution, or independent commit verification performed.

## Findings

### 1. Blocker — The neighbor analogy reverses the existing atomicity guarantee

**Grounding:** `docs/pr/9522/plan.md:136-144`; `userspace-dp/src/afxdp/coordinator/mod.rs:737-747`.

The existing neighbor replacement explicitly makes readers observe **either pre-replace or post-replace**, never a half-replaced set. The proposal instead clears the live learned FIB on chunk zero and exposes successive subsets.

This is not the neighbor pattern scaled up: it discards its crucial guarantee. Transport chunking is reasonable; **live-table chunking is not justified**.

Also, Q2’s “old tail + new head” description is inconsistent with the actual algorithm: after the specified clear, there is **no old tail** (`docs/pr/9522/plan.md:325-327`).

### 2. Blocker — One completion-time invalidation cannot cover earlier live mutations

**Grounding:** `docs/pr/9522/plan.md:140-144,238-241`; `userspace-dp/src/afxdp/flow_cache.rs:998-999`; `userspace-dp/src/afxdp/coordinator/mod.rs:1667-1700`.

Cache validity is pair equality. Clearing or changing live routes without advancing the pair leaves earlier forwarding decisions valid while fresh lookups see different routing content.

“Never per chunk” is therefore an invalid invariant **for this live-mutation design**. Performance concerns cannot override invalidation correctness.

A single bump works only if the completed replacement and its new validation pair become visible together. That requires staging and atomic publication, not the proposed algorithm.

### 3. Blocker — The convergence window recreates the rejected availability failure

**Grounding:** `docs/pr/9522/plan.md:136-162,194-196,204-209`; `userspace-dp/src/afxdp/poll_descriptor/mod.rs:5155-5181`.

Strict NoRoute adjudication uses the unzoned sentinel and falls through to default action. Clearing the learned partition consequently makes otherwise permitted, learned-only destinations unavailable on default-deny systems until their chunks arrive.

This affects previously working routes on **every replacement**, not merely newly learned routes during the existing debounce window. A transfer failure can extend it indefinitely; retaining a capped flag does nothing once that flag no longer gates disposition.

The cited ~1–3 seconds is the listener’s coalescing window, not a bound on full-table transfer or retry recovery. A “publishing” status bit cannot fix this forwarding behavior.

### 4. Major — Worker publication and FIB representation remain architecture decisions, not implementation details

**Grounding:** `docs/pr/9522/plan.md:172-176,277-278`; `userspace-dp/src/afxdp/coordinator/mod.rs:757-768,1595-1596`; `userspace-dp/src/afxdp/forwarding_build/fib.rs:37-139,163-185`; `userspace-dp/src/afxdp/forwarding/fib.rs:428-440`.

Existing publication clones `ForwardingState`. Mirroring it per chunk risks repeated full-state copies as the table grows. Mutating only coordinator-owned state, conversely, does not establish worker visibility. The plan never chooses which happens.

The lookup consumes a prefix/preference-sorted vector using first match. Consequently:

- Appending canonically emitted chunks is not sufficient to maintain lookup ordering.
- Two partitions require a defined cross-partition longest-prefix/preference selection algorithm.
- “Config first” globally would incorrectly suppress more-specific learned routes.
- Tags require explicit provenance and removal bookkeeping; `populate_routes` currently installs neither.

Choose the representation, publication boundary, sorting strategy, and memory budget before implementation.

### 5. Major — Gap-fill provenance and configuration interleaving are unspecified

**Grounding:** `docs/pr/9522/plan.md:136-139,247-250`; `pkg/dataplane/userspace/routes.go:789-792,839-851,856-868`; `userspace-dp/src/afxdp/forwarding_build/fib.rs:43-44`.

The existing `covered` set is constructed from the pre-existing operator-derived routes, using a key deliberately narrower than deduplication identity. `populate_routes` does **not** implement that rule.

A streamed implementation must retain this distinction across chunks. Building coverage from everything installed so far could suppress subsequent learned alternatives; using a stale config-only coverage set could conflict with an intervening configuration update.

The plan needs a transaction bound to a specific configuration/interface context, plus explicit abort or rebase behavior when that context changes.

### 6. Major — The control-socket benefit is asserted using timeout allowances as latency measurements

**Grounding:** `docs/pr/9522/plan.md:152-170,252-255`; `pkg/dataplane/userspace/process_control.go:109-128,268-285`; `pkg/dataplane/userspace/manager_overlay.go:102-104`; `userspace-dp/src/server/helpers/status.rs:22-39`.

`controlRoundtripDeadline` specifies an allowed timeout, not observed service time. Its three-second base also cannot establish a worst-case hold “well under” the one-second status period.

For chunks with service times \(s_i\) and intentional gaps \(y_i\):

- Total convergence is approximately `Σ(s_i + y_i) + commit`.
- Other callers’ latency improves only if the relevant locks are released and they actually receive service.
- More chunks add repeated request/status overhead.

The current overlay method holds `m.mu` across its operation. The new sender must explicitly change that scheduling model, not merely yield between calls.

The sharing premise also needs correction: session synchronization already has a dedicated socket and `sessionMu`. Any remaining session interference must be traced through actual shared helper resources.

Require measured request latency, status latency, publication cost, and convergence under route churn—not byte-budget tests alone.

### 7. Major — The transaction protocol cannot be specified by copying #6034

**Grounding:** `docs/pr/9522/plan.md:134-135,155-163,226-227`; `userspace-dp/src/afxdp/coordinator/mod.rs:694-718,770-777`.

The neighbor fence rejects a generation less than **or equal to** the last applied generation. Copying it literally rejects subsequent chunks sharing that generation.

The proposed ACK requires `(generation, index)`, but the public-surface summary adds only a generation field. Missing decisions include:

- Active versus committed generation.
- Duplicate chunk identity and lost-ACK replay.
- Missing chunks, inconsistent totals, and premature completion.
- Empty replacement semantics.
- Superseding transfers, restart recovery, and bounded staging lifetime.
- Validation failure without partial installation.

Stop-and-wait reduces reordering; it does not solve replay identity or transaction recovery.

### 8. Major — Content identity and partial-update recovery are applied too late or assumed to exist

**Grounding:** `docs/pr/9522/plan.md:140-144,158,242-245`; `userspace-dp/src/server/handlers/neighbors.rs:56-61`; `userspace-dp/src/server/handlers/snapshot.rs:127-147`; `pkg/dataplane/userspace/process_control.go:356-361`; `pkg/dataplane/userspace/partial_update_outcome_9684.go:18-45,78-83`.

The plan clears `content_digest` only on completion, although its live enforced content changes on chunk zero. Throughout transfer, the installed digest would incorrectly attest to the previous full snapshot.

Also, `requestLocked` currently advances the partial-update epoch only for neighbors and fabrics. The recovery section types likewise cover only those sections. Merely calling that method does not confer #9684 protection.

Define how every full-snapshot publisher interacts with pending/committed learned routes, including Compile races, deduplication, lost replies, writeback, persistence, and restart. Otherwise a full apply can erase or invalidate chunk progress.

### 9. Major — Additive serde fields do not make a required new verb upgrade-safe

**Grounding:** `docs/pr/9522/plan.md:103-118,204-209,261-266`; `userspace-dp/src/server/handlers/mod.rs:360-362`.

An old helper ignores unknown **fields**, but rejects an unknown **request type**. Keeping protocol version 10 does not establish `update_routes` capability.

Both upgrade directions require explicit behavior:

- New sender with an old helper must not silently return to capped, unadjudicated delegation.
- Old sender with a new strict helper can still withhold the table, recreating the availability failure.

A sticky refusal alone does not solve either case. Specify capability negotiation and safe activation ordering before deleting the gate.

### 10. Major — Kernel lookup has neither a demonstrated low miss rate nor a demonstrated “real zone”

**Grounding:** `docs/pr/9522/plan.md:178-191,337-350`; `userspace-dp/src/afxdp/poll_descriptor/mod.rs:5111-5119,5190-5203`; `userspace-dp/src/afxdp/forwarding_build/fib.rs:65-80,306-313`.

The existing NoRoute delegation path explicitly lacks session creation. Therefore, the claim that established flows make only their first packet consult the oracle does not follow: learned-only delegated traffic may repeatedly require lookup unless the design adds a cache or a forwarding/session admission path.

“Slow path” also does not mean asynchronous; synchronous lookup in this descriptor handler blocks that packet-processing worker.

Routing fidelity must account for the lookup context that Linux actually sees after reinjection: source/destination, ingress/VRF, table and policy-rule selection, mark, TOS/traffic class, and protocol/ports where applicable. It must also handle multipath selection, non-unicast results, interface-to-zone mapping, and lookup-to-reinjection changes. The plan establishes none of these end to end.

**Do not promote the fallback solely on the miss-rate argument.** Its required fidelity and workload evidence are prerequisites, not implementation follow-ups.

### 11. Major — The tests encode the broken intermediate-state contract

**Grounding:** `docs/pr/9522/plan.md:286-300`; `userspace-dp/src/afxdp/poll_descriptor/mod.rs:6434-6455`.

“Partial table does not bump fib” explicitly tests the invalid live-mutation behavior. A strict NoRoute deny test also cannot alone prove a complete learned import or continued availability.

Required acceptance coverage must instead include:

- Unchanged permitted destinations throughout replacement.
- Cache coherence at the actual publication boundary.
- Aborted and replayed transfers.
- Concurrent full configuration updates.
- Cross-chunk precedence and LPM correctness.
- Both upgrade directions and restart recovery.
- Real scheduling/latency evidence at full-table scale.

The stated single-recycle and #1913 approach is sound: downgrade the disposition and retain the existing trailing admission site. Neither alternative should introduce its own reinjection path.

## Required architectural reset

Retain chunking as **transport**, but stage an immutable replacement off the live forwarding view. Validate completeness and content identity, bind it to the configuration context, then publish the finished FIB and fresh validation pair together. Abort leaves the previous complete view intact.

That is a materially different plan, requiring explicit memory, startup-readiness, withdrawal/convergence, and scheduling policies. It is the appropriate next proposal—not implementation of this one.
