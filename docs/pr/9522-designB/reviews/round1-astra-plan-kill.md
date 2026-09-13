# Verdict: PLAN-KILL

**Scoped to Phase 1’s publication protocol, Phase 2’s live-mutation design, and dependent Phase 3 retirement.** Phase 0 remains a reasonable independent workstream, but its gates need specification.

This is a plan review, not an implementation verdict. **V1 repeats the required reset but does not satisfy it.** Shadow staging fixes clear-and-refill; it does not fix publication under stale validation.

References below use `docs/pr/9522-designB/plan.md` unless otherwise stated.

## 1. Blocking: new FIB is published before fresh validation

**Lines 132–140** explicitly order:

1. Swap forwarding and call `publish_runtime_view`.
2. Return commit ACK.
3. Go bumps the shim.
4. Send `bump_fib_generation`.

That exposes **new forwarding with the previous validation pair**. This is precisely what the reset prohibited—not an unspecified implementation detail.

The existing publication site confirms the consequence: `userspace-dp/src/afxdp/coordinator/mod.rs:1590–1598` clones forwarding paired with **current** validation. The subsequent bump performs a separate validation-only publication at `:1690–1700`.

**Required reset:** Go must allocate/authorize the commit identity before publication, and the helper must publish finished forwarding plus the corresponding fresh validation pair in one runtime-view store. Specify shim ordering, intervening bumps/config changes, and failure recovery. Helper ownership need not change; **post-publication ACK cannot be the prerequisite for obtaining the identity required at publication**.

Lines 197–198 therefore claim an invariant contradicted by the actual proposed sequence.

## 2. Blocking: “exactly once” is asserted, not a recovery protocol

**Lines 118–140, 149–150.**

Per-chunk invalidation is correctly excluded. Exactly-once commit invalidation is not established:

- A lost commit ACK can leave published content without its bump.
- Replaying the final chunk has no specified committed-result lookup.
- Receiving an ACK twice has no specified Go-side durable deduplication.
- A crash between shim bump and helper bump has no reconciliation rule.
- `(transfer,index)` ACK does not distinguish **stored**, **committed**, and **already committed**.

Require separate staging and committed identities, replayable terminal outcomes, and reconciliation across both process restarts. Define “exactly once” as a logical committed identity, not delivery of exactly one message.

## 3. Blocking: config binding and digest identity remain open questions

**Lines 109–114, 126–147, 199–201, 277–279.**

The wire envelope names no config-context identity or expected transfer digest. Yet commit requires content identity, and config changes supposedly abort through an epoch check.

Unresolved essentials include:

- Which config identity binds gap-fill, interfaces, table canonicalization and next-hop inference?
- Is it checked at every ingest and immediately before publication?
- What canonical content does Go hash, and what does the helper verify?
- How does a config-only snapshot digest relate to the helper’s merged stored snapshot?
- Does full apply preserve, reconstruct or remove the committed learned partition?
- What survives config replacement when the replacement learned transfer fails?

Rehash versus bitmap is not merely a performance choice: **bitmap completeness does not prove content identity**.

Also, the “Q1/Q2/Q3” references do not resolve these decisions: §11’s numbered questions concern different subjects.

## 4. Blocking: Phase 2 expressly exempts itself from atomicity

**Lines 158–167.**

“Each delta is self-consistent” does not make a batch transactional. Direct live mutation leaves undefined:

- rollback when a later addition fails validation;
- replacement ordering for withdraw-plus-add of one key;
- duplicate or skipped sequence handling;
- the committed base against which a delta is valid;
- what happens when a delta arrives during an older full transfer;
- whether that transfer can subsequently overwrite the delta.

A worker `Arc` may conceal intermediate coordinator mutations until publication; that does **not** establish abort safety or prevent later publication of a partially modified owner state.

**Kill Phase 2 as written.** Either defer it or build immutable candidate updates with explicit base identity and a defined transfer/delta serialization rule. Periodic anti-entropy is not permission for incorrect intermediate committed views.

## 5. Major: gap-fill ownership is not key-space separation

**Lines 141–147, 159–166, 205–211.**

Config and learned routes can have the same `(table,family,canonical-destination)` key; that collision is exactly why gap-fill exists. Giving withdrawals that key does not structurally distinguish ownership.

Require an explicit partition/provenance representation and rules for:

- config adding coverage after learned staging starts;
- config removing coverage previously suppressing a learned route;
- overlay changes;
- multiple same-key learned candidates spanning chunks;
- deterministic reassembly independent of replay/arrival order.

Computing gap-fill once is sound **only when its config context remains bound through commit**. Aborting staging alone does not explain how already committed learned content is reconciled with newly installed config.

## 6. Major: publication cost remains full-table work

**Lines 68–72, 132–137, 202–204, 232–237, 270–272.**

“One clone per transfer” is an improvement, not a scalability result. The cited publication function clones the entire forwarding state. Peak memory must include:

- coordinator forwarding;
- worker-visible forwarding and retained older worker views;
- staging structures;
- decoded chunks and stored snapshots;
- the new publication clone;
- digest/build scratch.

“Tens of MB” is unsupported. Also quantify how the LPM change affects **neighbor pushes and other existing full-forwarding clone sites**, not just route commits.

M0/M1 name measurements but supply no numeric memory, build, clone or worker-rotation acceptance thresholds.

## 7. Major: socket scheduling has sizes, not service guarantees

**Lines 84, 148–154, 207–209, 235–237.**

Using the plan’s estimate, one million routes is approximately **113 MB serialized**, or roughly **54–108 chunks** at 2–1 MiB, before envelope overhead.

To complete in 30 seconds requires roughly **3.77 MB/s effective throughput**, with an average **278–556 ms per chunk** if the entire budget were available to chunk roundtrips. Build, hashing, publication, persistence and competing requests reduce that allowance.

These are arithmetic requirements—not measurements. Releasing `m.mu` does not guarantee another requester service before reacquisition.

Require measured lock/socket hold percentiles, maximum status/HA wait, explicit scheduling behavior, and a total convergence budget. Restarting from zero after every 30-second timeout can create permanent nonconvergence; define progress behavior under sustained churn and supersession.

## 8. Major: transaction recovery is incomplete

**Lines 118–137, 149–153.**

Positive: old-table retention, missing-chunk refusal, supersession and empty-set intent are present.

Missing:

- conflicting duplicate chunk contents;
- bounds on total chunks, routes, decoded bytes and aggregate staging memory;
- index bounds and immutable envelope fields;
- abandoned-transfer timeout;
- whether validation failure poisons, discards or permits repair of staging;
- exact empty-transfer encoding;
- sender/helper restart identity and persistence;
- committed replay handling;
- supersede/config-abort races and late messages.

“One live transfer” bounds concurrency, **not staging lifetime or memory**. Add a state-transition table and failure-injection tests for every terminal/replay path.

## 9. Phase 0: direction sound; parity contract needs sharpening

**Lines 91–105, 216–218.**

The intended ordering is broadly correct. Explicitly pin:

- longer prefix wins regardless of a shorter prefix’s better preference;
- preference applies among same-prefix candidates;
- equal-preference insertion order survives chunking/reassembly;
- a selected discard or unresolved next-table route does not cause unintended fallback to an ancestor;
- connected-versus-static tie behavior remains unchanged;
- ECMP retains the same whole slice, member ordering and hash-to-member result.

Current selection first finds a static match, separately finds a connected match, then calls `choose_v4_route`: `userspace-dp/src/afxdp/forwarding/fib.rs:427–441`. Preserve that composition, not merely trie LPM behavior.

Choose the actual structure and numeric gates before approval; “binary/ART” still leaves materially different build/memory characteristics.

## 10. Major: precedent and rollout claims overreach

**Architecture — lines 228, 280–283:** The available precedent describes #961 as “PacketContext that wraps a packet” and #946 Phase 2 as “batched per-stage iteration” (`docs/pr/1354-transmit-phase-split/plan.md:434–440`). That is not evidence that all stateful transfer machinery is architecturally prohibited. Conversely, `update_neighbors` does not prove million-route transaction suitability. Evaluate the concrete ownership and cost mismatch, not issue-number resemblance.

**Rollout — lines 171–180, 212–215, 284–287:** Legacy fallback and strict mixed-version refusal are presented simultaneously without explaining which is reachable. Current protocol **16 is confirmed** at `userspace-dp/src/protocol/control.rs:131`; targeting 17 does not resolve compatibility.

Specify the actual pairing matrix, upgrade order, rollback/persisted-state behavior, first-full-transfer readiness, and operator-visible refusal/recovery status. Zero cap hits alone does not prove a complete table is installed.

## Re-entry bar

Retain shadow transport and independently gated LPM work. Before another approval round, provide:

1. One explicit FIB-plus-validation commit sequence.
2. Config-bound, digest-bound transaction and recovery state machines.
3. Delta deferral or transactional delta semantics.
4. Numeric resource/scheduling gates.
5. A coherent v17 deployment and rollback contract.

**The reset is not “stage, swap, then invalidate.” It is “publish complete content and fresh validation together.”**
