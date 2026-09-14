# Verdict: PLAN-KILL

**Scoped to Phase 1 and dependent Phase 3.** Phase 0 remains viable independently; Phase 2’s deferral is clean. The five-point re-entry bar is **not yet satisfied**.

Reviewed the available v2 document and relevant source. The supplied round-1 raw path does not exist, so I cannot verify its exact F9 wording or independently reconstruct that review.

### 1. Blocking: joint publication is necessary, but freshness is not established

`docs/pr/9522-designB/plan.md:119–129` removes the literal **publish-then-bump** gap within the proposed commit handler. Good.

However, “pre-bumped” does not establish that the carried generation is **fresh at publication**. The commit checks specify bitmap, hash and config binding—not a generation reservation or exclusion against other validation publishers.

Existing `BumpFIBGeneration` bumps the shim **before acquiring `m.mu`**, then independently publishes validation (`pkg/dataplane/userspace/manager_generation.go:57–60, 123–141`). The coordinator accepts equal generations (`userspace-dp/src/afxdp/coordinator/mod.rs:1690–1701`).

Consequently, the plan does not exclude:
- another publisher advancing helper validation beyond the reserved generation;
- a retry/confirmation path publishing the reserved generation against old routes before the transfer commits;
- committing different route content under an already-published pair.

One store site prevents torn views; it does **not** prevent reuse or rollback of their identity.

**Required:** one sequencing contract covering *all* generation publishers, a strict freshness check for a **new** route commit, and receipt-only handling for duplicate commits. Equal-value confirmation must be impossible before committed identity is established.

Q1 remains explicitly unanswered (`plan.md:252–255`). Snapshot consumers include `manager_overlay.go:193`, `manager_compile.go:258,866` and `manager_worker_arm_5134.go:65`; the shim also participates in BPF cache validity (`bpf/headers/xpf_maps.h:331–341`). The proposed safety assertion is not a consumer audit.

### 2. Blocking: retention cannot restore learned routes omitted before transfer

`plan.md:112–114,142–152` combines Go gap filtering with retained snapshots and Rust suppression.

Today Go **omits** covered learned routes before producing snapshots (`pkg/dataplane/userspace/routes.go:840–854`). Retaining that filtered partition cannot recover a learned route when a later config removes its covering entry. Rust suppression addresses **coverage additions**, not **coverage removals**.

The plan must choose:
- retention of an explicitly defined, complete learned candidate set, with approved provenance and suppression rules; or
- an apply transaction carrying enough Go-computed learned content to handle newly uncovered keys atomically.

Canonicalization parity alone does not establish provenance or completeness. This is a material unresolved design decision, not merely another corpus cell. It also undermines the unconditional no-window acceptance claim at `plan.md:41–44`.

### 3. Blocking: recovery is a checklist, not an enumerable machine

`plan.md:130–138` says lost ACK means **commit-only retries**, but status mismatch means **re-transfer**. A lost ACK followed by an unavailable status response satisfies both descriptions.

`plan.md:235–238` promises a recovery table rather than providing one. Missing decisions include:

- duplicate commit with identical transfer ID but different hash/fib;
- invalid commit after shim reservation;
- helper restart during commit-only retry;
- committed transfer superseded before its delayed ACK arrives;
- how committed receipt, server snapshot fib, coordinator validation and status advance together;
- staging expiry and restart identity reuse.

Also, config binding cannot silently use installed `content_digest`: commit clears that digest (`plan.md:139–141`). Define the separately retained config identity and its update rules.

**Required:** actual states, events, guards, mutations, responses and retry obligations, including which observations prove completion.

### 4. Blocking: mixed-version claims contradict the current gate

`plan.md:183` claims new helper plus old Go accepts capped snapshots. Existing `apply_snapshot` rejects **any unequal protocol version before other handling** (`userspace-dp/src/server/handlers/snapshot.rs:28–36`); the bump handler also version-gates (`:505–512`).

Bumping the helper to 17 therefore does not preserve v16 acceptance automatically. Same-package spawning does not establish independently rolled-back compatibility.

Specify explicit v16 admission semantics—or require paired rollout/rollback and remove the unsupported mixed-pair guarantees. Old-helper selection also needs a concrete v16 encoding path, not merely refusal detection (`plan.md:177–186`).

### 5. Major: numeric gates and convergence remain incomplete

- `plan.md:93–96`: build and memory have thresholds; lookup and throughput merely have measurements.
- `plan.md:226–230`: socket wait, HA delay and peak staging memory have no acceptance ceilings; “budget stated in PR” defers the gate.
- `plan.md:158–167`: timeout-triggered new transfer conflicts with epoch-only preemption. K=3 cannot guarantee completion under continuing config changes while every config change must abort staging.

Separate route churn from config churn and define explicit progress assumptions and failure dispositions.

### What is resolved

- **LPM direction:** preserving composition byte-for-byte plus the expanded corpus is materially better (`plan.md:82–91`), consistent with `choose_v4_route` and its v6 twin (`userspace-dp/src/afxdp/forwarding/fib.rs:863–899`). Pin both families and connected-shorter/equal/longer cases explicitly.
- **Delta deferral:** unambiguous and acceptable (`plan.md:170–172`).
- **Atomic-store direction:** correct, but insufficient without generation exclusivity and recovery semantics.

**Re-entry requires the transaction and compatibility contracts above in the plan itself—not promises to settle them during implementation.**
