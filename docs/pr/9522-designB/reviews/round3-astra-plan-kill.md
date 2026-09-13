# Verdict: PLAN-KILL

**Scoped to Phase 1 and dependent Phase 3. Phase 0 remains independently viable; Phase 2’s deferral is sound.** V3 improves the design substantially, but the joint-publication reset is not yet shippable.

### 1. Blocking — mint serialization is not publication serialization

`docs/pr/9522-designB/plan.md:132–148` sequences **minters**, then declares snapshot stampers benign. Those stampers also publish validation:

- `pkg/dataplane/userspace/manager_compile.go:866` samples the shim into a snapshot.
- `userspace-dp/src/afxdp/coordinator/snapshot_refresh.rs:342–345` installs snapshot validation.
- `userspace-dp/src/afxdp/coordinator/reconcile/snapshot.rs:564–567` does likewise.

Unless snapshot sampling/publication participates in the same exclusion contract, a snapshot can carry a reserved generation before the route commit. Strict freshness then correctly rejects the commit—but the plan has not prevented premature publication or specified its recovery.

Nor is “serial socket orders verbs as minted” a sufficient proof: each request opens its own connection (`pkg/dataplane/userspace/process_control.go:160–164`), and timeout leaves application outcome unknown (`:231–240`). Sender sequencing needs an explicit uncertain-outcome rule, not an assumed persistent ordered stream.

**Required:** one lock-order and publication contract covering snapshot publishers, bumps, commits, confirmation and retries; specify when an uncertain reservation is retired and a new generation becomes mandatory. Q1 at `plan.md:280–283` remains a question rather than the promised census.

### 2. Blocking — removal interim is not necessarily fail-closed

`plan.md:169–173` asserts that keeping old suppression after coverage removal causes only additional drops. That does not follow from an LPM FIB.

Go omits exact covered keys (`pkg/dataplane/userspace/routes.go:840–854`). Removing that configured entry while its learned replacement remains absent can expose a less-specific route or connected route. Absence of a specific entry is **not** a drop barrier; connected fallback is explicit at `userspace-dp/src/afxdp/forwarding/fib.rs:863–899`.

Therefore the interim can select a different forwarding path, not merely drop more. M2 currently tests an asserted property without defining machinery that guarantees it.

**Required:** atomic replacement content, or explicitly designed temporary suppression barriers with proven forwarding semantics. Merely marking routes dirty does not close this blocker. The unconditional availability claim and drops-more exception at `plan.md:44–48` also require reconciliation and user approval.

### 3. Blocking — recovery still lacks decisive transition rules

`plan.md:118–122,149–160` lists more events, but does not fully specify their transitions:

- **Unknown nonce automatically resets the fence.** A random boot nonce establishes distinctness, not recency. What prevents an obsolete epoch from becoming current again?
- **Receipt-only duplicate versus strict freshness:** after a later bump, a previously committed transfer’s fib is below current validation. Does receipt lookup precede freshness/fence rejection? What survives supersession?
- **Invalid commit after reservation:** re-pairing consumes that generation against existing content. The plan must explicitly forbid retrying a new-content commit with that consumed generation.
- **Restart identity:** a Manager nonce does not identify a helper incarnation. Completion evidence must be scoped to the currently serving helper, especially across restart and supersession.

These are transaction semantics, not implementation details. An actual transition table must define guard precedence, retained receipts, obsolete-response handling and generation retirement.

### 4. Major — numeric gates remain partly deferred, and progress assumptions conflict

`plan.md:253–254` still leaves status/HA maximum wait **“stated numerically in PR.”** A per-chunk p99 ceiling does not bound maximum HA delay or final commit work.

Also, staging aborts on **every** `iface_ctx` refresh (`plan.md:130–131`), whereas the convergence assumption only excludes config changes (`:184–187`). Same-plan refresh is itself an enumerated apply path. A config-quiet window therefore does not necessarily guarantee completion.

Define the actual quiet-window conditions, abort predicates, and numeric status/HA ceilings before implementation.

### What now passes

- **Version fork:** retaining v16 resolves the previous protocol-version contradiction (`plan.md:196–209`). Positive detection is a sound direction.
- **LPM corpus:** both families and connected shorter/equal/longer cases are now explicit (`plan.md:245–250`).
- Strict freshness, receipt-only duplicates, separate config binding, staging expiry and route/config churn separation are meaningful improvements.

**Final disposition:** proceed with Phase 0 only. Phase 1’s retention safety and complete publication/recovery contract remain unresolved; Phase 3 cannot ship independently of those fixes.
