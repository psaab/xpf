# PLAN-KILL

**Scoped to Design A as specified—not to kernel-assisted adjudication in principle.** The live-FIB reset is satisfied, but the replacement architecture still does not establish that the zone authorized is the zone Linux actually forwards into.

Read-only plan review of the supplied checkout. No execution, measurements, or independent commit verification performed.

## 1. Blocker — The query deliberately uses a different ingress context from forwarding

**Grounding:** `docs/pr/9522/plan.md:107-124,178-185`.

§5a explicitly says Linux sees `xpf-usp0` after reinjection and that an ingress-matching rule would decide differently. It nevertheless queries using the original logical ingress, then calls that “the same decision.”

Those statements are incompatible. A correct answer for the original ingress is not necessarily authorization for the actual reinjection path.

The plan also leaves unspecified whether the table input requests a table-constrained lookup or ordinary RPDB traversal, and how that corresponds to reinjection with a PBR override. A selector list cannot substitute for that contract.

**Required reset:** establish one end-to-end forwarding-context contract. Either forwarding preserves the context authorized, or activation excludes every topology where the two contexts can differ. Merely querying with more selectors does not fix this.

## 2. Blocker — The proposed cache discards inputs the query declares security-relevant

**Grounding:** `docs/pr/9522/plan.md:107-116,150-156,240-242`.

The query depends on source, ingress, protocol and ports. The cache key contains only `(table-selector, dst, src-class, tos)`.

- `src-class` has no defined routing-equivalence relation.
- Ingress, protocol and ports disappear entirely.
- Routing-domain/namespace identity is not explicitly bound.
- Cached zone identity survives configuration changes unless they also trigger the specified FIB invalidation.

Thus the plan can reuse a zone answer across routing-distinct packets. Re-evaluating policy does not repair evaluation against the wrong zone. The assertion that this cache cannot revive a stale ALLOW is false.

**Required revision:** cache only across a proven routing-equivalence key and bind answers to interface/zone/configuration context. Switching to verdict caching does not solve missing routing identity.

## 3. Blocker — Seconds-old zone authorization is not kernel forwarding parity

**Grounding:** `docs/pr/9522/plan.md:155-161,240-245,342-346`.

Linux performs another route decision after reinjection. It does not inherit the route selected by the earlier query. Consequently, a cached authorization can describe the previous zone while forwarding uses the current zone.

This is materially different from forwarding a packet using an already-selected kernel route. A TTL bounds answer age; it does not establish forwarding-policy correctness. Clearing on helper FIB publication also does not establish coherence with every kernel route or rule change.

Even zero TTL leaves the query-to-reinjection separation; seconds-long caching magnifies it.

**Required reset:** bind authorization to forwarding, or explicitly propose a weaker security invariant for user approval. “Not a bypass” cannot be an approved premise.

## 4. Blocker — Sentinel fallback is neither universally fail-closed nor availability-preserving

**Grounding:** `docs/pr/9522/plan.md:129-138,162-170,284-287,316`; `userspace-dp/src/protocol/snapshot.rs:637-649`.

The preserved sentinel behavior evaluates the **default action**, not the unknown real zone pair.

Therefore:

- With default permit, indeterminate resolution does not establish enforcement of real-pair denials.
- With default deny, permitted learned destinations become unavailable during resolver failure, unsupported routing, or rate-limit exhaustion.

The plan acknowledges default-action semantics, then repeatedly calls the same operation “fail-closed” and “never to delegation.” Those descriptions are not equivalent.

Rate limiting converts workload pressure into this policy/availability tradeoff; counters do not remove it. The test matrix omits the default-permit/explicit-pair-deny case.

**Required revision:** specify the actual security and availability contract for uncertainty. The current unconditional acceptance promises cannot both be claimed.

## 5. Major — Attestation is an aspiration, not a complete capability boundary

**Grounding:** `docs/pr/9522/plan.md:178-185,296-298,321-325`; `/usr/include/linux/fib_rules.h:19-31,43-77`.

The locally available Linux UAPI includes additional routing-rule dimensions: mark/mask, output interface, tunnel ID, l3mdev, UID range, DSCP masks, IPv6 flow label/mask, and port masks. The plan needs a version-scoped treatment of these—not merely “any future selector.”

Distinguish categories correctly:

- `uidrange`, marks and l3mdev require explicit supported semantics or conservative rejection.
- Realm/`FRA_FLOW` is not simply another packet input to invent.
- Rule protocol metadata is distinct from packet IP protocol.
- Inversion, priorities, goto, suppression and terminal actions affect rule evaluation even though they are not extra packet selectors.

Additional missing guarantees:

- Both address families and every relevant network namespace are covered.
- Unknown attributes survive enumeration sufficiently to trigger rejection.
- Rule changes invalidate the attestation promptly; snapshot-time enumeration alone is not a continuing capability guarantee.
- Multipath ambiguity is discoverable from the chosen query response; obtaining one selected ifindex does not prove all possible nexthops share its zone (`plan.md:134-142`).

Attestation also cannot compensate for the ingress mismatch in finding 1.

## 6. Major — The no-version-bump proof contradicts both the plan and the repository doctrine

**Grounding:** `docs/pr/9522/plan.md:178-201,229-230,256-258`; `userspace-dp/src/protocol/control.rs:96-103`; `userspace-dp/src/protocol/snapshot.rs:650-657`.

There **is** a new sender: Go emits a new security-relevant attestation field.

The specified encoding is internally inconsistent:

- Go `omitempty` omits ordinary `false`.
- Plain Rust `#[serde(default)]` on a bool defaults to `false`.
- §7 instead requires absence to mean complex.
- §5e says old senders successfully activate lookup, contradicting that absence rule.

Absence-as-complex also recreates the old-sender availability problem that §5e denies.

The v9 doctrine explicitly rejects “additive, old behavior unchanged” when that old behavior is the defect. The v10 comment specifically treats capped-miss disposition as authoritative—not mere telemetry.

**Required revision:** specify an unambiguous attestation representation and truthful mixed-version matrix, then use refusal/versioning consistent with that doctrine. A status signal alone does not refuse an unsafe pairing.

## 7. Major — Synchronous lookup has no worker-availability budget; scan measurements must gate A too

**Grounding:** `docs/pr/9522/plan.md:37-44,147-174,272,291-295`; `userspace-dp/src/afxdp/forwarding/fib.rs:428-440`.

“Slow path” is a classification, not scheduling isolation. Blocking this worker delays other traffic it processes.

A global queries-per-second ceiling does not bound an individual worker stall. The plan supplies no numeric hard deadline, burst budget, fairness policy, or acceptable unrelated-flow latency. p99 lookup RTT is insufficient for timeout behavior.

A shared resolver with bounded buffering requires explicit ownership and overload semantics, but rejecting that complexity does not validate synchronous blocking. Negative caching likewise does not solve distinct-key workloads.

The linear-scan premise needs correction:

- The cap bounds the learned import, not necessarily total helper-FIB size.
- Above cap, the plan says the entire learned import is withheld; that is not the same workload as scanning 65k imported learned routes.
- Existing linear scanning proves complexity, **not measured throughput collapse**.

I cannot honestly assert collapse without measurements. But baseline-versus-A throughput, worker latency, and legitimate permit availability must gate **A**, not merely future B. “No throughput win claimed” is not permission for an unbounded regression.

## Requested architectural dispositions

### Staging/atomicity reset: satisfied for A

**Grounding:** `docs/pr/9522/plan.md:94-97`.

No learned-FIB mutation means no partial replacement or new live-content/validation-pair mismatch. That round-1 objection is closed by construction. It does not close the new zone-cache coherence problem.

### Alternative B: defer, but do not approve its sketch

**Grounding:** `docs/pr/9522/plan.md:205-217`.

Chunked transport need not die entirely. Immutable staging plus an appropriate lookup structure remains a legitimate separate workstream.

However, “atomic swap → complete ACK → Go bump” still leaves unclear whether changed live content appears before its fresh validation pair. The future design must publish both together; the current sketch is not approval of that ordering.

**Bottom line:** v2 fixes the old publication architecture, but replaces it with an unbound routing oracle, incomplete cache identity, and contradictory uncertainty/skew semantics. Resolve those architectural contracts before implementation—not during smoke testing.
