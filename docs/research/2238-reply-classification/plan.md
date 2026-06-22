# #2238 — Locally-generated replies classified by the TRIGGER tuple, not the generated packet

- **Issue:** #2238 (MEDIUM, correctness / output-filter + CoS + DSCP + mirror bypass)
- **Mode:** `/research` — PLAN ONLY. No code, no PR, no production-source edits.
- **Revision:** r3 (incorporates Claude-SMR-r1 + Codex-r1 + AGY-r1 hostile
  reviews; both external reviewers returned PLAN NO on r2 → two changes folded:
  §6.2 flipped to FAIL-CLOSED, and Path B is now the COMMITTED decision, not a
  menu of equal options)
- **Status:** PLAN-READY (committed: **Path B** — explicit generated-reply
  classification contract; §6.2 fail-CLOSED on internal parse failure + counter;
  §10 scope-fences port-mirror direction semantics out)
- **Branch:** `research/2238-reply-classification`
- **Owner-WIP caveat:** the issue's only comment flags `icmp.rs` as in-progress
  local WIP. This is a plan-only deliverable; no source is touched. `/engineer`
  MUST re-confirm `icmp.rs` is free before implementing (the file is the primary
  edit site for the Time Exceeded leg).

---

## 1. Problem statement

Locally-generated control frames are emitted by the userspace dataplane in
reply to inbound packets, but their output-side classification (output firewall
filter terminal action / counters / policers / log, CoS forwarding-class →
queue, DSCP rewrite, port-mirror) is computed from the **triggering inbound
packet's tuple**, or is skipped entirely — never from the **generated frame's
own 5-tuple + egress interface**.

The generated frame is a *reflection* of the inbound frame (MAC swap, IP swap,
and frequently a protocol change). Its true egress tuple is therefore the
reverse of the trigger, with a different protocol for the ICMP cases:

| Generator | Trigger tuple (what is classified today) | Generated frame's OWN tuple (what SHOULD be classified) |
|---|---|---|
| ICMP/ICMPv6 Time Exceeded (`icmp.rs`) | inbound TCP/UDP/… `(src→dst, proto X)` | `(egress_primary_ip → inbound_src_ip, proto ICMP/ICMPv6)` |
| Policy-`reject` ICMP unreachable (`reject_reply.rs` → `build_reject_icmp_unreachable`) | inbound `(src→dst, proto X)` | `(egress_primary_ip → inbound_src_ip, proto ICMP/ICMPv6)` |
| Policy-`reject` TCP RST (`reject_reply.rs` → `build_reject_rst_frame`) | inbound `(src→dst, TCP, sport→dport)` | `(dst→src, TCP, dport→sport)` |
| SYN-cookie SYN-ACK / ACK-RST (`cookie_reply.rs`) | inbound SYN `(src→dst, TCP, sport→dport)` | `(dst→src, TCP, dport→sport)` |

### 1.1 Current handling, per leg (verified in source)

- **Time Exceeded** (`userspace-dp/src/afxdp/icmp.rs:51-90`): calls
  `resolve_cos_tx_selection_at(forwarding, ingress_ident.ifindex, meta,
  Some(&flow.forward_key), now_ns)` — `meta` and `flow.forward_key` are the
  TRIGGER. `cos.drop` short-circuits to silent drop; on accept it stamps
  `cos_queue_id`, `dscp_rewrite`, and sets `cos_tx_selection_resolved: true`,
  so the dispatch loop will NOT re-resolve. **Classified, but by the wrong
  tuple.** No mirror.
- **Embedded-ICMP NAT reversal** (`poll_descriptor/mod.rs:1182-1216`): a
  Prebuilt frame whose bytes ARE a NAT-reversed inbound ICMP error. Also calls
  `resolve_cos_tx_selection_at(..., meta, Some(&flow.forward_key), ...)` with
  the trigger and sets `cos_tx_selection_resolved: true`. **Same classify-by-
  trigger pattern.** This is a *forwarded* (not host-originated) frame; see
  §10 scope decision — it is a sibling, NOT in the issue's enumerated set.
- **Policy-reject reply** (`poll_descriptor/reject_reply.rs:51-62`): pushes a
  `TxRequest{ cos_queue_id: None, dscp_rewrite: None, mirror_clone: false,
  expected_protocol: meta.protocol, flow_key: Some(flow.forward_key) }`.
  **Not classified at all** — `enqueue_local_into_cos` honors the supplied
  `None` queue and never re-resolves a local `TxRequest`. No DSCP, no mirror,
  no output-filter terminal-action enforcement.
- **SYN-cookie reply** (`poll_descriptor/cookie_reply.rs:75-86`): identical
  shape — `cos_queue_id: None, dscp_rewrite: None, mirror_clone: false`. **Not
  classified.**

### 1.2 Why the dispatch loop does not save us

`tx/dispatch/mod.rs:129-142` re-resolves CoS only for `PendingForwardRequest`
values that have `cos_tx_selection_resolved == false`
(`pending_forward_needs_cos_tx_selection`). It does this against
`request.meta` + `request.flow_key`. Two reasons this does not fix #2238:

1. The Time Exceeded / embedded-ICMP Prebuilt requests arrive with
   `cos_tx_selection_resolved: true` → the loop skips them.
2. The reject / SYN-cookie replies are NOT `PendingForwardRequest`s at all —
   they are `TxRequest`s pushed straight onto `pending_tx_local`
   (`reject_reply.rs` / `cookie_reply.rs`), which is drained by
   `tx/drain/*` → `enqueue_local_into_cos`. That drain path NEVER calls
   `resolve_cos_tx_selection`; it honors `req.cos_queue_id` verbatim. DSCP
   rewrite is applied at transmit time from `req.dscp_rewrite`
   (`tx/transmit/mod.rs:110-111`, `tx/transmit/rewrite.rs`) — which is `None`.

Even where classification *is* keyed on `request.meta`/`request.flow_key`, the
meta/flow describe the trigger, not the generated bytes, so a per-tuple output
filter that matches `protocol icmp` never fires for an ICMP error generated in
response to a TCP/UDP flow.

### 1.3 Consequences (operator-visible)

- Output filter intended to discard locally generated ICMP errors never matches
  (sees the original TCP/UDP tuple, or never evaluates).
- Output filter matching the original transit flow can DROP the ICMP error even
  though the emitted packet is ICMP (false drop / wrong term).
- Output-filter term counters/logs are charged to the wrong tuple.
- DSCP rewrite / CoS queue is missing on generated control traffic, or wrongly
  inherited from the trigger (Time Exceeded leg inherits the trigger's
  forwarding-class → queue, which is at best coincidentally right).
- Port-mirror is hard-off (`mirror_clone: false`) for ALL generated replies —
  but see §10: xpf only implements **input-direction** port-mirror today, so
  "mirror the generated reply" is an OUTPUT-direction feature that does not yet
  exist. Scope decision below.

---

## 2. Root cause

There is no single "classify a host-generated reply by its own egress tuple"
contract. Each generator independently either (a) reuses the trigger's
`meta`/`flow_key` for `resolve_cos_tx_selection`, or (b) emits an unclassified
`TxRequest`. The generated bytes — which already exist and fully describe the
reply's true egress tuple — are never parsed back into a classification key.

Three things diverge from the transit path:

1. **Classification key source.** Transit forwards classify on the packet that
   will egress (the live/owned frame's meta+flow). Generated replies classify
   on the trigger.
2. **Coverage.** Transit forwards run output-filter + CoS + DSCP + mirror.
   Generated replies run a subset (Time Exceeded: filter+CoS+DSCP, no mirror)
   or nothing (reject/cookie).
3. **No re-resolution hook.** The drain/`enqueue_local_into_cos` path for local
   `TxRequest`s is a pure "honor the precomputed queue" path with no
   classification seam.

---

## 3. Goal / acceptance criteria

A host-generated reply is classified by **its own** egress 5-tuple +
egress interface for the output-side treatments xpf supports today:

1. **Output firewall filter**: the generated frame's tuple is evaluated against
   the *egress* interface output filter; a terminal `discard`/`reject` DROPS the
   generated reply; counters/log/policers are charged to the generated tuple.
2. **CoS forwarding-class → queue**: derived from the generated tuple (a
   filter `forwarding-class` action on the egress filter; or a DSCP/IEEE
   classifier on the egress interface keyed off the generated frame's DSCP).
3. **DSCP rewrite**: the egress filter's `dscp`/rewrite action applies to the
   generated frame's bytes.
4. **Port-mirror**: **DEFERRED** behind the §10 scope fence — see Path
   options + §10. Input-direction mirror of the *trigger* already fires (the
   inbound packet that caused the reply is itself mirrored on ingress). An
   output-direction mirror of the generated reply is a new feature, tracked
   separately, NOT folded into this bug fix (engineering-style §"Narrow scope").

Acceptance tests (unit, no smoke env needed for the classification logic):

- An output filter with `then discard` matching `protocol icmp` on the egress
  interface DROPS a generated Time Exceeded (whose inbound trigger was TCP).
- An output filter matching the inbound TCP tuple does NOT drop the generated
  ICMP error (proves the classify-by-generated-tuple, not trigger).
- An output filter `then forwarding-class <fc>` on the egress interface routes
  a generated RST to the queue mapped from `<fc>` (proves CoS by generated
  tuple).
- A DSCP-rewrite term on the egress filter rewrites the generated frame's DSCP
  byte (proves rewrite applies to generated bytes).
- Counter-factual pin: reconstruct the pre-fix call (classify on trigger) and
  assert it would have produced the WRONG verdict for the same fixtures.

Non-goals: output-direction port-mirror (separate issue); changing input-
direction mirror; NetFlow `sampling output` (unrelated, not wired in dp).

---

## 4. Design — the shared contract

Introduce ONE function that, given the **built reply bytes** + the egress
ifindex, parses the bytes into a classification key and returns a
`CoSTxSelection` (queue, dscp_rewrite, drop, filter_log). Every generator
routes through it before enqueue.

### 4.1 Parse the generated bytes into a `SessionKey`

A small parser `generated_reply_session_key(frame: &[u8]) -> Option<(SessionKey,
ForwardPacketMeta)>` that:

- walks L2 (handles the 0/4/8-byte VLAN tag the reflecting builders may add),
- reads L3 family + addresses + protocol + DSCP,
- reads L4 ports for TCP/UDP, or sets ports = 0 for ICMP/ICMPv6 (the output
  filter's ICMP terms key on protocol + optionally icmp-type, not ports — and
  `evaluate_filter_ref_tx_selection_*` already takes ports as `u16`, with 0
  the natural "no port" value, matching how ICMP is keyed elsewhere).

This reuses the existing `frame::inspect` helpers (`frame_l3_offset`, and the
v4/v6 header readers already used by the builders) so there is **one** parser
of wire bytes, not a second hand-rolled one. The `ForwardPacketMeta` carries
`addr_family`, `protocol`, `dscp`, `pkt_len`, and `ingress_*` set to
neutral/zero (the reply has no meaningful ingress PCP/VLAN for IEEE-classifier
purposes — it is host-originated; the egress filter + DSCP classifier are the
relevant inputs).

### 4.2 Classify

```
fn classify_generated_reply(
    forwarding: &ForwardingState,
    egress_ifindex: i32,
    frame: &[u8],
    now_ns: u64,
) -> GeneratedReplyVerdict
```

returns `{ drop: bool, cos_queue_id: Option<u8>, dscp_rewrite: Option<u8>,
filter_log: Option<FilterLogMatch> }` by:

1. `generated_reply_session_key(frame)` → `(key, meta)` (None ⇒ fail-closed
   per §6: on a parse failure, *do not drop*; emit unclassified, see §6.2).
2. `resolve_cos_tx_selection_at(forwarding, egress_ifindex, meta, Some(&key),
   now_ns)`.

This deliberately reuses `resolve_cos_tx_selection_at` (the *runtime-counted*
variant) so output-filter counters/policers/log are charged exactly once,
identically to transit. The only new code is the bytes→key parser and the
per-generator wiring.

### 4.3 Wire each generator

- **Time Exceeded** (`icmp.rs`): replace the trigger-keyed
  `resolve_cos_tx_selection_at(..., meta, Some(&flow.forward_key), ...)` with
  `classify_generated_reply(forwarding, target_ifindex, &prebuilt_frame,
  now_ns)`. Keep `cos_tx_selection_resolved: true` (now correctly resolved on
  the generated tuple). `target_ifindex` (the resolved egress, accounting for
  `bind_ifindex`) is the correct egress for the output filter — NOT
  `ingress_ident.ifindex`. (Current code resolves CoS on `ingress_ident.ifindex`
  via the helper's egress arg; the generated reply egresses on `target_ifindex`.
  This is a latent correctness nit the fix also corrects — call out in PR.)
- **Reject reply** (`reject_reply.rs`): after `build_*` produces `bytes`, call
  `classify_generated_reply(forwarding, ingress_ifindex, &bytes, now_ns)`. If
  `drop` ⇒ do not enqueue, count a dedicated
  `policy_reject_output_filter_drops` (distinct from budget drops), return
  false (fail-closed to the silent drop the caller already does). Else set
  `cos_queue_id`/`dscp_rewrite` on the `TxRequest`. `ingress_ifindex` IS the
  egress for a reflected reply (it goes back out the interface it came in on).
- **SYN-cookie reply** (`cookie_reply.rs`): same wiring as reject. A SYN-cookie
  SYN-ACK dropped by an output filter is a legitimate operator choice (rare).
  Count `syn_cookie_output_filter_drops`.

### 4.4 Mirror

Per §10 scope fence: **do not** wire port-mirror in this fix. Document in the
PR that input-direction mirror already captures the trigger and output-direction
mirror is tracked as a follow-up (§10 names the issue to file). The
`mirror_clone: false` stays; a code comment cross-references the follow-up so
the next reader does not "fix" it accidentally.

---

## 5. Path options — COMMITTED: Path B

> **r3 decision (Codex-r1 blocker):** Path B is the COMMITTED design, not one
> of three equal choices. Paths A and C are recorded below only as
> rejected-with-reason so the next reader does not re-litigate them. `/engineer`
> implements Path B; it must NOT route generated replies through the transit
> `PendingForwardRequest` loop (Path A's transit-loop / wrong-direction-mirror
> hazard).

### Path A — re-inject through the normal egress pipeline as a PendingForwardRequest

Build the reply, then feed it into the same `pending_forwards` path transit
uses (`PendingForwardFrame::Prebuilt` with `cos_tx_selection_resolved: false`),
letting the dispatch loop re-resolve CoS + run mirror on it.

- **Pros:** maximal reuse; mirror would come "for free" if/when output mirror
  exists; one classification site.
- **Cons:** (1) the dispatch loop classifies on `request.meta`/`request.flow_key`
  — still the TRIGGER unless we ALSO synthesize a generated meta+flow_key, so
  Path A does not actually avoid the parser; it just moves it. (2) The reject /
  cookie replies are `TxRequest`s on a different (drain) path; converting them
  to `PendingForwardRequest`s is a larger, riskier refactor touching the hot
  ingress loop. (3) The dispatch loop's mirror is INPUT-direction
  (`enqueue_sampled_mirror_clone(..., ingress_ifindex, ...)`) — it would mirror
  the reply as if it were *ingress* on the egress interface, which is wrong
  semantics, so the "free mirror" is illusory. **Rejected** as higher-risk for
  no real mirror benefit.

### Path B — explicit generated-reply classification contract (RECOMMENDED)

The §4 design: one `classify_generated_reply(bytes, egress_ifindex)` helper;
each generator calls it on its built bytes before enqueue; mirror deferred.

- **Pros:** minimal, scoped, testable in isolation (no BindingWorker needed —
  pure function over `ForwardingState` + bytes); reuses
  `resolve_cos_tx_selection_at` so counters/log/policer semantics are identical
  to transit by construction; corrects the Time Exceeded egress-ifindex nit;
  fail-closed parse handling is explicit.
- **Cons:** one new bytes→key parser (mitigated by reusing `frame::inspect`);
  three call-site edits; ICMP "ports = 0" needs a one-line justification in the
  filter-eval contract (already true for how ICMP is keyed today).
- **Hot-path cost:** all three generators are COLD
  (`#[cold] #[inline(never)]` reject/cookie; Time Exceeded fires only on
  TTL≤1). The added parse + classify is one L2/L3/L4 walk + one filter eval —
  on the exception path only, never per transit packet. Net hot-path delta:
  **zero**.

### Path C — stamp the verdict at build time inside each builder

Have each `build_*` function itself compute and return the queue/dscp/drop
alongside the bytes.

- **Cons:** spreads classification logic across 3+ builders (violates "one
  source of truth"); the builders currently take `&ForwardingState` only for
  egress lookup, and threading the full filter-eval into each duplicates the
  transit logic. **Rejected.**

**COMMITTED: Path B.** (Paths A + C are rejected-with-reason above and are not
re-openable without a new research round.)

---

## 6. Failure / fail-closed policy

### 6.1 Output-filter DROP of a generated reply — is it desirable?

**Yes, and it must be honored.** Junos applies output firewall filters to
host-generated traffic that egresses an interface; an operator filter that
`discard`s the reply is a deliberate policy (e.g. suppress ICMP unreachables
toward the internet, RFC-1812-style). The fix MUST let an output-filter
terminal `discard`/`reject` drop the generated reply. Each generator already
fail-closes to a silent drop on a build failure, so "classify says drop" maps
cleanly onto the existing drop return — with a dedicated counter so the drop is
attributable (not conflated with budget/parse drops).

### 6.2 Parse failure of the generated bytes — FAIL-CLOSED (Codex-r1 + AGY-r1)

**Decision (changed in r3): DROP the generated reply on any internal parse
failure, and bump a dedicated `generated_reply_classify_parse_errors` counter.**

The r2 plan proposed fail-OPEN (emit unclassified). Both external reviewers
returned PLAN NO on this: an output-filter terminal `discard`/`reject` is a
**security boundary** (e.g. suppressing outbound ICMP unreachables to hide
topology, RFC-1812-style). If the generated-bytes parser chokes and we fail
open, the reply leaks out PAST a `discard` filter the operator installed — the
bug restated as a security bypass. The reviewers' point stands and overrides
the r2 rationale.

Fail-closed is consistent with the rest of the project (CLAUDE.md,
engineering-style §"Overflow / failure policy": "Invariant violation at runtime
… bump a dedicated counter, continue" — here "continue" = drop this one reply,
not unwind). It is also consistent with how EVERY generator already fail-closes
to a silent drop on a build failure: a classify-parse failure folds onto the
identical drop return path. The dedicated counter makes the (logic-bug-only)
event attributable so it is never silent. The bytes are our own, so a parse
failure remains a logic bug — but the safe failure mode for a security-relevant
classification is to drop, not to leak.

SMR §A1 (which leaned fail-open) is overruled by the convergent Codex+AGY
finding; SMR r2 concurs.

### 6.3 TX-frame / budget exhaustion

Unchanged. The reject/cookie budget gate
(`syn_cookie_reply_budget_available`) runs BEFORE classification and still
fail-closes. Classification does not allocate a TX frame (it only decides
queue/dscp/drop); the frame is allocated later in `enqueue_local_into_cos` /
transmit, same as today.

---

## 7. HA / fabric interaction

- Generated replies are emitted on the **owner** node for the flow; they are
  not session-synced (they are stateless control frames). No HA delete/sync
  callback touches them.
- Fabric: the Time Exceeded path already early-returns
  `Some(false)` when `meta.meta_flags & FABRIC_INGRESS_FLAG` is set
  (`packet_ttl_would_expire`, `icmp.rs:6-8`) — i.e. it never generates a Time
  Exceeded for a frame that arrived over the fabric. Reject/cookie replies are
  on the local ingress path. The classification helper reads only
  `ForwardingState` (per-node, already HA-consistent) + the generated bytes, so
  there is no new cross-chassis state. **No fabric regression surface.**
- `make test-failover` is NOT strictly required by this change (no cluster /
  VRRP / session-sync / failover code touched), but `/engineer` should still
  run the standalone deploy + a targeted feature validation (output filter
  dropping a generated ICMP error) per engineering-style §8.

---

## 8. Files touched (estimate, for `/engineer`)

| File | Change |
|---|---|
| `userspace-dp/src/afxdp/frame/inspect.rs` (or a new `frame/generated.rs`) | NEW `generated_reply_session_key()` parser (reuses existing readers) |
| `userspace-dp/src/afxdp/tx/cos_classify.rs` | NEW `classify_generated_reply()` thin wrapper over `resolve_cos_tx_selection_at` |
| `userspace-dp/src/afxdp/icmp.rs` | Time Exceeded: classify on generated bytes + correct egress ifindex |
| `userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs` | classify before enqueue; honor drop; new counter |
| `userspace-dp/src/afxdp/poll_descriptor/cookie_reply.rs` | classify before enqueue; honor drop; new counter |
| counters (`umem/mod.rs` + snapshot + Go `pkg/api/metrics_userspace.go` / protocol) | new drop/parse-error counters surfaced to Prometheus |
| `userspace-dp/src/afxdp/.../tests` + builder tests | acceptance tests (§3) |
| `pkg/dataplane/README.md` or the relevant module doc | document generated-reply classification contract |

**Module-size note:** `icmp.rs` is ~535 LOC; adding the wiring + tests stays
under the 2,000-LOC smell threshold. The new parser belongs in `frame/`
(single-responsibility), not in `icmp.rs`.

**Counter wiring is a Go↔Rust wire-contract touch** (new snapshot fields). Per
the project's wire-bug history (#1961/#1976/#1977), `/engineer` MUST regenerate
`protocol_wire_v1.json` if a new wire field is added, and the architecture-
review step (engineering-style §4) applies because this adds protocol fields.

### 8.1 Implementation notes (Codex-r1 — non-blocking, but do these)

These are wiring details surfaced by the Codex r1 grounding pass; they are NOT
plan blockers (they do not change the design), but `/engineer` must handle them:

1. **ICMP-type keying is NOT in scope for the classifier.** The plan keys the
   generated reply on `(family, protocol, src/dst ip, ports=0)`. Codex
   confirmed the TX-selection eval (`filter/engine/tx_selection.rs`) does not
   key on `icmp-type` today; the plan does NOT rely on icmp-type matching (only
   `protocol icmp` + addresses). If a future operator wants `from { protocol
   icmp; icmp-type unreachable; }` to gate a generated reply, that is a
   SEPARATE filter-engine feature (file a follow-up); this fix neither needs
   nor adds it. Do not let an `/engineer` reviewer think the plan requires
   icmp-type matching.
2. **Counter wiring is two-tier.** New drop/parse-error counters need BOTH a
   per-batch `BatchCounters` field (incremented at the call site) AND a
   live/snapshot atomic field flushed at batch end — mirror the existing
   `policy_reject_*` / `syn_cookie_*` counter pattern in `afxdp/mod.rs` +
   `umem/mod.rs` + `umem/snapshot.rs`, then surface through the Go snapshot.
3. **Time Exceeded is called from MULTIPLE descriptor paths.**
   `build_local_time_exceeded_request` is reachable from several
   poll-descriptor sites; some do not currently thread a `&mut BatchCounters`.
   `/engineer` must either thread a counter handle to every Time Exceeded call
   site, or move the classify+count into a single shared choke point that all
   sites funnel through (preferred — "one source of truth"). The drop on
   output-filter `discard` must be counted on EVERY path, not just one.

---

## 9. Test strategy

1. **Unit (pure-function, no env):** `classify_generated_reply` over a
   constructed `ForwardingState` with an egress output filter:
   - `then discard` matching `protocol icmp` ⇒ `drop == true` for a generated
     Time Exceeded; `drop == false` for a generated RST whose tuple is TCP.
   - `then forwarding-class <fc>` ⇒ `cos_queue_id == queue_by_fc[<fc>]`.
   - DSCP-rewrite term ⇒ `dscp_rewrite == Some(expected)`.
   - filter matching the INBOUND TCP tuple ⇒ does NOT drop the generated ICMP
     error (the discriminating test).
2. **Counter-factual pin:** reconstruct `resolve_cos_tx_selection_at(...,
   trigger_meta, trigger_key, ...)` and assert it yields the WRONG verdict for
   the same fixtures — proving the test guards the actual failure mode
   (engineering-style "Test strength").
3. **Parse-failure path:** feed a truncated "generated" frame ⇒ unclassified
   emit + parse-error counter increment (§6.2).
4. **Per-generator integration (in-module tests):** reject_reply / cookie_reply
   produce a `TxRequest` with the classified queue/dscp; on filter-drop produce
   no `TxRequest` and bump the new counter.
5. **Feature validation (`/engineer`, standalone VM):** install an output
   filter `from protocol icmp; then discard` on the egress interface; drive a
   TTL-expired transit flow; confirm `show firewall` term counter advances and
   no ICMP error reaches the source (tcpdump on the test host). Confirm the
   same filter does NOT drop transit ICMP echo (sanity).

---

## 10. Scope fence (explicit)

**IN scope (this issue / one PR):**
- Time Exceeded, policy-reject ICMP unreachable, policy-reject TCP RST,
  SYN-cookie SYN-ACK, SYN-cookie ACK-RST — output filter + CoS + DSCP rewrite
  classified by the generated frame's own tuple/egress.

**OUT of scope (file follow-up issues, cross-reference in PR):**
- **Output-direction port-mirror of generated replies.** xpf implements only
  INPUT-direction port-mirror (`mirrors.go`: table keyed by ingress ifindex,
  one output per ingress; `mirror/mod.rs` resolves config by
  `ingress_ifindex`). Mirroring a host-generated egress frame is a new
  output-direction feature. Keeping it out honors engineering-style "bug fix
  and behaviour choice do not ride in the same PR." File: *"output-direction
  port-mirror (analyzer output) for transit + host-generated egress frames."*
- **Embedded-ICMP NAT-reversal classify-by-trigger**
  (`poll_descriptor/mod.rs:1182`). This is a *forwarded* (NAT-reversed inbound)
  ICMP error, not host-originated — it falls outside #2238's enumerated set. It
  shares the classify-by-trigger pattern and arguably should classify on the
  reversed tuple, but: (a) it is a transit frame so input-mirror already
  applies on its real ingress; (b) widening #2238 to it expands blast radius
  into the NAT path. File a sibling issue and decide there. (SMR §A3 argues for
  pulling it in — see disposition.)
- **NetFlow `sampling output`** — parsed in Go (`SamplingOutput`) but has no
  userspace consumer; unrelated to this bug.

---

## 11. Risks & mitigations

| Risk | Likelihood | Mitigation |
|---|---|---|
| New bytes→key parser drifts from the builders' wire format | Med | Parser reuses `frame::inspect` readers; builder tests feed real built frames through the parser (round-trip) |
| ICMP "ports = 0" mis-keys an output filter that matches `port` | Low | ICMP terms never match L4 ports in Junos; document; test an ICMP term + a port term coexisting |
| Output-filter DROP silently kills a reply an operator expected | Low/intended | Dedicated per-leg drop counter + `show firewall` term counter make it attributable; this is the desired behavior (§6.1) |
| Wire-contract regression on new counters (Go↔Rust) | Med | Regenerate `protocol_wire_v1.json`; reflection guard; decode test (per #1976/#1977 lesson) |
| Parse FAIL-CLOSED drops a reply on a builder/parser logic bug | Low | r3: fail-closed (drop) chosen over fail-open per Codex+AGY (an output `discard` is a security boundary; leaking past it is worse than dropping one control reply). Dedicated `generated_reply_classify_parse_errors` counter makes the (logic-bug-only) drop attributable — never silent (§6.2) |
| Touching `icmp.rs` collides with owner WIP | Med | `/engineer` re-confirms `icmp.rs` clean before editing (issue comment caveat) |
| Time Exceeded egress-ifindex correction changes behavior | Low | It is a correctness fix (classify on real egress); covered by a dedicated test asserting `target_ifindex != ingress` routes to the egress filter |

---

## 12. Reviewer verdict ledger

Round-by-round verdicts recorded in:
- `claude-smr-plan-r<N>.md`
- `codex-plan-r<N>.md`
- `agy-plan-r<N>.md`

Task IDs in `reviewer-ids.md`.
