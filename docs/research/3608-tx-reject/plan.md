# Plan: output firewall-filter `then reject` on the TX/CoS path — active reject vs silent drop (#3608)

## 1. Status

DRAFT v1 — pending adversarial plan review (Codex + AGY + Claude SMR).

Research-only. Stops at PLAN-READY / PLAN-DEFER / PLAN-KILL. No production
source changes, no PR. Implementation begins only on an explicit `/engineer
3608` after this plan converges and is manually approved.

Base: origin/master `a2c524281` (research worktree
`.claude/worktrees/3608-research`, branch `research/3608-tx-reject`).

## 2. Issue framing

On the TX/CoS forwarding path, a **transit** packet that matches an OUTPUT
firewall-filter terminal `then reject` term is realized as a **silent drop**
instead of an **active reject** (TCP RST for TCP, ICMP/ICMPv6 admin-prohibited
unreachable otherwise). The security boundary IS enforced — the packet never
egresses — but the source endpoint sees a timeout rather than an RST/unreachable.

Input-filter, lo0/host-bound, and policy `then reject` were already made active
rejects (#2089 policy, #2521 filter, #3071 zone-tcp-rst, #3445 lo0 nft). Output
firewall-filter reject on the transit egress path is the remaining residual,
documented but (until #3608) untracked (M11).

The issue folds:
- **M11** — file/confirm an issue-history entry for the output-filter-reject
  follow-up (previously undocumented as a tracking item).
- **L05** — a reusable reject-reply-synthesis interface independent of inbound
  descriptor ownership (the TX descriptor is being transmitted, not received).

## 3. Honest scope/value framing

**What the win actually is:** Junos parity + operator-visible diagnostics. An
operator who writes `filter output <f> term t then reject` expects the remote
endpoint to get an RST/unreachable, matching `then reject` everywhere else. Today
they silently get the `discard` behavior.

**What the win is NOT:** this is not a security-enforcement fix. The drop already
denies the traffic correctly. Severity is **Medium** (Codex H03) — a parity /
observability gap on an already-enforced action, not an open hole.

**Value realism:** output-firewall-filter `reject` (as distinct from policy
reject or input-filter reject, both already active) is a diagnostic niche. This
argues the change must be **low-cost and low-risk** to be worth doing — a large
refactor would not clear the value bar. The research below finds the machinery
and a same-function precedent already exist, so option (a) is in fact low-cost;
that is the crux of the READY-vs-DEFER decision.

## 4. What's already shipped / partially batched (the machinery exists)

The pessimistic framing in the #2521 README ("that site lacks the
descriptor/packet context the reflected-reply synthesis needs") predates the
precedents that remove the blocker. Chronology (verified via `git show -s`):

- **#2301 (merged 2026-06-21, `292ae40cf`)** — "add egress-MTU PTB decision to
  the generic forwarder". Introduced synthesizing a reply frame from the
  **transit forward path** (`enqueue_pending_forwards`, `tx/dispatch/mod.rs`) and
  L2-reflecting it back out the **ingress** interface via
  `ingress_binding.tx_pipeline.pending_tx_local`.
- **#2328 (`d251ed645`)** — routed that generated PTB through
  `classify_generated_reply` (output-filter/CoS/DSCP parity), keyed on the
  reply's OWN egress tuple + logical ifindex.
- **#2521 (merged 2026-06-24, `541b7d9f5`)** — active reply for **filter**
  `then reject` on the input/lo0 path, via the shared `enqueue_filter_reject_reply`.

So the forward/TX path already reflects-and-classifies a generated reply back out
the ingress interface (#2301/#2328, in the SAME function as one of the three
drop sites), and the reusable reject-reply interface already exists (#2521).
`enqueue_filter_reject_reply(tx_pipeline, forwarding, ingress_ifindex,
packet_frame: &[u8], meta, flow, counters)` takes a **byte slice**, not a
descriptor — it is **already descriptor-ownership-independent** (the L05 concern
is largely already satisfied by the #2521 signature).

**Conclusion:** #3608 is not a new subsystem. It is (1) recovering the `Reject`
signal that the TX-selection code deliberately collapses to a bool, and (2)
calling the existing synthesis at the three egress drop sites. The "lacks
context" note was a **scoping** decision at #2521 time, not a hard architectural
blocker.

## 5. Concrete design

### 5.1 Root cause (file:line, current master)

`CoSTxSelection` / `CachedTxSelectionDescriptor` carry only a `drop: bool`. Both
sites that compute it collapse the action:

- `tx/cos_classify.rs:230` (cached):
  `drop: output_result.action != crate::filter::FilterAction::Accept`
- `tx/cos_classify.rs:412` (runtime-counted):
  `let mut drop = output_result.policer_drop || output_result.action != Accept;`

`FilterAction` (filter/mod.rs:42) has `Accept | Discard | Reject` — the `Reject`
variant IS present at compute time and is thrown away. Downstream, three drop
sites act on the bool with a silent recycle:

1. **HOT cached path** — `poll_descriptor/flow_cache_hit.rs:181`
   `if cached_descriptor.tx_selection.drop || policer_action.drop {
   scratch.scratch_recycle.push(desc.addr); return Consumed; }`
   Has: original `packet_frame` (line 92), ingress `tx_pipeline`, `meta`, `flow`,
   `worker_ctx.forwarding`, `counters` (via telemetry). This is where most packets
   of an established rejected flow land.
2. **Deferred/pending-forward path** — `tx/dispatch/mod.rs:136`
   `let cos = resolve_pending_forward_cos_tx_selection(...); if cos.drop {
   recycle_ingress_frame(...); continue; }`
   Has: `ingress_binding` (frame at `request.desc.addr` in its UMEM, still valid
   before the drop-branch recycle), `request.meta`, `forwarding`, `counters`,
   `ingress_ident`. Same function as the #2301/#2328 PTB precedent
   (`tx/dispatch/mod.rs:1135-1185`).
3. **Slow-path build** — `forward_request.rs:215` `if cos.drop { return None; }`
   Has: `frame: &[u8]`, `meta`, `forwarding`, `flow`. Does NOT currently take
   `tx_pipeline`/`counters` — synthesis must be lifted to the caller or the fn
   extended (see 5.3).

### 5.2 Recover the `Reject` signal

Add a boolean discriminator distinguishing a terminal `Reject` from a `Discard`
or a policer drop. Two in-memory structs (NOT wire-serialized — flow cache is
process-local, no proto/JSON impact):

```rust
// tx/cos_classify.rs
struct CoSTxSelection {
    queue_id: Option<u8>,
    dscp_rewrite: Option<u8>,
    drop: bool,
    reject: bool,          // NEW: drop && action == Reject (NOT Discard/policer)
    filter_log: Option<FilterLogMatch>,
}
// flow_cache.rs
struct CachedTxSelectionDescriptor {
    queue_id: Option<u8>,
    dscp_rewrite: Option<u8>,
    drop: bool,
    reject: bool,          // NEW
    filter_counters: ...,
    three_color_policers: ...,
    filter_log: Option<FilterLogMatch>,
}
```

Set `reject = (output_result.action == FilterAction::Reject)` at both compute
sites. Invariant: `reject` implies `drop`; a policer drop or `Discard` sets
`drop=true, reject=false`. `drop` semantics are UNCHANGED (packet still dropped
from the forward path); `reject` is a strictly additive signal.

### 5.3 Synthesize at the three drop sites (option (a))

At each site, replace the bare silent recycle with:

```rust
if sel.drop {
    if sel.reject {
        // reflect the ORIGINAL inbound frame back out the INGRESS interface
        let _ = enqueue_filter_reject_reply(
            ingress_tx_pipeline, forwarding, ingress_ifindex_physical,
            original_frame, meta, flow, counters);
        // return value ignored: fail-closed drop happens regardless
    }
    <existing silent recycle>;   // unchanged — the transit frame is always dropped
}
```

- **Site 1 (hot cached):** call directly with `tx_pipeline`, `packet_frame`,
  `meta.ingress_ifindex as i32`, `flow`, `counters`. The reply enqueues to the
  current (== ingress) binding's `pending_tx_local`, egressing back out the
  ingress interface toward the source — identical to the input-path reject.
- **Site 2 (deferred):** read `ingress_binding.umem.area().slice(source_offset,
  request.desc.len)` BEFORE `recycle_ingress_frame`, then call with
  `ingress_binding.tx_pipeline` and `ingress_ident.ifindex`. Mirrors the #2301
  PTB block already in this function.
- **Site 3 (slow-path build):** simplest correct wiring is to have
  `build_live_forward_request_from_frame` return a discriminated drop
  (`Some(Rejected)` vs `None`) OR return `None` plus set a caller-visible reason,
  and have the caller (which owns `tx_pipeline`/`counters`) synthesize. Preferred:
  return an enum `ForwardBuildOutcome { Request(..), Drop, Reject }` so the caller
  branches. Alternative (heavier): thread `tx_pipeline`+`counters` into the
  builder. The enum is cleaner and keeps the builder side-effect-free.

**Reflection correctness (why the original inbound frame is the right input):**
`build_reject_rst_frame(frame)` reflects L2/L3/L4 (dst←src) and sets RST →
reply src = original dst, dst = original src, egress = ingress. For non-TCP,
`build_reject_icmp_unreachable(frame, meta, ingress_ifindex, forwarding)` sources
the ICMP from the firewall's ingress-interface primary and embeds the original
datagram. Because we reflect the **pre-NAT, pre-rewrite** inbound bytes, the
reply carries the addresses the source actually used — **correct under SNAT and
DNAT** (the source never saw the translation). Using the original frame (present
at the drop sites) is therefore a correctness advantage over any "rebuild from
the post-routing egress tuple" approach. Tuple reversal (L05) is performed by the
existing builders — no new reversal code.

**Inherited safety (no new emit path):** `enqueue_filter_reject_reply` already
routes through: the SYN-cookie TX-frame budget gate (transit-TX starvation
protection), the #2472 per-reason `GeneratedErrorReason::Reject` token bucket
(backscatter/amplification cap), `classify_generated_reply` on the reply's own
tuple (a reply that itself matches an output `discard`/`reject` fails closed — no
loop), fail-closed on non-first-fragment / inbound-RST / unparseable, and the
`filter_reject_sent` success counter. All inherited for free.

### 5.4 Option comparison (the design fork)

- **(a) Synthesize at TX-filter-match time (RECOMMENDED).** Thread `reject` +
  call the shared interface at the three drop sites. Reuses #2301/#2328/#2521;
  moderate, well-precedented. Per-packet reject reply (Junos-faithful).
- **(b) Move the reject decision earlier (pre-TX).** Evaluate the egress output
  filter's terminal reject during slow-path session resolution and synthesize
  there. Problem: the output filter is keyed on the post-routing egress ifindex,
  which is only known after routing — i.e. exactly where forward_request already
  runs. A "reject once at establishment then cache drop" variant UNDER-generates
  vs Junos (which rejects every packet). A "cache the reject signal, synthesize
  per-packet at the cached drop site" variant IS option (a). So (b) is either
  semantically wrong or converges to (a). **Rejected as a distinct path.**
- **(c) Commit-time warning, keep drop (FALLBACK / DEFER).** Emit a
  commit-time warning that output-filter `then reject` degrades to a silent drop,
  following the #3445 lo0-mirror-modifier and #3295 no-catch-all warn-not-reject
  precedent (`pkg/config`, lenient on load/peer-sync per #1960). Cheapest;
  preserves the correct drop; makes the gap operator-visible. Does NOT achieve
  active reject. This is the honest DEFER outcome if reviewers judge the hot-path
  touch not worth the Medium value.

Recommendation: **(a)**. If reviewers push back on the hot-path multi-site touch,
fall back to **(c)** and defer (a) behind #3608 (kept open).

## 6. Public API preservation

- No gRPC / HTTP / proto / CLI surface change. `filter output <f> then reject`
  already parses/compiles today (it just realizes as drop). No new config syntax.
- `CachedTxSelectionDescriptor` and `CoSTxSelection` are `pub(super)` /
  `pub(in crate::afxdp)` in-process structs; not serialized to disk, wire, or the
  control socket. Adding a field is source-internal.
- `drop` field semantics preserved bit-for-bit (packet still dropped). `reject`
  is purely additive.
- `enqueue_filter_reject_reply` signature reused as-is; no change to its callers
  on the input path.
- Option (c) alternative: additive commit-time WARNING only (never a new reject);
  lenient path unchanged (#1960 no-brick).

## 7. Hidden invariants the change must preserve

1. **`reject ⟹ drop`.** The transit frame is ALWAYS dropped from the forward
   path; the reject reply is a SEPARATE synthesized frame. Never leak the
   original past the filter.
2. **Fail-closed.** If synthesis returns `false` (budget/bucket/parse/fragment/
   inbound-RST), the silent drop still happens — the return value is ignored for
   the drop decision, only for the counter.
3. **Policer / `Discard` unaffected.** `policer_action.drop` and `Discard` keep
   `reject=false` → silent drop, no reply. Only terminal `Reject` synthesizes.
4. **Reply egresses the INGRESS interface, not the egress interface.** The reply
   goes back toward the source; classification uses the reply's own logical tuple
   (`classify_generated_reply`), matching #2328/#3035.
5. **No reply loop.** The reply is classified once (bool drop), never
   re-synthesized; it egresses a different interface than the rejecting output
   filter's interface in the common case, and fail-closes if the ingress
   interface's own output filter rejects it.
6. **Hot-path cost is on the exception arm only.** The `if drop` branch already
   exists; `if reject` executes synthesis only on a reject MATCH (rare). Steady
   accept/transit path adds one field read, no new allocation.
7. **Direction correctness.** Forward and reverse flows use distinct cache slots
   with independently-computed `reject`; each direction reflects its own packet.

## 8. Risk assessment (4-class)

| Class | Level | Detail / mitigation |
|-------|-------|---------------------|
| Behavioral regression | LOW–MED | `drop` semantics unchanged; `reject` additive. Risk is confined to the reject-match arm. 2 existing tests (`cos_classify_tests.rs:1477`, `:1424`) assert `selection.drop` on reject/discard — still pass (`drop` stays true); extend to assert `reject==true`/`false`. MED only because it touches the HOT `flow_cache_hit` path (site 1). |
| Lifetime / borrow-checker | MED | Site 2 needs a shared UMEM slice read from `ingress_binding` while later taking `&mut ingress_binding.tx_pipeline` — the #2301 PTB block already does exactly this split-borrow in the same function (proven pattern). Site 3 enum-return avoids threading a `&mut tx_pipeline` into the builder. |
| Performance regression | LOW | Steady state: one bool field in an existing struct + one branch already predicted-not-taken. Reject synthesis is cold/exception and rate-limited (#2472). No per-transit-packet cost on accept. A reject-filter applied to a high-volume flow generates rate-limited replies (bounded) + the existing drop — same profile as policy reject. |
| Architectural mismatch | LOW | Not a #961/#946-style dead-end. Reuses the exact #2301/#2328 forward-path reply pattern and the #2521 interface. No new subsystem, no new emit path, no wire/proto change. |

Edge cases to cover in the plan-review: (i) fabric-redirect egress + output
reject (the peer owns the egress output filter; the local node reflects out its
own ingress — document as out-of-scope for the peer's filter); (ii) IPv6/ICMPv6
(builder already dual-stack, icmp.rs:86/111); (iii) non-first fragment (builder
fail-closes); (iv) generated reply itself matching the ingress output filter
(fail-closed, no loop).

## 9. Test plan

Unit (Rust, `cargo test -p userspace-dp`):
1. `cos_classify`: `then reject` output filter sets `reject=true, drop=true`;
   `then discard` sets `reject=false, drop=true`; policer drop sets
   `reject=false, drop=true`; accept sets both false. (extend the two existing
   `:1424`/`:1477` tests + add discriminator asserts.)
2. Cached descriptor round-trips `reject` (flow_cache build → cache hit).
3. Site 1 (hot cached): a cached reject descriptor enqueues an RST (TCP) /
   ICMP unreachable (non-TCP) to the ingress `pending_tx_local`, bumps
   `filter_reject_sent`, AND still recycles the transit frame. Fail-on-revert:
   remove the synth call → `pending_tx_local` empty + counter 0.
4. Site 2 (deferred): a pending-forward reject reflects out `ingress_binding`
   before recycle; split-borrow compiles.
5. Site 3 (slow-path build): the enum-return `Reject` arm synthesizes at the
   caller.
6. Fail-closed: budget exhausted / #2472 bucket empty / non-first fragment /
   inbound RST → no reply, transit frame still dropped (reuse the reject_reply.rs
   test fixtures).
7. NAT correctness: a SNAT'd / DNAT'd transit flow rejected on egress reflects
   the PRE-NAT original addresses toward the source.
8. No-loop: reply classified against an ingress output `discard` → fail-closed
   drop, no second synthesis.

Full suite: `cargo test -p userspace-dp` (all ~950+ tests green), `cargo build`
clean, `cargo clippy` clean.

Smoke (loss userspace cluster, at `/engineer` time — NOT in `/research`):
- Configure `set interfaces reth0.80 unit 80 family inet filter output block
  term t from ... then reject` on the WAN egress. Drive a TCP flow from the LAN
  host; `tcpdump` on the LAN host MUST show an inbound RST (today: timeout).
- Non-TCP (UDP/ICMP) → ICMP admin-prohibited unreachable on the source.
- `show firewall filter` counters + `filter_reject_sent` advance.
- Confirm `then discard` on the same term still silently drops (no reply).
- Regression: plain forwarding throughput unchanged (no per-packet cost).

## 10. Out of scope (explicitly)

- **Fabric-redirected egress output filters** (the peer owns the egress
  interface's output filter; cross-chassis reject synthesis is a separate item).
- **A distinct `output_filter_reject_sent` counter** — reuse `filter_reject_sent`
  unless observability review demands the split (cheap follow-up if so).
- **Option (b)** entirely (rejected in 5.4).
- **lo0/host-bound and input-filter reject** (already shipped #2521/#3445).
- **M11 issue-history mechanics:** `docs/issues/issue-history.md` is GENERATED
  from GitHub (via `/sync-history`), not hand-edited. #3608 now exists as the
  tracking issue, so M11 ("no tracking entry") is RESOLVED by the issue itself and
  will appear on the next history regen. No manual doc edit in this plan (and none
  permitted under the `/research` no-production-source rule).

## 11. Open questions for adversarial review (≥5)

1. **Value bar:** is per-packet active reject on the output-filter path worth a
   3-site hot-path touch, or is the #3445-style commit-time WARNING (option c)
   the right terminal answer? (PLAN-READY(a) vs PLAN-DEFER(c).)
2. **Site 3 shape:** enum-return `ForwardBuildOutcome` vs threading
   `&mut tx_pipeline`/`counters` into `build_live_forward_request_from_frame` —
   which keeps the builder cleanest without a borrow tangle?
3. **Frame availability at site 2:** is `request.desc.addr` in the ingress UMEM
   guaranteed valid at `tx/dispatch/mod.rs:136` before `recycle_ingress_frame`,
   for BOTH `Live` and `Prebuilt` frame variants? (Prebuilt = NAT-reversed ICMP —
   does reflecting it make sense, or restrict reject synthesis to `Live`?)
4. **Reflection source-address semantics:** for a transit TCP reject, the RST
   carries L3 src = original destination (spoofed toward the source). Is that the
   desired Junos behavior for `then reject` on an OUTPUT filter, or should the RST
   be sourced from the firewall? (Policy reject / #2521 already reflect this way —
   confirm parity is intended, not an accident to inherit.)
5. **Backscatter under a reject-everything output filter on a high-rate flow:**
   is the shared #2472 `Reject` token bucket sufficient, or does the output-filter
   path need its own budget so it cannot starve policy/input reject replies?
6. **Counter attribution:** is folding output-filter reject into the existing
   `filter_reject_sent` acceptable, or must `show` distinguish input vs output
   filter reject for operator diagnostics?
7. **Deferred cos.rs path:** `resolve_pending_forward_cos_tx_selection` runs
   "after the UMEM frame may have been recycled" (cos.rs:141) — does any reject
   drop actually reach site 2 with a live frame, or is site 2 unreachable for
   reject in practice (making 2 sites, not 3)?
