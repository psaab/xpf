# #1849 — CoS per-packet overhead compensation (CAKE-style) for shaped WAN links

## 1. Status

- Revision: v1 (initial draft for hostile 3-way review)
- Branch: `research/1849-overhead-comp` (plan docs only, no production code)
- Issue: #1849, split from #1828 Option D at its convergence
  (`docs/research/1828-wan-sq/plan.md` v3, §4 Option D + §3 inventory row
  "Overhead compensation").
- **This plan explicitly invites PLAN-KILL.** The parent convergence flagged
  this feature as "dead weight for the high-rate-Ethernet loss cluster ...
  demand-gated; needs its own plan + evidence round". There is no demand
  evidence on file, no framed (PPPoE/ATM/DOCSIS) link in any lab environment
  to prove the real-world win on, and the affected code is the single most
  perf-sensitive region of the project (#1755/#1763 fought for fractions of a
  percent there). If the reviewers conclude the documented 85–95% headroom
  workaround (`docs/cos-wan-sqm.md` "Picking the rate") is adequate until a
  user actually asks, killing or deferring this is a correct outcome, not a
  failure.

## 2. Issue framing

The userspace CoS engine accounts **payload bytes** for shaping and
scheduling (`docs/cos-traffic-shaping.md:525-532` "Memory Accounting":
payload bytes for shaping/scheduling, UMEM frames for memory safety). On
low-rate framed uplinks (PPPoE/DSL/DOCSIS, VLAN handoffs), per-packet framing
overhead (Ethernet preamble+IFG ≈ 24 B, PPPoE 8 B, ATM cell padding) is
invisible to the token bucket, so a shaper set at 95% of contract still
overdrives the link on small-packet-heavy mixes — defeating the core SQM goal
of keeping the queue out of the CPE/modem buffer. CAKE treats `overhead N`
(+ `atm`/`ptm` cell modes + `mpu`) as a correctness feature for exactly this.

The xpf workaround today is documented headroom: shape at 85–95%, "stay
nearer 85%" on framed links (`docs/cos-wan-sqm.md:135-145`), over-sacrificing
throughput on large-packet mixes to stay safe on small-packet mixes.

## 3. Affected-code inventory (verified, every byte-debit site)

All byte-denominated accumulators in the CoS engine fall into two domains.
File refs are at `origin/master` `c40310e08`.

### 3a. Rate domain — denominated in configured wire-rate units

These all measure against `shaping-rate` / `transmit-rate`, i.e. against a
number that physically describes the wire. These are the compensation
candidates:

| # | Accumulator | Sized/credited | Debited |
|---|---|---|---|
| R1 | `root.tokens` (root shaper) | refill from `shaping_rate_bytes` + lease top-up sized by `head_len` (`cos/token_bucket.rs:115-137`) | `sent_bytes` at tx-completion (`cos/tx_completion.rs:550,735,843`) and direct-exact (`:550` via `apply_direct_exact_queue_accounting`) |
| R2 | `SharedCoSRootLease` (cross-worker root budget) | `acquire(now, deficit)` (`token_bucket.rs:134`) | `consume(sent_bytes)` (`tx_completion.rs:570`) |
| R3 | `queue.hot.tokens` (per-class guarantee / transmit-rate) | lease/refill sized by `head_len` (`token_bucket.rs:220-296`) | `sent_bytes` (`tx_completion.rs:542,706,812`) |
| R4 | `queue.hot.surplus_deficit` | — | `sent_bytes` (`tx_completion.rs:710,816`) |
| R5 | `SharedCoSQueueLease` v8 (equal-flow / fair-share) | coordinator-granted | `maybe_consume_exact_queue_lease(.., sent_bytes)` (`tx_completion.rs:368-379`) |
| R6 | Drain pass budgets `remaining_root`/`remaining_secondary` | sized from tokens | `-= cos_item_len(front)` (`queue_service/mod.rs:1649-1650,1692-1693`; `queue_service/drain.rs:107-108,246-247`) |
| R7 | Waterfill Phase-1 budget / `exact_demand_rate` / `residual_rate` (#1614 A1, #1743) | from configured rates (`queue_service/mod.rs:335`) | byte decrements in the selector |
| R8 | Runnable/parking estimates `cos_tokens_runnable_after(tokens, need=head_len, rate)` (`token_bucket.rs:332-365`) and head-vs-token comparisons (`tx_completion.rs:397-409`, `queue_service/mod.rs:524,650,960,1162,1261,1352`) | — | comparison sites, must use the same basis as R1/R3 |

### 3b. Occupancy domain — denominated in memory/backlog units

| # | Accumulator | Notes |
|---|---|---|
| O1 | `queue.hot.queued_bytes` | `+ item_len` at push (`queue_ops/push.rs:108,161` → accounting), `- sent_bytes` at completion (`tx_completion.rs:541`) and drop path (`queue_service/mod.rs:1612`). Dual-purpose: buffer/ECN admission vs `buffer_bytes` AND exact-backlog scheduling telemetry (`tx_completion.rs:388-409`). |
| O2 | MQFQ per-flow state: `flow_bucket_bytes`, `queue_vtime`, head/tail finish tags (`queue_ops/push.rs`, `pop.rs`, `accounting.rs`), `account_flow_bucket_tx` per-bucket TX rate | drives intra-queue fairness AND admission per-flow ECN/share caps (`cos/admission.rs:250-340`) |
| O3 | UMEM frame accounting | memory safety; never touched |
| O4 | Telemetry counters `drain_sent_bytes` etc. (`tx_completion.rs:502-531`), sojourn | operator-visible payload throughput; never compensated |

### 3c. Single choke points that make this tractable

- `cos_item_len(item)` (`cos/queue_ops/mod.rs:336-341`) is the only per-item
  length read in the scheduler (14 call sites, all with `queue`/`root`
  context in scope).
- Every settle function already returns `(sent_packets, sent_bytes)` pairs
  (`queue_service/mod.rs:1443-1560` and siblings), so batch-level wire bytes
  = `sent_bytes + sent_packets × overhead` with **zero new per-packet work**
  in the settle loops.

### 3d. Config/wire plumbing path (verified end-to-end)

`pkg/config/schema.go:1086-1088` (`shaping-rate { burst-size }` leaf) →
`pkg/config/compiler_class_of_service.go:304-313` (unit parse, both AST
shapes) → `pkg/config/types_cos.go:120-121` (`CoSInterfaceUnit`) →
`pkg/dataplane/userspace/interfaces.go:249` (`CoSShapingRateBytesPerSec`
plumb) → `pkg/dataplane/userspace/protocol.go:148-149`
(`InterfaceSnapshot`) → `userspace-dp/src/protocol/snapshot.rs:77-83` →
`userspace-dp/src/afxdp/forwarding_build/cos.rs:434` (`CoSInterfaceConfig`)
→ `types/cos.rs:369-372` (`CoSInterfaceRuntime`). Wire fixture:
`userspace-dp/tests/fixtures/protocol_wire_v1.json` (regen via
`XPF_PROTOCOL_WIRE_REGEN=1`), key-absent pins on both sides
(`userspace-dp/src/protocol/tests.rs:277` pattern).

## 4. Multiple Path Options (explicit)

### Option A — flat `overhead-accounting bytes N`, root shaper only

Compensate R1+R2+R6(root half)+R8(root comparisons) only. Per-class tokens,
MQFQ, occupancy all stay payload.

- **Pro:** smallest hot-path touch (~4 sites); directly fixes the only
  *correctness* problem (physical link overdrive — only the root shaper
  models the physical link).
- **Con:** incoherent boundary. `transmit-rate` guarantees are denominated in
  the same wire-rate units as `shaping-rate`; compensating one and not the
  other means class guarantee math and the root no longer add up — e.g. exact
  classes sized to sum to the shaping rate would underrun the root bucket on
  small-packet mixes, shifting the deficit entirely onto non-exact classes.
  The #1743/#1614 waterfill explicitly balances class budgets against the
  root budget; mixed bases re-introduce a skew of exactly the kind #1743
  fixed.

### Option B — flat add at every RATE-domain site (R1–R8), occupancy stays payload — RECOMMENDED IF NOT KILLED

One per-interface constant `overhead_bytes` (u64), resident on
`CoSInterfaceRuntime` adjacent to `tokens`/`shaping_rate_bytes`
(`types/cos.rs:370-372` — the same already-touched cache region as every
refill/debit) and copied into each `CoSQueueConfigState` at
`build_cos_interface_runtime` time (read alongside `exact`/
`guarantee_enabled` flags the selector already loads).

- Per-item sites (R6, R8 head peeks): `cos_item_wire_len(queue, item) =
  cos_item_len(item) + queue.config.overhead_bytes` — one u64 add, no
  branch, operand on an already-resident line.
- Batch debit sites (R1–R5): `wire = sent_bytes + sent_packets *
  overhead_bytes` — one mul+add per **batch**, packets count already
  returned by every settle fn.
- O1 `queued_bytes` keeps payload basis on BOTH push and completion sides
  (the basis-pairing invariant, §8-I2). O2 MQFQ stays payload (accepted
  residual: intra-queue fairness is payload-share, not wire-share — CAKE
  compensates here too; deferred, see §11).
- Default `overhead_bytes = 0` ⇒ bit-identical arithmetic to today
  (`x + 0`, `y + n*0`); no behavior change for every existing deployment.
- **Pro:** coherent boundary — *everything denominated in configured-rate
  units is wire bytes; everything denominated in memory is payload bytes*.
  Class ratios stay mutually consistent. Doc contract update is one line.
- **Con:** ~10–12 touched sites in the hottest code in the project; churn
  risk is the cost, not cycles.

### Option C — full CAKE parity: `frame-mode`/`cell-mode` (ATM 48/53 cell math) + `mpu`

Adds per-packet `ceil((len+overhead)/48)*53` for cell mode (div+mul per
packet, or reciprocal-multiply) and an `mpu` floor (`max`, branch-free cmov).

- **Pro:** the only mode that is *actually correct* for ATM-framed DSL; `mpu`
  is needed for exact Ethernet/DOCSIS accounting (min frame 64 B + preamble).
- **Con:** per-packet division in the hot path for a link type (ATM DSL) that
  is nearly extinct and that no user has asked for; doubles the config
  surface and test matrix. Junos precedent exists
  (`overhead-accounting (frame-mode|cell-mode)`), so the *spelling* must
  leave room for it, but the implementation has no demand basis.

### Option D — KILL / defer pending demand

No code. Keep #1849 open (or closed-not-planned) with a demand-gate note;
the `docs/cos-wan-sqm.md` headroom guidance (85% on framed links) remains the
documented workaround. Revisit on the first concrete user report of a framed
uplink deployment.

- **Pro:** zero risk to the hottest path; honest response to zero demand
  evidence; the workaround loses at most ~10% of contracted rate on
  large-packet mixes, on link classes (sub-100 Mbit DSL/DOCSIS) where xpf's
  AF_XDP dataplane is massively over-provisioned anyway.
- **Con:** the cookbook permanently ships with a "stay nearer 85%" fudge for
  a problem CAKE solved in 2015; the correctness argument from the parent
  plan ("most defensible Option D item") is abandoned rather than answered.

## 5. Config spelling (Junos parity — verified against Junos docs)

Real Junos syntax is `set class-of-service traffic-control-profiles <name>
overhead-accounting (frame-mode | cell-mode) bytes <-120..124>` (frame-mode
default; byte value rounded to multiple of 4 on Junos hardware). xpf has no
`traffic-control-profiles` tree — the shaper lives directly on the unit
(`shaping-rate { burst-size }`). Proposed spelling nests the Junos keyword
where the shaper actually is, exactly as `burst-size` already does:

```
set class-of-service interfaces <if> unit <u> shaping-rate <bw> overhead-accounting bytes <N>
```

- Keyword `overhead-accounting bytes` = Junos vocabulary, xpf-local
  placement (no profile indirection to invent).
- v1 accepts `bytes 0..124` (**unsigned**); negative values (Junos allows
  -120) are commit-rejected with a clear error until someone needs downward
  adjustment — this keeps every hot-path operation a pure u64 add with no
  clamp logic. Reviewers should adjudicate (§12 Q3).
- `frame-mode` is implied and not accepted as a token in v1; `cell-mode` is
  not accepted (Option C deferred). The schema shape leaves room to add both
  later without re-spelling.
- No rounding-to-4 (that is Junos ASIC behavior, not semantics).
- Typed-leaf validation in `config.SchemaValidate` (`schema_walk.go`), range
  + integer checks at commit (strict), lenient on Load/SyncApply (boot
  safety). Both AST shapes (hierarchical + flat-set) covered in
  compiler tests via `ParseSetCommand()` + `SetPath()` (the #1796/#1797
  flat-set-compiles-EMPTY class).

## 6. Concrete design (Option B, if not killed)

1. **Config:** `setSchema` child `overhead-accounting {args:0, children:
   {"bytes": {args:1}}}` under the existing `shaping-rate` node
   (`schema.go:1086`); `CoSInterfaceUnit.OverheadAccountingBytes uint64`
   (`types_cos.go`); compiler parse in `compiler_class_of_service.go`
   handling both AST shapes; commit-check range 0..=124, and warn-and-strip
   when set without `shaping-rate` (meaningless without a shaper, matching
   the `surplus_sharing` warn-and-strip precedent).
2. **Wire (additive):** `InterfaceSnapshot.CoSOverheadAccountingBytes uint64
   `json:"cos_overhead_bytes,omitempty"`` (protocol.go) ↔ snapshot.rs
   `#[serde(rename = "cos_overhead_bytes", default)]`. Fixture regen via
   `XPF_PROTOCOL_WIRE_REGEN=1`; key-absent pins BOTH sides (absent key ⇒ 0 ⇒
   bit-identical legacy behavior).
3. **Engine:** `CoSInterfaceConfig.overhead_bytes` → `CoSInterfaceRuntime
   .overhead_bytes` (placed adjacent to `tokens`) + copy into
   `CoSQueueConfigState.overhead_bytes` per queue. New helpers:
   `cos_item_wire_len(overhead, item)` for the per-item sites and
   `wire_batch_bytes(sent_bytes, sent_packets, overhead)` for the batch
   debits. Apply at R1–R8 per §3a; O1–O4 untouched. `sent_bytes`
   (payload) continues to feed `queued_bytes` decrements, telemetry, and
   sojourn untouched — only the token/lease/budget debits switch to the
   wire value.
4. **Status surface (small):** carry `overhead_bytes` in
   `CoSInterfaceStatus` (serde default) so `show class-of-service`/cosfmt can
   render it; operator can confirm what the engine is using.
5. **Docs (same PR):** `docs/cos-traffic-shaping.md` "Memory Accounting"
   gains the rate-domain/occupancy-domain distinction (payload bytes →
   "wire bytes = payload + configured overhead" for shaping/guarantee
   debits); `docs/cos-wan-sqm.md` overhead rows (lines 40, 143, 225) flip
   from "tracked as #1849" to the knob + guidance table (PPPoE 26+preamble,
   DOCSIS 18, plain Ethernet 38 incl. preamble/IFG if desired);
   `docs/config-schema.md` typed-leaf row.

## 7. Public API preservation

- Default 0 ⇒ arithmetic identity; no existing config changes meaning.
- Wire change is key-additive with serde default on both sides; old daemon ↔
  new helper and new daemon ↔ old helper both degrade to overhead=0.
- No gRPC/REST surface change beyond the config tree itself.
- Telemetry counters keep payload semantics (no operator dashboard breaks).

## 8. Hidden invariants the change must preserve

- **I1 (basis pairing):** for every accumulator, the credit/sizing site and
  the debit site MUST use the same basis. Lease sized with wire `head_len`
  but consumed with payload `sent_bytes` (or vice versa) silently leaks
  tokens → shaper drifts fast or slow permanently. The PR must include a
  table mapping every R-site pair and a test per pair.
- **I2 (`queued_bytes` drift):** push `+item_len` and completion
  `-sent_bytes` must remain payload-basis on both sides or `queued_bytes`
  drifts upward forever → queue never settles empty → flow-fair demotion
  (`cos_demote_empty_settles`, `queue_ops/mod.rs:318-333`) never fires and
  `runnable` logic corrupts.
- **I3 (overhead=0 identity):** with the knob unset the engine must be
  bit-identical in selection order and debit values — pin with a
  differential test in the `fused_diff_tests.rs` (#1763) style.
- **I4 (deploy wipes CoS):** smoke must re-apply CoS config after deploy
  (`test/incus/apply-cos-config.sh` / sqm fixture), standing gotcha.
- **I5 (hot-path discipline):** no new branches, no division, no new
  cachelines on the per-packet path (`docs/engineering-style.md`); the
  constant rides structs already resident at the touch sites.
- **I6 (#1829 coordination):** the sojourn/CoDel telemetry (PR #1846) reads
  payload-throughput counters; do not change their basis.

## 9. Risk assessment

| Risk | Level | Notes |
|---|---|---|
| Hot-path perf regression | LOW (cycles) | one u64 add per item-site, one mul+add per batch; operands on resident lines; default-0 |
| Correctness churn in hottest code | **MEDIUM-HIGH** | ~10–12 debit/sizing sites must stay basis-paired (I1/I2); this is the real cost and the main kill argument |
| Demand gate | **FAILS today** | zero user demand evidence; no framed link in any lab; reviewers must explicitly weigh §12 Q1 |
| Wire compat | LOW | additive + defaults + pins both sides |
| Config-surface risk | LOW | one nested leaf under an existing node; both-AST tests mandatory |
| Validation honesty | MEDIUM | only Ethernet-provable math (see §10); the real-world bufferbloat win is unprovable in-lab |

## 10. Test plan / validation evidence (what is actually provable)

The loss cluster is plain Ethernet — there is **no** PPPoE/ATM link anywhere
to demonstrate the CPE-buffer win. What IS provable:

1. **Unit (Rust):** token/lease debit math with overhead ∈ {0, 38, 124} on
   single packets and batches; basis-pairing tests per R-site (I1); I3
   identity differential; `queued_bytes` settle-to-zero under overhead>0
   (I2); runnable-estimate (R8) consistency.
2. **Unit (Go):** schema completion + commit-check range; compiler both-AST
   shapes (`ParseSetCommand()`+`SetPath()`); snapshot plumb; key-absent wire
   pins both sides; fixture regen.
3. **Live (loss userspace cluster):** shaped unit (e.g. reth0.80 at a low
   deliberate rate, say 200 Mbit) — small-datagram UDP (iperf3 -u, ~200 B)
   with overhead 0 vs overhead 100: measured payload goodput must scale by
   `payload/(payload+overhead)` within tolerance; large-packet TCP shows
   ≤~7% (100/1500) shift. This proves the debit math end-to-end on real
   hardware. Per-class matrix re-run to show class ratios stay consistent
   (Option B coherence claim). CoS re-applied post-deploy (I4).
4. **Perf gate:** the standard smoke A+B line-rate runs with overhead unset
   must show no throughput/CPU delta (default-0 identity at system level).

Reviewers must adjudicate whether this evidence bar is sufficient to ship a
feature whose motivating scenario cannot be demonstrated in-lab (§12 Q1/Q2).

## 11. Out of scope (explicitly)

- `cell-mode` ATM math, `ptm`, and `mpu` floors (Option C) — spelling room
  reserved, implementation deferred until a framed-link user exists.
- MQFQ wire-basis flow fairness (O2) and any admission/BDP/ECN re-basing —
  occupancy domain stays payload.
- Negative overhead values (Junos -120..-4) — commit-rejected in v1.
- Ack-filter, per-host keying (parent plan Option D siblings, unfiled).
- Ingress-side compensation beyond what egress shaping units get naturally.
- Any `traffic-control-profiles` config tree.

## 12. Open questions for adversarial review

1. **Q1 (demand gate — the kill question):** zero demand evidence, no
   in-lab framed link, hottest-path churn at MEDIUM-HIGH. Is "correctness
   feature for the cookbook's stated use case + default-0 + cheap" enough to
   ship Option B now, or is Option D (defer-on-demand) the honest verdict?
2. **Q2 (evidence bar):** is §10's Ethernet-math validation sufficient
   proof, given the motivating scenario (CPE buffer bloat on framed links)
   is structurally unprovable in this lab?
3. **Q3 (signed range):** v1 rejects negative bytes for pure-u64 hot math.
   Acceptable Junos-parity deviation, or must v1 take the full -120..124
   (forcing `saturating_add_signed` + ≥1 clamps at every site)?
4. **Q4 (boundary):** is the rate-domain/occupancy-domain split (Option B)
   the right coherent boundary, or does leaving MQFQ payload-based (O2)
   re-introduce a class of intra-queue skew that defeats the purpose on
   small-packet mixes?
5. **Q5 (placement):** `overhead-accounting` nested under `shaping-rate` vs
   a unit-level sibling? Nested matches `burst-size` precedent and ties the
   knob to the shaper's existence; sibling matches Junos's
   profile-level placement more loosely.
6. **Q6 (scheduler-map interaction):** with explicit scheduler-maps, R3
   per-class debits use the same per-interface constant — is a per-class
   override ever needed (answer should be no; overhead is a property of the
   physical link, not a class)?

## 13. Reviewer ledger

See `reviewer-ids.md` in this directory. Verdict vocabulary:
PLAN-READY / PLAN-NEEDS-MAJOR / PLAN-KILL, per round.
