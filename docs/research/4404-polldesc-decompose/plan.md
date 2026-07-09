# #4404 — Decompose `poll_binding_process_descriptor` (poll_descriptor/mod.rs)

Research-only plan. **No production code, no PR.** Read-only analysis at
`origin/master` `03a92b49c` (fetched + verified this session). Deliverable is
this plan doc, the two adversarial reviewer verdicts alongside it, and an issue
comment. Research stops at PLAN-READY / PLAN-KILL — implementation is a separate
`/engineer` (= `/triple-review`) pass.

---

## 1. Status

**PLAN-KILL (v3, CONVERGED 2-of-3: Codex PLAN-KILL + Claude-SMR PLAN-KILL; AGY
infra-down).** The arm-level decomposition this issue asks for is rejected. See
`claude-smr-plan-r2.md` and the Codex verdict (`task-mrdxqm0z-83tr4r`).

**Why the earlier PLAN-READY (v1/v2) was wrong.** v1/v2 rested on the premise
that the three target arms (FLOWLESS, SESSION-MISS, MissingNeighbor) are **cold
by construction**, so outlining them into `#[cold] #[inline(never)]` siblings is
hot-path-free. **That premise is false** (verified against `03a92b49c`):

- **FLOWLESS is the per-packet path for all fragmented / no-L4 traffic** — the
  flow-cache fast path requires `Some(flow)` (mod.rs:867), and non-first
  fragments + non-query ICMP deliberately have `flow == None`
  (poll_stages.rs:458). Fragmented traffic is a sustained line-rate workload.
- **SESSION-MISS is amortized-hot under deny-flood / at-cap** — denied and
  session-cap-refused packets install nothing (mod.rs:2968, 3469) and re-run the
  whole arm every packet (SYN/deny flood, at-cap DoS).
- **MissingNeighbor repeats per-packet while a neighbor stays unresolved**
  (mod.rs:5101 seed then re-resolve loop).

Outlining these into `#[inline(never)]` therefore reintroduces the **#1697-v1 /
#4409(b) per-packet-`call` regression on exactly the fragment / DoS /
unresolved-neighbor paths** — real, and the worst places to regress — with **no
executable codegen gate** to catch it (§9 was also wrong; see below).

The sections below are retained **as the analysis of record** (stage map,
invariants, why the design *can't* be safely gated). Their earlier PLAN-READY
framing is superseded by this Status. This doc is a **PLAN-KILL post-mortem**,
not an implementation handoff.

## 2. Issue framing

`userspace-dp/src/afxdp/poll_descriptor/mod.rs` is the AF_XDP ingress RX
forwarding loop. At `origin/master` `03a92b49c`:

- **6,294 LOC total**; **5,479 production** (lines 1–5479), **815 test**
  (5 `#[cfg(test)]` modules, 5480–6294).
- The single function `poll_binding_process_descriptor` spans **lines
  683–5478 ≈ 4,796 LOC** — the god-function this issue targets.
- This is ~2.4× the project's **2,000-production-LOC modularity threshold**
  (`docs/engineering-style.md`, "Modularity discipline") *for one function*,
  and the file is the largest in the crate.

### Ground-truth corrections to stale prior comments

- The **issue title** (`5,759 LOC … 1,368-LOC fn`) is a stale ps-review-010
  snapshot. The fn has **grown ~3.5×** since filing.
- The **2026-07-09 17:10 issue comment** ("cold-path extraction is already done
  … mod.rs is now 3,866 LOC … PLAN-DEFER, no clean seam", assessed at
  `4eb28ae25`) is a **stale-checkout misread**: `4eb28ae25` is a *direct
  ancestor* of `03a92b49c` (27 commits back) and `mod.rs` is **6,294 LOC at
  both** SHAs (`git show 4eb28ae25:…/mod.rs | wc -l` = 6294). The "3,866" figure
  does not correspond to any real revision of this file; the disposition built
  on it is void. Cold **leaf** extraction shipped (#1697), but the **cold arms
  are still inline** — the file did not shrink to 3,866.
- The **2026-07-07 converged comment** (stage map, PacketCtx, §4 phased plan,
  PLAN-DEFER-to-`/triple-review`) is **structurally accurate** (line numbers
  shifted +~60–260 as the fn grew) and is the substantive input this plan
  refines into an actionable, scope-bounded PLAN-READY.

## 3. Honest scope and value

**What is real:** a 4,796-LOC, 15-responsibility per-descriptor function is a
genuine maintainability liability. Its load-bearing invariants (single-recycle,
Junos host-inbound ordering, table-scoped local delivery, NAT precedence +
rollback, HA resolution) are documented in dense inline comment blocks buried
mid-function where they are hard to audit. This is the correctness cost of the
size, not merely aesthetics.

**What is NOT the value:** there is **no runtime/binary-size win to promise.**
The crate builds with the **default release profile** (`userspace-dp/Cargo.toml`
has *no* `[profile.release]`, `git grep` confirms no `codegen-units`/`lto`/
`opt-level` override → `codegen-units=16`, `lto=off`, `opt-level=3`,
`panic=unwind`). The only defensible performance framing is the #1697 one:
evicting **cold** bodies from the hot function's codegen unit *may* keep the
per-packet path more L1-i resident — an **unmeasured, un-promisable** effect.
The plan must therefore be justified on **navigability + auditability**, gated
so that it costs **zero throughput** — never sold as a speedup.

**Crucial structural finding (sizes the residual honestly):** the heavy
computation is **already delegated** to sibling modules — `session_glue/mod.rs`
(`resolve_flow_session_decision`), `forwarding/mod.rs`
(`finalize_new_flow_ha_resolution`, `install_helper_local_session_on_miss`),
`filter.rs` (`host_inbound_gated_lo0_action`), `disposition.rs`
(`record_forwarding_disposition`), `poll_stages.rs` (9 stage helpers), plus the
#1697 siblings. The 4,796 residual LOC is therefore mostly **orchestration
glue**: branch structure, ~14 threaded mutable locals, `scratch_forwards`
`PendingForwardRequest` construction, NAT-pre-routing/policy/install/telemetry
*ordering*, and very large inline invariant-comment blocks. This makes an arm a
*sequence of already-safe delegated calls + local threading* to lift — which
raises tractability but makes the **borrow-checker shape** the crux, not the
call graph.

## 4. Already-shipped (do not re-litigate)

- **#1327 / #1697** (merged, PR #1704): converted the flat file to a directory
  module and cold-outlined the leaf exception machinery →
  `flow_cache_hit.rs` (HOT, `#[inline(always)]`), `rx_telemetry.rs`,
  `filter.rs`, `nat_exception.rs`, `cookie_reply.rs`, `reject_reply.rs`.
  **#1697 is the dispositive precedent** (see §7): it PLAN-KILLed a v1 that
  outlined warm/hot guard-wrappers, then shipped a v2 that outlined only
  `#[cold] #[inline(never)]` rare/heavy bodies, gated by **`cargo asm`**
  (no new per-packet `call` into the cold module) + smoke.
- **#4404 inc 1** (merged, PR #4644, `eb1083d59`): split
  `debug_log_throttle.rs` (99 LOC) out. Established that **#4404 is driven as
  small gated `inc N` increments**, not one shot. (It moved mod.rs 6,121→6,042;
  subsequent feature work re-grew it to 6,294 — the increment stream has barely
  dented the *arms*, which are the real mass.)
- **#4780/#4781/#4782** (merged): moved `#[cfg(test)]` blocks of sibling
  modules to `_tests.rs` files (`cookie_reply_tests.rs`, `reject_reply_tests.rs`).
  These are test-file hygiene, not god-function reduction.

**Net:** cold *leaves* and *tests* are extracted; the cold **arms**
(`SESSION-MISS` ~2,207 LOC, `MissingNeighbor` ~990, `FLOWLESS` ~280) and the
warm/hot arms (`SESSION-HIT` ~408, `FORWARD-BUILD` ~460) remain inline. Those
arms are the residual 4,796.

## 5. Concrete design

### 5.1 Verified stage map (current `03a92b49c` line numbers)

Per-descriptor loop `while let Some(desc)` body inside 683–5478. Prologue
700–706 (`rx.receive`, three scratch `clear`s). Epilogue 5476 (`received.
release()`, `drop`), with a `recycle_now` push guarding each descriptor.

| # | Stage | Lines (approx) | Hot/Cold | Extract? |
|---|-------|----------------|----------|----------|
| 1 | RX telemetry + `try_parse_metadata` + `classify_metadata` | 707–730 | **HOT** | already delegated (glue stays) |
| 2 | Stages 5–11 glue (link-layer/GRE/parse-flow/fabric/screen/IPsec) | 730–860 | **HOT** | delegated to `poll_stages` (glue stays) |
| 3 | Flow-cache fast path `stage_flow_cache_hit` (`#[inline(always)]`) | 870 | **HOT (steady state)** | **DO NOT TOUCH** — established flows exit here → `continue` |
| 4 | Slow-path mutable-locals decl block | 900–965 | cold-entry | stays in caller (defines PacketCtx contents) |
| 5 | `let mut decision = if let Some(flow) { … }` expr | 965–~3900 | mixed | — |
| 5a | **SESSION-HIT** arm (`resolve_flow_session_decision` + host-inbound gate + ForwardCandidate) | 966–1374 (~408) | **WARM** | **Phase 3 — CONDITIONAL** |
| 5b | **SESSION-MISS** arm (`else`) | 1374–3581 (~2,207) | **COLD** (per-new-flow) | **Phase 2 — PLAN-READY** |
| 5c | **FLOWLESS** arm (flow `None`) | 3581–~3860 (~280) | **COLD** | **Phase 1 — PLAN-READY** (has test seam) |
| 6 | egress_rg + HAInactive fabric-redirect glue | ~3860–3908 | cold | stays / folds into 5c helper |
| 7 | **FORWARD-BUILD** `if matches!(ForwardCandidate\|FabricRedirect)` | 3909–4369 (~460) | **WARM/HOT** | **Phase 3 — CONDITIONAL** |
| 8 | **NON-FORWARD** `else` → `match disposition`; incl. **MissingNeighbor** ~4419–5410 (~990) | 4369–5410 | **COLD** | **Phase 2 — PLAN-READY** |
| 9 | metadata-invalid `else` + `recycle_now` epilogue | 5412–5478 | cold | stays in caller |

Measured facts: **35** `scratch_recycle.push` sites and **4** `recycle_now =
false` handoffs inside the fn; **0** `#[cold]` and **0** `#[inline]` on the
god-function itself (7 `#[inline]` are on the small top helpers 77–675).

### 5.2 PacketCtx — the loop-carried register bundle

A `struct PacketCtx` holding the ~14 loop-carried mutable locals threaded across
stages, passed `&mut` to extracted arm-fns:

```
recycle_now, meta (rebound), owned_packet_frame, decision,
debug, session_ingress_zone, flow_cache_owner_rg_id,
flow_cache_policy_counter_idx, flow_cache_policy_counter,
apply_nat_on_fabric, flow_cache_install_failed,
pre_routing_dnat_counter, neighbor_mac_epoch_at_resolve
```

The **heavy shared resources** (`binding: &mut BindingWorker`,
`sessions: &mut SessionTable`, `worker_ctx: &WorkerContext`, `screen`,
`telemetry`) stay as **separate `&mut`/`&` params** — they are *not* folded into
PacketCtx, because doing so would create the very borrow conflict §7.3 warns
about (an arm needs `&mut sessions` and `&mut ctx.decision` live simultaneously;
if `sessions` were a PacketCtx field, that is a double-`&mut`-of-one-struct
borrow error). Grouping only the *scalar/local* registers keeps the split
borrow-clean.

### 5.3 Proposed module boundaries + signatures (cold arms)

**Control-flow return type (mandatory — the arms contain `continue`).** The
arms have 18 internal `push(desc.addr); continue;` drop exits (14 SESSION-MISS,
4 MissingNeighbor) plus 4 `recycle_now=false` ownership-handoff fall-throughs
(§7.1). An extracted fn **cannot `continue` the caller's `while let` loop**, so
every arm-fn returns:

```rust
pub(super) enum ArmOutcome {
    DropRecycle,               // frame dropped: caller does
                               //   scratch_recycle.push(desc.addr); continue;
    Handoff,                   // frame ownership transferred (pushed to
                               //   scratch_forwards / buffered pending-neighbor):
                               //   caller does `continue` WITHOUT recycling
    Proceed(SessionDecision),  // caller falls through to FORWARD-BUILD with this
}
```

Each in-arm `push(desc.addr); continue;` → `return ArmOutcome::DropRecycle;`;
each `recycle_now=false; …; continue/fall-through` → `return
ArmOutcome::Handoff;`. The caller's single dispatch site becomes the **only**
recycle push in the extracted world (§7.1):
```rust
match resolve_session_miss(...) {
    ArmOutcome::DropRecycle => { binding.scratch.scratch_recycle.push(desc.addr); continue; }
    ArmOutcome::Handoff     => { continue; }
    ArmOutcome::Proceed(d)  => d,   // → FORWARD-BUILD / NON-FORWARD dispatch
}
```

New sibling `poll_descriptor/session_miss.rs`:
```rust
#[cold]
#[inline(never)]
pub(super) fn resolve_session_miss(
    ctx: &mut PacketCtx,
    binding: &mut BindingWorker,
    sessions: &mut SessionTable,
    screen: &mut ScreenState,
    worker_ctx: &WorkerContext,
    telemetry: &mut TelemetryContext,
    flow: &SessionFlow,
    desc_addr: u64,            // for the DropRecycle discriminant only; NOT pushed here
    now_ns: u64, now_secs: u64, ha_startup_grace_until_secs: u64,
    conntrack_v4_fd: c_int, conntrack_v6_fd: c_int,
) -> ArmOutcome
```

New sibling `poll_descriptor/missing_neighbor.rs`:
```rust
#[cold]
#[inline(never)]
pub(super) fn handle_missing_neighbor(
    ctx: &mut PacketCtx,
    binding: &mut BindingWorker,
    sessions: &mut SessionTable,
    worker_ctx: &WorkerContext,
    telemetry: &mut TelemetryContext,
    flow: &SessionFlow,
    decision: SessionDecision,
    now_ns: u64, now_secs: u64,
) -> ArmOutcome   // DropRecycle | Handoff (never Proceed — terminal disposition)
```

`FLOWLESS` (Phase 1) extracts to `poll_descriptor/flowless.rs` returning the
same `ArmOutcome`, reusing the already-standalone `flowless_base_resolution` /
`flowless_local_delivery_verdict` (kept in place or co-moved) and the existing
`flowless_local_delivery_tests`.

The **18-site `continue`→`return` + 4-site `Handoff` transformation must be
exhaustively audited** — a single missed site leaks or double-recycles a
descriptor with no unit test to catch it (§7.1). This is the sharpest edge of
the change, which is why FLOWLESS (fewest such sites) goes first.

All three are `#[cold] #[inline(never)]` — **hot-path-safe by construction**:
the steady-state per-packet path is `stage_flow_cache_hit → continue` (stage 3)
and never enters these arms; the first-packet forward-build (stage 7) is a
*separate* block that stays inline. The single risk is whether *removing* these
bodies perturbs the codegen of the stages that stay inline — which is exactly
what the §9 gate proves.

### 5.4 Recommended increment sequence (each an `#4404 inc N` PR, gated)

- **inc A (Phase 1, warm-up) — UNCONDITIONALLY PLAN-READY:** extract
  **FLOWLESS** → `flowless.rs`. Smallest, most self-contained, **already has a
  unit-test seam**, fewest recycle-drop sites. Establishes the `ArmOutcome` +
  PacketCtx pattern + the gate mechanics on the lowest-risk arm. Ships first and
  validates the borrow shape empirically before the big arms.
- **inc B (Phase 2a) — PLAN-READY-PENDING §11-Q1 BORROW SPIKE:** extract
  **SESSION-MISS** → `session_miss.rs`. Largest single win (~2,207 LOC out of
  the hot fn's CGU). Highest *behavioral* risk (NAT precedence/rollback, HA
  finalize, install ordering) **and** most borrow-contended (installs into
  `sessions` + pushes to `scratch_forwards` + reads `worker_ctx.forwarding` in
  one body). Do **not** declare implementable until the Q1 compile spike passes.
- **inc C (Phase 2b) — PLAN-READY-PENDING §11-Q1:** extract **MissingNeighbor**
  → `missing_neighbor.rs` (~990 LOC). Second-largest; `PendingNeighAdmission`
  buffering + re-applied NAT on the buffered `pending_decision`.
- **inc D (Phase 0 residual, optional):** `#[cold]`-annotate the remaining cold
  emitters still inline in the caller (`emit_policy_deny_event`,
  `emit_host_inbound_deny`, `emit_pending_filter_log`) if profiling/asm shows
  them in the hot CGU. Marginal — most cold leaves already left in #1697.
- **inc E (Phase 3, CONDITIONAL — PLAN-KILL-acceptable):** SESSION-HIT +
  FORWARD-BUILD via `#[inline(always)]` PacketCtx helpers. **Attempt only if
  the §9 asm gate proves the re-fused output is call-free with no new stack
  spill vs the flat monolith.** If asm shows ANY hot-path regression →
  **PLAN-KILL this phase**, leave the arms inline; inc A–C already deliver
  ~3,500 LOC of the win.

Post inc A–C, mod.rs drops from ~5,479 production LOC to ~**2,200–2,500** — near
but likely not under the 2,000 threshold in the hot fn alone; the fn itself
falls from ~4,796 to ~**1,300** LOC (glue + SESSION-HIT + FORWARD-BUILD). That
is the honest ceiling of the *safe* scope.

## 6. Public API preservation

`poll_binding_process_descriptor` is `pub(super)` with **one caller** (the
worker poll loop). Its signature is unchanged — all new helpers are private
`pub(super)` siblings. No cross-crate surface moves. Blast radius = the module +
its single caller; sibling `_tests.rs` reference internal fns only. Extracted
`#[cfg(test)]` seams (`flowless_local_delivery_tests` etc.) move with their fn
or import it via `use super::…`.

## 7. Hidden invariants (the load-bearing constraints)

### 7.1 Single-recycle (RX UMEM discipline) — the sharpest edge
Measured distribution of the **35** `scratch_recycle.push(desc.addr)` sites:
prologue/hot 7, SESSION-HIT 4, **SESSION-MISS 14**, FLOWLESS/glue 5,
**MissingNeighbor 4**, epilogue 1. Every in-arm site is `push(desc.addr);
continue;` (verified at 1389/1640/2253/2799/3086/4625/5088) — a **drop-and-
advance** exit. Plus **4** `recycle_now=false` fall-throughs (2568, 2930, 4276,
5375): ownership handoffs where the frame was pushed to `scratch_forwards` /
buffered for a pending neighbor and must **not** be recycled (2930 and 4276 sit
right after a `scratch_forwards.push`). Each `desc.addr` must be recycled
**exactly once**: a leak → UMEM exhaustion → RX-ring stall → throughput collapse
after N seconds; a double-push → UMEM corruption. **There is no isolated unit
test for the loop's recycle discipline** (the `FORCE_OVERSIZED`/
`FORCE_TUPLE_MISMATCH` tests live in `tx/dispatch/`; `inplace_randomized_sequence`
in `session/tests.rs` — they guard code the loop *calls*, not the loop body).

**Extraction rule (v2, corrected):** because the drop exits are *inside* the
arms and end in `continue`, they cannot be hoisted to the caller as `recycle_now`
mutations (v1's mistake). Instead each arm returns `ArmOutcome` (§5.3): the
in-arm `push; continue;` becomes `return DropRecycle;`, the `recycle_now=false`
handoffs become `return Handoff;`, and the **caller's single `match` becomes the
sole recycle-push site**. This *centralizes* the invariant to one place — an
improvement — but the **18-`continue` + 4-`Handoff` transformation must be
exhaustively audited** (one missed site = leak/double-recycle). The residual
gate is **manual-audit checklist + sustained-load flat-throughput smoke**
(multi-minute, RX-drop counter flat) — still not unit-testable; the sharpest
weakness, called out honestly. FLOWLESS-first (fewest sites) de-risks the
pattern before SESSION-MISS's 14 sites.

### 7.2 Hot-path codegen / inlining (the #1697 KILL trigger)
Nothing reachable from the `#[inline(always)]` `stage_flow_cache_hit` fast path
(stage 3) or the per-packet forward-build (stage 7) may acquire a **new
per-packet `call` edge** into a newly-`#[inline(never)]` module, and no new
by-value copy of the 96-byte `UserspaceDpMeta` may appear on the cache-hit path.
Cold-arm extraction (§5.3) is safe *because* those arms are not on that path —
but the *proof* is the §9 asm gate, not this assertion.

### 7.3 Borrow-checker shape (the tractability crux)
The monolith relies on NLL region-splitting: within one arm, `&mut sessions`,
`&mut ctx.decision`, and `&mut binding.scratch.*` are live at overlapping but
non-conflicting points. Lifting an arm into a fn forces those borrows to be
expressed as the fn's parameter set. **Open risk:** an arm may hold `&mut
sessions` (for `install_with_protocol_with_origin`) while also needing a `&`
borrow into `binding` that today NLL permits inline. Mitigation: keep
`sessions`, `binding`, `worker_ctx` as *distinct* params (§5.2), pass copies of
small `Copy` locals by value, and return `decision` by value rather than
threading it as `&mut` where possible. **This needs a compile spike before inc B
is declared implementable** — it is the single most likely reason a phase slips.

### 7.4 Behavioral invariants preserved verbatim across arms
- **Junos host-inbound order** host-inbound → lo0 → junos-host
  (`host_inbound_gated_lo0_action`), across the three parallel call sites
  (hit / miss / flowless).
- **Table-scoped local delivery** (#3769/#3151 `owned_here`) and
  **connected-route scoping** (#2388 `entry.table == table`).
- **NAT precedence + rollback:** SNAT rollback on install-refuse (#1861 §5.4,
  gated by `flow_cache_install_failed`); `pre_routing_dnat_counter` incremented
  **once** across the LocalMiss / ForwardCandidate / MissingNeighbor sites.
- **HA:** `finalize_new_flow_ha_resolution`, `owner_rg_id`, HAInactive
  fabric-redirect, `neighbor_mac_epoch_at_resolve` snapshot-before-resolve
  (#3918).

## 8. Risk assessment

| Risk | Severity | Mitigation |
|------|----------|------------|
| Hot-path codegen regression (new per-packet `call` / meta copy) — **the #1697 kill class** | **High for Phase 3; Low for Phase 1–2 (cold arms not on hot path)** | §9 `cargo asm` hot-BB diff, per increment. Phase 3 gated hard, PLAN-KILL-acceptable |
| Single-recycle double/leak (no unit test) | **High** | §7.1 rule (push stays in caller); manual audit checklist; sustained-load flat-throughput smoke |
| Borrow-checker shape blocks a clean cut | **Medium** | §7.3 compile spike before inc B; keep heavy resources as distinct params |
| Behavioral drift in NAT/HA ordering | **Medium** | full CoS smoke matrix + `test-failover` + many-new-flows load (§9) |
| "Readability-only, unproven win" objection (**the #4409(b) kill criterion**) | **Medium** | Distinguished in §10; #4409(b) killed because the extracted code was *amortized-HOT*; the #4404 cold arms are *genuinely cold* → different failure mode. #1697 is a *shipped* counterexample that a cargo-asm-gated cold-outline of THIS fn is project-accepted |
| Value ceiling: fn stays ~1,300 LOC even after inc A–C | Low | Honest in §5.4; still a 73% reduction of the fn and removes the 3,200-LOC cold mass |

## 9. Test / equivalence plan (the gate)

> **CORRECTION (v3, Codex R1):** the claim below that the poll loop is
> "un-callable in isolation" is **FALSE**. `txn_run_descriptor` (tests.rs:7672)
> builds test UMEM/XSK state and invokes the real
> `poll_binding_process_descriptor`, and existing tests assert on
> `scratch_recycle` (tests.rs:7952, 11691). Exact-count recycle unit tests are
> therefore achievable — a proper (future, narrower) plan MUST use them; the
> smoke-only framing here is inadequate. Retained below as the (flawed) v2 text.

The poll-loop body is ~~**un-callable in isolation**~~ (needs a live
`BindingWorker`/`MmapArea`/`SessionTable`/`WorkerContext`; prior reviews
confirmed) and there is **no existing criterion bench for it** (`userspace-dp/
benches/` covers `session_table`, `snat_allocator`, `tx_kick_latency`,
`prefix_set_lookup` — none the RX loop). So **criterion is not a usable gate
here**; `cargo asm` is the primary gate. Layered, applied **per increment**:

1. **PRIMARY — `cargo asm` hot-basic-block diff.** Dump
   `poll_binding_process_descriptor` (release profile) before/after. The cold
   arms *vanish* from the symbol, so a whole-function `diff` is meaningless —
   the gate inspects **only the hot basic blocks** that stay inline:
   (a) the `stage_flow_cache_hit → continue` cache-hit path, and (b) the
   `FORWARD-BUILD` `scratch_forwards.push` construction. **Pass = no new `call`
   edge from those blocks into the newly-`#[inline(never)]` modules, and no new
   stack spill/reload in the hot prologue/epilogue.** This is judgment-heavy but
   **proven-feasible — it is exactly the #1697 gate** that shipped.
   **Symbol-resolution fallback (F5):** the loop fn is `pub(super)` with one
   caller and may be inlined into it, so `cargo asm poll_binding_process_
   descriptor` may not resolve a standalone symbol. Fallback, in order:
   (i) `objdump -d` on the release `.o` and locate the loop by its string/const
   references; (ii) for the *capture build only*, pin the loop fn
   `#[inline(never)]` so `cargo asm` resolves it (do **not** commit the pin).
   #1697 hit and cleared this — confirm the chosen path works on day one, before
   inc B, not mid-implementation.
2. **BEHAVIOR — full cluster smoke** on `loss:xpf-userspace-fw0/fw1`: sustained
   iperf3 v4+v6, push+reverse, multi-stream, **CoS-on and CoS-off**, per-class
   matrix (the 5201–5206 forwarding-class servers), screen/NAT/session sanity,
   and **`make test-failover`** for the HA arms (`finalize_new_flow_ha_resolution`,
   fabric-redirect).
3. **MANY-NEW-FLOWS load (specific to Phase 2):** an established iperf stream is
   *all* cache-hit and never exercises SESSION-MISS/MissingNeighbor. inc B/C
   MUST run a **high-connection-count / short-flow** load (e.g. many parallel
   short connections) so the extracted cold arms actually execute under smoke.
4. **SUSTAINED-LOAD UMEM check (single-recycle):** a multi-minute run at line
   rate with **flat** throughput/RX-drop counters — the only observable proxy
   for the §7.1 recycle discipline.
5. **Existing unit tests:** `flowless_local_delivery_tests` (inc A),
   `session_glue`/`forwarding` tests (regression), plus the ext-header/resolver/
   session-limit/strict-syn suites already in this file.

## 10. Out of scope

- **Phase 3 (SESSION-HIT + FORWARD-BUILD warm/hot arm fusion)** unless the §9
  asm gate proves regression-free — explicitly **PLAN-KILL-acceptable**.
- Touching `stage_flow_cache_hit` / the `#[inline(always)]` fast path.
- Any `[profile.release]` / LTO / codegen-units change to "make the gate
  easier" — that is a separate, cross-cutting decision.
- Behavioral changes of any kind. This is a **byte-for-byte-behavior**
  refactor; the only intended delta is source layout + CGU placement of cold
  code.
- The #4409(b) NAT-allocator and #4408 tx/dispatch god-functions (separate
  issues; #4409(b) already PLAN-KILLed for a *different* reason — its target was
  amortized-hot, not cold).

## 11. Open questions

1. **Borrow spike (blocking for inc B):** does `resolve_session_miss` compile
   with `sessions`/`binding`/`ctx` as distinct `&mut` params, or does an
   overlapping-borrow force an awkward return-by-value / split? A 1-hour compile
   spike answers this and should gate declaring inc B implementable.
2. **asm-diff tooling:** `cargo asm` vs `objdump -d` on the release `.o` —
   which gives the cleaner per-basic-block view of a `pub(super)` fn that may
   itself be inlined into its caller? (#1697 used `cargo asm`; confirm it still
   resolves the symbol post-extraction.)
3. **Increment granularity:** is SESSION-MISS (2,207 LOC) safe to lift in one
   inc B, or must it split (DNAT-pre-routing / policy-eval / SNAT-alloc-install)
   into sub-helpers within `session_miss.rs` first? Prefer one file, multiple
   private fns, one PR — but the borrow spike (Q1) may force finer cuts.
4. **Is Phase 3 worth attempting at all**, given inc A–C reach the practical
   floor (~1,300-LOC fn) and Phase 3 is the highest-risk lowest-marginal-value
   step? Default recommendation: **do not** attempt Phase 3 unless a future
   profiling need re-justifies it.

---

### Recommendation (CONVERGED)

**PLAN-KILL the arm-level decomposition.** Every proposed arm seam (FLOWLESS,
SESSION-MISS, MissingNeighbor) sits on a real per-packet path
(fragment / DoS / unresolved-neighbor), so outlining reintroduces the
#1697-v1 / #4409(b) per-packet-`call` codegen regression; the specified
`cargo asm` gate is neither executable on this repo's tooling (cargo-asm 0.1.16
panics on these symbols, session_glue/promote.rs:15) nor aimed at the paths that
would regress; and the `ArmOutcome` control-flow rewrite changes behavior
(mod.rs:5375 fall-through accounting) with non-compilable signatures
(`decision` is produced by the expression, not an input; self-borrow of
`owned_packet_frame`). What survives is only more #1697-style cold **leaf-body**
outlining, which already largely shipped — not the arm decomposition filed here.

This converges with **#4409(b) PLAN-KILL** and **#4408 PLAN-DEFER**: the residual
`poll_binding_process_descriptor` is the **irreducible per-packet RX dispatch
core** with no clean, codegen-neutral, behavior-preserving arm seam.

**A future revisit is possible but is different, narrower work** (Codex §7):
target only genuinely-rare/heavy *sub-bodies*; ship compile-proven staged
signatures; add `txn_run_descriptor`-based **exact-one-owner recycle unit
tests** (the loop IS unit-testable — tests.rs:7672/7952/11691); produce
linked-binary `nm`/`objdump` artifacts with reproducible **named** anchors; set
**quantitative fragment / unresolved-neighbor / new-flow pps thresholds**. Until
such a specific seam is identified, no `/engineer` handoff. Issue labeled
`plan-kill`, closed.
