# #3607 — Screen `RateCounter` over-throttles sustained at-threshold traffic

## 1. Status

`DRAFT v3 — round-2 adversarial findings incorporated (Codex + AGY + Claude SMR),
pending convergence confirmation` (research branch `research/3607-screen-rate`,
base origin/master `9419bbc2c`).

`/research` plan. Stops at PLAN-READY / PLAN-DEFER / PLAN-KILL. No production
source changes, no PR.

**v3 change summary (round-2 review):**
- **syn-cookie-OFF aggregate drop** (AGY BLOCKER, Codex MAJOR): the count-all
  aggregate still drops legit sustained-at-threshold SYNs when `syn-cookie` is
  OFF, and that case has no cookie to bypass — so it IS fixed here, via a per-zone
  **OFF-attack token bucket** consulted only in the cookie-off drop path.
  `increment_and_classify` (alarm + cookie-ON activation) stays untouched.
- **missing-profile warn dampener is NOT migrated** (Codex MAJOR): it *relies* on
  suppress-until-idle (a pinned anti-log-flood behavior, `tests.rs:4085`) — stays
  on `RateCounter`.
- **sketch fail-closed re-derivation** (Codex BLOCKER): the token-bucket sketch is
  fail-closed (collisions only drain faster; a sustained-over-threshold victim
  always trips); "stay-tripped-until-idle" is deliberately replaced by
  "rate-enforced" — which IS the #3607 fix for the sketch. New tests pin it;
  DEFER-the-sketch is offered as a narrower scope.
- **`admit()` polarity pinned** (Codex MAJOR): `true = over-limit = drop/limited`,
  identical polarity to `RateCounter::increment`, so migrated call sites are
  drop-in.
- **ON-case cookie-lock documented** (AGY MAJOR) and standby-ACK validator
  signature churn acknowledged (AGY MINOR).

## 2. Issue framing

`userspace-dp/src/screen/rate.rs::RateCounter` is a two-bucket sliding-window
counter (#2937). #3607: it over-throttles a legitimate sender at exactly the
configured threshold — admitted only in the first second, then dropped every
subsequent second until a **fully idle second** resets the window. The module's
own doc's "a sustained sender is still admitted at ~`threshold` events per second"
is false.

Folded: **H02** (core over-throttle), **M09** (no sustained-threshold test),
**L10** (operator docs), **L14** (`u32` saturating adds).

## 3. Honest scope / value framing

Correctness fidelity to Junos flood-screen semantics (thresholds are pps —
`docs/syn-cookie-flood-protection.md:31,55-56`), not performance. Junos admits ≤
threshold sustained and drops the excess; xpf drops a sustained-at-threshold
source to ~0 after the first second.

Consumers fixed (shaper / validate-budget semantics — "admitted" never means
"skip a security check"):

1. **ICMP flood / UDP flood** zone-aggregate counters (over = DROP).
2. **Standby SYN-cookie ACK-validation limiter** (4096/s, `mod.rs:502-512`) —
   "admitted" = "spend SipHash"; a bogus ACK still fails the crypto check, so
   raising the admit rate to the intended budget has **no bypass**. Fixes legit
   returning clients during/after failover.
3. **#3315 per-source / per-destination SYN sketch** (`syn_rate.rs`) — a busy
   legit destination at `destination-threshold` throttled to ~0 (false positive);
   per-dest DROPS (never skips cookies), so shaping is safe.
4. **SYN-flood aggregate DROP path when `syn-cookie` is OFF** — `over_attack`
   returns `Drop("syn-flood")` (`mod.rs:704`); with no cookie there is nothing to
   bypass, so sustained-at-threshold legit SYNs must be admitted (v3 adds this).

Deliberately **not fixed** (documented, not "fixed"):

- **SYN-flood aggregate when `syn-cookie` is ON** — there "admitted" = "skip the
  cookie challenge," so admitting a sustained-at-threshold stream would let
  `threshold` spoofed SYNs/sec bypass the cookie AND (via lingering
  `cookie_active`) the per-source cap (round-1 BLOCKER). Its over-throttle is
  benign (a challenge is recoverable). §5 / §10.
- **missing-profile warn dampener** — wants suppress-until-idle; stays as-is.

**If reviewers judge the blast radius (new `TokenBucket` primitive + `now_ns`
threading through the screen call chain + sketch cell-type swap + a per-zone
OFF-attack bucket) disproportionate to the value, PLAN-DEFER-operator (fix L10 +
optionally L14) or PLAN-KILL is acceptable.** §10a.

## 4. What's already shipped / partially batched

- **#2937 (`1b1cb215b`)** — current two-bucket sliding window; must not
  reintroduce its sub-ms micro-burst.
- **#3315 (`44474b9ea`)** — `increment_and_classify` (single advance, dual
  attack+alarm) → SYN-cookie activation; count-min sketch of `RateCounter`s
  (`syn_rate.rs`, ROWS×COLS, ~192 KiB/zone/worker). Fail-closed: cells only
  increase within the window, collisions only over-count, victim always trips
  (`syn_rate.rs:33,41`). (`syn-flood timeout` was later enforced in #3527 as a
  per-zone `tcp_opening_ns` override — session-layer, unrelated to the counter.)
- **#3032** — SYN-cookie epoch uses a once-per-second cached **wall** clock;
  orthogonal to the rate counters (which use **monotonic** time).
- **Enabling fact + real cost:** `loop_now_ns = monotonic_nanos()` is read once
  per batch (`worker/loop_body/mod.rs:241`) and truncated to `loop_now_secs`
  (:363). The clock READ is zero-cost, but reaching the counters needs a signature
  change: `stage_screen_check` takes only `now_secs` (`poll_stages.rs:312`) and
  the standby-ACK path (`stage_screen_syn_cookie_ack_on_session_miss` /
  `validate_syn_cookie_ack_on_session_miss`, `poll_stages.rs:557-562`) also needs
  `now_ns` — churn beyond the screen module (AGY MINOR).

### 4a. Root-cause analysis (confirmed against `9419bbc2c`)

`increment` (`rate.rs:79-83`) advances then counts EVERY event before
`prev_count + count > threshold`; `advance` (`rate.rs:60-71`) demotes the whole
previous second to `prev_count` at **constant weight 1.0** for the whole current
second. Two coupled defects: (1) 1-s granularity ⇒ no sub-second decay ⇒
`prev_count + count` over-estimates by up to 2× at a boundary; (2) rejected events
are still counted ⇒ the sum stays saturated until a fully idle second.

Quantified (1-s granular; second `i` delivers `c`; `T`=threshold; steady state):
admitted/sec `= max(0, min(c, T − c))`.

| `c` | admitted/sec (current) | Junos |
|---|---|---|
| `≤ T/2` | `c` | `c` |
| `T/2 < c < T` | `T − c` | `c` |
| `= T` | **0** after second 0 (needs idle second) | `T` |
| `> T` | 0 | drop excess |

True sustained ceiling = `T/2`. `sustained_at_threshold_is_admitted`
(`rate.rs:220-237`) passes only because it feeds `T/2` (`half = THRESHOLD/2`) —
the M09 gap.

**Both defects jointly necessary:** granularity-fix-alone (weight + count-all) ⇒
`est = T·(1−f) + T·f ≡ T` ⇒ still drops all; not-counting-alone (Option C) ⇒
recurrence `a_i = min(c, T − a_{i-1})` collapses to `T,0,T,0` (avg `T/2`, a
flood-evasion waveform). The token bucket avoids both (continuous refill =
sub-ns granularity; consume only on admit).

## 5. Concrete design — Option B token bucket, consumer-split

New `TokenBucket` primitive alongside the retained `RateCounter`:

```rust
pub(super) struct TokenBucket {
    tokens_q: u64,        // fixed-point tokens; integer part <= capacity = threshold
    last_refill_ns: u64,  // monotonic ns
}
impl TokenBucket {
    /// SAME polarity as RateCounter::increment: returns TRUE when this event is
    /// OVER LIMIT (drop / limited); FALSE when admitted. Drop-in at existing
    /// call sites (mod.rs:614,623,724,741 already treat true == drop).
    fn admit_is_over(&mut self, now_ns: u64, threshold: u32) -> bool {
        // refill = (now_ns - last) * threshold via a precomputed fixed-point
        // tokens-per-ns reciprocal-multiply (NO per-packet 64-bit divide),
        // saturating-capped at capacity = threshold.
        // if tokens >= 1 unit: consume 1, return false (admit)
        // else: return true (over) and do NOT consume.
    }
}
```

Consumer split by security semantic:

| Consumer | Counter | Semantic | Why |
|---|---|---|---|
| ICMP / UDP flood | **TokenBucket** | shaper | over = drop; admit ≤T/s |
| Standby SYN-cookie ACK | **TokenBucket** | validate-budget | admit = spend SipHash; no bypass |
| per-source / per-dest sketch | **TokenBucket** | shaper (drop) | busy legit dest false-positive |
| SYN aggregate DROP, `syn-cookie` **OFF** | **TokenBucket** (new per-zone bucket) | shaper | no cookie ⇒ no bypass |
| SYN aggregate, `syn-cookie` **ON** (`increment_and_classify` → cookie) | **RateCounter (UNCHANGED)** | defense-latch (count-all) | admit = skip cookie ⇒ must stay sticky |
| alarm-threshold measurement | **RateCounter (UNCHANGED)** | arrival-rate observation | alarm counts all arrivals |
| missing-profile warn dampener | **RateCounter (UNCHANGED)** | suppress-until-idle | log dampener wants no re-warn (`tests.rs:4085`) |

### 5a. SYN aggregate: cookie-OFF fix without touching the invariant

Keep `increment_and_classify` (count-all, `RateCounter`) exactly as-is — it drives
(i) the alarm-threshold log crossing (arrival-rate observation) and (ii) cookie
activation when `syn-cookie` is ON. It is the round-1 signed-off invariant
(`rate.rs:97`, `mod.rs:631-634`); it must not become count-only-admitted (T/sec
cookie bypass).

Add a **per-zone attack `TokenBucket`** consulted ONLY in the cookie-OFF drop
decision:

```text
(over_attack_measured, over_alarm) = agg_rate.increment_and_classify(now_secs, attack, alarm)  // UNCHANGED
raise alarm if over_alarm (unchanged)
if syn_cookie ON:
    if over_attack_measured { mint cookie / activate }              // UNCHANGED — no bypass
else: // syn_cookie OFF
    if attack_bucket.admit_is_over(now_ns, attack) { Drop("syn-flood") }  // shaper: admits sustained <= attack
```

Cost: one extra `TokenBucket` per zone (16 B/zone — per-zone, not per-cell).
Alarm still measured on arrival rate; ON-cookie path bit-identical; OFF path now
admits sustained-at-threshold legit SYNs (AGY BLOCKER / Codex MAJOR fixed) with no
bypass (no cookie to bypass).

### 5b. Sketch migration is fail-closed (Codex BLOCKER)

Swapping the sketch cell type `RateCounter → TokenBucket` preserves #3315
fail-closed:
- **Collisions still over-count:** every key hashing to a cell drains that cell,
  so a victim's cell is drained by ≥ the victim's own load ⇒ it reaches "over" at
  ≤ the victim's true rate ⇒ **never a false negative** from hashing. (Refill
  affects all keys equally; collisions only drain faster.)
- **Sustained-over-threshold victim always trips:** a victim exceeding the
  per-dest rate keeps the bucket drained ⇒ keeps returning "over."
- **Deliberate change:** "stay-tripped until a fully idle second" is REPLACED by
  "rate-enforced" — a victim dropping below the rate regains budget. That is the
  #3607 fix for the sketch (a busy-but-legit dest is admitted at its threshold),
  not a regression. Pinned by new tests (§9). If reviewers want minimal risk,
  §10a offers DEFER-the-sketch (leave it on `RateCounter`, fix only §3 items 1,2,4).

### 5c. Rejected alternatives

- **Option A weighted sliding window** — low-threshold roughness (`T=1` → ~50%
  loss) hits the sketch regime; not recommended.
- **Option C stop-counting-rejected only** — `T,0,T,0` flood-evasion waveform.

### Cross-cutting

- **L14:** token bucket bounds `tokens ≤ capacity = threshold` ⇒ no saturation;
  resolved structurally (flood intensity is already the #3343 drop counters). The
  untouched aggregate `RateCounter` keeps its existing `saturating_add`.
- **L10:** rewrite `docs/syn-cookie-flood-protection.md:275-280` + module docs to
  state per-consumer semantics: token-bucket shaper (admit sustained ≤ threshold,
  burst = threshold) for consumers 1-4; the deliberate cookie-ON defense-latch for
  the aggregate; suppress-until-idle for the missing-profile dampener.

## 6. Public API preservation

- `RateCounter::increment_and_classify(now_secs, attack, alarm)` — **UNCHANGED**
  (aggregate alarm + cookie-ON).
- `RateCounter::increment` / `reset` — retained (missing-profile warn +
  aggregate/tests).
- **New** `TokenBucket::admit_is_over(now_ns, threshold) -> bool` — `true = over =
  drop/limited` (same polarity as `increment`, drop-in).
- `syn_rate.rs::SynRateSketch::increment` / `saturate_cell` — cell type →
  `TokenBucket`, clock arg → `now_ns`; public shapes preserved.
- `ScreenState::check_packet` / `check_packet_with_zone_id` /
  `validate_syn_cookie_ack_on_session_miss` — gain `now_ns` (retain `now_secs`
  for scan/cookie-active/validated-TTL/alarm-sec/epoch-gate).
- No Go / gRPC / CLI / protobuf change.

## 7. Hidden invariants the change must preserve

- **SYN-aggregate count-before-classify + always-count** (`rate.rs:97`,
  `mod.rs:631`) — preserved (aggregate `increment_and_classify` untouched).
- **Cookie-ON no-bypass** — the OFF-attack bucket is consulted ONLY when
  `syn-cookie` is OFF; the ON path is bit-identical.
- **#2937 anti-micro-burst** — token bucket: ≤ capacity tokens at a sub-ms
  straddle.
- **#3315 sketch fail-closed** — collisions only over-count; sustained victim
  always trips (§5b); AND-of-rows min-read unchanged.
- **missing-profile suppress-until-idle** (`tests.rs:4085`) — preserved (not
  migrated).
- **Allocation / hot path** — no per-packet alloc; integer-only; no per-packet
  divide (fixed-point refill); monotonic clock only.
- **16-byte layout / no HA-wire/persistence** — `TokenBucket` ≤ 16 B; nothing
  synced/serialized/persisted.
- **SYN-path side-effect ordering** (`mod.rs:665-745`) — aggregate first, per-dest
  always, per-source skipped when cookie-active — unchanged.

## 8. Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression | **MED** | Security-critical drop path; aggregate ON path untouched; RED-on-revert for #2937 (micro-burst) + #3607 (sustained) + sketch fail-closed (sustained victim trips). |
| Lifetime / borrow-checker | **LOW** | `TokenBucket` is a plain value; disjoint-field borrow in `check_packet_with_zone_id` unchanged; `now_ns` scalar param. |
| Performance regression | **LOW** | Reuse `loop_now_ns`; one fixed-point mul+add+cmp+cond-sub per event; 16 B; verify SYN/ICMP flood iperf + CPU. |
| Architectural mismatch | **LOW–MED** | Adds one small primitive + a per-zone OFF-attack bucket; blast radius is the `now_ns` signature threading (loop_body → forwarding → poll_stages → screen → sketch, incl. the standby-ACK validator) + sketch cell swap — mechanical but wide. |

## 9. Test plan

- `cargo build` clean; `cargo test screen::` (TokenBucket unit + sketch +
  enforcement + aggregate), `cargo test afxdp::poll_stages`, full `cargo test`;
  `go test ./...` (unaffected).
- **M09 RED-on-revert sustained-at-threshold** (deliverable): TokenBucket at
  exactly `threshold`/s for N seconds via `now_ns`; steady-state admit ≈ threshold
  (≥ 0.99·T), not ~0. RED against current `RateCounter`.
- **Low-threshold:** `T=1` sustained 1 pps admits every second.
- **Recovery:** after an over-limit burst, dropping to ≤ threshold recovers
  without a fully idle second.
- **cookie-OFF aggregate:** sustained-at-`attack-threshold` SYNs with `syn-cookie`
  OFF are admitted (RED against current count-all); alarm still fires on arrival
  rate; **cookie-ON aggregate tests stay green with NO edits** (proof the ON path
  is untouched).
- **#2937 retained:** adapt `boundary_double_burst_is_bounded` /
  `icmp_flood_sliding_window_..._recovers` to the bucket — sub-ms micro-burst
  bounded to ~threshold.
- **Sketch fail-closed:** sustained-over-threshold victim always trips (no time
  gaps); collisions only trip-more; a paused victim regains budget (the intended
  #3607 fix). #3315 tests updated for rate-enforcement vs stay-tripped.
- **missing-profile dampener unchanged:** `tests.rs:4085` (sustained flood into
  the next second does not re-WARN) stays green with NO edits.
- **L14:** the bucket never saturates at realistic thresholds.
- **Smoke (loss userspace cluster):** screen profile with low icmp/udp thresholds
  + low `destination-threshold`; sustained-at-threshold admitted, above-threshold
  dropped; v4 + v6; no forwarding regression; standby cookie-ACK path admits at
  the 4096/s budget under sustained load. `make test-failover` NOT required (no
  cluster/VRRP/session-sync code touched); a screen smoke IS.

## 10. Out of scope (explicitly)

- **SYN aggregate over-throttle when `syn-cookie` is ON** — deliberately retained
  (defense-latch / cookie-bypass safety). Consequence (AGY MAJOR): once tripped,
  the zone stays cookie-active while the arrival rate ≥ threshold plus a ≤64s tail
  (`active_until = now + EPOCH_SECS`, re-armed each `over_attack`,
  `mod.rs:681-682`), and per-source sketch limiting is suppressed during
  cookie-active (#3315 D3). This is Junos-consistent (cookie/proxy stays active
  while flooding) but triggers AT threshold rather than strictly above; mitigation
  is operator guidance (set `attack-threshold` above normal traffic). A
  hysteresis/decay refinement that releases cookie mode when the rate falls below
  threshold is a **tracked follow-up**, not #3607 (a count-only-admitted fix here
  would re-open the bypass).
- **Per-destination ICMP/UDP flood modeling** (Junos is per-dest; xpf per-zone).
- **Default thresholds** (#3024/#3230); **SYN-cookie epoch clock** (#3032);
  **HA sync of counter state** (stays per-worker).

### 10a. PLAN-DEFER / PLAN-KILL criteria

- **DEFER-the-sketch (narrower scope):** keep the #3315 sketch on `RateCounter`;
  ship only consumers 1, 2, 4 (ICMP/UDP flood, standby-ACK, cookie-OFF aggregate).
  Acceptable if the sketch fail-closed re-derivation is judged too risky.
- **PLAN-DEFER-operator:** if the whole blast radius is disproportionate, fix L10
  (correct the false doc claim) + optionally L14 now, defer the counter work.
- **PLAN-KILL:** if reviewers conclude the shaper consumers are defensive-only and
  sustained-at-threshold benign traffic is unrealistic even for the standby-ACK
  and per-dest cases. L10 must still be corrected regardless.

## 11. Open questions for adversarial review (round 3)

1. **Sketch fail-closed** (§5b): is the token-bucket sketch genuinely fail-closed
   (collisions over-drain; sustained victim trips), and is "rate-enforced" the
   right replacement for "stay-tripped-until-idle", or should the sketch be
   deferred (§10a)?
2. **cookie-OFF aggregate** (§5a): is a per-zone OFF-attack token bucket alongside
   the unchanged `increment_and_classify` the cleanest cut, or two mechanisms
   fighting over one decision?
3. **ON-case cookie-lock** (§10): is documenting it + operator guidance
   acceptable, or does #3607 need the hysteresis follow-up bundled in?
4. **Two primitives + a per-zone bucket**: acceptable complexity, or error-prone?
5. **`now_ns` signature churn** (incl. the standby-ACK validator): acceptable, or a
   reason to DEFER?
6. **Value vs blast radius**: with the ON-aggregate scoped out, is the remaining
   value (standby-ACK failover + busy-dest + ICMP/UDP + cookie-OFF SYN) worth it,
   or PLAN-DEFER-operator?
