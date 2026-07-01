# #3607 — Screen `RateCounter` over-throttles sustained at-threshold traffic

## 1. Status

`DRAFT v4 — round-3 adversarial findings incorporated (Codex + AGY + Claude SMR);
converged design, pending final confirmation` (research branch
`research/3607-screen-rate`, base origin/master `9419bbc2c`).

`/research` plan. Stops at PLAN-READY / PLAN-DEFER / PLAN-KILL. No production
source changes, no PR.

**v4 change summary (round-3 review):**
- **#3315 per-source/per-dest sketch migration is DEFERRED** (Codex held a
  BLOCKER twice: a refilling token-bucket cell replaces "stay-tripped-until-idle"
  with "rate-enforced", and whether stay-tripped is a required security property
  for the per-dest cap is a genuine open question). Removing the sketch from scope
  eliminates the contested change AND shrinks the blast radius (`now_ns` no longer
  threaded into `syn_rate.rs`). The per-dest/per-source #3607 over-throttle becomes
  a tracked follow-up with its own fail-closed analysis.
- **Alarm-threshold gating specified precisely** (Codex MAJOR): the alarm branch
  keeps reading the MEASURED `over_attack`/`over_alarm` from the unchanged
  `increment_and_classify`; the OFF-attack token bucket governs ONLY the
  cookie-OFF drop decision, so `syn-flood-alarm` semantics are unchanged.
- **TokenBucket cold-start = full** (Codex MAJOR, AGY MINOR): a fresh bucket starts
  with `tokens = capacity` (and latches `last_refill_ns` on first use), matching
  the current `RateCounter` which admits the first `threshold` events on a fresh
  zone. Clock delta uses `saturating_sub` (AGY MINOR).

Scope after v4 (fixed): **ICMP flood, UDP flood, standby SYN-cookie ACK limiter,
and the SYN-flood aggregate DROP path when `syn-cookie` is OFF.**

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

Consumers fixed (shaper / validate-budget — "admitted" never means "skip a
security check"):

1. **ICMP flood / UDP flood** zone-aggregate counters (over = DROP).
2. **Standby SYN-cookie ACK-validation limiter** (4096/s, `mod.rs:502-512`) —
   "admitted" = "spend SipHash"; a bogus ACK still fails the crypto check, so
   raising the admit rate to the intended budget has **no bypass**. This is the
   strongest value: legit returning clients during/after a failover are no longer
   suppressed.
3. **SYN-flood aggregate DROP path when `syn-cookie` is OFF** — `over_attack`
   returns `Drop("syn-flood")` (`mod.rs:704`); with no cookie there is nothing to
   bypass, so sustained-at-threshold legit SYNs must be admitted.

Deliberately **not fixed** (documented, not "fixed"):

- **SYN-flood aggregate when `syn-cookie` is ON** — "admitted" = "skip the cookie
  challenge"; admitting a sustained-at-threshold stream would let `threshold`
  spoofed SYNs/sec bypass the cookie AND (via lingering `cookie_active`) the
  per-source cap (round-1 BLOCKER). Its over-throttle is benign (a challenge is a
  recoverable extra RTT). §5 / §10.
- **#3315 per-source / per-destination sketch** — DEFERRED (§5b); its
  stay-tripped→rate-enforced change needs its own fail-closed analysis.
- **missing-profile warn dampener** — wants suppress-until-idle; stays as-is.

**If reviewers judge even this reduced blast radius (a new `TokenBucket` + `now_ns`
threading into the screen check path + a per-zone OFF-attack bucket)
disproportionate to the value, PLAN-DEFER-operator (fix L10 + optionally L14) or
PLAN-KILL is acceptable.** §10a.

## 4. What's already shipped / partially batched

- **#2937 (`1b1cb215b`)** — current two-bucket sliding window; must not
  reintroduce its sub-ms micro-burst.
- **#3315 (`44474b9ea`)** — `increment_and_classify` (single advance, dual
  attack+alarm) → SYN-cookie activation; count-min sketch of `RateCounter`s
  (`syn_rate.rs`, fail-closed: cells only increase within the window, collisions
  only over-count, victim always trips, `syn_rate.rs:33,41`). The sketch is NOT
  migrated in this change (§5b). (`syn-flood timeout` enforced later in #3527 as a
  per-zone `tcp_opening_ns` override — session-layer, unrelated.)
- **#3032** — SYN-cookie epoch uses a once-per-second cached **wall** clock;
  orthogonal to the rate counters (which use **monotonic** time).
- **Enabling fact + real cost:** `loop_now_ns = monotonic_nanos()` is read once
  per batch (`worker/loop_body/mod.rs:241`) and truncated to `loop_now_secs`
  (:363). The clock READ is zero-cost; reaching the migrated counters needs a
  signature change: `stage_screen_check` takes only `now_secs`
  (`poll_stages.rs:312`) and the standby-ACK path
  (`stage_screen_syn_cookie_ack_on_session_miss` /
  `validate_syn_cookie_ack_on_session_miss`, `poll_stages.rs:557-562`) needs
  `now_ns` — churn beyond the screen module (AGY MINOR), but NOT into `syn_rate.rs`
  now that the sketch is deferred.

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
    last_refill_ns: u64,  // monotonic ns; 0 == uninitialised (cold start)
}
impl TokenBucket {
    /// SAME polarity as RateCounter::increment: returns TRUE when this event is
    /// OVER LIMIT (drop / limited); FALSE when admitted. Drop-in at the existing
    /// call sites (mod.rs:614,623,724,741 already treat true == drop).
    fn admit_is_over(&mut self, now_ns: u64, threshold: u32) -> bool {
        if self.last_refill_ns == 0 {
            // Cold start: start FULL so a fresh zone admits the first `threshold`
            // events, matching today's RateCounter first-window behaviour.
            self.tokens_q = capacity_q(threshold);
            self.last_refill_ns = now_ns.max(1); // never leave it 0
        } else {
            let elapsed = now_ns.saturating_sub(self.last_refill_ns); // no underflow
            self.tokens_q = (self.tokens_q + refill_q(elapsed, threshold))
                .min(capacity_q(threshold));
            self.last_refill_ns = now_ns.max(1);
        }
        if self.tokens_q >= ONE {
            self.tokens_q -= ONE;   // consume only on admit
            false                    // admitted
        } else {
            true                     // over limit — do NOT consume
        }
    }
}
// refill_q(elapsed, threshold) = elapsed_ns * threshold via a precomputed
// fixed-point tokens-per-ns reciprocal-multiply — NO per-packet 64-bit divide.
```

Consumer split by security semantic:

| Consumer | Counter | Semantic | Why |
|---|---|---|---|
| ICMP / UDP flood | **TokenBucket** | shaper | over = drop; admit ≤T/s |
| Standby SYN-cookie ACK | **TokenBucket** | validate-budget | admit = spend SipHash; no bypass |
| SYN aggregate DROP, `syn-cookie` **OFF** | **TokenBucket** (new per-zone) | shaper | no cookie ⇒ no bypass |
| SYN aggregate, `syn-cookie` **ON** (`increment_and_classify` → cookie) | **RateCounter (UNCHANGED)** | defense-latch | admit = skip cookie ⇒ stay sticky |
| alarm-threshold measurement | **RateCounter (UNCHANGED)** | arrival-rate observation | alarm counts all arrivals |
| per-source / per-dest sketch | **RateCounter (UNCHANGED — DEFERRED)** | — | §5b: stay-tripped vs rate-enforced open |
| missing-profile warn dampener | **RateCounter (UNCHANGED)** | suppress-until-idle | log dampener wants no re-warn (`tests.rs:4085`) |

### 5a. SYN aggregate: cookie-OFF fix, exact alarm gating (Codex MAJOR)

`increment_and_classify` (count-all, `RateCounter`) is UNCHANGED — it is the
round-1 signed-off invariant (`rate.rs:97`, `mod.rs:631-634`) driving the alarm
crossing and cookie-ON activation. The alarm branch keeps its EXACT current gating
(fires only when MEASURED `over_alarm && !over_attack`, once per second per zone,
`mod.rs:706-718`) reading the measured values. Only the cookie-OFF DROP decision
changes:

```text
(over_attack, over_alarm) = agg_rate.increment_and_classify(now_secs, attack, alarm) // UNCHANGED (measured)
if over_attack:
    if syn_cookie ON:  mint cookie / activate; return Challenge         // UNCHANGED — no bypass
    else (OFF):        if off_attack_bucket.admit_is_over(now_ns, attack) { return Drop("syn-flood") }
                       // else fall through: the shaper admits this SYN
# alarm gate unchanged: fires iff (over_alarm && !over_attack) using the MEASURED values
if syn_alarm_threshold>0 && over_alarm && !over_attack && once_per_sec: raise syn-flood-alarm
... per-dest / per-source (unchanged, still RateCounter) ...
```

Because the alarm gate reads the MEASURED `over_attack` (unchanged), inserting the
OFF bucket cannot alter `syn-flood-alarm` semantics: a SYN with measured
`over_attack` never reaches the alarm branch (gated on `!over_attack`), exactly as
today; when the OFF bucket admits an over-attack SYN it proceeds to the per-IP
caps (as an admitted packet would). Cost: one `TokenBucket` per zone (16 B).

### 5b. Why the #3315 sketch is DEFERRED (Codex BLOCKER)

Migrating the sketch cells `RateCounter → TokenBucket` would replace
"stay-tripped-until-a-fully-idle-second" with "rate-enforced" (a victim that drops
below the per-dest rate regains budget). For the pure-drop shapers (§3) that is
unambiguously the #3607 fix, but for the #3315 *sketch* it is a genuine open
question whether stay-tripped is a required security property (a paced-at-threshold
attacker would no longer be permanently blocked — arguably correct rate-limiting,
but Codex flagged it as a fail-closed change twice). Rather than force a contested
change on a security-critical no-eviction sketch, the sketch stays on the current
`RateCounter` in this change. The per-source/per-destination #3607 over-throttle
(a busy legit destination at `destination-threshold` throttled to ~0) is a
**tracked follow-up** that must include its own fail-closed re-derivation and
tests. This also removes `now_ns` from `syn_rate.rs` (smaller blast radius).

### 5c. Rejected alternatives

- **Option A weighted sliding window** — low-threshold roughness (`T=1` → ~50%
  loss); not recommended.
- **Option C stop-counting-rejected only** — `T,0,T,0` flood-evasion waveform.

### Cross-cutting

- **L14:** token bucket bounds `tokens ≤ capacity = threshold` ⇒ no saturation;
  resolved structurally (flood intensity is already the #3343 drop counters). The
  untouched aggregate/sketch `RateCounter` keeps its existing `saturating_add`.
- **L10:** rewrite `docs/syn-cookie-flood-protection.md:275-280` + module docs:
  token-bucket shaper (admit sustained ≤ threshold, burst = threshold) for the
  migrated consumers; the deliberate cookie-ON defense-latch for the aggregate;
  the sketch/dampener remaining as-is; the sketch #3607 gap noted as a follow-up.

## 6. Public API preservation

- `RateCounter::increment_and_classify(now_secs, attack, alarm)` — **UNCHANGED**.
- `RateCounter::increment` / `reset` — retained (missing-profile warn + sketch +
  aggregate/tests).
- **New** `TokenBucket::admit_is_over(now_ns, threshold) -> bool` — `true = over =
  drop/limited` (same polarity as `increment`, drop-in).
- `syn_rate.rs::SynRateSketch` — **UNCHANGED** (sketch deferred; still `now_secs`).
- `ScreenState::check_packet` / `check_packet_with_zone_id` /
  `validate_syn_cookie_ack_on_session_miss` — gain `now_ns` (retain `now_secs`
  for scan/cookie-active/validated-TTL/alarm-sec/epoch-gate/sketch).
- No Go / gRPC / CLI / protobuf change.

## 7. Hidden invariants the change must preserve

- **SYN-aggregate count-before-classify + always-count** (`rate.rs:97`,
  `mod.rs:631`) — preserved (`increment_and_classify` untouched).
- **`syn-flood-alarm` gating** — preserved (§5a; alarm reads measured values).
- **Cookie-ON no-bypass** — the OFF-attack bucket is consulted ONLY when
  `syn-cookie` is OFF.
- **#3315 sketch fail-closed** — preserved by NOT migrating the sketch.
- **#2937 anti-micro-burst** — token bucket: ≤ capacity tokens at a sub-ms
  straddle.
- **First-packet admission on a fresh zone** — TokenBucket cold-start = full (§5).
- **missing-profile suppress-until-idle** (`tests.rs:4085`) — preserved.
- **Allocation / hot path** — no per-packet alloc; integer-only; no per-packet
  divide (fixed-point refill); monotonic clock only; `saturating_sub` on the delta.
- **16-byte layout / no HA-wire/persistence** — `TokenBucket` ≤ 16 B; nothing
  synced/serialized/persisted.
- **SYN-path side-effect ordering** (`mod.rs:665-745`) — unchanged.

## 8. Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression | **LOW–MED** | Sketch + aggregate ON path + alarm gating all untouched; RED-on-revert for #2937 (micro-burst) + #3607 (sustained) on the migrated consumers. |
| Lifetime / borrow-checker | **LOW** | `TokenBucket` is a plain value; disjoint-field borrow unchanged; `now_ns` scalar param. |
| Performance regression | **LOW** | Reuse `loop_now_ns`; one fixed-point mul+add+cmp+cond-sub per event; 16 B; verify SYN/ICMP flood iperf + CPU. |
| Architectural mismatch | **LOW** | One small primitive + a per-zone OFF-attack bucket; `now_ns` threading (loop_body → forwarding → poll_stages → screen, incl. standby-ACK validator — NOT the sketch). Mechanical, reduced by the sketch deferral. |

## 9. Test plan

- `cargo build` clean; `cargo test screen::` (TokenBucket unit + enforcement +
  aggregate), `cargo test afxdp::poll_stages`, full `cargo test`; `go test ./...`.
- **M09 RED-on-revert sustained-at-threshold** (deliverable): TokenBucket at
  exactly `threshold`/s for N seconds via `now_ns`; steady-state admit ≈ threshold
  (≥ 0.99·T), not ~0. RED against current `RateCounter`.
- **Low-threshold:** `T=1` sustained 1 pps admits every second.
- **Cold-start:** a fresh `TokenBucket` admits the first `threshold` events
  (`last_refill_ns == 0` ⇒ start full); `now_ns` near 0 does not false-drop.
- **Clock underflow:** an out-of-order `now_ns` (`< last_refill_ns`) does not panic
  (`saturating_sub`).
- **Recovery:** after an over-limit burst, dropping to ≤ threshold recovers
  without a fully idle second.
- **cookie-OFF aggregate:** sustained-at-`attack-threshold` SYNs with `syn-cookie`
  OFF are admitted (RED against current count-all); **alarm still fires on arrival
  rate** and **cookie-ON aggregate tests stay green with NO edits** (proof the ON
  path + alarm gating are untouched).
- **#2937 retained:** adapt `boundary_double_burst_is_bounded` /
  `icmp_flood_sliding_window_..._recovers` to the bucket — sub-ms micro-burst
  bounded to ~threshold.
- **Untouched-by-design stay green with NO edits:** #3315 sketch tests
  (still `RateCounter`); missing-profile `tests.rs:4085`.
- **Smoke (loss userspace cluster):** screen profile with low icmp/udp thresholds;
  sustained-at-threshold admitted, above-threshold dropped; v4 + v6; no forwarding
  regression; standby cookie-ACK path admits at the 4096/s budget under sustained
  load. `make test-failover` NOT required (no cluster/VRRP/session-sync code
  touched); a screen smoke IS.

## 10. Out of scope (explicitly)

- **#3315 per-source/per-dest sketch #3607 over-throttle** — DEFERRED to a tracked
  follow-up with its own fail-closed analysis (§5b).
- **SYN aggregate over-throttle when `syn-cookie` is ON** — deliberately retained
  (defense-latch / cookie-bypass safety). Consequence (AGY MAJOR): once tripped,
  the zone stays cookie-active while the arrival rate ≥ threshold plus a ≤64s tail
  (`active_until = now + EPOCH_SECS`, re-armed each `over_attack`,
  `mod.rs:681-682`), and per-source sketch limiting is suppressed during
  cookie-active (#3315 D3). Junos-consistent (cookie/proxy stays active while
  flooding) but triggers AT threshold not strictly above; mitigation is operator
  guidance (set `attack-threshold` above normal traffic). A hysteresis/decay
  refinement is a tracked follow-up, not #3607 (a count-only-admitted fix would
  re-open the bypass).
- **Per-destination ICMP/UDP flood modeling** (Junos is per-dest; xpf per-zone).
- **Default thresholds** (#3024/#3230); **SYN-cookie epoch clock** (#3032);
  **HA sync of counter state** (stays per-worker).

### 10a. PLAN-DEFER / PLAN-KILL criteria

- **PLAN-DEFER-operator:** if the reduced blast radius is still judged
  disproportionate, fix L10 (correct the false doc claim) + optionally L14 now,
  defer the counter work.
- **PLAN-KILL:** if reviewers conclude the shaper consumers are defensive-only and
  sustained-at-threshold benign traffic is unrealistic even for the standby-ACK
  case. L10 must still be corrected regardless (the doc currently makes a false
  claim).

## 11. Open questions for adversarial review (round 4)

1. **Sketch deferral** (§5b): is deferring the #3315 sketch the right call (avoids
   the contested stay-tripped→rate-enforced change), and is the remaining value
   (ICMP/UDP flood + standby-ACK + cookie-OFF SYN) still worth shipping?
2. **Alarm gating** (§5a): does reading the MEASURED `over_attack` for the alarm
   gate while the OFF bucket drives the drop fully preserve `syn-flood-alarm`
   semantics, or is there an ordering hole?
3. **Cold-start-full + fixed-point refill** (§5): correct and overflow-safe for
   both large `T` (1e6) and `T=1` in 16 bytes?
4. **Two primitives + a per-zone OFF bucket**: acceptable complexity?
5. **Value vs blast radius**: PLAN-READY as scoped, or PLAN-DEFER-operator?
