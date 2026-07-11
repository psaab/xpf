# Plan — #5177 NAT64 embedded ICMP-error L4 port/identifier restoration

**Revision:** r3 (3-reviewer convergence — Codex corrections folded in; PLAN-KILL as scoped)
**Base SHA:** `4e0c7f74c` (origin/master at research start)

> **Reviewer convergence (round 1):**
> - **Claude SMR — CONCUR PLAN-KILL** (hostile, 5 attacks; could not break the KILL). See `claude-smr-plan-r1.md`.
> - **Codex — CONCUR PLAN-KILL** (hostile, read-only; found NO counter-path; confirmed items 1–3; corrected the plan's citations; and *exhaustively proved a larger bug* — ordinary reverse NAT64 TCP/UDP replies are also broken, R-C resolved). See `codex-plan-r1.md`.
> - **AGY — INFRA-BLOCKED** after two documented retries (both runs went off-task, hallucinating about an unrelated `--print-timeout` CLI flag; zero signal). Per the research skill's infra-blocked exception, converged 2-of-3 (Claude SMR + Codex).
>
> r3 folds Codex's material corrections: (a) the ordinary-reply "may be broadly unreachable" hedge is **upgraded to exhaustively-broken**; (b) the `nat64_reverse: None` constructor citations are **corrected** to the three real production constructors; (c) the follow-up gains the small decision-derived ordinary-reply repair + the oversized-TCP IPv4-leak finding.
**Issue:** #5177 — "userspace-dp NAT64: reverse ICMP-error translation leaves
the translated PAT port/ICMP-id in the embedded quote instead of the original
client value."
**Scope:** research-only. Stops at PLAN-READY / PLAN-KILL. No production code
in this branch — plan doc + reviewer verdicts only.

> **r1 → r2 change:** r1 recommended a small fix (Option A: thread the port from
> `decision.nat` into `translate_embedded_*`). The delegated reachability trace
> **falsified** that approach on two independent grounds (§3.1). r2's
> recommendation is **PLAN-KILL #5177 as scoped**, plus a **new filed issue**
> for the real, larger defect the trace surfaced (NAT64 reverse ICMP errors are
> dropped entirely). The correctness *intent* of #5177 is valid but its named
> fix site and datum are both wrong.

---

## 1. Status / recommendation

**Recommendation: PLAN-KILL #5177 as literally scoped.** The named fix —
rewrite the quoted L4 port inside `translate_embedded_v4_to_v6` /
`translate_embedded_v6_to_v4` and source the value from the outer
`NatDecision` — is **inert** for the direction the issue describes and uses the
**wrong datum** for the other direction:

1. **Reverse direction (the issue's stated case — "delivered to the inside
   host"): the fix site is unreachable.** A reverse NAT64 ICMPv4 error is
   dropped upstream, never reaching `translate_embedded_v4_to_v6`.
2. **Forward direction: wrong datum.** Where `translate_embedded_v6_to_v4` *is*
   reachable, the outer `decision.nat.rewrite_src_port` is a **fresh per-error
   pool allocation**, not the quoted data flow's port — restoring it would write
   an unrelated port.

The underlying RFC-6146 correctness goal is valid, but the actual defect is
**upstream and larger**: the cross-family (`nat.nat64`) embedded-ICMP match is
produced and then **discarded by the same-family builder**, so the reverse
error is dropped. That is a separate, higher-severity bug → **file a new
issue** (§10) whose fix subsumes #5177's intent using the datum that *is*
already available (`EmbeddedIcmpMatch.original_src` / `.original_src_port`).

- [x] Defect in `translate_embedded_*` verified (verbatim L4 copy).
- [x] Reachability trace complete (§3.1) — reverse case fully confirmed dropped.
- [x] r1 Option A falsified; wrong-site + wrong-datum documented.
- [x] Converged 2-of-3 on PLAN-KILL: Claude SMR CONCUR + Codex CONCUR; AGY infra-blocked (2 retries).
- [x] Codex corrections folded (r3); R-C (ordinary reverse replies broken) proven.
- [ ] Follow-up issue filed for the real fix; `plan-kill` label on #5177.

---

## 2. Issue framing (the named defect, verified)

`translate_embedded_v4_to_v6` (`nat64.rs:2448-2501`) and its twin
`translate_embedded_v6_to_v4` (`nat64.rs:2363-2443`) restore the embedded
**addresses** but copy the quoted **L4 bytes verbatim** (`out[40..total]
.copy_from_slice(l4)` at `nat64.rs:2492`), applying only an embedded ICMP
type/code remap — no TCP/UDP port or ICMP-id rewrite. So *as a leaf function*
they do carry the bug the issue names.

The existing test `nat64_v4_to_v6_time_exceeded_translates_outer_and_embedded`
(`nat64_tests.rs:1873`) builds an embedded quote with L4
`[0x30,0x39,0x00,0x50,…]` (src port `0x3039`=12345) and asserts
`emb[40..48] == inner_l4` (`nat64_tests.rs:1928`) — i.e. it enshrines the
verbatim copy. **But this is a direct unit call to `translate_v4_to_v6`, which
takes addresses only and no port** — it is not a production ingress path.

The problem: **that leaf function is not reached from production ingress for the
direction the issue describes**, so fixing it there is invisible on real
traffic. §3.1 proves this.

---

## 3. Honest scope + value framing

### 3.1 Reachability trace — the load-bearing finding (Q1 resolved)

Delegated line-precise read-only trace (corroborated by an independent
first-hand read). **Reverse NAT64 ICMPv4 error** (outer `server → snat_v4`,
quoting the forward packet `snat_v4:pool_port → server:sport`):

1. Outer ICMPv4 error is L4-portless → session **MISS**.
2. `is_embedded_icmp_error` = true — `poll_descriptor/mod.rs:2170-2181`.
3. `if is_embedded_icmp_error {` — `:2454` → `try_embedded_icmp_nat_match` —
   `:2458`. **This arm is taken, so the normal `else if ForwardCandidate`
   NAT64 build at `:2619` / `:4183` is never reached.**
4. Outer family AF_INET → `match_outer_v4` — `icmp_embed/mod.rs:157`.
5. `match_outer_v4` parses the quote and calls
   `lookup_forward_nat_across_scopes(reverse_key)` —
   `icmp_embed/nat_match_v4.rs:18-42`. This **matches the forward IPv6 NAT64
   session cross-family** (NAT64-aware reverse key, `session/key.rs:112-141`),
   recovering `original_src = fwd.key.src_ip` = **the IPv6 client**
   (`nat_match_v4.rs:45`), `original_src_port = fwd.key.src_port` = **the
   original client port**, and `nat.nat64 = true`.
6. Poll: `icmp_match.nat.rewrite_src.is_some()` true (`:2485`) → AF_INET →
   `build_nat_reversed_icmp_error_v4` — `:2495`.
7. **Terminal: `build_nat_reversed_icmp_error_v4` returns `None`** at
   `icmp_embed/builders.rs:26-29` — `let original_client = match
   icmp_match.original_src { IpAddr::V4(v4) => v4, _ => return None }`. The
   match's `original_src` is `IpAddr::V6`, so the v4→v4 builder rejects it.
8. `None` → no `PendingForwardRequest` queued (`:2507`), `recycle_now` stays
   true; the untranslated IPv4 frame is kernel-reinjected/recycled
   (`:5432-5473`). **The v6 client never receives the error.**

`translate_embedded_v4_to_v6` is only invoked from `build_nat64_v4_to_v6_frame`
← `build_nat64_forwarded_frame` (AF_INET reverse branch, `frame/mod.rs:289-331`)
← the TX dispatcher gated on `is_nat64 = request.decision.nat.nat64`
(`tx/dispatch/mod.rs:677`). The embedded-ICMP path never produces a
`nat64`-flagged request (its only request carries `NatDecision::default()`,
`poll_descriptor/mod.rs:2510`). **So the reverse `translate_embedded_v4_to_v6`
site is dead for production ingress.**

**No explicit `nat64` guard** exists in `try_embedded_icmp_nat_match`; the cross
-family match is produced and the *effective* guard is the same-family builder's
family check at `builders.rs:26-29` (a silent drop).

**Larger latent bug — EXHAUSTIVELY PROVEN by Codex (R-C resolved):** ordinary
reverse NAT64 TCP/UDP replies are *also* broken, not only ICMP errors. The three
**real** production `PendingForwardRequest` constructors all hard-code
`nat64_reverse: None`:
- normal live forwarding — `forward_request.rs:288-302`,
- embedded-ICMP prebuilt forwarding — `poll_descriptor/mod.rs:2537-2557`,
- generated time-exceeded forwarding — `icmp.rs:257-281`.

*(Correction from r2: the earlier list — `poll_descriptor:2380/5701/5865`,
`worker/loop_body:1483`, `forwarding/mod.rs:804` — were `SessionMetadata`
fields, several test-only, NOT request constructors. Codex re-read and
relabeled them.)* The real `nat64_reverse` values live only on `SessionMetadata`
(`:3003-3010/:3280-3286`) and are never copied onto a request. The AF_INET
reverse branch of `build_nat64_forwarded_frame` *requires* `request.nat64_reverse`
(`frame/mod.rs:289-292`) → returns `None` → slow-path fallback
(`tx/dispatch/mod.rs:880-882/:1201-1203`) → `extract_l3_packet_with_nat` picks
same-family `apply_nat_ipv4` (`slow_path.rs:379-398`), which **discards the IPv6
rewrite addresses** (`frame/mod.rs:896-905`) and emits the packet **still as
IPv4** to the TUN. NAT64 is deliberately excluded from the flow cache
(`flow_cache.rs:321-329`), and the XDP shim does not translate NAT64
(`userspace-xdp/src/lib.rs:1427-1437`), so there is no alternate repair path.
**Net: the userspace production path emits no IPv6 reply for a NAT64 flow** —
consistent with the `#4565` note (`shared_ops.rs:700-707`) that the builder
"returns None … and the reply is dropped." Unit tests miss this because they call
`build_nat64_forwarded_frame` with `nat64_reverse` supplied explicitly; the gap
is purely at the request-construction boundary. **Additional leak:** an oversized
reverse NAT64 TCP reply is segmented *before* the NAT64 builder with no NAT64
exclusion (`tx/dispatch/mod.rs:541-591/:1458-1502`,
`frame/tcp_segmentation.rs:145-217`) and transmitted as IPv4.

### 3.2 Forward direction (v6→v4) — reachable, but wrong datum

`translate_embedded_v6_to_v4` IS reachable via `build_nat64_v6_to_v4_frame`
(`nat64.rs:1711-1718` → `translate_icmpv6_message_to_icmpv4`). BUT:
- A forward ICMPv6 **error** *also* trips `is_embedded_icmp_error` and is
  diverted to the same-family `match_outer_v6` at `:2454` before reaching the
  normal forward build at `:4183`, so even the forward embedded translation is
  reliably exercised only by **non-error** forward traffic.
- Even if it were reached: forward NAT64 is classified by
  **destination-prefix** (`poll_descriptor/mod.rs:1623`) and `rewrite_src_port`
  is a **fresh per-flow `allocate_source`** (`:2746` → `forward_decision`,
  `nat64.rs:984-994`) for *the ICMP error packet itself*, unrelated to the
  quoted data flow's pool port. So r1's "read `decision.nat.rewrite_src_port`
  for the embedded quote" would stamp an **unrelated** port.

### 3.3 Value verdict

The RFC-6146 goal (restore the embedded client tuple in NAT64 ICMP errors) is
real and operationally meaningful (PMTUD/traceroute through NAT64). But #5177's
**named fix is wrong on site and datum**, and the reverse path is dropped by a
larger upstream defect. Therefore:
- **#5177 as scoped → PLAN-KILL** (inert/wrong-datum leaf polish).
- The real correctness win belongs to a **new issue** (§10) whose fix restores
  the client tuple using `EmbeddedIcmpMatch.original_src`/`.original_src_port`
  (already available) and routes the cross-family match to a v4→v6 builder.

---

## 4. What's already shipped (context)

- **#2371 — embedded checksum**, **#4381 — stateful PAT (BIB)**, **#4512/#4565 —
  HA reverse-BIB sync.** #4381 populates `rewrite_src_port`/`rewrite_dst_port`.
  #4565's own note (`shared_ops.rs:700-707`) already acknowledges the reverse
  builder "returns None and the reply is dropped" without `nat64_reverse` — an
  early signal of the §3.1 gap. This plan does not re-litigate any of them.

---

## 5. Why the r1 design (Option A) is rejected

r1 proposed threading `decision.nat`'s port into `translate_embedded_*`. Rejected
because (§3): the reverse translator is **unreachable** (dropped upstream) and
the forward translator's `decision.nat` carries the **wrong** (fresh-allocation)
port. A green leaf-level unit test on `translate_embedded_*` would therefore
pass while the reverse bug still ships — exactly the "test the reachable path,
not a synthetic translator call" failure mode. r1 is preserved in git history
(commit `be71e0516`) for the record.

---

## 6. The correct fix (for the NEW issue, not #5177-as-scoped)

Sketch, so the KILL is constructive and the follow-up is actionable:

**Locus:** the `is_embedded_icmp_error` handler
(`poll_descriptor/mod.rs:2454-2600`) + a new **cross-family** builder, NOT
`translate_embedded_*`'s signature.

**Design:** when `try_embedded_icmp_nat_match` returns a match with
`icmp_match.nat.nat64 == true`, route to a NAT64 v4↔v6 ICMP-error builder
instead of the same-family `build_nat_reversed_icmp_error_v{4,6}`. The datum is
already in hand:
- `icmp_match.original_src` = the v6 client (outer new dst + embedded new src).
- `icmp_match.original_src_port` = **the original client port** (`fwd.key.src_port`)
  — this is the value #5177 wants, and it is already recovered.
- `icmp_match.original_dst` / `resolution` / `metadata` for outer src + egress.

The builder translates the outer ICMPv4→ICMPv6 (server→prefix::server,
snat_v4→client_v6) and the embedded quote v4→v6, stamping the embedded **source
port** = `original_src_port` and the embedded **src IP** = client_v6. It MAY
reuse `translate_embedded_v4_to_v6` as a subroutine **with** an added port
parameter (r1's leaf change becomes correct **only** in this context, fed the
right datum from `EmbeddedIcmpMatch`, not the outer `decision.nat`). The
symmetric forward case (`match_outer_v6`, `nat.nat64`) builds v6→v4.

**Checksum:** outer ICMPv6 checksum recomputed with the v6 pseudo-header (as the
same-family v6 builder already does); embedded L4 checksum left stale (kernels
don't validate it — consistent with the address rewrite).

**Blocking prerequisite:** §3.1's "no request populates `nat64_reverse`" gap may
mean the reverse v4→v6 whole-packet path needs wiring regardless (OQ7). The new
issue must scope this — the ICMP-error fix cannot be validated end-to-end if the
reverse reply path itself is broken.

**Test (reachable path, per the steer):** drive a real NAT64 flow, then feed an
inbound ICMPv4 error through the ingress classify (`poll_descriptor`), and assert
a v6 ICMPv6 error is emitted to the client with the embedded source port ==
original client port (TCP/UDP/ICMP-id). A leaf-only `translate_embedded_*` test
is explicitly insufficient.

---

## 7. Hidden invariants / gotchas (for the follow-up)

1. Cross-family routing must key on `nat.nat64`, not on outer family alone.
2. `EmbeddedIcmpMatch.original_src_port` is the correct client-port datum; the
   outer `decision.nat` is NOT (fresh allocation / dropped).
3. Truncated-quote bounds (no panic) still apply in the new builder.
4. Embedded L4 checksum left stale; outer recomputed by the builder.
5. The `nat64_reverse`-not-populated gap (§3.1) is a probable prerequisite.

---

## 8. Risk table (of the KILL decision)

| # | Risk | Likelihood | Mitigation |
|---|------|-----------|------------|
| K1 | A reviewer finds a path where the reverse error DOES reach `translate_embedded_v4_to_v6` (trace missed something) → KILL is wrong | Low | Trace is line-precise + first-hand-corroborated; reviewers asked to find the counter-path or ratify KILL. |
| K2 | KILL loses the valid RFC-6146 intent | Low | Intent preserved + made correct in the filed follow-up (§6/§10). |
| K3 | Normal reverse NAT64 replies actually work via an unexamined path, shrinking the follow-up | Medium | Scoped as OQ7 / a distinct investigation in the new issue; does not change #5177's KILL. |

---

## 9. Test plan (for the KILL)

No production code, so no test lands on #5177. The KILL is validated by:
- The reachability trace (§3.1) — reverse error is dropped; `translate_embedded_v4_to_v6` has no production caller for that direction.
- The forward-datum argument (§3.2) — `decision.nat.rewrite_src_port` is a fresh allocation.
- Reviewer convergence (adversarial: find the counter-path or ratify).
The **follow-up** issue carries the reachable-path `cargo test --release` matrix
described in §6.

---

## 10. Out of scope (of #5177) + filed follow-up

- **Filed follow-up issue (the real fix) — now scoped larger and higher
  severity, R-C proven:** "NAT64 reverse translation is broken in the userspace
  production path — `Nat64ReverseInfo` is lost at the `PendingForwardRequest`
  boundary." Two coupled defects:
  1. **Ordinary reverse TCP/UDP replies** emit IPv4 instead of the translated
     IPv6 (small repair: derive `src_v6`/`dst_v6` in the AF_INET builder from
     `decision.nat.rewrite_src`/`rewrite_dst`, which already carry the original
     v6 endpoints via `NatDecision::reverse` — `nat/mod.rs:106-120`,
     `frame/mod.rs:310-318`; no dependency on `request.nat64_reverse`).
  2. **Reverse ICMP errors** are dropped by the same-family `icmp_embed` builder
     (needs a cross-family v4↔v6 ICMP-error builder that restores the embedded
     client tuple — this subsumes #5177's intent using the already-available
     `EmbeddedIcmpMatch.original_src_port`). The ordinary-reply repair does NOT
     fix this sub-case (its request uses `NatDecision::default()`).
  3. **Oversized reverse TCP leaks as IPv4** via the segmentation path (no NAT64
     exclusion) — fold into the same fix.
  Recommend its own `/research` pass before `/engineer` — it is materially
  larger than #5177 and touches the request-carriage + a new builder. Link
  added on filing.
- Same-family SNAT/DNAT/NPTv6 embedded ICMP (already correct via `icmp_embed`).
- The NAT64 fast path (throughput) — untouched.

---

## 11. Open questions (each invitable to a different disposition)

1. **[RESOLVED] Reachability.** Reverse NAT64 ICMP error is dropped;
   `translate_embedded_v4_to_v6` unreachable for it (§3.1). → drives KILL.
2. **Is KILL correct vs. PLAN-REFRAME-under-#5177?** Should the larger fix be
   planned *under #5177* (reframe) instead of a new issue + KILL? Argument for
   KILL+new-issue: #5177's title/body/fix-direction are specifically the wrong
   leaf change; the real fix is a different subsystem (icmp_embed routing +
   cross-family builder) at higher severity. Reviewers to decide.
3. **Forward direction alone.** Is fixing only the (rarely-reached) forward
   embedded translation with the *correct* datum worth anything on its own?
   (Weak — also diverted to `match_outer_v6`.)
4. **Datum source.** Confirm `EmbeddedIcmpMatch.original_src_port ==
   fwd.key.src_port` is the original client port in all match arms (forward-NAT
   match vs. session-fallback). (`nat_match_v4.rs:46` vs `:106`.)
5. **[RESOLVED] `nat64_reverse` population gap (was OQ7).** Codex proved
   ordinary reverse TCP/UDP replies are broken too (emit IPv4). The reverse
   carriage MUST be wired before any ICMP-error fix can be validated end-to-end;
   both live in the filed follow-up. Recommend an end-to-end NAT64 reverse
   repro (v6 client ↔ v4 server through NAT64, assert v6 reply) as the first
   step of the follow-up's `/research`, since a shipped-but-only-unit-tested
   feature could still have a real reverse path this static trace didn't model.
6. **Checksum policy** for the new builder: leave embedded L4 stale (recommended)
   vs. incremental. (Same conclusion as r1 — kernels don't validate.)
7. **Value threshold.** Is NAT64-ICMP-error correctness (PMTUD/traceroute)
   high enough priority to schedule the larger follow-up now, or PLAN-DEFER it?

---

## Appendix — key line references (origin/master `4e0c7f74c`)

- `translate_embedded_v4_to_v6` / `_v6_to_v4` — `nat64.rs:2448` / `:2363`
  (verbatim L4 copy at `:2492` / `:2427`)
- `EmbeddedV4ToV6` / `EmbeddedV6ToV4` — `nat64.rs:2144` / `:2132` (addresses only)
- `Nat64ReverseInfo` — `nat64.rs:255-259` (addresses only)
- `build_nat64_forwarded_frame` (AF_INET reverse requires `nat64_reverse`) — `frame/mod.rs:232`, `:289-331`
- `is_nat64 = request.decision.nat.nat64` — `tx/dispatch/mod.rs:677`
- `is_embedded_icmp_error` — `poll_descriptor/mod.rs:2170`; ICMP arm `:2454`; same-family build `:2495`
- `match_outer_v4` recovers v6 `original_src` + client `original_src_port` — `icmp_embed/nat_match_v4.rs:41-46`
- same-family builder family guard (silent drop) — `icmp_embed/builders.rs:26-29`
- the THREE real production `PendingForwardRequest.nat64_reverse = None` constructors — `forward_request.rs:288-302`, `poll_descriptor/mod.rs:2537-2557`, `icmp.rs:257-281` (Codex correction; the r2 list conflated `SessionMetadata` sites)
- ordinary reverse reply slow-path IPv4 leak — `tx/dispatch/mod.rs:880-882` → `slow_path.rs:379-398` → `frame/mod.rs:896-905`; oversized-TCP segmentation leak — `frame/tcp_segmentation.rs:145-217`
- enshrining unit test (addresses-only call) — `nat64_tests.rs:1873`, assert `:1928`
- forward `rewrite_src_port` = fresh `allocate_source` — `poll_descriptor/mod.rs:2746` → `nat64.rs:984-994`
