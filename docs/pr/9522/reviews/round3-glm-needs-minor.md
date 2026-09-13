# Adversarial PLAN review — ROUND 3 (FINAL) — psaab/xpf#9522

**Reviewed:** `docs/pr/9522/plan.md` v3 @ `277da0b8`, base `7ef226474`, worktree `9522-learned-route-cap`. All citations read at head. Round-2 raws re-read; every load-bearing repo fact re-verified independently (not trusted from v3's §4).

---

## Part 1 — The four required items: are they *satisfied*, or reworded?

### Item 1 — §5a reinject-mirror rewrite: **SATISFIED in substance; one unsound sub-claim (finding R3-1)**

- **No table forcing:** real. "table = NONE FORCED … route_table_override and meta.routing_table are NOT lookup inputs" (plan §5a). v2's mode contradiction is deleted, not reconciled — there is now exactly one lookup mode: RPDB walk with the reinject context. This is the correct resolution of round-2 F-A defect 1.
- **iif = TUN:** verified against `userspace-dp/src/afxdp/mod.rs:445` (`DEFAULT_SLOW_PATH_TUN: &str = "xpf-usp0"`).
- **The fidelity target is the kernel's post-reinject walk, and the tree proves it:** `tests_fragment.rs:826-841` re-read — the #7409 second vector comment states verbatim that the steered NoRoute frame "is REINJECTED to the kernel, which resolves it in the MAIN table and forwards it down the very path the operator steered it away from." v3's PBR-disagreement cell (PBR says zone X, MAIN says zone Y ⇒ adjudicate Y) turns this vector *into the contract*. Correct, and the only coherent target given `BuildPBRRules` drops unrepresentable terms.
- **Inputs are all derivable in the arm today:** `poll_descriptor/mod.rs:5236-5248` — the arm already calls `noroute_policy_denial_gated(…, adj_flow.src_ip, adj_flow.dst_ip, meta.protocol, ports, policy_icmp, …)`. Every §5a lookup input (src, dst, proto, ports, flowless ports=0/`l4_present=false` per the #3291/#4024 mirror documented at mod.rs:5191-5199) exists at the call site. No new packet-parse surface.
- **Hash-parity cell:** present (§9), and the argument is sound: iif equal both sides, identical 5-tuple ⇒ `fib_multipath_hash` selects the same member. F-D's adjudicate-selected-member is strictly better than round-2's sentinel suggestion and correctly deletes cross-zone-multipath from the indeterminate list (§5b).
- **The uid sub-claim fails its own standard — see R3-1 below.** The architecture does not change because of it; the fix is to move one selector from "inert" to "attested."

### Item 2 — capped gate restored as fallback: **SATISFIED, fully**

- §5b's three rows are exactly the round-2 determined resolution: lookup success in *either* capped state ⇒ real-zone adjudication; indeterminate+capped ⇒ today's gated delegation (counted, status-signalled); indeterminate+uncapped ⇒ sentinel byte-identical to master. "Delegate without a verdict" survives *only* as the bounded capped fallback.
- The "no third outcome" overreach is explicitly retracted (§1, §5b), and `noroute_policy_denial_gated`'s early-`None` is kept as the named fallback rather than deleted — §6 "Deleted: nothing" is now internally consistent with §5b.
- **§5e row 1 / absent=legacy against the v10 doctrine:** verified coherent. `snapshot.rs:633-648` shows v10's flag was bumped precisely because it was "NOT skew-tolerant … black-holing IS the defect it was added to fix," and `learned_route_cap_blackhole_9054_test.go:336-343` states the two-question rule. v3's `ComplexPolicyRouting *bool` absent ⇒ legacy-verbatim passes both questions: (a) old helper ignores the field — and the tree *pins* unknown-field tolerance as a tested property, not an assumption (`protocol/tests.rs:2984-2996`, the #6853 additive-both-ways test rests "on the ABSENCE of `deny_unknown_fields`"); (b) what the old helper enforced (master behavior) is acceptable by definition for a skew window, because the defect here is helper-lo…
- Default-permit/indeterminate is specified with the delegation-with-signal cell (§5b, §9) — Astra blocker 4's "specify the actual contract for uncertainty" is met honestly (real-pair denials NOT enforced in that class, said out loud).
- Status signal + `metrics_descriptors_binding.go` doc update are required deliverables (§5e); the file is the right home — the #7409 reinject counter series live at `metrics_descriptors_binding.go:58-111` (`bindingSlowPathNoRoutePackets` et al.), and the cap-status descriptor at `metrics_descriptors_global.go:93` is adjacent. The rewritten #9054 cell pins equivalence *and* fallback-preservation so the residual can't be silently "fixed" into a blackhole later. Good.

### Item 3 — §5d attestation: **SATISFIED, with one looseness (R3-3)**

- The iproute2 readback is the tree's own proven remedy: `rule_dscp_kernel_7796_test.go:108-112` re-read, verbatim — "netlink's own RuleList cannot be used as the reader here: the library has no FRA_DSCP support at all … iproute2 is an INDEPENDENT reader." Naming this exact reader for the presence leg is the correct F-C fix; raw `FRA_*` parsing is an equivalent conservative alternative, and the UAPI surface it must cover is confirmed present on this host (`fib_rules.h:56-75`: FRA_FLOW, FRA_TUN_ID, FRA_L3MDEV, FRA_UID_RANGE, FRA_IP_PROTO, FRA_SPORT/DPORT_RANGE, FRA_DSCP, FRA_FLOWLABEL(_MASK), FRA_DSCP_MASK).
- Tri-state `*bool` with absent ⇒ legacy verbatim resolves the v2 `omitempty`-vs-absence contradiction in the only direction consistent with item 2.
- The DSCP-rule attestation cell is the one the proven-blind `netlink.RuleList` surface cannot pass — the right pin. Enumeration-failure ⇒ complex closes the reader-failure leg. Looseness: see R3-3.

### Item 4 — F-D/E/F/G + §5f: **SATISFIED**

- **F-D:** adjudicate-selected-member; FIB_MATCH deleted (§5a). Determinism is per-flow and exact; cross-zone ECMP becomes determinate rather than sentinel-dropped. Correct.
- **F-E:** negative entries with "same TTL/cap/clear discipline" (§5c) — mirrors the verified precedent (`neighbor_resolver.rs:71-83`: bounded 4096 queue, per-key 1 s rate limit, 3 s negative TTL, overflow counters). Per-worker socket, hard recv deadline, in-flight cap 1, global ceiling, overflow ⇒ indeterminate ⇒ §5b. Specified.
- **F-F:** TOCTOU honestly split — withdrawal-inside-TTL ⇒ kernel drops at reinject (availability ≤ TTL, not a bypass); change-to-deny-pair ⇒ bounded residual ≤ TTL, "same order as the standing inter-push residual" — verified: the 1 s/3 s coalescing window is documented at the arm itself (`poll_descriptor/mod.rs:5122-5135`). Astra blocker 3 demanded the weaker invariant be proposed explicitly for approval; §2/§3 do exactly that, with PLAN-KILL offered if reviewers reject it. I accept it: ≤3 s, cleared on every FIB publish, strictly narrower than master's *unbounded* capped window.
- **F-G:** M1-M3 ordered **before** arm wiring as go/no-go gates (§9 "Order is load-bearing"), the permit-throughput caveat ships with measured numbers, and §3 states rather than asserts. The scan premise re-verifies (`forwarding/fib.rs:429-431`, `routes.iter().find`).
- **§5f:** five lines of prerequisites + "No mechanism is pre-approved here; any future B justifies itself from zero." Sketch deleted. Sufficient.

---

## Part 2 — The named adversarial checks

**uidrange-inert claim (§5a): FALSE as worded — R3-1 (the blocking finding).** §5a asserts "forwarded packets carry no socket on either side, so uidrange rules are inert for this path on BOTH sides — no divergence to attest." The reinject leg is correct (no socket ⇒ `flowi_uid` = overflowuid, 0xFFFFFFFF). The query leg is not: the `RTM_GETROUTE` is issued *over a socket that has an owner*, and the kernel stamps `flowi_uid` from the netlink socket unless the request carries `RTA_UID`. `RTA_UID` does exist (`/usr/include/linux/rtnetlink.h:395`), so `uid=INVALID` is implementable on modern kernels — but netlink silently ignores unknown attributes on older kernels, so an implementation that merely sends the attribute gets socket-uid (root ⇒ 0) wit…

**Mirror-equality invariant (§7.12) vs the v10 two-question-style completeness sweep (§11 Q1):** the invariant is stated; the candidate inputs resolve as follows. *rp_filter on the TUN:* **verified, not assumed** — `pkg/networkd/networkd.go:634-661` (`restoreSlowPathRPFilter`, tunName `xpf-usp0`), plus the in-tree #2378 hazard warning that `max(conf/all, conf/dev)` can override the per-device 0 (`networkd.go:663-687`, warned to the operator); it is availability-only, never a zone divergence. *conntrack:* not a fib input for a first packet; a CONNMARK restore in prerouting mutates the mark, and any ip-rule consulting fwmark is attested complex — closed transitively. *TCP-MD5/MPTCP:* no `FRA_*` selector reads TCP options (fib_rules.h confirms the full…

**Skew matrix vs the two-question test:** passes — traced above under Item 2, including the in-tree pin that old readers tolerate unknown fields.

---

## Part 3 — The seven round-3 questions

1. **Mirror-equality completeness:** No kernel fib input exists beyond §5a's list. rp_filter verified 0 in-tree (networkd.go:634-661; conf/all hazard operator-warned); conntrack inert (mark-carrying rules attested); TCP-MD5/MPTCP inert (no selector). Residual: operator nft prerouting mutation of mark/tos + kernel-side NAT on the TUN — exclude by name (R3-2), do not attest (undetectable from `ip rule`). Not a KILL; the exclusion is the same operational family the plan already draws.
2. **uidrange-inert:** proven-FALSE as worded — R3-1. Attest it.
3. **Population:** not the core. Every xpf-managed rule family is in-list by construction (verified — rules.go emits no mark/uid/flowlabel/tun_id selector), so the determinate class covers every box whose rules xpf manages; the complex class requires operator-added exotic selectors, which the cap-crossing FRR-edge population does not typically carry. The deciding measurement is nearly free: the §5d reader doubles as a fleet census (read `ip rule` on capped boxes, compute out-of-list share) plus the post-rollout adjudicated/fallback/sentinel counters already required. Keep the plan; require the census be reported in the PR.
4. **Negative-cache direction:** correct. A negative entry maps to indeterminate ⇒ (uncapped) sentinel or (capped) gated delegation — both byte-identical to master's disposition in the same window. A stale negative during a flap never yields a wrong verdict, only master-identical behavior for ≤ TTL; harm is availability-only and bounded. Hygiene already in the plan ("same TTL/cap/clear") — hold the negative entries to clear-on-publish in review.
5. **Sync-query stall arithmetic:** in-flight cap 1 ⇒ worst-case head-of-line cost to an unrelated flow on the worker = D, the recv deadline. GETROUTE is an RCU-path lookup executed in the sender's context, not RTNL-serialized; D in the low-ms range is comfortably inside the slow-path budget (the arm already lives with the 1 s/3 s coalescing posture). M2's no-go action must be "switch to the resolver-thread shape" (`neighbor_resolver.rs` already implements it) — never "raise D." State that threshold numerically in the PR.
6. **KILL-B:** not required. Prerequisites + from-zero mandate pre-approves nothing; the pointer is inert. Keep as-is.
7. **Status-signal sufficiency:** counters + the adjudicated-vs-legacy distinction satisfy "not silently," but add one rate-limited WARN on first complex-attestation per snapshot build and one on sustained capped-indeterminate delegation — it tells the operator *why* the fix is inert on their box and that deny-policy traffic still transits unadjudicated. One log line; #9172 stays out of scope. Draw the line there.

---

## Required before PLAN-READY (all minor-class; none change architecture, none can create a new unsafe state)

1. **R3-1:** Close the uidrange hole — add `uidrange` to §5d's complex-selector list with an attestation cell (preferred), or specify `RTA_UID=4294967295` with a positive capability probe. The §5a "inert on BOTH sides — stated not assumed" sentence must go.
2. **R3-2:** Extend §5c's unsupported-topology exclusion to name operator nft prerouting mark/TOS/DSCP mutation and kernel-side NAT on `xpf-usp0` (mirror-equality, §7.12, is field-for-field false on that topology).
3. **R3-3:** §5d must name the iproute2 readback as the *primary* reader (raw `FRA_*` parse as the fallback), rather than deferring the choice to the implementation commit; the DSCP cell already pins whichever is chosen.
4. **R3-4:** Add the Q7 WARN log lines as required deliverables alongside the counters.

---

## Verdict: **NEEDS-MINOR**

The four round-2 required items are satisfied in mechanism, not merely wording: F-A's fix deletes the second lookup mode and pins the verified #7409 MAIN-table behavior as the contract (tests_fragment.rs:826-841); F-B's fix restores the gate as the bounded capped fallback with a byte-identical old-sender pairing that now genuinely passes the tree's own two-question doctrine (snapshot.rs:633-648; learned_route_cap_blackhole_9054_test.go:336-343); F-C's fix names the tree's own proven independent reader with the DSCP cell the netlink surface provably cannot pass (rule_dscp_kernel_7796_test.go:108-112); F-D/E/F/G are each implemented as specified with their gates ordered before wiring. What remains is one unsound inertness assertion on a single selector fami…
