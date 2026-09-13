# Adversarial PLAN review — ROUND 4 — psaab/xpf#9522

**Reviewed:** `docs/pr/9522/plan.md` v4 @ `eee0e25bcbf9d211ca2d82355392465004dd92b4`, branch `fix/9522-learned-route-cap` (worktree HEAD confirms), base `7ef226474`. Round-3 raws re-read; every load-bearing repo fact re-verified independently at this commit.

---

## Part 1 — Round-3 closure ledger: each R3 item closed IN MECHANISM?

### R3-1 (uidrange): **CLOSED.** `plan.md:137-140` retracts the v3 inertness sentence by name, rejects `RTA_UID` probing as version-fragile (the right call — silent-ignore on older kernels defeats a capability probe); `plan.md:242` moves uidrange into the §5d complex list; `plan.md:345` pins the cell. The residual factual note ("forwarded traffic carries no socket at reinject") is stated without being leaned on. No inertness claim survives anywhere in v4. ✓

### R3-2 (nft/NAT/netns named exclusions): **CLOSED.** `plan.md:212-217`: operator nft prerouting mark/TOS/DSCP mutation and kernel-side NAT on `xpf-usp0` excluded by name; per-snapshot-build `nft --json list` prerouting-mangle presence check with **non-empty OR parse-failure ⇒ `complex=true`** — fail-closed on the check itself, correctly. Netns exclusion backed by a claim I re-verified: **zero `setns`/netns-pinning hits in tree source** (only the plan's own mentions). ✓

### R3-3 (primary reader named): **CLOSED in letter.** `plan.md:238-241`: iproute2 `ip rule list` + `ip -6 rule list` PRIMARY (v6 enumeration explicit — Astra r3 §2 closed), raw `FRA_*` presence parse FALLBACK, choice made in-doc, `ip -Version` recorded. **But the guarantee sentence attached to it is unsound — finding R4-2 below.** ⚠

### R3-4 (WARN deliverables): **CLOSED.** `plan.md:277-280`: WARN on first complex-attestation per snapshot build; WARN on sustained capped-indeterminate delegation (>100/min, M3-confirmed); metrics-docs updates at the verified homes (`metrics_descriptors_binding.go:58-111`, `metrics_descriptors_global.go:93`). ✓

### Astra's six:
- **Fallback scoping:** CLOSED — `plan.md:188-191` scopes the default-action sentence to UNCAPPED indeterminate only; capped ⇒ delegation regardless of default action; the §9 cell pins both directions. The r3 §4 contradiction is gone. ✓
- **Withdrawal taxonomy:** CLOSED — `plan.md:222-229` (a)/(b)/(c) with the bound restated as *authorization freshness* ≤ TTL + reinject delay, (b) split same-zone/different-zone covering routes, G1 an explicit gate (`plan.md:56-61`) with rejection ⇒ kill. No smuggling. ✓
- **G2 as explicit parent gate:** CLOSED — `plan.md:62-65`, `plan.md:270-274`; v4 pre-picks neither E nor V and deletes the loser post-decision. ✓
- **Numeric thresholds + M4:** CLOSED — D = 5 ms with M2 PASS p99 ≤ 1 ms AND worst ≤ D; no-go = resolver-thread shape, never raise D (`plan.md:203-207`); R = 1000/s start sized by M3 with ≥2× headroom; M4 monotone-shrink acceptance (`plan.md:339-342`) is the correct invariant shape (the fix may only move packets OUT of unadjudicated delegation). G3 binds all four (`plan.md:66-68`). ✓
- **flowlabel/INNER via sysctls:** **PARTIALLY closed — finding R4-1 below.** The `fib_multipath_hash_fields` read + FLOWLABEL/INNER_* mask exclusion + cell (`plan.md:143-147`, `plan.md:251`, `plan.md:345`) is right, but the policy sysctl that gates whether that mask is even consulted is missing. ⚠
- **Netns + v6 + sysctls:** CLOSED — verified above. ✓

Repo facts spot-checked at this commit: `forwarding/fib.rs:431` linear scan ✓; `afxdp/mod.rs:445` `DEFAULT_SLOW_PATH_TUN` ✓; call site `poll_descriptor/mod.rs:5227-5231` (function `forwarding/mod.rs:184`) — plan's `5236+` is line-drift only; `tests_fragment.rs:834` MAIN-resolution text ✓; `rule_dscp_kernel_7796_test.go:108-112` verbatim ✓; `protocol/tests.rs:2980-2988` #6853 pin ✓; `networkd.go:634-687` rpfilter per-device-0 + conf/all warn-never-mutate ✓; `neighbor_resolver.rs:71-83` bounds ✓; `types_system.go:1025-1042` PBR 31000–31999 / next-table base 100 ✓; `rules.go:113` post-#9420 iif-scoped leak shapes ✓.

---

## Part 2 — Remaining holes (both real; both minor-class; both in the same subsystem)

### R4-1 (REQUIRED) — `hash_policy` 2/3 is an unattested divergence input, and the "covered" claim is false as worded

**Grounding:** `plan.md:147-148` ("`hash_policy` L3-vs-L4 only selects among passed inputs (covered)"), `plan.md:251` (only `fib_multipath_hash_fields` in the sysctl read), `plan.md:345` (mask-only cell).

`fib_multipath_hash_policy` values 2 and 3 hash the **inner header of encapsulated packets** (outer fallback only when not encapsulated; 256 = custom fields, which the plan's mask read correctly gates). The kernel consults `fib_multipath_hash_fields` **only at policy == 256** — at policy 2/3 the mask is ignored, so "mask ⊆ covered set" attests nothing on such a box. Structurally: the RTM_GETROUTE ECMP member selection is flowi-based (no skb ⇒ no inner dissection ⇒ outer-only hash, always), while the reinjected frame is a real skb — an encapsulated forwarded transit packet (IP-in-IP/GRE/VXLAN whose **outer** dst resolves to an ECMP route) hashes inner at reinject under policy 2/3. Member selection, hence egress ifindex, hence zone, diverges query…

**Required fix (doc-level, exclusion-tightening only):** add `fib_multipath_hash_policy` (v4+v6) to the §5d attestation read; admit only values {0, 1} (256 already gated via the fields read); 2/3 ⇒ `complex=true`; correct the §5a parenthetical; add the policy-2/3 encapsulated-transit cell to §9's hash-parity family. Unreadable ⇒ complex, same as the fields read.

### R4-2 (REQUIRED) — the §5d parse-fail-closed guarantee is mis-attributed: the shape-match does NOT bound reader-omission

**Grounding:** `plan.md:247-250` ("unknown future attributes fail closed through the shape-match, not through reader completeness — this is what bounds the 'independent reader omits attributes' residual").

Fail-closed fires on **unparseable** lines. An attribute iproute2 silently omits makes the line *more* canonical-looking, not less — this is historically real (pre-6.x iproute2 printed sport/dport-range rules as bare `from … lookup T` lines). A rule carrying an out-of-list **invisible** selector that reads a field the query cannot set (uid, v6 flowlabel, inner-on-encap) whose remaining printed text classifies in-list — e.g. colliding with the next-table shape at band [100, +window) (`rules.go:34-44`, `types_system.go:1040`) or a rib-group leak shape (`rules.go:574+`) — passes the shape-match with `complex=false`, and the §5d list entries for exactly those selectors (`plan.md:242-244`) never fire because the reader never prints them. Reachability …

**Required fix:** run the raw `FRA_*` attribute-presence TLV walk on **every** build (same netlink dump; any attribute type number outside the handled set ⇒ `complex=true`), demoting the iproute2 readback to the human-verifiable cross-check — the TLV walk sees every *present* attribute including unknown-to-reader ones, which is what actually bounds the residual; the shape-match alone does not. (Deliberately NOT exact-set comparison against rules.go's emitted set — that would over-trigger complex on legitimate foreign simple rules whose selectors are all in-list and query-settable, which the kernel mirrors exactly on both sides; per-rule TLV classification is the right shape.) Alternatively, re-attribute the bound honestly to exclusion (c) — but th…

---

## Part 3 — The named probes

- **parse-fail-closed sufficiency vs reader-blindness:** sufficient for the #7796 class (attributes the installed iproute2 prints — FRA_DSCP included at 7.1.0); NOT sufficient for post-reader attributes — see R4-2. The version-floor record is debug output, not enforcement, and the plan says so; correct, but then the guarantee must come from the TLV walk, not the shape-match.
- **nft-check cost per build:** per-snapshot-build exec + JSON parse, commit-driven, never per-packet — bounded and acceptable; absence/parse-failure fails closed (`plan.md:214-215`) ✓. One NOTE-class sentence worth adding: `nft --json list` cannot see **iptables-legacy** prerouting mutations — harmless under exclusion-by-name, but say it, since the check is advertised as "the signal."
- **use_neigh:** "same-state both sides modulo §5c TOCTOU" (`plan.md:148-149`) is stated and G1-bounded; the §9 query-vs-observed-reinject ECMP cell empirically pins it. NOTE-class: give that cell a dead-member variant so a persistent GETROUTE-ignores-liveness divergence (if one exists) has a detector.
- **Thresholds:** right. D = 5 ms / p99 ≤ 1 ms / worst ≤ D against a slow path that already tolerates 1 s/3 s coalescing is conservative; R = 1000/s with ≥2× headroom and overflow-to-fallback is safe; >100/min WARN is an operator-actionable signal; M4's monotone-shrink is the correct acceptance invariant; "never raise D" is the right no-go discipline. No change required.

---

## Verdict

Every round-3 item is closed in mechanism except the two tight spots above, and both live in the same subsystem (multipath-hash attestation completeness; reader-completeness attribution). Each is fixable with a doc edit + one sysctl read + one cell; neither changes architecture, and both tighten exclusions toward complex/indeterminate — they cannot create a new unsafe state. But I cannot return PLAN-READY while `plan.md:147` claims "covered" for an input the enumerated mechanism does not read, and `plan.md:247-250` asserts a guarantee the shape-match does not deliver — under the plan's own no-middle-ground rule, endorsing either sentence as-is would be the exact "stated not assumed" failure round 3 rejected.

**Verdict: NEEDS-MINOR** — R4-1 and R4-2 required; NOTES (iptables-legacy sentence, dead-member cell variant, `poll_descriptor` line-drift) optional. Fix scope is two paragraphs in §5a/§5d plus two §9 cells; no round-5 architecture questions remain.
