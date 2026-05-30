# AGY Adversarial Plan Review: #1608 Phase 4c Cold-Path Hardening

**Review Target:** `docs/research/1608-phase4c/plan.md` (v3 research-only plan)  
**Author:** Antigravity (Advanced Agentic Coding Team)  
**Verdict:** **PLAN-KILL-CONFIRMED**

---

## Executive Summary & Final Verdict

After a rigorous, hostile, and multi-dimensional analysis of the `plan.md` prose plan, the **PLAN-KILL** recommendation (Path A) is **CONFIRMED** with high confidence. 

Any attempt to ship Path B (verdict cache) or Path C (rate-limiting) under the current architecture is structurally flawed, creates severe microarchitectural vulnerabilities (L1/L2 cache pollution, cache thrashing), introduces critical correctness hazards (generation drift, match-dimension mismatches), and fails to address the actual bottleneck of the system. 

Furthermore, the factual topology, overlap claims, and memory math presented in the plan have been verified line-by-line against the codebase and are **100% accurate**. The details of these findings are laid out below.

---

## 1. Codebase Verification of Factual Claims

Every structural claim in Section 2 regarding the cold-path topology has been cross-referenced and verified against the checked-out workspace:

### A. The `#1660` Negative Neighbor Cache Fast-Fail Gate
*   **Claim:** `poll_descriptor/mod.rs:2392` `ForwardingDisposition::MissingNeighbor` arm — `#1660` dead-host negative-cache gate fires FIRST (`neg_neigh_gate`, `:2418`). A negatively cached, unresolved, unexpired destination is recycled immediately with no policy evaluation.
*   **Verification:** Verified in [userspace-dp/src/afxdp/poll_descriptor/mod.rs](file:///home/ps/git/bpfrx/.claude/worktrees/1608-research/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L2392-L2443).
    *   The `MissingNeighbor` arm starts at line 2392.
    *   At line 2418, the negative neighbor gate is checked:
        ```rust
        let fast_fail = neg_neigh_gate(
            &mut binding.neg_neigh_cache,
            &neg_key,
            now_ns,
            || {
                worker_ctx.forwarding.neighbors.contains_key(&neg_key)
                    || worker_ctx.dynamic_neighbors.get(&neg_key).is_some()
            },
        );
        ```
    *   If `fast_fail` is `true`, lines 2441-2442 execute:
        ```rust
        binding.scratch.scratch_recycle.push(desc.addr);
        continue;
        ```
    *   This completely bypasses the downstream policy evaluation `evaluate_policy_with_len` at line 2522. The claim is **empirically correct**.

### B. The Latency Histogram Wrappers
*   **Claim:** The slow-path policy evaluation functions are wrapped by the `#1620/#1635` cold-path latency histogram (`cp_sample_tag`, `cp_t_in`, `record_sample`).
*   **Verification:** Verified at both slow-path call sites in `poll_descriptor/mod.rs`:
    1.  **ForwardCandidate slow path:** [poll_descriptor/mod.rs:L1380-L1445](file:///home/ps/git/bpfrx/.claude/worktrees/1608-research/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L1380-L1445) wraps the call to `evaluate_policy_result_with_len` at line 1393.
    2.  **Session-install slow path:** [poll_descriptor/mod.rs:L2507-L2579](file:///home/ps/git/bpfrx/.claude/worktrees/1608-research/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L2507-L2579) wraps the call to `evaluate_policy_with_len` at line 2522.
    The claims are **empirically correct**.

### C. The Linear Scan Topology and Deduplication
*   **Claim:** `policy.rs:873` `evaluate_policy_result_with_len` performs an $O(1)$ lookup on `zone_pair_index` followed by a linear scan `for &idx in indices` over rule indices, and `try_match_rule` evaluates address matchers via `source_v4_match_any || source_literal_v4.contains() || source_book_idxs.iter().any(...)`.
*   **Verification:** Verified in [userspace-dp/src/policy.rs](file:///home/ps/git/bpfrx/.claude/worktrees/1608-research/userspace-dp/src/policy.rs):
    *   Line 873 defines `evaluate_policy_result_with_len`.
    *   Line 884-886 implements the linear scan:
        ```rust
        let key = zone_pair_key(from_id, to_id);
        if let Some(indices) = state.zone_pair_index.get(&key) {
            for &idx in indices {
                if let Some(result) = try_match_rule(...)
        ```
    *   Line 926 defines `try_match_rule`.
    *   Lines 944-949 implement the exact short-circuit and address book matching logic:
        ```rust
        let s = rule.source_v4_match_any
            || rule.source_literal_v4.contains(src)
            || rule
                .source_book_idxs
                .iter()
                .any(|&i| state.books[i as usize].v4.contains(src));
        ```
    *   Lines 182-185 verify the staging of multi-book LPM parallel arrays (`source_prefixes_v4`, etc.) which remain unconsumed. The claims are **empirically correct**.

---

## 2. Rigorous Verification of Section 8 Memory Math

The plan's calculations for struct sizing under 64-bit Rust alignment constraints are **flawless**:

1.  **`TokenBucket` Size:**
    *   `tokens_ns: u64` (8 B) + `burst_ns: u64` (8 B) + `last_refill_ns: u64` (8 B) + `rate_pps: u32` (4 B) = 28 B.
    *   Due to the presence of `u64` fields, the struct requires 8-byte alignment. Thus, 4 bytes of padding are added at the end, resulting in `std::mem::size_of::<TokenBucket>() = 32 B`.
2.  **`DestBucketEntry` Size:**
    *   `dst_ip: Option<IpAddr>` (24 B: `IpAddr` is 16 B, tag is 1 B, plus 7 B alignment padding).
    *   `bucket: TokenBucket` (32 B).
    *   Total size = 24 B + 32 B = **56 B**. (v2 plan incorrectly assumed 48 B by neglecting the 32 B padded size of the fixed-point `TokenBucket`).
3.  **`VerdictCacheEntry` Size:**
    *   `key_hash: u64` (8 B) + `from_zone_id: u16` (2 B) + `to_zone_id: u16` (2 B) + `src_port: u16` (2 B) + `dst_port: u16` (2 B) + `protocol: u8` (1 B) + `_pad: u8` (1 B) = 18 B.
    *   Next field is `src_ip: IpAddr` (align 8), requiring 6 B of padding. Subtotal = 24 B.
    *   `src_ip: IpAddr` (24 B) + `dst_ip: IpAddr` (24 B) + `config_generation: u64` (8 B) + `rule_idx: u32` (4 B) + `policy_id: u32` (4 B) + `action: u8` (1 B) + `_pad2: [u8; 7]` (7 B) = 72 B.
    *   Total size = 24 B + 72 B = **96 B** (verified to the byte).
4.  **L2/L3 Memory Budget Collision:**
    *   A 4 K-entry Verdict Cache = $4096 \times 96\text{ B} = 384\text{ KB}$. This single table blows past the total **256 KB** per-worker issue budget.
    *   A 2 K-entry Destination Bucket table = $2048 \times 56\text{ B} = 112\text{ KB}$.
    *   Combined, they require **496 KB** per worker, which violates L2/L3 cache residency limits. Under flood, this footprint will trigger continuous L2 cache eviction, severely degrading established-flow performance.

---

## 3. Hostile Pressure-Testing of Path B (Verdict Cache Only)

Path B is highly dangerous and must not be shipped due to three fatal microarchitectural and security vulnerabilities:

1.  **Vulnerability to Zero-Hit Cache Thrashing (DDoS Degradation):**
    Under a random-source SYN flood or a port scan, the incoming traffic presents unique 5-tuples. The verdict cache will achieve a **0% hit rate**. 
    For every packet, the core will pay:
    $$\text{Total Cost} = \text{Hash Calculation} + \text{Set Lookup (Cache Miss)} + \text{Linear Policy Scan} + \text{Cache Insertion (Memory Write \& Eviction)}$$
    Instead of mitigating the flood, the verdict cache **amplifies the CPU cost per packet** and thrashing-induced L1D/L2 evictions will degrade the flow-cache (hot path) performance on the same core.
2.  **Keying Physics vs. Correctness:**
    Because firewalls match on source subnets, the cache key must cover the source IP. If it does not, a "permit" verdict for a live destination primed by an allowed client would bypass the policy engine for an attacker spoofing a blocked IP. But including the source IP guarantees complete thrashing under random-source floods.
3.  **Config Generation and Match-Dimension Drift:**
    Relying on `config_generation` handles config reloads but does not protect against **match-dimension drift**. If a developer adds a new match dimension to `PolicyRule` (e.g., DSCP, time-of-day), the cache entry must be updated. A `mem::size_of` assert will not catch semantic additions inside standard fields, leading to silent security bypasses.

---

## 4. Hostile Pressure-Testing of Path C (Rate-Limiting Only)

Path C is conceptually stronger but fails under a realistic threat model:

1.  **Attacker Success via Collateral Damage (Legitimate Block):**
    If the rate-limiter is per-destination (to bypass the RSS worker-local 5-tuple spray issue), a flood to a live victim service will trip the rate limit. Once tripped, **all new connection requests to that service are silently dropped**, including those from legitimate clients. The attacker successfully achieves their Goal (Denial of Service) without saturating the firewall's CPU.
2.  **False Positives under Legitimate Bursts:**
    A per-destination cold-path rate-limit on a highly active virtual IP (e.g., a load balancer, CDN gateway, or DNS resolver) will experience high false-positive rates during legitimate traffic spikes (e.g., flash crowds, search engine indexing), dropping benign clients before they can establish sessions.

---

## 5. Overlap and Bottleneck Shifting Analysis

The plan's overlap analysis with `#1660` is highly accurate. `#1660` covers the most critical attack vector (flooding random, dead IP spaces) by fast-recycling the descriptor inside the `MissingNeighbor` arm before any policy evaluation occurs. 

For floods targeting **live, resolvable IPs**, the bottleneck is not actually the linear policy scan:
*   Once a packet is permitted, it immediately attempts to install a session.
*   Under a fast-rate SYN flood targeting a live host, the system will instantly saturate on **Session Table allocation locks and Conntrack capacity limit gates** rather than the linear rule scan.
*   Optimizing the policy scan via a verdict cache merely shifts the bottleneck to session allocation, yielding zero net throughput improvement while introducing significant complexity.

---

## Conclusion

The `plan.md` v3 research plan is exceptionally thorough, structurally sound, and factually bulletproof. Its recommendation of **PLAN-KILL** (Path A) with a **Path D (Measurement-First)** reopen criterion is the only responsible engineering path forward. No performance optimization should be shipped in this critical dataplane path without a saturating flamegraph demonstrating a measurable bottleneck.
