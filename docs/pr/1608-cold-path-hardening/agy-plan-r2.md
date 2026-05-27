# AGY plan-review r2 — #1608 v2

**Verdict:** **PLAN-KILL**

This adversarial review challenges the technical validity of the **v2** plan for issue #1608 "Phase 4c cold-path hardening." While the plan makes structural progress over the v1 attempt, it contains several critical structural loopholes, math errors, and new self-inflicted vulnerabilities that render the implementation dead-on-arrival.

Specifically, the plan contains **two new structural fatals** (including a severe event-logging DoS and a complete rate-limit bypass under thrashing), **two major compilation bugs** in its size proofs, and a **major cache-bypass loophole** under default-deny floods.

---

## Kill-axis verification (v1 → v2)

### Axis 1 — per-source-IP RSS spray defeat
*   **Verdict:** **PLAN-NEEDS-MAJOR** (Looped back to a new Fatal variant)
*   **Quoted Evidence (plan.md:58):**
    > `v2 fix: switch to per-DESTINATION-IP keying.`
    > `Too big. Use 512 sets × 4 ways = 2048 entries.` (plan.md:348)
*   **Analysis:** 
    Switching the rate-limiter primitive from per-source-IP to per-destination-IP is theoretically correct for defending targeted victim services under Symmetric RSS sprays. However, the concrete set-associative cache implementation (512 sets × 4 ways = 2048 entries) introduces a new fatal defect.
    
    Under a high-entropy DDoS flood (e.g. an attacker scanning or spraying $10^5$ distinct destinations or random IPs), the cache will undergo a severe **eviction storm (thrashing)**. When a packet lookup misses in the `DestBucket` table, the LRU way in the matching set is evicted, and a new `DestBucketEntry` is initialized with a brand-new `TokenBucket`.
    
    Crucially, the plan initializes new buckets with a non-zero allowed burst:
    > `Initial: tokens_ns = burst_ns = 1_000_000_000_000` (plan.md:302)
    
    Because every packet in a high-entropy flood hashes to a set, misses, evicts a bucket, and initializes a new bucket with `burst_ns` tokens, **every single packet will be allowed** because the newly created bucket always starts fully loaded! The rate limiter is completely bypassed under a thrashing attack.
    
    Even if initialized with a single token, as long as it is non-zero, an eviction storm allows the attacker to push wire-rate traffic because every packet is treated as the "first packet of a new bucket." The only defense left is the aggregate cap, which if tripped, drops *all* cold-path traffic, meaning the attacker successfully DoSes all legitimate services on the firewall anyway.

### Axis 2 — verdict cache wrong-verdict
*   **Verdict:** **PLAN-NEEDS-MAJOR** (Contains a major bypass loophole and ineffective safety assert)
*   **Quoted Evidence (plan.md:111):**
    > `v2 fix: key covers every try_match_rule input.`
    > `assert!(std::mem::size_of::<PolicyRule>() <= EXPECTED_POLICY_RULE_SIZE);` (plan.md:158)
*   **Analysis:**
    The key layout `(from_zone_id, to_zone_id, src_ip, dst_ip, proto, src_port, dport)` successfully covers all active input dimensions inside the current policy matcher (`policy.rs:467 try_match_rule`).
    
    However, the plan introduces a major structural gap by explicitly excluding default-action (`policy_id == 0`) results:
    > `// Insert only on Permit/Deny by rule (skip default_action with id=0` (plan.md:237-238)
    > `Without that skip, a flood matching the default-deny gets cached, then a config change adding a permit-rule for that flow doesn't take effect until eviction.` (plan.md:557-560)
    
    Under a standard random cold-path flood, the vast majority of attack traffic does not match any configured permit rules and evaluates to default-deny (`policy_id == 0`). By skipping cache insertions for `policy_id == 0`, **the verdict cache will experience a 0% hit rate under a default-deny flood**. Every single attack packet will force a full linear scan of the entire policy rule vector.
    
    Furthermore, the plan's justification for the skip is false: any configuration commit bumps `config_generation`, which instantly invalidates all existing cache entries anyway. Caching `policy_id == 0` is completely safe and absolutely mandatory to survive default-deny floods.
    
    Additionally, the compile-time safety check is brittle:
    `mem::size_of::<PolicyRule>()` includes heap-allocated types (`PrefixSetV4`, `PrefixSetV6`, `CompiledApplications`). These structs contain heap pointers (like `Vec` and `FxHashMap`) whose stack sizes are fixed regardless of the fields inside them. If a future PR adds a new match dimension inside `CompiledApplications` (e.g. DSCP or TCP flags), `size_of::<PolicyRule>` will remain unchanged, allowing a silent CACHE-KEY INVARIANT breach.

### Axis 3 — wrong insertion point
*   **Verdict:** **PLAN-KILL** (Triggers a catastrophic logging/event DoS)
*   **Quoted Evidence (plan.md:212):**
    > `if let Some(deny) = cold_gate.check_rate(dst_ip, counters) { return deny; }`
*   **Analysis:**
    Placing the helper `evaluate_policy_with_verdict_cache` to wrap the two actual policy-eval sites at `poll_descriptor/mod.rs:1375` (ForwardCandidate slow path) and `poll_descriptor/mod.rs:2393` (session-install slow path) is structurally correct.
    
    However, the implementation details introduce a catastrophic **logging and event stream exhaustion vulnerability**.
    
    When a packet is rate-limited, `cold_gate.check_rate` returns a standard `PolicyEvaluationResult` with action `Deny`. In `poll_descriptor/mod.rs`, receiving a non-`Permit` result from `evaluate_policy_result_with_len` falls through to the standard policy deny path at line 1810:
    ```rust
    } else {
        emit_policy_deny_event(
            worker_ctx.event_stream,
            flow,
            meta,
            from_zone_id,
            to_zone_id,
            owner_rg_id,
            policy_result.policy_id,
            policy_result.action,
            now_ns,
        );
        telemetry.dbg.policy_deny += 1;
        ...
    }
    ```
    Under a 1 Mpps flood, every rate-limited packet will trigger `emit_policy_deny_event`, pushing 1 million formatted events per second into the userspace event stream. This will instantly blow up the event queue buffer, exhaust memory, saturate the logger, and crash the userspace dataplane.
    
    A defensive rate-limiter must drop packets silently and instantly, only incrementing a lockless counter, and must never hit slow-path logging/event pipelines. Wrapping the rate-limiter inside the policy evaluator and returning a standard policy `Deny` makes this design structurally self-defeating.

### Axis 4 — token-bucket arithmetic
*   **Verdict:** **PLAN-READY**
*   **Quoted Evidence (plan.md:270):**
    > `tokens_ns: u64`
    > `let add = (elapsed as u128).saturating_mul(self.rate_pps as u128);` (plan.md:283)
*   **Analysis:**
    The fixed-point representation (where 1 token = $10^9$ token-ns of nanoseconds budget) is mathematically robust. The traces for 50µs, 10s, and 100s windows are correct. Because multiplication is used instead of integer division on the elapsed time, sub-token quanta are preserved without quantization loss. Applying the credit and updating `last_refill_ns = now_ns` is safely ordered. No division operations are executed on the hot path, making this extremely fast on x86_64.

### Axis 5 — storage budget
*   **Verdict:** **PLAN-KILL** (Contains two major compilation-failing math errors)
*   **Quoted Evidence (plan.md:345 & 389):**
    > `const _: () = assert!(std::mem::size_of::<DestBucketEntry>() == 48);`
    > `const _: () = assert!(std::mem::size_of::<VerdictCacheEntry>() == 88);`
*   **Analysis:**
    The plan claims to have verified the sizes and alignment of the data structures, but both of its compile-time size assertions will **FAIL to compile** due to incorrect size math and ignored alignment padding:
    
    1.  **`DestBucketEntry` Size math:**
        `TokenBucket` contains `tokens_ns: u64` (8), `burst_ns: u64` (8), `last_refill_ns: u64` (8), and `rate_pps: u32` (4). Total payload is 28 bytes. Due to 8-byte alignment required by the `u64` fields, the compiler pads `TokenBucket` to exactly **32 bytes** (not the 24 bytes claimed).
        `dst_ip: Option<IpAddr>` size is **24 bytes** on x86_64.
        Thus, `DestBucketEntry` size is $24 + 32 = \mathbf{56\text{ bytes}}$, not 48 bytes.
        The compile assert `size_of::<DestBucketEntry>() == 48` will fail.
    
    2.  **`VerdictCacheEntry` Size math:**
        Let's perform the exact offset layout check:
        *   `key_hash` (u64): 8 B (Offset 0)
        *   `from_zone_id` (u16) + `to_zone_id` (u16) + `src_port` (u16) + `dst_port` (u16) + `protocol` (u8) + `_pad` (u8): 10 B (Offsets 8 to 17). Total block is 18 B.
        *   `src_ip: IpAddr` has 8-byte alignment, so the compiler must insert **6 bytes of padding** after the `_pad` field.
        *   `src_ip` (IpAddr) starts at Offset 24, size 24 B (Offsets 24 to 47).
        *   `dst_ip` (IpAddr) starts at Offset 48, size 24 B (Offsets 48 to 71).
        *   `config_generation` (u64): 8 B (Offsets 72 to 79).
        *   `rule_idx` (u32): 4 B (Offsets 80 to 83).
        *   `policy_id` (u32): 4 B (Offsets 84 to 87).
        *   `action` (u8): 1 B (Offset 88).
        *   To align the 8-byte aligned struct, trailing padding of **7 bytes** is inserted after `action`, bringing the struct size to exactly $\mathbf{96\text{ bytes}}$ (not the 88 bytes claimed).
        The compile assert `size_of::<VerdictCacheEntry>() == 88` will fail.

### Axis 6 — acceptance gate
*   **Verdict:** **PLAN-READY**
*   **Quoted Evidence (plan.md:413):**
    > `defer empirical CPU% gate to follow-up; ship mechanism with local microbench proving O(1) behavior.`
*   **Analysis:**
    Honestly framing the acceptance criteria by removing the driver-level performance metric from this PR (deferring it to follow-up #1607-v2) is appropriate. Requiring isolated O(1) benchmarks for both the cache hit ($\le 30\text{ ns}$) and the bucket refill ($\le 15\text{ ns}$) provides proper unit-level validation without misleading system-level claims.

---

## New v2-introduced concerns

### F1: Table Thrashing bypasses Rate Limiting
*   **Severity:** **FATAL**
*   **Quoted Evidence (plan.md:348-352):**
    `const DEST_TABLE_SETS: usize = 512;`
    `const DEST_TABLE_WAYS: usize = 4;`
    `Initial: tokens_ns = burst_ns = 1_000_000_000_000` (plan.md:302)
*   **Critique:**
    Under a high-entropy address spray or horizontal destination scan, the set-associative table undergoes massive LRU evictions. Since a cache miss instantiates a new bucket with `burst_ns` tokens, every thrashed packet receives a full token credit and is allowed. The rate-limiter is completely bypassed under multi-destination floods.

### F2: Event Log Exhaustion DoS under Rate Limiting
*   **Severity:** **FATAL**
*   **Quoted Evidence (plan.md:212):**
    `if let Some(deny) = cold_gate.check_rate(dst_ip, counters) { return deny; }`
*   **Critique:**
    Injecting the rate limit drop *inside* the policy evaluation and returning a standard `PolicyAction::Deny` result triggers the standard policy drop event-stream pipeline (`emit_policy_deny_event`). This causes control-plane and logging-queue DoS under a 1 Mpps flood.

### F3: Hardcoded size assertions break the build
*   **Severity:** **MAJOR**
*   **Quoted Evidence (plan.md:345 & 389):**
    `const _: () = assert!(std::mem::size_of::<DestBucketEntry>() == 48);`
    `const _: () = assert!(std::mem::size_of::<VerdictCacheEntry>() == 88);`
*   **Critique:**
    The actual structural footprints are 56 bytes and 96 bytes. Hardcoding 48 and 88 inside the assertions will prevent compilation of the Rust dataplane.

### F4: Cache bypass on default-deny floods
*   **Severity:** **MAJOR**
*   **Quoted Evidence (plan.md:237-238):**
    `// Insert only on Permit/Deny by rule (skip default_action with id=0`
*   **Critique:**
    Excluding default-deny (`policy_id == 0`) results from the verdict cache means that a flood of random non-matching traffic hits the linear scan on every single packet, bypassing the protection of the cache. The justification for skipping is invalid because `config_generation` updates handle cache consistency safely.

### F5: Safety assert does not catch semantic changes
*   **Severity:** **MINOR**
*   **Quoted Evidence (plan.md:158):**
    `assert!(std::mem::size_of::<PolicyRule>() <= EXPECTED_POLICY_RULE_SIZE);`
*   **Critique:**
    `PolicyRule` contains heap-allocated structures. Adding new match terms inside these structures or changing their internal layouts will not change the stack footprint of `PolicyRule`, meaning the compile-time assert will not trip on future semantic match field additions.

---

## Verdict and recommendation

**Final Verdict:** **PLAN-KILL**

The v2 plan contains fatal architectural flaws, math errors that break compilation, and vulnerabilities that expose the firewall to severe event-logging DoS and rate-limiting bypass under attack. The plan must be rejected and rewritten before execution.

### Requirements for the next plan revision:
1.  **Decouple Rate Limiting from Policy Deny (Resolve F2/Axis 3):**
    Evaluate the cold-path rate-limiter *outside* the policy engine. If a packet is dropped, do NOT return a policy `Deny` that falls through to `emit_policy_deny_event`. Drop the packet silently, increment the batch counters, and recycle the descriptor instantly.
2.  **Mitigate Table Thrashing (Resolve F1/Axis 1):**
    Prevent the rate-limiter bypass under eviction storms. When a new `DestBucketEntry` is initialized on a cache miss, it must NOT start with a full `burst_ns` tokens if the table is thrashing. Alternatively, initialize new entries with a small single-packet credit or use a hash-ring that doesn't refresh tokens on eviction.
3.  **Fix Struct Size Mathematics (Resolve F3/Axis 5):**
    Update the size math and assertions to reflect the true padded footprints:
    *   `DestBucketEntry` = **56 bytes** (96 KB $\rightarrow$ 112 KB footprint for 2048 entries).
    *   `VerdictCacheEntry` = **96 bytes** (88 KB $\rightarrow$ 96 KB footprint for 1024 entries).
    *   Combined footprint = **208 KB**, which is still safely within the 256 KB L2 cache budget.
4.  **Cache Default-Deny Actions (Resolve F4/Axis 2):**
    Allow cache insertions for `policy_id == 0` results so that default-deny floods benefit from verdict cache acceleration. Rely on `config_generation` bumps during commits to safely invalidate default-deny cache entries.
5.  **Strengthen Invariant Documentation (Resolve F5/Axis 2):**
    Acknowledge that `mem::size_of` does not catch nested heap-allocated field additions. Complement the assert with a clear warning comment instructing developers to update the cache key if any new match dimension is introduced to the policy matcher.
