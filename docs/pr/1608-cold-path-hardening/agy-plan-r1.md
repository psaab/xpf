# Hostile Plan Review: Phase 4c Cold-Path Hardening (Issue #1608)

**Reviewer Hat:** Hostile HPC-Networking + DDoS-Mechanism + AF_XDP Dataplane Cache-Design Expert.

---

## 1. Executive Summary

This plan proposes two mechanisms—a per-source ingress rate-limiter (4c.1) and a verdict micro-cache (4c.2)—as defensive layers in front of the linear policy-scan backend. While the intent is sound, the concrete design suffers from fatal structural flaws, math errors, and physics violations that render the implementation ready to fail by construction.

**Verdict:** **PLAN-KILL**

To proceed, this plan requires a complete, non-trivial rewrite (see Section 4 for the explicit recovery path). 

---

## 2. Severity-Labeled Findings

### F1 (FATAL): Core-Symmetric RSS Bypass & CLI Knob Semantic Breakdown
*   **Plan References:** §2 (lines 129–208), §8 (lines 406–413), §9 R2 (lines 433–442)
*   **Critique:** 
    The plan relies on a per-worker (per-queue) local token-bucket table to implement what is advertised to the operator in the Junos CLI as a global "per-source IP" rate limit. In a realistic DDoS scenario, an attacker launches a multi-source or single-source SYN flood using random source ports to sweep the entropy space. Modern NIC hardware distributes this flood across $N$ RX queues (and thus $N$ independent AF_XDP worker threads) using Symmetric RSS hashing over the standard 5-tuple.
    
    Because the hashing sprays the same source's traffic across all workers:
    1. Each worker’s local bucket sees only $\approx 1/N$ of the source's actual traffic rate.
    2. An attacker sending a flood of $R$ pps from a single source IP has their traffic split such that each worker sees only $R/N$ pps.
    3. If the operator configures a rate limit of $L$ pps via the CLI, the attacker can effectively push up to $N \times L$ pps without triggering any local rate limiters, bypassing the filter entirely.
    4. If the attacker pushes a 100,000 pps flood from a source IP on a machine with $N = 8$ workers, and the configured threshold is 20,000 pps, each worker receives only 12,500 pps. Since 12,500 pps is below the 20,000 pps local limit, **zero packets are dropped**, and the cold path is fully saturated.

    Meeting the stated acceptance criterion of *"≥50% CPU% drop under 1 Mpps flood from 10 source IPs"* is structurally impossible under realistic RSS load because the per-worker token buckets will either leak the entire flood or require an operator to guess the core count and manually scale the CLI knobs. Global state consistency on zero-copy AF_XDP is a hard physics boundary; attempting to enforce "per-source" semantics with local state is a fundamental architectural lie.

---

### F2 (FATAL): Key-Invariant Violations and Wrong-Verdict Escapes
*   **Plan References:** §3.1 (lines 211–230), §9 R3 (lines 443–449)
*   **File Reference:** `userspace-dp/src/protocol/security.rs:62-90`
*   **Critique:**
    The proposed 4-tuple key `(src_ip, dst_ip, src_port, dst_port)` for the verdict micro-cache is dangerously incomplete. The plan hand-waves the security boundaries by stating it will *"reuse the has_dscp_match gate"* (line 446). 
    
    The codebase already documents the strict **CACHE-KEY INVARIANT (#1431)** at `userspace-dp/src/protocol/security.rs:62-90` which explicitly states:
    > "Skipping this classification SILENTLY breaks flow-cache: a first-packet decision gets reused for later packets that can differ on the new field."

    By caching a permit/deny decision based on only a 4-tuple, you completely bypass the policy linear scan for packets that differ in crucial match dimensions that are not in your key:
    *   **DSCP matches / DSCP Rewrites:** Policies can and do match on DSCP value.
    *   **Forwarding-Class & Routing-Instance:** Verdicts change based on these parameters.
    *   **IP Frag-Flags and TCP Flag Bits:** Crucial for deep packet filtering and SYN-flood screening.
    
    If any policy rule includes any match criterion outside the 4-tuple (e.g., DSCP or TCP flags), a "permit" verdict cached from a packet that satisfied the condition will be applied to a subsequent packet that does *not* satisfy the condition, bypassing the firewall entirely. The plan does not cite the `security.rs` invariant, nor does it define a comprehensive gate-off matrix for the 15+ other per-packet match dimensions.

---

### F3 (FATAL): High-Frequency Truncation and Infinite DoS under Fast Polling
*   **Plan References:** §2.2 (lines 162–183)
*   **Critique:**
    The proposed token bucket refill arithmetic is:
    ```rust
    elapsed_ns = now_ns - bucket.last_refill_ns
    refill_tokens = elapsed_ns * rate_pps / 1_000_000_000
    bucket.tokens = min(burst, bucket.tokens + refill_tokens)
    bucket.last_refill_ns = now_ns
    ```
    This naive integer division has a fatal truncation bug. If the worker spins fast—which a polling-based AF_XDP worker does when idle or under moderate load—the polling tick interval `elapsed_ns` is very small (e.g., 50 microseconds / 50,000 ns).
    
    If the operator configures a rate limit of `rate_pps = 1000`:
    $$\text{refill\_tokens} = \frac{50,000 \times 1,000}{1,000,000,000} = \frac{50,000,000}{1,000,000,000} = 0$$
    
    Every single high-frequency tick will compute exactly `0` refill tokens. Because the plan unconditionally updates `bucket.last_refill_ns = now_ns` on every lookup, the elapsed time is reset to 0, and the fractional tokens that should have accumulated are permanently discarded. Under fast polling, **the bucket will never refill a single token**, causing a permanent Denial of Service (DoS) for legitimate traffic as soon as the initial burst is consumed.

---

### F4 (MAJOR): Memory Budget Overflow and L2 Cache Saturation
*   **Plan References:** §2.1 (lines 131–160), §3.2 (lines 227–242)
*   **Critique:**
    The plan relies on a combined storage budget of 256 KB per worker to fit inside L2 cache. However, the plan's layout calculations are mathematically incorrect and ignore compiler alignment padding.
    
    A native Rust size-check verification on `x86_64` yields the following exact footprints:
    1.  `IpAddr` has a size of 17 bytes and alignment of 1.
    2.  `Option<IpAddr>` has a size of 17 bytes and alignment of 1.
    3.  `TokenBucket` (`u32` tokens + `u64` last_refill_ns) has a size of 16 bytes and an alignment of 8.
    4.  `SourceBucketEntry` contains `Option<IpAddr>` and `TokenBucket`. Due to the 8-byte alignment of `TokenBucket`, 7 bytes of padding are inserted after `Option<IpAddr>`, making the struct size exactly **40 bytes** (not the 32 bytes claimed in the plan).
    5.  `VerdictCacheKey` (`IpAddr`, `IpAddr`, `u16`, `u16`, `u8`, `u16`) has a size of **42 bytes**.
    6.  `CachedVerdict` (`Verdict` [8 bytes] + `u64` config_generation [8 bytes]) has a size of 16 bytes and alignment of 8.
    7.  `VerdictCacheEntry` contains `VerdictCacheKey` and `CachedVerdict`. To align the 8-byte `CachedVerdict`, 6 bytes of padding are added after the key, making the final entry size exactly **64 bytes** (not the 56 bytes claimed).

    Calculating the true memory footprints for 4K-entry tables:
    *   **Source IP Table (4c.1):** $4096 \times 40\text{ B} = 163,840\text{ bytes} = 160\text{ KB}$ (Budget was 128 KB)
    *   **Verdict Cache (4c.2):** $4096 \times 64\text{ B} = 262,144\text{ bytes} = 256\text{ KB}$ (Budget was 112 KB)
    *   **Combined Footprint:** $160\text{ KB} + 256\text{ KB} = 416\text{ KB}$.

    A combined memory footprint of **416 KB** overflows the 256 KB L2 cache target by **160 KB (62.5% overflow)**. This will trigger massive L2 cache evictions and cache thrashing, completely destroying any performance gains in the very fast-path loop it is trying to protect.

---

### F5 (MAJOR): Dishonest Acceptance Measurement via Cargo-Bench
*   **Plan References:** §0 (lines 27–40), §8 (lines 412–417)
*   **Critique:**
    Proposing `cargo bench` as a substitute for real 1 Mpps driver-level testing is technically dishonest for the stated acceptance criteria. 
    1.  A single-threaded cargo bench driving a isolated descriptor stream cannot simulate hardware interrupts, RX ring buffer pressure, context transitions, or NIC memory bus saturation.
    2.  A synthetic benchmark cannot simulate the RSS distribution pattern across cores.
    3.  Asserting a "≥50% CPU% drop" inside a cargo benchmark is nonsensical; a cargo benchmark runs the CPU core at 100% load and measures iteration throughput, not system-level thread utilization.
    
    If the acceptance metrics are not bound to real driver load, the optimization is untested under realistic attack pressure.

---

### F6 (MINOR): Stale `now_ns` Cadence under Policy Saturation
*   **Plan References:** §2.2 (lines 162–173), §7 Q1 (lines 359–370)
*   **Critique:**
    Under a 1 Mpps cold-path flood that misses both the flow cache and the verdict cache, the worker becomes entirely policy-scan bound. Because the policy scan takes hundreds of cycles, processing a single poll batch of 64 descriptors can take several milliseconds. 
    
    If `now_ns` is only captured once at the beginning of the batch in `poll_descriptor/mod.rs`, the rate-limiter will evaluate all 64 packets in that batch with the exact same stale timestamp. If multiple packets from the same source arrive in the same batch, they will see 0 elapsed nanoseconds, causing premature drops even if the source is well within its limits over a slightly longer window.

---

## 3. Review Verdict

**Final Verdict:** **PLAN-KILL**

The plan is mathematically, structurally, and cache-architecturally unsound. It cannot be approved in its current state.

---

## 4. Recovery Path

To salvage this issue and convert the verdict to a ready state, the author must rewrite the plan to address the following:

1.  **Resolve F1 (RSS Spray):**
    *   Explicitly rename the CLI configuration and metrics to `cold-path-rate-limit-per-worker` to maintain semantic honesty.
    *   Clearly document in the operator-facing guide that the effective global rate limit for a distributed attack is $N \times \text{configured\_rate}$, where $N$ is the number of active AF_XDP workers.
2.  **Resolve F2 (Cache-Key Invariants):**
    *   Explicitly wire the verdict cache to the existing `#1431` cache-key invariant infrastructure.
    *   Introduce a blanket rule: the verdict cache is **completely disabled/bypassed** if the active policy zone contains rules matching on DSCP, TCP flags, routing instance, or any other match parameter outside the verdict key.
3.  **Resolve F3 (Refill Truncation):**
    *   Replace the naive integer division with a fixed-point token representation (e.g., scale tokens by $2^{16}$ or track sub-token remainders) or keep track of the unused nanoseconds remainder:
        ```rust
        let elapsed = now_ns - bucket.last_refill_ns;
        let tokens_to_add = (elapsed * rate_pps) / 1_000_000_000;
        if tokens_to_add > 0 {
            bucket.tokens = min(burst, bucket.tokens + tokens_to_add);
            // Only consume the nanoseconds that actually contributed to whole tokens
            bucket.last_refill_ns += (tokens_to_add * 1_000_000_000) / rate_pps;
        }
        ```
4.  **Resolve F4 (Cache Sizing):**
    *   Compact the verdict cache entry. Reduce the tables to **2K entries × 4 ways** or separate the IPv4 and IPv6 structures. 
    *   Provide correct mathematical proofs of structural sizes showing the padded struct layouts fitting strictly within the **256 KB L2 cache footprint**.
5.  **Resolve F5 (Measurement):**
    *   Explicitly gate the merging of #1608 on the completion of the #1607 driver-level synthetic flood harness, or rewrite the acceptance criteria to measure throughput speedups under microbenchmarks rather than system CPU percentage.

---
*AGY Adversarial Review Group*
