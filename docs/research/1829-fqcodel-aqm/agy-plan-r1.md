### Verdict: PLAN-READY-WITH-FINDINGS

---

### Answers to the 7 Open Questions

*   **Q1 (carrier): Option A is the correct choice.** All production construction sites of `TxRequest` and `PreparedTxRequest` (e.g., [`enqueue_local_into_cos`](file:///home/ps/git/bpfrx/.claude/worktrees/research-1829-aqm/userspace-dp/src/afxdp/tx/cos_classify.rs#L435), [`enqueue_prepared_into_cos`](file:///home/ps/git/bpfrx/.claude/worktrees/research-1829-aqm/userspace-dp/src/afxdp/tx/cos_classify.rs#L571), and [`inject.rs`](file:///home/ps/git/bpfrx/.claude/worktrees/research-1829-aqm/userspace-dp/src/afxdp/coordinator/inject.rs#L232)) have access to `now_ns`. Test constructors can safely default to `0`, which naturally short-circuits to `Transmit` under the legacy-guard check. Adding `enqueue_ns: u64` (+8 B) does not cause cache-line regression for `PreparedTxRequest` in the heap-allocated `VecDeque`.
*   **Q2 (value): Retain Phase 2 (No PLAN-KILL).** The time-vs-bytes decoupling argument is highly valid. When a class is under-serviced due to surplus sharing or strict priority contention, the actual service rate drops. Under these conditions, the byte-denominated admission bounds ([`admission.rs:230`](file:///home/ps/git/bpfrx/.claude/worktrees/research-1829-aqm/userspace-dp/src/afxdp/cos/admission.rs#L230)) fail to prevent excessive queueing delays (e.g., 625 KB at 100 Mbps actual service rate is 50 ms delay). A time-domain dequeue AQM solves this by directly measuring real sojourn time.
*   **Q3 (state): Keep arrays, but restructure as Array-of-Structs (AoS).** See **Finding 1**.
*   **Q4 (signal policy): ECT-marking-only is fully defensible.** FQ-CoDel's per-flow scheduling ([`#1735`](file:///home/ps/git/bpfrx/.claude/worktrees/research-1829-aqm/userspace-dp/src/afxdp/cos/queue_ops/push.rs#L19)) isolates responsive flows. If a single flow is unresponsive, its bucket will build up, but it will eventually tail-drop at admission ([`admission.rs:124`](file:///home/ps/git/bpfrx/.claude/worktrees/research-1829-aqm/userspace-dp/src/afxdp/cos/admission.rs#L124)) without starving neighboring buckets. Drop-escalation for ECT is unnecessary.
*   **Q5 (placement): The fused-peek boundary is the correct choke point.** If the check lived in `pop_known_bucket_inner`, returning `None` on drop would cause the drain loops ([`drain.rs:241-245`](file:///home/ps/git/bpfrx/.claude/worktrees/research-1829-aqm/userspace-dp/src/afxdp/cos/queue_service/drain.rs#L241-L245)) to interpret it as a queue-empty event and prematurely break. Peek-time drop allows head eviction and continuation.
*   **Q6 (FIFO drains): Scratch-build-time measurement is correct.** Settle-time is post-TX-commit where packets are already written to the hardware ring and cannot be dropped. Single-flow queues stay FIFO but can still build up standing delay under strict priority / surplus restrictions, making FIFO-path CoDel support critical.
*   **Q7 (#1828): Airtight.** All forwarded traffic uses AF_XDP TX rings via direct syscalls ([`rings.rs:246`](file:///home/ps/git/bpfrx/.claude/worktrees/research-1829-aqm/userspace-dp/src/afxdp/tx/rings.rs#L246)), bypassing kernel qdiscs completely in both ZC and generic/copy modes. Kernel WAN qdisc is a strict NO-OP for forwarded traffic.

---

### Numbered Findings

#### [Finding 1] [MEDIUM] Parallel Arrays vs. Array-of-Structs cache-locality mismatch
*   **File/Line:** `userspace-dp/src/afxdp/types/cos.rs` (proposed under Section 6, 2a)
*   **Description:** The proposed parallel array structure (`first_above_ns: [u64; 4096]`, `drop_next_ns: [u64; 4096]`, etc.) forces the CPU to fetch cache lines from 5 disjoint regions in memory to service a single bucket. This introduces up to 5 cache misses per dequeue, wasting cycles on the hot path.
*   **Remedy:** Pack the per-bucket CoDel state into a single contiguous array of structs: `codel_state: [CodelBucketState; 4096]`, where:
    ```rust
    struct CodelBucketState {
        first_above_ns: u64,
        drop_next_ns: u64,
        count: u16,
        lastcount: u16,
        dropping: bool,
    }
    ```
    This struct fits in 24 bytes (alignment 8). Accessing a bucket's CoDel state will consume only a single cache line, preserving L1 cache efficiency.

#### [Finding 2] [HIGH] Congestion double-signaling for owner-local-exact queues
*   **File/Line:** [`userspace-dp/src/afxdp/cos/admission.rs:349`](file:///home/ps/git/bpfrx/.claude/worktrees/research-1829-aqm/userspace-dp/src/afxdp/cos/admission.rs#L349)
*   **Description:** For `owner-local-exact` queues, the admission path currently CE-marks packets on the per-flow bucket depth threshold. Stacking dequeue-time per-flow CoDel marking on top will cause double-signaling under load, collapsing TCP cwnd twice and degrading throughput into bimodal flow starvation (the `#784` regression signature).
*   **Remedy:** When `codel_target_ns > 0`, modify the admission ECN check in `apply_cos_admission_ecn_policy` to bypass per-flow marking on that queue, delegating all time-domain marking exclusively to the dequeue-time CoDel law.

#### [Finding 3] [MEDIUM] Missing counter decrements and byte subtraction in FIFO CoDel drops
*   **File/Line:** [`userspace-dp/src/afxdp/cos/queue_service/drain.rs:37`](file:///home/ps/git/bpfrx/.claude/worktrees/research-1829-aqm/userspace-dp/src/afxdp/cos/queue_service/drain.rs#L37), [`drain.rs:301`](file:///home/ps/git/bpfrx/.claude/worktrees/research-1829-aqm/userspace-dp/src/afxdp/cos/queue_service/drain.rs#L301)
*   **Description:** In FIFO drains, packets are built into scratch from `items` via `.get(index)` and popped later at settle-time. If CoDel drops a packet during batch building (scratch-build-time), it must be removed from `queue.hot.items`. If we remove it immediately, we must decrement `queue.hot.local_item_count` (if Local) and subtract its bytes from `queue.hot.queued_bytes` immediately, as well as trigger Prepared recycle. Failing to do so causes state leak and permanent accounting drift, since settle-time only pops successfully transmitted scratch frames.
*   **Remedy:** Ensure the FIFO drain paths perform immediate `local_item_count` and `queued_bytes` subtractions and execute the proper Prepared recycle (`recycle_cancelled_prepared_offset_with_shared`) when a packet is dropped during the batch build.
