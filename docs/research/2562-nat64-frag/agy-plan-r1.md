# AGY — hostile plan review r1 (#2562)

Adversarial design review of `docs/research/2562-nat64-frag/plan.md` (v1).
Verbatim agent result (harness tags stripped). Full AGY artifact:
`/home/ps/.gemini/antigravity-cli/brain/ed64a0bf-61a5-45f1-81d2-5c2080853257/hostile_plan_review.md`.

## Verdict: PLAN-DEFER

The plan is strictly blocked by the prerequisite #3291 Stage 4 (the
fragment-association cache), which is currently deferred. Additionally, critical
design flaws in NAT64 reverse translation and egress packet copying must be
addressed before the plan can be marked ready.

**High Severity Findings:**

1. **Reverse NAT64 Translation (v4→v6) Metadata Dependency:** The reverse path in
   `build_nat64_forwarded_frame` (`userspace-dp/src/afxdp/frame/mod.rs:213-219`)
   relies on `nat64_reverse` (`Nat64ReverseInfo`,
   `userspace-dp/src/session/entry.rs:32`). Since this is not carried in the
   generic `SessionDecision`, reverse non-first fragments will fail to translate
   on cache hits.

2. **Egress Path Allocation/Copy Mismatch:** The stage-4 cache assumes
   same-family in-place rewrites. NAT64 is cross-family, requiring buffer size
   changes (±20 bytes) and a copy path, introducing an architectural mismatch
   with the shared egress stage.

3. **Process-Shared Cache Requirement:** Verification of `sessions: SessionTable`
   (`userspace-dp/src/afxdp/worker/loop_body/setup.rs:40`) confirms session state
   is strictly thread-isolated. Because default RSS splits fragments across worker
   threads, a worker-local cache is guaranteed to fail; a process-shared sharded
   cache is mandatory.

**Medium/Low Severity Findings:**

4. **Fragmented ICMP Checksum Limitation:** Translating fragmented ICMP/ICMPv6
   changes the pseudo-header checksum. Without reassembly, calculating the correct
   checksum is impossible; unconditionally dropping them is the correct
   mitigation.

5. **UDP Zero-Checksum Simplification:** No zero-checksum tracking is needed in
   the cache. A dropped first fragment prevents cache insertion, and subsequent
   fragments naturally drop on cache miss due to missing `orig_src_v6`.

## Disposition

All 5 findings folded into plan v2: #1→S1 (reverse value field, §3.3/§5.1/§5.4);
#2→S3 (cross-family egress dispatch framing, §5.1/§5.2); #3→confirms §5.3
process-shared (AGY holds the stronger "guaranteed to fail" position; plan keeps
the robustness framing, both reach process-shared-mandatory); #4→confirms the
ICMP drop (§5.2.3); #5→resolves Q4 (no zero-csum cache flag, §5.2/§11).
