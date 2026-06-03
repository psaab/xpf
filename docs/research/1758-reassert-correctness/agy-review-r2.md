# AGY Adversarial Review: #1758 Session-Refresh Secondary-Index Re-assert

**Reviewer**: Antigravity (AI Coding Assistant)  
**Date**: 2026-06-03  
**Target**: `docs/research/1758-reassert-correctness/plan.md`  
**Verdict**: **PLAN-READY** (Accept the plan's recommendation to **PLAN-KILL** the perf-opt framing of removing the re-assert, file a separate correctness tracker for the structural 1:N collision, and ship a telemetry counter).

---

## 1. Reachability Commitment & Code Proof

We commit to the reachability answer: **REACHABLE**. 

Two live sessions can derive the same secondary key `K` in `nat_reverse_index` under four distinct vectors where `rewrite_src_port = None`. Below is the code evidence proving reachability using the primary vector (interface-mode SNAT):

### Vector 1: Interface-Mode SNAT (Default)
In [userspace-dp/src/nat/source.rs](file:///home/ps/git/bpfrx/.claude/worktrees/1758-research/userspace-dp/src/nat/source.rs#L431-L441), interface-mode SNAT returns a `NatDecision` with `rewrite_src` populated but leaving `rewrite_src_port` as the default `None`:
```rust
        if rule.interface_mode {
            let rewrite_src = match src_ip {
                IpAddr::V4(_) => egress_v4.map(IpAddr::V4),
                IpAddr::V6(_) => egress_v6.map(IpAddr::V6),
            };
            return SourceNatLookup::Matched(NatDecision {
                rewrite_src,
                rewrite_dst: None,
                ..NatDecision::default()
            });
        }
```

In [userspace-dp/src/session/key.rs](file:///home/ps/git/bpfrx/.claude/worktrees/1758-research/userspace-dp/src/session/key.rs#L88-L92), `reverse_wire_key` constructs the reverse mapping key. When `nat.rewrite_src_port` is `None`, it defaults to the original client's source port (`forward_key.src_port`):
```rust
        (
            nat.rewrite_dst_port.unwrap_or(forward_key.dst_port),
            nat.rewrite_src_port.unwrap_or(forward_key.src_port),
        )
```
This maps the reverse packet's destination port (`dst_port`) directly to the original client source port. 

Thus, if two distinct internal hosts (e.g. `10.0.0.1` and `10.0.0.2`) use the **same ephemeral source port** (e.g., `5555`) to connect to the **same external service** (e.g., `8.8.8.8:443`), both will rewrite their source IP to the egress interface IP (e.g., `203.0.113.9`) and keep the port `5555` unchanged. Both sessions construct the identical reverse wire key:
`src=8.8.8.8:443, dst=203.0.113.9:5555`

Finally, in [userspace-dp/src/session/mod.rs](file:///home/ps/git/bpfrx/.claude/worktrees/1758-research/userspace-dp/src/session/mod.rs#L1357-L1358), both sessions write to the single-valued reverse index:
```rust
            self.nat_reverse_index
                .insert(reverse_wire_key(key, nat), handle);
```
Since `FxHashMap::insert` performs an unconditional overwrite, the second session silently displaces the first.

---

## 2. Review Agreements/Disagreements

### (a) REACHABLE
* **Status**: **AGREE**
* **Rationale**: The code analysis in Section 1 shows that interface-mode SNAT, NAT64 (`nat64.rs:113`), DNAT-to-shared-backend (`destination.rs:129`), and non-bijective static NAT (`static_nat.rs:73`) all leave `rewrite_src_port = None`. Any time two distinct forward sessions map to the same external IP/port tuple, a collision on key `K` in `nat_reverse_index` is guaranteed.

### (b) Re-assert Removal is Not a Clean Fix
* **Status**: **AGREE**
* **Rationale**: The re-assert in `update_session` acts as a last-writer-wins arbitration for a 1:N relationship modeled inside a 1:1 data structure. If we remove the re-assert, we "solve" the problem where S1's expiration deletes the entry for S2, but we introduce a worse bug: S1 is permanently stranded at install-time (displaced by S2) and can never recover its reverse mapping key upon refresh. Both states lead to packet drop/loss of connectivity. The underlying defect is structural.

### (c) Disposition (PLAN-KILL perf framing + tracker + counter)
* **Status**: **AGREE**
* **Rationale**: The "~1% perf optimization" framing is a dangerous simplification that hides a correctness issue.
  1. The perf framing must be killed (`PLAN-KILL`), leaving the re-assert intact.
  2. A separate correctness tracker must be spun to address the 1:N collision structure.
  3. A telemetry counter must be deployed on `insert` overwrites to measure real-world collision frequency. The cost is negligible because `insert` already returns the displaced value, avoiding additional map reads.

---

## 3. Adversarial Analysis of Open Questions

1. **Read-side Validation Sufficiency**: Yes, the check in `find_forward_nat_match` (`!reply_matches_forward_session(...)`) bounds the harm to a silent packet drop/miss rather than misrouting traffic to the wrong host. This is a critical security property.
2. **Additional Vectors**: Codex's discovery of the three additional vectors (NAT64, DNAT to shared backend, static NAT) is sound. The `reverse_canonical` bypass is safe since identical 5-tuples constitute the same session, preventing distinct session collisions on that path.
3. **TCP vs UDP Exposure**: TCP sessions will self-heal if the victim session transmits forward packets, as they will re-refresh and re-assert the key. However, UDP sessions or silent-forward/active-reverse flows (e.g. Server Sent Events, long-polling, or UDP tunnels) will remain permanently stranded once displaced and the peer expires the key.
4. **Telemetry Cost**: The displacement counter is practically free. By checking the option returned by `insert`, we avoid any extra lookup:
   ```rust
   if let Some(old_handle) = self.nat_reverse_index.insert(key, handle) {
       if old_handle != handle {
           // Increment telemetry counter
       }
   }
   ```

---

## 4. Final Verdict

**PLAN-READY** (The plan to PLAN-KILL the perf optimization, spin a correctness tracker, and deploy telemetry is correct and ready for execution).
