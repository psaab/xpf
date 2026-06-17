VERDICT: PLAN-NEEDS-WORK

### 1. Verification of r1 Findings Resolution
The r2 plan successfully addresses all four findings from r1:

*   **Finding #1 (ID-match) → Resolved:**
    > "13: - **F1 (all three reviewers):** removed the contradictory `echo.ID == want.ID` predicate. The authoritative reply-match is now **Seq + Data-nonce only**; ID is ignored on datagram sockets"
    > "109: - **(5a) Reply matching — Seq + Data-nonce, NOT ID.** ... Therefore the prober MUST set a unique monotonic **Seq** per probe AND carry a random per-probe **nonce in `Echo.Data`**, and require BOTH to match on the reply."

*   **Finding #2 (overlay/underlay VRF) → Resolved:**
    > "16: - **AGY #2 (decisive architectural correction):** the keepalive probes the tunnel's **outer underlay `Destination`**, which routes in the **global/underlay** table — NOT the tunnel's overlay VRF. r1's §5b "bind the probe socket to `vrf-<instance>`" was backwards and is **removed**."
    > "119: - **(5b) Probe target is the UNDERLAY endpoint; route it in the underlay/global table — do NOT bind to the overlay VRF.**"

*   **Finding #3 (SO_BINDTODEVICE privilege catch-22) → Resolved:**
    > "21: - **AGY #3 + Codex F2 (privilege catch-22 / no Control hook):** dissolved for the common case by dropping overlay-VRF binding. The rare "underlay itself lives in a VRF" case is documented as out-of-scope (follow-up)..."

*   **Finding #4 (fail-open hides outages) → Resolved:**
    > "31: - **C1 rename + transient/structural split (Codex F5 + AGY #4):** renamed C1 to **hold-on-unknown**. Split `ProbeUnsupported` into **structural** ... vs **transient** ... Transient unsupported is bounded: after a sustained-unknown window it escalates to a loud status + does NOT silently hold up forever."
    > "161: - **Transient Unsupported escalation (addresses AGY #4):** if Unsupported is caused by a *transient local resource* error... escalate to a louder status... and a `slog.Error`. Do NOT silently hold "up" forever..."

---

### 2. New Defect / Gap: Source Address Selection
The plan has a critical gap regarding the socket bind address for the outbound probe.

*   **Finding #5 (Missing Local Source IP Binding):**
    > "234: Production impl: `icmp.ListenPacket("udp4"/"udp6", ...)` (NO `SO_BINDTODEVICE`; global table — §5b), build `icmp.Echo{Seq, Data: nonce}`, `WriteTo` the underlay `Destination`"

    **Justification:**
    If the probe socket binds to a wildcard address (e.g. `""` or `"0.0.0.0"`), the kernel performs default source address selection. On systems with multiple local IPs, secondary IPs, or policy-based routing, the kernel can easily choose an egress source IP that differs from the tunnel's configured local source address (`TunnelConfig.Source`).
    This creates three operational risks:
    1.  **Ingress Filtering:** Path firewalls or the remote peer may drop the ICMP Echo Request if it does not originate from the configured tunnel endpoint IP.
    2.  **Routing Mismatch:** The reply will be routed back to the kernel-chosen source IP instead of the tunnel source IP, failing the probe.
    3.  **Invalid Path Validation:** The probe fails to validate the reachability of the actual path used by the encapsulated tunnel traffic.
    
    **Correction:**
    The socket must bind specifically to the tunnel's configured local source IP (e.g. `icmp.ListenPacket("udp4", localSourceIP)`). The plan must be updated to pass the tunnel's local source address to the prober and bind the socket to it.
