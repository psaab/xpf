# AGY hostile plan review — #6751 (round 40)

# AGY Hostile Plan Review — #6751 Plan v15.28 (Round 40 Convergence Adjudication)

**Verdict**: **PLAN-READY**

---

### Executive Summary & Convergence Adjudication

Plan document [`docs/research/6751-nopat-admission/plan.md`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md) at **v15.28** (commit `f5a790271`) has been evaluated following the round-39 fold verification, Codex r39 fold checks, Claude SMR r40 review, and hostile attack.

- **Folds Verified**: AGY r39's 1 nit, Codex r39's 2 BLOCKERs, 1 MAJOR, 1 MINOR, and 2 NITs, along with Claude SMR r40's fold check, have all been verified as folded in `plan.md` v15.28.
- **Substrate Integrity**: Both core design forks remain intact and settled (**PATH A** sole-writer helper in [§4.0.1](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L415-L541); **Option (a)** preserve-first + exact PAT fallback in [§4](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L744-L822)).
- **Convergence**: **Zero BLOCKER or MAJOR defects survive v15.28.** All line numbers referenced below have been verified via `grep` directly against `docs/research/6751-nopat-admission/plan.md` at commit `f5a790271`.

---

### 1. Codex r39 BLOCKER 1 Fold Attack Analysis (Capability-Gated Windows)

**Fold Rule** ([`plan.md:667-686`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L667-L686)): Bulk windows from non-capability-advertising peers are **FRAMING-ONLY** — they install frames per today's rolling-upgrade interop, but NEVER clear `alias-suspect` lineage, NEVER drive the definitive alias pass, and NEVER release the reconciliation hold for lineage purposes.

#### Hostile Attack Results:
- **(a) Capability Advertisement Integrity**:
  - *Analysis*: The capability rides `syncMsgCapability` on an internal cluster TCP mesh transport. Middleboxes cannot forge or strip custom frame types without breaking internal cluster transport integrity (`sync_auth.go:321`). Frame types are explicitly tagged with single-byte type headers in `pkg/cluster`. Legacy peers emit only pre-existing frame types and ignore `syncMsgCapability`. Sound.
- **(b) Lost Capability Advertisement Recovery**:
  - *Analysis* ([`plan.md:1292-1310`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1292-L1310)): Capability is advertised **PERIODICALLY** on a dedicated ticker (aligned to the 5–10s heartbeat/ping ticker) and resets to `UNKNOWN` on reconnection. If a frame is lost or arrives late during setup, the peer is treated as framing-only until the next periodic ticker arrives ($\le 10\text{s}$), which transitions the state to capable. The system self-heals without degrading NEW peers permanently. Sound.
- **(c) Coherence of Framing-Only + Retained ACK**:
  - *Analysis* ([`plan.md:687-689`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L687-L689)): For legacy peers, the standby sends peer ACKs and releases the VRRP hold (preserving availability during rolling upgrades) while retaining `alias-suspect` marks on imported sessions (preventing false lineage clears on lossy legacy bulk windows). Disposition (traffic allowed) and Lineage (fallback PAT/preservation retained for session lifetime) are decoupled. This composition is completely coherent, honest, and safe. Sound.

---

### 2. Codex r39 BLOCKER 2 Fold Attack Analysis (Retained-C0 & Interval Cap)

**Fold Rule** ([`plan.md:694-716`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L694-L716)): For legacy no-ACK peers with lost close notifications, NO plan-bounded detector kills $C_0$. The terminal is the readiness-timeout degraded release with debt retained, and `quiet_interval = min(2.5 × keepalive_timeout, readiness_timeout)`.

#### Hostile Attack Results:
- **(a) Zombie-$C_0$ Debt Discharge Path**:
  - *Analysis* ([`plan.md:725-731`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L725-L731)): The debt pair `(epoch -> debtGen)` is written BEFORE the peer-facing End frame and is cleared **ONLY by a matching peer ACK**. When a genuine both-empty transition occurs later (e.g. peer reboot, socket timeout, or clean reconnect), the new connection $C_{\text{new}}$ finds `debt == true` and triggers an authoritative cold prime. The debt machinery guarantees discharge on the next clean reconnect independent of the fence. Sound.
- **(b) Quiet Interval Cap `min(2.5 × keepalive, readiness_timeout)`**:
  - *Analysis* ([`plan.md:711-716`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L711-L716)): For CURRENT peers (`peerHeartbeatAckEver == true`), missed-heartbeat tracking is active. At `keepalive = 1s`, silence detection and slot clearance occur within $2.5\text{s}$. Thus 2.5s is fully sufficient to guarantee slot clearance for fast keepalives. Capping at `readiness_timeout` (5s) prevents the 7.5s (3s keepalive) ordering inconsistency caught by Codex r39. Sound.

---

### 3. §6 Reconciliation, Mutex, Accept Trace, & Wording Verification

All four items requested for grep verification exist at the exact expected lines in `plan.md` (v15.28):

1. **§6 Two-Field Reconciliation**:
   - Verified at [`plan.md:2725-2735`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L2725-L2735): "`SyncedSessionEntry` gains TWO additive fields (AGY r39 nit): `pub_token: u64` ... and the alias lineage STAGE (`alias-suspect` / `alias-lineage` / clear...)".
2. **Named Admission Mutex**:
   - Verified at [`plan.md:19-21`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L19-L21) and [`plan.md:2958-2964`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L2958-L2964): "the engaged flag and the stamp are read/issued under ONE named admission mutex — Codex r39 nit 5: the admission linearization point is explicit, covering engaged-check, stamp issuance, child registration, the release-side generation advance, and disengage ordering, with advance-BEFORE-disengage required — distinct from the connection-state and setup-state locks, `sync.go:301/322`".
3. **Exact Accept Trace**:
   - Verified at [`plan.md:22-23`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L22-L23), [`plan.md:637`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L637), and [`plan.md:2968`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L2968): "`accept-after-sweep-start -> resume-after-release` (refused at admission — no stamp is ever issued mid-window)".
4. **Wording Cleanup ("CURRENT Store as Definitive")**:
   - Verified at [`plan.md:3251-3253`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L3251-L3253): "against the CURRENT store (which is disposition-definitive only, never lineage-definitive — Codex r39 nit 6's wording cleanup)".

---

### 4. Full-Plan Convergence Sweep

A comprehensive grep-verified sweep across all sections confirms:
- **Both design forks are settled**: **PATH A** sole-writer helper ([`plan.md:415-541`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L415-L541)) and **Option (a)** reserve-or-PAT fallback ([`plan.md:744-822`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L744-L822)).
- **Option (a) core**: Preserved across four independent no-kill-shot confirmations.
- **Legacy wire honesty**: Completely wire-honest (framing-only bulk windows for legacy peers; readiness-timeout degraded release with retained debt for zombie $C_0$).
- **Observability taxonomy**: Fully consistent ($6 \text{ helper-side} + 3 \text{ Go-side} = 9 \text{ total counters}$, [`plan.md:2633-2659`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L2633-L2659)).

---

### Numbered Findings

*No BLOCKER, MAJOR, MINOR, or NIT defects remain in plan v15.28.*

---

### Conclusion

Plan v15.28 is **PLAN-READY**. All design parameters, wire honesty claims, transport fences, and generation mechanics are closed, verified, and ready for implementation.
