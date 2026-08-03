# AGY hostile plan review — #6751 (round 25)

查看 target document `/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md`。

先用 `view_file` 查阅 `plan.md` 的内容或者 grep 特定的 section 9、section 8、lifecycle mutation、generation-CAS、send guard、episode latch 等。
Let's inspect `plan.md` around section 9 and relevant code/design sections!
PLAN-NEEDS-REVISION

### 1. [BLOCKER] Generation-CAS for Class-(b) Lifecycle Mutations Permits Equal-Generation Overwrites Between Slot $N$ Disconnect and Slot $N+1$ Connect
**File & Line Evidence:**
- `docs/research/6751-nopat-admission/plan.md:814-821`
- `docs/research/6751-nopat-admission/plan.md:723-731`

**Analysis:**
v15.11 introduces generation-tagged compare-and-swap (CAS) with monotonic-advance semantics for Class-(b) lifecycle state fields (`syncPeerConnected`, connection epoch, heartbeat suppression, bulk-prime flags, readiness arming, bulk-received/ack-received priming flags). The plan specifies that a mutation commits if its event generation is `>=` the currently stored generation (`docs/research/6751-nopat-admission/plan.md:816`).

However, under the slot generation assignment model (`docs/research/6751-nopat-admission/plan.md:723-731`):
1. When Slot $C_1$ disconnects/aborts, the registry increments `ABORT-GENERATION` from $g-1$ to $g$. $C_1$'s disconnect callback `onSessionSyncPeerDisconnected` is enqueued with generation $g$ (setting `syncPeerConnected = false`).
2. When replacement Slot $C_2$ is admitted immediately after $C_1$'s disconnect, it reads the current `ABORT-GENERATION` (which is $g$) without incrementing it. $C_2$'s connect callback `onSessionSyncPeerConnected` is enqueued with generation $g$ (setting `syncPeerConnected = true`).
3. Both $C_1$'s disconnect callback and $C_2$'s connect callback now carry the **SAME generation $g$**.
4. Because callbacks execute asynchronously on background goroutines (`go s.OnPeerConnected()`), suppose $C_2$'s connect callback executes FIRST and commits `(g, true)`.
5. When $C_1$'s delayed disconnect callback executes SECOND, it compares its event generation ($g$) against the stored generation ($g$). Because $g \ge g$ is **TRUE**, the CAS succeeds and overwrites the stored state with `(g, false)`.

**Impact:**
A stale disconnect callback from a closed connection ($C_1$) overwrites the live connect state of a replacement connection ($C_2$) with `false`, disarming readiness timers, suppressing heartbeats, and breaking session synchronization on an active connection.

**Required Fix:**
1. **Strict Monotonic Generation Advance Across Admissions:** Slot admission of $C_{N+1}$ MUST monotonically advance the event generation counter relative to $C_N$'s disconnect ($g_{\text{connect}} > g_{\text{disconnect}}$), so no connect callback ever shares a generation number with a prior disconnect callback.
2. **Strict Inequality CAS for Value-Flipping Mutations:** Alternatively, for opposite-value state transitions (e.g. `true` $\to$ `false` or `false` $\to$ `true`), require strict inequality ($g_{\text{event}} > g_{\text{stored}}$) so equal-generation stale writes cannot flip active state.

---

### Direct Analysis of Round-25 Attack Vectors

#### 1. Generation-CAS & Lifecycle Mutations (Codex Finding 1)
- **(a) Non-monotonic Values:** Generation-CAS tracks the monotonicity of the **generation tag** ($g$), not the value itself. As long as event generations strictly increase ($g_1 < g_2 < g_3$), a flag can freely flip values (`true` $\to$ `false` $\to$ `true`) across advancing generations. Value non-monotonicity is preserved.
- **(b) Event Generation Assignment / Forging Ahead:** Callbacks read the generation from their connection slot stamped at admission and cannot forge a generation higher than the registry's `ABORT-GENERATION`. However, as proven in **Finding 1 (BLOCKER)** above, if admission does not increment the generation counter, a new slot inherits the disconnect's generation number, causing equal-generation collisions under `>=`.

#### 2. Epoch-Bound Send Guard at Dequeue/Send Effect Point (Codex Finding 2)
- **(a) Held Delta Across Epoch Flaps ($N \to N+1 \to N+2$):** A delta dequeued under Epoch $N$ binds Epoch $N$. If the connection flaps $N \to N+1 \to N+2$ before sending, `sendLoop` compares the delta's bound epoch ($N$) against the active connection epoch ($N+2$) and discards it. This binding is **correct** because Epoch $N+2$'s cold-prime bulk (`doBulkSync()`) is the authoritative snapshot backstop that re-conveys all live sessions.
- **(b) Normal Reconnects & Cold-Prime Backstop:** On any connection re-establishment, `wasDisconnected` evaluates to `true` (guaranteed by v15.11's logical slot detachment in `docs/research/6751-nopat-admission/plan.md:939-955`), which arms `needColdPrime = true`. Cold-prime transmits all active sessions and `BulkEnd` reconciliation cleans up deleted sessions. Discarding Epoch-$N$ deltas on normal reconnects is safe and fully covered by the cold-prime backstop.

#### 3. Cap Recovery Anti-Self-Rearm & Episode Latch (Codex Finding 3)
- The chain is **fully closed**:
  - `stampInstallGenV4/V6` refusals occurring **DURING** an active recovery bulk (`BulkSync()`, `sync_bulk.go:95/135`) are recorded as bulk-triggered and explicitly forbidden from re-arming the saturation dirty flag or Episode Latch (`docs/research/6751-nopat-admission/plan.md:899-902`).
  - The Episode Latch permits at most one recovery bulk per cooldown window (`docs/research/6751-nopat-admission/plan.md:897-898`), preventing the 1-second sweep (`sync_conn_sweep.go:47/118`) from re-triggering back-to-back recovery bulks under persistent cap saturation.

---

### 2. [MINOR] Explicit Ingestion of `outboundBulkAcked` and `inboundBulkAcked` in Class-(b) CAS Inventory
**File & Line Evidence:**
- `docs/research/6751-nopat-admission/plan.md:809-815`

**Analysis:**
In §5.6 clause (ii)(b), the inventory of Class-(b) daemon lifecycle mutations explicitly lists `syncPeerConnected`, connection epoch, heartbeat-suppression state, bulk-prime flags, readiness arming, and bulk-received/ack-received priming flags (`onSessionSyncPeerConnected`, `onSessionSyncPeerDisconnected`, `onSessionSyncBulkReceived`, `onSessionSyncBulkAckReceived`). 

In `pkg/cluster/sync.go`, `s.outboundBulkAcked` (sync.go:479) and `s.inboundBulkAcked` are also lifecycle flags set during bulk ACK processing.

**Recommendation:**
Explicitly list `outboundBulkAcked` and `inboundBulkAcked` in §5.6 clause (ii)(b) to ensure they are wrapped in the generation-CAS pair alongside `onSessionSyncBulkAckReceived`.

---

### 3. [NIT] Observability Counter Taxonomy Clarification
**File & Line Evidence:**
- `docs/research/6751-nopat-admission/plan.md:1237-1284`
- `docs/research/6751-nopat-admission/plan.md:1309-1312`

**Analysis:**
Section 5.8 summarizes the added observability metrics as "four helper-side status counters... PLUS THREE Go-side Prometheus counters". However, `xpf_userspace_interface_snat_sync_identity_conflict_drops_total` is recorded inside the Rust helper coordinator (`ha/session_import.rs`), whereas the alias-quarantine metrics are Go `pkg/cluster` Prometheus counters.

**Recommendation:**
Slightly adjust the summary sentence in §5.8 to explicitly list the 4 helper status counters (`pat_collisions_total`, `identity_exhaustion_total`, `registry_cap_exhaustion_total`, `sync_identity_conflict_drops_total`) and 3 Go cluster counters (`forward_wire_alias_ignored_total`, `alias_quarantine_admitted_total`, `alias_quarantine_overflow_total`), clarifying the 4+3=7 counter inventory.
