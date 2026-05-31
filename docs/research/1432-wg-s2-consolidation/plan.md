# #1432 — WireGuard S2 datapath consolidation: reconcile #1432 / #1434 / #1389 against the #1703 S-step plan

Status: **PLAN-READY v1 (DRAFT)** — awaiting 3-way hostile review (Codex + AGY +
Claude-SMR). This is a **consolidation/issue-structure research**, NOT an
implementation plan. The deliverable is: (a) the verified relationship between
the four pre-existing WireGuard issues, (b) a recommended issue structure with
concrete dedup actions, and (c) the S2 scope boundary so the next `/engineer`
run has a clean target. **No production code is touched by this research.**

Issue: #1432 (the consolidation surface). Related: #1703 (umbrella), #1709 (S1,
MERGED via PR #1716), #1434, #1389.

Worktree branch: `research/1432-wg-s2-consolidation` off `origin/master`
@ 6198223c8.

> If reviewers conclude the recommended structure is wrong (e.g. #1432 is NOT
> cleanly S2, or S2 should be a fresh issue), **proposing a different structure
> is the expected outcome** — this research exists precisely to be hostile to
> the user's "#1432 IS S2" hypothesis.

---

## 1. Issue framing (in my words)

S1 of the #1703 WireGuard-interop umbrella just merged (PR #1716, merge
`a35132bca`): xpf's `userspace-dp` WG engine is now **wire-protocol compliant**
— it builds/parses spec-correct handshake framing (msg type 1/2, MAC1
keyed-BLAKE2s, MAC2 skip, LE indices) and carries a strictly-monotonic TAI64N
timestamp, validated by full byte-exact spec known-answer vectors in both
roles. **The handshake is done; nothing downstream is wired.**

The #1703 owner parked S2–S6 and left an explicit instruction (the last #1703
comment): *"Reconcile with pre-existing WG issues before S2: #1432 overlaps
S2's datapath wiring; #1434 overlaps S4/S5; #1389 is a broader umbrella. The S2
plan should dedup against #1432 specifically (it may BE the S2 work, or
vice-versa)."*

Three pre-existing issues predate the #1703 umbrella and the S1 clean-room
work, and risk spawning a **parallel third track** if S2 opens without
reconciliation:

- **#1432** "Implement High-Performance WireGuard Support in Userspace
  Dataplane" — a checklist tracker that claims a `boringtun 0.6` engine with RX
  decap in `poll_stages.rs`, TX encap in `dispatch.rs`, and protocol snapshot
  support all marked **done (`[x]`)**, with Go compiler + CLI + perf benchmarking
  marked **open (`[ ]`)**. References a design doc
  `docs/design/wireguard-support.md` on a `feature/wireguard-support` branch.
- **#1434** "Implement Multi-Tunnel WireGuard Support" — multiple WG interfaces
  (wg0/wg1), per-interface keys + listen-ports, RX/TX engine lookup by port,
  `show security wireguard public-key`, `request security wireguard
  generate-private-key`.
- **#1389** "Edge gateway feature bundle" — a broad 6-feature product umbrella
  (multi-WAN, DNS/DDNS, **WireGuard**, PBR, smart queueing) whose Phase 5 is an
  "easy WireGuard setup" that — critically — recommends a **kernel-WireGuard +
  veth** architecture, NOT the userspace-dp clean-room engine.

The consolidation question: **is #1432 the S2 datapath work, or something
else?** And what happens to #1434 and #1389?

---

## 2. Honest scope / value framing

This is not a perf change and not a code change — it is an **issue-graph
correctness** task. The value is preventing a wasted parallel implementation
track and giving the next `/engineer 1703 S2` (or `/engineer <chosen issue>`) a
single canonical target with a non-overlapping scope boundary. The cost is one
research pass + issue edits (relabel/close/re-scope/comment). The honest risk is
**mis-deduping**: closing an issue that actually carries unique scope, or
re-scoping #1432 onto S2 when its "high-performance" framing is really a *later*
perf step distinct from basic datapath wiring. The plan must resolve that with
code evidence, not vibes.

---

## 3. What's already shipped / proven (the S1 + clean-room foundation)

Verified against `origin/master` @ 6198223c8 in this worktree.

### 3.1 The merged engine is `snow`-based clean-room, NOT boringtun

- `userspace-dp/Cargo.toml` has **no `boringtun` dependency**; `git grep -il
  boringtun` returns only historical docs (`docs/vpp-dataplane-assessment.md`,
  `docs/pr/wireguard-clean/plan.md`, issue/PR history) — never source.
- The engine uses `snow` (Noise framework): `engine.rs`, `framing.rs`,
  `session.rs`, `handshake.rs`, `handshake_session.rs`, `tai64n.rs` all import
  `snow`. Origin commit `49a29cf6f` "WireGuard clean-room dataplane termination
  (snow-based) (#1499)".
- **#1432's `[x]` "WireGuardEngine wrapper around boringtun 0.6"** is therefore
  **fiction relative to master.** It described a different, abandoned
  implementation (`feature/wireguard-support`). `docs/design/wireguard-support.md`
  **does not exist on master** (`find` confirms absent). This is decisive for
  the dedup: #1432's "done" sub-tasks are NOT done in the shipped codebase.

### 3.2 S1 (PR #1716) delivered — handshake/framing/crypto only

`wg/` module on master (6769 LOC incl. tests):
- `handshake.rs` (651), `handshake_session.rs` (557), `tai64n.rs` (383) are the
  S1 additions: spec framing + monotonic TAI64N + two-phase index reservation +
  at-most-one-pending-per-peer DoS bound.
- `engine.rs` (1807), `session.rs` (365), `framing.rs` (151), `allowed_ips.rs`
  (291), `mss.rs` (184), `dscp.rs` (52), `peer.rs` (119), `scratch.rs` (63):
  pre-S1 clean-room crypto/replay/AllowedIPs/transport-record library.
- `tests.rs` (2005) — full spec KAT suite + framed self-handshake both
  directions.

### 3.3 Everything downstream of the handshake is UNWIRED (the S2 surface)

This is the core finding. The engine is dead code from the datapath's view:

- **`WgEngine` is instantiated nowhere outside tests.** `grep "WgEngine::new\|
  WgEngine {"` outside `wg/tests.rs` + `wg/engine.rs` returns only
  `handshake_session.rs:98` (`impl WgEngine`). No worker, coordinator, or
  binding constructs one.
- **`mod wg;` is gated WIP.** `afxdp/mod.rs:125-129`: *"Engine + tests only in
  this PR; hot-path activation lands in a follow-up."*
- **`try_encap` / `try_decap` have ZERO call sites outside `wg/`.** The encap
  builders that dispatch actually calls (`encapsulate_native_gre_frame` at
  `tx/dispatch.rs:785-792`, `frame/mod.rs:212`,
  `frame/tcp_segmentation.rs:309`, `tunnel.rs:189`) never branch to WG.
- **`poll_stages.rs` and `tx/dispatch.rs` have NO wg references at all.**
- **`TunnelEndpoint` (datapath struct, `types/forwarding.rs:156`) is
  `#[allow(dead_code)]`, mode is gre/ipip only, has NO Wg* fields.** The
  *snapshot* DTO `TunnelEndpointSnapshot` (`protocol/snapshot.rs:341-374`) and
  its Go twin (`protocol.go:298-314`) DO carry `wg_listen_port /
  wg_local_privkey_hex / wg_peer_pubkey_hex / wg_allowed_ips / wg_endpoint /
  wg_keepalive_secs` — but they are **dead DTO fields**: the runtime
  `TunnelEndpoint` never reads them.
- **The Go control plane NEVER populates any `Wg*` field** (`grep "Wg[A-Z]" pkg/
  | grep "="` is empty) and there is **no `"wireguard"` Mode** in the Go
  config/compiler. The chain Junos→Go→snapshot→Rust-runtime→engine is broken at
  the source AND at the runtime-struct hydration.
- **No UDP socket plumbing exists.** `listen_port` is stored as engine data
  (`engine.rs:181`) but nothing binds a `UdpSocket` or demuxes inbound
  `UDP/<listen_port>`. The S1 plan §5.4c and `wireguard-clean/plan.md` both note
  the UDP send/recv layer is unbuilt.
- **No WG CLI exists.** `generate-private-key` / `show security wireguard
  public-key` are absent from `pkg/cmdtree` + `pkg/cli` (they lived only on the
  dead `feature/wireguard-support` branch — #1434 calls to "restore" them, but
  there is nothing to restore on master).

### 3.4 The S2 integration points are already pin-pointed (by wireguard-clean/plan.md)

The clean-room PR's plan (`docs/pr/wireguard-clean/plan.md` §Integration) names
the exact S2 wiring sites, all currently un-activated:
- **Egress encap** — three call sites take the same `match endpoint.mode {
  "wireguard" => wg_engine.try_encap(...)?, _ => encapsulate_native_gre_frame
  (...) }` shape: `frame/mod.rs:212` (primary copy-path, invoked by
  `tx/dispatch.rs:785-792`), `frame/tcp_segmentation.rs:309` (TSO path),
  `tunnel.rs:189` (local-origination path). Gate boolean `uses_native_tunnel`
  computed at `tx/dispatch.rs:430`.
- **Ingress decap** — the poll_descriptor classifier where outer L2/L3/L4 is
  already stripped; WG ingress = `UDP/<listen_port>`.
- **Protocol extension** — already landed (the dead DTO fields above); S2 must
  hydrate the runtime `TunnelEndpoint` from them + add the `"wireguard"` mode.

### 3.5 S1's own deferral list IS the S2 charter

`docs/pr/1709-wireguard-s1-wire-protocol-compliance/plan.md` §10 "Out of scope"
+ §5.4c explicitly defer to **S2**:
1. AF_XDP hot-path encap/decap wiring + runtime `TunnelEndpoint` extension.
2. The **live kernel-WireGuard-on-VM interop test** (the independent-peer proof
   S1 could not provide), with a pinned peer-VM spec: Debian-13 incus **VM**,
   SR-IOV VF on `mlx1` vlan 3667, IPv4 `10.0.61.103/24`, reaching xpf at the LAN
   VIP `10.0.61.1` (mirrors `cluster-userspace-host`). **S2 must verify a free
   mlx1 VF (id ≥4) at provision time** or reuse a spare real VM.
3. A single transport-record round-trip over the harness UDP socket to confirm
   key agreement (Test 1b/2b — transport-flow over the AF_XDP worker stays a
   later step).

This is a near-exact match to #1703 S2 as worded in the umbrella's S-step
comment: *"dataplane tunnel wiring: wire the wg engine into the AF_XDP datapath
for a live client tunnel (encap/decap on the data path)"* + the ratified S1/S2
boundary item (b+): the live kernel-wg interop test lands in S2.

---

## 4. The four-issue relationship (verified, hostile to the hypothesis)

| Issue | Title | Claimed state | Actual state vs master | True overlap |
|---|---|---|---|---|
| **#1703** | WG interop umbrella | S1 merged, S2–S6 parked | Accurate. S-step plan in comments. | The umbrella. Owns the S-step ladder. |
| **#1432** | "High-Performance WG in userspace DP" | boringtun engine + RX/TX/protocol **done**; Go compiler + CLI + perf **open** | "done" items are **fiction** (boringtun never landed; design doc absent). The shipped engine is snow-based S1. The OPEN items (Go compiler, CLIS, perf) are real future work. | **The datapath-wiring + activation half of S2**, mislabeled as "done via boringtun." Its OPEN items straddle S2 (no items), S4 (Go config), and a *future* perf step. |
| **#1434** | Multi-Tunnel WG | multiple wgN, per-iface keys/ports, port-keyed engine map, public-key CLI, generate-private-key | None of it exists on master; the engine is single-instance, no port demux map, no CLI. "Restore generate-private-key" has nothing to restore. | **S4 (config surface, multi-peer) + S5 (responder/multi-instance).** Pure future work; no overlap with S2's single-tunnel wiring. |
| **#1389** | Edge gateway bundle | broad 6-feature product ask; Phase 5 = "easy WG" via **kernel-WG + veth** | Architecturally **divergent** — recommends kernel WG + veth re-entry, which the clean-room userspace-dp engine SUPERSEDES. The WG portion is a product/UX wrapper. | **References WG; does not implement it.** Should depend on #1703, not duplicate it. Its kernel-WG+veth recommendation is stale and must be annotated superseded. |

### 4.1 Hostile test of the user's hypothesis ("#1432 IS S2")

**Hypothesis mostly holds, with one correction the user flagged as possible.**

- **For (#1432 == S2):** #1432's title is literally "WireGuard Support in
  Userspace Dataplane," and its three `[x]` items (engine + RX decap in
  poll_stages + TX encap in dispatch + protocol snapshot) name **exactly the S2
  datapath-wiring surface** (poll_stages decap, dispatch encap, snapshot). That
  those items are checked-but-fictional doesn't change that the *work they
  describe* is S2. So #1432's body, read as a work description rather than a
  status report, IS the S2 datapath activation.

- **Against (the "High-Performance" angle ≠ basic wiring) — the user's own
  hostile prompt:** the title says "**High-Performance**," and one open item is
  "Performance benchmarking and optimization." Is #1432 really a *perf/zero-copy*
  step that comes AFTER basic datapath wiring (i.e. the user's Option C)?
  **Verdict: NO, not cleanly.** Evidence: (a) the `[x]` items are basic wiring
  (decap stage, encap stage, protocol), not zero-copy/SIMD; "high-performance"
  is the *motivation* (userspace crypto on the AF_XDP path instead of
  kernel-WG+veth, contra #1389), not a distinct deliverable. (b) The
  per-MEMORY.md SIMD/perf history (#966–#969 all PLAN-KILLED: ChaCha20-Poly1305
  is already AVX-512 in the crate; there is no userspace crypto hot-loop to
  hand-optimize) means a standalone "WG perf" issue would almost certainly
  PLAN-KILL. So #1432's perf framing is best treated as the *rationale* for
  doing WG in userspace-dp at all, and its one real open perf item folds into
  S2's acceptance (the live interop must sustain a transport-record round-trip;
  any throughput target is a later, separately-justified step — NOT a blocker
  for S2).

- **Caveat the structure must encode:** #1432's three OPEN items are NOT all S2.
  "Go control-plane compiler for WireGuard config" = **S4**. "CLI for key
  management" = **S4/S5** (and overlaps #1434). "Performance benchmarking" =
  later/optional, likely-KILL as a standalone. So #1432 cannot be re-scoped to
  S2 *as-is* without amputating its S4/perf items — they must be migrated to
  #1434/#1703-S4 to keep S2's boundary clean.

---

## 5. Concrete design — recommended issue structure (the deliverable)

### 5.1 Options considered

- **Option A — #1432 BECOMES #1703 S2 (re-scope in place).** Relabel #1432 to
  "#1703 S2: wire the S1 wire-compliant engine into the AF_XDP datapath
  (encap/decap) + live kernel-WireGuard interop test." Strip its fictional
  `[x]` boringtun items, migrate its Go-compiler/CLI open items to #1434, drop
  perf to a footnote. #1434 → S4/S5. #1389 → annotate (depends-on #1703,
  kernel-WG+veth superseded). **No third track.**
- **Option B — S2 is a fresh sub-issue; #1432 closed-as-superseded.** Open a
  clean `#1703 S2` issue mirroring §3.5; close #1432 as superseded (its premise
  — boringtun, kernel-WG+veth-era — is obsolete). Pro: clean slate, no fictional
  history to carry. Con: loses the #1432 backlink/discussion; "close a
  long-standing tracker" reads as scope loss to an observer; an extra issue
  number for no semantic gain.
- **Option C — #1432 = the perf/zero-copy step AFTER S2 basic wiring.** Keep
  #1432 as a *later* perf issue; open fresh S2 for basic wiring. **Rejected in
  §4.1:** there is no distinct perf deliverable (crypto already vectorized;
  SIMD/perf precedent is PLAN-KILL); this would create the exact parallel/empty
  track the user wants to avoid.

### 5.2 Recommendation: **Option A** (re-scope #1432 in place as #1703 S2)

Rationale: #1432's *work description* already IS S2 (§4.1); re-scoping in place
preserves the issue's history/backlinks while removing the fictional status, and
costs one issue edit + comment rather than a close+open churn. Option B's only
real advantage (no fictional history) is achieved by Option A's "strip the `[x]`
items" edit anyway. Option C is structurally wrong.

**Concrete dedup actions (research output — to be executed by the human/operator
or the subsequent `/engineer`, NOT by this research run):**

1. **#1432 — re-scope to "#1703 S2: WireGuard datapath wiring + live interop."**
   - Post a comment: the boringtun `[x]` items are obsolete (master ships a
     snow-based clean-room engine via #1499/#1709); the real remaining work is
     S2 datapath activation per §3.3–§3.5 + §5.3 below.
   - Re-scope its checklist to the S2 boundary (§5.3). Migrate "Go control-plane
     compiler" + "CLI key management" out to #1434/#1703-S4. Demote "perf
     benchmarking" to a non-blocking footnote (revisit only with a measured
     bottleneck, per the #966–#969 KILL precedent).
   - Add `Part of #1703` and link as the S2 deliverable.
2. **#1434 — relabel as #1703 S4/S5 (config surface + multi-peer/responder).**
   Comment: nothing to "restore" on master; this is net-new work that depends on
   S2 (single-tunnel datapath) landing first. Sequence after S2.
3. **#1389 — keep as the broad edge-gateway umbrella; annotate.** Comment: its
   Phase-5 WireGuard work is delivered by the #1703 S-step chain (userspace-dp
   engine), NOT by the stale kernel-WG+veth recommendation in
   `docs/vpp-dataplane-assessment.md:716-849`; mark that recommendation
   superseded. #1389 *consumes* #1703; it must not spawn a parallel WG impl.
4. **#1703 — record the consolidation** in the umbrella: S2 = #1432
   (re-scoped); S4/S5 absorb #1434; #1389 depends-on, does not duplicate.

### 5.3 The S2 scope boundary (so the next /engineer has a clean target)

**S2 IN scope** (one tunnel, initiator-first, v4-first, matching #1703 S2 +
S1 §3.5 deferrals):
- Hydrate the runtime `TunnelEndpoint` (`types/forwarding.rs:156`) from the
  already-landed `Wg*` snapshot DTO fields; add `mode == "wireguard"` handling.
- A control-thread **UDP socket** layer that binds `wg_listen_port`, drives the
  S1 `create_initiation`/`consume_response`/`consume_initiation_create_response`
  handshake methods, and pumps transport records. (NOT on the AF_XDP poll
  worker — S1 §7 invariant: handshake crypto is control-thread only.)
- **Egress encap** wiring at the three `match endpoint.mode` sites
  (`frame/mod.rs:212`, `frame/tcp_segmentation.rs:309`, `tunnel.rs:189`) →
  `wg_engine.try_encap(...)`.
- **Ingress decap** wiring at the poll_descriptor classifier for
  `UDP/<listen_port>` → `wg_engine.try_decap(...)` + AllowedIPs inner-src gate.
- **The live kernel-WireGuard-on-VM interop test** (S1's deferred independent-
  peer proof): Debian-13 incus VM, mlx1 vlan-3667 VF, `10.0.61.103`, both
  directions handshake-complete + one transport-record round-trip. Verify a free
  mlx1 VF at provision time.
- DF/PMTUD/MSS-clamp wiring on the WG path (`wg/mss.rs` already correct, just
  unwired); document "no userspace IP reassembly" (S1 research bonus gap).

**S2 OUT of scope** (stays in later S-steps — prevents S2 from sprawling):
- Multiple WG interfaces / port-keyed engine map / per-interface keys (**#1434
  → S4/S5**).
- Junos `wireguard` config grammar + Go compiler + base64↔hex (**S4**; #1432's
  migrated open item).
- WG CLI (`generate-private-key`, `show security wireguard`) (**S4/S5**; #1434).
- persistent-keepalive timer emit, REKEY/REJECT-AFTER timers, endpoint
  re-resolution/roaming, empty-record (keepalive/key-confirm) acceptance
  (**S3/S5**).
- Non-zero PSK plumbing (**S5**); cookie-reply type-3 + IPv6 outer + DSCP/ECN
  (**S7**); HA RG WG-session migration + TAI64N disk persistence (**S6/S8**).
- Transport-flow saturation / CoS-iperf3 throughput targets + any "high-
  performance" benchmarking (**later/optional, likely-KILL standalone**).

### 5.4 Why NOT a third track (the user's stated fear)

Without this consolidation, opening "#1703 S2" fresh while #1432 sits open
labeled "implement WG in userspace DP (boringtun, done)" guarantees: (a) an
observer re-opens the boringtun path, or (b) #1434's "restore the CLI" spawns
config work before the datapath exists, or (c) #1389's kernel-WG+veth Phase 5
gets implemented in parallel with the userspace engine. Option A collapses all
three onto the single S-step ladder with one canonical S2 target = #1432
re-scoped.

---

## 6. Public API preservation

N/A — no code changes in this research. The S2 *implementation* (separate
`/engineer` run) must preserve all S1 `pub(crate)` signatures
(`create_initiation`/`consume_response`/`consume_initiation_create_response`/
`try_encap`/`try_decap`/`install_session`/`reconcile_peers`) and the landed
`Wg*` DTO field names/JSON tags (wire-compat with older daemons via
`#[serde(default)]`).

---

## 7. Hidden invariants the consolidation (and the eventual S2) must preserve

- **Handshake crypto is control-thread only** (S1 §7 / AGY r1 #2). S2's UDP
  layer + handshake driving must NOT run on the AF_XDP poll worker; the hot
  encap/decap path takes only `RwLock::read` on `peer.current`
  (`engine.rs:510-514`) — no `HandshakeState` build on the data path.
- **No hot-path allocation** (#1207/#946 discipline). S2 encap/decap must reuse
  the `WgWorkerScratch` `RefCell<Vec<u8>>` buffers (`scratch.rs:18-25`) per the
  clean-room plan — no `vec![]` per packet (that was clean-room defect #6).
- **TAI64N monotonicity** survives only in-process today; S2's restart runbook
  must flush the kernel peer's WG state (`ip link del/add wgref`) when xpf
  restarts, until S6 lands disk persistence (S1 §5.2).
- **Engine keys encap on `wg_peer_pubkey_hex`, NOT AllowedIPs LPM** (decap-only
  gate) — cryptokey-routing-safe; S2 wiring must not invert this.
- **Wire-compat DTO discipline** — the `Wg*` snapshot fields are
  `#[serde(default)]`; `wg_local_privkey_hex` is `skip_serializing` + redacted
  in Debug. S2 must keep both.
- **Consolidation must not orphan unique scope** — before relabeling #1434 to
  S4/S5, confirm its multi-instance/port-demux requirements are captured in the
  S4/S5 charter (they are net-new, so labeling, not closing).

---

## 8. Risk assessment

| Class | Level | Notes |
|---|---|---|
| Mis-dedup: closing/repurposing an issue that holds unique scope | **MED** | Mitigated by §4 table + §5.3 boundary: #1434's multi-instance scope is migrated (relabeled), not closed; #1389 stays open as the consumer umbrella. Nothing is closed-as-dup in Option A. |
| Hypothesis wrong (#1432 ≠ S2) | **LOW** | §4.1 hostile test confirms #1432's work description IS S2; the only correction (its perf framing ≠ a distinct step, and its Go/CLI items are S4) is encoded in §5.2/§5.3. |
| S2 scope sprawl if boundary is loose | **MED** | §5.3 IN/OUT list pins S2 to single-tunnel + live interop; multi-tunnel/config/CLI/PSK/perf are explicitly OUT. |
| Stale architecture leaks (kernel-WG+veth from #1389) | **LOW** | §5.2 action 3 annotates `vpp-dataplane-assessment.md:716-849` superseded; userspace-dp engine is the decided path. |
| Live-interop harness blocked (no free mlx1 VF) | **MED** | Inherited from S1 §5.4c; S2 must verify VF id ≥4 free or reuse a spare VM. This is an S2-implementation risk, surfaced here so the boundary names it. |
| Research touches production code | **NONE** | Read-only; deliverable is plan + issue edits. |

---

## 9. Test plan

This is a consolidation research — **no build/test of code**. Validation is:
- **Evidence audit** (done, §3): every "unwired" claim backed by a grep/read
  citation against `origin/master` @ 6198223c8 (WgEngine instantiation, encap
  call sites, Go Wg* population, mode==wireguard, UDP socket, CLI).
- **3-way hostile plan review** (Codex + AGY + Claude-SMR) on this doc — must
  converge that Option A is correct and the S2 boundary is sound, or propose a
  different structure.
- **No CoS/iperf smoke** — no datapath change. (The eventual S2 *implementation*
  PR carries the full live-interop + CoS-iperf smoke per the matrix.)

---

## 10. Out of scope (explicit)

- Implementing S2 (datapath wiring) — that is a separate `/engineer` run against
  the re-scoped #1432.
- Implementing S3–S8 (timers/roaming, config, responder/PSK, cookie/IPv6/DSCP,
  HA migration).
- Executing the issue edits — this research RECOMMENDS them; the operator/`/engineer`
  applies them. (Per /research contract: deliverable is the plan + verdicts +
  issue comment, not the GitHub mutations to other issues.)
- Any change to the S1-merged code.

---

## 11. Open questions for adversarial review (each invitable to a different structure)

1. **Is Option A (re-scope #1432 in place) right, or is Option B (close #1432 +
   fresh S2) cleaner** given #1432's body is substantially fiction (boringtun,
   absent design doc)? I argue A preserves history at equal cost to B's "strip
   the lies" edit. Kill A if carrying a fiction-laden tracker forward is judged
   worse than a clean close+open.
2. **Does #1432 carry a genuine distinct "high-performance" deliverable that
   belongs AFTER S2 (Option C)?** I argue NO (§4.1: crypto already vectorized;
   SIMD/perf precedent is PLAN-KILL). Counter-example wanted: a concrete WG
   userspace-dp hot-loop that would benefit from a dedicated perf issue.
3. **Should #1434 fold into S4/S5, or is multi-tunnel a fundamental S2
   requirement** (i.e. must S2 wire a port-keyed engine *map* from day one to
   avoid a painful single→multi refactor later)? I scope S2 single-tunnel; argue
   the engine's `sessions_by_local_index` demux already keys on receiver_index
   (not port), so single→multi is additive, not a rewrite. Kill if the
   single-instance assumption calcifies a wrong data structure.
4. **Is the S2 IN/OUT boundary (§5.3) correct** — specifically, does the live
   kernel-wg interop test belong in S2 (with the datapath) or should it be its
   own S2.5? S1 ratified it lands in S2 next to the UDP plumbing it shares; I
   keep that. Kill if the VM-harness surface is large enough to warrant its own
   step.
5. **Is anything OTHER than these four issues a hidden parallel WG track?** I
   checked: branches `wireguard-fresh-*`, `refactor/1441-wireguard-engine-
   modularize` exist but #1441 is a modularization refactor of the engine, not a
   datapath track. Confirm no fifth WG issue/PR is open that S2 would collide
   with.
6. **Does #1389's kernel-WG+veth recommendation need a stronger disposition than
   an annotation** — e.g. should `docs/vpp-dataplane-assessment.md:716-849` be
   edited in this research, or is a comment enough (no-code-in-research rule)?

---
