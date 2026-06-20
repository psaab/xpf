# Plan of Action — #2078: rst-invalidate-session / no-syn-check / no-syn-check-in-tunnel enforcement on the userspace dataplane

- **Issue:** #2078 (audit-verified, severity LOW)
- **Revision:** r1 (initial draft for hostile review)
- **Branch:** `research/2078-tcp-state-enforcement`
- **Status:** DRAFT — awaiting 3-way hostile plan review (Codex + AGY + Claude SMR)
- **Mode:** /research — STOPS at PLAN-READY or PLAN-KILL. No code, no PR.

---

## 1. Problem statement

Three Junos `set security flow tcp-session` knobs are parsed and committed
but enforce **nothing** on the live userspace dataplane:

- `rst-invalidate-session` — a valid in-window TCP RST should immediately
  tear down the matching session.
- `no-syn-check` — disable the (normally-on) rule that a TCP session may
  only be *created* by a SYN; with it set, a mid-stream non-SYN packet may
  open a new session.
- `no-syn-check-in-tunnel` — same as `no-syn-check` but scoped to traffic
  arriving inside a tunnel.

### What exists today (verified against source)

| Layer | State | Evidence |
|---|---|---|
| Junos parse → typed config | WIRED | `pkg/config/compiler_security.go:571-577` sets `NoSynCheck`, `NoSynCheckInTunnel`, `RstInvalidateSession` on `TCPSessionConfig` (`pkg/config/types_security.go:114-116`). |
| Legacy eBPF compile | DEAD | `pkg/dataplane/compiler.go:1069-1080` packs these into `FlowConfigValue.TCPFlags` (`pkg/dataplane/maps_flow.go:24`) and calls `dp.SetFlowConfig(fc)` (`compiler.go:1106`). In the userspace path `SetFlowConfig` resolves to the no-op stub `userspaceShimCompileDataplane.SetFlowConfig` (`pkg/dataplane/loader.go:392` → `return nil`). The `flow_config_map` eBPF map is the retired dataplane (#1373/#1476). **The flags are written to a dead map.** |
| Userspace `FlowSnapshot` (Go) | ABSENT | `pkg/dataplane/userspace/protocol.go:97-110` — no `NoSynCheck`/`RstInvalidateSession`/`NoSynCheckInTunnel` fields. `buildFlowSnapshot` (`flow.go:5-22`) never reads them. |
| Userspace `FlowSnapshot` (Rust serde) | ABSENT | `userspace-dp/src/protocol/snapshot.rs:137-162` — no matching serde fields. |
| Rust dataplane TCP-state logic | ABSENT (mostly) | No syn-check on create; no in-window RST validation. See §2. |

### The crucial finding that makes this research-first

This is **not** a config-wiring bug. Even after wiring the flags through the
snapshot, the Rust dataplane has **no TCP state machine** to enforce them
against. The session table is a pure 5-tuple flow entry. So enforcement
requires **new dataplane behavior**, and the central question is *how much*.

---

## 2. Current Rust TCP/conntrack state (verified)

Source: `userspace-dp/src/session/`, `userspace-dp/src/afxdp/`.

**Session entry is a flow entry, not a TCP connection.**
`SessionEntry` (`session/mod.rs:108-122`): `decision, metadata, origin,
install_epoch, last_seen_ns, expires_after_ns, closing: bool, wheel_tick`.
`SessionKey` (`session/key.rs:10-17`): `{addr_family, protocol, src_ip,
dst_ip, src_port, dst_port}` — pure 5-tuple. **No seq/ack/window, no TCP
state enum.** (`SESS_STATE_ESTABLISHED` in `afxdp/bpf_map/mod.rs:442` is a
display-only export to the BPF conntrack HASH map for `show` commands, not
dataplane logic.)

**Session creation has no SYN gate.**
`install_with_protocol_with_origin` (`session/mod.rs:748-815`) receives
`tcp_flags: u8` but only uses them to compute the timeout
(`session_timeout_ns`, `mod.rs:1587`) and to set `closing` on FIN|RST. **Any
packet that misses the table and reaches a forward decision installs a
session** — there is no `tcp_flags & SYN` requirement. Install call sites:
`poll_descriptor/mod.rs:487, 1318, 1520, 2641`.

**RST/FIN already shorten the timeout — but do NOT tear down.**
`lookup_with_origin` (`session/mod.rs:633-657`): on a TCP packet with
FIN|RST it sets `entry.closing = true` and shortens `expires_after_ns` to
`TCP_CLOSING_TIMEOUT_NS = 30s` (`mod.rs:27`). The session is **not** removed
immediately; it ages out via the timer wheel after 30s. Constants:
`TCP_FIN = 0x01`, `TCP_RST = 0x04` (`mod.rs:97-98`).

**No sequence/window validation anywhere.** No `snd_nxt`/`rcv_nxt`/window
fields exist in any session structure.

**TCP flags are FREE on the fast path.** `meta.tcp_flags` is a fixed field
(`afxdp/types/mod.rs:118`) in the 96-byte `#[repr(C)] UserspaceDpMeta` the
BPF shim writes per packet (compile-time-asserted layout, `types/mod.rs:132`).
The Rust fast path reads it already (`session_timeout_ns`, `closing`
computation, MSS-clamp path proves the TCP header is also located). **A
per-packet flag test adds no new parse and no allocation.** There is also a
raw-frame fallback `extract_tcp_flags_and_window` (`afxdp/frame/tcp.rs:80-109`)
used for tunnel-decap and telemetry cross-check.

**HA wire already carries `tcp_flags`.** `SyncedSessionEntry`
(`afxdp/worker/mod.rs:278-285`) carries `protocol: u8` + `tcp_flags: u8`
across the cluster sync wire (`afxdp/session_delta.rs`). The `closing` bool
is recomputed locally per-worker on lookup, not synced.

**Config flag flow seam (existing pattern).** Go `snapshot.flow.<x>` →
Rust `state.<x>` in `afxdp/forwarding_build/mod.rs:173-199` (e.g.
`state.allow_dns_reply = snapshot.flow.allow_dns_reply`), with the flag
living on `ForwardingState`. New flags follow this exact one-line pattern.

---

## 3. Gap analysis — what each knob requires vs what exists

| Knob | Junos semantics | What the dataplane must do | Distance from today |
|---|---|---|---|
| **no-syn-check** (default OFF, i.e. syn-check ON) | Drop a non-SYN TCP packet that would *create* a new session; only a SYN opens a session. With knob ON, allow mid-stream create. | At the session-miss → install boundary, if `protocol==TCP && !(tcp_flags & SYN) && syn_check_enabled` then **do not create + drop** the packet (count it). | SMALL — one branch at the install boundary; flags already present. **But:** changes default behavior (see §5 RISK-1). |
| **rst-invalidate-session** (default OFF) | A valid in-window RST tears the session down *immediately*. | On a TCP packet with RST that hits a session, if knob ON: remove the session now (instead of only shortening to 30s). "Valid/in-window" requires seq tracking we do not have. | SMALL (without seq check) / LARGE (with true in-window check). |
| **no-syn-check-in-tunnel** (default OFF) | Same as no-syn-check but scoped to tunnel-ingress traffic. | Same branch as no-syn-check, gated additionally on "packet arrived via tunnel decap". | SMALL — `metadata.fabric_ingress`/tunnel-decap context already exists; one extra condition. |

**Semantic subtlety (Junos):** the SYN gate normally accepts a session only
on the initiating SYN. The vSRX also normally accepts the SYN-ACK on the
*reverse* path of an already-installed forward session — that reverse install
must NOT be blocked by syn-check (it already has the forward session as
context). Our reverse-flow install (`ReverseFlow` origin, `mod.rs:491`,
call site `poll_descriptor/mod.rs:487`) is a *distinct* path from the
client-initiated forward miss; the syn-check gate must apply **only to the
client-initiated forward-create path**, not to reverse/NAT-reply installs.
This is the single most important correctness constraint and the main reason
this is a state-machine design, not a one-liner.

**"In-window" for rst-invalidate:** real Junos validates the RST sequence
against the expected window before honoring it (anti-spoof — an off-window
RST is ignored). We have **zero** sequence state. Honoring *any* RST in the
matching 5-tuple is weaker than Junos but still strictly safe-direction
(tearing down on a spoofed in-tuple RST is a DoS vector — see RISK-2).

---

## 4. Wire-protocol additions (HA/upgrade-safe)

Identical mechanism for all path options that ship anything.

**Go side** (`pkg/dataplane/userspace/protocol.go` `FlowSnapshot`, +
`pkg/dataplane/userspace/flow.go` `buildFlowSnapshot`):

```go
// FlowSnapshot additions
NoSynCheck           bool `json:"no_syn_check,omitempty"`
NoSynCheckInTunnel   bool `json:"no_syn_check_in_tunnel,omitempty"`
RstInvalidateSession bool `json:"rst_invalidate_session,omitempty"`
```
`buildFlowSnapshot` reads them from `cfg.Security.Flow.TCPSession` under the
existing `if cfg.Security.Flow.TCPSession != nil` guard (`flow.go:18`).

**Rust side** (`userspace-dp/src/protocol/snapshot.rs` `FlowSnapshot`):
```rust
#[serde(rename = "no_syn_check", default)]            pub no_syn_check: bool,
#[serde(rename = "no_syn_check_in_tunnel", default)]  pub no_syn_check_in_tunnel: bool,
#[serde(rename = "rst_invalidate_session", default)]  pub rst_invalidate_session: bool,
```

**Upgrade/HA safety (the #1961 wire-parity class).** #1961 was the
Go-marshals-`[]uint8`-as-base64 vs Rust-expects-`Vec<u8>` decode break that
EOF'd the whole snapshot → `enabled:false` → no transit. The lesson: a wire
mismatch on *one* field fails the *entire* `apply_snapshot` decode. Here the
risk class is low because:
- Go `bool` ↔ Rust `bool` is a primitive JSON `true`/`false` — no
  numeric-width or container-type ambiguity (unlike #1961/#1977).
- `omitempty` (Go) + `#[serde(default)]` (Rust) means: old daemon → new
  helper omits the field → Rust defaults to `false` (= current behavior,
  syn-check enforcement only-when-requested, which is correct since the
  feature is opt-out-of-default for no-syn-check and opt-in for the others);
  new daemon → old helper, the old helper ignores unknown fields (serde
  default behavior for the existing decode) → no break.
- This must be covered by a Go↔Rust round-trip decode test (see §7), and a
  reflection-parity guard if the project has one for `FlowSnapshot` (it does
  for the #1977 NUM_WIDTH siblings — confirm and extend).

**Default-semantics gotcha (call out in review):** `no_syn_check` is a
*disable* knob — Junos default is syn-check ON. But `false` on the wire must
mean "syn-check enforced". Since we are *introducing* syn-check enforcement
that never existed, shipping it as "enforced by default" is a **behavior
change for every existing deployment** (RISK-1). The wire default (`false`
→ "do not set no_syn_check" → "syn-check ON") is the Junos-correct default
but is NOT the current xpf behavior. Path B/C address this.

---

## 5. Hot-path cost

The per-packet additions for the minimal scope (syn-check + RST-teardown):

- **syn-check:** at the forward-create miss path only (not per forwarded
  packet — only on session *miss*, already the cold/install path). Cost: one
  `tcp_flags & SYN` test + a config bool, both already in registers. Negligible
  and **off the steady-state hot path** (miss path runs once per flow).
- **rst-invalidate:** on the session-*hit* path for TCP packets, `lookup`
  already computes `(tcp_flags & (TCP_FIN|TCP_RST))` (`mod.rs:633`). Adding
  "if RST && rst_invalidate_session: remove now" is one extra predictable
  branch on the existing RST arm. Config-time bool → branch-predictor-free
  per `docs/engineering-style.md:180-183`. No new allocation, no new parse.

This satisfies the hot-path discipline: no allocations, config-time booleans,
account-don't-unwind (the syn-check drop bumps a counter and continues).

**If true in-window seq validation were added (Path A):** that requires
per-session `snd_nxt`/`rcv_nxt`/window state updated on *every* forwarded
TCP packet — a real per-packet write to the session entry on the hot path,
plus the entry grows and the HA-sync wire grows. That is the expensive option.

---

## 6. Path options

### Path A — Full TCP state machine
Add `snd_nxt/rcv_nxt/window` + a state enum to `SessionEntry`; validate
RST/SYN against window; sync the new state across HA.
- **Pro:** true Junos parity incl. real in-window RST and proper mid-stream
  detection.
- **Con:** per-packet seq/window writes on the hot path; `SessionEntry` and
  `SyncedSessionEntry` grow (HA wire + memory per session); large surface,
  high regression risk on a forwarding fast path that currently does zero
  seq tracking. **Cost wildly disproportionate to two LOW-severity, rarely
  used vSRX knobs.**
- **Verdict:** REJECT. Out of proportion.

### Path B — Minimal: syn-check + RST-immediate-teardown (NO seq validation)  ← recommended-if-ship
Wire the three flags (§4). Enforce:
- `no-syn-check` / `no-syn-check-in-tunnel`: gate the **forward-create**
  install path (not reverse/NAT-reply installs) on `tcp_flags & SYN`,
  dropping+counting a non-SYN create when syn-check is active and the knob
  is not set. `no-syn-check-in-tunnel` widens the allow to tunnel-ingress.
- `rst-invalidate-session`: on the existing RST arm in `lookup`, if the knob
  is set, remove the session immediately instead of shortening to 30s. RST is
  honored for any packet matching the 5-tuple (no window check — documented
  as weaker-than-Junos but safe-direction; mitigated by RISK-2 note).
- **Pro:** small, hot-path-cheap, matches the operator-visible behavior of
  the knobs for the common case; reuses existing `tcp_flags`/`closing` plumbing.
- **Con:** rst-invalidate without window check is spoofable (RISK-2);
  syn-check-on-by-default is a behavior change (RISK-1) unless gated.
- **Open decision for review:** does syn-check ship **enforced-by-default**
  (Junos-correct, behavior change) or **only-active-when explicitly
  configured** (safer rollout, deviates from Junos default)? Recommendation:
  ship syn-check enforcement gated so that it is a **no-op unless the
  operator has the tcp-session stanza configured at all**, OR ship it
  default-on but behind the existing config and call it out loudly in
  release notes + docs. Reviewers must converge on this.

### Path C — PLAN-KILL / defer
Do nothing in the dataplane. Options within C:
- C1: pure-doc — document that these knobs are accepted-but-not-enforced
  (a known vSRX-parity gap), keep the legacy dead write or remove it, file
  a parity-gap note. Zero dataplane risk.
- C2: as C1 **plus** make the config compiler emit a commit-time *warning*
  ("rst-invalidate-session is accepted but not enforced on this dataplane")
  so operators are not silently misled — matches the project's
  accepted-but-warned pattern for unimplemented knobs.
- **Rationale:** these are rarely-used knobs, LOW severity; the audit itself
  rated this LOW. The risk of *silently misleading* an operator (knob set,
  not enforced) is the real harm, and C2 removes that harm at near-zero risk.

### What gets removed regardless
The dead `flow_config_map`/`SetFlowConfig` TCPFlags packing
(`compiler.go:1069-1080`, `maps_flow.go:24`) writes to a retired map. If we
ship Path B it becomes redundant; if we ship Path C it is misleading dead
code. Either way: **remove the dead TCPFlags write** (or, at minimum,
comment it as retired) — but ONLY as part of whichever path ships, and only
after confirming nothing else reads `FlowConfigValue.TCPFlags`.

---

## 7. Test + smoke plan (applies to Path B; Path C is doc/unit only)

**Rust unit/integration:**
- syn-check: forward-miss with non-SYN TCP + syn-check active → no session
  installed + drop counter increments; with `no_syn_check` set → session
  installed. Reverse/NAT-reply install with non-SYN (SYN-ACK) must still
  succeed (the critical §3 constraint).
- no-syn-check-in-tunnel: tunnel-ingress non-SYN creates only when the
  in-tunnel knob is set, not when only the global knob differs.
- rst-invalidate: session present, RST packet hits → with knob set the entry
  is gone immediately (lookup returns miss next packet); without knob, entry
  persists with 30s closing timeout (current behavior preserved).
- HA-wire: `FlowSnapshot` Go→JSON→Rust round-trip decode test asserting the
  three new bools decode (the #1961/#1977 wire-parity guard); old-helper
  forward-compat (unknown field ignored) + old-daemon back-comp (omitted →
  `false`).

**Go unit:** `buildFlowSnapshot` carries the three flags from
`TCPSessionConfig`; nil-`TCPSession` guard preserved.

**Loss-cluster smoke (REQUIRED at /engineer time — this is hot-path/dataplane):**
- `make cluster-deploy` to `loss:xpf-userspace-fw0/fw1`; re-apply CoS
  (`apply-cos-config.sh` — deploy wipes CoS).
- Sustained iperf3 v4+v6 through `reth0.80` target `172.16.80.200` (NOT
  172.16.100.x) both directions, baseline vs with-knobs, confirm no
  throughput regression (syn-check is miss-path; rst is one branch).
- `make test-failover` (MANDATORY — touches session/forwarding hot path):
  must pass 14/0 with the new `tcp_flags`-gated logic and the (unchanged)
  HA wire.
- Functional: with `rst-invalidate-session`, send a flow, RST it, confirm
  `show security flow session` shows immediate teardown vs 30s closing
  without the knob. With syn-check, confirm a mid-stream non-SYN flow is
  dropped (and allowed with `no-syn-check`).

---

## 8. Risks

- **RISK-1 (behavior change):** introducing syn-check enforcement changes
  default forwarding for every existing deployment that today silently
  accepts mid-stream TCP. Mitigation: gate the rollout (see Path B open
  decision); release-note + doc it; the loss-cluster smoke must include a
  pre-existing-flow continuity check.
- **RISK-2 (spoofable RST without window check):** honoring any in-tuple RST
  is a teardown DoS vector if an attacker can guess the 5-tuple. Junos
  mitigates with the window check we lack. Mitigation: document the
  limitation; note that `rst-invalidate-session` is operator-opt-in (default
  off) so the operator accepts this tradeoff by enabling it; do NOT enable by
  default.
- **RISK-3 (reverse-path false drop):** if syn-check wrongly applies to the
  reverse/NAT-reply install path, legitimate SYN-ACK / mid-stream reply
  sessions break. Mitigation: gate strictly to the client-initiated
  forward-create path; explicit test (§7).
- **RISK-4 (wire decode break):** a malformed new field could EOF the whole
  snapshot (#1961 class). Mitigation: bool/serde-default is the low-risk
  subclass; round-trip + parity-guard test.
- **RISK-5 (dead-code removal scope creep):** removing the `flow_config_map`
  TCPFlags write could touch the retired-dataplane surface. Mitigation:
  confirm no remaining reader of `FlowConfigValue.TCPFlags`; do it only
  inside the shipping path.

## 9. Files touched (if Path B ships)

- `pkg/dataplane/userspace/protocol.go` — 3 `FlowSnapshot` fields.
- `pkg/dataplane/userspace/flow.go` — `buildFlowSnapshot` reads them.
- `userspace-dp/src/protocol/snapshot.rs` — 3 serde fields.
- `userspace-dp/src/afxdp/forwarding_build/mod.rs` — `state.* = snapshot.flow.*`.
- `userspace-dp/src/afxdp/forwarding/mod.rs` (or `ForwardingState` def) — 3 bools.
- `userspace-dp/src/session/mod.rs` — syn-check gate (install boundary) +
  rst-invalidate teardown on the RST arm; new drop/teardown counters.
- `userspace-dp/src/afxdp/poll_descriptor/mod.rs` — pass the syn-check
  context into the forward-create install call (NOT reverse-install call).
- `pkg/dataplane/compiler.go` / `maps_flow.go` — remove/retire the dead
  `TCPFlags` write.
- Docs: `pkg/dataplane/README.md` / flow docs + a parity note; release note
  for the syn-check default decision.
- Tests per §7.

## 10. Recommendation

**If shipping: Path B (minimal syn-check + RST-immediate-teardown, no seq
validation), with syn-check rollout gated per the §6 open decision.**
Rationale: it is hot-path-cheap (flags already on the fast path; no
allocations; config-time-predictable branches), reuses the existing
`tcp_flags`/`closing` plumbing, and delivers the operator-visible behavior
of all three knobs for the common case at a small, well-bounded surface.
Path A (full TCP state machine) is rejected as wildly disproportionate to
two LOW-severity rarely-used knobs.

**However, the honest framing is that Path C2 (warn-and-document) is a
defensible PLAN-KILL** given the LOW severity and that the *real* harm today
is silent misleading, not a forwarding bug. The single most important harm —
"operator sets the knob and believes it works" — is removed by C2 at
near-zero risk. Reviewers should explicitly choose B-vs-C2 with cost/benefit,
and may converge on PLAN-KILL-with-C2-followup as a legitimate outcome.

## 11. Open questions for reviewers (must converge)

1. **Ship at all?** B vs C2 — is enforcing two rarely-used LOW knobs worth
   any hot-path/forwarding-path risk, vs warn-and-document?
2. **syn-check default:** enforced-by-default (Junos-correct, behavior
   change) or only-when-configured (safe, non-Junos default)?
3. **rst-invalidate without window check:** acceptable as a documented
   weaker-than-Junos behavior given it is opt-in and default-off?
4. **Dead-code:** remove the `flow_config_map` TCPFlags write now, or leave
   it (retired) and only stop relying on it?
