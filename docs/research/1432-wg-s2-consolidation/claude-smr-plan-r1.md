# Claude-SMR hostile plan review r1 — #1432 WG S2 consolidation

Reviewer: Claude (domain SMR: WireGuard protocol, AF_XDP userspace dataplane,
Rust, project issue-graph hygiene). HOSTILE pass per
`feedback_triple_review_includes_claude_smr`. I tried to break the
recommendation, not bless it.

Plan under review: `docs/research/1432-wg-s2-consolidation/plan.md` (v1 + the
two Codex-r1 fixes folded: S-step relabel, perf-item disposition).

## Claims I independently verified against origin/master @ 6198223c8

1. **Engine is snow-based, not boringtun.** `grep boringtun userspace-dp/
   Cargo.toml` → empty; `wg/engine.rs`/`framing.rs`/`session.rs` import `snow`.
   `docs/design/wireguard-support.md` absent (`find` empty). → #1432's `[x]`
   boringtun items ARE fiction vs master. **Confirmed; load-bearing for the
   whole dedup.**
2. **Engine is unwired.** `WgEngine::new` appears only in `wg/tests.rs` /
   `wg/engine.rs` / `handshake_session.rs:98` (the latter is `impl`, not a
   construction). `try_encap`/`try_decap` have zero call sites outside `wg/`.
   `poll_stages.rs` + `tx/dispatch.rs` carry no `wg` token. `afxdp/mod.rs:125`:
   "hot-path activation lands in a follow-up." **Confirmed.**
3. **Runtime `TunnelEndpoint` (types/forwarding.rs:156) is `#[allow(dead_code)]`,
   gre/ipip mode only, no Wg* fields.** The *snapshot* DTO has Wg* fields
   (`protocol/snapshot.rs:341-374` + `protocol.go:298-314`) but `grep "Wg[A-Z]"
   pkg/ | grep "="` is empty → Go never populates them, and there is no
   `mode=="wireguard"` in Go. **Confirmed — the chain is dead at BOTH the Go
   source AND the runtime-struct hydration. The plan's §3.3 phrasing is
   accurate.**
4. **S1 plan defers exactly the S2 charter.** `1709...plan.md` §10 + §5.4c defer
   datapath encap/decap + runtime TunnelEndpoint extension + the live
   kernel-wg-on-VM interop test (mlx1 vlan3667 VF, 10.0.61.103, VIP 10.0.61.1).
   **Confirmed.**
5. **S-step canonical ladder** — `docs/wireguard-interop.md:15-21`: S2=dataplane
   activation+live interop, S4=PSK, S5=timers/roaming/persistence, S6=Junos
   config, S7=cookie/IPv6/DSCP, S8=HA; **no S3.** The plan v1 had this wrong
   (Codex caught it); the folded fix now matches. **Confirmed the fix is
   correct.**

## Hostile findings

### F1 (MINOR, already folded) — S-step mislabel.
Caught by Codex; the plan now carries the canonical ladder block and routes
#1432's config/CLI items to S6, PSK to S4, timers to S5. Verified the fixed
text against `wireguard-interop.md`. **Resolved.**

### F2 (MINOR, already folded) — perf-item must be preserved, not "likely-KILL"d.
Caught by Codex; folded as "post-S2 measured validation; dedicated perf item
only on a measured bottleneck." This is the correct disposition and is
consistent with the #966–#969 KILL precedent (which killed *unmeasured*
speculative SIMD, not measurement-gated perf). **Resolved.**

### F3 (MINOR) — the §5.3 "no userspace IP reassembly" item is an interop HAZARD, not just a doc note.
The plan lists "document 'no userspace IP reassembly'" as an S2 IN item
(§5.3, inherited from the S1 research bonus gap). I pushed on whether this is
merely cosmetic. It is not purely cosmetic for a *client/initiator to UniFi*
path: a full-tunnel `AllowedIPs=0.0.0.0/0` peer pushing 1500-MTU inner traffic
over a ~1420 WG tunnel will fragment the OUTER UDP datagram on an over-PMTU
path, and a fragmented inbound WG datagram is undecryptable without reassembly
→ silent black-hole that looks like an interop failure. **This does not change
the issue structure** (it is correctly an S2-implementation concern, and the
MSS-clamp wiring already in §5.3 IN mitigates the common TCP case), but the
plan should state explicitly that S2's live-interop acceptance MUST include a
full-tunnel (0.0.0.0/0) case that pushes >MTU inner traffic, so the
no-reassembly limitation is *observed and bounded*, not just documented. This
is a one-line strengthening of the S2 acceptance, not a structural change.
**Recommend folding; not blocking.**

### F4 (verified NOT a defect) — does the single-tunnel S2 calcify a wrong data structure?
This was my strongest attack on the structure (the #761/#964-step-3 class:
a data-structure decision that's painful to reverse). I read the demux path:
`engine.rs:177-182` (single `listen_port` field) and `session.rs:62-69` /
the `sessions_by_local_index` map keyed on **receiver_index**, not
`(port,index)`. Multi-tunnel (#1434) adds a *port→engine* selection layer
ABOVE the socket, and each engine keeps its own receiver-index demux. So
single→multi is **additive** (a `HashMap<u16, WgEngine>` wrapper + per-port
UDP bind), NOT a rewrite of the in-engine demux. The plan's §11 Q3 reasoning
is correct. **The single-tunnel S2 boundary does NOT calcify a wrong
structure.** This is the key reason Option A's scope split is safe.

### F5 (verified NOT a defect) — is #1389 orphaned?
#1389 Phase 5's kernel-WG+veth recommendation is genuinely superseded by the
userspace-dp engine, and its other 5 features (multi-WAN/DNS/DDNS/PBR/smart-
queueing) are out of WG scope entirely. Annotating #1389 as a consumer umbrella
orphans nothing — its WG ask is *satisfied by* the #1703 chain. **Confirmed.**

### F6 (NIT) — Option B's cost is slightly understated.
The plan says Option B "loses the #1432 backlink/discussion." Minor add: Option
B also breaks any external references to #1432 as "the WireGuard issue" (it is
the most-discoverable WG issue by title). Option A's edit-in-place keeps that
discoverability. This *strengthens* Option A; worth a half-sentence but not
blocking.

## Where I tried to force a different structure and failed
- **Option B (close+fresh):** rejected — Option A achieves B's only real benefit
  (strip fiction) via an in-place edit, at lower churn, preserving
  discoverability (F6).
- **Option C (#1432=later perf):** rejected — F4 + the #966–#969 precedent show
  there is no distinct perf deliverable to defer; C would create the empty
  parallel track the user fears.
- **"Multi-tunnel must be IN S2":** rejected by F4 (additive, not a rewrite).

## Verdict

**VERDICT: PLAN-NEEDS-MINOR (r1).** Option A is correct and survives a hostile
attempt to find a better structure; the two Codex findings (S-step relabel,
perf preservation) are real and already folded; F3 (full-tunnel >MTU case in S2
acceptance) and F6 (discoverability) are one-line strengthenings. No structural
defect, no orphaned scope, no calcified data structure. Fold F3/F6 and this is
PLAN-READY.
