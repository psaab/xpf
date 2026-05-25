# #1524 — Multi-peer WG dispatch via allowed-ips LPM

Status: **DRAFT v1 — PLAN-KILL CANDIDATE — pending adversarial plan
review to confirm "premature; integration PR not shipped" verdict**

## TL;DR

#1524 asks for the dispatcher LPM lookup + commit-time overlap
validation + multi-peer encap tests that the **WireGuard integration
PR** must satisfy. The premise of this issue is that an integration
PR is open or imminent. On a full audit of `origin/master`
(commit `c5c52a14`, 2026-05-25), **no such integration PR exists**:

- `userspace-dp/src/afxdp/wg/` is internally-callable-only
  (`pub(crate)`). `try_encap` has **zero call sites** outside the
  `wg/` module — `grep -rn "try_encap" userspace-dp/src/` returns
  nothing from `tx/`, `forwarding/`, `frame/`, etc.
- `pkg/dataplane/userspace/`, `pkg/config/`, `proto/`, `cmd/`
  contain **zero references** to `wireguard`, `WireGuard`,
  `WgPeer`, `WgPub`, `wg_engine`. `snapshot.go` `buildTunnelEndpointSnapshots`
  has no WG-aware code path.
- `try_encap` is `pub(crate)` and called only from `wg::tests` —
  it is not even reachable from `crate::afxdp::tx::dispatch` (the
  predecessor #1438 cited `tx/dispatch.rs:578`, which no longer
  has a `try_encap` call; the clean-room rewrite intentionally
  decoupled the engine from the dispatcher pending integration).
- #1501 (engine follow-ups) is **closed**. Its body says
  explicitly: "Bucket B integration items... a separate
  integration PR will own them, not the post-merge cleanup PR."
  The only #1501 follow-up that has shipped is #1533 (A2: outer
  UDP cs=0 doc + regression gate). The integration PR has not
  been opened.
- No open PR matches "wireguard", "integration", or related
  terms (`gh pr list --state open --limit 100`).

#1524's own acceptance-criteria section is titled "(integration
PR must satisfy)". Without that integration PR existing, this
issue has no implementation target: there is no Go-side
dispatcher to teach LPM lookup, no Go-side config compiler call
site to teach overlap validation, no integration-test scaffold
to add an encap roundtrip to. The only thing that could land
today is **engine-only** work (extending `try_encap` to a
peer-less form), which by itself satisfies zero of the 6
acceptance criteria and risks committing to an API shape
before the integration layer's own constraints are known.

Per the triple-review skill's standing rules:

> **"Refactor: <Pattern>" issues that don't fit the codebase
> reality SHOULD be killed at plan time.** #946 Phase 2, #961
> PacketContext both died this way. Don't push through a
> wrong-target architecture.

And per the prompt that authorized this run:

> If the integration PR hasn't shipped: **PLAN-KILL with rationale
> "premature; revisit once integration PR closes"**

This plan documents the PLAN-KILL premise so both reviewers can
verify it from primary sources, then return PLAN-KILL or
PLAN-READY-FOR-PARTIAL with worked counter-evidence.

## Issue framing

#1524 says: "the dispatcher MUST: (1) look up the inner packet's
destination IP against the per-interface allowed-ips LPM trie,
(2) map the longest-prefix match to the owning peer's pubkey,
(3) pass that pubkey to `try_encap`, (4) reject (drop + counter)
if no peer covers the destination."

The acceptance criteria:

1. Dispatcher LPM lookup (engine-side OR integration-side; engine
   already has `AllowedIps`).
2. Single-peer fast path preserved.
3. No-match drop counter `wg_tx_no_peer_route`.
4. Commit-time overlap validation in Go config compiler.
5. Tests: 3-peer unit, overlap validation, integration encap
   roundtrip.
6. Operator docs.

The issue body explicitly frames criteria 1+2+3 as
"integration PR must satisfy" decisions — it leaves the
engine-vs-integration split as an open architectural question:

> "Implementation may live in the Rust engine (extend `try_encap`
> to a peer-less form that internally does LPM) OR in the
> integration-layer Go side (build a shared LPM, look up, pass
> pubkey). The engine already has `AllowedIps`; extending
> `try_encap` is the lower-coupling option."

That trade-off is **only resolvable in the presence of the
integration PR**: the cost of "extend `try_encap`" depends on
how the integration layer threads the inner packet to the
engine, and the cost of "Go-side parallel LPM" depends on
whether the Go config compiler already builds a per-interface
peer→prefix index. Neither side exists today.

## Honest scope/value framing

The WireGuard end-state value is real (multi-peer hub-and-spoke
is a first-class WG use case; kernel WG handles this via
`AllowedIPs` cryptokey routing). The problem #1524 names is
also real: without LPM dispatch, multi-peer interfaces would
either misroute (wrong peer's session) or require the
integration layer to track per-flow peer identity.

At present, the **absolute value of shipping engine-only
LPM-dispatch work today** is:

- 0 production users — no multi-peer WG interface can be
  configured (no Junos `interfaces stN unit X family inet
  address ... peer pubkey ... allowed-ips ...` parser exists).
- 0 tests exercise the integration boundary that #1524's
  acceptance criteria #1 hinges on (engine-vs-integration
  split), because the integration boundary itself has not been
  drawn.
- Risk of locking in a `try_encap_lpm`-style API shape that
  the integration PR has to fight against later. The
  integration PR may discover that **the Go-side LPM is the
  right home** (because the Go config compiler already needs
  the index for overlap validation in criterion #4), and the
  engine-side LPM becomes dead code immediately after it lands.

If reviewers conclude the perf gain is too small to justify the
churn, PLAN-KILL is an acceptable verdict. In this case the
"perf gain" is zero today (no integration path exists), so the
churn-vs-gain math is simply churn against zero.

## What's already shipped / partially batched

- `userspace-dp/src/afxdp/wg/engine.rs` — pubkey-explicit
  `try_encap(peer_pubkey: &[u8;32], inner_ip, out)` at line 500.
- `engine.rs:236` — `allowed_ips: AllowedIps` (the LPM
  structure already present on the per-interface table).
- `engine.rs:752` — `try_decap` already calls
  `table.allowed_ips.matches_for_peer(inner_src, peer_idx)` to
  enforce cryptokey-routing on the ingress side. The LPM trie
  is fully wired into the decap path; the encap path has not
  been wired because there is no caller.
- `userspace-dp/src/afxdp/wg/allowed_ips.rs` — the LPM
  implementation (longest-prefix match, peer-index→pubkey).
- `userspace-dp/src/afxdp/wg/peer.rs` — per-peer state with
  `allowed_ips: Vec<IpNet>` on the config side.
- Nothing else. No `pkg/config/` WG types, no `proto/xpf/v1/`
  WG messages, no `pkg/dataplane/userspace/snapshot.go` WG
  endpoint wiring, no `tx/dispatch.rs` WG encap call site.

## Concrete design — N/A (PLAN-KILL candidate)

The plan-kill premise is that there is **no design to commit to
today**. The decision between "engine-side `try_encap_lpm`" and
"Go-side parallel LPM" is the architectural pivot that #1524
poses, and neither answer is defensible without the integration
PR's constraints on the table.

If reviewers reject the PLAN-KILL and demand a partial-engine-
only shipment, a defensible scope would be:

- Add `try_encap_lpm(&self, inner_ip: &[u8], out: &mut [u8]) ->
  Result<EncapOutcome, EncapError>` to `engine.rs`. It would
  parse `inner_ip[0] >> 4` to discriminate v4/v6, extract the
  inner destination, call `self.allowed_ips.lookup(dst)` to get
  the peer index, resolve the peer's current session, and
  return `EncapOutcome` or `EncapError::NoPeerRoute`.
- Add `EncapError::NoPeerRoute` variant.
- Add a per-engine `tx_no_peer_route: AtomicU64` counter
  incremented on `NoPeerRoute`.
- Tests: 3-peer table with `10.0.0.0/16`, `10.1.0.0/16`,
  `10.2.0.0/16`; `try_encap_lpm` against `10.1.0.42` returns
  the peer-2 session; `try_encap_lpm` against `192.168.0.1`
  returns `NoPeerRoute` and increments the counter.
- This is ~200-300 LOC. It satisfies **0 of 6** acceptance
  criteria when scored by the issue body (criteria 1 says
  "the dispatcher resolves the target peer" — the engine is
  not the dispatcher; the dispatcher is the integration-layer
  caller, which does not exist). It satisfies "criterion 1
  *if* the integration layer chooses the engine-side option" —
  but the integration layer can't choose yet.

This partial shipment is what the issue itself flags as the
"lower-coupling option" — but the issue also says the choice
between engine-side and Go-side LPM is the integration PR's
decision. Shipping the engine-side path before the integration
PR is open is **pre-committing to one half of an
architecturally-open question**. That's the #946 Phase 2 /
#961 PacketContext anti-pattern this skill exists to prevent.

## Public API preservation

N/A — PLAN-KILL candidate; no API changes proposed.

If the partial-engine-only fallback is forced through (NOT
recommended): all current `engine.rs` `pub(crate)` API
preserved. New `try_encap_lpm` is additive. `try_encap` (the
explicit-peer form) stays unchanged for the single-peer fast
path.

## Hidden invariants the change must preserve

If forced to partial-engine shipment:

- **Cryptokey-routing safety:** the engine's existing comment
  at `try_encap` line 506-508 says "Cryptokey-routing safety:
  the forwarding decision tells us which peer to encrypt to.
  We do NOT consult AllowedIPs to pick a peer on egress."
  That comment exists because **the integration layer is
  supposed to do the forwarding decision**, and the engine
  trusts the integration layer's pubkey. Adding
  `try_encap_lpm` to the engine **violates this invariant** —
  the engine would now be the entity consulting AllowedIPs
  to pick a peer on egress.
  This is the **single biggest reason** for PLAN-KILL: the
  engine's current comment is documenting an architectural
  decision (egress peer selection happens upstream of the
  engine) that #1524's "extend `try_encap`" suggestion would
  reverse. The integration PR is the right place to decide
  whether to reverse that decision, because it sees both
  sides.
- Session reference semantics (`peer.current.read().clone()`)
  preserved.
- Replay-counter / nonce ordering preserved.
- No allocation in encap fast path (per #1499 r6 review).

## Risk assessment — 4-class table

| Class | Level | Notes |
|---|---|---|
| Behavioral regression risk | **HIGH** | Adding `try_encap_lpm` reverses the documented "engine does not consult AllowedIPs on egress" invariant. Integration PR may reject this design choice. |
| Lifetime / borrow-checker risk | LOW | Engine internals are well-typed; lookup is `&self`. |
| Performance regression risk | LOW | LPM is sub-microsecond; only called on egress encap path which is not a hot loop today (no integration). |
| Architectural mismatch risk | **HIGH** | This is the #946 Phase 2 / #961 PacketContext pattern: shipping code against an architectural premise (the integration boundary) that has not been validated by the actual integration code. |

## Test plan — N/A (PLAN-KILL candidate)

If forced to partial-engine shipment:

- `cargo test --release -p userspace-dp wg::` — all engine
  tests pass.
- New tests:
  - `try_encap_lpm_three_peer_lpm_resolves_correctly`
  - `try_encap_lpm_no_peer_match_returns_no_peer_route`
  - `try_encap_lpm_increments_tx_no_peer_route_counter`
  - `try_encap_lpm_single_peer_fast_path_matches_explicit`
- 5/5 flake on each new test.
- Smoke matrix: irrelevant — no integration path means iperf3
  smoke can't exercise the WG dispatcher.

## Out of scope (explicitly)

- Slow-path keepalive worker (#1501 B1, B2).
- Roaming endpoint update (#1501 B3).
- Responder peer-identification helper (#1501 B4).
- Junos config syntax for `interfaces stN unit X peer pubkey
  ... allowed-ips ...`. (This is integration PR scope.)
- Go-side `pkg/config/` types for WG. (Integration PR scope.)
- Go-side `pkg/dataplane/userspace/snapshot.go` WG endpoint
  wiring. (Integration PR scope.)
- Go-side `proto/xpf/v1/` WG messages. (Integration PR scope.)
- Operator docs for multi-peer dispatch semantics.
  (Belongs with the integration PR; doc-without-feature is
  vapor.)

## Open questions for adversarial review

Each invitable to PLAN-KILL.

1. **Is the integration PR for #1499 actually open or
   imminent?** Confirm or refute by `gh pr list --state open
   --limit 200 --search "wireguard OR integration OR WG OR
   keepalive"` and by walking `pkg/dataplane/userspace/`,
   `pkg/config/`, and `proto/`. If reviewers find evidence
   the integration PR exists or is imminent, the PLAN-KILL
   premise collapses and we should proceed with a real plan.
2. **Does engine-side `try_encap_lpm` violate the existing
   cryptokey-routing-safety invariant** in `engine.rs:506-508`
   ("we do NOT consult AllowedIPs to pick a peer on egress")?
   If yes, can the integration PR choose Go-side LPM and
   keep that invariant? If yes, shipping engine-side LPM
   now is premature.
3. **Can criterion #4 (commit-time overlap validation) ship
   without criteria #1, #2, #3?** I.e., can we ship a
   Go-only overlap validator today against a non-existent
   `pkg/config/` WG type? Answer: no, because there are no
   WG-aware config types to validate; criterion #4 depends
   on criteria 1-3.
4. **Is there value in shipping the engine-side `try_encap_lpm`
   as a speculative API ahead of integration?** Risk: the
   integration PR rejects the API shape and we have to
   rev/rip the work. Risk-benefit: same as #946 Phase 2
   (forecasting integration constraints without seeing them).
5. **Is the #1438 closure rationale still sound?** #1438 was
   closed as "concrete code paths no longer exist; concern
   survives in #1524." Does #1524 itself have the same flaw
   — concrete code paths don't exist yet either?
6. **What is the right artifact for #1524 right now?**
   Options: (a) close as duplicate of "open the integration
   PR" tracking, (b) PLAN-KILL with rationale "premature;
   re-open when integration PR has a draft branch", (c) ship
   engine-only partial work and accept rev risk. Reviewers
   please rank.

## Verdict requested

**PLAN-KILL — premature; revisit once integration PR opens
(or its draft branch exists with a WG-aware
`pkg/dataplane/userspace/snapshot.go` / `pkg/config/wg.go` /
`proto/xpf/v1/wg.proto` skeleton committed).**

If both reviewers concur, this plan is closed as PLAN-KILL,
#1524 receives a comment with the analysis, and the issue
either stays open as a tracker (awaiting integration PR) or
is closed as a duplicate of "open the integration PR".
