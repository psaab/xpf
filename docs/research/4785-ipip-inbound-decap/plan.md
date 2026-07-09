# Plan-of-Action — #4785 IPIP (proto-4) inbound decap unimplemented (userspace-dp feature/parity gap)

- **Revision:** r1 (pre-review)
- **Issue:** #4785 — residual of the #4478 `/research` (PLAN-KILLed the security
  framing; this is the fail-CLOSED feature-completeness residual).
- **Mode:** `/research` — deliverable is a converged plan + reviewer verdicts.
  NO PR, NO production code changes.
- **Base:** origin/master `9e30255de`
- **Reviewers:** Codex + Claude-SMR (2-of-3; AGY/gemini infra-down this session).
  Copilot joins at `/engineer` if this ever ships.
- **Reference design:** `docs/research/4478-ipip-decap-zone/plan.md` §5 (Path
  B/C/E), on branch `research/4478-ipip-decap-zone`. This plan STARTS from that
  design and corrects two premises that reshape the recommendation.

---

## 0. VERDICT (r1, pre-review): PLAN-DEFER — demand-gated, NOT "#1864-gated"

**Recommendation: PLAN-DEFER.** Do not ship an IPIP forwarding path now. IPIP
inbound (and, per Finding-2 below, outbound) is a **niche, fail-closed,
never-worked** vSRX parity gap with **zero demonstrated operator demand**. The
complete fix is a **large hot-path effort** — a new userspace-dp IPIP
**encap + decap** engine PLUS a **novel "Go writes `USERSPACE_SESSIONS`"
HA-ownership boundary** — disproportionate to the value while nothing depends on
it. Defer until a real operator requirement materializes; keep the issue OPEN
and ready (Path B below is the viable implementation when demand appears).

This plan **corrects the task's "defer until #1864 unblocks Path C" framing**,
which rests on a stale premise (Finding-1): **#1864 is CLOSED** and did **not**
unblock Path C. The defer is therefore **demand-gated**, not blocker-gated.

Two research findings drive the verdict beyond the #4478 appendix:

- **Finding-1 — #1864 is CLOSED and does not unblock Path C.** #1864
  (`COMPLETED` 2026-06-11) was resolved by **pinning the BPF toolchain + adding
  a load guard**, NOT by reclaiming verifier budget. The `userspace-xdp` shim
  remains at/near the **1,000,000 processed-insn** verifier ceiling with **no
  headroom** and **no open issue tracking budget reclamation**. So Path C
  (`native_ipip` shim redirect, which ADDS insns) is blocked by a **standing
  architectural ceiling**, not a temporary tracked blocker. "Defer until #1864"
  = defer to an event that already happened and did not help.
- **Finding-2 — IPIP is non-functional in BOTH directions.** The #4478 §5/§6
  appendix says "IPIP egress stays on the kernel `Iptun`." That is **false**
  under the anchor-only reality the same plan's §0 established: in the userspace
  dataplane every tunnel is `AnchorOnly=true` → a `netlink.Tuntap` routing
  anchor; **there is no kernel `Iptun`**. An egress inner packet routed to the
  IPIP anchor resolves `tunnel_endpoint_id != 0`, hits the egress dispatcher
  (`frame/mod.rs` L399-404), classifies `tunnel_mode_kind("ipip") ==
  TunnelKind::Unknown`, and is **DROPPED** (`None`, fail-closed). So the true
  scope to make IPIP a *working* feature is full GRE parity — **encap (egress) +
  decap (inbound) + steering** — not just "mirror the GRE inbound decap stage."
  A decap-only Path B would ship a half-feature (inbound decaps, return traffic
  drops).

**This is PLAN-DEFER, not PLAN-KILL.** The gap is a legitimate Junos `ip-in-ip`
parity feature that CAN be implemented via Path B (§5) with no verifier
dependency. It stays open, ready, demand-gated. §5 records the concrete design
so a future `/engineer 4785` can start immediately.

---

## 1. Status

Code study is complete against origin/master `9e30255de`. Every line-number
claim below was re-verified on current master (the #4478 plan was written
against `4eb28ae25eb8`; the architecture is intact, offsets shifted). The
recommendation is a **posture/priority call**, not a correctness blocker: Path B
is mechanically viable; the question is whether the value justifies the churn
now. This plan argues it does not, yet.

---

## 2. Issue framing

`set …tunnel … mode ipip` (`pkg/config/types_routing.go`) parses and commits;
the daemon creates the tunnel anchor (`AnchorOnly=true` in userspace mode →
`netlink.Tuntap`, `pkg/routing/tunnel.go` `applyAnchorLocked`); and the endpoint
reaches the userspace-dp snapshot with its zone + ifindex
(`buildTunnelEndpointSnapshots`, `pkg/dataplane/userspace/tunnels.go` L123-130
copies `Ifindex`, `Zone`, `Mode`, `Source`, `Destination`). But there is **no
userspace-dp IPIP forwarding primitive**:

- **Inbound (the issue's title):** an outer proto-4 frame whose outer dst is the
  firewall's tunnel-source (a local address in `USERSPACE_LOCAL_V4/V6`) is NOT
  `native_gre` (proto-4 ≠ proto-47), so the shim runs `!native_gre` →
  `live_userspace_session_action` (miss) → `is_local_destination` true →
  `cpumap_or_pass` → kernel INPUT → **no `IPPROTO_IPIP` handler** (the anchor is
  a TUN, not an `Iptun` decapper) → **dropped**. Fail-closed.
- **Outbound (Finding-2):** an inner packet routed by FRR to the IPIP anchor
  ifindex resolves `tunnel_endpoint_id != 0` and hits the egress dispatcher
  (`frame/mod.rs` L399-404), which fail-closes on `TunnelKind::Unknown` →
  **dropped**. No userspace IPIP encap exists.

Net: **IPIP tunnels pass no traffic in either direction.** vSRX supports
`ip-in-ip`; xpf does not (in the userspace dataplane, the only runtime).

**Severity: LOW / feature-completeness.** Fail-closed (no bypass, no security
urgency). Synthetic surface today: no `mode ipip` appears in any smoke/cluster
config, and the only `ipip` references in the tree are proto-number tables
(`userspace-dp/src/ip_proto.rs`, `pkg/appid/catalog.go`) and the kernel link
builder (`buildKernelTunnelLink`, dead in userspace mode). No operator relies on
it because it never worked.

---

## 3. Honest scope + value (niche, fail-closed — PLAN-DEFER is the correct call)

**Value is genuinely low and there is no urgency.** IPIP inbound/outbound is a
niche encapsulation: production deployments overwhelmingly use GRE, WireGuard,
or IPsec (all implemented). The feature is fail-closed (drops; no security risk,
no bypass, no data-plane hazard from leaving it unimplemented) and has **never
worked**, so there is no regression, no migration, and no user to disappoint by
deferring. The issue itself is labelled `enhancement` and self-describes as
LOW/niche.

**Cost is genuinely high and mostly in the hot path.** Making IPIP a *working*
feature (Finding-2: both directions) requires:

1. A new userspace-dp IPIP **decap** primitive (mirror
   `try_native_gre_decap_from_frame`, ~150 lines, per-packet path).
2. A new userspace-dp IPIP **encap** primitive (mirror
   `encapsulate_native_gre_frame`; simpler — no GRE header, just an outer IP
   header — but still a hot-path builder with DF/PMTU/oversize handling).
3. `TunnelKind::Ipip` added to **every** `match TunnelKind` site (egress
   dispatch `frame/mod.rs`, TSO/segmentation MTU `frame/tcp_segmentation.rs`,
   ICMP-PTB inner-MTU `afxdp/icmp_ptb.rs`) — a compile-time-enforced fan-out.
4. A new kind-segregated `ipip_decap_index` on `ForwardingState` + a decap poll
   stage (mirror `stage_native_gre_decap`, stage 6).
5. A **novel "Go writes `USERSPACE_SESSIONS`" steering mechanism** (Path B) —
   today Go's ONLY interaction with that map is a startup-flush DELETE-all
   (`maps_sync.go` L567-585); userspace-dp owns live entries. Making Go a
   *writer* is a new HA-ownership boundary with real invariants (§7 HI-1/6/7).
6. Go↔shim key-parity tests, Rust decap/encap unit tests, a loss-cluster IPIP
   topology, `/triple-review` (hot-path forwarding + a new decap AND encap
   stage), and operator/module docs.

That is a multi-day hot-path effort touching ~8 files, introducing a novel
HA-ownership boundary, for a zero-demand parity checkbox. The project's
engineering discipline ("keep solutions simple and direct"; hot-path allocation
rules; review severity) argues against paying it speculatively.

**The clean alternative is blocked with no reclamation planned (Finding-1).**
Path C (`native_ipip` shim redirect) would be cleaner (no per-flow map, no
Go-writes-sessions, tuple-agnostic) but ADDS shim insns to a program already at
the 1M verifier ceiling; #1864 closed as a toolchain-pin, not a budget reclaim,
and nothing tracks reclaiming that budget. So shipping now means committing the
**Path B static-session mechanism permanently** (Path C is not a near-term
replacement) — which removes the "throwaway steering" argument but leaves the
"novel HA-ownership boundary for a niche feature" cost standing.

**Conclusion:** PLAN-DEFER on value/priority grounds. Not PLAN-KILL — the design
is sound and demand-gated. If demand appears, ship Path B (§5).

---

## 4. The already-shipped GRE analogue (reference architecture)

GRE is the proven template; the IPIP work mirrors it at every site. Verified on
master:

**Steering (shim).** GRE sets a global ctrl flag
`userspaceCtrlFlagNativeGRE = 4` (`maps_sync.go` L44,144-145) when
`snapshotHasNativeGRE`. The shim computes `native_gre = protocol==PROTO_GRE &&
(ctrl.flags & NATIVE_GRE)` (`lib.rs` L430-431) and takes the `else` arm
(L646-668) that **skips `is_local_destination`** and redirects the OUTER GRE
frame to XSK. IPIP has no such flag/branch (and cannot afford one — Finding-1).

**Decap (userspace-dp).** `stage_native_gre_decap` (poll stage 6,
`poll_stages.rs` L240) → `try_native_gre_decap_from_frame` (`gre.rs` L621-789)
matches the outer tuple against the **kind-segregated** `gre_decap_index`
(`types/forwarding.rs` L110, populated only for `TunnelKind::Gre` in
`forwarding_build/tunnels.rs` L110-116), re-checks `tunnel_mode_kind == Gre`
(`gre.rs` L494, defense-in-depth), strips the outer header, and builds
`inner_meta` with **`ingress_zone = ifindex_to_zone_id[endpoint.logical_ifindex]`**
(`gre.rs` L750-763) — **this re-zone is the enforcement mechanism**. It stamps
`meta_flags: GRE_DECAP_INGRESS_FLAG` (0x40, `icmp.rs` L18), which downstream
selects only the `tcp-mss gre-in` clamp (`forwarding/mod.rs` L1241) — NOT a
security gate.

**Encap (userspace-dp).** The egress dispatcher (`frame/mod.rs` L399-404)
resolves `tunnel_endpoint_id → tunnel_mode_kind` and dispatches:
`Gre → encapsulate_native_gre_frame` (`gre.rs` L809), `WireGuard →
wg_encap_frame`, and — since #2327 — **`Unknown | None → None` (fail closed,
drop)**. IPIP endpoints are inserted into `tunnel_endpoints` /
`tunnel_endpoint_by_ifindex` unconditionally (`tunnels.rs` L72-101), so an
egress packet to an IPIP anchor DOES reach this dispatcher and IS dropped today.

**Go plumbing already present.** IPIP endpoints reach the snapshot with zone +
ifindex (§2). The only missing Go piece is steering (Path B B2).

---

## 5. Concrete design — Path B (the viable implementation, for when demand appears)

Path B needs **NO shim change ⇒ NO #1864 / verifier dependency** — the decisive
advantage over Path C given Finding-1. It is the recommended implementation IF
`/engineer 4785` is ever unblocked by demand. **Corrected scope (Finding-2):**
it must implement BOTH decap and encap, not decap alone.

### Steering (confirmed viable, no shim insns)

An outer proto-4 frame with a normal-unicast outer dst does NOT hit
`should_fallback_early` (`lib.rs` L1340-1361 returns false for non-multicast,
non-link-local, non-broadcast v4/v6 dst — verified), so it reaches
`if !native_gre { live_userspace_session_action(&parsed) }` (L584-585).
`live_userspace_session_action` (L1427-1438) keys `UserspaceSessionKey {
addr_family, protocol, pad:0, src_port, dst_port, src_addr, dst_addr }`; for
proto-4 `parse_l4`'s default arm yields `src_port = dst_port = 0`. A **static**
`USERSPACE_SESSIONS` entry valued `USERSPACE_SESSION_ACTION_REDIRECT (=1)`
therefore steers the OUTER frame to XSK **before** `is_local_destination`
(L621) is consulted — with **zero shim instructions**.

### Site-by-site (GRE site → IPIP analogue)

| # | GRE site | IPIP analogue (Path B) |
|---|----------|------------------------|
| B1 | `native_gre` ctrl flag + classify+redirect (`lib.rs` L430,646-668) | **NONE.** Steering via the existing `live_userspace_session_action` hook. Zero shim insns (no verifier cost). |
| B2 | Go sets `userspaceCtrlFlagNativeGRE` (`maps_sync.go` L142-145) | **NEW:** Go publishes a static `UserspaceSessionKey{addr_family=OUTER, protocol=4, ports=0, src_addr=remote, dst_addr=local-source} → REDIRECT` per `mode ipip` endpoint. Publish AFTER the L567 startup flush and on RG activation (HI-6). Network-order addr bytes; parity test vs shim parser (HI-1). |
| B3 | `tunnel_mode_kind → Gre` (`tunnels.rs` L144-150) | **NEW** `TunnelKind::Ipip` for `mode=="ipip"`. Adds a variant → every `match TunnelKind` site must gain an arm (compile-time enforced). |
| B4 | `gre_decap_index` populate (`tunnels.rs` L110-116) | **NEW** `ipip_decap_index: FastMap<(i32, IpAddr, IpAddr), Vec<u16>>`, populated only for `TunnelKind::Ipip`, keyed `(outer_family, source, destination)`. |
| B5 | `try_native_gre_decap_from_frame` (`gre.rs` L621-789) | **NEW** `try_native_ipip_decap_from_frame`: match proto-4 outer vs `ipip_decap_index`; re-check `tunnel_mode_kind==Ipip` (HI-4); strip outer IP header (no GRE header); inner starts at outer payload; `inner_meta.ingress_zone = ifindex_to_zone_id[logical_ifindex]` (the enforcement); inner family/offsets off the wire; RFC 6040 ECN combine. Likely **no** meta flag (no `tcp-mss ipip-in` context). |
| B6 | `stage_native_gre_decap` poll stage 6 (`poll_stages.rs` L240) | **NEW** `stage_native_ipip_decap` (or a combined tunnel-decap stage), guarded on `has_ipip_tunnels` (mirror `has_wg_tunnels`). |
| B7 (**Finding-2, NEW leg**) | `encapsulate_native_gre_frame` egress arm (`frame/mod.rs` L401) | **NEW** `encapsulate_native_ipip_frame` + a `TunnelKind::Ipip =>` egress arm. Simpler than GRE (outer IP only, no GRE header) but must handle DF/PMTU/oversize like GRE. **Without this, return traffic drops** — the half-feature failure. |
| B8 | `native_gre_inner_mtu` in `tcp_segmentation.rs` L47 + `icmp_ptb.rs` L212 | **NEW** `TunnelKind::Ipip` arms returning the IPIP inner-MTU (transport MTU − outer IP header), so TSO segmentation and ICMP-PTB inner-MTU are correct. |

### HA / persistence (the Path B new-mechanism cost — CONFIRMED)

Go today only DELETES from `userspace_sessions` (startup flush, `maps_sync.go`
L567-585); userspace-dp OWNS the live entries. Path B makes Go a **static
writer**. Safe iff: (a) userspace-dp's per-session deletes are keyed on its OWN
`SessionTable`, which never holds the synthetic outer-flow key; (b) the RG
republish ADDs, never wipes; (c) the only wipe is Go's startup flush, so Go MUST
(re)publish AFTER it (HI-6). Config-derived, deterministic ⇒ both HA nodes
publish identical keys. **Each of (a)/(b)/(c) MUST carry a test at
`/engineer`** (HI-7).

### Paths NOT recommended

- **Path C (`native_ipip` shim redirect):** cleaner steering (no per-flow map,
  tuple-agnostic) but **blocked by the standing 1M verifier ceiling**
  (Finding-1: #1864 closed as pin+guard, no budget reclamation tracked). Strictly
  worse than B for shipping (blocked) and no better on any residual (there is no
  fail-open residual for a feature — the kernel has no Iptun to leak through).
  Deprioritized indefinitely.
- **Path E (full parity incl. anchor lifecycle):** for a FEATURE, Path B already
  IS the full-parity shape (encap + decap + anchor) because there is no kernel
  `Iptun` to replace — the anchor already exists. So "Path E" collapses into
  Path B once Finding-2 is folded in. The only thing Path C/E would add over B
  is shim-based steering, which is verifier-blocked.
- **Path F (commit-time reject `mode ipip`):** for a fail-closed feature with no
  security urgency, hard-rejecting a valid Junos stanza breaks config
  portability. **Not recommended.** A softer variant — a commit-time ADVISORY
  warning that `mode ipip` does not forward under the userspace dataplane — is a
  cheap, safe, out-of-hot-path interim that converts a silent drop into a
  visible, documented gap (§10 out-of-scope; could be its own tiny issue).

---

## 6. API / behavior preservation

- **No config-syntax change.** `set …tunnel … mode ipip` continues to parse and
  create the anchor. Deferring changes nothing operator-visible.
- **No gRPC/CLI/proto change** for Path B. If shipped, `show security flow
  session` would begin showing decapped-inner sessions on the tunnel zone (a
  strict observability improvement; today those flows are invisible).
- **Non-IPIP datapath byte-identical.** The `live_userspace_session_action` hook
  already runs for every non-GRE packet; Path B changes only *map contents* + a
  new poll stage gated on `has_ipip_tunnels`. Zero shim change ⇒ the GRE/plain
  fast path is bit-identical.
- **Egress fail-closed today is preserved until B7 lands.** The `Unknown → None`
  drop (`frame/mod.rs` L403) is the current (correct, safe) behavior; Path B B7
  replaces it with real encap only for `mode ipip`.

---

## 7. Hidden invariants (for the eventual `/engineer`)

- **HI-1 (session-key parity):** the Go static entry (B2) must byte-match the
  shim's `UserspaceSessionKey` for a proto-4 frame: `{addr_family=OUTER,
  protocol=4, pad=0, src_port=0, dst_port=0, src_addr=remote(network-order),
  dst_addr=local-source}`. A mismatch is a silent no-steer (feature silently
  stays broken). MUST carry a Go↔shim key-layout parity test.
- **HI-2 (no fail-open residual — the FEATURE dividend of Finding-1/§0):**
  unlike the security framing, there is **no** degraded-window fail-open,
  because there is no kernel `Iptun` to decap. During degraded windows an IPIP
  outer is passed to the kernel and simply dropped (feature doesn't work while
  degraded) — fail-closed, acceptable.
- **HI-3 (re-zone is the mechanism):** enforcement is `inner_meta.ingress_zone`
  = tunnel-interface zone. The tunnel interface MUST be zoned and present in
  `ifindex_to_zone_id`; an UNZONED ipip tunnel would re-zone to 0 — define
  drop-vs-default-zone explicitly (OQ-4).
- **HI-4 (kind segregation, defense-in-depth):** mirror `gre.rs` L494 — an
  `ipip_decap_index` candidate MUST re-assert `tunnel_mode_kind == Ipip` so a
  future indexing bug cannot decap a GRE/WG row as IPIP.
- **HI-5 (primitive-miss fail-closed):** a redirected proto-4 frame that misses
  `ipip_decap_index` is treated as ordinary transit (policy on the outer
  5-tuple) → drop/host-inbound, never fail-open. Preserve as a tested property.
- **HI-6 (startup-flush ordering):** B2 publish MUST re-run after the
  `maps_sync.go` L567 flush and on RG activation, or the steering entry is wiped
  on the first ctrl-enable. Idempotent + deterministic.
- **HI-7 (synthetic-key collision + GC/HA safety):** the Go static entry must
  not collide with, or be evicted by, a real userspace-dp session or the HA
  session-sync/GC path. Analysis says safe (different keys; deletes are
  per-owned-key), but B2 MUST assert it with a test.
- **HI-8 (egress symmetry, Finding-2):** decap-only is a half-feature. B7
  (encap) MUST land in the same change, or return traffic silently drops and the
  loss-cluster test (§9) fails on the reverse direction.

---

## 8. Risk table (4-class)

| Class | Risk | Path B (recommended if shipped) | Path C (shim) | Defer (recommended NOW) |
|-------|------|--------------------------------|---------------|-------------------------|
| **Security** | Fail-open? | NO (no kernel Iptun; HI-2) | NO | NO (stays fail-closed drop) |
| | Primitive-miss safety | fail-closed (HI-5) | fail-closed | n/a |
| **Correctness** | Session-key parity (HI-1) | MUST test | n/a (no map) | n/a |
| | Egress symmetry (HI-8) | MUST include encap (B7) | MUST include encap | n/a |
| | Unzoned re-zone (HI-3) | define (OQ-4) | define | n/a |
| | Kind mis-decap | prevented (HI-4) | prevented | n/a |
| **Perf** | Hot-path cost | +1 poll stage gated on `has_ipip`; +encap builder on egress; map lookup already runs | +verifier budget (**over 1M cap — blocked**) | ZERO |
| | GRE/plain fast path | bit-identical (no shim change) | shim rebuilt (`make generate`, verifier gate) | untouched |
| **Ops/HA** | New mechanism | Go writes `userspace_sessions` (novel boundary; HI-1/6/7) | none | none |
| | #1864 / verifier dependency | **NONE** | **HARD BLOCK (standing ceiling, no reclamation)** | none |
| | `make generate` verifier gate | NOT touched | REQUIRED | not touched |
| | Maintenance burden | two steering models (static-session IPIP vs native-flag GRE/WG) — permanent asymmetry | one model (but blocked) | none |

---

## 9. Test plan (for the eventual `/engineer`; also proves the gap today)

**Loss-cluster IPIP topology** (`loss:xpf-userspace-fw0/fw1`, per
`docs/ha-cluster-userspace.conf`; WAN = `reth0`/`ge-0-0-2`, LAN = `reth1.0`
`10.0.61.0/24`):

1. **Config (candidate):** a `mode ipip` tunnel terminating on a WAN address
   (e.g. `reth0.50` `172.16.50.8`) with `source 172.16.50.8`, `destination
   <remote>`, the tunnel unit in a `trust`-facing zone; a zone policy that
   **DENIES** the inner destination and one that **ALLOWS** a control host.
2. **Baseline (proves the gap, runs FIRST, before any code):** from the remote,
   send a proto-4 frame (outer `src=<remote> dst=172.16.50.8`, inner IPv4 dst =
   a LAN host). Observe: LAN host receives **nothing** (dropped — no decap); no
   userspace session appears. Reverse: originate inner traffic toward `<remote>`
   from a LAN host → **dropped** at the egress dispatcher (Finding-2). Capture
   both drops as the baseline.
3. **Fix — inbound (Path B decap):** the inner packet on an ALLOWED inner dst is
   forwarded to the LAN host; on a DENIED inner dst it is DROPPED by policy;
   `show security flow session` shows the decapped inner flow on the tunnel zone
   (`/security-matrix` deny-proof shape).
4. **Fix — outbound (Path B encap, HI-8):** LAN→remote inner traffic is
   encapsulated and leaves as proto-4 to `<remote>` (tcpdump on the WAN
   segment); a bidirectional iperf3 through the tunnel sustains throughput.
5. **Degraded (HI-2):** stop the helper / stale heartbeat → inbound proto-4 is
   kernel-dropped (feature off, fail-closed). Confirm NO fail-open.
6. **Standard smoke unaffected:** v4+v6 iperf3 via `172.16.80.200` /
   `2001:559:8585:80::200` at line rate, CoS-on and CoS-off, push + reverse.
7. **Rust unit tests** (mirror `afxdp/tests.rs` GRE cases): decap re-zones to
   tunnel zone; miss is fail-closed; ECN combine; inner-IPv4 offsets; encap
   round-trips; DF/oversize handling.

---

## 10. Out of scope

- **Shipping IPIP now.** This plan DEFERS; §5 is the design for a future
  demand-gated `/engineer 4785`.
- **proto-41 / 6in4 (sit-mode).** Latent — xpf has no sit-mode tunnel, so proto-41
  is not reachable. The primitive should be family-agnostic but no sit tunnel is
  added here (the title's "proto-4/41" overstates the current surface).
- **Verifier-budget reclamation** (the real Path C prerequisite) — untracked;
  worth a SEPARATE issue if the shim's 1M ceiling is to be reclaimed. Path C is
  gated on it; Path B is not.
- **A commit-time advisory warning for `mode ipip`** (the soft Path-F variant) —
  a cheap, safe, out-of-hot-path interim that makes the silent drop visible. Not
  part of this plan's recommendation; could be its own tiny issue if operators
  hit the silent no-op before demand justifies the full feature.
- **IPsec / GRE / WG** — implemented; untouched.

---

## 11. Open questions (each invitable to a different verdict)

1. **OQ-1 — DEMAND:** is there ANY operator asking for IPIP inbound/outbound, or
   is this pure speculative parity? The verdict hinges on this. Absent demand →
   DEFER. With demand → ship Path B (§5). (Author's read: no demand today.)
2. **OQ-2 — Finding-2 acceptance:** do reviewers agree that decap-only is a
   half-feature and the true scope is encap+decap+steering (so "just mirror the
   GRE decap stage" understates the work by ~2×)? If a reviewer shows a
   surviving egress path (e.g. some kernel encap I missed), the scope shrinks.
3. **OQ-3 — Finding-1 acceptance:** do reviewers agree #1864 (closed as
   pin+guard) does NOT unblock Path C, so "defer until #1864" is a stale framing
   and the defer must be re-grounded on demand? Is there a hidden open issue
   tracking verifier-budget reclamation that I missed?
4. **OQ-4 — unzoned tunnel (HI-3):** should a decapped inner packet on an
   UNZONED ipip tunnel drop (fail-closed) or take a default zone? Junos
   semantics + xpf convention.
5. **OQ-5 — Go-as-writer boundary (HI-1/6/7):** is Go writing static
   `USERSPACE_SESSIONS` entries an acceptable new ownership boundary, or does it
   risk surprising the HA/session-sync/GC code in a way that argues for waiting
   for a verifier-budget reclamation + Path C instead (i.e. defer even if demand
   appears)?
6. **OQ-6 — soft Path-F interim:** is a commit-time advisory warning for `mode
   ipip` worth doing NOW (cheap, converts silent-drop to visible) independent of
   the full feature, or is even that noise for a never-used stanza?
7. **OQ-7 — encap PMTU/ICMP hazard:** does userspace-dp owning both IPIP encap
   and decap (vs GRE's proven path) introduce any asymmetric-PMTU / ICMP-PTB
   translation hazard the GRE path already solved that IPIP must replicate
   (`icmp_ptb.rs` Ipip arm)?

---

## Recommendation (r1, pre-Codex)

**PLAN-DEFER.** IPIP inbound/outbound is a niche, fail-closed, never-worked vSRX
parity gap with no demonstrated demand. The complete fix (Finding-2:
encap + decap + steering) is a large hot-path effort plus a novel
Go-writes-`USERSPACE_SESSIONS` HA-ownership boundary, disproportionate to the
value. The clean path (Path C) is blocked by a standing verifier ceiling that
#1864 did NOT reclaim (Finding-1), so "defer until #1864" is corrected to a
**demand-gated** defer. Keep #4785 OPEN and ready; §5 is the Path B design a
future `/engineer 4785` starts from. Optionally file the soft Path-F advisory
warning and/or a verifier-budget-reclamation issue as cheap, separable
follow-ups. This is DEFER, not KILL — the feature is legitimate and implementable
on demand.
