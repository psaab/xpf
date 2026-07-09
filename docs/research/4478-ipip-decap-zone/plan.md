# Plan-of-Action — #4478 IPIP (proto-4) decap has no userspace zone enforcement

- **Revision:** r2 (SMR r1 = PLAN-REVISE folded in; Codex r1 pending)
- **Issue:** #4478 (opus-172 M-1) — IPIP tunnel decap fail-open, parallel to the GRE gap that HAS a userspace decap stage
- **Mode:** `/research` — deliverable is a converged plan + reviewer verdicts. NO PR, NO production code changes.
- **Base:** origin/master `4eb28ae25eb8`
- **Reviewers:** Codex + Claude-SMR (2-of-3; AGY/gemini infra-down this session). Copilot joins at `/engineer`.

---

## 1. Status

Code study COMPLETE. The OWNER's first-pass triage comment on #4478 is
**confirmed correct** against origin/master, and extended with five new
load-bearing findings (§4, §7). Plan drafted; awaiting Codex + Claude-SMR
convergence.

Provisional recommendation: **Path B (no-shim static steering + userspace-dp
IPIP decap primitive)** as the shippable fix, framed honestly as closing the
*steady-state* fail-open with a documented *degraded-window* residual, plus a
filed follow-up for **Path E (full kernel-Iptun→TUN-anchor GRE parity)** to
eliminate the residual once the #1864 verifier budget is reclaimed.
**PLAN-DEFER behind #1864 is an explicitly reviewer-selectable alternative**
(§3, §11) — this plan surfaces the tradeoff rather than forcing a single answer.

---

## 2. Issue framing (the confirmed fail-open)

An inbound IP-in-IP (outer protocol 4) frame whose **outer destination is the
firewall's own tunnel-source address** and whose **outer source matches a
configured `mode "ipip"` endpoint's remote** is **kernel-decapped by the
`netlink.Iptun` / `netlink.Ip6tnl` device** (`pkg/routing/tunnel.go`
`buildKernelTunnelLink`, the `case "ipip"` arm ≈ L687-703) and the inner packet
is **kernel-forwarded into whatever zone its inner destination routes to, with
NO userspace zone policy applied**. This is a fail-open: untrusted WAN traffic
can be injected past the policy engine into a protected zone.

### Why the shim sends the outer frame to the kernel (root cause, verified)

In `userspace-xdp/src/lib.rs::try_xdp_userspace`, a non-GRE / non-native packet
(IPIP is proto-4, not proto-47) takes the `if !native_gre { … }` arm (≈L584).
On a session miss it reaches `is_local_destination(&parsed)` (≈L621). Because
the IPIP outer destination is the firewall's tunnel-source — an interface
address that `buildLocalAddressEntries` (`pkg/dataplane/userspace/maps_sync.go`
L1400-1436) publishes into `USERSPACE_LOCAL_V4/V6` — `is_local_destination`
returns **true** (`lib.rs` L1363-1380) → `cpumap_or_pass(ctrl)` → the frame
goes to the **kernel**, where the `Iptun` device decaps it. The inner packet
never re-enters the XDP shim (XDP is an ingress-only hook; a kernel-forwarded
packet leaving via the egress interface does not traverse that interface's XDP
ingress program). **Confirmed kernel-forwarded raw, not re-ingressed** — this
answers the parent's crux question #1.

### Contrast: GRE is NOT kernel-decapped (verified)

GRE mode does **not** create a kernel GRE device. `pkg/routing/tunnel.go`
creates a **`netlink.Tuntap` routing-only anchor** (`anchorReusable`, the
`&netlink.Tuntap{…}` add ≈L557-564); FRR routes inner traffic to that anchor
and **userspace-dp performs encap/decap itself**. When
`snapshotHasNativeGRE(snapshot)` is true (any endpoint mode `""`/`"gre"`/
`"ip6gre"`, `maps_sync.go` L1595-1609) the Go control plane sets the global
`userspaceCtrlFlagNativeGRE = 4` bit (`maps_sync.go` L44, L142-145). The shim
then computes `native_gre = protocol==PROTO_GRE && (ctrl.flags & NATIVE_GRE)`
(`lib.rs` L430-431) and takes the `else` arm (`lib.rs` L646-668) which
**deliberately skips `is_local_destination`** and instead calls
`classify_native_gre_inner` → redirects the OUTER GRE frame to the XSK
(userspace-dp). userspace-dp then runs `try_native_gre_decap_from_frame`
(`userspace-dp/src/afxdp/gre.rs` L621-789) as poll **stage 6**
(`poll_stages.rs::stage_native_gre_decap` L240-252), which rebuilds the inner
packet's meta with **`ingress_zone` = the tunnel interface's zone**
(`gre.rs` L750-763, `ingress_zone` looked up from
`ifindex_to_zone_id[endpoint.logical_ifindex]`) and stamps
`meta_flags: GRE_DECAP_INGRESS_FLAG` (`gre.rs` L775; the flag itself only
selects the `tcp-mss gre-in` clamp downstream — `forwarding/mod.rs` L1241 — it
is **not** the security mechanism; the re-zone via `ingress_zone` is).

**So GRE closes the gap by (a) having no kernel device to decap, and (b) a shim
redirect that bypasses the local-delivery shunt.** IPIP has neither.

---

## 3. Honest scope + value

**The fail-open is real, M-1, and worth fixing.** The reachable surface is
narrow but genuine: an attacker who can source-spoof the configured remote
tunnel endpoint's IP (feasible on a WAN without ingress RPF) and send a proto-4
frame to the firewall's tunnel-source address gets a one-way inner-packet
injection into a protected zone. Return traffic still hits userspace policy, so
it is an injection primitive (spoofed one-way reachability to internal
services / amplification), not a full bidirectional bypass.

**PLAN-KILL is NOT appropriate** — the gap is reachable and confirmed
(the OWNER's security-matrix reasoning + this trace). But two honest
de-scoping outcomes ARE on the table and reviewers may select either:

- **PLAN-DEFER behind #1864.** Every architecturally-clean path (native_ipip
  shim redirect; full Iptun→anchor parity) requires a shim source change that
  the #1864 verifier ceiling currently rejects (baseline `xdp_userspace_prog` ≈
  990,796 insns vs the 1,000,000 processed-insn cap; the OWNER measured even a
  one-term `&& !native_ipip` gate exceeding 1M). If the security team judges the
  interim partial fix (Path B) not worth its new-mechanism cost, deferring the
  whole item behind a verifier-budget-reclamation prerequisite is defensible.
- **Ship Path B now as a partial mitigation.** Path B needs NO shim change
  (no #1864 dependency). It closes the steady-state (24/7) fail-open on the
  healthy fast path and leaves a degraded-window residual (§7 HI-2). This is a
  real reduction from "always open" to "open only while the userspace helper is
  degraded." **Honest caveat (SMR r1):** the degraded state is
  ADVERSARIALLY REACHABLE — an attacker who can crash/stall the helper (resource
  exhaustion, a panic, a bulk-sync control-socket stall) can re-open the
  fail-open and then inject. So Path B's guarantee is "fail-closed while the
  helper is healthy," and helper health is itself an attack surface. The
  steady-state closure is still a genuine improvement, but Path B is NOT a full
  fail-closed guarantee.
- **Refuse the feature (Path F, fail-closed interim).** If the security posture
  is "no fail-open," the principled move while the real fix is blocked is to
  REJECT `mode "ipip"` at commit (§5 Path F) rather than ship steering that is
  open during degraded windows. Cost: breaks existing IPIP users.

The plan's value is enumerating the design surface so this call is made with
eyes open, and specifying an acceptance gate (§9) that currently PROVES the gap
is open and will PROVE it closed.

---

## 4. The already-shipped GRE analogue (reference architecture) + 5 new findings

The GRE three-layer path (§2) is the template. Beyond the OWNER's comment, code
study surfaced five precision points that shape the design:

1. **IPIP endpoints already reach the userspace snapshot.**
   `buildTunnelEndpointSnapshots` (`pkg/dataplane/userspace/tunnels.go` L13-134)
   copies `Mode: tunnel.Mode` for **all** non-WG modes (the only gate is
   `Source`/`Destination` non-empty, which IPIP satisfies), with
   `Zone: iface.Zone` and `Ifindex: iface.Ifindex`. So a `mode "ipip"` endpoint
   is ALREADY in `snapshot.TunnelEndpoints` with its zone and ifindex — the Go
   plumbing to *inform* userspace-dp of the tunnel exists. What is missing is
   purely on the userspace-dp side: `tunnel_mode_kind("ipip")` returns
   `TunnelKind::Unknown` (`forwarding_build/tunnels.rs` L144-150), so IPIP
   endpoints are NOT indexed into `gre_decap_index` (only `TunnelKind::Gre` is,
   L110-116) and thus are invisible to `match_tunnel_endpoint` (`gre.rs`
   L477-507).

2. **Free ctrl-flag bit = `0x20`.** Existing: CPUMap=1, Trace=2, NativeGRE=4,
   Strict=8, WgRx=16 (`maps_sync.go` L42-50). A hypothetical
   `userspaceCtrlFlagNativeIPIP` would be 32.

3. **Both no-shim (Path B) and shim (Path C) leave a degraded-window residual
   fail-open.** The shim's degraded short-circuits (`is_degraded_local_or_control`
   → `pass_local_control` → kernel, at `lib.rs` L465-533) run BEFORE both the
   `live_userspace_session_action` lookup (L585, Path B's hook) AND the
   native-tunnel branch (L584/646, Path C's hook). During heartbeat-stale /
   binding-not-ready / ctrl-disabled windows an IPIP outer (local dst) is passed
   to the kernel → the `Iptun` decaps → fail-open returns. This residual is
   INHERENT to keeping the kernel `Iptun` device. GRE does NOT have it because
   its kernel device is a TUN anchor that cannot decap. **Only Path E
   (Iptun→anchor) is fully fail-closed.**

4. **Reachable surface is proto-4 with an IPv4 inner.** `buildKernelTunnelLink`
   creates `Iptun` (4in4, outer proto 4) and `Ip6tnl{Proto:4}` (4in6, v6-outer
   next-header 4). Both carry an **IPv4 inner** packet. xpf has **no sit-mode /
   6in4 tunnel**, so **proto-41 is latent** (not currently reachable) — the
   issue title's "proto-4/41" overstates the current surface. The decap
   primitive should key inner family off the wire for future-proofing but the
   only reachable inner family today is IPv4.

5. **Primitive-miss is fail-CLOSED.** If userspace-dp receives a redirected
   proto-4 outer frame whose tuple misses the `ipip_decap_index`, it does not
   decap; the frame is treated as ordinary transit (policy lookup on the outer
   5-tuple src=remote/dst=local-tunnel-source/proto=4) which drops or takes
   host-inbound — never fail-open. This is a safety property of Path B/C: a
   registration bug degrades to drop, not to bypass.

---

## 5. Concrete design — three viable paths, site-by-site

### Path B (RECOMMENDED shippable) — static `USERSPACE_SESSIONS` steering + userspace-dp IPIP decap

No shim change ⇒ **no #1864 dependency**. Reuses the existing `!native_gre`
session-lookup hook (`lib.rs` L585): a static `USERSPACE_SESSIONS` entry keyed
on the inbound IPIP OUTER flow, valued `USERSPACE_SESSION_ACTION_REDIRECT`,
makes `live_userspace_session_action` return REDIRECT **before**
`is_local_destination` is consulted → the outer frame is steered to XSK →
userspace-dp decaps it and re-zones.

**Site-by-site (GRE site → IPIP analogue):**

| # | GRE site | IPIP analogue (Path B) |
|---|----------|------------------------|
| B1 | Shim `native_gre` ctrl flag + classify+redirect (`lib.rs` L430-431, L646-668) | **NONE.** Steering is via the existing `live_userspace_session_action` hook (L585). Zero shim insns. |
| B2 | Go sets `userspaceCtrlFlagNativeGRE` (`maps_sync.go` L142-145) | **NEW**: Go publishes a static `UserspaceSessionKey{addr_family, protocol=4, src_port=0, dst_port=0, src_addr=remote, dst_addr=local-source}` → value REDIRECT into `userspace_sessions` for each configured `mode "ipip"` endpoint. Key layout: `lib.rs` L227-237 (`addr_family:u8, protocol:u8, pad:u16, src_port:u16, dst_port:u16, src_addr:[16], dst_addr:[16]`), native-endian addr bytes. Publish site parallels `buildLocalAddressEntries`; re-publish on every ctrl-enable AFTER the startup flush (`maps_sync.go` L567-584) and on RG activation. |
| B3 | `tunnel_mode_kind` → `TunnelKind::Gre` (`forwarding_build/tunnels.rs` L144-150) | **NEW** `TunnelKind::Ipip` for `mode=="ipip"`; egress dispatcher's fail-closed `_ =>` arm unchanged (IPIP egress stays on the kernel `Iptun`, §10). |
| B4 | `gre_decap_index` populate (`tunnels.rs` L110-116) | **NEW** `ipip_decap_index: FastMap<(i32, IpAddr, IpAddr), Vec<u16>>` on `ForwardingState` (`types/forwarding.rs` L110), populated for `TunnelKind::Ipip` endpoints, same `(outer_family, source, destination)` key. |
| B5 | `try_native_gre_decap_from_frame` (`gre.rs` L621-789) + `match_tunnel_endpoint` | **NEW** `try_native_ipip_decap_from_frame`: match proto-4 outer against `ipip_decap_index`; strip the outer IP header (no GRE header); inner starts at outer payload; build `inner_meta` with `ingress_ifindex = endpoint.logical_ifindex`, **`ingress_zone` = `ifindex_to_zone_id[logical_ifindex]`** (the security mechanism), inner family/protocol/offsets from the wire, RFC 6040 ECN combine (as GRE). Likely NO separate meta flag (there is no `tcp-mss ipip-in` context; omit unless a downstream consumer needs it). |
| B6 | `stage_native_gre_decap` poll stage 6 (`poll_stages.rs` L240-252) | **NEW** `stage_native_ipip_decap` (or fold into a combined tunnel-decap stage 6) invoked at the same point, guarded so it only runs when `has_ipip_tunnels` (mirror `has_wg_tunnels`). |
| B7 | `select_tcp_mss` gre-in clamp (`forwarding/mod.rs` L1241) | **NONE** unless B5 emits a flag; default `all-tcp`/none. |

**HA / persistence (the Path B new-mechanism cost):** Go today only DELETES
from `userspace_sessions` (startup flush); userspace-dp OWNS the map's live
entries. Path B makes Go a static *writer*. This is safe because (a)
userspace-dp's per-session deletes (`session_glue/mod.rs` L470/787-788) are
keyed on its OWN `SessionTable`, which never contains the synthetic outer-flow
key, so GC won't evict it; (b) the RG republish (`afxdp/ha.rs` L172) ADDs, never
wipes; (c) the only wipe is Go's startup flush, so Go must (re)publish AFTER it.
The static entries are config-derived and deterministic ⇒ both HA nodes publish
identical keys.

### Path C (native_ipip shim redirect) — cleaner steering, BLOCKED by #1864

Broaden the shim: `native_ipip = (proto==4 [|| proto==41 latent]) && (ctrl.flags
& NATIVE_IPIP)`; reuse the `native_gre` structure (`if !native_tunnel {…} else
{classify}`) so IPIP-local skips `is_local_destination` and redirects to XSK.
B3-B6 unchanged. **Advantages over B:** no per-flow map, no Go-writes-to-sessions
new mechanism, tuple-agnostic (any spoofed source that hits the index). **Fatal
blocker:** the OWNER empirically measured that even the minimal gate blows the 1M
verifier cap (§3). Path C is strictly *worse than B for shipping now* (blocked)
and *no better on the degraded residual* (§4-3). Deprioritized unless #1864 is
reclaimed — at which point Path E is preferable anyway.

### Path E (full GRE parity) — Iptun→TUN anchor + userspace IPIP encap/decap — the only FULLY fail-closed answer

Replace the kernel `Iptun`/`Ip6tnl` with a `netlink.Tuntap` anchor (as GRE),
add userspace-dp IPIP **egress encap** (new `encapsulate_native_ipip_frame` +
`TunnelKind::Ipip` egress-dispatcher arm) alongside B3-B6 decap, and the Path C
shim redirect. Removes the degraded residual entirely (no kernel device to
decap). **Largest scope + still #1864-blocked** (needs the shim redirect). This
is the correct long-term architecture; file it as the follow-up that Path B's
residual points at.

### Path F (commit-time fail-closed refusal) — the cheapest genuinely fail-closed interim

Reject `mode "ipip"` at commit (or reject it only when the tunnel's unit is
placed in a security zone, i.e. when the fail-open is actually reachable) with a
clear error citing #4478, UNTIL enforcement (B/E) ships. Precedent: xpf already
hard-rejects unsafe/retired config (`ErrEBPFDataplaneRetired`). **Fail-closed,
no dataplane change, no #1864 dependency, trivially correct.** Cost: breaks any
existing IPIP user (a real regression for a legitimate Junos feature). Path F is
the "no fail-open at any cost" answer; it trades the feature for the guarantee.
It is the correct interim IF the security owner will not accept Path B's
degraded-window residual AND will not wait for Path E. Note B and F are not
mutually exclusive with the DEFER→E endgame: F now + E later keeps the door open
to restore the feature fail-closed.

**Rejected paths (from the OWNER's enumeration):**
- **Path A (exclude tunnel-source from `USERSPACE_LOCAL`):** changes local
  delivery of that address (often the WAN IP) for ALL protocols and interacts
  with `is_degraded_local_or_control` → management-plane lockout risk during a
  degraded window. Rejected — disproportionate blast radius.
- **Path D (XDP+zone or nft on the Iptun device):** duplicates the entire
  userspace policy engine in the kernel path. Rejected — architecturally against
  the userspace-enforcement model.

---

## 6. API / behavior preservation

- No config-syntax change. `set … tunnel … mode ipip` continues to parse
  (`types_routing.go` L453) and create the kernel device (Path B/C keep the
  `Iptun` for egress; only Path E replaces it).
- No gRPC/CLI/proto change for Path B. `show security flow session` would begin
  to show decapped-inner sessions on the tunnel zone (a strict improvement in
  observability — today those flows are invisible to xpf).
- Egress (inner→outer encap) path unchanged for B/C: FRR routes inner traffic
  to the kernel `Iptun`, kernel encaps. Inbound decapped inner packets are
  forwarded by userspace-dp normally (not re-encapped) — no double-processing.
- Non-IPIP datapath byte-identical for B (the session-lookup hook already runs
  for every non-GRE packet; only map *contents* change). For C, the non-IPIP
  path must stay bit-identical — gate the whole `native_ipip` block on the
  `NATIVE_IPIP` flag bit exactly as WG_RX gates its block (`lib.rs` L562).

---

## 7. Hidden invariants

- **HI-1 (session-key parity) — RESOLVED:** the Go static entry (B2) must match
  the shim parser's output for a proto-4 frame exactly. **Verified**: `parse_l4`
  (`lib.rs` L1484-1528) hits the `_ => Some((l4_offset, 0, 0, 0, 0))` default arm
  for proto-4, so `flow_src_port = flow_dst_port = tcp_flags = 0`, and
  `parse_ipv4` (L1214-1236) writes network-order address bytes into the low 4
  bytes of the 16-byte `src_addr`/`dst_addr`. The key is therefore fully
  deterministic and Go-reproducible: `{addr_family=outer, protocol=4,
  pad=0, src_port=0, dst_port=0, src_addr=remote, dst_addr=local-source}`. A
  mismatch would be a silent no-steer (fail-open persists), so the B2
  implementation MUST carry a Go↔shim key-layout parity test.
- **HI-2 (degraded residual, adversarially reachable):** §4-3. B/C are fail-open
  during degraded windows (heartbeat-stale / binding-not-ready / ctrl-disabled),
  and that state is ATTACKER-INDUCIBLE (helper crash/stall). Must be documented
  in `forwarding/README.md` and the operator tunnel doc, and is the primary
  justification for prioritizing the Path E follow-up.
- **HI-7 (synthetic-key collision safety, MUST verify at /engineer):** the
  Go static `userspace_sessions` entry (B2) must not collide with or be
  overwritten by a real userspace-dp session. Analysis: a TRANSIT proto-4 flow
  (outer dst NOT local) keys on a different `dst_addr`, so no collision with the
  synthetic `(proto=4, ports=0, remote, local_source)` entry; the decapped INNER
  flow keys on the inner 5-tuple, a different key, so no overwrite. This holds
  only if userspace-dp has NO full-map republish that rewrites/wipes keys it does
  not own — `shared_ops.rs` republish ADDs and `session_glue` deletes per-key
  (spot-checked), but the B2 implementation MUST assert this with a test before
  relying on it.
- **HI-3 (re-zone is the mechanism):** enforcement is `inner_meta.ingress_zone`
  = tunnel-interface zone, NOT any meta flag. The tunnel interface MUST be zoned
  and present in `ifindex_to_zone_id`; an UNZONED ipip tunnel would re-zone to 0
  — define that behavior (drop vs. default-zone) explicitly.
- **HI-4 (kind-segregation, defense-in-depth):** mirror GRE's re-check
  (`gre.rs` L492-496) — an `ipip_decap_index` candidate must re-assert
  `tunnel_mode_kind == Ipip` so a future indexing bug cannot decap a GRE/WG row
  as IPIP.
- **HI-5 (primitive-miss fail-closed):** §4-5 — preserve as a tested property.
- **HI-6 (startup-flush ordering):** B2 publish must be idempotent and re-run
  after the `maps_sync.go` L567 flush and on RG activation, or the steering
  entry is wiped on the first ctrl-enable.

---

## 8. Risk table

| Class | Risk | Path B | Path C | Path E |
|-------|------|--------|--------|--------|
| **Security** | Steady-state fail-open closed? | YES (healthy path) | YES (blocked) | YES |
| | Degraded-window residual? | YES (HI-2) | YES (HI-2) | NO |
| | Primitive-miss safety | fail-closed (HI-5) | fail-closed | fail-closed |
| **Correctness** | Session-key parity (HI-1) | MUST verify OQ-1 | N/A (no map) | N/A |
| | Double-decap (kernel+userspace) | none (outer redirected pre-kernel) | none | none (no kernel dev) |
| | Unzoned-tunnel re-zone (HI-3) | define | define | define |
| **Perf** | Hot-path cost | +1 poll stage gated on `has_ipip`; map lookup already runs | +verifier budget (blocked) | +encap/decap both dirs |
| **Ops/HA** | New mechanism | Go writes `userspace_sessions` (new); republish/HA (HI-6) | none | anchor lifecycle + egress encap |
| | #1864 dependency | NONE | HARD BLOCK | HARD BLOCK |
| | Verifier gate (`make generate`) | NOT touched | REQUIRED | REQUIRED |

**Path F (commit-time refusal)** is off-table because it is a config-plane
change with no dataplane/perf/HA surface: fully fail-closed, no #1864
dependency, no verifier gate, its only "risk" is the operational regression of
refusing a configured `mode "ipip"` (breaks existing users). It is the
fail-closed bookend opposite Path B (open-when-degraded) in the §3 three-way
choice.

---

## 9. Test plan (acceptance gate — currently PROVES the gap is open)

**Loss-cluster IPIP topology** (`loss:xpf-userspace-fw0/fw1`, per
`docs/ha-cluster-userspace.conf`; WAN = `reth0`/`ge-0-0-2`, LAN = `reth1.0`
`10.0.61.0/24`):

1. Config stanza (candidate): a `mode "ipip"` tunnel terminating on a WAN
   address (e.g. `reth0.50` `172.16.50.8`) with `source 172.16.50.8`,
   `destination <remote>`, the tunnel unit placed in a `trust`-facing zone; a
   zone policy that **DENIES** untrust→trust for the inner destination.
2. Inner traffic: from the "remote" side (or a spoofed-source host on the WAN
   segment) send a proto-4 frame: outer `src=<remote>` `dst=172.16.50.8`, inner
   IPv4 dst = a LAN host (`10.0.61.x`) that the deny policy covers.
3. **Observable proving the gap is OPEN (baseline, today) — GATING PRECONDITION
   (SMR r1):** the LAN host RECEIVES the inner packet (tcpdump on the LAN host)
   despite the deny policy → kernel-forwarded past policy. A screen/flow counter
   shows NO userspace session for the flow. **The /engineer phase MUST run this
   baseline FIRST and capture the injected inner packet on the LAN host before
   writing any code.** If the baseline canNOT reproduce the injection in a
   realistic config (e.g. RPF, or no inter-zone FIB route to the inner dst,
   silently closes it — OQ-6), that is a PLAN-KILL / severity-downgrade signal
   and the fix does not proceed.
4. **Observable proving the fix (Path B):** the inner packet is DROPPED by the
   deny policy; `show security flow session` shows the decapped inner flow on
   the tunnel zone (or a policy-deny drop counter increments); tcpdump on the
   LAN host shows nothing.
5. **Degraded residual (HI-2) regression:** with the userspace helper stopped /
   heartbeat stale, repeat step 2 → document that the inner packet is again
   kernel-forwarded (residual is expected for B/C; would be closed only by E).
6. Standard smoke unaffected: v4+v6 iperf3 through `172.16.80.200` /
   `2001:559:8585:80::200` at line rate, CoS-on and CoS-off, push + reverse
   (`feedback_smoke_v4_and_v6`, `feedback_smoke_push_and_reverse`).
7. Rust unit tests mirroring `afxdp/tests.rs` GRE-decap cases:
   `try_native_ipip_decap_from_frame` re-zones to the tunnel zone; miss is
   fail-closed; ECN combine; inner-IPv4 offsets.

Reference the existing `/security-matrix` skill for the deny-enforcement proof
shape.

---

## 10. Out of scope

- **IPIP egress (inner→outer) zone enforcement.** #4478 is the INBOUND decap
  fail-open. Egress uses the kernel `Iptun`; any egress-side gap is a separate
  issue. (Path E would subsume it.)
- **proto-41 / 6in4 (sit-mode).** Latent, not currently reachable (§4-4). The
  primitive should be family-agnostic but no sit-mode tunnel is being added.
- **The #1864 verifier-budget reclamation** itself — a prerequisite for C/E,
  tracked separately.
- **Path E delivery** — filed as the follow-up that Path B's residual points at.

---

## 11. Open questions (each invitable to PLAN-KILL / PLAN-DEFER)

1. **OQ-1 (HI-1) — RESOLVED, Path B viable:** verified during this study —
   `parse_l4`'s default arm (`lib.rs` L1526) yields ports=0 for proto-4, so the
   static key is deterministic and Go-reproducible (§7 HI-1). No longer a
   blocker; retained as the mandate for a Go↔shim key-parity test.
2. **OQ-2:** is the sub-second degraded-window residual (HI-2) acceptable for an
   M-1 security fix, or does the security team require the fully-fail-closed
   Path E (and therefore accept the #1864 block + larger scope)? If E is
   required, this becomes PLAN-DEFER behind #1864.
3. **OQ-3:** is Go-as-a-writer of `userspace_sessions` (B2) an acceptable new
   ownership boundary, or does it violate a map-ownership invariant that would
   surprise the HA/session-sync code? (Investigate any full-map republish in
   userspace-dp that assumes sole ownership.)
4. **OQ-4:** for an UNZONED ipip tunnel (HI-3), should the decapped inner packet
   drop (fail-closed) or take a default zone? Junos semantics + xpf convention.
5. **OQ-5:** does keeping the kernel `Iptun` for egress while userspace-dp owns
   inbound decap create any asymmetric-path / ICMP / PMTU hazard (e.g. kernel
   generates a PTB for the egress direction that userspace-dp doesn't expect)?
6. **OQ-6 (reachability sanity) — now a §9 gating precondition:** does the
   firewall's kernel FIB actually forward a decapped inner packet into the
   protected zone in a realistic config, or is the injection only reachable when
   the operator has configured inter-zone routing anyway? The §9 step-3 baseline
   RESOLVES this at /engineer time before code; a negative result is a PLAN-KILL /
   severity-downgrade signal.
7. **OQ-7 (three-way interim choice, security-owner call):** with OQ-1 resolved
   and HI-2 now framed as adversarially reachable, the real decision is among:
   **(B)** ship the partial steering fix (steady-state closed, open-when-degraded);
   **(F)** refuse `mode "ipip"` at commit (fail-closed, feature removed); or
   **(DEFER→E)** wait for the #1864 verifier budget and do full Iptun→anchor
   parity (fail-closed, feature kept). This is a posture judgment, not a
   correctness question — the plan surfaces it for the owner to pick.
8. **OQ-8 (outer family, B2 key):** for the Ip6tnl 4in6 case the OUTER family is
   IPv6 while the inner is IPv4; B2 MUST key the static entry on the OUTER family
   (`addr_family`), not the inner. Confirm in the B2 implementation.

---

## Recommendation (r2, pre-Codex)

The correctness questions are resolved: OQ-1 (deterministic proto-4 key) makes
Path B mechanically viable, and the crux + GRE contrast are verified. What
remains is a **posture choice** (OQ-7) that the plan deliberately surfaces
rather than forces:

1. **Preferred if the owner accepts a degraded-window residual:** ship **Path B**
   (no shim, no #1864) to close the steady-state fail-open NOW, gated on the §9
   step-3 baseline reproducing the injection first, with the HI-7 collision test
   and Path E filed as the residual-closing follow-up.
2. **Preferred if the posture is "no fail-open, feature-loss acceptable":**
   **Path F** (commit-time refuse `mode "ipip"`) — fully fail-closed today.
3. **Preferred if the posture is "no fail-open, keep the feature":**
   **PLAN-DEFER** behind #1864 → **Path E** (full Iptun→anchor parity).

My provisional lean is **Path B now + Path E follow-up** (option 1): it is the
only option that improves the security posture immediately without removing a
legitimate feature, and the residual is bounded to helper-degraded windows and
explicitly tracked. But this is a judgment call for the security owner, and
Path F / DEFER are both defensible — the plan is PLAN-READY for that decision to
be made, not a claim that Path B is the only answer.
