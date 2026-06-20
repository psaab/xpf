# #1434 — Implement Multi-Tunnel WireGuard Support — research plan

**Status: DRAFT v1 (draft-fanout, NOT reviewed, NOT approved, NO code written)**

This is a plan-of-action only. No production source is touched. No
Codex/AGY/Copilot pass has run. The disposition section at the end states
plainly whether this should ship, be deferred to lab, be split into
increments, or be PLAN-KILLed.

---

## 1. Issue framing (as filed)

Issue #1434 "Implement Multi-Tunnel WireGuard Support" asks for:

- Support multiple WireGuard interfaces (wg0, wg1, ...).
- Per-interface private/public keys and per-interface UDP listen ports.
- Correct RX/TX routing based on port/identity.
- Implementation details (verbatim):
  - Move WireGuard config from global `ConfigSnapshot` to per-interface
    `InterfaceSnapshot`.
  - Refactor `BindingWorker` to hold a map of `WireGuardEngine` indexed
    by port.
  - Update RX pipeline to look up engine by destination port.
  - Update TX pipeline to use `wg_listen_port` from
    `TunnelEndpointSnapshot` for engine selection.
  - Update CLI to show local public keys per-interface.
  - Restore `request security wireguard generate-private-key`.
- Verification: `show security wireguard public-key`; functional
  multi-tunnel traffic tests.

**The issue text is significantly stale.** It was filed against an early
S2a-era mental model that no longer matches the shipped architecture. The
"already shipped" section below quantifies how much of the requested work
landed under #1432 (S2a), #1865, #1866, #1904, #1910, #1919, and #1736.
A faithful plan must re-derive the *actual* remaining gap rather than
implement the issue's literal task list, most of which is already done or
was done a different (and correct) way.

---

## 2. Honest scope and value

**Value.** WireGuard is a shipped, operator-visible feature (telemetry in
#1865, address lifecycle in #1919, live kernel-WG interop harness in
#1736). Today an operator can configure exactly one usable WG tunnel.
Multiple site-to-site WG peers, or WG to several hubs, is a normal
real-world topology. The feature is small in marginal code but real in
operator value: it removes an arbitrary "one tunnel" ceiling on an
otherwise complete subsystem.

**Scope reality.** Most of the literal issue task list is already
implemented:

- WG config is NOT global. It lives per-tunnel-endpoint on
  `TunnelConfig` (Go: `pkg/config/types_routing.go`) and on
  `TunnelEndpointSnapshot` (Rust: `protocol/snapshot.rs`), per interface
  and per unit. The Go emitter (`pkg/config/tunnelemit.go`) already emits
  one endpoint per configured interface-level WG tunnel.
- The Rust forwarding state already holds `wg_engines:
  FastMap<u16, Arc<WgEngine>>` keyed by tunnel-endpoint id
  (`afxdp/types/forwarding.rs`), and `populate_wg_engines`
  (`forwarding_build/wg.rs`) builds one engine per `mode=="wireguard"`
  endpoint with per-engine identity-stable Arc reuse.
- One WG control thread is spawned PER engine id, each binding its own
  kernel UDP socket on its own `wg_listen_port`
  (`coordinator/tunnel_supervision.rs::spawn_wg_control_threads` +
  `spawn_one_wg_control_thread`; bind in `coordinator/wg_control.rs`).
- Telemetry already iterates a per-tunnel vector
  (`status.WgTunnels`, rendered by
  `pkg/dataplane/userspace/format/wireguard.go`).

So the literal asks "move config to per-interface", "hold a map of
engines indexed by port", "RX by dest port", "TX by wg_listen_port" are
**already true** in spirit (engines keyed by id, RX by kernel-socket
demux per port, TX by per-engine control thread). The *one* place still
hard-wired to a single tunnel is the **XDP shim ctrl block**: it carries
a single `wg_listen_port: u32` and steers local-destination UDP for
exactly one port to the kernel (`maps_sync.go::snapshotWgListenPort` —
"first configured endpoint's listen port wins"; shim
`userspace-xdp/src/lib.rs::wg_steer_to_kernel`).

**Net remaining work = the shim port-steering generalization (one
genuine hot-path change) plus the two CLI items (public-key show, restore
generate-private-key) plus a no-WG-tunnel-on-the-second-port functional
test.** That is materially smaller than the issue implies.

> If reviewers conclude the perf gain/scope is too small to justify the
> churn, PLAN-KILL is acceptable. The honest counter-argument is in the
> self-SMR: the data-plane is already 90% multi-tunnel; the only thing
> that *breaks* a second tunnel is the single-port shim gate, which is a
> few-line hot-path edit on the most verifier-constrained file in the
> tree, so the risk/reward must be weighed carefully.

---

## 3. What is already shipped (do NOT re-do)

| Capability | Where | Status |
|---|---|---|
| Per-tunnel WG config (privkey/pubkey/port/allowed-ips/endpoint/keepalive) | `pkg/config/types_routing.go` `TunnelConfig`, parsed in `compiler_interfaces.go::parseTunnelWireguard` | shipped (#1432) |
| Config-mode schema for `tunnel wireguard { ... }` | `pkg/config/schema_interfaces.go::wireguardSchemaNode` | shipped |
| Per-endpoint snapshot WG fields | `protocol/snapshot.rs::TunnelEndpointSnapshot` (privkey redacted, `skip_serializing`) | shipped (#1432) |
| One `Arc<WgEngine>` per endpoint id, identity-stable Arc reuse, TAI64N seeding | `forwarding_build/wg.rs::populate_wg_engines` | shipped (#1432 §4.2) |
| `wg_engines: FastMap<u16, Arc<WgEngine>>` | `afxdp/types/forwarding.rs` | shipped |
| One control thread per engine id, own UDP socket on own listen port | `coordinator/tunnel_supervision.rs`, `coordinator/wg_control.rs` | shipped (#1432 S2a + #1866 lifecycle) |
| AF_XDP transit-egress encap selects engine by id | `frame/wg.rs::wg_encap_frame` (`wg_engines.get(&id)`) | shipped |
| Per-tunnel telemetry + `show security wireguard [detail]` | `format/wireguard.go`, `cli/cli_show_security_wireguard.go`, `coordinator/status.rs` | shipped (#1865) |
| WG address lifecycle on tunnel removal | #1919, #1905 | shipped |
| Interface-level WG single-TUN-per-interface unit pick | `tunnelemit.go` (#1910/#1904) | shipped |
| Live kernel-WG interop harness | `test/.../wg-interop.sh` (#1736) | shipped |

**Single-tunnel ceiling that remains:**

1. **Shim port steering is single-port.** `snapshotWgListenPort` returns
   the FIRST WG endpoint's port; the shim packs ONE port into
   `UserspaceCtrl.wg_listen_port` and `wg_steer_to_kernel` matches that
   one port. A second WG tunnel on a different port will NOT have its
   inbound transport UDP steered to the kernel socket — it falls into the
   AF_XDP transit path and is dropped (no local session). This is the
   functional blocker.

2. **No `show security wireguard public-key` / local public key
   surface.** The engine derives `local_public_key` at construction
   (`wg/engine.rs:282`) but the status row only carries
   `peer_pubkey_hex` + `listen_port` (`coordinator/status.rs:710-711`).
   The local public key — the thing an operator must hand to the peer —
   is not plumbed to the status row or rendered.

3. **No `request security wireguard generate-private-key`.** No such
   command exists anywhere (grep: zero hits in `pkg`, `cmd`,
   `userspace-dp/src` outside tests). The issue says "restore" but there
   is no evidence it ever shipped; treat it as net-new.

4. **No two-WG-tunnel functional test.** `two_tunnel_snapshot()` in
   `forwarding_build/tests.rs` is GRE(id 824)+WG(id 7), not two WG
   tunnels. There is no test that two WG engines on two ports both decap.

---

## 4. Concrete design (code-level)

### Step 1 — shim multi-port steering (the only hot-path change)

The shim must steer local-destination UDP to the kernel for ANY
configured WG listen port, not just the first. Three viable paths:

**Path A (RECOMMENDED): a dedicated WG-port set map.**
Add a small BPF hash/array map (e.g. `USERSPACE_WG_PORTS:
HashMap<u16, u8>` or a fixed `Array<u16; N>`) populated by Go on every
apply with the set of configured WG listen ports. `wg_steer_to_kernel`
becomes: still gated on `USERSPACE_CTRL_FLAG_WG_RX` (zero-cost when no WG
tunnel), then on the WG path do `protocol==UDP && is_local_destination &&
wg_ports.get(&dst_port).is_some()`. Keep the single `wg_listen_port`
ctrl field for back-compat / the common single-tunnel case but treat the
map as authoritative when populated.
- *Pro:* unbounded port count, exact semantics, the per-packet cost is
  one hash lookup ONLY on the already-gated WG branch (non-WG traffic
  unaffected — the #1432 zero-cost-when-absent property is preserved).
- *Con:* new BPF map = new verifier surface + new Go map writer + ABI
  bump; the shim is the kernel-verifier-gated file (`make generate`,
  pinned toolchain, #1864) so any shim edit pays the full regen+verify
  gate.

**Path B: widen the ctrl block to a small fixed port array.**
Replace `wg_listen_port: u32` with e.g. `wg_listen_ports: [u16; 8]`
inside `UserspaceCtrl`. `wg_steer_to_kernel` loops the (tiny, unrolled)
array.
- *Pro:* no new map; reuses the existing single-instance ctrl Array.
- *Con:* hard cap on tunnel count (8 or whatever); a fixed-size loop in
  the hot path; ctrl-block ABI change (Go mirror + size assertions +
  metadata-version bump); the loop is branchy in a place that was
  deliberately gated for v6 line-rate (#1432 noted a bare load+compare
  nudged v6 retransmits). A loop is strictly worse than the gated single
  compare for the single-tunnel common case unless carefully ordered
  (first slot fast).

**Path C: steer ALL local-destination UDP to the kernel when WG is on.**
Drop the per-port check entirely; if `WG_RX` flag is set, any
local-destination UDP goes to the kernel.
- *Pro:* trivial, no map, no ABI change.
- *Con:* WRONG. It would shunt every local UDP service (DHCP client,
  IKE/500/4500 for strongSwan, SNMP, syslog, RPM probes) to the kernel
  path, bypassing the userspace policy engine and changing behavior for
  unrelated services. The existing code comment at `wg_steer_to_kernel`
  explicitly warns "a port-only match would shunt transit/DNAT UDP on the
  WG port to the kernel" — Path C is the even-broader version of that
  mistake. **Rejected.**

**Recommendation: Path A.** It is the only option that scales, keeps the
zero-cost-when-absent property, and matches the existing engine-keyed
architecture. Path B is acceptable as a smaller-footprint fallback if
reviewers want to avoid a new map, accepting a hard tunnel cap.

Go side for Path A: a new map writer next to `snapshotWgListenPort` that
collects ALL `mode=="wireguard"` endpoint ports into the set map, plus
keep writing the first port into the legacy ctrl field for
single-tunnel back-compat and the `WG_RX` flag. ABI/metadata-version bump
handled like prior shim ABI changes.

### Step 2 — local public key plumbing + telemetry

- Rust: add `local_pubkey_hex` (and confirm `listen_port`, peer pubkey
  already present) to the WG status row built in `coordinator/status.rs`
  (~line 705-717), sourced from
  `engine.local_public_key()` (add a thin accessor on `WgEngine` if not
  public; the field exists at `wg/engine.rs:282`).
- Go: add `LocalPubkeyHex string` to the `WgTunnel` status struct
  (`pkg/dataplane/userspace/`), decode it from the snapshot.
- `format/wireguard.go`: render `Local public key: <hex/base64>` per
  tunnel. Decide hex vs WireGuard-canonical base64 — operators paste WG
  keys as base64 into peer configs, so render base64 (or both) for
  `public-key` even though the wire/snapshot carries hex.
- CLI: add `show security wireguard public-key` (cmdtree node under the
  existing `wireguard` node in `pkg/cmdtree/tree.go:448`; dispatch in
  `cli_show_security_dispatch.go`). It prints, per configured WG tunnel,
  the interface/endpoint name, listen port, and local public key in the
  base64 form a peer needs.

### Step 3 — `request security wireguard generate-private-key`

- A stateless helper that emits a fresh X25519 private key (and its
  derived public key) for the operator to paste into config. It does NOT
  mutate config (Junos `request` semantics) — it just prints.
- Two viable placements:
  - **Path 3a (RECOMMENDED): pure Go.** Generate the key in Go using the
    same X25519 primitive the project already depends on (the Rust engine
    uses x25519; Go side can use `golang.org/x/crypto/curve25519` /
    `crypto/ecdh`). No daemon round-trip, works even with no dataplane
    loaded, trivially testable. Print private + derived public in WG
    base64.
  - **Path 3b: round-trip to the helper.** Add a control-socket RPC that
    asks the Rust side to generate. Heavier, couples a stateless utility
    to the dataplane lifecycle, and the control socket is contended (see
    CLAUDE.md control-socket rule). Rejected unless there is a reason the
    key MUST come from the helper's RNG.
- Wire into cmdtree under `request security wireguard` + dispatch.
- Clamp the private key per X25519 (the generator must produce a clamped
  scalar so the derived public key matches what the engine will derive).

---

## 5. Public API / behavior preservation

- **Single-tunnel configs must be byte-for-byte unaffected.** Path A
  keeps writing the legacy `wg_listen_port` ctrl field and the `WG_RX`
  flag; a single-tunnel config produces an identical shim ctrl block plus
  one entry in the new port map. The zero-cost-when-absent gate
  (`WG_RX`) is untouched, so non-WG deployments see no per-packet change.
- **Snapshot wire compatibility.** No `TunnelEndpointSnapshot` field
  changes are required for Steps 1/3; Step 2 adds a status-row field
  (state snapshot, not config), which is `#[serde(default)]`-safe in both
  directions. Watch the Go↔Rust `[]uint8` base64 trap (MEMORY #1961) if
  any new byte-slice field is added — local pubkey should travel as a hex
  STRING (as `peer_pubkey_hex` already does), not a `Vec<u8>`.
- **`show security wireguard [detail]` output stays stable**; the new
  `public-key` subcommand is additive.
- **Config grammar unchanged** — multi-tunnel is already expressible
  (one `tunnel wireguard` per interface/unit); no new `set` leaf.

---

## 6. Hidden invariants to respect

- **Kernel-verifier shim gate (#1864).** Any shim edit (Step 1) requires
  `make generate` with the pinned toolchain and must pass the kernel
  verifier. The shim program allowlist canary rejects new program
  symbols, so any new helper must inline (the existing
  `wg_steer_to_kernel` comment documents that a `#[cold]` variant tripped
  the canary). Path A's map lookup is a normal helper call, not a new
  program — should be fine, but the regen+verify gate is mandatory.
- **Hot-path allocation.** No per-packet allocation in the shim or the
  AF_XDP worker path. Path A adds one map lookup on the already-gated WG
  branch — no alloc. Engine selection stays `FastMap::get`.
- **Zero-cost-when-absent (#1432).** Do NOT add an unconditional
  `wg_listen_port` load; keep everything behind `WG_FLAG_RX`. The commit
  history explicitly records that a bare per-packet load nudged v6
  retransmits at line rate.
- **ABI / metadata-version.** Step 1 bumps the shim ctrl ABI
  (new map, or widened ctrl field). Bump `userspaceMetadataVersion`
  (currently 4) in lockstep on both sides; keep the C/Rust/Go size
  assertions (`const _: [(); N]`) coherent.
- **TAI64N monotonicity across reload.** `populate_wg_engines` already
  seeds high-water per engine on identity change. Multi-tunnel does not
  change this, but any refactor of that function must preserve per-id
  seeding (a re-handshake storm / black-hole is the failure mode).
- **HA / failover ordering.** WG endpoints carry a session-sync
  `TunnelEndpointID` path (`manager_ha.go`). Multiple WG endpoints
  multiply the per-id session-sync rows; verify failover preserves each
  tunnel's id→engine mapping and that control threads respawn per id on
  the new primary. `make test-failover` is mandatory because the change
  touches tunnel endpoint identity and the control-thread lifecycle that
  failover exercises.
- **Boot-class.** WG control threads spawn from forwarding state; a
  config that compiles but has two WG tunnels must not change boot
  classification. No interaction expected, but the second tunnel's bind
  failure (EADDRINUSE if a host wgN claims the port) must remain a
  per-thread tombstone+backoff (already handled in `wg_control.rs`), not
  a daemon-fatal — verify it stays per-id isolated.
- **Byte order / key encoding.** WG keys travel as hex strings in the
  snapshot; do not introduce a `Vec<u8>` field (MEMORY #1961 base64 wire
  trap). Local pubkey rendered to operators must be WG-canonical base64.
- **Dual-AST.** No new flat-set grammar is needed (multi-tunnel uses the
  existing per-interface tunnel stanza), so the flat vs hierarchical AST
  hazard does not apply to Steps 1/2/3 — but the `public-key`/
  `generate-private-key` operational commands go through cmdtree, not
  the config schema, so confirm completion/`?` help is wired in cmdtree
  only.
- **Port-collision across tunnels.** Two WG tunnels must not share a
  listen port. Today the single-port shim hides this; once multi-port is
  real, two endpoints with the same `wg_listen_port` would both bind and
  the second bind fails (EADDRINUSE) → silent dead tunnel. Add a
  commit-time validation in the Go compiler that two `mode=="wireguard"`
  endpoints cannot share a listen port (fail-closed at commit, not a
  runtime bind race).

---

## 7. Risk table (4 classes)

| Class | Risk | Likelihood | Mitigation |
|---|---|---|---|
| **Correctness** | Second tunnel's inbound UDP not steered → silent dead tunnel | High if Step 1 wrong | Path A exact-port-set map; two-WG functional test on loss cluster; assert both engines decap |
| **Correctness** | Two tunnels share a listen port → second bind EADDRINUSE, silent | Medium | Commit-time port-uniqueness validation (Go compiler), fail-closed |
| **Correctness** | generate-private-key clamp mismatch → derived pubkey ≠ engine's | Medium | Reuse X25519 clamp; round-trip test (generate → feed as privkey → engine derives same pubkey) |
| **Performance** | Shim per-packet regression (esp. v6 line rate) | Medium | Keep `WG_RX` gate; map lookup only on WG branch; perf-test v4+v6 line rate before/after |
| **Verifier/ABI** | Shim regen fails verifier or trips program-allowlist canary | Medium | Inline helper, no new program symbol; `make generate` pinned toolchain; verify on 6.18+ |
| **HA/failover** | Per-id engine/control-thread mapping lost on failover with 2 tunnels | Medium | `make test-failover`; assert both tunnels recover; per-id tombstone isolation preserved |
| **Lab/operational** | EADDRINUSE vs host wgN, learned-endpoint, MTU per tunnel | Low-Med | Reuse #1736 interop harness per tunnel; per-thread bind tombstone already isolates |

---

## 8. Test plan

- **Unit (Go):** port-uniqueness commit validation; `snapshotWgListenPort`
  → new all-ports collector parity; generate-private-key clamp + derived
  pubkey round-trip; `format/wireguard.go` renders local pubkey + the new
  `public-key` view.
- **Unit (Rust):** a real **two-WG-tunnel snapshot** (two
  `mode=="wireguard"` endpoints, distinct ports/keys) →
  `build_forwarding_state` yields two engines, two control-thread spawn
  desires, distinct listen ports; identity-stable Arc reuse holds
  per-id when one of two changes; status row carries each engine's local
  pubkey.
- **Shim:** `make generate` passes the kernel-verifier gate; a unit/host
  test (or the existing shim test harness) that `wg_steer_to_kernel`
  matches BOTH configured ports and still rejects non-local and non-WG
  UDP.
- **Functional (NEEDS the loss cluster lab):** bring up two WG tunnels on
  two ports to two peers (kernel WG via the #1736 interop harness, one
  peer per tunnel), confirm both handshake, both decap, both encap, and
  `show security wireguard` + `show security wireguard public-key` render
  both with correct local keys. Sustained iperf3 through each tunnel
  (MEMORY: never trust curl/200; use sustained iperf both directions,
  v4+v6, confirm `show security flow statistics` advances).
- **Perf (lab):** line-rate v4 + v6 through the non-WG fast path
  unchanged before/after the shim edit (the #1432 v6-retransmit
  sensitivity is the canary).
- **HA:** `make test-failover` with two WG tunnels configured — both
  recover, zero stuck sessions.

**This feature CANNOT be fully validated without the loss cluster** (two
real WG peers + line-rate forwarding + failover). Unit tests prove the
config/engine/telemetry plumbing; only the lab proves the shim steering
and dual-tunnel decap.

---

## 9. Increment plan (which ships first)

This is **multi-increment**. Three clean increments, each independently
reviewable and shippable:

- **Step 1 — shim multi-port steering + commit-time port uniqueness.**
  This is the increment that actually *unlocks* a second tunnel. It is
  the riskiest (hot-path shim, verifier gate, perf) and MUST go through
  the loss cluster + perf + failover before merge. **This is the
  shippable-first increment if the goal is "two tunnels actually work".**
  But it is also the one most defensible to PLAN-KILL if the perf/risk
  cost is judged too high for the demand.
- **Step 2 — local public key telemetry + `show security wireguard
  public-key`.** Pure additive, no hot-path, no shim. Shippable
  independently and is genuinely useful even with a single tunnel
  (operators currently cannot see their own public key). **Lowest risk;
  arguably the best first merge** — it delivers operator value with zero
  data-plane risk and can land while Step 1 is still in lab.
- **Step 3 — `request security wireguard generate-private-key`.** Pure
  Go utility, no hot-path, no shim, no daemon round-trip (Path 3a).
  Independently shippable. Lowest risk alongside Step 2.

Recommended merge order: **Step 2 + Step 3 first** (low-risk operator
value, no lab dependency), then **Step 1** gated on full lab validation.
Do not bundle Step 1 with 2/3 — Step 1's verifier/perf/failover gate
would needlessly block the safe CLI work.

---

## 10. Out of scope

- Full Junos WireGuard grammar (multi-peer per tunnel, fwmark, table,
  pre-shared keys) — the current grammar is deliberately narrower
  (one peer per tunnel; see `wireguardSchemaNode` and the S6 note in
  `types_routing.go:328`). Multi-peer-per-tunnel is a separate feature.
- AF_XDP hot-path WG decap (the current design decaps in the kernel
  socket via the control thread; there is no AF_XDP decap stage — S2a
  note in `wg/timers.rs:14`). Not part of multi-tunnel.
- Session migration of live WG transport sessions across config change
  (#1432 S5).
- Roaming / multiple peer endpoints per tunnel.
- Any DPDK/eBPF-dataplane work (both retired).

---

## 11. Open questions (for adversarial review)

1. **Is the demand real enough to touch the shim at all?** The shim is
   the single most verifier-/perf-constrained file in the tree. Steps 2+3
   deliver operator value with zero data-plane risk. Is there a concrete
   operator/topology that needs >1 WG tunnel TODAY, or is Step 1 churn we
   should defer until demand is proven? (This is the PLAN-KILL pivot for
   Step 1.)
2. **Path A (port-set map) vs Path B (fixed ctrl array)?** A scales but
   adds a BPF map + verifier surface + ABI bump; B caps tunnel count but
   needs no new map. Which does the team prefer given the shim regen
   cost, and what is an acceptable hard cap if B?
3. **Does adding ANY work to the WG steering branch regress v6 line
   rate?** #1432 recorded that even a bare `wg_listen_port` load nudged
   v6 retransmits. A map lookup is heavier than a compare. Must we
   benchmark before committing to Path A, and is the answer "single port
   stays a compare, only fall to the map for >1 port"?
4. **Port-uniqueness: commit-time reject vs runtime tolerate?** Should
   two WG tunnels sharing a listen port be a hard commit error
   (fail-closed, recommended), or tolerated with the second tombstoned at
   bind? The HA implication: a config-sync'd peer must reach the same
   verdict.
5. **Local public key encoding for the operator surface** — WG-canonical
   base64 (what peers paste) vs hex (what the snapshot carries) vs both?
   And does the snapshot need to carry the local pubkey at all, or should
   the Go side derive it from the (redacted-on-state) private key it
   never sees — meaning the Rust status row is the only source?
6. **generate-private-key in Go vs helper round-trip** — is there any
   requirement that the key come from the helper's RNG / be installed
   atomically, or is a stateless Go print (Path 3a) acceptable (it is for
   Junos `request` semantics)?
7. **Failover with N WG tunnels** — does the per-id session-sync +
   control-thread respawn scale cleanly to several tunnels, or does the
   per-id control-socket traffic (status poll, sync) hit the
   control-socket contention ceiling called out in CLAUDE.md?

---

## Claude self-SMR (hostile)

**Strongest objection to my own plan:** the issue is mostly already done,
and the one part that ISN'T (the shim single-port gate) is the part with
the worst risk/reward in the entire subsystem. The data-plane is already
multi-engine, multi-control-thread, multi-telemetry. The literal "blocker"
is a single 16-bit field in the verifier-gated shim plus a "first port
wins" helper in Go. To make a second tunnel work I must touch the one file
that requires `make generate`, a pinned toolchain, a kernel-verifier pass,
and a documented v6-line-rate sensitivity — for a feature whose real-world
demand is unproven (no operator request is cited in the issue; it reads
like a roadmap stub). Steps 2 and 3 (public-key show, generate-private-key)
are genuinely useful and cheap, but they are NOT what the issue title
promises ("multi-tunnel") — they are single-tunnel quality-of-life that
happens to be in the same file neighborhood.

Second objection: the issue's own implementation directions are wrong
("move config to per-interface InterfaceSnapshot" — it's already on
TunnelEndpointSnapshot; "BindingWorker holds a map indexed by port" — it's
ForwardingState holding a map indexed by id, and BindingWorker does NOT and
should NOT own the engines). Implementing the issue literally would be a
regression. A faithful implementer must reinterpret the whole task, which
is a smell that the issue should be rewritten before any code.

**Disposition: LIKELY-DEFER-MULTI-INCREMENT (with a Step-1 PLAN-KILL
caveat).**

- The feature is too large and too risk-stratified for one PR. Split as
  in §9.
- **Shippable first increment: Step 2 (local public-key telemetry +
  `show security wireguard public-key`) and Step 3
  (`request security wireguard generate-private-key`)** — low-risk, no
  hot-path, no lab dependency, real operator value, can merge
  immediately as a normal quad-reviewed PR.
- **Step 1 (shim multi-port steering) is LIKELY-DEFER-LAB AND a
  PLAN-KILL candidate.** It is the only increment that delivers literal
  "multi-tunnel", it REQUIRES the loss cluster (two real WG peers +
  perf + `make test-failover`), and its risk/reward should be explicitly
  ratified before any shim edit. If reviewers cannot point to a concrete
  multi-tunnel topology in demand, Step 1 should be PLAN-KILLed and the
  issue re-scoped to Steps 2+3 (rename the issue or close #1434 in favor
  of the smaller asks). Recommend bringing Step 1 to plan review with the
  Path A/B/perf questions (#2, #3) answered by a quick line-rate
  benchmark BEFORE committing to implementation.

Bottom line for the orchestrator: do NOT engineer this as a single PR. If
demand for >1 tunnel is real, ship Steps 2+3 now and take Step 1 to the
lab with a perf gate. If demand is unproven, ship Steps 2+3 and PLAN-KILL
Step 1, re-scoping the issue.
