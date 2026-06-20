# #1434 — Implement Multi-Tunnel WireGuard Support — research plan

**Status: DRAFT v2 (research, NOT reviewed, NOT approved, NO code written)**

Plan-of-action only. No production source is touched. No Codex/AGY/Copilot
pass has run. This v2 independently re-verifies every load-bearing claim
against `origin/master` at HEAD `fc3f41ef8` (a v1 draft existed on
`research/1434-multi-tunnel-wireguard`; this v2 confirms its central finding
holds on current master and re-states the increment plan). The disposition
section states plainly whether this should ship, defer, or be PLAN-KILLed.

---

## 1. Issue framing (as filed)

Issue #1434 "Implement Multi-Tunnel WireGuard Support" asks for:

- Support multiple WireGuard interfaces (wg0, wg1, ...).
- Per-interface private/public keys and per-interface UDP listen ports.
- Correct RX/TX routing based on port/identity.
- Implementation details (verbatim from the issue):
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
S2a-era mental model that no longer matches the shipped architecture. Most
of the literal task list landed under #1432 (S2a) and follow-ups (#1865,
#1866, #1904, #1910, #1919, #1736). A faithful plan must re-derive the
*actual* remaining gap rather than implement the issue's literal task list
— some of which would be a **regression** if implemented as written (the
issue says "hold a map indexed by port"; the shipped design holds a map
indexed by tunnel-endpoint *id*, which is correct; and config already lives
on `TunnelEndpointSnapshot`, not the global `ConfigSnapshot`).

---

## 2. Honest scope and value

**Value.** WireGuard is a shipped, operator-visible feature (telemetry in
#1865, address lifecycle in #1919, live kernel-WG interop harness in
#1736). Today an operator can configure exactly one *usable* WG tunnel: a
second tunnel on a different listen port is silently dead because its
inbound transport UDP is never steered to the kernel socket (see §3).
Multiple site-to-site WG peers, or WG to several hubs, is a normal
real-world topology. The feature is small in marginal code but real in
operator value: it removes an arbitrary "one tunnel" ceiling on an
otherwise complete subsystem, plus two genuinely missing CLI affordances
(seeing your own public key; generating a key pair).

**Scope reality.** Most of the literal issue task list is already
implemented (citations verified at HEAD `fc3f41ef8`):

- WG config is NOT global. It lives per-tunnel on `TunnelConfig`
  (`pkg/config/types_routing.go:330` `WgListenPort` et al.) and on
  `TunnelEndpointSnapshot` (`pkg/dataplane/userspace/protocol.go:311`;
  Rust `userspace-dp/src/protocol/snapshot.rs`). The Go emitter
  (`pkg/config/tunnelemit.go`) emits one endpoint per configured
  interface-level WG tunnel.
- The Rust forwarding state holds `wg_engines: FastMap<u16,
  Arc<WgEngine>>` keyed by tunnel-endpoint id
  (`userspace-dp/src/afxdp/types/forwarding.rs:31`), and
  `populate_wg_engines` (`forwarding_build/wg.rs:37`) builds one engine
  per `mode == "wireguard"` endpoint with per-id identity-stable Arc
  reuse (`wg.rs:54-81`).
- One WG control thread is spawned PER engine id, each binding its own
  kernel UDP socket on its own `wg_listen_port`
  (`coordinator/tunnel_supervision.rs:498` `spawn_wg_control_threads`,
  `:651` `spawn_one_wg_control_thread`, `:671` reads
  `endpoint.wg_listen_port`; bind in `coordinator/wg_control.rs:119`
  `bind_wg_socket`, with EADDRINUSE handled as a per-thread exit/tombstone
  at `wg_control.rs:117-128`).
- AF_XDP transit-egress encap selects the engine by id
  (`frame/wg.rs::wg_encap_frame` via `wg_engines.get(&id)`).
- Telemetry iterates a per-tunnel vector
  (`coordinator/status.rs:705-717`, rendered by
  `pkg/dataplane/userspace/format/wireguard.go`), and
  `show security wireguard [detail]` exists
  (`pkg/cmdtree/tree.go:448-450`).

So the literal asks "move config to per-interface", "hold a map of engines
indexed by port", "RX by dest port", "TX by wg_listen_port" are **already
true in spirit** (engines keyed by id, RX demuxed by the kernel per
bound-port socket, TX per-engine control thread). The *one* place still
hard-wired to a single tunnel is the **XDP shim ctrl block**: it carries a
single `wg_listen_port` and steers local-destination UDP for exactly one
port to the kernel
(`pkg/dataplane/userspace/maps_sync.go:1547` `snapshotWgListenPort` —
"first configured endpoint's listen port wins"; shim
`userspace-xdp/src/lib.rs:1246` `wg_steer_to_kernel`, single
`flow_dst_port == wg_port` compare).

**Net remaining work = the shim port-steering generalization (one genuine
hot-path change) + commit-time port-uniqueness validation + the two CLI
items (public-key show, generate-private-key) + a two-WG functional/unit
test.** Materially smaller than the issue implies.

---

## 3. What is already shipped (do NOT re-do) — verified at HEAD fc3f41ef8

| Capability | Where (verified) | Status |
|---|---|---|
| Per-tunnel WG config (privkey/pubkey/port/allowed-ips/endpoint/keepalive) | `pkg/config/types_routing.go:330`, parsed `compiler_interfaces.go:687` (`case "listen-port"`) | shipped (#1432) |
| Config-mode schema for `tunnel wireguard { ... }` | `pkg/config/schema_interfaces.go:353-372` `wireguardSchemaNode` | shipped |
| Per-endpoint snapshot WG fields (Go) | `pkg/dataplane/userspace/protocol.go:311-321` (`WgListenPort`, `WgLocalPrivkeyHex`, `WgPeerPubkeyHex`, `WgAllowedIPs`) | shipped (#1432) |
| Per-endpoint snapshot WG fields (Rust), privkey `skip_serializing` redacted | `userspace-dp/src/protocol/snapshot.rs:354-411` | shipped (#1432) |
| One `Arc<WgEngine>` per endpoint id, identity-stable Arc reuse, TAI64N seeding | `forwarding_build/wg.rs:37-81` | shipped (#1432 §4.2) |
| `wg_engines: FastMap<u16, Arc<WgEngine>>` | `afxdp/types/forwarding.rs:31` | shipped |
| One control thread per engine id, own UDP socket on own listen port; per-thread EADDRINUSE tombstone | `coordinator/tunnel_supervision.rs:498,651,671`; `coordinator/wg_control.rs:117-128` | shipped (#1432 S2a + #1866 lifecycle) |
| AF_XDP transit-egress encap selects engine by id | `frame/wg.rs::wg_encap_frame` (`wg_engines.get(&id)`) | shipped |
| Per-tunnel telemetry + `show security wireguard [detail]` | `coordinator/status.rs:705-717`, `format/wireguard.go`, `pkg/cmdtree/tree.go:448` | shipped (#1865) |
| Local public key derived at engine construction (accessor exists) | `wg/engine.rs:282` (field), `:370` (derive), `:463` `fn local_public_key()` | shipped (but NOT plumbed to status/CLI) |
| WG address lifecycle on tunnel removal | #1919, #1905 | shipped |
| Interface-level WG single-TUN-per-interface unit pick | `tunnelemit.go` (#1910/#1904) | shipped |
| Live kernel-WG interop harness | `test/incus/.../wg-interop.sh` (#1736) | shipped |

**Single-tunnel ceiling that remains (each verified at HEAD):**

1. **Shim port steering is single-port (FUNCTIONAL BLOCKER).**
   `snapshotWgListenPort` (`maps_sync.go:1547-1560`) iterates
   `TunnelEndpoints` and `return`s the FIRST `mode=="wireguard"`
   endpoint's `WgListenPort`. The shim packs ONE port into
   `UserspaceCtrl.wg_listen_port` (`lib.rs:114`) and `wg_steer_to_kernel`
   matches exactly that one port (`lib.rs:1247-1251`). A second WG tunnel
   on a different port will NOT have its inbound transport UDP steered to
   the kernel socket — it falls into the AF_XDP transit path and is
   dropped (no local session). This is the actual blocker that makes a
   second tunnel non-functional.

2. **No `show security wireguard public-key` / local-public-key surface.**
   The engine derives `local_public_key` at construction
   (`wg/engine.rs:282/370`) and exposes `local_public_key()`
   (`wg/engine.rs:463`), but the status row built in
   `coordinator/status.rs:710-711` only carries `listen_port` +
   `peer_pubkey_hex` — the LOCAL public key (the thing an operator hands
   to the peer) is never plumbed to the status row, the Go format, or any
   CLI command. `grep` for `public-key`/`local_public_key` across
   `pkg/cli`, `pkg/cmdtree`, `format/` returns zero hits.

3. **No `request security wireguard generate-private-key`.** Zero hits
   anywhere in `pkg`, `cmd`, `userspace-dp/src` (outside engine internals).
   The issue says "restore" but there is no evidence it ever shipped;
   treat it as net-new.

4. **No commit-time WG listen-port uniqueness validation.** `grep` of
   `compiler_interfaces.go`, `schema_walk.go`, `tunnelemit.go` finds no
   cross-endpoint WG-port collision check (the "collision gate" hits are
   tunnel-ID collision per #1814, unrelated). Two WG tunnels with the
   same `wg_listen_port` would today produce two control threads, the
   second of which fails its bind with EADDRINUSE and tombstones —
   a silent dead tunnel rather than a fail-closed commit error.

5. **No two-WG-tunnel test.** `two_tunnel_snapshot()`
   (`forwarding_build/tests.rs:2134-2165`) is GRE(id 824) + WG(id 7),
   NOT two WG tunnels. No test asserts two WG engines on two distinct
   ports both build, both bind, and both decap.

---

## 4. Concrete design (code-level)

### Step 1 — shim multi-port steering (the only hot-path change)

The shim must steer local-destination UDP to the kernel for ANY
configured WG listen port, not just the first. Three viable paths:

**Path A (RECOMMENDED): a dedicated WG-port set map.**
Add a small BPF hash/array map (e.g. `USERSPACE_WG_PORTS:
HashMap<u16, u8>` or a fixed `Array<u16; N>`) populated by Go on every
apply with the set of configured WG listen ports. `wg_steer_to_kernel`
becomes: still gated on `USERSPACE_CTRL_FLAG_WG_RX` (the bit-test that
keeps non-WG traffic zero-cost — `lib.rs:518`), then on the WG path do
`protocol==UDP && is_local_destination(pkt) && wg_ports.get(&dst_port)`.
Keep the single `wg_listen_port` ctrl field for back-compat / the common
single-tunnel case but treat the map as authoritative when populated.
`is_local_destination` MUST stay (the existing comment at `lib.rs:1243`
warns a port-only match would shunt transit/DNAT UDP to the kernel).
- *Pro:* unbounded port count, exact semantics; per-packet cost is one
  hash lookup ONLY on the already-gated WG branch (the #1432
  zero-cost-when-absent property is preserved for non-WG deployments).
- *Con:* new BPF map = new verifier surface + new Go map writer + ABI
  bump; the shim is the kernel-verifier-gated file (`make generate`,
  pinned toolchain, #1864), so any shim edit pays the full regen+verify
  gate, and a new program symbol would trip the program-allowlist canary
  (the lookup is a normal inlinable helper, not a new program — fine).

**Path B: widen the ctrl block to a small fixed port array.**
Replace `wg_listen_port: u32` with e.g. `wg_listen_ports: [u16; 8]` in
`UserspaceCtrl`. `wg_steer_to_kernel` loops the (tiny, unrolled) array.
- *Pro:* no new map; reuses the existing single-instance ctrl Array.
- *Con:* hard cap on tunnel count; a fixed-size loop in the hot path;
  ctrl-block ABI change (Go mirror + size assertions + metadata-version
  bump). The loop is strictly worse than the gated single compare for the
  single-tunnel common case unless first-slot-fast ordered (#1432 noted a
  bare load+compare nudged v6 retransmits at line rate).

**Path C: steer ALL local-destination UDP to the kernel when WG is on.**
Drop the per-port check; if `WG_RX` is set, any local-destination UDP
goes to the kernel.
- *Con:* WRONG. Would shunt every local UDP service (DHCP client,
  IKE/500/4500 for strongSwan, SNMP, syslog, RPM probes) to the kernel,
  bypassing the userspace policy engine for unrelated services. The
  `wg_steer_to_kernel` comment explicitly warns against the narrower
  version of this. **Rejected.**

**Recommendation: Path A.** Only option that scales, keeps
zero-cost-when-absent, and matches the engine-keyed architecture. Path B
is an acceptable smaller-footprint fallback if reviewers want to avoid a
new map, accepting a hard tunnel cap.

Go side for Path A: a new map writer next to `snapshotWgListenPort` that
collects ALL `mode=="wireguard"` endpoint ports into the set map, plus
keep writing the first port into the legacy ctrl field for single-tunnel
back-compat and the `WG_RX` flag. ABI/metadata-version bump handled like
prior shim ABI changes (`userspaceMetadataVersion` in lockstep both
sides; keep C/Rust/Go `const _: [(); N]` size assertions coherent).

### Step 1b — commit-time WG listen-port uniqueness (fail-closed)

Add a Go compiler/SchemaValidate check that two `mode=="wireguard"`
endpoints cannot share a `wg_listen_port`. Fail-closed at commit, not a
runtime bind race. The HA implication: a config-sync'd peer must reach the
same verdict (validation is deterministic on the snapshot, so it does).
This pairs with Step 1 — once multi-port steering is real, a duplicate
port is the new silent-failure mode and must be rejected up front. Small,
pure Go, no hot-path; bundle it WITH Step 1 (it is the safety rail for
Step 1).

### Step 2 — local public key plumbing + `show security wireguard public-key`

- Rust: add `local_pubkey_hex` to the WG status row built in
  `coordinator/status.rs:705-717`, sourced from
  `engine.local_public_key()` (`wg/engine.rs:463`, already public to the
  crate). Travel as a hex STRING like the existing `peer_pubkey_hex`
  (`status.rs:711`) — do NOT add a `Vec<u8>` field (MEMORY #1961 base64
  wire trap).
- Go: add `LocalPubkeyHex string` to the `WgTunnel` status struct
  (`pkg/dataplane/userspace/`), decode it from the snapshot.
- `format/wireguard.go`: render the local public key per tunnel. Operators
  paste WG keys as **base64** into peer configs, so render base64 (convert
  the hex the wire carries) for the operator surface.
- CLI: add `show security wireguard public-key` (child node under the
  existing `wireguard` node at `pkg/cmdtree/tree.go:448`; dispatch in the
  show-security dispatcher). Print, per configured WG tunnel, the
  interface/endpoint name, listen port, and local public key in the
  base64 form a peer needs.

Pure additive, no hot-path, no shim. Useful even with a single tunnel
(operators currently cannot see their own public key).

### Step 3 — `request security wireguard generate-private-key`

A stateless helper that emits a fresh clamped X25519 private key and its
derived public key for the operator to paste into config. It does NOT
mutate config (Junos `request` semantics) — it prints.

- **Path 3a (RECOMMENDED): pure Go.** Generate with
  `crypto/ecdh` (X25519) or `golang.org/x/crypto/curve25519`. No daemon
  round-trip, works with no dataplane loaded, trivially testable. Print
  private + derived public in WG base64. Must produce a clamped scalar so
  the derived public key matches what the engine derives from the same
  private key (round-trip test: generate → feed as `private-key` → engine
  derives the same public key).
- **Path 3b: control-socket RPC to the helper.** Heavier; couples a
  stateless utility to the dataplane lifecycle; the control socket is
  contended (CLAUDE.md control-socket rule). Rejected unless the key MUST
  come from the helper's RNG.
- Wire into cmdtree under `request security wireguard` + dispatch.

Pure Go utility, no hot-path, no shim, no daemon round-trip.

---

## 5. Public API / behavior preservation

- **Single-tunnel configs must be byte-for-byte unaffected.** Path A keeps
  writing the legacy `wg_listen_port` ctrl field + the `WG_RX` flag; a
  single-tunnel config produces an identical shim ctrl block plus one
  entry in the new port map. The `WG_RX` gate (`lib.rs:518`) is untouched,
  so non-WG deployments see no per-packet change.
- **Snapshot wire compatibility.** No `TunnelEndpointSnapshot` field
  changes for Steps 1/1b/3; Step 2 adds a status-row field (state, not
  config), `#[serde(default)]`-safe both directions. Local pubkey travels
  as a hex STRING (MEMORY #1961 `[]uint8` base64 trap avoided).
- **`show security wireguard [detail]` output stays stable**; the new
  `public-key` subcommand is additive.
- **Config grammar unchanged** — multi-tunnel is already expressible (one
  `tunnel wireguard` per interface/unit); no new `set` leaf. Step 1b adds
  a *rejection*, not a grammar change.

---

## 6. Hidden invariants to respect

- **Kernel-verifier shim gate (#1864).** Step 1 requires `make generate`
  with the pinned toolchain and must pass the kernel verifier on 6.18+.
  The program-allowlist canary rejects new program symbols, so any new
  helper must inline (the `wg_steer_to_kernel` comment at `lib.rs:1240`
  documents that a `#[cold]`/`#[inline(never)]` variant tripped the
  canary). Path A's map lookup is a normal helper call — fine — but the
  regen+verify gate is mandatory.
- **Hot-path allocation.** No per-packet allocation in shim or AF_XDP
  worker. Path A adds one map lookup on the already-gated WG branch — no
  alloc. Engine selection stays `FastMap::get`.
- **Zero-cost-when-absent (#1432).** Do NOT add an unconditional
  `wg_listen_port` load; keep everything behind `WG_FLAG_RX`. History
  records a bare per-packet load nudged v6 retransmits at line rate; a
  map lookup is heavier than a compare, so the single-port common case
  should stay a compare (consult the map only for >1 port, OR accept the
  lookup but benchmark v6 line rate first — open question §11.3).
- **ABI / metadata-version.** Step 1 bumps the shim ctrl ABI (new map, or
  widened ctrl field). Bump `userspaceMetadataVersion` in lockstep on
  both sides; keep the C/Rust/Go size assertions coherent.
- **TAI64N monotonicity across reload.** `populate_wg_engines` seeds
  high-water per engine on identity change; any refactor must preserve
  per-id seeding (re-handshake storm / black-hole is the failure mode).
- **HA / failover ordering.** WG endpoints carry a session-sync
  `TunnelEndpointID` path. Multiple WG endpoints multiply per-id
  session-sync rows; failover must preserve each tunnel's id→engine
  mapping and respawn control threads per id on the new primary.
  `make test-failover` is MANDATORY because the change touches tunnel
  endpoint identity + the control-thread lifecycle failover exercises.
- **Boot-class.** A config with two WG tunnels must not change boot
  classification; the second tunnel's bind failure (EADDRINUSE vs a host
  wgN) must remain a per-thread tombstone+backoff
  (`wg_control.rs:117-128`), not daemon-fatal — verify it stays per-id
  isolated.
- **Key encoding.** WG keys travel as hex strings; operator-facing output
  is WG-canonical base64. No `Vec<u8>` field (MEMORY #1961).
- **Dual-AST.** No new flat-set grammar (multi-tunnel uses the existing
  per-interface tunnel stanza); `public-key`/`generate-private-key` go
  through cmdtree (operational), not the config schema — confirm
  completion/`?` help is wired in cmdtree only.

---

## 7. Risk table

| Class | Risk | Likelihood | Mitigation |
|---|---|---|---|
| **Correctness** | Second tunnel inbound UDP not steered → silent dead tunnel | High if Step 1 wrong | Path A exact-port-set map; two-WG functional test on loss cluster; assert both engines decap |
| **Correctness** | Two tunnels share a listen port → second bind EADDRINUSE, silent | Medium | Step 1b commit-time port-uniqueness (Go), fail-closed |
| **Correctness** | generate-private-key clamp mismatch → derived pubkey ≠ engine's | Medium | Reuse X25519 clamp; round-trip test (generate → feed as privkey → engine derives same pubkey) |
| **Performance** | Shim per-packet regression (esp. v6 line rate) | Medium | Keep `WG_RX` gate; map lookup only on WG branch (or only on >1 port); perf-test v4+v6 line rate before/after |
| **Verifier/ABI** | Shim regen fails verifier or trips program-allowlist canary | Medium | Inline helper, no new program symbol; `make generate` pinned toolchain; verify 6.18+ |
| **HA/failover** | Per-id engine/control-thread mapping lost on failover with 2 tunnels | Medium | `make test-failover`; assert both tunnels recover; per-id tombstone isolation preserved |
| **Lab/operational** | EADDRINUSE vs host wgN, learned-endpoint, per-tunnel MTU | Low-Med | Reuse #1736 interop harness per tunnel; per-thread bind tombstone already isolates |

---

## 8. Test plan

- **Unit (Go):** Step 1b port-uniqueness commit validation; the new
  all-ports collector parity vs `snapshotWgListenPort`;
  generate-private-key clamp + derived-pubkey round-trip;
  `format/wireguard.go` renders local pubkey + the new `public-key` view.
- **Unit (Rust):** a real **two-WG-tunnel snapshot** (two
  `mode=="wireguard"` endpoints, distinct ports/keys — NOT the current
  GRE+WG `two_tunnel_snapshot`) → `build_forwarding_state` yields two
  engines, two control-thread spawn desires, distinct listen ports;
  identity-stable Arc reuse holds per-id when one of two changes; status
  row carries each engine's local pubkey.
- **Shim:** `make generate` passes the kernel-verifier gate; a host/unit
  test that `wg_steer_to_kernel` matches BOTH configured ports and still
  rejects non-local and non-WG UDP.
- **Functional (NEEDS the loss cluster lab):** bring up two WG tunnels on
  two ports to two peers (kernel WG via the #1736 interop harness, one
  peer per tunnel); confirm both handshake, both decap, both encap, and
  `show security wireguard` + `show security wireguard public-key` render
  both with correct local keys. Sustained iperf3 through EACH tunnel both
  directions, v4+v6 (MEMORY: never trust curl/200; confirm
  `show security flow statistics` advances).
- **Perf (lab):** line-rate v4 + v6 through the non-WG fast path
  unchanged before/after the shim edit (the #1432 v6-retransmit
  sensitivity is the canary).
- **HA:** `make test-failover` with two WG tunnels — both recover, zero
  stuck sessions.

**Step 1 CANNOT be fully validated without the loss cluster** (two real WG
peers + line-rate forwarding + failover). Unit tests prove the
config/engine/telemetry plumbing; only the lab proves the shim steering
and dual-tunnel decap. Steps 2/3 are fully validatable by unit tests.

---

## 9. Increment plan (which ships first)

This is **multi-increment**. Three clean increments, each independently
reviewable and shippable:

- **Increment 1 (Step 2 + Step 3) — operator-visible CLI, NO hot-path,
  NO lab.** Local-public-key telemetry + `show security wireguard
  public-key` + `request security wireguard generate-private-key`. Pure
  additive Go + a thin Rust status-row field. **This is the feasible small
  first increment.** It delivers real operator value (you currently cannot
  see your own public key, nor generate a key pair) with zero data-plane
  risk, no shim regen, no lab dependency. Shippable as one normal
  quad-reviewed PR. Size: small (~1 Rust status field + accessor wiring,
  ~1 Go status field, 1 format change, 2 cmdtree nodes + 2 dispatchers, 1
  Go keygen util, ~4-5 unit tests).
- **Increment 2 (Step 1 + Step 1b) — shim multi-port steering +
  commit-time port uniqueness.** The increment that actually *unlocks* a
  second usable tunnel. Riskiest (hot-path shim, verifier gate, perf, ABI
  bump) and MUST go through the loss cluster + perf + `make test-failover`
  before merge. **This is the "two tunnels actually work" increment** —
  and the one most defensible to gate hard or PLAN-KILL if perf/risk are
  judged too high for demand. Bring to plan review with the Path A/B and
  v6-line-rate questions (§11.2/§11.3) answered by a quick benchmark
  BEFORE any shim edit.
- **(Test slice rides Increment 2):** the two-WG-tunnel Rust unit test +
  the lab functional/perf/failover validation.

Recommended order: **Increment 1 first** (low-risk operator value, no lab
dependency), then **Increment 2** gated on full lab validation. Do NOT
bundle Increment 2 with Increment 1 — Increment 2's verifier/perf/failover
gate would needlessly block the safe CLI work.

---

## 10. Out of scope

- Full Junos WireGuard grammar (multi-peer per tunnel, fwmark, table,
  pre-shared keys) — the current grammar is deliberately narrower (one
  peer per tunnel; `wireguardSchemaNode`, the S6 note in
  `types_routing.go`). Multi-peer-per-tunnel is a separate feature.
- AF_XDP hot-path WG decap (current design decaps in the kernel socket
  via the control thread; there is no AF_XDP decap stage — S2a note in
  `wg/timers.rs`). Not part of multi-tunnel.
- Session migration of live WG transport sessions across config change
  (#1432 S5).
- Roaming / multiple peer endpoints per tunnel.
- Any DPDK/eBPF-dataplane work (both retired).

---

## 11. Open questions (for adversarial review)

1. **Is demand for >1 tunnel real enough to touch the shim at all?** The
   shim is the single most verifier-/perf-constrained file in the tree.
   Increment 1 delivers operator value with zero data-plane risk. Is there
   a concrete operator/topology that needs >1 WG tunnel TODAY, or is
   Increment 2 churn to defer until demand is proven? (This is the
   PLAN-KILL pivot for Increment 2.)
2. **Path A (port-set map) vs Path B (fixed ctrl array)?** A scales but
   adds a BPF map + verifier surface + ABI bump; B caps tunnel count but
   needs no new map. Which, given the shim regen cost, and what is an
   acceptable hard cap if B?
3. **Does adding ANY work to the WG steering branch regress v6 line
   rate?** #1432 recorded that even a bare `wg_listen_port` load nudged v6
   retransmits. A map lookup is heavier than a compare. Benchmark before
   committing to Path A; consider "single port stays a compare, only fall
   to the map for >1 port".
4. **Port-uniqueness: commit-time reject (recommended, §Step 1b) vs
   runtime tolerate (tombstone the second)?** HA: a config-sync'd peer
   must reach the same verdict — commit-time validation is deterministic
   on the snapshot, so it does.
5. **Local public key encoding for the operator surface** — WG-canonical
   base64 (what peers paste) vs hex (what the snapshot carries) vs both?
   And: should the snapshot carry the local pubkey at all, or could the
   Go side derive it from the privkey? (The privkey IS present Go-side at
   `protocol.go:312` `WgLocalPrivkeyHex`, so a Go-side derivation is
   possible and avoids a Rust status-row change — weigh against the Rust
   engine being the authoritative source of truth.)
6. **generate-private-key in Go (Path 3a) vs helper round-trip (3b)** —
   any requirement the key come from the helper's RNG / be installed
   atomically, or is a stateless Go print acceptable (it is for Junos
   `request` semantics)?
7. **Failover with N WG tunnels** — does per-id session-sync +
   control-thread respawn scale cleanly to several tunnels, or does the
   per-id control-socket traffic (status poll, sync) hit the
   control-socket contention ceiling (CLAUDE.md control-socket rule)?

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
like a roadmap stub). Increment 1 (public-key show, generate-private-key)
is genuinely useful and cheap, but it is NOT what the issue title promises
("multi-tunnel") — it is single-tunnel quality-of-life that happens to be
in the same file neighborhood.

Second objection: the issue's own implementation directions are wrong
("move config to per-interface InterfaceSnapshot" — it's already on
`TunnelEndpointSnapshot`; "BindingWorker holds a map indexed by port" —
it's `ForwardingState` holding a map indexed by id, and `BindingWorker`
does NOT and should NOT own the engines). Implementing the issue literally
would be a regression. A faithful implementer must reinterpret the whole
task — a smell that the issue should be re-scoped before any code.

Third objection (verification honesty): this v2 re-verified every claim at
HEAD `fc3f41ef8` and found NO drift from the v1 finding — but I did NOT run
the helper, deploy to the lab, or prove the second tunnel actually dies. I
proved it *should* die by reading `snapshotWgListenPort` (first-wins) +
`wg_steer_to_kernel` (single compare) + `is_local_destination` (mandatory).
A reviewer should demand a lab repro (config two tunnels, tcpdump the
second port, confirm the inbound transport UDP is not decapped) before
ratifying Increment 2's premise.

**Disposition: PLAN-DEFER-MULTI-INCREMENT — with a feasible small first
increment available now.**

- The feature is too large and too risk-stratified for one PR. Split as in
  §9.
- **Feasible small first increment (PLAN-READY): Increment 1 — Step 2
  (local public-key telemetry + `show security wireguard public-key`) +
  Step 3 (`request security wireguard generate-private-key`).** Low-risk,
  no hot-path, no shim, no lab dependency, real operator value. Mergeable
  as a normal quad-reviewed PR. This is what I recommend doing first if
  the campaign wants forward progress on #1434 now.
- **Increment 2 (shim multi-port steering + port-uniqueness) is
  DEFER-LAB AND a PLAN-KILL candidate.** It is the only increment that
  delivers literal "multi-tunnel", REQUIRES the loss cluster (two real WG
  peers + perf + `make test-failover`), and its risk/reward must be
  explicitly ratified (with a v6-line-rate benchmark and a lab repro of
  the dead second tunnel) before any shim edit. If no concrete >1-tunnel
  topology is in demand, Increment 2 should be PLAN-KILLed and #1434
  re-scoped to Increment 1 (then closed), with multi-port steering filed
  as its own demand-gated issue.

Bottom line for the orchestrator: do NOT engineer this as one PR. Ship
Increment 1 now (small, safe, real value). Take Increment 2 to plan review
gated on (a) a cited multi-tunnel demand, (b) a v6-line-rate perf budget,
and (c) a lab repro confirming the second tunnel is currently dead.
