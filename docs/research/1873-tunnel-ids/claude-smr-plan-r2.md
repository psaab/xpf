# #1873 plan v2 — Claude SMR hostile review (round 2)

Reviewer: Claude (domain SMR). Posture: hostile, including against my
own v2 text. One self-found MAJOR, one MINOR, plus verification
results for the §11 questions I could resolve from code.

## MAJOR 1 — R-C as worded in v2 BREAKS the designed WG cold path

v2 §5 R-C says: "every site that maps a forwarded-frame build failure
to `fallback_to_slow_path = true` must instead DROP … when
`decision.resolution.tunnel_endpoint_id != 0`."

That is too broad. The slow-path reinjection of tunnel-marked inner
packets is the DESIGNED cold path for an EXISTING tunnel:

- `wg_encap_frame` returns `None` on `EncapError::NoSession` after
  arming a handshake request (`frame/wg.rs:101-106`) — i.e. every
  pre-handshake packet is a "build failure".
- The reinjected inner packet enters the kernel, which routes it via
  the wgN netdev route (Go pre-creates the TUN + routes), and the WG
  control thread reads it from the TUN and encrypts
  (`wg_control.rs:120-126` open_tun; `wg_control.rs:547` "Encap one
  inner IP packet read from the TUN and send it to the peer").

Dropping ALL tunnel-marked build failures would black-hole WG
cold-start traffic until the handshake completes with zero kernel
assist — a functional regression the live smoke would catch (cold
connects through the tunnel would stall).

The leak AGY r1 proved is specifically the ABSENT-endpoint case: the
tunnel netdev/route are gone (or going), so the kernel falls through
to the default route and the inner packet leaves PLAINTEXT on the
WAN. AGY r1's own required-revision wording was already correct:
drop when `tunnel_endpoint_id != 0` **and**
`forwarding.tunnel_endpoints.get(&id).is_none()`.

**Required v3 change:** R-C condition = id-unresolvable, not
build-failed. Chokepoint: `maybe_reinject_slow_path_from_frame`
(after the `local_tunnel_deliveries` LocalDelivery branch, before
`slow_path.enqueue`) — a single gate covers BOTH doors:
(a) build-failure fallback (`handle_forward_build_failure`,
`slow_path.rs:60-73`), and (b) the disposition-allowlist door in
`maybe_reinject_slow_path` (`slow_path.rs:95-101` allows `NoRoute` —
which is exactly what `resolve_tunnel_forwarding_resolution` returns
for an absent id, so a removed-tunnel session packet reaches the
reinjector WITHOUT any build attempt; v2's build-failure-site framing
misses this door entirely).

## MINOR 2 — R-B commit check must be symmetric across cluster nodes

The collision commit-error runs over the per-node EFFECTIVE config.
With `groups node0`-scoped tunnels (the wg-interop pattern), node0's
effective name set differs from node1's: a collision involving a
node0-scoped name would fail commit on node0 but pass on node1 —
a config-sync split where the originating node accepts and the peer
rejects (or vice versa). **Required v3 change:** run the collision
check over the UNION of tunnel names across all `groups` blocks plus
the main hierarchy (raw config), so accept/reject is identical on
both nodes. Union-checking is strictly more conservative and
content-deterministic.

## Verification results (§11 questions)

- **Q3 (R-D propagation)**: `SessionDeltaKind::Close` deltas drive
  live-table delete + shared-map removal + peer-worker replication +
  event-stream emission (`session_delta.rs:164-192`); Go maps
  close/delete to `SessionDeltaReasonClose` (`runtime_delta.go:121`).
  Standby applies its own snapshots → its own R-D walk purges its
  synced entries. No lingering-resync trace found. R-D design stands,
  conditional on implementing the purge AS Close deltas through that
  machinery (already the plan text).
- **Q6 (R-C completeness)**: enumerated reinjection doors:
  (a) `handle_forward_build_failure` → `_from_frame` (build-failure);
  (b) `maybe_reinject_slow_path` disposition allowlist (NoRoute /
  MissingNeighbor / LocalDelivery / NextTableUnsupported) — reachable
  by removed-id sessions via `lookup_forwarding_resolution_for_session`
  when the cached fallback returns None (`session_glue/mod.rs:96-101`);
  (c) `local_tunnel_deliveries` LocalDelivery branch — must stay OPEN
  (that is GRE local-origin inbound delivery, keyed by
  `local_ifindex`, not the encap direction). The single chokepoint in
  MAJOR 1 covers (a)+(b) and leaves (c) intact.
- **Q4 (consumer re-check around R-C/R-D)**: no array-by-id or
  dense-id assumption found near the touch points; purge walk
  operates on shared maps + worker session tables already keyed by
  full session keys.

## Verdict

PLAN-NEEDS-REVISION — v3 must (1) re-scope R-C to the
id-unresolvable condition at the `maybe_reinject_slow_path_from_frame`
chokepoint, (2) make the R-B commit check union-of-groups symmetric.
Path A v2 architecture otherwise stands; no kill found.
