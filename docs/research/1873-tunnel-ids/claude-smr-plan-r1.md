# #1873 plan v1 — Claude SMR hostile review (round 1)

Reviewer: Claude (domain SMR: HA/dataplane identity, CPU/SW design).
Posture: hostile. I tried to kill Path A three ways; two attacks
produced required revisions, none produced a kill.

## Attack 1 — determinism domain is WRONG in v1 (MAJOR, must fix)

Plan §5 assigns the id inside `addEndpoint`, i.e. AFTER the
eligibility gates (`ifaceByName` presence check at `tunnels.go:56-58`,
GRE source/dest gate at `tunnels.go:53`). Therefore the `used` set —
and hence collision probing — depends on RUNTIME interface state, not
config content alone:

- Node0 has `wg0`'s ifindex up at build time; node1 builds its
  snapshot in a window where `wg0`'s netdev is briefly absent
  (`InterfaceSnapshot.Ifindex <= 0` → not in `ifaceByName`). If any
  OTHER tunnel collides with `wg0`'s id, the two nodes probe
  differently → cross-node id disagreement on a tunnel NEITHER node
  edited. This contradicts §5's headline claim "both nodes compute ids
  from config content alone".

**Required revision (R1):** compute the id assignment over the FULL
sorted configured tunnel-name domain (every name that has a `Tunnel`
config, per-unit qualified — derivable from `cfg` alone, BEFORE
`ifaceByName`/source-dest gates), then emit only eligible rows. Ids
become a pure function of `cfg`; runtime interface presence can no
longer perturb probing. This also strengthens §11-q6 from "documented
residual" to "eliminated".

## Attack 2 — node-scoped config breaks "same config" premise (MINOR, document)

`groups node0`-scoped tunnel stanzas (exactly the pattern
`test/incus/wg-interop.sh` mandates for secondary suppression) mean
the EFFECTIVE config differs per node by design. A node0-only tunnel
participates in node0's probing domain but not node1's. Non-colliding
names still agree (hash is per-name); only collision chains involving
a node-scoped name can diverge across nodes — and a node-scoped
tunnel's sessions are never owned by the other node anyway. Needs a
sentence in §7 (invariant 1) so nobody later "fixes" determinism by
hashing the whole config. Not a kill: today's positional scheme is
strictly worse under node-scoped tunnels (EVERY later-sorting id
diverges across nodes, colliding or not).

## Attack 3 — wrong-tunnel encap under stable ids (attempted kill, FAILED)

Tried to construct a plaintext-leak or wrong-tunnel trace surviving
Path A:

- Stale id on removed tunnel: `frame/wg.rs:51-53` (`get(&id)?` on both
  endpoint and engine) and `gre.rs:308` (`get(...)?`) early-return
  None → frame dropped. `cached_session_resolution`
  (`session_glue/mod.rs:18-41`) preserves `tunnel_endpoint_id` in the
  fallback resolution, so the encap gate still routes through the
  tunnel path and hits the same `None` → drop. No plaintext egress
  found.
- Reuse hazard (§5 residual 2) is real but correctly characterized:
  requires a NEW tunnel whose hash equals a removed tunnel's id while
  sessions of the removed tunnel still live (~1/65535 per add vs
  certainty today). The A+D hybrid rejection in §5 is sound — history
  dependence re-breaks cross-node agreement, which the fixed-binary
  cluster wire (`sync_protocol.go:154/239/371/472`) cannot absorb.

## Checks that PASSED

- Consumer map §2 verified against code; I found no additional id
  consumer that assumes density/contiguity. `FastMap<u16,_>`
  (`types/forwarding.rs:23`), `BTreeMap<u16,_>` (`coordinator/mod.rs:68`),
  fixed-width u16 in event stream (`codec.rs:209`), cluster wire
  (`sync_protocol.go`), Go scans (`manager_ha.go:854,867`) — all
  value-agnostic. Status/display ordering changes (BTreeMap by id) are
  cosmetic.
- §6 "no wire schema change / no fixture regen" verified:
  `tests/fixtures/protocol_wire_v1.json:257` pins an empty
  `tunnel_endpoints` array; ids are values not schema.
- Path B/C/D kills are fair. B: `String` in
  `ForwardingResolution` violates hot-path allocation rules and the
  cluster `SessionValue` mirror is hand-rolled fixed offsets. C:
  leaves `decision.resolution.tunnel_endpoint_id` renumbering — the
  worst defect — unfixed. D: per-node history → permanent cross-node
  divergence.
- Test plan: hash-freeze literal pin is essential (wire-adjacent
  constant) — good. Rust `Arc::ptr_eq` survivor pin is the right
  contract test.

## Required changes for v2

1. **R1 (MAJOR):** id assignment domain = configured tunnel names from
   `cfg` only, pre-eligibility; emit-gates stay where they are.
2. **R2 (MINOR):** document node-scoped (`groups nodeN`) tunnels as a
   bounded, by-design per-node domain difference in §7.
3. **R3 (MINOR):** live-validation §9 should remove the tunnel whose
   name sorts FIRST (that's the case that renumbers the survivor under
   the old scheme) — state this explicitly so the test can't silently
   pick the order-insensitive variant.

## Verdict

PLAN-NEEDS-REVISION (R1 mandatory; R2/R3 editorial). Path A is the
right architecture; no kill found.
