# Claude SMR — hostile plan review r4 (#5837)

**Verdict: PLAN-READY.** v4 closes Codex r3's transaction-correctness findings, including
the two genuine new regressions (rollback-deletes-active-key, IPv6-AH shunt). I
independently confirmed the two load-bearing code facts and the fixes are correct.

## Codex r3 dispositions — verified
- **Rollback-deletes-active-key (r3 #1/#2) → fixed correctly.** v4 §5d computes
  `new_only = desired − current`, inserts only new keys with `BPF_NOEXIST`, and rolls back
  only `new_only` — so an unchanged active-generation key is never overwritten or deleted.
  Union-capacity preflight (`|current ∪ desired|` per family) captures the transient
  insert-before-delete window. This is the correct transactional shape.
- **Mandatory pins (r3 #3) → fixed.** Confirmed `open_optional_map` returns `Ok(None)` on
  an empty pin (snapshot.rs:369, "feature genuinely absent; no gating"). v4 §5c opens the
  intent maps fail-closed when the capability is active — a translating config can't
  silently activate without intent FDs.
- **Restart persistence (r3 #3) → fixed.** My r2/r3 "empty on start → status quo" reasoning
  was wrong for restart (pinned maps persist, loader_userspace_shim.go:63). v4 §5b now
  mandates a restart reconcile against the recompiled authoritative set before readiness,
  and correctly limits the empty→status-quo fail-safe to a truly fresh node.
- **IPv6-AH regression (r3 #4) → fixed, and it's real.** Confirmed against the helper's own
  doc (forwarding/mod.rs:1288-1305): the IPv6 parser walks through AH (lib.rs:1269), so
  `meta.protocol` becomes the inner next-header and the helper's `PROTO_AH` arm never fires
  for IPv6 AH — which "still reaches the kernel XFRM stack via the shim's
  `is_local_destination`" shunt. v4's `ah_present` guard (§5a/§8.6) declines AH-carrying
  packets so the shunt is preserved. Good catch by Codex; correctly resolved.
- **Complete §5d set / activation ordering / availability scope / exact-port static NAT /
  ladder disambiguation** — all present and matched to code cites.

## Assessment
The plan is now implementation-ready at a level of detail well beyond a typical research
deliverable — every failure mode Codex probed (byte-order, collision, atomicity, capacity,
restart persistence, IPv6-AH cross-layer, over-steer availability) has a specified, code-
verified resolution. The one irreducible unknown remains the verifier verdict, which both
reviewers agree is acceptably bounded (real `BPF_PROG_LOAD` gate + explicit v4-only/reclaim/
PLAN-KILL ladder + machine-readable capability tag). That is exactly the right shape for a
shim-gated /research output.

## Residual (non-blocking, implement-time)
- `ah_present` adds a field to `ParsedPacket` and a set in the IPv6 `NEXTHDR_AUTH` arm — a
  small, contained parser change; verify it doesn't perturb the verifier budget (it's one
  bool, negligible, but it lands in the hot parser).
- The §5d capability-tag ↔ diagnostic wiring is a Go/Rust contract to nail at implement time.

## Bottom line
v4 resolves every r3 finding with correct, code-verified fixes, including two real
regressions. Architecture and verifier bounding were already accepted. **PLAN-READY.**
I'd green-light `/engineer 5837`: build Phase-1 exact-both, `shimverify` FIRST, treat REJECT
as the ladder fork.
