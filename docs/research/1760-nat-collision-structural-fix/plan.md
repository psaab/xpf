# #1760 — NAT reverse-key 1:N collision: structural fix

**Status:** DRAFT v1 — pending adversarial plan review (Codex + AGY + Claude SMR)
**Branch:** `research/1760-nat-collision-counter`
**Issue:** #1760 (stage-1 counter shipped in #1762; this is stage-2)

---

## 1. Issue framing

#1760 is the correctness residue of the #1758 research: the secondary
reverse indices (`nat_reverse_index`, `reverse_translated_index`) are
single-valued (one reverse key `K` → one `u32` handle). When two live
sessions derive the same `K`, the index holds only one; the per-refresh
re-assert (`index_forward_nat_key_parts`) is last-writer-wins arbitration,
and value-guarded removal on expiry can delete `K` while a second live
session still needs it — permanently breaking that session's reverse path.

Stage-1 (the `nat_reverse_key_collisions` telemetry counter) merged in
**#1762** (`da85a8127`): displacement detected at the `nat_reverse_index`
re-insert with a displaced-handle guard, exported per-worker + aggregate to
Prometheus. **Live incidence on the loss cluster: 0** (interface-SNAT
config, idle/steady-state scrape). The operator chose to engineer the
structural fix now despite 0 observed incidence (latent-bug hardening).

## 2. The decisive architectural finding (changes the recommended fix)

The issue's "recommended approach" floats a **multi-valued reverse index**.
**That is architecturally wrong**, and the plan must say so:

`reverse_wire_key(forward, nat)` (`session/key.rs:84`) emits a *complete*
`SessionKey` — all six fields (`addr_family, protocol, src_ip, dst_ip,
src_port, dst_port`) — i.e. the **exact L3/L4 5-tuple a reply packet
carries**. `reply_matches_forward_session` (`key.rs`) only checks
`reverse_wire_key(forward) == reply_key || reverse_canonical_key == reply_key`
— it introduces **no field beyond `K` itself**.

Therefore **two live sessions sharing `K` have byte-identical reply tuples
at L3/L4.** A reply matching `K` is *genuinely ambiguous on the wire*:
with a multi-valued index you would have ≥2 candidate forward sessions,
both pass `reply_matches_forward_session`, and **there is no packet field
to disambiguate**. The NAT has mapped two distinct internal flows onto one
identical external 5-tuple; replies are physically indistinguishable.

Worked reachability (confirms genuine ambiguity, not index limitation):
- **Interface-SNAT** (`nat/source.rs:431`): `rewrite_src_port = None` →
  `K.dst_port = src_port` preserved. Two internal hosts SNAT'd to the same
  external `src_ip` (interface addr) that happen to use the same source
  port toward the same dst:port collide. Reply tuple
  `(dst_ip, ext_src_ip, dst_port, src_port)` identical.
- **DNAT-shared-backend** (`nat/destination.rs:126`): one client, same
  source port, to two VIPs both DNAT'ing to one `backend:port`. `K =
  (backend, client, backend_port, client_port)` identical; the original
  VIP is **not** on the reply, so the firewall cannot recover which VIP
  the reply belongs to. *Most operationally likely.*
- **NAT64** (`nat64.rs:97`): round-robin pool v4 addr, no port → same shape.
- **Non-bijective static NAT** (`nat/static_nat.rs:70`): two originals → one
  translated → identical reverse tuple.
- **Pool-mode SNAT is immune** because `owner_by_translated`
  (`nat/allocator.rs:461`) refuses a duplicate live external tuple at
  allocation — i.e. it *already does install-time prevention*. The fix
  generalizes that immunity to the other modes.

**Conclusion:** the only correctness-preserving fix is to **prevent the
collision at install** — refuse the second session, or disambiguate it so
the two sessions get distinct external tuples (distinct `K`). The
single-valued index is not the bug; the bug is admitting a second session
that aliases an existing live external identity.

## 3. Current behavior to preserve / not break

- `find_forward_nat_match` (`mod.rs:613`) looks up `K`, then **verifies**
  with `reply_matches_forward_session`. A wrong-handle collision today
  therefore yields either a dropped reply (verify fails) or a mis-NAT
  (verify passes for the wrong session) — both are corruption. The fix
  must not regress the verify path.
- The displaced-handle guard added in #1762
  (`index_forward_nat_key_parts`, `mod.rs:1393`) already distinguishes a
  benign re-assert (`prev == handle`, S1 re-winning its own `K`) from a
  genuine collision (`prev = Some(other)`). This is the exact hook the fix
  reuses — but at **install**, not on every per-packet re-assert.
- The displaced/incumbent handle may be **stale** (expired, not yet GC'd).
  A counter can over-count harmlessly; a *refusal* must not drop a new
  flow for a dead incumbent. The fix MUST check incumbent liveness
  (`entries.get(handle)` present AND not expired) before refusing.
- HA sync: a refuse/disambiguate decision must be **deterministic across
  peers** (both nodes must make the same choice) or session-sync will
  diverge. Reverse-sync replays installs; the decision must replay
  identically. This is the highest-risk surface — §7.

## 4. Path options

**Path A — Install-time refusal (RECOMMENDED for v1).** At forward-NAT
session install, if `K = reverse_wire_key(key, nat)` is already owned by a
**different, live** handle, refuse the new session: do not install, drop
its trigger packet, increment `nat_reverse_key_refused_total`. Correct for
**all four modes**. Failure mode = the second flow fails to establish
(a clean, observable SYN drop) instead of silently corrupting both.
Smallest blast radius; no new allocator; deterministic (both HA peers see
the same incumbent and refuse identically *if* the incumbent is synced
before the second install — see §7 risk).

**Path B — Source-port disambiguation (PAT) for SNAT/NAT64.** On
collision, allocate a free source port so `K` becomes unique (what
pool-mode already does). Strict Junos interface-source-NAT parity (Junos
interface NAT *is* PAT). But: requires a port allocator for interface-mode
(currently portless), changes the on-wire source port (visible to peers,
MSS/ALG interactions), and **cannot help DNAT-shared-backend or static
NAT** (no source rewrite available there) — those still need Path A. So
Path B is *additive on top of* Path A, not a replacement.

**Path C — Multi-valued index. REJECTED** (see §2): cannot disambiguate
identical reply tuples; would institutionalize a guess.

**Recommendation: ship Path A now** (correct for all modes, minimal,
the failure mode is strictly better than today). Treat Path B as a
*separate, optional* Junos-parity follow-up for SNAT/NAT64 only, its own
issue, gated on whether refusal-drops are observed via the new counter.

## 5. Concrete design (Path A)

**Install site.** Forward-NAT install flows through
`index_forward_nat_key_parts` (re-assert) and the initial install in
`update_session` / the install entrypoint. Add a pre-install guard in the
**non-reverse, NAT-present** branch only:

```rust
// pseudocode, in the install path BEFORE committing the new handle:
if !is_reverse && nat_rewrites_identity(&decision.nat) {
    let k = reverse_wire_key(key, decision.nat);
    if let Some(&incumbent) = self.nat_reverse_index.get(&k) {
        if incumbent != new_handle && self.is_live(incumbent) {
            self.nat_reverse_key_refused = self.nat_reverse_key_refused.saturating_add(1);
            return InstallOutcome::RefusedReverseKeyCollision; // drop trigger pkt
        }
        // incumbent dead/stale → fall through, new session displaces it
    }
}
```

- `is_live(handle)`: `entries.get(handle).filter(|r| !r.entry.is_expired(now))`.
- `nat_rewrites_identity`: true when the NAT changes the external tuple
  such that the reverse key is shared-able (i.e. not a no-op NAT). Pool-mode
  is already filtered out upstream by `owner_by_translated`; the guard is a
  cheap second line.
- The benign re-assert (S1 re-winning its own `K`) is `incumbent ==
  new_handle` → no refusal. Verified against #1762's existing guard.

**Caller handling.** The install entrypoint returns the refusal outcome up
to the packet path, which drops the trigger packet (SYN) — same disposition
as a policy deny / no-route. No partial session state is left behind.

**Counter.** Add `nat_reverse_key_refused` mirroring the #1762 counter end
to end: `SessionTable` field + accessor, worker snapshot
(`loop_body/mod.rs`), `worker_runtime` atomic, coordinator status,
`protocol/{binding,control}.rs`, Go `protocol.go`, Prometheus
`metrics_descriptors.go` (per-worker + aggregate), tests. (#1762 is the
exact template — same wiring, new name.)

## 6. Public API / invariants preserved

- No `SessionKey` / index *type* change (Path C avoided) → no
  reverse-lookup contract change, no HA wire-format change.
- `find_forward_nat_match` / `reply_matches_forward_session` untouched.
- `index_forward_nat_key_parts` re-assert semantics unchanged for
  non-colliding sessions (the overwhelming majority; counter is 0 live).
- The fix only ever *prevents* an install; it never changes an
  already-installed session's NAT.

## 7. Risk assessment

| Class | Level | Note |
|---|---|---|
| Behavioral regression | **MED** | A refusal drops a flow that today installs (and silently corrupts). Correct, but it IS a behavior change for the colliding case. Gate: counter shows refusals are as rare as collisions (0 live). |
| HA divergence | **HIGH** | If node A installed S1 but the sync to node B is in-flight when B installs S2, B's incumbent check misses S1 → B admits S2, A refuses it → divergent tables. Mitigation: the refusal must be **reproducible on reverse-sync replay** and the bulk-sync hold must settle incumbents first. Needs explicit design + `make test-failover`. |
| Borrow/lifetime | LOW | Guard is a `get` + `filter` before the `&mut` install; no aliasing. |
| Perf | LOW | One extra `FxHashMap::get` + liveness check on the **install** slow path only (not per-packet). |
| Architectural mismatch | LOW | Path A generalizes the already-proven pool-mode `owner_by_translated` immunity. |

## 8. Test plan

- Unit: reproduce the #1760 mechanical scenario (S1 install→`K→S1`; S2
  install collides → **refused**, S1 intact, `refused` counter = 1).
  Incumbent-dead variant (S1 expired → S2 admitted, displaces). Re-assert
  variant (S1 re-install → no refusal). One per reachable mode
  (interface-SNAT, DNAT-shared, NAT64, static).
- Differential vs master: non-colliding workloads install identically
  (counter stays 0, no behavior change).
- `cargo test` full + 5× flake on the new named tests; Go suite.
- **HA**: `make test-failover` — install collisions across a failover,
  assert no table divergence (the §7 HIGH risk). v4 + v6.
- Smoke matrix on loss cluster (deploy wipes CoS — re-apply): v4/v6 ×
  push/reverse × CoS off/on. Confirm `refused` counter stays 0 under
  normal traffic (no false refusals).

## 9. Out of scope

- Path B (PAT disambiguation) — separate Junos-parity follow-up.
- Multi-valued index (Path C) — rejected, §2.
- Changing pool-mode SNAT (already immune).

## 10. Open questions for adversarial review

1. Is the §2 claim airtight — is there ANY reply-packet field (ICMP id,
   the `reverse_canonical_key` alias) that distinguishes two `K`-colliding
   sessions and would make a multi-valued index viable after all? If so,
   Path C reopens.
2. §7 HA divergence: is install-time refusal safe under reverse-sync
   replay + bulk-sync hold, or does the non-determinism make refusal worse
   than today's silent corruption on a cluster? Could the fix be
   **owner-RG-gated** (only the RG owner refuses)?
3. Is dropping the trigger SYN the right disposition, or should the refused
   session fall back to **no-NAT pass / policy deny** semantics?
4. Incumbent-liveness check: is `is_expired(now)` sufficient, or are there
   closing/half-open states where the incumbent is "live" but its `K` is
   already reclaimable?
5. Given live incidence is 0, is even Path A justified, or is the correct
   research outcome "document + keep gated" (PLAN-KILL of the code change,
   keep the counter watching)? PLAN-KILL is an acceptable verdict.
