# #1758 — Path E follow-up: session-refresh secondary-index re-assert

**Status: DRAFT v1 (pending Codex + AGY + Claude SMR).**

**Reachability verdict (Step 1): REACHABLE.** Two *live* sessions CAN
derive the same secondary key `K` in the `nat_reverse_index` —
specifically via **interface-mode source NAT** (`source-nat { interface; }`),
which is the *default/primary* SNAT mode and the mode the HA cluster smoke
config itself uses (`docs/ha-cluster-userspace.conf:197/201/209`).
Interface-mode SNAT rewrites only the source IP, **not** the source port
(`nat/source.rs:431-441`, `rewrite_src_port` stays `None`). Two distinct
internal hosts using the **same ephemeral source port** to the **same
external server** therefore translate to the **same external tuple**
`(egress_ip, src_port)` → the same reverse-wire key `K`.

**But the right fix is NOT "remove the re-assert."** The re-assert is
last-writer-wins arbitration of an inherently **1:N** mapping
(`nat_reverse_index: FxHashMap<SessionKey,u32>` — single-valued). Removing
it trades the expiry-deletes-the-victim corruption AGY described for a
*different* corruption (install-time displacement leaves the older live
session's reverse path permanently dead). The underlying defect is
structural: a single-valued reverse index cannot represent two live
sessions sharing `K`. See §5.

**Recommendation (Step 2/3): this is a latent bug, but a NARROW and
LOW-SEVERITY one, and the perf-opt framing (#1758 title) is the wrong
lever. Recommend: (a) close the "~1% perf opt" framing as PLAN-KILL — do
NOT remove the re-assert (it is load-bearing); (b) file/keep a separate
correctness tracker for the structural 1:N collision with the bounded
real-world severity below, and decide fix-vs-accept there.** The single
clean code change worth shipping now is small: make the secondary-index
collision *observable* (a counter) so we can measure whether it ever
fires in production before paying for a multi-valued index.

---

## 1. Question framing

#1758 asks whether the unconditional secondary-index ADD re-assert in
`SessionTable::update_session` / `refresh_for_ha_transition`
(`session/mod.rs:902`, `:1043`) — preserved byte-identically by #1753 Path
E from the old `remove_entry`+`restore_entry` — is a harmless ~1% perf
opportunity or a latent NAT-corruption bug. AGY argued both sides across
review rounds (r1 "structurally necessary" → r2 "causes corruption"). The
deciding fact: **can two live sessions derive the same secondary key K?**

## 2. The mechanism (code walk)

`index_forward_nat_key_parts` (`session/mod.rs:1343-1374`) inserts, for a
forward (non-reverse) entry, into a single-valued map:

```
self.nat_reverse_index.insert(reverse_wire_key(key, nat), handle);   // :1357
```

`FxHashMap::insert` **overwrites** any existing `K→handle`. There is no
insert-if-absent. The same unconditional insert runs in three places:
`install_with_protocol_with_origin:700`, `upsert_synced_with_origin:787`,
and the refresh re-assert `update_session:902`.

Removal is **value-guarded** (`remove_forward_nat_index_parts:1411-1414`):
`K` is deleted only if `nat_reverse_index[K] == handle_being_removed`.

`reverse_wire_key` (`session/key.rs:84-122`) for a SNAT'd forward flow =
`{src=server, dst=(rewrite_src ip, rewrite_src_port-or-orig-src-port)}`.
For **interface-mode SNAT** `rewrite_src_port` is `None`, so the dst port
is the *original client source port*.

Lookup of the reverse packet (`find_forward_nat_match:585-599`) resolves
`K → handle`, then **re-validates**: it recomputes the transform from the
resolved record and rejects on mismatch. So a mis-pointed `K` yields a
*miss* (reply dropped / treated as new), not a wrong-session match — the
read side is self-defending. The damage is on the **index-occupancy /
deletion** side, not on read-misrouting.

## 3. Allocator uniqueness — pool-mode is SAFE

`nat/allocator.rs` tracks `owner_by_translated: FxHashMap<TranslatedTuple,
AllocationOwner>` under one `Mutex`. `assign_owner_locked:461` refuses a
tuple already owned; `claim_free_port_locked:416` advances to the next
port on refusal. A tuple is freed only by `release_flow` / `rollback_flow`
/ `gc_expired_locked`, all of which require the owning flow to be gone.

**Empirical probe** (throwaway, reverted): a single pool address with a
2-port range handed flows distinct ports `40000`, `40001`, then returned
`AllocatorExhausted` for every subsequent live flow — it NEVER duplicated
an external `(ip,port)` among live flows. **Pool-mode SNAT cannot reach
the K-collision while both flows are live.**

GC-window note: `expire_stale_entries` (`session/mod.rs:367`) calls
`remove_entry` (clearing `K`) and the worker loop calls
`release_source_nat_allocation` (freeing the tuple for reuse) in the
**same single-threaded `&mut sessions` iteration**
(`afxdp/worker/loop_body/mod.rs:668-687`). The session index `K` is
removed *before* the pool tuple becomes reclaimable, so a reused pool
tuple's new session indexes a `K` that is already vacant — no overlap.

## 4. Interface-mode SNAT — REACHABLE (the one live path)

Interface-mode SNAT (`nat/source.rs:431-441`) returns
`NatDecision{ rewrite_src: Some(egress), rewrite_src_port: None }` — **no
port allocator involvement, no port rewrite, no uniqueness tracking.**

**Empirical probe** (reverted): two sources `10.0.0.1:5555` and
`10.0.0.2:5555` to `8.8.8.8:443`, both interface-NAT'd to egress
`203.0.113.9`, produced **identical** `reverse_wire_key` (`rk_equal=true`).

End-to-end through `SessionTable` with production-shaped interface-mode
decisions:
- install S1 → `K→S1`; install S2 → `K→S2` (S1 silently displaced).
- S1 refresh (`refresh_local`) re-asserts → `K→S1` (S2 now displaced).
- S2 kept live via `lookup` (which does **not** re-assert `K`).
- S1 expires → value-guarded removal sees `K→S1` → **deletes K**.
- Result: `s2_live=true reply_resolves=None` — S2 is a live session whose
  reverse path is permanently gone. **AGY r2's trace reproduced exactly.**

**Reachability conditions (all required, conjunctive):**
1. interface-mode SNAT (default mode — common), AND
2. two internal hosts behind the same egress IP, AND
3. the **same source L4 port** in flight to the **same `(server_ip,
   server_port)`** simultaneously, AND
4. one session refreshes (re-winning `K`) then expires while the other is
   still live and has *not* refreshed in between.

With OS-random ephemeral source ports (Linux 32768–60999, ~28k values)
the birthday-collision odds per (host-pair, server) are low but **nonzero
and unbounded over time at scale** — and become *likely* for workloads
with fixed/low-entropy source ports (e.g. clients binding a fixed source
port, some VoIP/RTP, hashed L4 source-port pinning).

## 5. Why "remove the re-assert" is NOT a clean fix

The re-assert is **load-bearing**. Probe `displacement_victim` (reverted):
- install S1 (`K→S1`), install S2 (`K→S2`, hijack) — S1's reverse path is
  now dead *at install time*, before any refresh.
- S1 (the live victim) refresh **re-wins** `K→S1` via the re-assert.

So the re-assert is the *only* mechanism by which a displaced-but-live
session recovers its reverse index. Remove it on the no-reindex path and:
- you fix the "S1-refresh-then-expire deletes S2" ordering, BUT
- you permanently strand any session displaced by a *later* install
  (install-time hijack) — it can never recover `K` while live.

Both behaviors are corruption; the re-assert merely chooses last-writer-
wins. **The true defect is the single-valued `nat_reverse_index` under a
1:N collision.** A correct fix requires the index value to be a *set* of
handles (or a collision chain) with per-handle value-guarded add/remove —
a structural change, not a one-line deletion. That is exactly the
#1207/#1545/#1317 "structural rearchitecture dressed as a perf nit" trap;
it must not be smuggled in under a ~1% perf banner.

## 6. Severity assessment (honest)

- **Blast radius:** one session's reverse path (one flow), not table-wide.
- **Self-recovery:** the read side re-validates, so a TCP flow that keeps
  sending will re-`refresh` (re-winning `K`) on its next forward packet —
  the dead window is bounded by the refresh cadence, and the flow is only
  permanently dead if it goes silent in the forward direction while the
  colliding peer churns the index. For long-idle-then-reply patterns (a
  server pushing data after client silence) the reverse packet can miss →
  treated as a new/unmatched flow → policy re-eval / drop depending on
  zone policy. UDP (no forward keepalive) is more exposed than TCP.
- **Pool-mode (port-overloaded) SNAT is immune** (§3). Operators who need
  many-to-one masquerade with guaranteed reverse-path integrity already
  have the safe mode available.
- **Pre-existing:** #1753 preserved this byte-identically; not a #1753
  regression. All four #1753 reviewers verified parity — correctly.

Net: a real but **narrow, bounded, self-healing-on-active-flows** latent
bug in the *default* SNAT mode. Not a fire; not nothing.

## 7. Recommendation

1. **PLAN-KILL the #1758 perf framing.** Do not remove the re-assert. It
   is load-bearing (§5); removing it is not a fix and the ~1% is not worth
   trading one corruption for another. Label `plan-kill` + keep the perf
   issue closed.
2. **Spin a separate correctness tracker** for the structural 1:N
   interface-mode-SNAT reverse-index collision, carrying §4 conditions +
   §6 severity + the four reverted probes as the repro spec. Decide fix
   (multi-valued index / collision chain) vs documented-accept there, with
   its own gated /research. Do **not** auto-escalate to a rearchitecture.
3. **Optional small, safe, shippable now:** add a release-mode counter
   incremented when `index_forward_nat_key_parts` overwrites a *different*
   live handle on `nat_reverse_index` (collision-displacement counter),
   exported via the existing session-stats path. This makes the collision
   *observable in production* so the fix-vs-accept decision in (2) is
   data-driven rather than speculative. This is the one change that earns
   its keep; it is not part of #1758's perf ask and can be its own tiny
   PR.

## 8. Repro (the reverted probes — to be re-added by the fix PR, if any)

Four `#[test]` probes were written in
`userspace-dp/src/session/tests.rs`, run green, and reverted (research-
only; no production source modified):
- `probe_1758_allocator_uniqueness` — pool-mode never duplicates a live
  tuple (proves §3).
- `probe_1758_interface_mode_collision` — interface-mode yields identical
  external tuple for two sources sharing a source port (proves §4 cond).
- `probe_1758_iface_mode_end_to_end_corruption` — full S2-reverse-path
  deletion (`s2_live=true reply_resolves=None`).
- `probe_1758_counterfactual_no_reassert` — without the re-assert, S2
  survives THIS ordering (`reply_resolves=Some(S2)`)…
- `probe_1758_displacement_victim` — …but install-time hijack strands the
  older live session without it. Together (4) prove removal is not a fix.

## 9. Risk

| Option | Risk |
|---|---|
| Remove re-assert (#1758 literal ask) | HIGH — not a fix; introduces install-displacement corruption; trades bugs |
| Multi-valued reverse index | MED/HIGH — structural; the #1207/#1545/#1317 trap; needs its own research + differential tests |
| Collision-displacement counter only | LOW — observability, no behavior change |
| Document-accept (pool-mode is the safe mode) | LOW — operator guidance |

## 10. Out of scope

- Implementing a multi-valued / chained reverse index (own tracker).
- Touching the pool-mode allocator (proven immune).
- Any change to #1753 (it is correct parity; closed).

## 11. Open questions for adversarial review

1. Is the read-side re-validation (`find_forward_nat_match:589-591`)
   sufficient that the *only* observable harm is a reverse-path **miss**
   (drop / new-flow re-eval), never a wrong-session **mismatch** (packets
   delivered to the wrong host)? Quote the validation that bounds it.
2. Is there any *other* live K-collision vector I missed — static NAT
   (`static_nat.rs`), DNAT reverse, NAT64 AF-cross, or the
   `reverse_canonical` (no-NAT) second insert at `:1359-1362`? (My read:
   reverse_canonical for non-NAT collides only on identical 5-tuple =
   same primary key = not distinct sessions; DNAT/static map 1:1 and are
   port-preserving but distinct dst → distinct K. Confirm or break.)
3. Does any forward-keepalive cadence guarantee bound the dead-window for
   TCP such that severity is genuinely "self-healing", or is there a
   silent-forward / active-reverse pattern (server-push, UDP) where the
   reverse path stays dead indefinitely? This sets fix-vs-accept.
4. Is the collision-displacement counter (rec 3) actually cheap on the
   refresh hot path (one extra `get` before the `insert` to compare the
   prior handle), or does it reintroduce the per-packet cost #1753
   removed? If it costs, gate it behind a debug/feature flag.
