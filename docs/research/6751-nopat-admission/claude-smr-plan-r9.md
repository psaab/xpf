# Claude SMR hostile plan review — #6751 plan v9 (round 9, convergence adjudication)

Reviewer: Claude SMR. Posture: hostile — v9 is my own fold of Codex r8's
zero-id blocker; this pass re-walks the fail-closed consequence and the
compare-and-remove identity chain, then attacks the drop-counter semantics
the fold introduces. Codex r9 was in flight when this was written.

## Fail-closed zero-id alias import — consequence verified safe

Codex r8's demand was "fail closed or use a genuine persistent alias-group
identity"; v9 fails closed. The consequence needed verification, and AGY
r9's walk matches the code I re-read: `publish_shared_session` populates
`shared_forward_wire_sessions[forward_wire_key(entry)]` for every
non-reverse entry whose wire key differs from its canonical key
(shared_ops.rs:943-957 region), so for an id-0-synced fabric-redirect
session whose explicit alias import dropped, the base session's publish
ALREADY populated the forward-wire map with the same wire tuple →
`lookup_shared_forward_wire_match` resolves the fabric-return packet to
the base entry safely (shared_ops.rs:585-635). The missing explicit alias
row degrades nothing on the lookup path — the explicit row is redundant
with the derived forward-wire index row for this direction. Fail-closed
is therefore not merely safe, it is nearly free.

## Compare-and-remove identity chain

The chain (equal non-zero `RTFlowSessionID` → equal non-zero
node-local `SessionID` → full-`SessionValue`-ex-generation-and-counters)
applied atomically under each removing map's own lock answers both of
Codex r8's attacks: the same-key/same-NAT/different-id replacement
(first two links discriminate) and the cross-lock third-party slot
replacement (per-map atomicity). AGY r9's enumeration of value fields
that can differ between colliding id-0 sessions (zones, policy_id,
inactivity timeout, FIB details, owner_rg_id, fabric_ingress, log flags,
nat64_reverse) confirms the third link's discrimination depth; the
node-local id mint is a strictly monotonic 48-bit per-node counter, so no
two same-node sessions share it.

## Self-found nit (documentation, does NOT block)

### N17 — the conflict-drop counter aggregates the benign id-0 alias drop

`xpf_userspace_interface_snat_sync_identity_conflict_drops_total` fires
both for a genuine conflict (a different session's identity squatting the
tuple) and for a legitimate id-0 alias importing into its own base's
identity (the fail-closed legacy case AGY proved benign). An operator
watching the counter cannot distinguish "attacker/legacy collision" from
"benign legacy alias redundancy". v9.1 adds one sentence to §5.8: the
drop path distinguishes the two where it can (a conflict against a record
whose value carries the SAME RTFlowSessionID is the benign own-base case
— for id-0 imports the benign case is indistinguishable from a genuine
conflict by construction, which is exactly why it fails closed), and the
counter's doc text says id-0 legacy alias drops are included and benign.
No new series; documentation only.

## Verdict

**PLAN-READY-WITH-NITS.** No BLOCKER or MAJOR survives. The zero-id
fail-closed is verified near-free (the derived forward-wire index row
covers the lookup), and the identity chain closes the sweep validation.
N17 (counter-semantics documentation) folds into v9.1 wording. If Codex
r9 converges, this is terminal.
