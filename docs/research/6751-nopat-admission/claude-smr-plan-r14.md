# Claude SMR hostile plan review — #6751 plan v14 (round 14, convergence adjudication)

Reviewer: Claude SMR. Posture: hostile — v14 is my own fourth alias
iteration, this time adopting Codex r13's own direction (negotiated
sender-side alias omission) plus a receiver-side quarantine for the
legacy window. This pass attacks the negotiation channel, the
quarantine's confirm/admit logic, and the delete-suppression lifecycle.
Codex r14 was in flight when this was written.

## Negotiated omission, attacked

The happy path (new+new) is where the design must be simplest, and it
is: the sender skips the alias derivation branch entirely
(daemon_ha_userspace_stream.go:370/379), so zero alias upserts AND zero
alias deletes cross the wire. Nothing at the receiver needs to happen
at all — no signature, no quarantine, no collateral, genuine self-NAT
and identity-NPTv6 rows flow normally. The capability field is additive
and old-peer-ignorable, so an old sender never learns and keeps
deriving (today's behavior for old receivers) — no hard version gate,
no rolling-upgrade break. The one implementation question I leave open
in §11 Q2: where the handshake capability actually rides (pkg/cluster
sync.go:295 lifecycle / connect exchange) — a channel question, not a
design question.

## Legacy quarantine, attacked

The signature gained three refinements across r13 and I re-derived each:

- **NAT64 exclusion (Codex r13 B2)**: the v4 NAT64 rewrite is padded
  into a v6 slot and reformatted as IPv6 (eventstream.go:1350), so a
  legitimate NAT64 client at the reformatted address WOULD match the
  source-only signature. The decoded `Nat64SnatV4` field
  (sync_protocol.go:616) gives a positive exclusion — no reliance on
  address shape at all. Verified the field exists post-decode.
- **Full-tuple equality (Codex r13 M3a)**: same-address pool/interface
  PAT and same-IP static mapped-port sessions are bijective by port
  (static_nat.rs:746 rewrites address AND port), so requiring
  `src_port == rewrite_src_port OR rewrite_src_port == 0` excludes them
  while still matching the alias (whose key carries the full translated
  tuple, port included) and the no-PAT alias (port field 0/preserved).
- **Fabric-redirect gate (Codex r13 M3b, partial)**: the alias
  derivation only fires for `FabricRedirect && !FabricIngress`
  sessions, so the signature gates on the same condition — non-fabric
  identity-NPTv6 rows never quarantine. The remaining fabric
  identity-NPTv6 case (canonical == wire, no alias ever derived,
  daemon_ha_userspace_convert.go:511) flows through quarantine and is
  ADMITTED on timeout: no sibling base ever arrives for it because
  there IS no second row. A sync delay for a corner, not a drop.

The confirm-vs-admit split is where I pressed hardest: is the
sibling-base predicate (forward-wire relation + identical decision +
equal non-zero RT-flow id) reliable for an actual pair? Yes — this is
the r6-r8 predicate evaluated against two concrete decoded rows with
concrete values; the r7/r8 failure modes were about using it to attach
ownership without the id clause and about using it at all on
zero-information. Here it is one clause of a confirm decision whose
alternative (timeout-admit) is also safe, so a false negative degrades
to a sync delay and a false positive degrades to a dropped alias that
the peer re-exports — both bounded.

## Delete suppression lifecycle, attacked

Suppression is keyed to the confirmed-alias set AND the base's open
lifecycle (the exporter sends base+alias deletes in the same close
delta, daemon_ha_userspace_stream.go:393/400). Codex r13 B1's
counterexample (alias A at K dropped; direct D installs at K; D closes
before A; D's delete suppressed → D strands) now resolves as: A is
confirmed-alias → K enters the suppression set; D's delete arriving
while A's base is open IS suppressed → D's row strands until its own
session timeout (bounded; entries expire on their own timeouts). Versus
today, where A's upsert clobbered D's row at publish with certainty
(shared_ops.rs:907). Bounded stranding versus certain clobber —
strictly safer-or-equal in every cell, and only in the #2387 overlap
corner at all. The suppression entry clears when the base's delete
processes (same close delta), so no long-tail suppression window.

## Verdict

**PLAN-READY-WITH-NITS.** No BLOCKER or MAJOR survives. The happy path
has zero receiver machinery and zero collateral; the legacy window is
priced as bounded delays/strandings against today's certain clobbers.
Residual nits: none new beyond the carried implementation-time items
(the §11 Q2 channel question for the capability field). If Codex r14
converges, this is terminal.
