# Claude SMR hostile plan review — #6751 plan v15.9 (round 22 fold-check, convergence adjudication)

Reviewer: Claude SMR. Posture: hostile — v15.9 folds Codex r22's
effect-authorization blocker, which is the deepest systems question of
the alias saga: you cannot un-send a frame, so what does "stale" even
mean for effects that are already on the wire? This pass verifies the
reversibility classification against each effect type's actual
semantics and attacks the partial-bulk disposition. Codex r23 has not
been dispatched yet.

## The classification, verified per effect type

- **Session frames / bulk writes**: the pre-write generation check
  stops further frames after an abort (effective). Already-written
  frames are accepted as individually-valid provisional installs — and
  this is the honest part I probed hardest: is "provisional"
  meaningful when the peer installs frames immediately
  (sync_conn_read.go:109)? Yes, because of what a bulk snapshot IS:
  individual frame installs are each valid sessions from the sender's
  authoritative state at send time, while the AUTHORITATIVE property
  (deleting what's absent) lives only in the BulkEnd reconcile
  (sync_conn_read.go:205). A partial bulk never reaches BulkEnd, so it
  is never ACKed, never reconciled, and never releases the sync hold —
  its installs stand as individually-valid state until the NEXT
  complete bulk's authoritative reconcile converges them (deleting
  whatever the new authoritative snapshot lacks). That is exactly the
  "retained until a fresh authoritative reconcile" answer Codex
  demanded, and it is the same disposition any interrupted bulk has
  today (the receive deadline, required new behavior, bounds it).
- **Callbacks**: the binding + revalidate-before-trigger rule cancels
  stale intents before externally visible work; work already triggered
  is convergent because config reconcile and DHCP/IPsec re-advertisement
  read CURRENT state at execution (daemon_ha_sync.go:934's actual
  work), never a verdict-time snapshot. A completed-but-stale callback
  therefore installs current state, which cannot be stale. The claim
  hinges on the callback reading current state at execution — the plan
  names this explicitly as a requirement, and §9 pins the
  generation-race cancellation test.
- **Journal replay**: no abort-generation coupling is needed, because
  the per-(sender,key) monotonic install generation (#2170) already
  orders session state — a replay traveling post-abort either carries
  still-current per-key state (valid install) or an older per-key
  generation for a key with newer state (rejected by the receiver's
  existing strict-older rule). This is the cleanest of the four: the
  ordering mechanism already exists and is independent of the abort
  generation. The plan's rationale is correct and minimal.
- **Clock writes**: idempotent and self-correcting — nothing to prove.

## Attacks attempted

- **Provisional installs serving traffic**: a session installed from a
  partial bulk forwards packets before the next authoritative bulk
  converges — but that session existed on the sender when sent, so
  forwarding it is correct (it is not a phantom); the reconcile only
  ever deletes (never creates), so convergence can only REMOVE stale
  state, not hide a valid one. The dangerous direction (a stale install
  outliving its validity) is bounded by the receive deadline plus the
  next complete bulk, and the session's own timeout is the backstop.
- **Two partial bulks back-to-back**: each is deadline-bounded
  independently; the epoch rules (fail-closed drop of pinned
  quarantines at each death shape) apply per epoch; no accumulation.
- **The two-loop reality**: clause (4)'s guard operates at each effect
  site (there is no global loop — sync_conn_gen.go:64/381), and the
  reversibility classification makes each effect type safe at its own
  site rather than pretending a single commit point exists. The plan
  no longer claims a global serialization it cannot have.
- **§11**: the false-positive claim now reads self-NAT AND non-fabric
  identity-NPTv6, matching the normative no-gate design.

## Verdict

**PLAN-READY-WITH-NITS.** No BLOCKER or MAJOR survives v15.9. The
abort/effect contract is now honest about irreversibility: stop what
you can (pre-write generation checks), classify what you can't
(provisional installs, convergent callbacks, per-key-ordered journal,
idempotent clock), and bound everything by the receive deadline plus
the next authoritative reconcile. If Codex r23 converges, this is
terminal.
