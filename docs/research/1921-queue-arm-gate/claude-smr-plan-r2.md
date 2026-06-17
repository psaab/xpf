# Claude SMR — hostile plan review r2 (#1921 queue/arm-gate re-research)

Reviewing plan @ r2 (pivoted to PLAN-KILL + scoped durability follow-up).
Stance: hostile — does the KILL hold up, or is it premature?

## The pivot is correct and evidence-backed

r1 routed Case-1/Case-2 to a live Phase-0. Codex r1 #2 found the artifact
that decides it without a live run: `docs/research/1928-virtio-copy-xsk-rx/
plan.md:83` — validation venue `t1921-fw`, explicitly **4-queue virtio**,
v4+v6 0% loss, tx_completions nonzero across LAN+WAN bindings, SNAT proven,
`rx≈tx≈fwd=5000 pps` sustained flood. I verified this file directly. A
black-holing multi-queue path is incompatible with `fwd=5000, 0 drop`
across all bindings. ⇒ **Case 1: the bug is fixed.** PLAN-KILL of the
forwarding-fix scope is the honest call.

## Attacks on the KILL

### A1 — Could the 5000pps proof have hidden a black-hole on one queue?
If RSS hashed the iperf/flood flows onto only the bound queues, a stranded
queue could exist undetected. Counter: the validation says
`tx_completions_total nonzero across LAN+WAN bindings` (plural, both
interfaces' bindings) AND `rx≈tx≈fwd` — if a queue were stranded, fwd would
lag rx by the stranded fraction under a 5000pps flood. It doesn't. Also the
#1927 ledger independently recorded "redirects now happen on all 4 queues"
post-dedup. The KILL holds; I cannot manufacture a counter-example where
all-binding is false yet these signals are true.

### A2 — Is the latent durability gap real enough to demand the follow-up?
Yes the code path exists (verified r1), but it is unreachable on virtio
(no unbound queue) and on mlx5/i40e (bind all advertised). There is NO
current venue where it fires. So the follow-up is genuinely optional
defence-in-depth, correctly de-prioritised and explicitly NOT blocking
#1921 closure. Good — r2 does not over-claim.

### A3 — Does closing #1921 lose the durability work?
No: r2 files it as a separate labelled follow-up with the corrected scope
(fail-closed, max(BOUND)+1, no global rebind, bitmap-out). The design is
captured so it isn't re-derived. Acceptable.

### A4 — Is `max(BOUND)+1` actually safe, or did r2 inherit a bug?
r2 correctly documents the residual: scalar queue_count can't represent an
*interior* hole; `max(BOUND)+1` re-strands an interior unbound queue. r2
does NOT claim to fix interior holes — it documents the prefix assumption
and defers the bitmap. This is the honest limit, not a hidden bug. Good.

### A5 — Doc correction
The `image-validation.md` venue warning (`:79`) is stale (predates fixes by
~4h) and actively misleading (says virtio doesn't forward when #1929 proves
it does). r2 flags it for correction independent of the follow-up. Correct
and cheap; should happen regardless.

## Residual nit
r2 §7 should make the closing comment explicitly cite that the original
Defect A (sysfs enumeration) and Defect B (arm gate) were each refuted as
*causes*, so a future reader doesn't re-file them. r2 §1 already does this;
just ensure the issue-closing comment carries it. (Non-blocking.)

## Verdict

**PLAN-READY (as a PLAN-KILL of the forwarding bug + optional scoped
durability follow-up).** The KILL is backed by the #1929 4-queue virtio
validation; the durability residual is correctly de-scoped and corrected
per all reviewer findings (fail-closed default, max(BOUND)+1,
Bound&&XSKRegistered key, no global-rebind watchdog, interior-hole prefix
assumption documented). No fatal counter-example to the KILL exists.
