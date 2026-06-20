# Claude-SMR hostile plan review — #1387 Inc-2 DDNS backend (round 1)

Reviewer: Claude (self-SMR, hostile). Target: `plan.md` (DRAFT) in this dir.
Posture: assume the plan is wrong until it survives. Severity tags:
**BLOCKER** (must fix before engineering), **MAJOR** (must address or explicitly
accept with rationale), **MINOR** (cleanup), **QUESTION** (under-specified).

Verdict up front: **PLAN-READY WITH CONDITIONS.** The feasible-slice framing is
sound and the in-process-responder claim is correct and load-bearing. But three
issues (M1 the memfile↔RG mapping, M2 the upsert atomicity claim, M3 the
disabled-loop construction order) are under-nailed enough that engineering them
as written would produce review churn or a correctness gap. None are kill-level.

---

## BLOCKER — none.

I tried to find a kill. The closest candidate was "the live backend is actually
lab-bound, so the whole feasible-slice claim is false." It is not: `miekg/dns`
exposes `dns.Server` with `Listener`/`PacketConn` bind on an ephemeral loopback
port and a `TsigSecret` map, and the repo already runs in-process servers in
tests. The claim survives. No blocker.

---

## MAJOR

### M1 — The HA gate's correctness rests on an UNVERIFIED Kea-memfile↔RG mapping.
The plan's §4.3 "node-level gate is safe because a BACKUP node's Kea is stopped,
so its memfile is stale and it won't act" — and §11 Q2 admits this is unverified.
This is not a side question; it is THE correctness pillar of R2 (dueling writers).
If two RGs' DHCP subnets can land in the SAME `/var/lib/kea/kea-leases4.csv`
(Kea writes ONE memfile per family, not per subnet/RG — this is almost certainly
true), then a node that is MASTER for RG1 and BACKUP for RG2 reads a single
memfile containing BOTH RGs' leases, and node-level "reconcile all readable
leases" **publishes RG2's leases from the RG1-master node** — exactly the dueling
write the gate is supposed to prevent, because the RG2-master node ALSO publishes
them. The "BACKUP Kea is stopped" argument fails the moment a node is mixed
MASTER/BACKUP across RGs (which is the normal active/active HA layout).
**This makes per-RG lease attribution NOT a refinement but a likely requirement.**
Action: before engineering, READ the Kea render (`pkg/dhcpserver/dhcpserver.go`)
to confirm one-memfile-per-family, and confirm whether the loss cluster / typical
config runs active/active multi-RG. If yes, the §6-fork-2 "ship node-level, file
per-RG as refinement" disposition is WRONG and per-RG attribution
(subnet_id → group → RG → is-this-node-master) must be in the Inc-2 PR. The plan
currently hedges this into an open question; promote it to a pre-engineering
decision with a definitive code read. *Severity MAJOR because it can ship a
dueling-writer bug that unit tests (single-node) won't catch and only the lab
exposes.*

### M2 — "delete-RRset-then-add in one UPDATE is atomic" overstates what protects R1.
§4.1 leans on "DNS UPDATE delete-RRset-then-add within one message is atomic at
the server." That is true for the *upsert* but it is the wrong sentence to anchor
the cardinal-sin (R1) protection on, and it quietly contradicts the delete path.
For `replace-owned` UPSERT the plan says "delete the existing RRset then add" —
but deleting the whole RRset on upsert would ALSO delete a co-resident,
xpf-did-not-create A record on the same name (the very collateral R1 forbids),
and §9.1 explicitly tests that a co-resident record SURVIVES a *delete*. The
upsert and delete must use the SAME exact-RR discipline: upsert = delete-exact-
old-owned-rdata (from the store, if the address changed) + add-new-rdata, NOT
delete-whole-RRset. The plan's own DeleteLease prose ("delete the exact RR, not
the whole RRset") is right; the UpsertLease prose ("delete the existing RRset")
is wrong and inconsistent. Action: rewrite §4.1 upsert to never issue a
delete-RRset; an A/AAAA upsert is "add the new RR" (and, when the address moved,
the move is already handled by Inc-1's reconciler deleting the OLD owned tuple via
DeleteLease before the new add — so UpsertLease may not need any delete at all,
just an idempotent add). Re-derive whether UpsertLease needs a delete sub-op at
all given the reconciler already calls DeleteLease for moves. *MAJOR because as
written it could delete a non-owned co-resident record on every upsert.*

### M3 — Disabled-path: "build the manager only when enabled" vs "loop always ticks" is contradictory and risks a withdraw-on-disable miss.
§4.2 says the `DDNSManager` is built with a live updater "only when the active
config enables DDNS … otherwise it is built with nopUpdater (or not started)"
AND that the disabled loop "still ticks but Reconcile takes the withdraw fast
path." These conflict: if the manager is "not started" when disabled, then a
config that goes enabled→disabled has no running loop to RUN `withdrawAllLocked`,
so the records published while enabled are NEVER withdrawn (leak + the operator
thinks `delete dynamic-dns` cleaned the zone). The manager+loop must ALWAYS exist
once the daemon starts (or be (re)started on any commit that previously had
records owned), so the disable transition can withdraw. Action: nail the
lifecycle — construct the `DDNSManager` + loop unconditionally at daemon start
(cheap; idle when disabled), updater resolved per-Reconcile (§6 fork 1, which the
plan already prefers — good, this fork choice MUST be the one taken, because
resolve-per-Reconcile is what lets a single always-on manager serve both the
nopUpdater-disabled and rfc2136-enabled states without a swap). State this as a
hard constraint, not a "(or not started)" alternative. *MAJOR because it can
silently fail the issue's explicit "config removal deletes owned records"
acceptance criterion.*

---

## MINOR

### m4 — Prometheus result-label cardinality.
`xpf_dhcp_ddns_upserts_total{result}` etc. — bound the label set explicitly
(`ok`/`fail` only; `skipped` is its own metric). An unbounded `result` (e.g. a
raw rcode string) would be a cardinality leak. The plan says "map onto DDNSStats"
which is fine, but state the label value set is closed.

### m5 — `nodeID` watermark seed source.
§4.2 says the seed "comes from the cluster node-id (already known to the daemon)"
— but in STANDALONE mode there is no node-id file. `ownerWatermark` folds nodeID
only as a TXT hint, NOT into the delete-matching key (Inc-1 ddns.go:176), so a
missing/empty nodeID is harmless to correctness — but say so, so a reviewer
doesn't flag "standalone has no node-id."

### m6 — `make test-failover` 14/0 is a data-plane metric; DDNS doesn't ride that path.
§9.3 frames the failover gate well, but the "14/0 iperf unaffected" check proves
*non-regression of the dataplane*, NOT that DDNS did the right thing across
failover. The DDNS-specific failover assertion (no dueling writes, records kept
on new MASTER) needs its own observation during the failover run (e.g. snapshot
the throwaway DNS server's UPDATE log across the transition). Make the failover
test plan call out the DDNS-specific observation, not just the iperf number.

### m7 — TTL semantics in the delete path.
Inc-1's `deleteOwnedLocked` re-derives the record including the stored TTL and
passes it to `DeleteLease`. RFC 2136 deletes ignore TTL (a delete RR's TTL must
be 0). The backend must zero the TTL on delete RRs regardless of the stored
value. Trivial, but a real wire-correctness item — add a unit assertion.

---

## QUESTION (must be answered, several already in plan §11 — these are additional)

### Q-A — go.mod: is adding `github.com/miekg/dns` acceptable, or is there a project
constraint on new third-party deps? The plan asserts it's "the de-facto standard"
(true) but the repo has a notably lean go.mod (no DNS lib, no fsnotify). Confirm
there's no policy against pulling a ~30-file DNS library, and whether its
transitive deps (`golang.org/x/*`, already present) stay clean. If a new dep is
frowned upon, the fallback is a hand-rolled RFC 2136 message builder (more code,
more risk) — which would change the §2 effort estimate materially.

### Q-B — Loop ↔ Kea-apply ordering on a fresh lease. The reconcile loop reads the
memfile Kea writes. On a brand-new commit that ENABLES DHCP+DDNS, is there a
window where the loop reconciles BEFORE Kea has created the memfile (so it sees
"no leases" and the store is empty — benign) vs a window where it could delete
something? Benign on first-enable (empty store), but worth one sentence: the
loop's first reconcile after enable can only ADD; it can only delete what's in
its own store, which is empty until it has added. So no early-delete hazard.
Confirm and state it.

### Q-C — Does enabling commit-time validation on `update-server`/`tsig-algorithm`
(§4.5/§7) break any EXISTING committed config in the wild? The plan flags this as
"acceptable, the value was inert." But Inc-1 SHIPPED these as free-form, so a
config committed against Inc-1 with a malformed update-server is now in someone's
active.json; on the next commit/boot it would warn (or error, if validation is
hard). The plan says "warn/error" — pick: it MUST be warn (not error) for inert
pre-existing values, or it can brick a boot. Hard validation only on NEW edits is
hard to scope; safest is warn-only at commit for these leaves. Decide.

---

## What the plan got right (so review doesn't relitigate it)

- The feasible-slice vs lab split is correct and is the plan's strongest call. The
  in-process `miekg/dns` responder genuinely removes the lab dependency for the
  backend wire format and the reconcile semantics. This is the right architecture.
- Reusing `snapshotRethMasterState` (the SAME ownership source as the Kea manager)
  instead of inventing a new gate is exactly right — one source of truth.
- BACKUP = stop-writing-not-withdraw (R3) is the subtle HA point and the plan
  nails it.
- Not touching `reconcileOnceLocked` / `deleteOwnedLocked` / the state store —
  preserving Inc-1's never-delete boundary rather than re-deriving it — is the
  correct discipline.
- Rejecting fsnotify and per-cycle connection pooling (YAGNI for a 30s loop) is
  the right altitude.
- The descriptor-coverage canary being called out as a build-time gate (R8/§9.1)
  shows the plan understands the checked-collector trap.

## Required actions before PLAN-READY → ENGINEER

1. **M1**: read the Kea render to settle one-memfile-per-family + active/active
   multi-RG reality; if confirmed, move per-RG lease attribution INTO Inc-2 scope
   (resolve §11 Q2 as a decision, not a question).
2. **M2**: rewrite §4.1 UpsertLease to use exact-RR discipline (no delete-RRset);
   confirm whether UpsertLease needs any delete sub-op given the reconciler
   already deletes the old owned tuple on a move.
3. **M3**: make "always-construct the manager+loop at daemon start, updater
   resolved per-Reconcile" a hard constraint (not an alternative), so
   enabled→disabled reliably withdraws.
4. Answer Q-A (new-dep policy), Q-C (warn-not-error on legacy free-form leaves).
5. Fold m4/m6/m7 into §4/§9.

With M1-M3 resolved and Q-A/Q-C answered, this is ready to engineer as a single
PR with the lab as a confirmation pass.
