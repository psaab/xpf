# Claude-SMR hostile plan review — #1387 Inc-2 DDNS backend (round 2)

Reviewer: Claude (self-SMR, hostile). Target: `plan.md` (r1 → being revised to r2)
in this dir. Posture: assume the plan is wrong until it survives. Severity tags:
**BLOCKER**, **MAJOR**, **MINOR**, **QUESTION**.

This is the round that returned **PLAN-NEEDS-MAJOR against r1** and forced the r2
revision. The r1 SMR (`claude-smr-plan-r1.md`) returned PLAN-READY-WITH-CONDITIONS
and its M1 fold went the WRONG way — it added a per-RG `subnet_id` single-writer
mechanism. r2's job is to tear that mechanism out.

Verdict up front (against r1): **PLAN-NEEDS-MAJOR** — one MAJOR, blocking, in the
HA single-writer design. After the r2 corrections below are applied:
**PLAN-READY (r2).**

---

## BLOCKER — none.

---

## MAJOR

### M-r2-1 — r1's per-RG `subnet_id` HA single-writer mechanism is UNSOUND and UNNECESSARY.

r1 (§4.3/§6/§11 Q2) shipped per-RG-lease attribution as the dueling-writer
defense: `subnet_id` (from the memfile) → group → interface → RG → "am I MASTER
for THIS LEASE's RG". Both halves of that are wrong.

**(a) It is UNNECESSARY — the dueling-write scenario r1 feared does not occur.**
r1's whole motivation was "one shared memfile holds ALL RGs' leases, so a mixed
MASTER/BACKUP node would publish a peer's leases." That premise is FALSE. The Kea
config each node serves is rendered MASTER-FILTERED, so a node's memfile already
contains ONLY its own currently-MASTER RGs' leases. Verified against source:

- `pkg/daemon/daemon_apply.go:1095-1101` —
  `d.dhcpServer.ApplyClusterCommit(d.filterDHCPConfigForMasterRGs(cfg))`.
- `pkg/daemon/daemon_ha.go:919-927` (VRRP MASTER transition) —
  `d.dhcpServer.ApplyAsync(d.filterDHCPConfigForMasterRGs(cfg), …)`.
- `pkg/daemon/daemon_ha.go:988-1041` — `filterDHCPConfigForMasterRGs` keeps a
  group's interfaces only when `masterIfaces[iface]` (built from
  `snapshotRethMasterState()` ∩ `rethInterfacesForRG`); zero-kept groups dropped;
  returns `nil` when nothing is MASTER.
- `pkg/dhcpserver/dhcpserver.go:184/217/229` — `ApplyClusterCommit` →
  `apply` → `generateKea4/6Config(cfg)` renders ONLY the handed-in groups into the
  per-family memfile.

So a BACKUP RG's subnets are NEVER rendered into this node's Kea, and its leases
are NEVER in this node's memfile. The render-time filter ALREADY did the per-RG
attribution. A node-level gate ("MASTER for ≥1 RG → reconcile my memfile") cannot
see a peer-owned lease; the two nodes' input sets are disjoint by RG ownership.
No dueling write is possible.

**(b) It is UNSOUND even if it were needed — `subnet_id` is not a stable key.**
The memfile `subnet_id` is assigned by Kea-render map-iteration order:
`subnetID := 1; for _, group := range cfg.DHCPLocalServer.Groups { ID: subnetID;
…; subnetID++ }` (`pkg/dhcpserver/dhcpserver.go:511-518` v4, `588-595` v6), and
`Groups` is a Go `map[string]*DHCPServerGroup`
(`pkg/config/types_system.go:902-903`) → nondeterministic iteration order. Worse,
each node renders a DIFFERENT (master-filtered) group set, and the same node
re-renders with a different map order across reconciles. So subnet_id→group→RG is
per-node and per-render UNSTABLE. The lease parser already documents subnet_id as
non-compared, absence-degrades-safely metadata (`pkg/dhcpserver/ddns_leases.go:63`,
`recordsEqual` ignores it). r1's attribution map would have keyed the single-writer
gate on an unstable value — a latent dueling-writer/leak bug exactly where r1
thought it was adding safety.

**Action (taken in r2):** replace the per-RG gate with a NODE-LEVEL gate
("reconcile my memfile IFF MASTER for ≥1 RG", reusing `snapshotRethMasterState`),
and DELETE the subnet_id attribution map. If a future increment ever needs
per-lease attribution against an UN-filtered memfile (it does not in this
codebase), the STABLE key is `Address → pool.Subnet longest-prefix → group →
rethInterfacesForRG → RG` (`daemon_ha.go:732, 1235`), NEVER subnet_id — stated as
fallback only. *This correction SHRINKS the PR.* §4.3/§6/§10/§11 Q2 rewritten.

### M-r2-2 — Async MASTER-takeover ordering was unstated (now folded; was a latent reviewer trap).

On MASTER takeover the Kea reconcile is enqueued ASYNC
(`d.dhcpServer.ApplyAsync(…)`, `daemon_ha.go:925`; the comment there notes Kea
shells out to systemctl with a 15s bound and must not run inline on the VRRP
loop). The DDNS nudge fired at the same wire-point may therefore run BEFORE Kea
has repopulated this node's memfile. r1 did not say this, so a reviewer would
reasonably flag "does the nudge race the Kea apply and delete records it can't
see?" It is BENIGN — the DDNS reconcile is store-driven and add-only-from-current-
leases; a too-early reconcile sees fewer/no leases and can only ADD on the next
cycle, never delete on the strength of a not-yet-written lease (a delete requires
the record in this node's own ownership store). *Action (taken in r2):* state it
explicitly, mirroring the enable-case Q-B note; add a unit test that an early
nudge against a not-yet-populated memfile issues ZERO deletes (§4.3, §9.1).

---

## MINOR

### m-r2-1 — Prometheus `reason` enum carried a now-dead value.
r1's `reason` enum included `not-owner-rg`, which only made sense under per-lease
gating. With a node-level gate a BACKUP-for-all node simply does not reconcile —
there is no per-lease ownership skip to count. *Action (r2):* drop `not-owner-rg`;
add `ptr-notauth` for the §11 Q6 reverse-zone skip. Enum is
`{no-name, no-backend, conflict, ptr-notauth}`. Cardinality still closed (m4).

### m-r2-2 — The "subnet_id" mention in the test plan and risk table.
Ensure no residual test asserts on subnet_id and that R2's mitigation cites the
master-filtered render (not a per-lease gate) as the primary defense. *Action
(r2):* §9 test bullet asserts the gate reads `snapshotRethMasterState` ONLY;
R2 row rewritten to cite the disjoint-by-RG master-filtered memfile.

---

## QUESTION — RESOLVED in r2 (these were open in r1 §11)

### Q1 (zone surface) — RESOLVED, not open.
The RFC 2136 UPDATE MUST carry a zone name, so this is a decision, not a question.
**Decision: Inc-2 ships `Domain`-derived forward zone + canonical reverse
(in-addr.arpa/ip6.arpa); explicit `forward-zone`/`reverse-zone` config leaves are
an ADDITIVE follow-up.** The zone-resolution helper (§4.1) takes an optional
explicit zone list and falls back to `Domain`/canonical-reverse, so the follow-up
wires new leaves into an existing parameter with no helper rewrite and no Inc-2
config-schema change (`DHCPDynamicDNSConfig` has only `Domain` today —
`pkg/config/types_system.go:838-877`). §11 Q1, §4.1, §4.5, §5, §7 updated.

### Q6 (reverse-zone NOTAUTH) — RESOLVED, implement now.
A NOTAUTH/REFUSED on the PTR UPDATE is a COUNTED SKIP
(`skipped_total{reason="ptr-notauth"}`), NOT a blocking error: the forward
A/AAAA add still succeeds, the lease's reconcile is not marked failed, no
retry-storm against a reverse zone we cannot write. An explicit `publish-ptr`
toggle is deferred to the same additive follow-up as the zone leaves. §11 Q6,
§4.1, §4.4 updated.

---

## What r1's folds got right (carried into r2 unchanged)

- **M2 (exact-RR upsert, no delete-RRset)** — §4.1's upsert is an idempotent
  exact-RR ADD; the address-move delete is the reconciler's job via the exact-RR
  `DeleteLease`. Correct; unchanged. The R1 cardinal-sin boundary
  (`deleteOwnedLocked` sole authority) is preserved.
- **M3 (always-construct the manager+loop at daemon start, updater resolved
  per-Reconcile)** — the hard constraint that lets one always-on manager serve
  both nopUpdater-disabled and rfc2136-enabled and reliably withdraw on
  enabled→disabled. Correct; unchanged.
- **The feasible-slice vs lab split** — the in-process `miekg/dns` responder
  removes the lab dependency for the wire format and reconcile semantics; only the
  live Kea→DNS e2e and `make test-failover`-with-DDNS are lab-gated. Confirmed
  again; the reviewer agrees this split is the plan's strongest call.
- **Reusing `snapshotRethMasterState`** as the single ownership source (not a new
  gate) — even more clearly right now that the gate is node-level.

## Required actions before PLAN-READY → ENGINEER (r2)

1. **M-r2-1**: node-level gate; delete subnet_id attribution; fallback key
   documented as Address→Subnet→group→RG, not subnet_id. *(done in r2)*
2. **M-r2-2**: state the async-takeover ordering; add the zero-deletes-on-early-
   nudge test. *(done in r2)*
3. Fold m-r2-1 (reason enum) and m-r2-2 (no subnet_id in tests / R2 wording).
   *(done in r2)*
4. Q1 (zone surface) and Q6 (PTR NOTAUTH) decided, not open. *(done in r2)*

With M-r2-1 and M-r2-2 applied and Q1/Q6 decided, the plan is **PLAN-READY (r2)**.
The HA gate is now SIMPLER than r1 (a node-level boolean, no per-lease walk, no
unstable subnet_id key) and provably single-writer because the Kea render is
master-filtered. Remaining engineer items (Q-A go.mod dep, Q-C WARN-only legacy
leaf validation) are non-blocking.
