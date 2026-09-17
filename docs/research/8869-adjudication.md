# 8869 — GEMINI-049 merits-adjudication log (round 2+)

Living verdict record for the consequence-ordered merits pass over
`gemini-review-049` findings. Round scope, counts and next-round start point
live in `docs/log/8869-round2.md`; this file carries the per-finding verdicts
with their evidence.

- **Adjudication HEAD**: `origin/master` `43e7038a1` (all file:line citations
  below are at this SHA unless a row names its own base).
- **Report base**: `b0f3aba21`.
- **Prior art**: `docs/log/8869.md` (round 1: 10 consequence-ordered rows +
  `004`/`051`/`052`/`061`; `054`/`029`/`080` in issue comments) and the #8869
  thread (29 comments, calibration batches 1+2, triage steps i–ii). 17 of 56
  body-High adjudicated before this round; 39 not reached.
- **Verdict discipline** (inherited from round 1): mechanism and consequence
  are separate verdicts; fixed-since is not wrong-when-written (base read
  required); not reached is not dismissed. Mechanical-dismiss count stays 0 —
  every row below was read on its merits.
## Evidence source

The exact report body was located at `/tmp/gemini-review-049.md` (521K,
6,841 lines) and the structured copy at `/tmp/research-work.wbojXp0Wtq/f049.json`.
The finding bodies below were read from that source, not reconstructed from
titles or issue comments. Relevant report ranges are recorded per row. The
report is intentionally kept out of the repository; it is a source artifact,
not a shipped research document. The cited code was read at both
`b0f3aba21` and `43e7038a1` where the row claims a base verdict.

Where a row has a static mechanism but its operational consequence needs a
packet or many-core measurement, the consequence is recorded **UNRESOLVED**,
not converted into a dismissal or a new defect claim.

## `GEMINI-049-011` (High): MQFQ virtual-time inversion — REFUTED, wrong when written

Pinned at `origin/master` `43e7038a1`. Read, not executed (structural argument
is exact arithmetic; in-tree cells assert both directions — see below).

Claim (from the exact report body, `/tmp/gemini-review-049.md:775-910`, plus
the batch-1 calibration row): the virtual-time bookkeeping inverts around a
drained bucket — the system frontier ends up below a drained bucket's tail (or
a reactivated bucket re-enters below it), letting it jump ahead of backlogged
flows.

| axis | verdict |
|---|---|
| cited files changed base..HEAD | **UNCHANGED** (`git diff --stat b0f3aba21 HEAD` empty on both files) — cannot be fixed-since at the cited site |
| mechanism — vtime left below a drained bucket's tail | **REFUTED**, twice over, both guards present at base |
| consequence — reactivated/idle flow jumps the queue | **REFUTED** |
| disposition | **WRONG WHEN WRITTEN** — agrees with the batch-1 calibration verdict, now on merits |

### Guard 1 (pop side): `vtime = max(vtime, served_finish)` — exact, not approximate

`pop.rs:251-252` (identical at base, verified via `git show b0f3aba21:userspace-dp/src/afxdp/cos/queue_ops/pop.rs`):

```rust
if push_snapshot {
    ff.queue_vtime = ff.queue_vtime.max(served_finish);
}
```

`served_finish` is the popped packet's head-finish, captured before mutation
(`pop.rs:180`). Trace a bucket holding packets `p1..pn` with cumulative
finishes `f1 < … < fn = tail`: enqueue sets `head = f1`; each pop advances
`head += bytes(next_head)` (`pop.rs:268-270`), so after popping `p(n-1)` the
head is exactly `fn = tail`. Popping the last packet serves `tail`, and
`vtime = max(vtime, tail)`. The frontier is at or above the drained tail
exactly — the batch-1 "within one packet" hedge was conservative.

### Guard 2 (enqueue side): drain reset + frontier re-anchor

Even without guard 1, no stale tail survives: on drain-to-0 the dequeue path
resets both finishes (`accounting.rs:119-129`, present at base):

```rust
ff.flow_bucket_head_finish_bytes[bucket] = 0;
ff.flow_bucket_tail_finish_bytes[bucket] = 0;
```

and the next enqueue re-anchors at the live frontier (`accounting.rs:61-67`):

```rust
let new_tail = ff.flow_bucket_tail_finish_bytes[bucket]
    .max(ff.queue_vtime)
    .saturating_add(item_len);
```

This is the textbook WFQ/STVC start-tag rule (`start = max(prev_finish,
vtime)`). A reactivated bucket enters at `vtime + len`, strictly above the
frontier — it cannot jump backlogged flows whose heads are all `> vtime`.

### In-tree pins

- `mqfq_idle_flow_reanchors_at_frontier_not_zero`
  (`pop_tests/ordering.rs:368`): idle-returning flow anchors at `vtime + bytes`.
- `mqfq_brief_idle_reentry_exercises_both_max_arms`
  (`pop_tests/snapshot_stack.rs:215`): both `max` arms after drain + re-entry.
- `mqfq_scratch_drop_preserves_vtime_for_multi_survivor_restore`
  (`pop_tests/rollback.rs:28`): no vtime regression across drop + restore.
- `mqfq_enqueue_bumps_finish_time_by_byte_count`
  (`pop_tests/ordering.rs:480`): the `max(finish, vtime) + bytes` formula.

### Invariants

- Dismissed on mechanical grounds: **0** (merits read: full pop + accounting +
  push paths, arithmetic trace, base comparison).
- No probe run: the refutation is exact arithmetic over unchanged code plus
  four in-tree cells asserting both directions.

## Dataplane/wire rows (consequence order)

### `GEMINI-049-006` (High): SYN-cookie ACK RST — mechanism confirmed, consequence unresolved

Exact report body: `/tmp/gemini-review-049.md:469-516`. Base validity is
**VALID**: `b0f3aba21` and HEAD both emit `seq=parsed.ack`,
`ack=parsed.seq+1`, and `RST|ACK` from `build_syn_cookie_ack_rst_frame`.
HEAD evidence is `userspace-dp/src/afxdp/frame/tcp.rs:502-515`; the assembler
writes those values at `:767-769`. The cold caller is reachable through
`poll_stages.rs:1099-1102` -> `poll_descriptor/mod.rs:1516-1527` ->
`poll_descriptor/cookie_reply.rs:68`.

| axis | verdict |
|---|---|
| mechanism | **CONFIRMED LIVE** — the ACK-bearing cookie reply still has an ACK field and `ack=seq+1` |
| consequence | **UNRESOLVED** — the report's Linux 20–120 s stall/drop claim needs a real peer capture; repository evidence proves neither acceptance nor rejection of the extra ACK field |
| disposition | **LIVE protocol discrepancy; no issue filed pending packet-level proof** |

The function's own comment (`tcp.rs:487-489`) says RFC 793's ACK-bearing reset
does not include an ACK field, while the `#9419` comment (`:491-500`) argues
from the sequence number only. Existing tests intentionally pin the current
bytes (`tests_nat_rewrite.rs:161-205`, `tcp_tests.rs:1430`); they are not
proof that a Linux peer accepts the packet. This row is not a mechanical
dismissal, and the unresolved consequence remains in the next-round queue.

### `GEMINI-049-013` (High): IPv4 L4 checksum helper — production consequence NOT REACHED

Exact report body: `/tmp/gemini-review-049.md:934-1021`. Base validity is
**VALID** for the helper-level mechanism: `checksum.rs:394-421` has no
zero-checksum early return, while `_words` has the guard at `:479-481`.
At HEAD the only production caller, `frame/mod.rs:1341-1354`, explicitly
checks UDP zero at `:1345-1350`; source-only directional helpers call the
guarded `_words` sibling (`checksum.rs:431-461`), and the port rewrite path
also guards at `frame/mod.rs:1728-1730`.

| axis | verdict |
|---|---|
| mechanism | **CONFIRMED in an internal helper**, unchanged from base |
| consequence | **NOT REACHED** — the only production path explicitly skips zero UDP checksums; direct test-only helper use does not establish wire corruption |
| disposition | **NOT REACHED for the reported wire defect; no issue filed** |

The reported High “silent blackhole” is not a current production verdict.
Moving the existing three-line guard into `adjust_l4_checksum_ipv4` would be
future-misuse hardening, not evidence that current NAT traffic is broken.

### `GEMINI-049-014` (High): SharedCoSLeaseState cache line — layout confirmed, impact unresolved

Exact report body: `/tmp/gemini-review-049.md:1022-1108`. Base validity is
**VALID** and the struct is unchanged. `lease.rs:74-79` aligns the struct start
but places `credits` at offset 0 and `last_refill_ns` at offset 8 on the same
cache line. CAS loops are at `lease.rs:205-212` and `:299-305`. The callers
are per drain-loop/queue (`cos/queue_service/mod.rs:612,756,1039,1266,1510`),
and `token_bucket.rs:206-293` gates top-up when the lease is below its
watermark; this is not a per-packet write.

| axis | verdict |
|---|---|
| mechanism | **CONFIRMED LIVE** — the two shared atomics are co-located |
| consequence | **UNRESOLVED** — no many-core CAS-failure/cache-miss or throughput measurement establishes the report's “severe 100 Gbps” impact |
| disposition | **PERF HARDENING CANDIDATE; no issue filed pending a many-core measurement** |

The repository does state a cache-line isolation rule
(`docs/engineering-style.md:522-525`, `docs/cos-traffic-shaping.md:833-847`)
and has padded-atomic precedents. That establishes a design-contract
violation candidate, not the report's throughput magnitude. A measurement must
separate the shared `credits` CAS contention from any extra false sharing
before a fix issue is actionable.

### `GEMINI-049-015` (High): DNAT steering holder mutex — mechanism confirmed, claimed fast-path consequence refuted

Exact report body: `/tmp/gemini-review-049.md:1110-1200`. Base validity is
**VALID** for the registry shape. HEAD has
`DNAT_STEERING_HOLDERS: Mutex<HashMap<DnatSteeringKey, Vec<SessionKey>>>`
at `afxdp/checksum.rs:280-282`; add/release lock it at `:312-314` and
`:336-338`, with `Vec` growth. But the callers are session install/close:
publish calls add at `checksum.rs:525` beside the BPF map update at `:553`,
delete calls release at `:406` beside map deletion at `:600`; the session and
HA callers are `poll_descriptor/mod.rs:3452,6493`, `session_delta.rs:730`,
and `ha/session_import.rs:699,727,965`.

| axis | verdict |
|---|---|
| mechanism | **CONFIRMED** — process-global mutex and heap-backed holder vectors exist |
| consequence | **REFUTED as stated** — this is not a per-packet dataplane fast path, and no evidence shows the mutex rather than the colocated BPF syscall binds CPS |
| disposition | **NOT a High dataplane defect; no issue filed** |

The source comment at `checksum.rs:267-270` explicitly scopes the lock to one
uncontended mutex per NAT session install/close. A CPS benchmark would be
needed before any scalability issue, and the report's “multi-million to
sub-100k” claim is not code-proven.

### `GEMINI-049-024` (High): NAT64 fragment identification — RFC contract refutes the defect

Exact report body: `/tmp/gemini-review-049.md:1734-1780`. The casts at
`nat64.rs:2483-2492`, `:3282-3290`, and `:3858-3863` are present at both
base and HEAD, so the reported mechanism (32-bit IPv6 Identification narrowed
to 16 bits) is a true code description. It is **not a defect**: RFC 7915
§5.1 requires the IPv6-to-IPv4 Identification to be “copied from the
low-order 16 bits” (RFC source read: `https://www.rfc-editor.org/rfc/rfc7915`,
lines 428-430 and 882-883). The report's proposed non-truncating behavior
would violate the translation standard.

| axis | verdict |
|---|---|
| mechanism as code description | **CONFIRMED** |
| consequence/contract violation | **REFUTED** — low-16 propagation is normative; the post-translation overlap guard is the relevant collision defense |
| disposition | **WRONG CONTRACT; no issue filed** |

The full-width pre-translation `FragAssoc` key (`fragment_assoc/key.rs:35,57`)
does not change the wire rule. No new issue is justified without a separate
failure in collision handling.

### `GEMINI-049-025` (High): NAT port recycle TIME_WAIT claim — mechanism confirmed, standards consequence unresolved

Exact report body: `/tmp/gemini-review-049.md:1780-1834`. Base validity is
**VALID** for the narrow mechanism: `RecycleRing` stores only `VecDeque<u16>`
(`nat/allocator.rs:804-805`), `free_recycle` returns a token immediately
(`:1173-1189`), and `claim` pops it without an elapsed-time gate (`:1042-1168`).
The FIFO order is pinned by `tests_pool.rs:4133-4138`; FIFO is not a timestamp
quarantine.

| axis | verdict |
|---|---|
| mechanism | **CONFIRMED** — no `freed_at`/hold timer is present |
| consequence | **UNRESOLVED** — RFC 5382 §4.3 makes TIME_WAIT retention optional and RFC 6888 permits immediate reuse under tracking/filtering exceptions; this repository read does not prove that the allocator falls outside those exceptions or that a conflicting tuple reaches a peer |
| disposition | **DEFERRED, not dismissed; no issue filed** |

The FIFO comment (`allocator.rs:33-57`) states an operational heuristic, not a
normative hold. A valid issue needs a near-exhaustion churn capture or a
repository contract showing that the required TCP/session tracking exception
does not apply. The prior #3011 FIFO issue is not duplicate proof of a
TIME_WAIT violation.

### `GEMINI-049-026` (High): address-only/PAT shared allocator collision — CONFIRMED LIVE

Exact report body: `/tmp/gemini-review-049.md:1835-1928`. Base validity is
**VALID** and the mechanism is unchanged at HEAD. `allocator_key_for` omits
`no_translation` (`nat/source/mod.rs:398-405`), address-only mode owns no PAT
occupancy bit (`nat/allocator.rs:2516-2525`, `:3722-3729`), and the PAT arm
allocates from the bitmap (`nat/source/match_rules.rs:851-879`). The peer
guard deliberately skips owners in the same allocator
(`nat/source/overlap.rs:156-163`). Therefore two rules sharing one allocator
can admit an address-only flow preserving public port `P` and a PAT flow at
the same address and `P`, leaving indistinguishable reverse tuples.

| axis | verdict |
|---|---|
| mechanism | **CONFIRMED LIVE** |
| consequence | **CONFIRMED structurally** — simultaneous reverse-key collision is fail-open and can misdeliver replies |
| disposition | **REAL; filed as #10190** |

This is distinct from #5269/#5341's address-only token cases and #8115's
cross-allocator peer guard. The existing #6528 fixture proves allocator
sharing and mode-correct teardown, but not simultaneous PAT/address-only
collision. New issue: https://github.com/psaab/xpf/issues/10190.

### `GEMINI-049-030` (High): embedded ICMPv4-to-v6 type/checksum claim — refuted at base

Exact report body: `/tmp/gemini-review-049.md:2049-2239`. The report says the
base translator copies Type 8 verbatim. The exact base source does not: at
`b0f3aba21:userspace-dp/src/nat64.rs:3281-3285`, it already calls
`embedded_icmpv4_type_to_icmpv6`, mapping echo request/reply to 128/129. HEAD
retains the same mapping at `nat64.rs:3445-3472`. The quoted inner checksum is
left unchanged by explicit design (`nat64.rs:3430-3432`) because it is
informational; the outer ICMPv6 checksum is recomputed by the caller.

| axis | verdict |
|---|---|
| mechanism | **REFUTED at report base** — the claimed missing type remap was already present |
| consequence | **REFUTED** — no invalid Type 8 wire quote follows from this path |
| disposition | **WRONG WHEN WRITTEN; no issue filed** |

### `GEMINI-049-096` (High): NAT64 IPv6 payload length narrowing — CONFIRMED, constrained reachability

Exact report body: `/tmp/gemini-review-049.md:6543-6638`. Base validity is
**VALID** and the casts remain at HEAD. The outer translator computes
`ipv4_total_len = 20 + l4_len` then narrows it (`nat64.rs:2517-2518`);
the non-first path does the same at `:3858-3859`; and the embedded path has
`:3261-3262`. The embedded quote is capped by `MAX_EMBEDDED_LEN = 1300`
(`:1886`, `:3217`), so its wrap is unreachable. IPv6 payload lengths
65,516–65,535 are valid ordinary 16-bit payload lengths; outer/non-first code
can receive one when an unusually large ingress MTU or GRO buffer delivers the
whole packet.

| axis | verdict |
|---|---|
| mechanism | **CONFIRMED LIVE** — `20 + L` can exceed `u16::MAX` before the cast |
| consequence | **CONFIRMED structurally, constrained operationally** — the header wraps below the legal IPv4 minimum while the returned `usize` remains unwrapped; ordinary 1500/9000 MTUs do not reach it, but IPv6 jumbogram semantics are not required |
| disposition | **REAL; filed as #10191** |

The fix must fail closed before every outer/non-first cast; saturating the
field would emit another invalid datagram. New issue:
https://github.com/psaab/xpf/issues/10191.

## Control-plane rows

### `GEMINI-049-033` (High): family compound-key brace-elision — fixed since report base

Exact report body: `/tmp/gemini-review-049.md:2241-2310`. Base validity is
**VALID**: the old walker advanced over the two-key `family inet` compound
identity but recursed using the one-key schema level, so `filter`/`address`
children were not visited. HEAD fixes the traversal in
`pkg/config/compact_normalize_8662.go:86-110,139-140,239-240` and admits the
full scope chain in `pkg/config/compact_normalize_scope.go:605-612`.
Relevant fixes are `56271ec0a` (#8763 traversal) and `7ee3d4318` (#8755
interface-unit chain), with existing braced/packed reachability cells.

| axis | verdict |
|---|---|
| mechanism at base | **CONFIRMED** |
| current consequence | **NOT PRESENT** — the fixed walker and scope chain reach both spellings |
| disposition | **FIXED-SINCE; no issue filed** |

### `GEMINI-049-034` (High): DNAT port parser range claim — wrong when written

Exact report body: `/tmp/gemini-review-049.md:2311-2380`. The parser-level
mechanism is real (`compiler_nat_destination.go:300-326,331-423` still keeps
numeric values in `DestinationPorts`), but the report's base claim that the
strict gate checked only `InvalidDestinationPorts` is false. At
`b0f3aba21:pkg/config/compiler_validate_strict_nat.go:413-424`, the gate already
iterated every `DestinationPorts` value and rejected `p < 1 || p > 65535`;
the same value check remains at HEAD (`:413-424`).

| axis | verdict |
|---|---|
| parser mechanism | **CONFIRMED** — form parsing intentionally leaves value range to consumers |
| report consequence at base | **REFUTED** — the base commit already rejected 70000 before any dataplane cast |
| disposition | **WRONG WHEN WRITTEN; no issue filed** |

The downstream builder checks are defense in depth, not the first fix for this
finding. The report's own refutation attempt is contradicted by the exact
base source.

### `GEMINI-049-035` (High): GRE key/TTL narrowing — fixed since report base

Exact report body: `/tmp/gemini-review-049.md:2383-2510`. Base validity is
**VALID** for the raw signed-to-unsigned narrowing. HEAD's shared
`parseInterfaceNumeric9899` gate (`pkg/config/compiler_interfaces.go:27-64`)
accepts digits only and enforces bounds; both interface and unit sites use it
(`:270-298,424-443`). The old raw-Atoi sites are gone; `fcfdafcb5` carries the
bound-numeric implementation.

| axis | verdict |
|---|---|
| mechanism at base | **CONFIRMED** |
| current consequence | **NOT PRESENT** — strict reject and lenient quarantine prevent wrapped key/TTL values |
| disposition | **FIXED-SINCE; no issue filed** |

### `GEMINI-049-047` (High): confirm-resolution tombstone — live residual, existing duplicate

Exact report body: `/tmp/gemini-review-049.md:3122-3238`. The base source
already contains the tombstone sequence: `resolveConfirmRemovalLocked` calls
`markConfirmResolvedLocked`, and `markConfirmResolvedLocked` sets
`tombstone.Resolved = true` before the delete
(`b0f3aba21:pkg/configstore/store_commit.go:673-750`). The report's live
mechanism is the **double failure**: `WriteConfirm(&tombstone)` fails
best-effort, then `DeleteConfirm` also fails; the retry loop re-drives the
delete but not the failed tombstone write, so a restart can still see an
unmarked resolved record.

| axis | verdict |
|---|---|
| mechanism at base | **CONFIRMED** — the best-effort tombstone write and delete-only retry leave the double-failure residual |
| current consequence | **LIVE but narrowly conditioned** — the same code remains at `store_commit.go:792-815,845-864`; ordinary delete failure is tombstoned, while a simultaneous write+delete failure retains the old resurrection window |
| disposition | **KNOWN RESIDUAL; duplicate of #5915/#8565/#6739, no new High issue** |

This is not fixed-since: `3e97c3002` is the tombstone change already present at
the report base, not a post-base remedy for its failed-tombstone residual. The
existing chain records the conjunction as low-priority/accepted; filing it
### `GEMINI-049-049` (Medium): SNMP hash omits EngineID — mechanism present, consequence refuted

Exact report body: `/tmp/gemini-review-049.md:3239-3310`; the body severity
is **Medium** (also `f049.json` entry 48), so this row is not part of the
56-High denominator. Base and HEAD hash the same v3-user fields but do not hash
the construction-time EngineID
(`pkg/daemon/daemon_snmp_reconcile.go:166-178,439-441`). The proposed stale
key state is not reachable: `pkg/snmp/agent.go:377-393,413-418,517-527`
keeps EngineID immutable for an agent lifetime, and `pkg/snmp/v3.go:57-73,105-133`
re-localizes keys against that same ID. A hostname change leaves the running
agent's advertised ID and keys consistent; a new ID occurs at agent
construction and triggers normal USM discovery.

| axis | verdict |
|---|---|
| mechanism | **CONFIRMED as a hash omission** |
| consequence | **REFUTED** — no stale-key transition exists under the immutable-ID lifecycle |
| disposition | **WRONG CONSEQUENCE; no issue filed** |

Adding EngineID to the hash would trigger a no-op update and is not a remedy.

## Round totals after these fifteen rows

- High rows adjudicated before this round: **17 of 56**.
- This round: **14 High + 1 Medium** (`011,006,013,014,015,024,025,026,030,033,034,035,096,047,049`).
- Cumulative: **31 of 56 High**, **25 High not reached**; one Medium also
  adjudicated; **0 mechanical dismissals**.
- New issues filed: **#10190** and **#10191** only. Rows with unresolved
  consequences remain queued; a static mechanism is never silently upgraded
  to a material defect.

## Next start point

Continue with the first unreached High after `GEMINI-049-049`, preserving the
same dataplane-before-control-plane ordering. The next control-plane rows
already identified for review are `055` and `057`; do not treat the 25-row
High remainder as clean.


### Invariants

- Dismissed on mechanical grounds: **0** (all fifteen rows read on merits).
- Every fixed-since or wrong-when-written label has a direct base read; no label
  is inferred from a changed file alone.
- No production code changed in this round; no test suite is applicable to the
  docs-only deliverable.
