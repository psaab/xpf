# #2562 — NAT64 non-first-fragment translation: plan of action

**Status:** DRAFT v2 — folds Claude-SMR r1 (S1–S5) + AGY r1 (5 findings);
awaiting Codex r1
**Issue:** psaab/xpf#2562 — *userspace-dp: NAT64 non-first fragment translation
needs a stateful frag-id→SNAT cache (deferred from #2488)*
**Base:** origin/master `a30a1f98b` (Merge PR #3600 — #3291 flowless enforcement)
**Mode:** `/research` — design only. No code, no PR. Stops at PLAN-READY /
PLAN-DEFER / PLAN-KILL.

---

## 1. Issue framing

A NAT64 datagram that is fragmented does not traverse the firewall end-to-end.
After #2488/#2561 the **first** fragment (offset 0, carries the L4 header)
translates correctly per RFC 7915 (MF/offset/Identification derived from the
IPv6 Fragment Header v6→v4, a v4→v6 Fragment Header inserted, L4 checksum
adjusted for the pseudo-header delta). But every **non-first** fragment
(offset > 0, no L4 header) is dropped in both directions. The receiver gets the
first fragment marked MF=1 and never the rest → reassembly times out → the whole
datagram is lost.

A non-first fragment carries no L4 ports, so it cannot find the flow/session
that holds the translation state (the SNAT source the first fragment chose for
v6→v4, or the `orig_src_v6` the reverse session holds for v4→v6). The issue asks
for a **stateful fragment-association cache** keyed by `(src, dst, frag-id)` that
carries the first fragment's translation decision to its non-first fragments, so
they translate to the same source and reassemble at the receiver.

**The decision this `/research` pass must make** (per the framing): is this the
*same* fragment-association subsystem that #3291 explicitly deferred as its
"stage 4", or a NAT64-specific mechanism? The strong prior is one shared
subsystem. Section 5/6 resolves it: **share — with one important refinement to
the #3291 stage-4 placement (it must be process-shared, not worker-local).**

---

## 2. Honest scope / value framing

NAT64 is deployed with DNS64. Large UDP DNS/DNSSEC responses (reverse, v4→v6) and
large client uploads (forward, v6→v4) are **genuine real-world NAT64 traffic**
that fragments. Silently dropping fragmented datagrams breaks them. This is not
academic.

Counter-weight (honest): the case is **niche** (only datagrams large enough to
fragment), and it is **lab-bound** — the loss userspace cluster has **no NAT64
path**, so this can only be verified with unit / synthetic-packet tests
(`userspace-dp/src/nat64_tests.rs` is the established pattern), never a live
cluster smoke. #1852 set a precedent of *dropping* pool-mode SNAT non-first
fragments that was accepted.

*If reviewers conclude the value is too small to justify the subsystem, or that
it must wait on a maintainer decision about the #3291 stage-4 prerequisite,
PLAN-DEFER (or PLAN-KILL→document-drop) is an acceptable verdict.* This plan's
own recommendation (Section 11) is **PLAN-DEFER**, because #2562 is strictly
dependent on a prerequisite (#3291 stage 4) that is itself deferred.

---

## 3. Ground truth — what the code does today (origin/master a30a1f98b)

### 3.1 The translators fail closed on non-first fragments

- **v6→v4 drop:** `userspace-dp/src/nat64.rs:760-764` —
  `if ipv6_is_non_first_fragment(packet) { return None; }` inside
  `write_v6_to_v4_into`. `ipv6_is_non_first_fragment` (nat64.rs:612) walks the
  extension-header chain and returns true iff a Fragment Header (44) is present
  with a non-zero 13-bit offset.
- **v4→v6 drop:** `userspace-dp/src/nat64.rs:~999` —
  `let v4_offset_units = v4_frag_word & 0x1FFF; … if v4_offset_units != 0 {
  return None; }` inside `write_v4_to_v6_into`.
- Existing tests assert the drop: `nat64_tests.rs`
  `translate_v6_to_v4_non_first_fragment_dropped` (2052),
  `nat64_v4_to_v6_non_first_fragment_dropped` (2351),
  `nat64_v6_to_v4_non_first_fragment_still_dropped` (2384).

### 3.2 The translators are NOT EVEN REACHED for non-first fragments today

This is the sharper, post-#3600 truth and the reason a "just stop dropping in the
translator" patch is insufficient:

- NAT64 forward classification (`classify_ipv6_dest`, which extracts the v4
  destination and allocates the SNAT source) runs **only on the `Some(flow)`
  cold path**: `userspace-dp/src/afxdp/poll_descriptor/mod.rs:1055`.
- The forward decision is committed there:
  `decision.nat = Nat64State::forward_decision(snat_v4, dst_v4)`
  (`poll_descriptor/mod.rs:1987`), and the reverse mapping
  `Nat64ReverseInfo { orig_src_v6, orig_dst_v6 }` is stored **in the session**
  (`poll_descriptor/mod.rs:1988`, `session/entry.rs:32`).
- A non-first fragment is **flowless** (#2344: `parse_session_flow_from_*`
  returns `None` so payload bytes are never read as L4 ports), so it never enters
  the `Some(flow)` arm. It lands in the **flowless `else` arm**
  (`poll_descriptor/mod.rs:2712`). After #3600 that arm runs L3 policy / input
  filter / PBR, then returns
  `SessionDecision { resolution: final_resolution, nat: NatDecision::default() }`
  (`poll_descriptor/mod.rs:~2905`).
- **`classify_ipv6_dest` is never called on the flowless arm, and
  `nat = NatDecision::default()`.** So a non-first NAT64 fragment:
  - **Forward (v6→v4):** its destination is the *synthetic NAT64 v6 prefix
    address*. The flowless arm runs `resolve_forwarding` on that v6 address with
    no translation. NAT64 prefixes are not installed as plain v6 routes, so the
    typical outcome is `NoRoute` → drop. If a default v6 route *does* cover the
    prefix, the fragment is **forwarded untranslated** (a v6 packet that can
    never reassemble with the v4 first fragment at the receiver) — a worse,
    fail-open variant.
  - **Reverse (v4→v6):** the reply fragment's destination is `snat_v4` (a pool
    address). The flowless arm does no reverse translation → mistranslate /
    misroute / drop.

So the gap is **two-layered**: even a translator that handled non-first frags
would not be invoked, because the flowless arm has no NAT64 classification and no
carried decision. **The fix must (a) carry the first fragment's NAT64 decision to
the flowless arm and (b) make the translator translate (not drop) a non-first
fragment as L3-only.** Part (a) is exactly the #3291 stage-4 fragment-association
cache; part (b) is the NAT64-specific delta.

### 3.3 The decision object already models NAT64 (key sharing fact)

`NatDecision` (`userspace-dp/src/nat/mod.rs:67`) carries
`rewrite_src/rewrite_dst (Option<IpAddr>)`, `rewrite_src_port/dst_port`,
`nat64: bool`, `nptv6: bool`. `Nat64State::forward_decision(snat_v4, dst_v4)`
(nat64.rs:373) returns `NatDecision { rewrite_src: Some(V4(snat_v4)), rewrite_dst:
Some(V4(dst_v4)), nat64: true, … }`.

**Consequence (forward):** a fragment-association cache that stores the first
fragment's full `SessionDecision` (resolution + `NatDecision`) *already* carries
the NAT64 **forward** translation (`snat_v4`/`dst_v4`). The forward direction
needs no value extension.

**Correction (reverse) — Claude-SMR S1:** the **reverse** v4→v6 translation is
NOT driven by `NatDecision`. It is driven by `Nat64ReverseInfo { orig_src_v6,
orig_dst_v6 }`, stamped on the **session metadata** (`poll_descriptor/mod.rs:2180`
forward entry, `:2428` reverse entry) and recovered on the TX path
(`afxdp/frame/mod.rs:248` `let info = nat64_reverse?` → `build_nat64_v4_to_v6_frame`).
`NatDecision` (`nat/mod.rs:67`) has no v6-original-source field. **Therefore the
cached VALUE must be extended for NAT64: forward fits `NatDecision`; reverse needs
the session's `nat64_reverse` mapping folded into the cached value.** The cache
remains ONE shared subsystem (same key / eviction / TTL / DoS / HA / process-
shared placement); the cross-family extension is on the value side (this reverse
field) AND the egress side (cross-family frame build, Section 5).

### 3.4 Sharing model — the load-bearing constraint

- **`SessionTable` is PER-WORKER:** `userspace-dp/src/afxdp/worker/loop_body/
  setup.rs:40` (`pub(super) sessions: SessionTable`); session/mod.rs:570 comment
  "every worker's SessionTable on this node shares the same seed" (shared seed,
  separate tables).
- **The warm-path flow cache is PER-WORKER** (`afxdp/flow_cache.rs`, a hot
  lock-free per-worker structure; counters accumulated per-binding).
- This is fine for normal flows: RSS steers all packets of a 4-tuple to one
  worker. **But fragments are NOT GUARANTEED to co-locate** (Claude-SMR S2): the
  NIC may steer the **first** fragment by 4-tuple (it has ports) and **non-first**
  fragments by 2-tuple (no ports), so under a plausible default mlx5 RSS config
  they can hash to **different RX queues → different workers**. The first
  fragment's state (session, flow-cache decision) is then on worker A while the
  non-first fragment arrives on worker B. A correct design must NOT depend on RSS
  co-locating fragments (some configs hash all fragments, first included, by the
  2-tuple and DO co-locate — but we cannot rely on it). AGY r1 holds the stronger
  position that the split is effectively guaranteed under the live default; either
  way the conclusion is the same — a worker-local cache cannot be trusted.

**This is the central architectural finding of this pass** and it constrains the
shared subsystem's placement (Section 5.3 / Section 7).

### 3.5 Fragmented ICMP first-fragment zero checksum (linked sub-item agy-039-03)

Today NAT64 forwards a fragmented ICMPv6 first fragment with a zero ICMPv6
checksum; harmless only because non-first frags are dropped and the datagram
never reassembles. If fragments traverse, this becomes a real receiver-discard
bug — and the ICMP checksum covers the **whole** datagram, so it cannot be
recomputed from a single fragment without true reassembly. This must be resolved
as part of this work, not as a standalone issue (per the issue comment).

---

## 4. What is already shipped / must be composed with

- **#2488 / PR #2561** — per-packet RFC-7915 fragment correctness for FIRST and
  atomic fragments (the translators' frag-field handling: v4 ident = low-16 of
  the v6 32-bit ident; v6 ident = v4 16-bit ident zero-extended; offset copied
  verbatim in 8-byte units; v4→v6 Fragment Header inserted; v4 UDP frag with
  zero checksum dropped). **These field policies are exactly what a non-first
  fragment also needs — the translator already computes them; it just must stop
  short-circuiting to `None`.**
- **#2344** — non-first fragments are flowless (payload never read as ports).
  **Invariant: must not be reintroduced.** The fragment-association cache must
  key on L3 + IP-ID, never synthesize an L4 tuple from payload bytes.
- **#3064** — L3 fragment screens (ping-of-death / teardrop / icmp-fragment) run
  on the flowless path (`check_fragment_screens_l3`). Screens run BEFORE this
  cache (defense in depth against a frag flood).
- **#3291 / PR #3600 (merged today, base of this branch)** — the flowless
  transit arm now enforces zone policy + input filter + PBR using a synthetic
  L3-only `SessionFlow` (ports 0, `l4_present=false`, never inserted). **PR #3600
  explicitly documents the deferred stage:** *"A flow PERMITTED only by an
  L4-specific term has its non-first fragments fall to the default policy
  (fail-closed drop) until the deferred fragment-association-cache stage of the
  converged plan (`docs/research/3291-flowless-enforcement/plan.md`) carries the
  first fragment's verdict."*
- **#3291 converged plan, stage 4** (`research/3291-flowless-enforcement` branch,
  SHA `d723e250d`) — designed the fragment-association cache to store the first
  fragment's **full `SessionDecision`** (not a bare verdict), session-lifetime-
  bound, with an **IP-ID aliasing defense** (AGY-1: fold a timestamp/generation
  into the entry; the v4 frag-id is only 16 bits and wraps fast), and **NAT
  header rewrite on egress fragments** (AGY-2: a non-first fragment of a
  NAT'd flow must have its outer L3 header rewritten per the cached
  `NatDecision`, not merely inherit the permit). **#2562 is the cross-family
  (NAT64) instance of AGY-2.**
- **#1852** — pool-mode SNAT drops non-first fragments
  (`source_nat_non_first_fragment`); address-only/static NAT translate fragments
  deterministically (no per-flow state). NAT64 pools are like pool-mode SNAT:
  they need per-flow state → they need the cache.

---

## 5. The crux — shared subsystem vs NAT64-specific, and the design

### 5.1 Verdict: SHARE the #3291 stage-4 fragment-association subsystem

Reasons, in order of strength:

1. **The storage is (almost) identical.** #3291 stage-4 stores the first
   fragment's full `SessionDecision`. `SessionDecision.nat` is a `NatDecision`,
   and `Nat64State::forward_decision` already populates it with the NAT64 forward
   translation (`nat64=true`, `rewrite_src=snat_v4`, `rewrite_dst=dst_v4`). The
   FORWARD value needs no extension. The REVERSE value needs the session's
   `Nat64ReverseInfo` folded in (Claude-SMR S1, §3.3) — a small NAT64-specific
   field on the SHARED cached value, NOT a second cache. **A NAT64-specific
   `(src,dst,frag-id)→mapping` cache would duplicate the key, eviction, TTL, DoS
   bound, IP-ID defense, and HA policy of the stage-4 cache; sharing avoids that
   fork.**
2. **The keys are identical.** Both want a **port-free** key
   `(addr_family, src_ip, dst_ip, protocol, ip_id/frag_id)` so all fragments of
   one datagram co-locate. There is no NAT64-specific key shape.
3. **The hazards are identical and already analyzed in stage 4:** IP-ID aliasing
   (16-bit v4 frag-id wrap), DoS bound (bounded LRU + pressure event), reorder
   (non-first-before-first → drop+counter or short hold), HA (no sync). Solving
   them once is strictly better than twice.
4. **The egress mechanism generalizes cleanly.** #3291 stage-4's AGY-2 step
   already says "rewrite the egress fragment's L3 header per the cached
   `NatDecision`". NAT64 is just the cross-family case of that one step.

**Therefore #2562 is NOT a separate cache. It is, precisely (Claude-SMR S3):
the SHARED stage-4 cache (key / eviction / TTL / DoS bound / IP-ID defense / HA
non-sync / process-shared placement) + a NAT64-specific value extension
(`Nat64ReverseInfo`, S1) + a NAT64-specific egress dispatch (cross-family frame
build, not a same-family header rewrite) + the translator un-drop.** "One
subsystem" means one cache, not free code: the egress/value halves are genuine
NAT64 work on top. This supersedes the earlier campaign-8 `/research` comment on
#2562 (which proposed a self-contained NAT64-specific sharded cache); that comment
predates PR #3600 and the #3291 stage-4 design and did not cross-reference it.

**Dependency seam (Claude-SMR S4):** because the value needs a cross-family field
(S1) and the egress needs a cross-family dispatch (S3), #3291 stage 4 must design
its cached-value type as an EXTENSIBLE container and its egress step as a
DISPATCH from day one, or #2562 forces a retrofit. The recommendation is
therefore "defer behind #3291 stage 4 **AND** require stage 4 to reserve the
cross-family value/egress seam."

### 5.2 The NAT64-specific delta (what #2562 adds on top of stage 4)

1. **Carry NAT64 classification onto the flowless arm.** Today
   `classify_ipv6_dest` runs only on the cold path. Stage 4's cache hands the
   non-first fragment the first fragment's `SessionDecision.nat` (which already
   encodes `snat_v4`/`dst_v4` forward, or the reverse mapping), so the flowless
   arm does **not** need to re-run `classify_ipv6_dest` — it consults the cache.
   On a cache hit with `nat.nat64 == true`, dispatch to the NAT64 frame builder
   instead of the same-family L3 rewrite.

2. **A non-first-fragment "L3-only translate" mode in the #2488 translators.**
   Add a path in `write_v6_to_v4_into` / `write_v4_to_v6_into` (gated by a
   `non_first_fragment: bool` argument, or a sibling
   `write_*_non_first_fragment_into`) that, instead of `return None`:
   - copies the L4/payload region **verbatim** (no L4 parse, no L4 checksum —
     there is no transport header);
   - translates **only** the L3 header across families;
   - **v6→v4:** strip the 40-byte v6 header + Fragment Header; emit a 20-byte v4
     header with DF=0, MF copied from the v6 Fragment Header M flag, the 13-bit
     offset copied verbatim, **v4 ident = low-16 of the v6 32-bit ident** (the
     SAME truncation the first fragment used — load-bearing for reassembly),
     recompute the v4 header checksum; net L3 length change **−20 − 8** (drop v6
     base + Fragment Header) **+ 0** for payload;
   - **v4→v6:** emit a 40-byte v6 header + an 8-byte Fragment Header; offset
     copied verbatim, M from v4 MF, **v6 ident = v4 16-bit ident zero-extended**;
     net L3 length change **+20 + 8**;
   - v4 UDP zero-checksum needs NO special tracking in the cache (AGY r1
     finding 5 — resolves Q4): the existing #2488 rule drops a first fragment
     whose UDP checksum is 0, so that datagram never inserts a cache entry, and
     its non-first fragments then naturally miss → drop. No "first-frag-had-zero-
     csum" flag is required.
   - **No L4 checksum touch in either direction** (no L4 header present). This is
     simpler than the first-fragment path, which adjusts the L4 checksum for the
     pseudo-header delta.

3. **Drop fragmented ICMP/ICMPv6 NAT64 in BOTH directions (first AND non-first),
   with a counter** (resolves agy-039-03). The ICMP checksum covers the whole
   datagram and cannot be recomputed from a fragment without reassembly.
   Fragmented ICMP is niche (large echo only). The cache serves TCP/UDP. This is
   a small, separable change that can ship with or slightly ahead of the cache.

### 5.3 The refinement to stage 4: process-shared, not worker-local

The #3291 stage-4 plan describes the cache as **worker-local + an L3+proto
session fallback** on a cache miss. **That is not RSS-robust given §3.4: the
session table and flow cache are per-worker, and fragments split across
workers.** A worker-local cache populated by the first fragment on worker A is
invisible to the non-first fragment on worker B, and the "L3+proto session
fallback" also fails because the *session* is on worker A too. Under default
mlx5 RSS this silently drops fragmented NAT64 datagrams while passing every
single-worker unit test — the worst kind of regression.

**Resolution (applies to the shared subsystem, benefiting both #3291 and
#2562):** the fragment-association cache must be **process-shared and sharded** —
N shards by `hash(family, src, dst, proto, ip_id)` (port-free so all fragments of
one datagram hit the same shard), each shard a fixed-capacity LRU+TTL behind a
`parking_lot::Mutex`. The hot path (non-fragmented packets) never touches it, so
contention is confined to the rare fragment path. The L3+proto session fallback
becomes a *secondary* recovery that only helps when the fragment happens to land
on the session's worker; the process-shared cache is the *primary*, RSS-robust
mechanism.

This is the one substantive correction this pass makes to the #3291 stage-4
design, and it is the reason the two issues must be designed as one subsystem
rather than #2562 silently inheriting a worker-local assumption that breaks it.

### 5.4 Cache shape (the shared subsystem)

- **Key:** `(addr_family: u8, src_ip, dst_ip, protocol: u8, ip_id: u32)` — IPv4
  packs the 16-bit frag-id into the low 16 of `ip_id`; IPv6 uses the 32-bit
  Fragment Header Identification. Port-free.
- **Value:** the first fragment's `SessionDecision` (resolution + `NatDecision`),
  **plus — for NAT64 — the session's `Nat64ReverseInfo`** (Claude-SMR S1 / AGY-1:
  the reverse v4→v6 build needs `orig_src_v6`/`orig_dst_v6`, which `NatDecision`
  does not carry), **plus an entry deadline (monotonic ns) and a
  generation/timestamp** for the IP-ID aliasing defense. The NAT64 reverse field
  is an `Option` on the shared value — empty for the generic #3291 stage-4 case,
  populated for NAT64 — so it is one cache, not two.
- **Populate:** only the FIRST fragment (offset 0, has L4, passed policy, created
  or matched a session/produced a `SessionDecision`) inserts. **Non-first
  fragments NEVER insert** — the load-bearing DoS property (an attacker cannot
  grow the table with cheap headerless fragments).
- **Consult:** non-first fragments look up; on hit → translate per the cached
  decision (NAT64 cross-family dispatch when `nat.nat64`); on miss → drop +
  counter (`nat64_frag_assoc_miss` / the generic `frag_assoc_miss`).
- **Bound:** fixed per-shard capacity (e.g. 64–256 entries/shard × N shards ≈ a
  few hundred KB), LRU eviction, pressure event (reuse the screen scan-table
  pattern). No payload bytes stored.
- **TTL:** short (target ~2 s) for the *association*; refresh-on-hit so a long-
  lived fragmented flow keeps its entry, with the L3+proto session lookup as the
  fallback when an entry was evicted but the session is still live (inv. 11/R9
  from stage 4). Document the deviation from RFC's 60 s reassembly timeout — we
  associate, we do not reassemble.

### 5.5 Counters / metrics (follow the `nat64_no_source_pool` plumbing)

New `nat64_*` (and/or generic `frag_assoc_*`) counters threaded through the
existing pipeline: `worker/mod.rs` telemetry counters → `umem` `AtomicU64`
→ `umem/snapshot.rs` → `coordinator/refresh_bindings.rs` + `reset.rs` →
`protocol/binding.rs` (`WireUint64`, `#[serde(default)]`). Proposed:
`nat64_frag_assoc_inserts`, `nat64_frag_assoc_hits`, `nat64_frag_assoc_miss`,
`nat64_frag_icmp_dropped`. (If the shared subsystem owns generic
`frag_assoc_*`, NAT64 increments those + a NAT64-specific `nat64_frag_*` subset.)

---

## 6. Design options

### Option A — share the #3291 stage-4 subsystem, NAT64 = cross-family extension [RECOMMENDED]

Build the process-shared sharded fragment-association cache **once** (stage 4 of
the #3291 plan), then add the NAT64 cross-family egress dispatch + the
non-first-fragment L3-only translator mode + the fragmented-ICMP drop. One
subsystem, one set of hazards solved once. **Dependency:** #3291 stage 4 must
land first (or co-deliver). #2562 cannot be `/engineer`'d standalone.

### Option B — NAT64-specific frag-id→mapping cache (the earlier #2562 comment)

A self-contained sharded `(src,dst,ident)→snat_v4/orig_src_v6` cache, no HA sync,
~2 s TTL, drop-on-miss. **Rejected as the primary path:** it duplicates the
stage-4 cache (storage, key, all hazards) and **lacks the session-lifetime
fallback**, so it drops mid-flow fragments of a long-lived flow after a 2 s
eviction. It also forks the codebase into two near-identical frag caches that
will drift. Acceptable ONLY if #3291 stage 4 is abandoned — then #2562 would
stand up the cache itself (and the same process-shared/sharded requirement from
§5.3 applies).

### Option C — true IP reassembly (`force-ip-reassembly`)

Reassemble the full datagram before translation (the `security flow
force-ip-reassembly` feature-gap, docs/feature-gaps.md:300). **Rejected for this
issue:** far larger (a reassembly engine: per-source buffers, overlap handling,
timeout, DoS surface by datagram size), and it solves a different feature. The
association cache is the minimal correct mechanism; reassembly is a separate,
bigger project. (It *would* additionally fix fragmented-ICMP — but at a cost out
of proportion to this issue.)

**Recommendation: Option A**, sequenced behind #3291 stage 4.

---

## 7. Hidden invariants the change must preserve

1. **#2344:** non-first fragments stay flowless; payload bytes are never read as
   L4 ports. The cache keys on L3 + IP-ID only.
2. **Non-first fragments never insert into the cache** (DoS) and are never
   inserted into any session index (#3290).
3. **Same v4/v6 ident across all fragments of a datagram.** v6→v4 must use the
   SAME low-16 truncation the first fragment used; v4→v6 the same zero-extension.
   A mismatch makes fragments unreassemblable — silently. (Test must assert the
   first and non-first translated idents match.)
4. **Hot path untouched.** Non-fragmented packets never lock the shared cache.
5. **Screens run first** (#3064) — a frag flood is rate-limited before it can
   pressure the cache.
6. **Side-effect ordering on the flowless arm** matches PR #3600: input filter →
   PBR → policy → (new) NAT64 translate → forward. The cache consult and
   translation happen only after the packet is permitted.
7. **HA:** the cache is NOT synced (transient, sub-second). The durable
   `snat_v4`/reverse mapping is already carried by session sync; only the
   transient association is lost on failover → the in-flight fragmented datagram
   is dropped → retransmitted. Documented, bounded, acceptable. (No new control-
   socket traffic — respects the CLAUDE.md control-socket contention rules.)
8. **No L4 checksum work on non-first fragments** (no L4 header). Only the v4 L3
   header checksum is (re)computed.

---

## 8. Risk assessment

| # | Risk | Severity | Mitigation |
|---|------|----------|------------|
| R1 | Cross-worker fragment split silently drops datagrams (worker-local cache) | **HIGH** | Process-shared sharded cache (§5.3); a cross-worker insert-A/consult-B test; do NOT inherit stage-4's worker-local assumption |
| R2 | IP-ID aliasing: 16-bit v4 frag-id wraps → stale hit → wrong-source / wrong-verdict inheritance | **HIGH** | Fold timestamp/generation into the entry + aggressive age bound (stage-4 AGY-1); short TTL |
| R3 | Cache = DoS surface (frag flood) | MED | Non-first frags never insert; bounded LRU + pressure event; screens (#3064) run first; reverse inserts gated by live sessions |
| R4 | Mid-flow eviction drops fragments of a long-lived flow | MED | Refresh-on-hit + L3+proto session fallback (stage-4 inv.11/R9); TTL not shorter than needed |
| R5 | Fragmented ICMP first-fragment zero checksum becomes a real discard bug once frags traverse (agy-039-03) | MED | DROP fragmented ICMP/ICMPv6 both directions + counter (§5.2.3) |
| R6 | Reorder: non-first arrives before first | LOW | Drop + counter (RFC permits; sender retransmits); no payload buffering (would be a bigger DoS surface) |
| R7 | Reintroducing an L4 read on a fragment (#2344 regression) | MED | Cache keys L3+IP-ID only; non-first translator copies payload verbatim, never parses L4 |
| R8 | Lab-bound: no live NAT64 on the cluster | MED | Unit/synthetic verification only (accepted precedent); RED-on-revert tests are the gate |
| R9 | Architectural mismatch: two competing frag caches drift | MED→LOW | Option A (one shared subsystem) eliminates the fork |
| R10 | Dependency: #3291 stage 4 is itself deferred | — | This plan's verdict is PLAN-DEFER with an explicit `blocked-by #3291 stage 4` |

**PLAN-DEFER / PLAN-KILL is explicitly acceptable** if reviewers judge the shared
fragment-association subsystem large enough to need its own staged effort or a
maintainer decision — which is precisely this plan's recommendation.

---

## 9. Test plan (unit / synthetic — RED-on-revert)

No live NAT64 on the cluster; verification is `nat64_tests.rs` +
`afxdp/tests.rs` full-poll-loop tests (the #3600 `txn_run_descriptor` pattern).

1. **Forward v6→v4, 2-fragment UDP:** first then non-first → BOTH translate, the
   non-first gets the SAME `snat_v4` as the first, frag fields preserved, output
   is a reassemblable v4 datagram. **RED on revert:** forcing the non-first
   translator back to `return None` (or `nat = default()` on the flowless arm)
   must fail this test.
3. **Ident equality invariant:** assert the first and non-first translated v4
   idents are equal (and v6→v4 = low-16 of the v6 ident). RED if the truncation
   diverges.
3. **Reverse v4→v6 symmetric:** large DNS64-style reply, first + non-first →
   both translate to the same `orig_src_v6`; reassemblable v6 datagram.
4. **Cross-worker:** insert-on-worker-A / consult-on-worker-B against the shared
   structure → hit. RED if the cache is made worker-local.
5. **Non-first-before-first (reorder):** miss → drop + `nat64_frag_assoc_miss`.
6. **Orphan non-first flood (attack):** never inserts; cache size stays bounded;
   miss counter increments; no stale-hit wrong-source.
7. **Pool > 1:** the non-first inherits the first fragment's round-robin
   `snat_v4`, NOT a recomputed/hashed value.
8. **Fragmented ICMP echo:** dropped both directions + `nat64_frag_icmp_dropped`.
9. **TTL expiry + LRU eviction** unit tests; deleting the bound/TTL must fail a
   test (RED-on-revert of the DoS bound).
10. **No-regression:** the three existing non-first-fragment-dropped tests are
    rewritten to assert *translate* (the behavior change) — keep one
    `*_still_dropped` for the fragmented-ICMP case.
11. Full `cargo test --release` green; the relevant named tests 5× for flake.

---

## 10. Out of scope (explicitly)

- True IP reassembly / `force-ip-reassembly` (Option C; separate feature gap).
- HA sync of the fragment-association cache (intentionally not synced).
- Buffering out-of-order non-first-before-first fragments (drop + counter; a
  pending buffer is a larger DoS surface — deferred / not planned).
- Fragmented-ICMP **translation** (we DROP it; full reassembly would be needed).
- The non-NAT64 same-family egress-rewrite half of #3291 stage 4 (that is #3291's
  scope; #2562 only adds the cross-family dispatch on top of it).

---

## 11. Open questions for adversarial review (each invitable to PLAN-DEFER/KILL)

1. **Sequencing:** must #3291 stage 4 land first, or should #2562 co-deliver the
   shared cache *and* the NAT64 extension in one effort? (Plan assumes stage 4 is
   the prerequisite → PLAN-DEFER. Is co-delivery preferable so the cache is
   designed with the cross-family egress requirement from day one?)
2. **Process-shared vs worker-local (§5.3):** is the per-worker session/flow-cache
   model (proven at `worker/loop_body/setup.rs:40`) definitely the live posture,
   making a process-shared sharded cache mandatory? Or is there a cross-worker
   session-visibility mechanism that would let a worker-local cache + session
   fallback suffice? (If a reviewer can show sessions ARE cross-worker visible,
   the §5.3 refinement is unnecessary.)
3. **How does NAT64 reverse work across workers TODAY?** The v6 forward session
   is on worker A (v6 hash); the v4 reply hashes to worker B (v4 hash). Verify
   whether reverse NAT64 currently relies on RSS/symmetry, on a shared index, or
   is itself cross-worker-fragile — it informs where the reverse cache/decision
   must live.
4. **[RESOLVED — AGY r1 finding 5]** v4-UDP-zero-checksum: no cache flag needed.
   The #2488 rule drops the first fragment whose UDP checksum is 0, so it never
   inserts, and its non-first fragments then miss → drop naturally. Dropping only
   the first is sufficient.
5. **DoS bound numbers:** what per-shard capacity / shard count / TTL is the
   right fixed ceiling? (Plan suggests a few hundred KB, ~2 s TTL.)
6. **Ship-now vs defer:** given niche + lab-bound (no cluster smoke), is the
   DNS64-large-response value worth the subsystem now, or does it wait on the
   #3291 stage-4 maintainer decision? (Plan: defer.)
7. **Counter ownership:** generic `frag_assoc_*` (shared) + a NAT64 subset, or
   NAT64-only counters? (Affects whether #3291 stage 4 and #2562 share the wire
   schema.)
