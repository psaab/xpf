# Plan of action — #3617: locally-generated reject/error replies are never mirror-cloned

- Issue: #3617 (audit / enhancement; from codex-review-002 M04, folds L10, L18)
- Base: origin/master `f1d00ffeb`
- Branch: `research/3617-mirror-clone`
- Revision: **r2** (r1→r2: SMR accuracy fix — L10 is covered for reject +
  SYN-cookie replies but NOT for the PTB/time-exceeded generated ICMP errors)
- Status: **PLAN-KILL (works-as-intended)** — recommended verdict, pending 3-way review convergence
- Mode: `/research` — stops at PLAN-READY / PLAN-KILL. No PR. No production code.

---

## 1. Problem statement

The issue asserts that locally-generated reject/error replies (policy/filter
`then reject` → TCP RST or ICMP/ICMPv6 admin-prohibited unreachable; and, by
extension in L18, SYN-cookie replies, PTB / time-exceeded ICMP errors) are
enqueued with `mirror_clone: false` hard-coded. It concludes that a configured
port-mirroring / analyzer session therefore "sees the trigger packet but NOT
the RST/ICMP reject the device actually sent," which the issue frames as
misrepresenting what the box put on the wire for forensics (policy rejects,
PMTUD, scanner behaviour).

The issue explicitly classifies itself as a **design-fork**: "the 'should local
replies be mirrored' question is a policy decision → becomes driveable once
decided." This research answers that policy question against Junos semantics
and against the actual xpf mirror mechanism.

## 2. Current behaviour (file:line evidence, origin/master f1d00ffeb)

### 2.1 The `mirror_clone: false` on generated replies

- `userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs:233-244` — the reject
  reply `TxRequest` (TCP RST / ICMP unreachable) sets `mirror_clone: false`.
- `userspace-dp/src/afxdp/poll_descriptor/cookie_reply.rs:111-124` — the
  SYN-cookie reply `TxRequest` sets `mirror_clone: false` (same pattern).
- All three transit-forward paths ALSO set `mirror_clone: false` on the
  forwarded frame itself: `neighbor_dispatch.rs:372`, `flow_cache_hit.rs:384`,
  `tx/dispatch/mod.rs` (multiple), `tunnel.rs:637`, `coordinator/inject.rs:256`,
  `tx/tcp_segmentation.rs:296`.

### 2.2 What `mirror_clone` actually means (the load-bearing finding)

`mirror_clone: true` does **NOT** mean "please clone this frame to the
analyzer." It marks a `TxRequest`/`PreparedTxRequest`/CoS item as *being itself
a mirror copy*, which makes it **droppable** when free TX frames fall to/below
the reserve:

- `tx/transmit/mod.rs:102` — `if req.mirror_clone && free_tx_frames.len() <=
  MIRROR_TX_FRAME_RESERVE { drop + count mirror_drops_tx_frame_reserve }`.
- `cos/queue_service/drain.rs:73` and `:253` — same reserve-drop gate.
- `tx/cos_classify.rs:648` — `prepare_local_request_for_cos` returns `Err`
  (defers) when a `mirror_clone` request would dip below the reserve.

The **actual** mirror clone is a *separate* frame built by the mirror machinery
and directed at the analyzer's `output_ifindex`, with `mirror_clone: true` set
on that copy:

- `userspace-dp/src/afxdp/mirror/fast_path.rs:145-199`
  (`enqueue_mirror_clone_to_binding`) copies the source frame into a fresh TX
  frame, sets `egress_ifindex: config.output_ifindex` and `mirror_clone: true`,
  and pushes it onto the target binding's pending TX.

**Consequence:** setting `mirror_clone: true` on the reject/cookie reply's own
`TxRequest` (the literal fix the issue implies) would NOT send a copy to the
analyzer. It would only mark the reply itself as droppable under TX pressure —
i.e. it would make the firewall's own RST/ICMP LESS reliable, the opposite of
the intent. The issue's stated mechanism is a misreading of the field.

### 2.3 What the mirror mechanism actually does

- **Direction: ingress only.** The Go compiler only reads
  `forwarding-options port-mirroring instance <n> input { rate; ingress {
  interface <if>; } } output { interface <if>; }` — see
  `pkg/config/compiler_services.go:1295-1333` (`compilePortMirroring`). Only the
  `input.ingress.interface` list becomes mirror sources. There is **no
  egress/output-direction mirroring** compiled at all.
- **Keyed by ingress ifindex.** `pkg/dataplane/userspace/mirrors.go:64-86`
  emits one `MirrorConfigSnapshot{ IngressIfindex, OutputIfindex, Rate }` per
  ingress interface (one output per ingress; fail-closed on duplicates).
- **Runtime lookup is by ingress interface.**
  `userspace-dp/src/afxdp/mirror/mod.rs:54-69` (`resolve_mirror_config`) keys
  on the packet's ingress (logical) ifindex.
- **Triggered on the admitted-forward path only, cloning the as-received
  ingress frame.** The only three live mirror-clone call sites are:
  `flow_cache_hit.rs:284-367` (fast path), `neighbor_dispatch.rs:315-331`
  (ARP/NDP-resolved retransmit), `tx/dispatch/mod.rs:253-268` (slow-path
  forward). Each clones the *original ingress frame* (`packet_frame.to_vec()` /
  `source_frame`), keyed on the *ingress* config.

### 2.4 Corollary: the issue's premise ("sees the trigger but not the reply") is wrong

A policy/filter `reject` is decided on the **cold deny/exception arm** of
`poll_descriptor`; the trigger packet is **dropped before any forward**, so it
never reaches any of the three forward-path mirror-clone sites. Therefore for a
*rejected* flow the analyzer today sees **neither** the trigger nor the reply.
The stated "sees the trigger packet" is only true for flows that are *admitted
and forwarded* — which by definition are not the reject case. (For the L18
extension cases — PTB / time-exceeded — the trigger frame that WAS forwarded up
to the MTU/TTL check may be mirrored; but the generated ICMP error is a new
host-originated egress frame, covered by §4.)

## 3. Root-cause / mechanism analysis

There are two independent facts:

1. **Mechanism mismatch.** Mirroring a generated reply is *output-direction*
   mirroring of a *host-originated* frame. xpf implements *ingress-direction*
   mirroring of *transit* frames only. There is no code path — and no config
   grammar — by which a generated reply could be mirror-cloned today, and
   "threading `mirror_clone` through `classify_generated_reply`" does not create
   one (§2.2).

2. **Policy question.** Even a hypothetical full-Junos egress-mirroring
   implementation would not mirror these replies, because Junos restricts
   port-mirroring to transit data (§4).

## 4. Junos ground truth (the policy answer)

Authoritative Juniper documentation, confirmed across three independent
sources:

- **"Only transit data is supported."** — Junos OS *Configuring Port
  Mirroring* (Traffic Sampling, Forwarding, and Monitoring User Guide).
  Locally-generated / Routing-Engine-generated traffic (ICMP errors, TCP RST,
  ARP, control packets) is excluded.
- **"Layer 2 local data (packets destined for or sent by the Routing Engine,
  such as Layer 2 control packets) are not mirrored."** — Junos port-mirroring
  concept docs.
- **"CPU-generated packets (such as ARP, ICMP, BPDU, and LACP) cannot be
  mirrored on egress."** — Junos analyzer limitations.

Sources:
- https://www.juniper.net/documentation/us/en/software/junos/sampling-forwarding-monitoring/topics/concept/policy-configuring-port-mirroring.html
- https://www.juniper.net/documentation/us/en/software/junos/network-mgmt/topics/topic-map/port-mirroring-and-analyzers.html
- https://www.juniper.net/documentation/us/en/software/junos/network-mgmt/topics/topic-map/port-mirroring-and-analyzers-configuring.html

**Conclusion:** on a real Junos device (including SRX), the firewall's own
generated reject RST / ICMP unreachable / SYN-cookie SYN-ACK / PTB /
time-exceeded packets are **never** mirror-cloned to an analyzer, in either
direction. xpf's current behaviour (generated replies not mirror-cloned) is
therefore **Junos-conformant / works-as-intended**. Implementing the issue's
request would make xpf **diverge** from Junos by mirroring host-originated
control traffic a real SRX would never mirror.

## 5. Design options

### Option A — PLAN-KILL, close as works-as-intended (RECOMMENDED)

Do nothing to the reply builders. `mirror_clone: false` on generated replies is
correct and matches Junos "transit data only." Document the decision in the
issue and (optionally) in the mirror/README as a pinned invariant.

- Pro: Junos-conformant; zero risk; no hot-path change; no new config surface.
- Pro: the L10 test the issue asks for **already exists for the two reply
  families** — `reject_reply.rs:394` asserts `!req.mirror_clone` and
  `cookie_reply.rs:504` asserts `!req.mirror_clone`. **Residual:** the
  forward-path generated ICMP errors (PTB / Frag-Needed
  `tx/dispatch/mod.rs:438`, time-exceeded `:204`) set `mirror_clone: false` but
  have no test asserting it — L10 is NOT fully covered for the ICMP-error
  family. This is a one-line `assert!(!req.mirror_clone)` pin best folded into a
  future test-sweep; it is not a behaviour change and does not warrant holding
  #3617 open.
- Con: leaves the operator forensics desire (see host-generated wire traffic)
  unmet — but that desire is met by other means: the replies are already
  counted (`policy_reject_sent`, `filter_reject_sent`, SYN-cookie counters,
  generated-ICMP-error counters) and are subject to output firewall filters and
  CoS via `classify_generated_reply`.

### Option B — PLAN-DEFER: opt-in NON-Junos "mirror host-generated replies" knob

Add a deliberate, explicitly-non-Junos config knob (e.g. a per-instance or
global `include-host-generated` flag) that, when set, calls the mirror-clone
machinery for generated replies keyed on the reply's egress interface. Requires
(a) a new config grammar + wire field, (b) an egress-keyed mirror lookup (xpf's
table is ingress-keyed today), (c) hot-cold plumbing of a mirror decision into
each generator, (d) rate/reserve accounting for the extra clones.

- Pro: satisfies the forensics use-case for operators who want it.
- Con: net-new non-Junos feature; only worthwhile on explicit user demand; the
  audit issue is not that demand. Should be a NEW issue framed as a divergence,
  not this one.

### Option C — PLAN-DEFER: implement full Junos egress/output-direction mirroring

Build the missing `output`-direction port-mirroring (transit egress frames),
which xpf lacks entirely. This does **not** cover generated replies (Junos
excludes host-generated egress traffic), so it does NOT resolve #3617; it is a
separate feature gap. Listed only to show it is not a path to the issue's ask.

### L18 (shared local-output pipeline) — already substantially realized

The L18 aspiration — a shared abstraction for reject / PTB / time-exceeded /
cookie so CoS/DSCP/output-filter/telemetry stay consistent — is already largely
met by the shared `classify_generated_reply` SSOT
(`tx/cos_classify.rs:62-91`), through which every generator routes its egress
classification (#2238/#3026/#3035). Any further consolidation is an orthogonal
refactor, not a mirroring change, and is out of scope for #3617.

## 6. Recommendation & verdict

**PLAN-KILL — close #3617 as works-as-intended.**

Rationale (three independent, each individually sufficient):
1. **Junos parity:** Junos port-mirroring mirrors transit data only; generated
   reject/error replies are host-originated and are never mirrored on real
   hardware. Mirroring them would be a divergence, not a fix.
2. **Mechanism:** the proposed fix ("thread `mirror_clone` / set it on the
   reply") is a misreading — `mirror_clone: true` marks a frame droppable, it
   does not clone; it would degrade reply reliability, not add analyzer copies.
3. **L10 largely done:** the requested "pin mirror_clone as a deliberate
   invariant" test already asserts the correct value (`false`) in
   `reject_reply.rs` and `cookie_reply.rs`. The only gap is a missing one-line
   pin on the PTB/time-exceeded generated ICMP errors — a test-sweep item, not
   a reason to keep the issue open.

If a future operator explicitly wants non-Junos analyzer visibility into
host-generated control traffic, open a new, separately-scoped feature issue
(Option B) that is framed as a deliberate Junos divergence.

## 7. Risk table

| Change | Risk | Severity | Mitigation |
|---|---|---|---|
| PLAN-KILL (no code) | None — behaviour unchanged | None | n/a |
| (rejected) set `mirror_clone: true` on replies | Replies become droppable under TX reserve pressure → firewall's own RST/ICMP silently dropped | High | Do not do it; the field is a droppability marker |
| (deferred) Option B non-Junos knob | New config surface, egress-keyed mirror lookup, extra clone TX-frame pressure, Junos divergence | Medium | Explicit opt-in; separate issue; reserve accounting |
| (deferred) Option C egress mirroring | Does not resolve #3617; large feature | Medium | Separate issue |

## 8. Test plan

For the recommended PLAN-KILL there is **no code change**, therefore no new
tests are required. The invariant is already covered:

- `cargo test -p userspace-dp reject_reply` — includes
  `reject_tcp_with_egress_enqueues_rst` (asserts `!req.mirror_clone`).
- `cargo test -p userspace-dp cookie_reply` — includes the
  `assert!(!req.mirror_clone)` pin.
- `cargo test -p userspace-dp mirror` — the transit mirror-clone tests
  (`neighbor_dispatch` `mirror_req.mirror_clone` / `!forwarded_req.mirror_clone`)
  confirm the field's true droppability/clone-copy semantics.

If Option B is ever chosen, the test plan would be: config→snapshot round-trip
for the new knob; egress-keyed mirror lookup unit test; a generator test
asserting a separate analyzer clone is enqueued with `mirror_clone: true` and
`egress_ifindex == output_ifindex`; reserve-pressure fail-safe (reply itself
must never be dropped in favour of its mirror copy); and a smoke on the loss
cluster confirming analyzer receipt.

## 9. Blast radius / affected files

- **Recommended (PLAN-KILL):** zero source files. Optional one-paragraph note in
  `userspace-dp/src/afxdp/README.md` or a mirror doc recording the invariant +
  Junos rationale (doc-only; can also live purely in the issue).
- **Reference-only (not to be changed):**
  `userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs`,
  `.../cookie_reply.rs`, `userspace-dp/src/afxdp/tx/cos_classify.rs`,
  `userspace-dp/src/afxdp/mirror/{mod,fast_path,resolver}.rs`,
  `pkg/config/compiler_services.go`, `pkg/dataplane/userspace/mirrors.go`.

## 10. Rollback / non-goals

- Non-goal: mirroring host-generated replies (Junos does not; §4).
- Non-goal: implementing egress-direction port-mirroring (Option C; separate gap).
- Non-goal: any change to `mirror_clone` field semantics.
- Rollback: n/a (no code change).

## 11. Open questions / references

- Q: Does the user want a deliberate NON-Junos forensics extension (Option B)?
  If yes, that is a new issue, not #3617. Default assumption: no (audit issue,
  parity-driven project).
- References: #2089 (reject synthesis), #2521 (filter reject), #3071 (zone
  tcp-rst / unified deny reply), #2238 (generated-reply output classification),
  #3026/#3035 (logical-ifindex classify), #1374 (SYN-cookie replies),
  #1986 (mirror module split). Junos docs cited in §4.
