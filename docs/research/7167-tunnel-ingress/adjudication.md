# #7167 — bounded logical-tunnel-ingress: the adjudication

Continues `plan-r1.md` and `plan-r2.md`. Written at `origin/master`
`e0748d0c2`, after `#8062` landed the shared primitive and before any
adjudication mechanism exists.

**This document decides the SHAPE of the remaining work.** It is not a
plan for one PR. Its conclusion is that the issue's founding premise —
that WireGuard and IPsec are one defect wearing two costumes, so the hard
part should be solved once — is **wrong at the mechanism level**, and that
acting on it would build a bounded cross-thread packet handoff that the
WireGuard half does not need and the IPsec half cannot be fixed by alone.

---

## 0. What changed under the issue since it was written

Three premises the issue and `plan-r2.md` rest on have moved. None of them
retire the defect; two of them narrow it and one of them re-shapes the fix.

### 0.1 The outbound half is no longer fail-open (#7480)

`plan-r2.md` §3 and the issue comments dated 2026-08-29 conclude that a
Shape B (`bind-interface`-only) secure tunnel forwards its **outbound**
LAN → tunnel traffic through the Linux kernel with no adjudication, via
`NoRoute` → `is_slow_path_eligible()` → reinject. That was true when it
was measured. It is **no longer the current behaviour**.

`#7480` added an adjudication step to the `NoRoute` arm of
`poll_binding_process_descriptor`
(`userspace-dp/src/afxdp/poll_descriptor/mod.rs`, the
`ForwardingDisposition::NoRoute` arm), which calls
`forwarding::noroute_policy_denial` (`forwarding/mod.rs:126`) **before**
the frame reaches the slow-path chokepoint, and on a non-permit verdict
rewrites the disposition to `PolicyDenied` — which is *not* slow-path
eligible. The arm's own comment states the consequence:

> The egress is unresolved by definition here, so `to_zone_id` is the
> #3110 unzoned sentinel 0 and the evaluation falls through to the DEFAULT
> action. On a Junos-default deny box that means a NoRoute frame now
> drops.

So the accurate statement of the outbound direction today is:

| shape | outbound (LAN → tunnel) | requirement 9 |
|---|---|---|
| Shape A (interface row, zoned) | `MissingNeighbor` → its own zone-policy evaluation | satisfied |
| Shape B (`bind-interface` only) | `NoRoute` → `noroute_policy_denial` with to-zone 0 → **default action** | satisfied on a `deny-all` default; **still unadjudicated kernel forwarding on a `permit-all` default** |

`security policies default-policy permit-all` is a supported setting
(`pkg/config/types_security.go:137`), so the fail-open residue is real but
is now **narrow and operator-selected** rather than the standing behaviour
of a blessed config shape. That is a materially smaller claim than the one
the issue currently carries, and anyone costing requirement 9 from
`plan-r2.md` will over-budget it.

### 0.2 The shared primitive already landed (#8062)

`logical_ingress::build_logical_ingress_packet`
(`userspace-dp/src/afxdp/logical_ingress.rs`) is the protocol-agnostic
synthesize / ECN-combine / reparse / logical-rebind body, extracted out of
native GRE decap. Its `LogicalIngressParams` deliberately has no `Default`
and no `Option` on `config_generation` / `fib_generation`, so a new caller
cannot acquire an attachment generation by omission (invariant 5).

GRE is still its only caller — verified with a positive control (the same
grep that returns zero non-GRE callers does return `gre.rs:873`).

### 0.3 The WireGuard directions are ASYMMETRIC, and only one of them is broken

This is the finding that re-shapes the fix, and it is not recorded in the
issue, in `plan-r1.md`, or in `plan-r2.md`.

**WireGuard ENCAPSULATION already runs inside the AF_XDP worker, after
full adjudication.** `frame/mod.rs:420` dispatches
`TunnelKind::WireGuard` to `wg::wg_encap_frame` (`frame/wg.rs:473`) from
inside the forward-frame builder — i.e. on a packet that has already been
through screen, flow cache, session, route, policy and NAT. That path
reaches the live engine through `forwarding.wg_engines`
(`types/forwarding.rs:117`), does its own AllowedIPs longest-prefix match
(`engine.peer_for_dest`), and honours the per-peer endpoint.

**WireGuard DECAPSULATION runs in the control thread, before nothing.**
`coordinator/wg_control/dispatch.rs:215` writes the authenticated
plaintext straight to the `wgN` TUN.

So the worker **already holds every input the decap direction needs**:

| input decap needs | where the worker already has it |
|---|---|
| the live `WgEngine` | `forwarding.wg_engines` — the encap path reads it per packet |
| `try_decap` callable off a shared handle | `try_decap(&self, ...)` (`wg/engine.rs:1441`) — `&self`, with an internally synchronised session table (`RwLock`) and per-session replay-window mutex |
| the tunnel's logical ifindex | `TunnelEndpoint.logical_ifindex`, already used by the encap path's re-ownership guard |
| synthesize / rebind / reparse | `build_logical_ingress_packet` (#8062) |
| the outer ECN bits | **better than the control thread has them** — the outer IP header is still in the frame, so `outer_ecn_bits(frame, meta)` works directly, where the socket path must recover them out-of-band via `IP_RECVTOS` / `IPV6_RECVTCLASS` cmsg because the kernel UDP stack already stripped the header |
| attachment generations | inherited from the triggering RX meta, exactly as GRE does — the fencing problem the issue raises for a control-thread caller **does not arise** |

The encap direction is not merely present, it is **complete**: the WireGuard
TX path populates `decision.resolution.tx_ifindex` with the *physical
underlay* NIC (`frame/wg.rs:365-414`, #6308), which is the one producer of
that field in the tree. That is why LAN → WireGuard works end to end today
while an `xfrmi` egress does not (`resolve_tx_binding_ifindex` falls
through to the unbound tunnel ifindex and the dispatcher records
`missing_egress_binding`). So the WireGuard half has **no egress problem to
solve** — only the ingress asymmetry.

The asymmetry, not the absence of a handoff mechanism, is the defect.

---

## 1. The refuted premise

> "both are the same defect wearing two protocol costumes … Carrying them
> separately means solving the hard part twice."

They are the same defect at the level of **consequence** (tunnel plaintext
reaches the kernel FIB unadjudicated). They are **not** the same defect at
the level of **mechanism**, and the mechanism is what a fix is built from:

- **WireGuard decrypts inside xpf's own userspace.** The decision to
  decrypt on a non-worker thread is xpf's own, and it is reversible. The
  fix is to move the decap to the side that already does the encap. No
  cross-thread packet queue is required, so invariants 1 (bounded
  handoff), 5 (attachment fencing) and much of 8 (ownership / recycling
  model) are satisfied **structurally, by not creating the thing they
  constrain**.

- **IPsec decrypts inside the Linux kernel XFRM stack.** The issue
  explicitly (and correctly) forbids duplicating that: *"Preserve Linux
  XFRM as crypto/SA authority for this issue; do not duplicate
  decryption."* There is therefore no point inside userspace-dp where the
  plaintext exists — `forwarding/mss.rs` already says so — and the fix
  genuinely does require a capture mechanism that does not exist.

The only genuinely shared piece is the synthesize/rebind/reparse body, and
**it has already shipped** (#8062). Building a "single bounded
logical-tunnel-ingress abstraction" on top of that would be building the
WireGuard half out of a mechanism it does not need, in order to share it
with an IPsec half that is blocked on a separate, unanswered question.

---

## 2. The options, and what each costs

### Option A — WireGuard: move type-4 decap into the worker (CHOSEN for the WG half)

Claim inbound WireGuard **transport-data** records in the AF_XDP worker
instead of steering them to the kernel, decap them there through the
already-shared engine, and hand the result to
`build_logical_ingress_packet` exactly as native GRE does.

Cost, honestly stated:

1. **A shim change.** `wg_steer_to_kernel` (`userspace-xdp/src/lib.rs:1480`)
   currently matches on `UDP && dst_port == wg_listen_port &&
   is_local_destination` and does not look at the WireGuard message type.
   It must steer types 1/2/3 (handshake/cookie) to the kernel and leave
   type 4 to userspace. That is one bounds-checked read of the first
   payload byte, but it is a shim change: `make generate`, the pinned
   toolchain and the kernel-verifier gate (#1864).
2. **Endpoint roaming.** The control thread learns a peer's endpoint from
   authenticated datagrams, and data records are the dominant signal. If
   they stop arriving there, roaming degrades to handshake/keepalive
   cadence. Preserving it needs a **metadata** report from the worker to
   the control thread — bounded and lossy-tolerable, unlike a packet
   queue. This is the one place Option A owes new cross-thread plumbing,
   and it is the design's real open question.
3. **Replay-window contention.** `try_decap` takes a per-session mutex.
   Today that mutex is uncontended (one control thread). Under N workers
   it becomes a per-packet lock on the dataplane hot path, which the
   project's hot-path discipline treats as a defect by default. In
   practice RSS hashes one peer's 5-tuple to one worker, so a session is
   single-writer — but a **roaming** peer changes its source port and can
   migrate workers, so "single-writer in practice" is an assumption that
   owes a measurement, not an assertion.
4. **Handshake/data split ownership.** Sessions are created by the control
   thread and read by workers through the `Arc`. `populate_wg_engines`
   already preserves the engine across snapshot rebuilds
   (`forwarding_build/wg.rs:81`), so session state survives a rotation.

What it buys: invariants 2, 3, 4, 5, 6 and 7 come out **free**, because the
packet is an ordinary worker-pipeline frame from the moment it is decrypted
— the same way GRE's are. Invariant 1's bounded handoff is not satisfied so
much as **made unnecessary**.

### Option B — IPsec: a capture mechanism for XFRM plaintext (NOT chosen; B1 is refuted, B2 is unpriced)

Two sub-options. The issue is right that exactly one must be picked and
proven. **B1 is now refuted on measurement**, which narrows the IPsec half
to B2 and makes its cost the honest blocker.

#### B1 — an ingress-only AF_XDP / generic-XDP binding on the `xfrmi`: REFUTED

Four independent obstacles, each on its own sufficient, measured at this
HEAD:

1. **Framing.** The shim's `parse_l2` (`userspace-xdp/src/lib.rs:1302-1321`)
   unconditionally reads 14 bytes of Ethernet header; its only branch is
   the VLAN one. `frame_l3_offset` (`frame/inspect.rs:315-327`) returns
   only 14 or 18, and the one site that trusts a metadata offset
   whitelists exactly `14 | 18` (`tx/dispatch/mod.rs:1543-1546`). An
   `xfrmi` emits a bare L3 packet. Worse, **the L2 parse runs BEFORE the
   ingress-set lookup** (`lib.rs:456-467` vs `:479`), so on a raw-L3 frame
   bytes `[12..14]` are the first two octets of the IP SOURCE address and
   an inner source of the form `8.0.x.x` reads as ethertype `0x0800`.
   The consequence then depends on whether that ifindex is in the ingress
   set, and BOTH branches are bad — see the correction note below for the
   exact arithmetic:

   - **not in the set** — the shifted parse's RESULT is discarded at the
     gate, but `drop_degraded_transit` on a shifted-parse FAILURE is
     reached *before* the gate, so the packet is `XDP_DROP`ped. A
     source-address-selected drop.
   - **in the set** — the gate passes and the garbage 5-tuple feeds
     binding and session lookup.

   Either way it is attacker-selectable by inner source address, not
   merely a miss.
2. **Queue collapse.** `planning.rs:792` computes
   `candidates.iter().map(|(_, rx)| *rx).min()` and `:827-828` builds a
   uniform `queue_count × interfaces` grid. There is **no per-interface
   queue count**, so an "ingress-only, 1-queue" binding is not expressible
   in the plan's data structure: admitting a 1-RX-queue `xfrmi` as a
   candidate collapses **every physical NIC to one queue and one worker**.
3. **Bind fragility.** A generic-XDP non-virtio interface gets
   `COPY_ONLY_BIND_FLAGS` — a **one**-element list (`bind.rs:189`) — and
   `alternate_bind_strategy` returns `None` for it (`bind.rs:437-444`), so
   exactly ONE bind attempt is made with no fallback (`bind.rs:179`). The
   shared-UMEM path is unreachable because `interface_driver_name` reads
   `/sys/class/net/<if>/device/driver` and an `xfrmi` has no `device`
   symlink. A failed bind leaves the slot out of the readiness report
   while Go has **already** placed the ifindex in the ingress map — the
   shim then takes `BINDING_MISSING` → `drop_degraded_transit`
   (`userspace-xdp/src/lib.rs:520`). That is a **black-holed tunnel**,
   not a degraded one.
4. **No egress.** `resolve_tx_binding_ifindex`
   (`tx/dispatch/shared_recycle.rs:189-206`) falls through to
   `.unwrap_or(egress_ifindex)` — the unbound tunnel ifindex — and the
   dispatcher's no-target-binding arm records `missing_egress_binding` and
   calls `recycle_ingress_frame` (`tx/dispatch/mod.rs:759-778`): a silent
   drop. Adjudicating ingress without also building egress converts
   today's *unadjudicated-but-forwarded* plaintext into *dropped*
   plaintext.

**The in-repo precedent cited for B1 does not transfer.** #6700 and
`plan-r1.md` both point at the fabric IPVLAN parent as the worked example
of a generic-XDP 1-queue attach. It is `IPVLAN_MODE_L2`
(`pkg/daemon/daemon_ha_fabric.go:57-63`), so it carries full Ethernet
frames and is not a raw-L3 precedent; the AF_XDP binding is on the
**physical virtio parent**, not the IPVLAN child (which is itself excluded
by the `"fab name"` class); and a `virtio_net` parent takes
`AUTO_BIND_FLAGS`, not the `COPY_ONLY` arm. The `COPY_ONLY` arm is
untested on any shipped topology.

#### B2 — a bounded kernel → userspace capture bridge: the only surviving option, and unpriced

This is where the issue's invariant 1 genuinely belongs. It is real work:
there is no read-back path today. `slowpath.rs` is **write-only** — a
channel-fed worker thread that writes to the TUN, with no reader.

Both sub-options are additionally gated by a **sequencing constraint** that
neither plan costed: `pkg/daemon/daemon_transit_gate.go` (#5275) documents
this bypass as **load-bearing** — it never lowers `ip_forward` while armed
precisely because *"some ARMED paths DO XDP_PASS to the kernel and rely on
it — the route-based-VPN plaintext leaving an xfrm interface"*. Closing
the bypass without first providing a policy-authoritative return path
breaks forwarding that works today.

### Option E — a bounded packet-bearing `WorkerCommand` + an owned-frame adjudication entry point (the issue's LITERAL ask; REJECTED as unnecessary for WireGuard)

This is what the issue asks for in invariant 1, and it is worth pricing
because the price is the argument against it, not against its feasibility.

**It is feasible, and cheaper than the 5,806-line
`poll_binding_process_descriptor` suggests.** Measured at this HEAD: of the
78 code uses of the RX descriptor in that function, only **3** read packet
bytes out of the UMEM — and all three already have `_from_frame` twins in
the tree, one of which the function itself already calls. 44 are
recycle bookkeeping and 25 are `desc.len` used as a byte counter. Of the 8
`area` uses, 3 read bytes and one reads the shim's out-of-band metadata
from UMEM headroom.

**And the owned-frame path is already proven in production.** After the
native-GRE substitution at `stage_native_gre_decap`, the pipeline runs on
`packet_frame` (owned-or-raw) at **51** sites versus **2** ungated
`raw_frame` reaches, and each of the three descriptor-hard paths carries an
explicit `owned_packet_frame.is_none()` / `.is_some()` guard that predates
this question: the in-place UMEM rewrite (`flow_cache_hit.rs`), neighbor
learning (`stage_parse_flow_and_learn`'s `learn_from_live_frame`), and
pending-neighbor buffering. The TX side already carries
`PendingForwardFrame::Owned`. So an owned `Vec<u8>` survives screen → flow
cache → session → route → policy → NAT → filters → host-inbound →
disposition → TX **today**.

The residual cost is nonetheless real, and it is three things, not one:

1. `binding.xsk.rx.receive` is the loop DRIVER, so an owned entry point
   means extracting the loop BODY into `adjudicate_one(frame, meta, …)` —
   with `binding: &mut BindingWorker` threaded through 17 distinct fields
   that would each need a disjoint borrow or a second binding owner.
2. `PendingForwardRequest.desc` is a non-`Option` `XdpDesc`, and TX
   dispatch unconditionally computes `source_offset = request.desc.addr`
   and calls `recycle_ingress_frame`. An owned frame with no UMEM slot
   needs that field to become optional.
3. **A semantic change nothing would flag:** all 25 byte counters use
   `desc.len`, i.e. the OUTER length. An owned entry point has no outer
   length and would meter at `frame.len()` — a visible change to every
   policy, disposition and NAT counter, on a path where the old and new
   numbers are both plausible.

**Why it is rejected for WireGuard anyway:** Option A needs none of it.
A WireGuard transport-data record claimed by the worker arrives as an
ordinary AF_XDP descriptor on an ordinary binding, and its decap
substitutes an owned frame at exactly the substitution point native GRE
already uses. No new entry point, no `PendingForwardRequest` change, no
counter-semantics change, and the outer length stays available so the byte
counters keep meaning what they mean today.

Option E therefore belongs to **Option B2** (the IPsec capture bridge),
where there genuinely is no descriptor and no worker to receive one — which
is the second, independent reason not to build it as a shared abstraction
in the WireGuard half.

### Option C — a policy gate in the WireGuard control thread (REJECTED, on mechanism)

Evaluate zone policy on the decapped inner packet in the control thread,
just before the TUN write; drop on deny, write on permit.

**This does not work, and the reason is measurable rather than
aesthetic.** Policy evaluation needs a **to-zone**, which comes from the
FIB resolution of the inner destination. The control thread has no
`ForwardingState` at all — `wg_control_loop`
(`coordinator/wg_control/mod.rs:118`) receives a tunnel name, an endpoint
id, an `Arc<WgEngine>`, a port, MTUs, endpoint hosts, resolver telemetry,
an exception ring and a stop flag, and nothing else. With no FIB it can
only pass to-zone 0, and #3110 makes zone 0 ineligible for **every** rule
tier including the wildcard, so the evaluation falls through to the
default action for every packet. The result is not a policy gate; it is a
global on/off switch that **drops every tunnel packet on a deny-all box**
and **changes nothing on a permit-all box**.

Giving the control thread a FIB to fix that is re-implementing the
forwarding pipeline on a second thread, which is the thing the issue
already forbids ("xpf does not re-implement inner routing or policy").

### Option D — an nftables `hook forward` chain (REJECTED, by the issue, correctly)

Restated only because it is the thing a reader reaches for first: it puts
security authority in a second engine that does not share xpf's zones,
sessions, NAT or screen, and it would have to be kept in agreement with
the compiled policy forever.

---

## 2a. An incidental finding, filed separately

The descriptor-weld measurement turned up a defect that is **not** #7167
and is live today on the native-GRE decap path.

At two sites in `poll_binding_process_descriptor`, the CLASSIFICATION reads
the decapped inner frame while the HELPER is handed the un-decapped outer
one:

- the NAT64 ICMP-error arm classifies on `packet_frame` and then calls
  `try_translate_nat64_icmp_error(desc, raw_frame, meta, …)`;
- the embedded-ICMP reversal arm classifies on `packet_frame` (its own
  comment says *"read the INNER ICMP type from `packet_frame` (decapped
  post native-GRE, else `raw_frame`)"*) and then calls
  `try_reverse_embedded_icmp_error(&*area, desc, raw_frame, meta, …)`,
  which in turn calls `try_embedded_icmp_nat_match(area, desc, meta, …)` —
  slicing the OUTER UMEM frame and parsing it at INNER offsets.

That is the same outer/inner pairing hazard #1885 and #1902 each fixed at a
sibling site, and both of those fixes left a comment in this very function
stating the rule: *"`desc` still references the un-decapped OUTER UMEM
frame while `meta`/the decision describe the synthetic INNER frame."* Two
arms were fixed; these two were not.

It is recorded here because any owned-frame ingress mechanism lands on the
same two sites, but it is a pre-existing GRE defect with its own
fail-on-revert test to design and is filed on its own.

## 3. The decision

1. **Split the work by protocol.** #7167 stays open as the umbrella for the
   *consequence*, but the two halves are independent builds and may proceed
   in parallel. Nothing is solved twice: the only shared code is #8062's
   primitive, which is already in the tree and which both halves call.
2. **WireGuard is fixed by Option A** — move type-4 decap into the worker,
   making the decap direction symmetric with the encap direction that is
   already there. It is the cheaper half, it needs no new packet-bearing
   `WorkerCommand`, and it converges on the GRE model the issue names as
   the target.
3. **IPsec is Option B2, because B1 is refuted.** The xfrmi-binding
   sub-option fails on four independent grounds at this HEAD (framing,
   queue collapse, single-attempt bind with a black-holing failure mode,
   and no egress), and its cited in-repo precedent is an L2 IPVLAN on a
   physical virtio parent, which is not a precedent for either raw-L3
   framing or the copy-only bind arm. That leaves the bounded
   kernel → userspace capture bridge as the only surviving mechanism, and
   it is **unpriced** — there is no read-back path today, and #5275's
   transit gate makes the current bypass load-bearing, so the bridge must
   be built and proven BEFORE the bypass can be closed.
4. **Do not build a bounded cross-thread packet handoff (Option E) for
   WireGuard.** It is the most expensive thing the issue asks for; the
   WireGuard half does not need it because a worker-claimed data record is
   an ordinary descriptor and its decap reuses the owned-frame
   substitution point native GRE already proves; and building it in the
   WireGuard half in order to share it with IPsec would couple the cheap
   half to the blocked half. Option E is IPsec's (B2's) cost, and it should
   be priced there.
5. **Do not admit a tunnel netdev to the ingress set as a first step —
   and note that ONE ALREADY IS.** Both planners place the ifindex in the
   ingress map before any binding exists, and the shim's
   `BINDING_MISSING` arm then takes `drop_degraded_transit`. So
   "un-exclude the interface and see what breaks" is not an exploratory
   step — it is a black-holed tunnel. This is also why the exclusion arms
   must not be deleted to make room for a fix: `Tunnel` and
   `SecureTunnel` are two of eight classes sharing one predicate, and
   removing either un-excludes only by removing the fail-closed behaviour
   that currently keeps the tunnel alive.

   **This point was written as forward-looking advice and it is already
   violated** — see the correction note below. The BASE row of a
   canonically-spelled WireGuard tunnel is admitted today.

### What this decision does NOT claim

- It does not claim Option A is small. It is a shim change plus a worker
  stage plus a roaming-attribution design, and it owes a cluster smoke.
- It does not claim the roaming question is answered. It is the one place
  Option A needs new cross-thread plumbing and it is unresolved here.
- It does not claim the replay-window contention is acceptable. It claims
  RSS makes it *probably* single-writer per session and that the exception
  (a roaming peer changing source port) is a **measurement**, not a
  reading.
- It says nothing about `#7949` (whether a `bind-interface`-only tunnel
  should acquire an interface snapshot row). That question belongs to
  whichever IPsec capture mechanism wins.

---

## 4. The next PR, scoped

**WireGuard, step 2** (step 1 was #8062):

> Teach the XDP shim to steer WireGuard **handshake/cookie** records
> (message types 1, 2, 3) to the kernel and leave **transport-data**
> records (type 4) to the userspace worker, behind the existing
> `USERSPACE_CTRL_FLAG_WG_RX` gate, with no worker-side decap yet.

Deliberately inert on its own — and that is the point of the split: the
shim change is the piece that needs `make generate`, the pinned toolchain,
the kernel-verifier gate and a live-NIC smoke, and it should not be
reviewed in the same PR as the decap semantics. Until step 3 lands, a
type-4 record that reaches userspace with no worker-side decap must take
the **existing** local-delivery/kernel path so the tunnel keeps working —
which makes this step measurable (the shim's type classification) without
being a behaviour change.

Acceptance for step 2:

- A type-4 record and a type-1 record with identical 5-tuples classify
  DIFFERENTLY. A test whose fixture varies only the payload's first byte,
  because a fixture that varies the 5-tuple would pass on the pre-existing
  port match and prove nothing.
- A truncated UDP payload (no readable type byte) classifies as
  **kernel-steered** — the pre-#7167 behaviour — never as worker-claimed.
- The `is_local_destination` guard is unchanged and still mandatory: a
  port-only match would shunt transit/DNAT UDP on the WireGuard port, and
  that is a separate, worse bug (the guard's own comment says so).

**Step 3** is the worker decap stage + the roaming report. **Step 4** is
the IPsec capture measurement (B1's reachability on real hardware), which
does not depend on steps 2–3.

### 4.0 Step 3 as BUILT (#8274) — the step that moves packets

Landed. `try_wg_decap_from_frame` (`userspace-dp/src/afxdp/wg/decap.rs`) runs
as stage 6b of `poll_binding_process_descriptor`, immediately after native GRE
decap and guarded on `owned_packet_frame.is_none()`; the shim's
`wg_worker_claims_record` stops handing type-4 records to the kernel so the
stage is reachable. The two edits are one change — either alone is broken.

The inner packet is rebound through `build_logical_ingress_packet` with the
TUNNEL's `logical_ifindex`, which is what satisfies **invariant 2** of this
document for WireGuard: the inner flow is adjudicated in the tunnel's zone, not
the underlay's. Generations are INHERITED from the RX meta (**invariant 5**);
fabricating them would make every packet look current and silently defeat
attachment fencing. Both are pinned by mutation-killed cells — see
`docs/log/8274.md` for the table of which mutation killed which cell.

Two limits on the claim, so this section is not read as more than it is:

- The control thread's plaintext TUN write is UNCHANGED. It is unreachable for
  type-4 on any shim-covered ingress, and it remains the only path on an
  ingress the shim does not cover. The adjudication gap is closed on the
  measured path and open on an unmeasured one.
- Host-inbound over a WireGuard tunnel still reaches the local stack via that
  TUN write. GRE has a `local_tunnel_deliveries` seam for this; WireGuard does
  not, and building one is separate work.

> **Later changes to those limits (#9521, #9594, #9251).** The control
> thread's TUN write is no longer made for every listen port: since #9521 a
> kernel-path transport record for any port other than the steered one is
> dropped (`rx_unsteered_transport_drops`). For the steered port, the
> uncovered-ingress path above had a second way onto the same write — a
> degraded dataplane on COVERED ingress (helper start, redundancy-group
> transition, reth link cycle, stale heartbeat). #9594 closed that one for
> transit: the thread learns the record's ingress from `IP_PKTINFO` and, on an
> ingress the shim adjudicates, delivers only traffic addressed to the firewall
> (`rx_degraded_transit_drops`). #9251
> rewrote the #5618 commit advisory to state that split instead of the
> pre-#8274 "zone not enforced" account. The host-inbound bullet above is as
> #8274 wrote it and was not re-verified by those changes.

### 4.1 Step 2 as BUILT (#8274), and two things it corrected

Landed. The classification lives in `userspace-xdp/src/wg_classify.rs`, a
`core`-only module the shim calls and
`userspace-dp/src/afxdp/frame/tests_shim_wg_classify_8274.rs`
`#[path]`-includes and EXECUTES — the `ipv6_ext_walk` shape, adopted for the
reason that file's own comment gives: five successive source-text models of a
shim property each leaked, the worst accepting the deletion of a security
property.

**The type byte is captured in `parse_l4`, not at the steer site**, and that
was forced by the verifier rather than chosen. Reading it at
`pkt.payload_offset` inside `wg_steer_to_kernel` was rejected —
`invalid access to packet, off=0 size=1, R8 offset is outside of the packet` —
because that offset arrives through a `ParsedPacket` field with a wide
`var_off`. It was rejected identically with a hand-rolled deref and with the
shim's own `read_bytes`, and the documented narrowing mask did not fix it
either. Reading at the same freshly-validated `l4_offset` the mandatory
8-byte UDP header read already uses does verify, because a 9-byte read there
is a shape the verifier already accepts.

**`ParsedPacket` carries a `bool`, not the byte**, and that was also forced.
Widening the struct by a `u16` relocated an UNRELATED packet read into a BPF
subprogram and the verifier rejected the object at a 1-byte load dominated by
a 4-byte check (`frame1`, offset reloaded from the stack). The failing site
was not the new read at all. A `bool` lands in existing padding.

**Cost, stated because it is spent from a shared budget**: verifier headroom
falls from 31.38% (686,201 insns) to 23.20% (768,026), against a 15.0% floor —
81,974 insns of slack remain. Master's baseline was re-measured in a throwaway
worktree at its own head rather than carried over from before the merge. Runtime cost is approximately nil: the common
UDP path now does ONE 9-byte read where it did one 8-byte read, and the
8-byte fallback runs only for a zero-length payload.

**Inertness, argued rather than assumed** (the issue's comment asks for it to
be measured). For exactly the packet set the WireGuard arm matched, a type-4
record now falls through to the session-miss path and is matched by the SAME
`is_local_destination` predicate a few arms down, returning the SAME
`cpumap_or_pass(ctrl)`. `native_gre` cannot divert it (that gate requires
`protocol == PROTO_GRE`; a WireGuard record is UDP). `should_fallback_early`
and the NDP arm end at the kernel too. The ONE divergent outcome is
`USERSPACE_SESSION_ACTION_REDIRECT`, and nothing installs a session on the
outer 5-tuple: the outer UDP header is synthesized at frame-build time by
`wg_encap_frame` under the INNER flow's session, and the inbound direction
still reaches the kernel without the worker adjudicating it. The live
`wg-interop.sh` smoke is what measures the conclusion.

**What a host test CANNOT bind here, said plainly.** The cells execute the
classification module and four mutations kill them selectively, but nothing a
host test can express binds the shim's CALL SITE: if `wg_steer_to_kernel`
stopped calling `wg_classify`, every cell would stay green. The shim is not
executable off-target, and emitting a fact about the constant would be a claim
written into inert code rather than a binding. The live-NIC smoke is the only
thing that binds the wiring, which is why step 2 owes one.


---

## 5. CORRECTION (filed as #8279): a raw-L3 TUN is ALREADY in the ingress set

Two things in this document need correcting, and the second changes a
recommendation rather than a wording. Recorded here rather than silently
edited above, because the reasoning that produced the error is worth
keeping: **§2 Option B ground 1 was written about a HYPOTHETICAL
interface B1 would introduce, and the parse ordering it relies on is a
property of the CURRENT code.** Asking "is that ground live today?" is
what found this.

### 5.1 The consequence of the misparse depends on the ingress-set gate

Ground 1 originally said the shim "parses an IPv4 header 14 bytes into
the real one … an attacker-selectable misparse". True, but incomplete
about what the misparse then DOES, and the two branches differ:

`try_xdp_userspace` runs `parse_l2` -> `parse_ipv4`/`parse_ipv6` ->
`let Some(parsed) = parsed else { drop_degraded_transit(...) }` -> and
only THEN the `USERSPACE_INGRESS_IFACES` test. `drop_degraded_transit` is
`Ok(xdp_action::XDP_DROP)`.

On a raw IPv4 packet, bytes `[12..14]` are `src[0..2]`, so a source in
`8.0.0.0/16` yields `eth_proto == 0x0800`; `parse_ipv4` then reads
`iph[0] = src[2]` and returns `None` unless `src[2] >> 4 == 4` and
`src[2] & 0x0f >= 5`. So for 241 of 256 values of `src[2]` the packet is
**dropped before the gate**, and for `0x45`-`0x4f` a garbage `parsed`
survives to the gate. `8.0.0.0/16` is allocated, routable space. The IPv6
twin needs a source beginning `86dd:`, in reserved `8000::/1`.

### 5.2 The WireGuard base row is admitted — recommendation 5 is already violated

- `interfaces.go:371` sets the BASE row's flag as `Tunnel: iface.Tunnel != nil`
  — **interface-level only**. The UNIT row at `:446` is the OR.
- The zone fans UP from unit to base
  (`pkg/config/host_inbound_effective_view.go`).
- So `set interfaces wgN unit 0 tunnel mode wireguard` — the spelling this
  repo calls canonical — yields a base row with `Tunnel = false` and a
  Zone, matching no exclusion class.
- And that netdev is raw L3: on a userspace-dataplane box every tunnel is
  an anchor TUN (`daemon_run_routehelpers.go:63` `anchorOnly`, applied to
  the unit-level tunnel at `:106`; `routing/tunnel.go:503-512` creates
  `netlink.Tuntap{Mode: TUNTAP_MODE_TUN}` = ARPHRD_NONE).

This is pinned green at HEAD by
`TestRefusedNetdevNeedsEveryOwnerToAgree/canonical_wireguard_spelling`
(`secure_tunnel_parent_redirect_6691_test.go`), which asserts
`wantIngress: []uint32{10, 40}` and `wantRSS: [ge-0-0-0 wg1408]` where 40
is the WireGuard TUN. The #6691 round-9 unanimity rule
(`ingress_exclusions.go:578-580`) was introduced specifically to re-admit
it, so this is long-standing and deliberate, not a regression.

**It also corrects a premise #5618 and #7167 both carry** — that `wgN`
rows are `Tunnel=true` and therefore excluded. That holds for the
interface-level spelling and for the UNIT row. It does not hold for the
base row under the canonical spelling.

### 5.3 What this does NOT change

The four grounds refuting B1 all still stand; ground 1's mechanism is
sharper, not weaker. Options A, C and E are untouched: none of them
turned on this. What changes is that "admit a tunnel netdev" is not a
hypothetical hazard to avoid but a state to be **audited and decided**,
and #8279 carries that.

**Not yet verified, and it is the reachability hinge:** whether on a live
box the XDP attach on a TUN succeeds, whether XDP runs on packets
userspace WRITES into a TUN, and whether the AF_XDP binding on it
succeeds or leaves the slot absent (which would take `BINDING_MISSING` ->
`drop_degraded_transit`, a broader drop than the source-selected one).
All three need hardware; the arithmetic above is from the source.

**A fourth hardware-gated item, from #8276's B2 pricing.** The in-process
half of the capture bridge is measured and committed
(`userspace-dp/benches/b2_capture_bridge.rs`, #8545). Against the
2,797 ns/packet budget derived from #5275's appliance measurement
(4.29 Gbit/s v4 = 357,500 pps), a 1500-byte copy costs 25.4 ns (0.9%), a
same-thread queue handoff 111 ns (4.0%), and a **cross-thread round trip
12,648 ns — 452% of budget**. So Option E *as a per-packet cross-thread
mechanism* is priced OUT: one-way it is ~2.3x the whole budget before the
capture syscall, before adjudication, before re-inject. What survives is
same-thread adjudication, or a batched handoff at **B >= 3** frames per
wake.

What is NOT priced, and cannot be inferred from a userspace channel
benchmark, is the **kernel half** — an nfqueue round trip, or an
AF_PACKET read plus an authoritative re-inject. For the two shapes that
survive, that is the dominant unknown and it decides B2. It needs a box
where XFRM SAs and netfilter can be driven against real traffic — the
same hardware the three items above are waiting on.

Two caveats that must travel with those numbers. The ns figures are from a
dev box while the pps budget is an appliance measurement, so the 2.3x is
an order-of-magnitude indication, not a verdict; one run of
`cargo bench --bench b2_capture_bridge` on the loss userspace cluster
converts it, and the instrument is already committed. And the pooled-slot
row must not be read as "allocation is free" — that shape takes an extra
per-slot mutex the owned shape does not, so the near-equality is not a
clean isolation of allocation cost.
