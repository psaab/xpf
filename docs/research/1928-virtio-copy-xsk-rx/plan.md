# #1928 — virtio_net AF_XDP copy-mode XSK RX delivery gap: plan of action

**Status:** DRAFT v2 — Phase-0 live probe DONE (results below); pending review.

## Phase 0 RESULTS (live, t1921-fw 4-queue virtio, dedup+probe binary)

Ran the Path-1 probe (virtio native → `EXPLICIT_MODE_BIND_FLAGS=[ZC, COPY]`):
- **virtio REJECTS zero-copy**: the ZC bind returns `libxdp private
  bind(flags=0x000c): Invalid argument` on every queue → falls back to copy.
  **Path 1 (ZC) is OUT for virtio_net on this venue/kernel.** (RX-ZC may exist
  upstream ~6.11+, but this virtio backend does not negotiate it.)
- **`AUTO_BIND_FLAGS=[0]` vs explicit `XSK_BIND_FLAGS_COPY` behave
  DIFFERENTLY**: with AUTO (the current code) the dataplane forwarded NOTHING
  (0 sessions, 0 tx_completions). After the probe (which falls back to explicit
  `XSK_BIND_FLAGS_COPY`), the dataplane began forwarding *some* traffic —
  sessions + `tx_completions_total` went nonzero. So the bind flag is genuinely
  load-bearing: **virtio needs the explicit COPY flag, not flags=0.**
- **v4 transit still fails** (0%, SNAT hits=0, no v4 transit session) even with
  explicit copy, while v6 transit improved. So there is a SECOND v4-specific
  layer beyond the bind flag (SNAT and/or dataplane ARP resolution for the WAN
  next-hop — resolver `get_attempts` stayed 0, which is itself suspicious).

**Revised lead = Path 2-variant:** virtio native should bind with explicit
`XSK_BIND_FLAGS_COPY` (not `AUTO_BIND_FLAGS`); keep generic/fabric virtio on
AUTO via the `interface_uses_generic_xdp` guard. THEN investigate the residual
v4-transit-specific failure (SNAT / dataplane neighbor resolution). The
forwarding signal calibrated against the working mlx5 cluster is
**sessions + `tx_completions_total`** (NOT `rx_packets_total`, which is 0 even
when forwarding works). NOTE: the live picture is still partly murky (v6 6/6
ping but only a v4 wan-local session visible) — Phase-0 needs a cleaner pass
isolating dataplane-vs-kernel per family before committing the exact fix.

---

(original v1 framing below)


## 1. Issue framing

On virtio_net (native XDP), after the #1921 binding fixes (PR #1927) the shim
redirects packets to the XSKMAP — `ethtool -S` shows `rx_xdp_redirects`
climbing on all queues — but they never reach the userspace sockets:
`xpf_userspace_binding_rx_packets_total` stays 0, 0 transit sessions, 0 SNAT
hits, no drop counters. Every bind is **Copy mode**. End-to-end transit
forwarding on virtio is therefore still dead. mlx5 VFs (loss cluster,
**zero-copy**) are unaffected.

## 2. Honest scope/value framing

This is the *actual* remaining blocker for the #1879 appliance to forward on
virtio (bridges/virtio is the most portable backing). #1921's fixes are
necessary (clean binding, redirects happen) but insufficient without this.
*If reviewers conclude virtio copy-mode AF_XDP RX simply cannot deliver
reliably and ZC is unavailable, "document virtio as control-plane/mgmt-only,
require mlx5-VF/i40e-PF for the dataplane" is an acceptable PLAN-KILL outcome.*

## 3. Diagnosis (live-observed, to be confirmed)

`XDP_REDIRECT` into the XSKMAP succeeds at the XDP layer (counted in
`rx_xdp_redirects`) but the frame is dropped before delivery to userspace — the
signature of an **unfed FILL ring in copy mode**: in copy mode the kernel needs
a UMEM fill-ring buffer to copy the frame into; with none available the
redirected frame is dropped after the redirect counter bumps.

Why copy mode at all: `bind_flag_candidates_for_driver`
(`userspace-dp/src/afxdp/bind.rs:194`) returns `AUTO_BIND_FLAGS=[0]`
(auto-mode) for `virtio_net`, vs `[XSK_BIND_FLAGS_ZEROCOPY, XSK_BIND_FLAGS_COPY]`
for other drivers. Auto-mode (flags=0) let the kernel pick — it chose **copy**.
virtio_net RX zero-copy has existed since ~6.11 (appliance kernel is 7.0), so ZC
*should* be negotiable but is never requested. So there are two candidate roots,
not mutually exclusive:
- (R-A) virtio never *asks* for ZC → gets copy → the copy-mode fill-ring path is
  the one that must work, and it doesn't.
- (R-B) the copy-mode fill ring is primed once post-bind
  (`prime_fill_ring_offsets`, `bind.rs`) but not continuously refilled / NAPI
  not driven for virtio copy RX, so it empties and stays empty.

Phase 0 must confirm which (kernel `xdp_statistics.rx_fill_ring_empty_descs`
per binding — already surfaced at `worker/loop_body/mod.rs:962` — and whether a
ZC bind on virtio 7.0 negotiates and then delivers).

## 4. What's relevant / already there

- `EXPLICIT_MODE_BIND_FLAGS=[ZEROCOPY, COPY]` already exists and is used for
  non-virtio drivers (`bind.rs:7`): try ZC, fall back to copy. virtio is the
  only driver special-cased to AUTO.
- `query_bound_xsk_mode` (`bind.rs:443`) reports the negotiated mode;
  `XskBindMode`/`is_zerocopy` already branch the TX path (`tx/rings.rs:238`).
- `rx_fill_ring_empty_descs` per-binding kernel stat is already collected
  (`worker/loop_body/mod.rs:962`) — the direct instrument for R-B.
- `prime_fill_ring_offsets` (`bind.rs`) primes the fill ring post-bind and
  drives NAPI via recvmsg/poll/sendto.

## 5. Path options

### Path 1 (likely primary) — let virtio negotiate ZERO-COPY
Stop special-casing `virtio_net` to `AUTO_BIND_FLAGS`; use
`EXPLICIT_MODE_BIND_FLAGS=[ZEROCOPY, COPY]` (or a virtio-native variant) so the
bind tries ZC first and falls back to copy. If virtio 7.0 negotiates ZC, the
proven ZC fill-ring/NAPI path (same as mlx5) delivers packets. Smallest change;
contingent on virtio ZC actually negotiating + delivering (Phase 0).
Risk: generic-XDP virtio (fabric parent, xdpgeneric) must STAY copy/auto — ZC is
only for native; keep the `interface_uses_generic_xdp` guard.

### Path 2 — make copy-mode RX delivery actually work
If virtio won't do ZC (or ZC is unavailable on the target kernel), fix the
copy-mode path: continuously refill the fill ring from the worker RX loop for
copy-mode bindings, and ensure NAPI is driven (copy-mode RX on virtio needs the
fill ring kept non-empty). Larger, copy-mode-specific.

### Path 3 — both: prefer ZC, and make copy fallback correct
ZC where available; a correct copy fallback for kernels/drivers without ZC.
Most robust, most work.

### Recommendation
Phase 0 first (cheap): on the virtio venue, (a) force a ZC bind and check it
negotiates + delivers (rx_packets>0); (b) read `rx_fill_ring_empty_descs` in the
current copy-mode run. If (a) works → **Path 1**. If ZC unavailable but (b)
shows an empty fill ring → **Path 2**. Don't pre-commit.

## 6. API / interface preservation
No wire/protocol change expected; bind-flag selection is internal to the helper.
`XskBindMode` reporting already exists. Confirm no Go-side assumption that virtio
is always copy.

## 7. Hidden invariants
- Generic-XDP interfaces (fabric parent, xdpgeneric) must NOT request ZC
  (unsupported) — keep `interface_uses_generic_xdp` → copy/auto.
- mlx5/i40e behavior unchanged (they already try ZC).
- Copy fallback must still function for drivers/kernels without ZC.
- The TX path's `is_zerocopy` branch must be correct for a virtio ZC bind.

## 8. Risk assessment
| Class | Level | Notes |
|---|---|---|
| Behavioral regression | MED | bind-flag change affects virtio everywhere; generic-mode guard critical |
| Lifetime/borrow | LOW | flag-list selection + fill-ring refill |
| Perf | LOW (positive) | ZC is faster than copy |
| Architectural mismatch | LOW | ZC-first mirrors the existing non-virtio path |

## 9. Test plan
- **Phase 0**: virtio venue (t1921-fw, 4-queue) — force ZC bind, check negotiate
  + rx_packets>0; read rx_fill_ring_empty_descs in copy mode.
- **Fix validation (virtio)**: LAN→WAN v4+v6 ping + iperf3 + SNAT session install;
  rx_packets>0 on the flow's queue; sessions nonzero. Fix-iteration loop: stop
  xpfd → push helper → start.
- **mlx5 regression (loss)**: full failover + forwarding matrix — ZC behavior on
  mlx5 must be unchanged.
- Rust unit tests for the bind-flag selection (virtio native → ZC-first; virtio
  generic → copy).

## 10. Out of scope
- The #1921 binding/rebind fixes (PR #1927).
- Non-virtio drivers.

## 11. Open questions for adversarial review
1. Does virtio_net 7.0 actually negotiate XDP_ZEROCOPY when requested, and does
   it then deliver to userspace? (The crux — Phase 0.)
2. Is the copy-mode RX path genuinely broken in xpf (fill ring not refilled), or
   is it only ever exercised on virtio (so latent)?
3. [PARTIALLY RESOLVED] Why virtio→AUTO originally: git log shows the
   special-case came from `ddc27dcc4 "userspace: resolve virtio fabric AF_XDP
   bind"` + `d137e3ee5 "select XSK bind mode from XDP attach mode"` — i.e. it was
   for the virtio **fabric parent in generic (xdpgeneric) mode**, where AF_XDP is
   copy-only, and got applied to ALL virtio via `bind_flag_candidates_for_driver`
   including native-XDP virtio. No evidence of a deliberate native-virtio ZC
   hang. So Path 1 = scope ZC to NATIVE virtio (the `interface_uses_generic_xdp`
   guard already exists), keep generic/fabric virtio on copy/auto. Reviewers:
   confirm there's no other reason native virtio ZC was avoided.
4. Does ZC on virtio interact badly with the fabric IPVLAN parent (generic mode)?
5. Is "virtio = mgmt-only, require mlx5-VF/i40e-PF for dataplane" the honest
   answer if virtio copy-mode RX can't be made reliable and ZC is flaky?
