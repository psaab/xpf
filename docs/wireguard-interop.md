# WireGuard interop — status and validation

Tracking doc for the #1703 WireGuard interop umbrella (interop with kernel
WireGuard, UniFi Network 10.4+, EdgeOS/EdgeRouter, UDM/UDM-Pro — all of which
run reference-compliant kernel WireGuard).

WireGuard is a fixed protocol: a byte-compliant implementation interoperates
with any other compliant implementation regardless of vendor. The work is
therefore staged by capability, not by vendor.

## Status by stage

| Stage | Scope | State |
|-------|-------|-------|
| S1 (#1709) | Wire-protocol compliance: TAI64N + handshake framing (msg type 1/2, MAC1) on build + parse, both roles | **DONE (this PR)** — validated by spec known-answer vectors + an xpf↔xpf framed-handshake regression. **NOT yet validated against an independent peer** (see "honesty note" below). |
| S2 | Dataplane activation (AF_XDP hot-path encap/decap) **+ the live kernel-WireGuard-on-a-VM interop test** | pending |
| S4 | Non-zero pre-shared key (PSK) plumbing | **plumbing DONE (#1434 B2)** — per-peer `preshared-key` on `WgPeerConfig` (Go config + wire + engine `WgPeerConfig.preshared_key` + `Peer.preshared_key`), wired into both handshake builders: the initiator sets the peer's PSK at `build_initiator_handshake` time, the responder reads msg1, identifies the peer via `get_remote_static`, then `set_psk(2, …)` before `write_message(msg2)` (snow 0.10.0 mid-handshake API). Secret hygiene: `Secret`/`Zeroizing`/`skip_serializing` on every surface (config `String()`, wire DTO, runtime peer, status). #4103 F12: the engine-config CARRIERS `WgEngineConfig.local_private_key` and `WgPeerConfig.preshared_key` are now `Zeroizing<[u8; 32]>` too (they were plain `[u8; 32]` behind `#[derive(Clone)]`), so a cloned/dropped config built each WG commit no longer leaves a plaintext X25519 private key or PSK in freed heap/stack; the `forwarding_build/wg.rs` build sites clone the `Zeroizing` source instead of deref-copying to plaintext. Unit-tested (`per_peer_psk_handshake_roundtrip`, `wg_config_secret_carriers_are_zeroizing`); the LIVE kernel-WG PSK interop validation stays #1703. |
| #1434 | Multi-PEER per WG interface (N peers on one listen port) | **DONE (#1434 B1a+B1b)** — Go config `TunnelConfig.WgPeers []WgPeerConfig` (named-instance `peer <pubkey>` schema + dual-AST compiler + commit gate; the commit gate also validates the tunnel's LOCAL identity — `listen-port` in `[1,65535]` and a 64-hex `private-key` — so a value the Rust `hydrate_wg_identity` would drop the WHOLE row on can never commit clean into a silent dead tunnel, #3863), wire slice `wg_peers`, Rust engine fed N peers (RX/decap already multi-peer), egress generalized: encap LPM-selects the peer by inner-dst AllowedIPs (`frame/wg.rs` + `engine.peer_for_dest`), the WG control thread keeps per-peer effective-endpoint + per-peer handshake attempt + per-peer keepalive/rekey timers (`timer_pass_for_peer`), and per-peer status rows. The LIVE multi-peer handshake / Ubiquiti interop validation is #1703. KNOWN LIMITATION: the worker-driven NoSession/rekey REQUEST edges are still engine-wide (single edge), not per-peer — the per-peer T6/T7/T8 timers ARE per-peer; per-peer request edges ride #1703. |
| S5 | Persistent-keepalive + REKEY/REJECT-AFTER timers + endpoint roaming + empty-record (keepalive/key-confirm) handling + TAI64N disk persistence | **timers + keepalives DONE (#1888/#1889)** — full whitepaper §6.1 timer machine (REKEY_AFTER_TIME 120s initiator-only, 165s receive horizon, REJECT_AFTER_TIME 180s per-use + expiry teardown, 5s/90s retry discipline, 10s passive + configured persistent keepalives, post-msg2 key-confirmation keepalive) on a blocking-poll(2) control loop; design of record `docs/research/1888-wg-timers/plan.md`. Authenticated-datagram endpoint LEARNING shipped in S2a/#1888 (keepalives now count); engine-level roam API + TAI64N disk persistence remain pending. **#7230 correction — this row overstated keepalive learning for two years of commits.** "Keepalives now count" was true only on a SINGLE-peer interface. `try_decap` returned the zero-length keepalive as `MalformedInner`, which discarded the peer identity, and the caller recovered it with `single_peer_pubkey()` — `None` on any multi-peer tunnel. So a peer whose only traffic is keepalives (a roaming client, or one behind a NAT that rebinds) did NOT roam its endpoint and was blackholed until its next handshake: bounded at roughly 120-180s, degraded rather than an outage. The comments in that path asserted the attribution was ambiguous; it was not — `try_decap` demuxes the session from `hdr.receiver_index` BEFORE any AEAD work, so the identity was in hand at the moment the error was built and was simply thrown away with it. #7230 adds `DecapError::Keepalive(peer_pubkey)`, so keepalive endpoint learning now holds on **any** interface, multi-peer included. **#7686 closes the residue this row named.** A MALFORMED-but-authenticated inner packet had the same discard one variant over: it reached the caller without a peer and fell back to `single_peer_pubkey()`, so on a multi-peer interface it roamed nothing. `DecapError::MalformedInner` now carries the peer pubkey, from both post-AEAD construction sites (the inner-source-IP parse and the inner-length parse), which have the session in hand for the same reason the keepalive arm does. It stays an ERROR and still counts as a malformed-inner DROP — carrying the identity does not make it deliverable, and the "no TUN write" contract is unchanged. With that, `single_peer_pubkey()` had no production caller and was DELETED: it was the mechanism by which a discarded identity got guessed, and removing it means the class cannot recur through that path. Endpoint learning for authenticated datagrams now holds on any interface for both the keepalive and malformed-inner arms. **#9018 correction — that sentence was true of the SOCKET path and was hollowed by #8274 step 3, which nothing re-checked.** Step 3 moved transport-data decap into the AF_XDP worker, and the worker collapsed every `try_decap` error with `.ok()?` — including the two arms #7230 and #7686 had just given a peer identity to. The socket path in `wg_control/dispatch.rs` still mapped both to `InboundOutcome::Authenticated(pk)` correctly, but it no longer SEES these records: a keepalive is a type-4 transport record, so `wg_worker_claims_record` claims it for the worker and the shim declines `cpumap_or_pass`. So the identical blackhole this row describes came back on the worker path, with the same bound (the peer's next handshake — types 1/2/3 are still steered to the kernel by `wg_steer_to_kernel_on_port_match`, and `REJECT_AFTER_TIME` is 180s, so roughly 120-180s, degraded rather than an outage). The worker now matches both arms and calls the same `note_worker_observed_endpoint` the success arm uses, then declines the frame exactly as before — an authenticated record with nothing to deliver may roam a peer, and an unauthenticated one must never do so. #2961: the handshake attempt machine's GIVE-UP branch (`drive_attempt_machine`, after the 90s `REKEY_ATTEMPT_TIME` window) now advances the T8 pacing anchor (`note_t8_attempt(now)`), so a permanently-unreachable persistent-keepalive peer waits a full keepalive interval before the next `KeepaliveNoSession` initiation instead of re-firing a fresh 90s window every ~1s tick — the gap between failed-handshake windows is now ≥ keepalive_interval (matching wireguard-go, which stops re-initiating after `REKEY_ATTEMPT_TIME` until a new send/keepalive is due). A peer that comes back to life re-anchors T8 on fresh authenticated traffic (`anchor = max(last_send_any, last_recv_any, t8_last_attempt)`), so the cooldown is a floor, not a penalty on the live/successful path. #4546: REJECT_AFTER_TIME is now honored CONSISTENTLY across all four session-liveness sites — `try_encap`'s T3 encrypt gate, `expire_sessions`' ~1s GC teardown, `peer_has_usable_session` (keepalive emission), AND `peer_has_confirmed_session` (the NoSession-edge rekey gate the control loop consults). Previously the last was age-blind: a confirmed session aged past 180s but not yet GC'd still reported `confirmed`, so the `wg_control::drive_attempt_machine` NoSession-edge rekey was SKIPPED until the next GC tick — a bounded ~0-1s rekey blackhole at the expiry boundary. The gate now reads the same mock-aware `now_ns()` clock and returns false for an expired session so the rekey fires promptly; `session_confirmed` in the per-peer status row (`coordinator/status.rs`) inherits the same non-stale semantics |
| S6 | Junos config surface (grammar + compiler + snapshot population, base64↔hex keys) | pending |
| S7 | Type-3 CookieReply + MAC2 generation/verification + IPv6 outer encap + DSCP/ECN | **DSCP/ECN encap DONE (#2303 transit, #7758 host-originated)** — inner DSCP+ECN copied onto the outer header (uniform DSCP + RFC 6040 ECN ingress copy). This row read simply "DONE (#2303)" until #7758 and was half true: #2303 wired the TRANSIT encap path only, and the host-originated path (inner read from the wgN TUN) still sent an unmarked outer, so the outer DSCP depended on which of the two WG encap paths a packet took. RFC 6040 §4.2 decap-side ECN *combine* shipped for GRE (#2315) AND WG (#2317) — WG captures the outer ECN via `recvmsg` + `IP_RECVTOS`/`IPV6_RECVTCLASS` cmsg and folds it into the decrypted inner via the shared `apply_decap_ecn_combine` (live ECN-propagation verification lab-deferred to #1703-class interop). **RESPONDER CookieReply + MAC2 under-load DoS mitigation DONE (#4094 PR-A)** — a per-tunnel rotating secret `Rm` (120 s, one-window previous-secret carry), an inbound-initiation fixed-window load gate, and MAC2 verification bind an initiation to the source that received the responder's type-3 CookieReply, so a valid-MAC1 flood (attacker knows our public key) no longer forces a Noise handshake per forged datagram. See "Responder cookie / MAC2 under-load DoS mitigation" below. **INITIATOR-side CookieReply *consume* DONE (#4094 PR-B)** — an inbound type-3 is decrypted (responder pubkey-derived key + our last-sent MAC1 as AAD), the cookie stored per-peer, and our NEXT initiation carries a real MAC2 (honoring the 120 s cookie TTL), so xpf-as-initiator now completes a handshake against a peer that is itself under load. IPv6 outer encap still pending |
| S8 | HA RG WG-session migration | pending |

## Config shape: interface-level tunnel with per-unit peers (#7786)

A WireGuard interface can be written two ways, and they are not the same
object.

- **Per-unit** — `set interfaces wgN unit U tunnel mode wireguard ...` with no
  interface-level `tunnel` stanza. This is the canonical spelling. Each unit
  emits its own tunnel endpoint with its own device, listen port, private key
  and peers.
- **Interface-level** — `set interfaces wgN tunnel mode wireguard ...`. This is
  **ONE persistent TUN and ONE local identity**: one kernel UDP socket, one
  private key (`TunnelConfig.WgListenPort` / `WgLocalPrivkeyHex` are
  tunnel-level; `WgPeers` is the per-peer set). The emitter produces exactly
  one endpoint for the whole interface, keyed by the lowest configured unit ref
  (#1910).

Under the **interface-level** form a unit may still carry its own `tunnel`
stanza, and what that means is now defined:

- **`peer` entries are additive.** Every unit's peers are merged into the
  interface's single endpoint, de-duplicated by public key and sorted by public
  key. A unit re-declaring an inherited peer is already refused at commit
  (`duplicate peer public key`), so a unit's peers are always the inherited set
  plus keys no other unit declares — the merge cannot conflict and needs no
  precedence rule.

  Before #7786 those peers were discarded. `pkg/dataplane/userspace/tunnels.go`
  builds the wire peer set from the emitted endpoint's `TunnelConfig`, and that
  is the only path config peers have to the dataplane, so a peer authored under
  a unit was parsed, deep-copied (#3898) and validated — and then silently
  never installed. The tunnel came up carrying only the interface-level peers.

- **`listen-port` and `private-key` overrides are refused at commit.** They ask
  for a second local identity on one logical interface, which the one-socket /
  one-identity model has no representation for. Merging such a unit would offer
  a *different* identity's peers the parent's key; emitting it as its own
  endpoint would put two endpoints on one listen port (two WireGuard tunnels
  sharing a listen port compile without complaint, and
  `WireGuardListenPorts()` de-duplicates them, so nothing would report it).
  Configure the second identity on its own interface.

  This shape was previously half-wired in a misleading direction: routing
  materialised the unit's TUN and `WireGuardListenPorts()` already collected
  the unit's port, so the host-inbound filter opened a port that no endpoint
  ever listened on.

### Which device the unit lives on (#6941)

A unit that stays on the interface's WireGuard mode **shares the interface
device**. It does not get a `wgNuU` device of its own.

That follows from the one-endpoint rule above: if the interface has exactly one
emitted endpoint, at most one device can ever carry its WireGuard traffic. A
per-unit device could therefore only ever hold the unit's *addresses*, with no
endpoint behind them — and address placement follows the same name, so whenever
the lowest configured unit was not the one carrying the tunnel stanza, the
WireGuard engine serving a unit's peers ran on one netdev while that unit's
address sat on another. Routing materialised the loser as an orphan.

This only became reachable when #7786 made per-unit peers actually install.
Before that they were discarded, so the orphan device referenced nothing.

A unit that **overrides** the mode (`tunnel mode gre` / `mode ipip` under a
WireGuard interface) keeps its own `wgNuU` device. It is a different kind of
tunnel, and `pkg/routing/tunnel.go` keys its desired set by `TunnelConfig.Name`
— sharing a name across two different *modes* would hand routing one device
with two conflicting records, rather than the benign same-name/same-mode
sharing that key already relies on.

## Tunnel MTU + MSS + DSCP/ECN model (#2299 / #2300 / #2303 / #2329)

These correctness fixes share the encap sites and the tunnel-MTU
model. They apply to BOTH WireGuard and (for DSCP/ECN) GRE.

### MSS clamp (#2299)
A WG-bound TCP SYN's MSS is clamped via the WireGuard overhead, not the
GRE formula. `forwarding::tunnel_tcp_mss` dispatches by endpoint mode:
`wireguard` → `wg::mss::wg_tcp_mss(outer_family, inner_family,
outer_mtu)` (accounts for outer IP + UDP(8) + WG data header(16) +
Poly1305 tag(16) + §5.4.6 padding(≤15)); everything else keeps
`native_gre_tcp_mss` bit-for-bit. Before #2299 a WG SYN was clamped with
the GRE value (~36–60 bytes too high), so the peer sent full-MSS data
segments that the WG encap MTU guard then silently dropped at
`encap_mtu_drops` — the classic "handshake + ping pass, bulk TCP stalls
at zero bytes" failure.

### TCP-segmentation egress is mode-aware on BOTH axes (#2329)
The fallback TCP-segmentation egress builder
(`frame/tcp_segmentation.rs::segment_forwarded_tcp_frames_from_frame`)
re-segments an oversized forwarded TCP flow when the sender ignores the
advertised MSS, the session predates the clamp, or a middlebox injects
larger segments. Before #2329 it was tunnel-mode-BLIND in two places —
both effectively hardcoded to GRE:

1. **Inner-L3 MTU math.** It sized every tunnel's segments with the GRE
   inner-MTU formula (`native_gre_inner_mtu`). For a WireGuard endpoint
   that budget is ~36–60 bytes too large, so the oversized WG-bound
   segments were built and then dropped at the WG encap MTU guard
   (`encap_mtu_drops`) — the same blackhole #2299 closed for the SYN
   path, re-opened for the segmentation fallback.
2. **Encap dispatch.** It unconditionally called
   `encapsulate_native_gre_frame` for any `tunnel_endpoint_id != 0`, so a
   WireGuard tunnel's segmented TCP went out **GRE-encapsulated** (wrong
   protocol on the wire; for an inet WG endpoint it even built a
   degenerate `0.0.0.0→0.0.0.0` outer) — a mis-encapsulation, worse than
   the MTU drop.

Both axes now dispatch on the typed `TunnelKind` (the #2327 classifier,
`forwarding_build/tunnels.rs::tunnel_mode_kind`) and reuse the existing
SSOT helpers — no parallel overhead math:

- MTU: `Gre` → `native_gre_inner_mtu`; `WireGuard` →
  `wg::mss::wg_inner_mtu(outer_family, outer_mtu)` (the pad-aware inverse
  of `wg_encapped_size`, the same helper #2330's post-transform PMTUD
  uses); `Unknown`/missing → 0 budget → drop. A tunnel budget is NOT
  floored to 1280 (that floor stays on the plain-forward path only): a
  small-outer-MTU tunnel has a genuinely smaller inner budget, and
  flooring it would re-introduce the oversized-then-dropped blackhole.
- Encap: `Gre` → `encapsulate_native_gre_frame`; `WireGuard` →
  `frame/wg.rs::wg_encap_frame` (the same builder the normal egress path
  uses — it pulls the live noise session from `forwarding.wg_engines`
  itself, so the segmentation site needs no extra keystate); `Unknown`/
  missing → drop (fail closed, mirroring the #2327 build-egress
  dispatch in `frame/mod.rs`).

After #2329 the segmentation path, the normal egress path (#2327), the
SYN MSS clamp (#2299, `tunnel_tcp_mss`), the encap MTU guards
(#2331/#1865), and the post-transform PMTUD (#2330) are ALL mode-aware
and share `native_gre_inner_mtu` / `wg::mss::wg_inner_mtu` /
`TunnelKind`.

### Transit-egress encap is no-alloc beyond the owned return (#2792)
`frame/wg.rs::wg_encap_frame` previously allocated TWO heap `Vec`s per
packet on the encrypt/transmit path: an intermediate `wg_record` scratch
that `try_encap` wrote into, then a copy of that scratch into the output
frame `Vec`. Both the intermediate buffer and the copy are gone. The
function now sizes the output frame ONCE to the pad-aware maximum WG
record length (the same `WG_DATA_HEADER_LEN + pad_to_16(inner) +
POLY1305_TAG_LEN` arithmetic the #2680 MTU guard already validated) and
hands `try_encap` a `&mut [u8]` over the output frame's UDP-payload slot
directly — the WG transport record (data header + ciphertext + Poly1305
tag) is encrypted into its final wire position. The frame is then
truncated to the actual encapped length reported by `EncapOutcome::len`.
This is sound because `try_encap` stages the padded plaintext on the
stack (MaybeUninit), so snow's non-overlapping plaintext/ciphertext
requirement is satisfied without a separate output buffer. The single
remaining allocation is the function's OWNED `Vec<u8>` return value,
which is structurally identical to the GRE sibling
(`encapsulate_native_gre_frame`) and is required because the
TCP-segmentation caller accumulates one owned frame per segment in a
`Vec<Vec<u8>>`. The wire bytes are unchanged: same header bytes, same
ciphertext+tag, same outer framing — locked by the round-trip
byte-identity test `wg_encap_in_place_matches_separate_buffer`, which
decrypts the in-place-written record under the paired peer's transport
and asserts the recovered plaintext equals the original inner IP packet
(fails on a wrong encrypt offset / mis-sized buffer / bad truncation).

### Outer MTU SSOT (#2300 / #2680 / #2517)
There is now ONE outer-MTU model. The transit-egress encap
(`frame/wg.rs`) and the control-thread egress (`coordinator/wg_control.rs`)
both gate the OUTER encapped datagram against the REAL underlay-egress
interface MTU, not a hardcoded 1500. The control thread is handed the
resolved underlay MTU at spawn (`Coordinator::resolve_wg_outer_mtu`
route-looks-up the peer endpoint in the endpoint's transport table).
`WG_DEFAULT_OUTER_MTU` (1500) is now ONLY the last-resort fallback for an
unconfigured/unroutable endpoint.

**#2921 (stale captured outer_mtu after a same-engine refresh).** The
control thread is handed `outer_mtu` BY VALUE at spawn, but the WG engine
reuse identity (`wg_identity_unchanged`, `forwarding_build/wg.rs`) compares
only the listen port, local private key, and peer set — it ignores the
transport table, the resolved egress ifindex, and the egress MTU. So a
refresh that changes ONLY the underlay route/table/egress MTU (e.g. an
operator lowers the WAN MTU, or a route flips to a different egress
interface) reused the engine `Arc`, did NOT trip the stale prune
(`spawn_wg_control_threads`), and left the TUN-origin egress guard on the
spawn-time MTU forever — while the transit/forwarded path re-resolves the
underlay per snapshot (#2680). The same tunnel then enforced DIFFERENT
outer MTUs by packet origin: after an MTU increase the local path kept
dropping packets that now fit; after a decrease it emitted datagrams the
kernel had to fragment/reject. The fix captures the resolved MTU in
`WgControlEntry.spawned_outer_mtu` and adds an `outer_mtu_changed` stale
reason to the apply-time prune: when a fresh `resolve_wg_outer_mtu`
diverges from the captured value (and the attachment is otherwise stable),
the thread is stopped + respawned against the current underlay MTU. The
re-resolution is cheap and runs ONLY at apply time per endpoint (the same
cadence the engine-Arc/attachment prune already runs at), never
per-packet; the unchanged common case is byte-identical (no thread churn).

**#5291 (TUN-origin egress is per-peer — the #2845 analog on the local
path).** #2921 captured ONE `outer_mtu` scalar at spawn (the first
endpoint-bearing peer's underlay, `resolve_wg_outer_mtu`) and the
TUN-origin egress guard (`coordinator/wg_control.rs::encap_and_send`)
applied it to EVERY peer. But the TUN egress path LPM-selects the peer by
inner destination (`engine.peer_for_dest`, cryptokey routing) exactly like
the transit path, so on a wg interface whose peers ride DIFFERENT underlay
paths a TUN inner packet to peer B was size-checked against peer A's MTU —
fragmentation/underlay drop if A>B, over-conservative `encap_mtu_drops` if
A<B; reordering the peers flipped the behaviour. This is the SAME defect
#2845 fixed for the transit/PTB path (`wg_endpoint_physical_outer_mtu` /
`wg_peer_outer_dst`), left open on the TUN-origin path because #2921 kept
the first-peer scalar. The fix resolves the underlay MTU PER PEER at spawn
(`Coordinator::resolve_wg_per_peer_outer_mtus`, keyed by public key, using
the same `resolve_underlay_egress_mtu` SSOT the scalar uses), hands the map
by value into the control thread alongside the scalar
(`WgControlEntry.spawned_per_peer_outer_mtu`), and the guard sizes the
SELECTED peer's encap against `per_peer.get(pk).unwrap_or(scalar)`. A peer
absent from the map (learned/roamed endpoint, unresolvable while
`forwarding` is reachable only at spawn) falls back to the interface-level
scalar — the exact pre-#5291 behaviour for that peer. The map is kept
fresh across underlay-MTU changes by the #2921 restart gate, extended to
compare the whole per-peer map (a NON-first peer's MTU change moves no
scalar). Single-peer / homogeneous-underlay tunnels are byte-identical:
every peer resolves to the same MTU the scalar would, so the per-peer
lookup returns the scalar's value.

**#2517 (GRE inner-MTU shares the same fallback).** The native-GRE
inner-MTU resolver `native_gre_inner_mtu` now resolves its outer/transport
MTU through the SAME `tunnel_outer_mtu` SSOT helper the WG MSS clamp uses,
instead of an independent egress-lookup chain. The two paths had drifted on
the miss case: `tunnel_outer_mtu` falls back to 1500 (`.filter(|m| *m > 0)
.unwrap_or(1500)`), but `native_gre_inner_mtu` used `unwrap_or_default()` →
0, which made `native_gre_tcp_mss` return 0 and silently DISABLE a
configured GRE outbound TCP MSS clamp during a transient egress-map miss
(re-reconciliation / interface bringup) — the clamp came back only on the
next reconcile. After #2517 a GRE egress-map miss falls back to the 1500
underlay MTU and `native_gre_tcp_mss` keeps computing a real clamp, exactly
like the WG path. Both tunnel MSS-clamp paths now read one resolver and
cannot drift again.

**#2680 (transit-egress site).** The `frame/wg.rs` guard previously read
the MTU of `decision.resolution.egress_ifindex`, which for a tunnel-resolved
flow is the tunnel LOGICAL ifindex (the WG interface, MTU ~1420), NOT the
physical underlay. Comparing the full OUTER encapped size against the
LOGICAL MTU silently dropped inner packets whose outer datagram fit the
1500-byte underlay (`encap_mtu_drops`) — broken PMTUD / tunnel transit. The
guard now resolves the PHYSICAL egress MTU via `outer_physical_egress_mtu`,
which route-looks-up the SELECTED peer endpoint (`engine.peer_for_dest`, the
real outer hop — the endpoint-level `destination` is zeroed to `0.0.0.0` for
WG, so `resolve_tunnel_outer` cannot be reused here) in the endpoint's
transport table and gates against that underlay interface's MTU.
Distinctions kept separate: OUTER encapped size vs PHYSICAL underlay MTU is
THIS guard; the INNER packet's own logical/PMTUD budget is the inner-MTU
clamp / post-transform PMTUD (#2299/#2330/#2457). Conservative fallback: an
unresolvable outer route falls back to the resolution's `egress_ifindex` MTU
(the pre-#2680 behaviour) then 1500 — never tighter than before.
On the Go side, `wgTunMTUForEndpoint` honors an operator-set `mtu` on the
tunnel interface (the supported sub-1500 override — PPPoE 1492, cloud
overlays ~1450); with no operator MTU it derives the wgN inner MTU from
`wgDefaultOuterMTU` minus the family overhead. The pre-#2300 code ignored
`tc.MTU` entirely and always derived from 1500, so a lowered-underlay
deployment could not set a smaller wgN MTU. Both branches are clamped to the
engine ceiling (#2457, below).

**#2684 (PTB advertisement — the #2680 sibling on the same SSOT).** The
post-transform PMTUD path (`post_transform_inner_mtu`, the TX dispatcher's
inner-MTU derivation that turns an oversized DF-IPv4 / IPv6 inner into a
Frag-Needed / Packet-Too-Big) computed the WG arm's outer MTU via
`tunnel_outer_mtu` (the #2300 transport-MTU SSOT). For a WG transit flow
`endpoint.destination` is zeroed (the peer carries the real outer hop), so
`tunnel_outer_mtu`'s `tx_ifindex` resolution NoRoutes and the chain falls
through to the tunnel LOGICAL `egress_ifindex` MTU (~1420 = underlay −
encap). Feeding that already-reduced MTU to `wg_inner_mtu` subtracts the WG
outer overhead a SECOND time, so the PTB advertised
`wg_inner_mtu(1420)` ≈ 1345 (v4) / 1325 (v6) — ~80-100B SMALLER than the
underlay actually permits. The encap drop guard (#2680) admits inner packets
up to `wg_inner_mtu(physical=1500)` ≈ 1425 (v4) / 1405 (v6), so a DF-IPv4 /
IPv6 inner in the band `(wg_inner_mtu(logical), wg_inner_mtu(physical)]` got
a PTB clamping the sender ~100B too low (over-conservative — safe, no drops,
but unnecessary fragmentation pressure / throughput loss).

The WG arm now derives the outer MTU from the PHYSICAL underlay via
`frame::wg_endpoint_physical_outer_mtu`, a thin wrapper over the same #2680
`outer_physical_egress_mtu` SSOT the encap guard uses.
Corrected formula: advertised inner MTU = `wg_inner_mtu(outer_family,
physical_underlay_mtu)` = `physical_mtu − WG_OVERHEAD_{V4,V6} −
WG_MAX_PADDING` — EXACTLY the inverse of `wg_encapped_size` the encap guard
admits against, so the PTB and the guard now agree. GRE is unaffected:
its `endpoint.destination` is the real outer hop, so `tunnel_outer_mtu`
already resolves to the physical underlay for `native_gre_inner_mtu`.

**#2845 (per-peer underlay — the #2684 follow-up).** #2684 originally
resolved the physical egress via the FIRST peer that carried an endpoint
address, on the assumption that the WG underlay is per-tunnel-endpoint, not
per-inner-flow (#2734). That assumption is wrong when one wg interface has
peers on DIFFERENT underlay paths: the encap path LPM-selects the peer by
inner destination (`engine.peer_for_dest`) and computes the outer hop / MTU
guard from THAT peer's endpoint, but the PTB ran before peer selection and
used the first peer's endpoint. So a PTB for traffic to peer B could quote
peer A's underlay MTU — over-advertising (next packet dropped by peer B's
encap guard) or under-advertising (needless throughput loss). The dispatcher
now threads the pre-encap inner destination into `post_transform_inner_mtu`,
which passes it to `wg_endpoint_physical_outer_mtu`. The helper selects the
SAME peer the encap path will (`engine.peer_for_dest` on the inner
destination — the live engine owns the AllowedIPs LPM and the per-snapshot
endpoint binding, #2836) and resolves the underlay via THAT peer's endpoint
route. Conservative fallback (no inner destination available, no live engine,
or no peer covers the destination) reverts to the first peer with an endpoint
— byte-identical when all peers share one underlay; the pre-#2684 logical
`egress_ifindex` MTU when even that has no endpoint. A covering peer with NO
endpoint resolves to the logical fallback rather than borrowing a different
peer's underlay (the encap path drops such a packet anyway, so the PTB value
is moot).

**#2457 (advertised/configured inner MTU clamped to the engine ceiling).**
The WG engine encrypts at most `PADDED_PLAINTEXT_MAX = 4096` bytes of
§5.4.6-padded plaintext per transport message; the encap path rejects any
inner whose 16-byte-padded length exceeds that, counting `encap_mtu_drops`.
Because `PADDED_PLAINTEXT_MAX` is itself a 16-multiple, the largest
ENCRYPTABLE unpadded inner IP packet is exactly 4096 — exported as
`engine::WG_ENGINE_MAX_INNER_MTU` (compile-time-asserted: 4096 pads to ≤4096
and is accepted, 4097 pads to 4112 and is rejected). This is a HARD ceiling
INDEPENDENT of the outer link: the prior MTU math was purely
`outer_mtu − overhead − pad`, so on a jumbo underlay (or an operator
`set interfaces wgN unit U family inet mtu 9000`) the advertised / configured
inner MTU could exceed 4096. A sender that honored the larger advertised MTU
still had every oversized inner packet silently dropped at the engine cap —
advertised-vs-encryptable mismatch.

Both surfaces now clamp to the ceiling:

- Rust `wg::mss::wg_inner_mtu` (the pad-aware SSOT feeding TCP segmentation
  AND the #2684 PTB advertisement) returns
  `min(outer_mtu − overhead − pad, WG_ENGINE_MAX_INNER_MTU)`. At a normal
  ≤1500 underlay the clamp is a no-op; on a jumbo underlay it caps both the
  segmentation budget and the PTB the engine advertises to inner senders at
  4096. This is distinct from #2684, which fixed WHICH outer MTU the PTB
  reads (logical→physical); #2457 caps the RESULT against what the engine can
  encrypt regardless of how large the (now-correct) physical underlay is.
- Go `pkg/routing/tunnel.go::wgTunMTUForEndpoint` clamps the configured wgN
  DEVICE MTU — an operator `mtu` override (and the default-derived value) is
  `min(value, wgEngineMaxInnerMTU)`, where `wgEngineMaxInnerMTU = 4096`
  mirrors the Rust constant. This keeps the kernel from handing the engine a
  plaintext above the encryptable maximum in the first place.

A jumbo WireGuard inner (>4096) is therefore intentionally NOT supported
today; raising it is a coordinated bump of `PADDED_PLAINTEXT_MAX` (with
proven stack/heap safety for the larger staging buffer) plus the two mirrored
ceiling constants — the compile-time assert in `engine.rs` and the
`wgEngineMaxInnerMTU != 4096` guard in the Go test fail loudly if one side
drifts.

**#2910 (decap is length-driven, NOT padding-validating).** WG §5.4.6
padding is a SEND-side rule (the sender zero-pads plaintext to a 16-byte
multiple). On RECEIVE the transport is length-driven:
`engine::inner_ip_len_after_decap` reads the inner-IP length (IPv4
`total_length` / IPv6 40 + `payload_length`), bounds it against the
AEAD-validated plaintext (`claimed > pkt.len()` → drop — the only real
length invariant, since `pkt` is `read_message`'s `ciphertext_len − 16`
output), then truncates `DecapOutcome.len` to that inner length. The
trailing pad bytes are DISCARDED, never forwarded. The receiver does NOT
validate that the padding is all-zero: the Poly1305 tag already
authenticates the entire plaintext including the padding, so non-zero
padding cannot be forged — rejecting it bought no security but broke
interop with conforming peers (kernel WireGuard / wireguard-go do not
require zero padding; a peer may randomize it for traffic-analysis
resistance). The pre-#2910 `if pkt[claimed..].any(|b| b != 0) { drop }`
check surfaced such records as `MalformedInner` and was removed. Fail-on-
revert: `decap_accepts_nonzero_trailing_padding_and_bounds_to_inner_len`.

**#2701 (transit-egress OUTER SOURCE).** The #2680 MTU fix resolved the
physical underlay egress for the MTU guard but left the OUTER IP SOURCE
still read from `decision.resolution.egress_ifindex` (the LOGICAL tunnel
ifindex). When the logical WG interface carries no WAN primary the
`primary_v4?`/`primary_v6?` lookup returned `None` → dropped transit; when
it carried a tunnel address the outer UDP was sourced from that tunnel
address (breaking source-dependent policy/NAT/upstream anti-spoofing). The
MTU helper is now factored into `outer_physical_egress_ifindex` (returns the
physical underlay ifindex via the same route-to-selected-peer lookup), used
for BOTH the MTU guard (`outer_physical_egress_mtu` wraps it) AND the outer
source primary. So the outer UDP is always sourced from the physical WAN
primary, not the tunnel-logical address. Same conservative fallback: an
unresolvable outer falls back to `egress_ifindex` (no worse than pre-#2701).

**#3992 (single outer-route resolution per packet).** #2680 and #2701 shared
one CONCEPT — the physical underlay egress via the route to the selected peer
endpoint — but `wg_encap_frame` computed it TWICE per packet: once via
`outer_physical_egress_mtu` for the MTU guard, then again via a second
`outer_physical_egress_ifindex` call at the outer-source-write site. Both used
the same `peer_endpoint.ip()` and the same `endpoint.transport_table`, so the
two FIB LPMs always returned the identical ifindex — the second was pure
redundant per-packet work on the encrypt hot path (FIB LPM cost is non-trivial
at line rate over a tunnel). `wg_encap_frame` now resolves
`outer_physical_egress_ifindex` ONCE, caches the ifindex + the `state.egress`
row, and reuses both for the MTU guard (inlining `outer_physical_egress_mtu`'s
body against the shared row — byte-identical guard MTU) AND the outer-source
lookup. The emitted outer header is byte-identical (the dedup does not change
WHICH route is chosen); `outer_physical_egress_mtu` remains the SSOT for the
PTB path (`wg_endpoint_physical_outer_mtu`), which is a separate call site.
RED-on-revert: `wg_encap_frame_resolves_outer_route_once_v4` counts entries to
`outer_physical_egress_ifindex` per encap (test-only `OUTER_ROUTE_RESOLVE_COUNT`
seam) and asserts exactly 1 (2 before the fix) plus outer-header byte-identity.
(Post-#5292 the single resolution is `outer_physical_egress_resolution`; the
`outer_physical_egress_ifindex` wrapper is retained for the PTB path and the
helper tests.)

**#5292 (transit-egress OUTER L2/VLAN — peer before route/connected admission).**
#2680/#2701/#3992 made the outer MTU + IP SOURCE follow the selected peer's
physical underlay egress, but `wg_encap_frame` still read the outer Ethernet
header — the dst MAC (`neighbor_mac`), the src MAC, and the VLAN — from
`decision.resolution`. That resolution was produced BEFORE the AllowedIPs peer
selection, by admitting the route/connected entry that carries the WG endpoint
id: `resolve_tunnel_forwarding_resolution` resolves the endpoint-level
`destination`, which the build zeroes to `0.0.0.0`/`::` for WireGuard (the peer
carries the real outer hop). So the stored L2/VLAN is either NoRoute (no
neighbor/src/VLAN → the encap `?`-drops → blackhole) or, when a default route
matches `0.0.0.0`, the DEFAULT route's adjacency — a neighbor MAC / src MAC /
VLAN describing a different egress than the actually-selected peer needs. The
outer IP source already followed the peer (#2701), so the emitted frame was
internally inconsistent (peer source IP carried on the default route's L2/VLAN,
often the wrong 802.1Q tag). The fix derives the outer L2/VLAN from the SAME
single physical-egress resolution snapshot used for the MTU + source: `src_mac`
+ VLAN come straight from the resolved physical egress row, and the outer
next-hop `neighbor_mac` comes from the peer route's resolution (falling back to
`decision.resolution.neighbor_mac` only when the underlay next-hop is not yet
statically resolved — a dynamic-learned hop shared with the default route, the
common single-underlay case). The non-route/connected admission paths that
already worked are unaffected. RED-on-revert:
`wg_encap_outer_l2_vlan_follows_selected_peer_not_zeroed_decision` (a peer
reached via a different VLAN/adjacency than the stored decision emits the
peer's L2/VLAN, not the decision's) and
`wg_encap_builds_when_zeroed_decision_has_no_l2` (the frame builds against the
peer even when the stored decision carries no usable L2 — the no-blackhole
leg). NOTE: this fixes the outer FRAME identity for a decision that reaches the
builder; the upstream tunnel-resolution SSOT (`resolve_tunnel_forwarding_resolution`)
still stores the LOGICAL `egress_ifindex` + `tx_ifindex = 0` for a WG endpoint
(see #2837), so the canonical wgN-TUN topology — where the kernel routes inner
traffic to the wgN device and the WG control thread owns egress — is the
primary path; this AF_XDP transit-egress builder is the secondary path (see the
`frame/wg.rs` module header).

**#6308 (transit-egress TX DISPATCH — physical egress binding, the other half of
#5292).** #5292 fixed the outer FRAME bytes; the egress-NIC DISPATCH is the
other half of the same zeroed-endpoint problem. The TX dispatcher picks the
egress XSK binding from `decision.resolution.tx_ifindex` (the physical bind
ifindex) or, when that is 0, from `resolve_tx_binding_ifindex(egress_ifindex)`
(`forward_request::resolve_forward_target_ifindex`). Because
`resolve_tunnel_forwarding_resolution` resolves the ZEROED WG endpoint
destination (#2837), a WG transit-egress flow stores `egress_ifindex =` the
LOGICAL wgN ifindex and:

- **WG transport table HAS a default route** — the `0.0.0.0`/`::` lookup matches
  it, so `tx_ifindex =` the default egress bind ifindex. With ONE underlay that
  is the same physical WAN parent the peer route resolves to, so dispatch
  already egresses the correct port. **Common case, unchanged.** With SEVERAL
  underlays it is not: see #6345 below.
- **ONLY a specific peer route, NO default** — `0.0.0.0`/`::` NoRoutes →
  `tx_ifindex = 0` → the fallback `resolve_tx_binding_ifindex(logical wgN)`
  returns the logical ifindex, which has **no XSK binding**, so the TX
  dispatcher `NO_EGRESS_BINDING`-DROPS a frame #5292 built correctly (the bytes
  were right; the packet never egressed). This was the #6308 bug.

**#6345 (the `tx_ifindex > 0` branch — multi-underlay).** #6308 fixed only the
`tx_ifindex == 0` branch, leaving the fast path above taking the stored
resolution verbatim. For a WG transit-egress flow whose transport table DOES
carry a default route, that value is the DEFAULT-route parent — while
`wg_encap_frame` builds the outer L2/VLAN/src against the SELECTED PEER's
more-specific route (#6306). With one underlay the two are the same NIC and
nothing changes. With SEVERAL — a peer reachable over a different NIC than the
default route's — dispatch targeted one NIC while the bytes carried another
egress's L2: a frame emitted on the wrong wire, carrying a source MAC and VLAN
belonging to a different segment.

`resolve_forward_target_ifindex` therefore consults the peer-route resolution
FIRST, on both branches, and falls back to `tx_ifindex` only when it does not
resolve. Dispatch NIC and frame L2 are then the same NIC by construction. If the
peer's NIC has no XSK binding the dispatcher drops, which is the correct
fail-closed posture against emitting a mismatched frame onto the wrong underlay.
The non-tunnel fast path is still one integer compare — the resolver's first act
is `tunnel_endpoint_id == 0 -> None`, after which a plain forward takes
`tx_ifindex` verbatim exactly as before.

The fix resolves the physical underlay egress against the SAME selected-peer
route #5292 uses for the bytes — `wg::wg_transit_egress_physical_egress_ifindex`
(re-exported from `frame`) runs `wg_peer_outer_dst` → `engine.peer_for_dest`
(the inner-destination AllowedIPs LPM) →
`outer_physical_egress_resolution` → `outer_egress_ifindex_or_fallback`, and
`resolve_forward_target_ifindex` feeds that physical egress into
`resolve_tx_binding_ifindex`. So the dispatch SSOT and the frame-bytes SSOT
agree on ONE physical NIC. Non-WG flows and unresolvable-peer flows keep the
pre-#6308 logical fallback (fail-closed identical to before). Like #5292, this changes only
the secondary AF_XDP transit-egress path (not the canonical wgN-TUN topology
where the WG control thread owns egress); the upstream resolution SSOT
(`resolve_tunnel_forwarding_resolution`) is deliberately left storing the
logical `egress_ifindex` + `tx_ifindex = 0` (#2837). RED-on-revert:
`wg_transit_egress_dispatch_specific_peer_no_default_6308` (a specific-peer-route
+ no-default WG flow dispatches to reth0.80's physical parent NIC, not the
logical wgN 400 → `NO_EGRESS_BINDING`; a default-route flow with `tx_ifindex >
0` still dispatches to the default egress verbatim).

**#6340 (dispatch peer selection follows the POST-NAT dst — closing the #6308
DNAT SSOT hole).** #6308 resolved the dispatch egress by selecting the WG peer
from the inner destination's AllowedIPs LPM, but at the dispatch site
(`resolve_forward_target_ifindex`) the frame in hand is the PRE-NAT ingress
frame, while `wg_encap_frame` selects its peer from the POST-NAT frame — the
encap builder applies DNAT into `out` (`apply_nat_ipv4/6` writes
`nat.rewrite_dst`) BEFORE its own peer LPM (`inner_dst_ip(&out)`). Under a DNAT
that rewrites the inner dst ACROSS two AllowedIPs peers on DISTINCT physical
underlays (no default route → `tx_ifindex == 0`), the #6308 dispatch selected
the PRE-NAT peer's NIC while the bytes carried the POST-NAT peer's L2 — a wire
mismatch (dispatch and bytes disagree on the physical NIC). Not a #6308
regression (that edge already dropped pre-#6308), but the SSOT thesis "dispatch
and bytes agree on ONE physical NIC" must hold unconditionally. The fix keys the
dispatch peer selection on the POST-NAT dst: `wg_transit_egress_physical_egress_ifindex`
now uses `decision.nat.rewrite_dst` (the post-DNAT dst) when a same-family DNAT
applies, else the frame's parsed inner dst — the SAME key `wg_encap_frame` reads
from `out`. NAT64 (`nat.nat64`) is excluded (the address family changes, so
neither `rewrite_dst` nor the pre-NAT frame dst is a valid same-family AllowedIPs
key for the endpoint's peers): it returns `None` → the conservative
logical-ifindex fallback (fail-closed; a NAT64→WG transit flow is undeliverable
on this path regardless). RED-on-revert:
`wg_transit_egress_dispatch_follows_post_nat_peer_6308` (a DNAT rewriting the
inner dst across two AllowedIPs peers on distinct physical NICs dispatches to the
POST-NAT peer's NIC, the one `wg_encap_frame` emits bytes for; selecting from the
pre-NAT dst resolves the wrong peer). The non-DNAT
`wg_transit_egress_dispatch_specific_peer_no_default_6308` is unchanged.

**#2703 (outer TTL default).** A tunnel TTL of `0` is the "use the default
64" sentinel in the Go config (`schema_interfaces.go`, `types_routing.go`),
and the netlink GRE path applies it (`pkg/routing/tunnel.go: if ttl == 0 {
ttl = 64 }`). The AF_XDP transit path passed `tunnel.TTL` raw into the
snapshot, and the Rust frame builders (`frame/wg.rs`, `gre.rs`) write the
snapshot TTL straight into the outer IP header — so a default-config tunnel
emitted outer TTL/hop-limit 0 → deterministic first-hop blackhole. The 0→64
default is now applied Go-side in `pkg/dataplane/userspace/tunnels.go` (the
SSOT, mirroring the netlink precedent) before the value reaches the
snapshot; an explicit non-zero TTL is preserved. As a fail-closed backstop,
`TunnelTtl::try_from_snapshot` now maps a NEGATIVE snapshot TTL (corrupt /
mixed-version) to the documented default 64 rather than 0 (an out-of-range
value > 255 still fails the snapshot CLOSED via `TunnelTtlOutOfRange`).

Residual / follow-up: the per-peer LEARNED-endpoint roam case still uses
the spawn-time outer MTU on the control thread (the transit-egress path
already reads the real per-packet egress MTU); the Go default cannot see
the route at the tunnel-manager layer, so a non-1500 underlay relies on
either the operator `mtu` statement or the Rust egress guard as the
authoritative backstop.

### DSCP/ECN propagation (#2303 encap, #2315 GRE decap, #7758 WG host encap)

**Encap (#2303, completed for WG in #7758).** GRE and WG encap copy the
inner packet's full TOS / IPv6 Traffic-Class byte (DSCP 6 bits + ECN 2
bits) onto the outer header via `gre::inner_tos_byte`, instead of
hardcoding 0. This is the uniform DSCP model (RFC 2983) — per-hop QoS
classification survives the tunnel — plus the RFC 6040 normal-mode ECN
ingress COPY (inner ECN → outer ECN). `wg::dscp::tos_from_dscp` (which
clears ECN) is retained for the DSCP-only case but is NOT the encap
reader.

**WireGuard has TWO encap paths, and until #7758 only one copied.**
#2303 wired the TRANSIT path (`frame/wg.rs`, inner arriving on AF_XDP).
The HOST-ORIGINATED path (`wg_control::encap_and_send`, inner read from
the wgN TUN) ended at a bare `send_to` with no per-datagram control
message, so its outer DS byte stayed 0. The same inner marking therefore
produced a different outer DSCP depending on which path a packet took —
an internal routing detail no operator can see, while a downstream
classifier sees WG traffic marked or unmarked accordingly. #7758 gives
the host path the same copy, through `sendmsg` with `IP_TOS` /
`IPV6_TCLASS` ancillary data because the value is per-packet.

The cmsg level follows the destination's WIRE family, not the socket
family: a v4-mapped destination on the dual-stack AF_INET6 socket emits
an IPv4 datagram and takes `IP_TOS`, mirroring the receive side where
`IP_RECVTOS` governs both native v4 and v4-mapped delivery. The
loopback round-trip test asserts the DS byte as RECEIVED rather than
trusting that mapping.

Sends that carry NO inner packet — handshake initiation, handshake
response, cookie reply, keepalive — are deliberately exempt and go out
unmarked: there is no inner DS byte to propagate, and a keepalive
inheriting some other packet's DSCP is exactly what a per-datagram cmsg
exists to prevent. `wg_send_to` takes the TOS as an explicit
`Option<u8>` so a new send site has to decide rather than inherit.

**Decap (#2315 GRE / #2317 WG).** The RFC 6040 §4.2 decap-side ECN
*combine* (outer ECN → inner ECN) — the half that actually reflects a CE
mark applied by a congested router on the outer path back to the inner
endpoints — is implemented for **both tunnel paths** via the shared
`gre::apply_decap_ecn_combine`: an outer CE upgrades an ECN-capable inner
to CE; the illegal outer-CE / inner-Not-ECT combination is dropped; the
inner DSCP is authoritative at decap and is never copied from the outer.
DSCP is not copied back at decap.

- **GRE (#2315)** reads the outer ECN from the still-present outer IP
  header in the frame (`outer_ecn_bits`, wired into
  `try_native_gre_decap_from_frame`). Illegal-combination drops surface as
  `xpf_userspace_gre_decap_ecn_illegal_drops_total`.

- **WireGuard (#2317)** captures the outer ECN out-of-band. The WG control
  thread reads transport records from a kernel `UdpSocket`, which strips
  the outer IP header (and its ECN) before the datagram reaches
  userspace, so the recv loop uses `recvmsg` with the `IP_RECVTOS` (v4 /
  v4-mapped) and `IPV6_RECVTCLASS` (v6) socket options enabled at bind;
  the outer DS byte arrives as ancillary data (`IP_TOS` / `IPV6_TCLASS`
  cmsg), and its low 2 bits are folded into the freshly-decrypted inner IP
  packet — before `tun.write_all` — through the same combine. Illegal-
  combination drops surface as
  `xpf_userspace_wg_decap_ecn_illegal_drops_total` (a sibling counter, so
  the two families are independently observable). The combine is skipped
  best-effort when no TOS cmsg arrives (a kernel that did not honor the
  sockopt) — never fatal to the tunnel. Live end-to-end verification (a
  real WG peer CE-marking the outer → CE on the inner) is lab-bound,
  deferred to the #1703-class interop validation; the code path and unit
  tests (cmsg parse for v4/v6, the §4.2 combine reuse, CE upgrade + IPv4
  checksum, illegal-combo drop+count) are in tree. The `recvmsg` control
  buffer is the 8-byte-aligned `CmsgBuf([u8; 256])` newtype (#2334) so the
  `cmsghdr` header-field reads the `CMSG_*` macros perform are naturally
  aligned (a bare `[u8; N]` is align-1; reading `cmsg_len`/`cmsg_level`/
  `cmsg_type` through an under-aligned `*const cmsghdr` is UB and a SIGBUS
  risk on strict-alignment targets such as ARMv8). A compile-time
  `align_of::<CmsgBuf>() >= align_of::<cmsghdr>()` assertion is the
  fail-on-revert sentinel.

- **Link-local v6 endpoint scope (#2995)** — the same `recvmsg` loop
  converts the kernel-populated `msg_name` `sockaddr_storage` into a Rust
  `SocketAddr` (`sockaddr_storage_to_socketaddr`) to learn / refresh a
  peer's roaming endpoint. The AF_INET6 arm builds a `SocketAddrV6` that
  preserves `sin6_scope_id` and `sin6_flowinfo` rather than discarding
  them via `SocketAddr::new` (which fixes `scope_id = 0`). A WireGuard
  underlay endpoint that is an IPv6 link-local address (`fe80::/10`)
  carries the receiving-interface scope; without it the next
  `wg_send_to` toward the learned endpoint is rejected by the kernel with
  EINVAL/ENODEV (a link-local destination requires a non-zero scope) and
  the tunnel never establishes. The scope survives `canonicalize_endpoint`
  (it only unmaps v4-mapped v6, passing native v6 through untouched). For
  a global v6 endpoint the kernel sets `sin6_scope_id = 0`, so the change
  is a no-op there. Fail-on-revert: the `wg_control`
  `sockaddr_storage_to_socketaddr_preserves_link_local_scope` unit test
  goes RED (scope_id 0 vs ifindex) if the construction reverts to
  `SocketAddr::new`.

## What S1 delivers

S1 makes xpf's WireGuard **handshake bytes** standards-compliant:

- **TAI64N timestamp** (`userspace-dp/src/afxdp/wg/tai64n.rs`): a 12-byte
  big-endian `0x400000000000000a + unix_secs` (the `+10` is the 1970-epoch
  TAI−UTC leap offset, matching kernel WireGuard and wireguard-go) followed by
  whitened nanoseconds (`& 0xFF000000`). The clock is strictly monotonic
  in-process so xpf never DoSes its own re-handshakes with a backwards
  timestamp. Carried as the encrypted Noise payload of message 1.
- **Responder handshake anti-replay** (`Peer::greatest_tai64n`,
  `check_and_update_tai64n`, #4092): the greatest TAI64N ever accepted in a
  type-1 initiation from a peer is held per-peer; an initiation whose
  recovered TAI64N is `<=` that high-water is a replay/reorder and is
  rejected (whitepaper §5.1; kernel `memcmp(timestamp, last_timestamp) > 0`).
  **Reload survival (#4103):** an identity-changing WG config commit (add an
  allowed-ip, rotate a PSK, add/remove a peer) rebuilds the engine via
  `WgEngine::new`, which starts from an empty peer table and would give every
  surviving peer a fresh `greatest_tai64n = [0; 12]`. `populate_wg_engines`
  (`forwarding_build/wg.rs`) carries each surviving peer's high-water forward
  across the rebuild, keyed by pubkey (`greatest_tai64n_by_pubkey` /
  `seed_greatest_tai64n`) — the incoming-side mirror of the #1432 initiator
  clock re-seed. A new or re-keyed pubkey correctly starts fresh (a different
  peer identity). Without the carry-over, a benign commit would silently
  disarm the anti-replay for every peer, letting an attacker replay a
  captured initiation. Matches kernel / wireguard-go, which retain per-peer
  `last_timestamp` across a reconfigure.
- **Handshake framing** (`userspace-dp/src/afxdp/wg/handshake.rs`): the WG
  type-1 MessageInitiation (148 bytes) and type-2 MessageResponse (92 bytes)
  on-wire framing — type byte, reserved, sender/receiver index, and
  `MAC1 = keyed-BLAKE2s-128(BLAKE2s-256("mac1----" || recipient_static_pub),
  msg[0..offsetof(mac1)])`. MAC2 is emitted as zeros on build UNLESS the
  initiator holds a fresh cookie for the peer (#4094 PR-B — see below), in
  which case `create_initiation` stamps
  `MAC2 = keyed-BLAKE2s-128(cookie, msg[0..offsetof(mac2)])`; on parse it is
  skip-verified when NOT under load (spec-correct) and validated against the
  responder cookie when under load (#4094 PR-A — see below).
- **Canonical 32-bit type word on every parse** (#5193/#5191
  `handshake::is_canonical_type`): WG carries `message_type` as a
  little-endian u32, and kernel WireGuard / wireguard-go compare all four
  bytes. Every xpf parser now does the same — the type-1/type-2 handshake
  parsers, `framing::parse_data_header` (type 4 transport data) and
  `CookieChecker::decrypt_cookie_reply` (type 3) all call the single
  `is_canonical_type` helper. Before #5191 the transport-data and CookieReply
  paths compared only the low byte and accepted nonzero RESERVED bytes, so a
  datagram xpf would decrypt was one a kernel peer discards — a parser
  differential, and the kind of ambiguity an evasion probe looks for. xpf's own
  encoders have always written the reserved bytes as zero, so nothing
  interoperable is rejected by the tightening.

## Responder cookie / MAC2 under-load DoS mitigation (#4094 PR-A)

MAC1 keys on the responder's static *public* key, which is not secret and
does not bind an initiation to its source address. Without the cookie layer,
an attacker who knows our public key can forge valid-MAC1 type-1 initiations
with spoofed sources and force one Noise responder handshake (an X25519 DH +
AEAD) per datagram — a CPU-exhaustion DoS. mac1-only is authentication-safe
but has no anti-flood layer; the WireGuard whitepaper §5.4.7 cookie mechanism
is exactly that layer.

`userspace-dp/src/afxdp/wg/cookie.rs` implements the RESPONDER half:

- **Rotating secret `Rm`** — a per-tunnel random 32-byte secret held in the
  engine's `CookieChecker`, rotated every `COOKIE_ROTATION_TIME_NS` (120 s,
  mirroring wireguard-go `CookieRefreshTime`). The PREVIOUS secret is kept for
  one rotation window so a cookie issued just before a rotation still
  validates its MAC2 (a cookie straddling the boundary is not dropped). A gap
  of ≥ two windows with no traffic starts fresh with no previous, bounding any
  secret's validity to `< 2 × COOKIE_ROTATION_TIME_NS`.
- **Load detector** — a fixed-window per-second rate gate on inbound type-1
  arrivals. Above `INITIATIONS_UNDER_LOAD_THRESHOLD` (25/window; far above any
  legitimate rekey pattern, well below a flood) the tunnel is "under load" for
  a sticky `UNDER_LOAD_GRACE_NS` (1 s) grace, mirroring wireguard-go's
  `UnderLoadAfterTime`.
- **Under-load path** (`WgEngine::classify_initiation`, ordering mirrors
  wireguard-go `device/receive.go`): not-under-load → process normally
  (byte-identical to pre-#4094). Under load: a valid MAC2 → process (the peer
  proved it holds a source-bound cookie); a valid MAC1 but missing/bad MAC2 →
  emit a type-3 CookieReply and DROP the initiation with no Noise crypto; a
  bad-MAC1 / malformed datagram → fall through to the cheap consume-path drop
  (no crypto, correct per-reason counter) with NO reply, so a random /
  bad-MAC1 flood cannot turn the responder into a reflector.
- **Cookie construction** — `cookie = keyed-BLAKE2s-128(Rm, src_ip||src_port)`
  over the datagram's ACTUAL source (`from` in `wg_control::dispatch_inbound`,
  never a claimed one). The type-3 reply carries the cookie
  XChaCha20-Poly1305-encrypted under
  `key = BLAKE2s-256("cookie--" || responder_static_pub)`, a random 24-byte
  nonce, and the triggering initiation's MAC1 as AEAD associated data; it
  echoes the initiator's sender_index. `MAC2 = keyed-BLAKE2s-128(cookie,
  msg[0..offsetof(mac2)])` is recomputed from the current source and checked
  against the current secret and (within the window) the previous one.
  XChaCha20-Poly1305 is a NEW primitive vs snow's transport ChaChaPoly (24-
  vs 12-byte nonce); the `chacha20poly1305` crate was already transitive via
  snow (0.10.1) and is promoted to a direct, `default-features = false` dep.
- **Reply budget** — a per-window cap (`COOKIE_REPLY_BUDGET_PER_WINDOW`, 40)
  on emitted cookie replies so a heavy valid-MAC1 flood cannot make the
  generated replies themselves a CPU/socket sink (the WG analog of the
  syn-cookie reply-budget discipline). WG cookie replies leave via the
  tunnel's UDP socket, not the AF_XDP TX ring.
- **Per-source reply bucket (#4332)** — the reply budget above is GLOBAL per
  tunnel, so a determined valid-MAC1 flood from ONE source could drain the
  shared budget and budget-suppress a legit peer's FIRST cookie challenge from a
  DIFFERENT source. `CookieChecker::source_reply_allowed(src_ip, now)` adds a
  small per-SOURCE token bucket (`SOURCE_REPLIES_PER_SEC` 20/s sustained,
  `SOURCE_REPLY_BURST` 5 burst, `PACKET_COST_NS`/`MAX_TOKENS_NS` accrued-time
  credit), mirroring wireguard-go `device/ratelimiter.go`. It is layered BEFORE
  the global budget in `classify_initiation` — **both** gates must pass — so a
  flood from one source throttles only its own bucket and cannot starve another
  source's challenge. The table is GC-swept every `SOURCE_GC_INTERVAL_NS` (1 s;
  idle buckets dropped) and hard-capped at `SOURCE_TABLE_MAX` (2048): a NEW
  source that would overflow the cap is DENIED (fail CLOSED, no reply), never
  inserted, bounding the map against the spoofed-source-IP memory-amplification
  vector this hardening could otherwise introduce. The refill obeys the same
  monotonic-clock discipline as the SYN-cookie token bucket (#4330/#4321): a
  backwards `now_ns` credits nothing (`saturating_sub`) and never lowers a
  bucket's `last_ns` high-water mark, so a clock glitch cannot be replayed into
  an over-credit. Per-source throttle drops (and the full-table fail-closed) are
  counted with the global-budget family under `hs_cookie_reply_budget_drops`.
- **Counters** — `hs_cookie_replies_sent`, `hs_rx_under_load_no_mac2`,
  `hs_rx_under_load_mac2_ok`, `hs_cookie_reply_budget_drops` (Prometheus:
  `xpf_userspace_wg_cookie_replies_total{event}` +
  `xpf_userspace_wg_handshake_rx_drops_total{reason=under_load_no_mac2|cookie_reply_budget}`).

## Initiator cookie-reply consume (#4094 PR-B)

PR-A gave the RESPONDER half; PR-B completes the interop by teaching the
INITIATOR to answer a cookie challenge. Without it, an inbound type-3 was
dropped and xpf-as-initiator could never complete a handshake against a peer
that was itself under load (the responder keeps challenging; the initiator
keeps sending zero-MAC2 initiations). The initiator half mirrors wireguard-go
`CookieGenerator` and lives in `cookie::InitiatorCookie` (per-peer state held
in `WgEngine::cookie_gen`, keyed by responder pubkey):

- **On every outbound initiation** (`create_initiation` →
  `WgEngine::add_initiator_macs` → `InitiatorCookie::add_macs`, run AFTER
  `build_initiation` writes MAC1 and zeroes MAC2): record the message's MAC1 as
  the AEAD AAD for a future cookie-reply, and — if we hold a cookie younger than
  `COOKIE_ROTATION_TIME_NS` (the same 120 s TTL as the responder secret) — stamp
  `MAC2 = keyed-BLAKE2s-128(cookie, msg[0..offsetof(mac2)])`. No cookie, or an
  expired one, leaves MAC2 zero (spec-correct).
- **On an inbound type-3 CookieReply** (`wg_control::dispatch_inbound` →
  `WgEngine::consume_cookie_reply`): the reply's `receiver_index` echoes the
  `sender_index` of the initiation that triggered it, which is the key of a
  pending initiator handshake — look it up to attribute the reply to a peer,
  decrypt the sealed cookie with that peer's (the responder's) public-key-derived
  key and our stored last-sent MAC1 as the AAD
  (`CookieChecker::decrypt_cookie_reply`, now production, not a test mirror), and
  store the cookie + receive time. Fails CLOSED (no state change, no panic) for a
  reply we cannot attribute (no matching in-flight initiation) or cannot decrypt
  (wrong key / bad AAD / tampered ciphertext). A cookie-reply is XChaCha-sealed
  under our own public-key-derived key and proves nothing about whether the
  source holds the peer's keys, so it is NOT authenticated for endpoint-learning.
- **Counters** — `hs_rx_cookie_consumed` (Prometheus:
  `xpf_userspace_wg_cookie_replies_total{event=consumed}`) on a successful
  decrypt+store; `hs_rx_cookie_unsupported` (its former S7-placeholder wire name,
  now a real drop-by-reason site) on an unattributable / undecryptable reply.
- **Lifecycle / peer removal (#4362)** — `cookie_gen` is keyed by peer pubkey
  and, like `pending_by_peer`, lives OUTSIDE the atomically-swapped `PeerTable`.
  `WgEngine::reconcile_peers` therefore drains a removed peer's `cookie_gen`
  entry alongside its `sessions_by_local_index` demux entries and pending
  handshake reservations — otherwise each peer removal would leak a stale
  `InitiatorCookie` (~56 bytes) until process restart. A kept peer's entry is
  left untouched. RED-on-revert: `engine_tests.rs`
  `reconcile_peers_drains_dropped_peer_cookie_gen`.

**RED-on-revert (PR-B):** `cookie.rs`
`initiator_cookie_roundtrip_stamps_accepted_mac2` (a responder cookie-reply is
consumed by the initiator and the retried MAC2 verifies against the responder's
own `verify_initiation_mac2` — and is rejected from a different source),
`initiator_expired_cookie_yields_zero_mac2` (a cookie past the 120 s TTL is not
used), `initiator_drops_undecryptable_cookie_reply` (tampered/wrong-key reply is
dropped fail-closed), `initiator_ignores_cookie_reply_before_any_initiation`; and
the engine-wired end-to-end `initiator_consume_completes_handshake_under_load`
(an initiator challenged by a responder under load consumes the cookie-reply and
its retried `create_initiation` is admitted as `Process`). Neutering the MAC2
stamp makes the stamping tests fail (retried MAC2 stays zero / re-challenged).

**RED-on-revert:** `classify_initiation_under_load_requires_mac2` (drives a
synthetic initiation flood past the threshold, then asserts a spoofed/unprimed
initiation without a valid MAC2 is cookie-challenged and NOT handshaked, while
one echoing a decrypted-cookie MAC2 IS processed, and a stolen MAC2 from a
different source is re-challenged). Reverting the gate makes it `Process` for
every initiation and the test fails. #4332 adds
`classify_initiation_per_source_budget_isolation` (a flood from one source past
the global budget must NOT budget-suppress a legit peer's challenge from another
source) plus the `cookie.rs` unit tests `source_bucket_burst_then_throttle`,
`source_bucket_isolates_sources`, `source_table_cap_fails_closed`,
`source_gc_reclaims_idle_buckets`, and `source_bucket_ignores_backwards_clock`.
- **Engine orchestration**
  (`userspace-dp/src/afxdp/wg/handshake_session.rs`): `create_initiation`,
  `consume_response`, and `consume_initiation_create_response` compose snow +
  the framing + the TAI64N clock into the full handshake in both roles, with a
  two-phase index reservation (reserve before send, at most one pending per
  peer) so a completed handshake's session is never blackholed by an index
  collision. Handshake construction runs on the control thread only — never
  the AF_XDP poll worker.

## Honesty note (S1/S2 boundary)

**S1 is NOT yet proven to interoperate with an independent WireGuard peer.**
Its in-tree gate is spec known-answer vectors (the WG construction hashes, the
MAC1 keyed-BLAKE2s-128 construction, the TAI64N encoding, and full byte-exact
msg1/msg2 wire images) plus an xpf-against-xpf framed-handshake round-trip.
Those pin every framing/MAC1/TAI64N byte to the canonical construction, but a
symmetric build/parse bug shared by both xpf roles would pass them. The
independent-peer proof — a live handshake against the **Linux kernel
WireGuard** module — lands in S2 alongside the dataplane/UDP wiring it shares.
Do not claim "xpf interoperates with WireGuard / UniFi" on the basis of S1
alone.

## S2 live kernel-WireGuard interop recipe (reference; built in S2)

The independent reference is the Linux kernel WireGuard module running on a
real incus **virtual machine** (never a container — containers share the host
kernel and cannot use the WG module or create `type wireguard` links). This is
byte-identical to what UniFi / EdgeOS / UDM run.

```sh
# On a Debian-13 VM peer (root; install wireguard-tools if absent):
ip link add wgref type wireguard
wg set wgref private-key <ref.priv> listen-port <P> \
   peer <xpf.pub> allowed-ips 0.0.0.0/0 endpoint <xpf_vm_ip>:<Q>
ip addr add <wg-overlay>/24 dev wgref
ip link set wgref up

# Direction A: xpf create_initiation -> UDP <peer_vm_ip>:<P>; kernel wg
#   verifies MAC1 + decrypts the TAI64N + replies type-2; xpf
#   consume_response derives the session. Assert via `wg show wgref`
#   (peer-side cross-check) and `show security wireguard` on xpf
#   (#1865 — local handshake counters are the primary oracle).
# Direction B: kernel wg initiates (persistent-keepalive 1); xpf
#   consume_initiation_create_response replies; assert `wg show` completes.
```

The peer VM attaches to the same SR-IOV LAN segment as the cluster host
(`mlx1` / VLAN 3667 on the loss userspace cluster); S2 must verify a free VF
exists before launching the peer, or reuse an existing real VM on that segment.

## Operator CLI surface (key handling)

These operational commands support bringing a tunnel up against a peer.
They are read-only / stateless (`request` prints, it does not mutate
config), so both work on a standalone box and through the remote `cli`.

- **`show security wireguard public-key`** (#1434 Increment 1) — prints
  the **local** static public key per configured WG tunnel, in
  WireGuard-canonical base64 (the form a peer pastes into its
  `[Peer] PublicKey =`). The key is derived once by the helper from the
  local private key at engine construction and surfaced on the per-tunnel
  status row (`local_pubkey_hex`, hex on the wire; the CLI re-renders it
  as base64). A tunnel whose helper has not yet surfaced a key renders
  `(unavailable)` rather than being dropped. Complements
  `show security wireguard [detail]` (#1865 telemetry), which already
  shows the **peer** public key and handshake/transfer counters.

- **`request security wireguard generate-private-key`** (#1434
  Increment 1) — generates a fresh Curve25519/X25519 private key and
  prints it with its derived public key, both in WireGuard-canonical
  base64 — equivalent to `wg genkey` + `wg pubkey`. The key is generated
  locally in pure Go (`pkg/wgkey`, stdlib `crypto/ecdh`); it needs no
  dataplane and issues no control-socket / gRPC round-trip. The printed
  private key is clamped per the Curve25519 convention
  (`priv[0]&=248; priv[31]&=127; priv[31]|=64`) so it is byte-identical
  to what `wg genkey` emits. Paste the private key under the tunnel's
  `tunnel wireguard local-private-key`; hand the public key to the peer.

### Multi-tunnel status (#1434 scope note)

The dataplane is multi-engine: one `Arc<WgEngine>` and one control thread per
configured WG tunnel-endpoint id (`wg_engines`, `spawn_wg_control_threads`),
per-tunnel telemetry rows, and engine-by-id encap. **Increment 1** added the
local-key telemetry and the two CLI commands above. **Increment 2 — steering a
SET of listen ports in the AF_XDP shim — is DEFERRED and tracked as #9587**: a
verifier-gated `userspace-xdp` change with a documented v6-line-rate
sensitivity that must pass the loss cluster, perf and `make test-failover`.
Design of record: `docs/research/1434-multi-tunnel-wireguard/plan.md`.

#### What happens to a second listen port (#9521)

The shim steers WireGuard for ONE listen port. `UserspaceCtrl.wg_listen_port`
is a scalar, and the worker-claim predicate (`wg_worker_claims_record`) requires
the datagram's destination port to equal it. A transport-data record for that
port is decapsulated by the worker and its inner packet is adjudicated under
the tunnel's ingress zone (#8274). A record for any OTHER configured listen
port is not claimed and reaches the kernel, where that tunnel's own control
thread receives it: the host-inbound filter admits every configured listen
port, and the helper runs a control thread per endpoint.

| | steered port | every other configured port |
|---|---|---|
| handshake and cookie records | kernel -> control thread | kernel -> control thread |
| transport data | worker decap -> zone, session, policy, NAT | kernel -> control thread -> **dropped and counted** |
| outbound traffic | worker encap after policy | worker encap after policy |

**Which port is steered.** `config.SteeredWireGuardListenPort`: the first
WireGuard endpoint, in `config.EmitTunnelEndpointNames` order (interfaces
sorted by name, units ascending), that carries a listen port. It is derived
from the configuration and stamped on the helper snapshot as
`wg_steered_listen_port`. The shim ctrl block (`snapshotWgListenPort`) and the
helper both read that one field, and the commit warning names the same value.
Before #9521 the shim scalar was the first endpoint that *survived* the
intersection with the live interface rows, so a missing netdev for the warned
tunnel silently promoted the next tunnel's port — the one the warning had just
called unsteered.

**The drop.** Until #9521 an unsteered port's control thread decrypted the
record and wrote the plaintext inner packet to its wgN TUN, and the kernel
forwarded it with no zone policy, no session, no NAT and no counters: an
authenticated peer on that port reached whatever the kernel routed to, bounded
only by its `allowed-ips` (a source-ownership check, not a destination
policy). The thread now authenticates the record — so key confirmation, the
replay window and endpoint roaming behave as for a keepalive — and drops the
plaintext, counting it as `rx_unsteered_transport_drops`: the `unsteered-port`
receive-drop reason in `show security wireguard detail`, and
`xpf_userspace_wg_transport_drops_total{direction="decap",reason="unsteered_port"}`.
A snapshot that names no steered port delivers for no endpoint. The steered
port's thread still delivers, because #8274 kept that write for ingress the
shim does not cover (`docs/log/8274.md`, "The residual, stated rather than
closed"). Worker decapsulation is not gated by the steered port — the worker
matches every configured listen port — so a record the shim hands to the
worker for any other reason is still adjudicated normally.

So a second tunnel on a distinct port completes handshakes and sends, and gets
no inbound traffic through the kernel path. It is refused, not dead: this
section once called it dead (false — it was live, which was the bypass, #9016),
and then "served by the kernel path" (true until #9521, and the bypass itself).

**Why a drop in the helper,** rather than refusing the port in the host-inbound
filter or rejecting the configuration at commit:

- **The filter cannot refuse it.** The input chain accepts `ct state
  established` traffic ahead of the WireGuard admit, so a peer answering a
  handshake xpf initiated rides conntrack past any per-port rule; a zone whose
  `host-inbound-traffic` admits all services accepts the port regardless; and
  no host-inbound table is installed at all when nothing needs one. Every such
  record converges on the control thread's socket.
- **A commit reject would brick.** A box already running a multi-port config
  could not commit an unrelated change (#1960).
- **Steering the set is Increment 2** (#9587), above.

It is surfaced at commit. `validateWireguardSingleSteeredPort`
(`pkg/config/compiler_validate_wireguard_multiport.go`, run from
`runTailGates`) emits a **warning** whenever the configuration resolves to more
than one distinct WireGuard listen port, naming the steered port and every
refused one. For `wg0` on 51820 and `wg1` on 51900:

```
wireguard: 2 distinct listen-ports are configured, but the dataplane steers
inbound WireGuard transport for only ONE of them. listen-port 51820 (wg0) IS
steered onto the AF_XDP WireGuard path, where its decapsulated traffic is
adjudicated under the tunnel's ingress zone (screen, session, policy, NAT).
listen-port 51900 (wg1) is NOT steered, and inbound transport for that
tunnel is REFUSED rather than forwarded unadjudicated: a transport record
that reaches that tunnel through the kernel is DROPPED (counted as an
unsteered-port receive drop) instead of being written to its wgN TUN, where
the kernel would forward it with no zone policy, no session and no counters.
Handshakes still complete and outbound traffic still flows, so that tunnel
can come up and still pass no inbound traffic. Only one WireGuard
listen-port can be steered until multi-port steering lands (#1434 Increment
2, tracked as #9587).
```

Two WG tunnels that SHARE one listen port lose nothing to the steering scalar
and draw no warning.

Fail-on-revert guards: `TestWireGuardDistinctListenPortsWarnsAtCommit_1434`,
`TestWireGuardSingleListenPortDoesNotWarn_1434`,
`TestWireGuardSameListenPortDoesNotWarn_1434`,
`TestWireGuardThreeListenPortsWarnsOnce_1434`,
`TestMultiportAdvisoryDoesNotClaimTheTunnelIsDead9016`,
`TestSteeredWireGuardListenPortIsTheEmitterFirst9521` and
`TestMultiportWarningNamesTheSteeredPortDerivation9521` (`pkg/config`);
`TestWireGuardSteeringAdvisoryNamesTheProgrammedPort_1434`,
`TestSnapshotProgramsTheWarnedWireGuardPort9521`,
`TestOnlyFirstWireGuardListenPortIsSteered9016`,
`TestSnapshotWgSteeredListenPortWireKey9521` and
`TestFormatWireguardUnsteeredPortDrops9521` (`pkg/dataplane/userspace`), which
require the programmed port to equal the warned one with every tunnel netdev
present, with the warned one absent, and with none; and in `userspace-dp`,
`wg_unsteered_endpoint_refuses_kernel_transport_end_to_end_9521` (real spawned
control threads, IPv4 and IPv6),
`unsteered_port_kernel_transport_is_dropped_not_written_9521`,
`kernel_transport_decision_fails_closed_9521`,
`wg_resteering_restarts_control_threads_with_the_new_decision_9521`,
`worker_decap_is_not_gated_by_the_steered_port_9521` and
`wg_steered_listen_port_wire_key_9521`.

## Host-inbound admission of the WG listen port (#5582)

The shim steers local-destination UDP on the configured WG listen port to
the kernel (`wg_steer_to_kernel`, `userspace-xdp/src/lib.rs`) so the
userspace WireGuard control socket receives the outer transport. But the
kernel input path is also guarded by the host-inbound nftables chain
(`inet xpf_hostinbound`, `pkg/daemon/daemon_nft.go`): on a **restricted**
security zone (a zone with a `host-inbound-traffic` set that does not open
the WG port, or no stanza at all — Junos default-deny) the per-zone
catch-all silently DROPs everything not explicitly admitted.

A returning packet for an xpf-**initiated** handshake is `ct state
established` and passes, which is why interop where xpf dials out first
succeeded. But a **fresh passive (responder-only) handshake** — the
supported "external peer initiates, xpf listens" config — is conntrack
`NEW`: it misses the service accepts and hits the catch-all drop, so a
responder-only listener on a restricted zoned address could never come up
after boot / conntrack expiry.

**Fix (#5582): a dynamic, automatic host-inbound admission tied to the
configured listen port(s) — not a static `system-services` token.** When
any WG tunnel is configured, `buildHostInboundFilterPayload` emits a
single coarse `udp dport <configured-wg-port(s)> accept` on the input
hook (`emitHostInboundWireGuardAccept`). Rationale:

- **Automatic, not a manual token.** The shim *already* steers the port
  unconditionally; requiring the operator to separately open it would let
  the shim steer a packet the kernel then drops. A configured WireGuard
  listener therefore *implies* host admission of exactly its listen port.
- **Dynamic port, so no static SSOT token.** WireGuard's port is
  operator-configured, so it does not fit the static token→port SSOT
  (`config.HostInboundServiceMatch`, e.g. `ssh`→22) that the nft mirror
  and the Rust classifier render from; a `system-services wireguard`
  token would need a fake fixed port and would break the token-parity
  tests. The port set is the compile-time SSOT
  `config.WireGuardListenPorts()` (all configured WG tunnels).
- **Scoped to the shim's steering, not widened.** The rule is a single
  global accept, but the nft `input` hook only ever sees host-destined
  packets, so a bare `udp dport <port>` admits the WG port to **every
  firewall-local address** — exactly the shim's `is_local_destination`
  scope — while transit/forward UDP (which traverses the `forward` hook,
  never this chain) is untouched, so transit/DNAT UDP on the WG port is
  never shunted around policy. Only the WG port is opened; every other
  host-bound service stays under the per-zone default-deny.
- **Composes with the #5565 per-interface host-inbound scoping.** With a
  `to-zone junos-host` DENY program present, the WG accept is placed
  AFTER the fine iifname-scoped DROP subchain, so an explicit operator
  junos-host deny of a WG source still wins; it is a coarse admit like
  the ND/PMTUD accepts.

**Runtime-vs-config nuance:** the admission uses the CONFIGURED listen
ports (the compile-time SSOT). The shim steers only one of them (see
"Multi-tunnel status" above) and the filter admits ALL of them. For the others
that admit is not a no-op, and it is not where they are refused: it is what
lets an unsteered tunnel's handshakes reach its control thread, and the helper —
not this filter — drops that tunnel's kernel-path transport (#9521), because an
input-hook admit list cannot refuse `ct established` traffic, a zone that
admits all services, or anything when no table is installed.

Fail-on-revert guards: `TestHostInboundFilterAdmitsWireGuardListenPort`
and `TestHostInboundFilterWireGuardPayloadParses` (`pkg/daemon`),
`TestWireGuardListenPorts_5582` (`pkg/config`).
