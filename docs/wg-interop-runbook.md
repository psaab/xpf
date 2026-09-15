# WireGuard live interop runbook (#1736 / #1703 S2b)

Operator guide for the live kernel-WireGuard interop harness
`test/incus/wg-interop.sh`. The harness proves the S2a WireGuard datapath
(#1432, PR #1739) against an independent reference peer — the Linux kernel
WireGuard implementation in a Debian-13 incus instance on the shared loss
userspace cluster. `WG_PEER_TYPE=vm` (default) gives a fully independent
guest kernel; `WG_PEER_TYPE=container` is the plan §4 fallback (kernel
WireGuard is netns-aware, so the protocol/crypto stack is still the
reference kernel implementation — it runs in the loss HOST kernel, a
reduced but still independent-implementation claim). The 2026-06-11
validation used the container fallback because freshly created incus VMs
never bring up the agent on the loss host (images:debian/13 and /12;
pre-existing fw VMs unaffected).

Converged research plan: `docs/pr/1736-wg-interop/plan.md`
(PLAN-READY 3-of-3: Codex + AGY + Claude SMR, 2 rounds).

## Topology

```
loss:xpf-userspace-fw0 (node0, RG0 primary)
  ge-0-0-1 10.0.61.1/24 (LAN VIP, VLAN 3667)   <- WG outer endpoint
  wg0      10.78.0.1/24 + fd00:78::1/64        <- inner (persistent TUN)
loss:xpf-wg-peer (Debian-13 VM or container, kernel WireGuard)
  eth1 (mlx1 SR-IOV VF, VLAN 3667) 10.0.61.103/24 + 2001:559:8585:ef00::103
  eth0 (incusbr0) mgmt/apt
  wgref    10.78.0.2/24 + fd00:78::2/64        <- kernel wg device
```

WG outer transport: UDP 51820 over the VLAN-3667 LAN. Inner subnets:
`10.78.0.0/24`, `fd00:78::/64`. Constants: `test/incus/wg-interop.env`.

## Running

```bash
./test/incus/wg-interop.sh all            # full plan order, then teardown
./test/incus/wg-interop.sh all --keep     # keep the peer VM afterwards
# or stepwise:
./test/incus/wg-interop.sh preflight      # P0 + fast-path baseline
./test/incus/wg-interop.sh provision      # peer VM (idempotent)
./test/incus/wg-interop.sh configure      # keys + P1 initiator handshake
./test/incus/wg-interop.sh test p2        # p2 p4a p3 p4b p5 p6 p7 p8 | all
./test/incus/wg-interop.sh teardown
```

Evidence lands in `/tmp/wg-interop-<timestamp>/` (override with
`WG_EVIDENCE_DIR`). Standalone, every cluster command runs under
`flock /tmp/xpf-cluster.lock sg incus-admin`; long traffic runs detached
inside the instances so the lock is never held across a phase. Inside a
`test/incus/with-cluster.sh` lock cell (#1875) the per-command flock is
skipped — the cell already owns the cluster for the whole run. Do NOT
wrap this script in a raw outer `flock /tmp/xpf-cluster.lock` — that
deadlocks; use `with-cluster.sh`:

```
./test/incus/with-cluster.sh "1736 wg-interop" -- \
    env WG_PEER_TYPE=container ./test/incus/wg-interop.sh all
```

Phase order is `P0 P1 P2 P4a P3 P4b P5 P6 P7 P8` (P4a needs the
xpf-initiated session from P1; P4b needs the kernel-initiated session
from P3 — see plan §5.2; P8 needs P1's wg0 up as its single-tunnel
control — see ## P8 below).

## P8 — two steered listen ports (#9587)

`./test/incus/wg-interop.sh test p8` (also runs at the end of `all`).
Commits an ADDITIVE node0-scoped `interfaces wg1` stanza (distinct listen
port `:51821`, disjoint inners `10.78.1.0/24` + `fd00:78:1::/64`, same xpf
identity — no bind collision on distinct ports) with `wg1.0` joining the
existing `wg` zone; the peer gets a second kernel device `wgref2` with
per-device allowed-ips (TAI64N domains stay separate). Verifies: wg0
control still passes with wg1 present; wg1 v4+v6 both directions; per-tunnel
engine encap/decap growth with flat unsteered drops (steering-config +
liveness witnesses — never which path served the records).

- Programmed set: `bpftool map dump pinned
  /sys/fs/bpf/xpf/userspace_ctrl` — bytes 20..23 are the count (expect 2),
  bytes 24..39 the ports array in little-endian u16s (`6c ca` = 51820,
  `6d ca` = 51821), zero-filled past count. Count 0 with tunnels
  configured = the snapshot never programmed the set (check the commit
  applied).
- Per-tunnel engine counters (liveness, NOT worker-path proof — the control
  thread bumps the same engine): query the helper status socket on fw0 and
  read `wg_tunnels[]` (`tunnel`, `encap_packets`, `decap_packets`,
  `rx_unsteered_transport_drops`).
- Zone/session-level per-port policy proof stays outstanding for a live
  #10038 world; P8 asserts cryptokey-routing deny only.

## The restart runbook (TAI64N)

xpf's TAI64N handshake-timestamp high-water survives only in-process
until S6 adds disk persistence. **If the tunnel does not recover on
its own after an xpfd restart, flush the kernel peer's WG state** so
its per-peer TAI64N high-water is cleared:

```bash
ip link del wgref
ip link add wgref type wireguard
wg set wgref private-key ... listen-port 51820 peer <xpf-pub> allowed-ips ...
ip addr add 10.78.0.2/24 dev wgref && ip link set wgref up mtu 1420
```

(The harness's `peer_wg_setup` is exactly this procedure; P6 exercises
it when needed.) Note: xpf's TAI64N is wall-clock-derived, so with a
sane NTP clock a restart usually recovers WITHOUT the flush
(post-restart timestamps are naturally higher). The flush guards the
backwards-clock-step / same-whitened-tick edge.

**Peer-flush ordering note (historical severity downgraded by #1888).**
Before the S5 timers shipped, a confirmed engine never re-initiated, so
wiping the peer's state under a live session manufactured a
confirmed-but-dead blackhole. Since #1888 the 15s no-reply reinit (T7)
and the 180s expiry + rekey machinery repair that state automatically
within seconds; the harness's flush-BEFORE-commit ordering and the P6
no-flush-first branch are retained as obsolete-but-harmless (they also
keep the runbook valid against pre-#1888 builds).

## Mandatory: node0 scoping of the WG stanza

The cluster config is synced to both nodes and the SECONDARY also
carries `10.0.61.1/24` on its LAN interface. The wg0 stanza MUST live
under `groups node0` (the canonical config applies
`apply-groups "${node}"`), or fw1 would run a WG control thread with the
SAME static identity: its initiations would never complete (handshake
responses go to the VRRP master's MAC), retry every 1 s forever, and
ratchet the peer's TAI64N high-water against fw0 (intermittent
replay-rejection of fw0's own re-handshakes). The harness asserts at P1
that fw1 has neither a `wg0` netdev nor a `:51820` bind, and fails hard
("BLOCKING finding") if scoping ever stops compiling.

## wg0 peer config shape (harness commit path)

The harness commits the xpf side as an apply-group (`groups node0`) so
the stanza is node0-scoped (see above). Under the #1434 multi-peer
schema the WireGuard **peer is a named instance keyed by its public
key** — the pubkey IS the instance arg, there is no `public-key` child
leaf:

```
set groups node0 interfaces wg0 tunnel wireguard private-key <64-hex>
set groups node0 interfaces wg0 tunnel wireguard peer <64-hex-pubkey> allowed-ips 10.78.0.0/24
set groups node0 interfaces wg0 tunnel wireguard peer <64-hex-pubkey> allowed-ips fd78::/64
set groups node0 interfaces wg0 tunnel wireguard peer <64-hex-pubkey> endpoint <ip>:51820
```

Keys are **hex** in the xpf config but `wg genkey`/`wg pubkey` emit
**base64**, so the harness converts base64→hex (`base64 -d | od -An
-tx1`) before the commit and asserts a 64-hex length. An earlier
`peer public-key <hex>` form (a pre-#1434 grammar) drifted from this
schema: it committed a bogus peer literally named `public-key`, which
the commit check rejected with `peer 0 has an invalid public key (got
"public-key")` — the #6279 harness bit-rot. `test/incus/wg-interop.sh`
fails fast if the captured key is not 64 hex chars before it commits.

### wg0 host-inbound zone — REQUIRED for peer-initiated inner traffic (#6279 P2)

The same commit ALSO puts `wg0.0` in a node0-scoped security zone that
permits host-inbound ping:

```
set groups node0 security zones security-zone wg interfaces wg0.0
set groups node0 security zones security-zone wg host-inbound-traffic system-services ping
```

Why it is mandatory: a decap'd WireGuard **inner** packet is written to
the `wg0` TUN and firewalled by the **kernel** nftables `xpf_hostinbound`
chain (the #3070 host-inbound-traffic enforcement — dst-address keyed,
grouped by zone; the AF_XDP inner-src AllowedIPs gate in `try_decap` is a
separate check). #3070 landed 2026-06-25, 15 days AFTER this harness was
first written, so the original config left `wg0` in NO zone. Under
enforcement an addressed-but-unzoned interface's firewall-local address
falls into the #4420 HI-2 catch-all DROP, so a **peer-initiated** inner
ping to the xpf `wg0` address (`10.78.0.1` / `fd00:78::1`) is dropped —
this was the #6279 P2 failure (`peer->xpf inner v4 ping failed`).
`xpf->peer` still worked because the reply rides the chain's leading
`ct state established,related accept`, which is what made the drop look
one-directional.

The dedicated `wg` zone moves the inner v4+v6 addresses into a zoned
`icmp/icmpv6 type echo-request accept`, mirroring how the base cluster
config already zones the `gr-0/0/0.0` GRE tunnel in `security-zone sfmix`
with `host-inbound-traffic system-services ping`. The zone is
node0-scoped (fw1 never compiles it — same secondary-suppression
discipline as the wg0 stanza) and is created/deleted **as a pair** with
`wg0` in the same commit: a zone naming an undefined interface is a
strict commit reject (#5248), so `xpf_wg_commit` adds both and
`wg_stanza_delete` + `teardown` delete both.

## Known S-step limitations the operator will observe

| Observation | Cause | Owner |
|---|---|---|
| xpf never sends keepalives; one-way traffic makes the kernel peer re-handshake every ~25 s | persistent-keepalive timer unimplemented (config field is plumbed, ignored) | S5 |
| xpf never initiates time-based rekey; on an xpf-initiated session the tunnel recovers via the peer's expiry-driven re-handshake at REJECT_AFTER_TIME (~180 s) with a small bounded gap | REKEY/REJECT timers unimplemented | S5 |
| brief egress drop right after a peer-initiated rekey | stricter-than-spec unconfirmed-responder TX gate (`engine.rs` try_encap; no `peer.previous` TX fallback) — ms-scale vs kernel wg | file if >1 s measured |
| keys are hex in xpf config, base64 in `wg` | minimal S2a grammar | S6 (#1434) |
| ~~no `wg show`-equivalent / WG counters on the xpf side~~ | RESOLVED by #1865: `show security wireguard [detail]` + `xpf_userspace_wg_*` Prometheus family + `wg_tunnels` status rows | done (#1865) |
| responder under an init-flood answers valid-MAC1 initiations with a type-3 CookieReply + validates MAC2 before the Noise handshake | #4094 PR-A responder DoS mitigation (whitepaper §5.4.7) — intended | done (#4094 PR-A) |
| INBOUND cookie (type 3) messages still dropped (`hs_rx_cookie_unsupported`); xpf-as-initiator cannot complete against a peer that is itself under load | initiator-side CookieReply consume unimplemented | PR-B (#4094) |
| PSK must be absent/zero on the peer | PSK plumbing unimplemented | S4 |
| WG tunnel removed from config keeps the persistent wgN TUN link (by design — tearing it flaps the device + live peer) but now PRUNES the kernel addresses this manager applied (#1919), so they no longer route; the kernel connected route (and any FRR direct→connected redistribution of it) goes with the address | link kept = S2a persistent-TUN tradeoff; address prune fixed in #1919 | link teardown S6 (#1434); harness teardown still `ip link del`s the persistent link |
| WG tunnel removed while the daemon was DOWN is not address-pruned on the next start | restart-adoption: the manager only prunes WG addresses it tracked applying | S6 (#1434) restart-time WG reconcile |
| WG tunnel removed from config does NOT unbind its VRF master | WG binds VRF directly, bypassing the appliedRI claim machinery (same root cause as no-unbind-on-routing-instance-removal for a still-configured WG tunnel) | S6 (#1434) VRF-claim adoption for WG |
| failover during WG = tunnel outage until fw0 preempts back | WG engine state is per-node, not HA-synced; wg0 is node0-scoped | S8 |

## >MTU / fragmentation semantics (P5)

- peer→xpf with peer `wgref` MTU raised to 1500: inner 1500 B encaps to a
  1560 B outer; kernel wg sends outer with DF=0 → on-wire IPv4
  fragmentation. At xpf, fragment 1 reaches the kernel via the shim WG
  port gate; fragment 2 (no UDP header) reaches the kernel via the
  session-miss local-destination fallback — kernel reassembly then feeds
  the control-thread socket, so **clean success is the expected
  outcome**; a clean drop is acceptable; a wedge is a failure.
- xpf→peer oversize: the wg0 TUN MTU (≈1425, computed as
  1500 − overhead − worst-case pad) makes the kernel fragment the INNER
  packet; each fragment encaps independently and the peer reassembles
  after decap — deterministic success.

## Shared-cluster hazards observed live (2026-06-11 validation)

- **Concurrent agents commit on this cluster.** Any foreign commit that
  does a config replace/rollback (CoS sweeps and similar loops commit
  every ~75 s when active) WIPES the wg0 stanza mid-run: the dataplane
  snapshot loses the endpoint, the coordinator stops the WG control
  thread, and the tunnel dies at a random point in a phase — observed
  as a P4a tail blackout that was NOT a WireGuard bug. Before a run,
  check `/etc/xpf/.config.journal` on fw0 is quiet; if a phase dies
  mid-run, re-check it before triaging the engine.
- **The WG outer VIP is the real mastership predicate.** After any
  xpfd restart/deploy, fw0 comes up SECONDARY on ALL redundancy groups
  (preempt off) and 10.0.61.1 is removed from ge-0-0-1; the kernel then
  fails every WG send with a SILENT EINVAL (no route/source — visible
  only via strace or the RecentExceptions ring, #1865), so the tunnel
  looks dead-air while `show chassis cluster status` can still read
  "node0 primary" for RG0. The engine itself is fine: it keeps
  initiating at 1/s and handshakes within seconds of the VIP returning
  (root-caused live 2026-06-11). The harness gates every phase on
  `ensure_wg_mastership` (VIP-present check + all-RG failback); when
  driving manually, fail back EVERY RG, not just RG0:
  `request chassis cluster failover redundancy-group <0|1|2> node 0`.
  This mechanism also retro-explains the earlier "first commit after a
  daemon start brings the engine up late" observation.
- **Config removal leaks the control thread + port** (#1866): the
  harness preflight self-cleans the leaked TUN and P1 restarts xpfd if
  the listen port is still pinned with no stanza present.

## Failure triage

0. **Start with the local counters (#1865)** — `show security
   wireguard detail` on fw0 (or the `xpf_userspace_wg_*` Prometheus
   family) is now the PRIMARY oracle; the peer-side `wg show` and
   tcpdump steps below are cross-checks, not first resort:
   - initiations created ↑ + `handshake-send` I/O errors ↑ +
     completions flat = the silent-send class (the #1736 EINVAL bug).
   - `mac1-mismatch` ↑ = key mismatch (wrong/garbled peer key).
   - handshakes complete but transmit drops `mtu-exceeded` ↑ = the
     pad-aware MTU guard (the #1736 v4-mapped blackhole class).
   - transmit drops `unconfirmed-session` ↑ = transient responder
     key-confirmation window (expected blip at rekey, not a fault).
   - receive drops `allowed-ips-violation` ↑ = inner-source gate
     (triage step 3).
1. P1 no handshake: tcpdump UDP 51820 on the peer — msg1 arriving?
   If NOTHING leaves fw0, strace the `xpf-wg-control-` thread for
   `sendto` errors (the dual-stack v4-mapped send bug fixed in this PR
   showed exactly one silent EINVAL per initiator tick — now also
   visible without strace as `hs_send_errors` per triage step 0).
   xpf side: `journalctl -u xpfd | grep -i wg`, check the wg0 TUN exists
   and `:51820` is bound on fw0; check the peer's `wg show wgref` for
   key mismatch (hex↔base64 conversion).
2. wg0 TUN missing after commit: the daemon-side collect gate — see the
   #1736 fix in `pkg/daemon/daemon_run.go` (`collectAppliedTunnels`
   wireguard exemption); confirm the deployed build includes it.
3. Handshake but no transport: AllowedIPs mismatch (xpf decap gates
   inner SOURCE against the peer's allowed-ips in the xpf config).
3a. `peer->xpf` inner ping fails while `xpf->peer` inner ping SUCCEEDS
   (the #6279 P2 signature): `wg0` is not in a host-inbound zone. The
   decap'd inner packet is dropped by the kernel `xpf_hostinbound` chain
   (#3070) because the wg0 inner address is addressed-but-unzoned (#4420
   HI-2 catch-all DROP); `xpf->peer` survives on the chain's leading
   `ct state established,related accept`. Fix: `wg0.0` needs a security
   zone with `host-inbound-traffic system-services ping` (the harness
   commits one — see "wg0 host-inbound zone" above).
4. P4a blackout after ~180 s: should self-heal within ~15 s since the
   #1888 S5 timers (T7 no-reply reinit / expiry-driven rekey) — a
   PERMANENT blackout is now a regression; capture
   xpf_userspace_wg_rekeys_initiated_total + sessions_expired and file
   it.
5. Cluster unhealthy / VIP not on fw0: the WG outer VIP follows the
   reth's OWN redundancy group (NOT RG0), and config commits need RG0
   primaryship — fail back EVERY RG:
   `request chassis cluster failover redundancy-group <id> node 0`.

## Teardown guarantees

Teardown removes the config stanza, deletes the leaked `wg0` TUN,
verifies BOTH nodes have no `wg0` and no `:51820` bind, deletes
`xpf-wg-peer` (unless `--keep`), and re-checks the fast path. If a run
dies mid-phase, `./test/incus/wg-interop.sh teardown` is safe to run
standalone (idempotent).
