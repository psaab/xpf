# SYN Cookie Flood Protection

## Overview

When `security flow syn-flood-protection-mode syn-cookie` is configured, SYN
floods trigger cookie-based source validation in XDP instead of dropping all SYNs
indiscriminately. Legitimate sources pass after a single extra round-trip;
spoofed sources fail validation. Once validated, a source has zero per-packet
overhead for subsequent connections during the flood — the whitelist is keyed
on the client and service, not on one ephemeral port, and survives being read
(see "Whitelist scope and lifetime (#9419)").

**Commit:** `8cbf31a`

## Configuration

```
set security flow syn-flood-protection-mode syn-cookie
set security screen ids-option SCREEN tcp syn-flood alarm-threshold 512 attack-threshold 1024
set security zones security-zone untrust screen SCREEN
```

The `syn-flood-protection-mode` is a global flow setting. The per-zone screen
`syn-flood` thresholds control when the mode activates. When the threshold is
exceeded:

- **Without syn-cookie mode:** SYNs are dropped (existing behavior)
- **With syn-cookie mode:** SYNs trigger the cookie challenge instead of being dropped

### Default attack-threshold (#3024)

Matching Junos SRX, a `tcp syn-flood` screen that is enabled WITHOUT an
explicit `attack-threshold` arms at the default of **200 SYN segments/second**.
Configuring syn-flood with only `destination-threshold`, `source-threshold`,
`alarm-threshold`, or `timeout` (no `attack-threshold`) still enables the
screen — and the nested syn-cookie challenge — at that default rate. The
config compiler seeds the default at parse time
(`defaultSynFloodAttackThreshold` in `pkg/config/compiler_security.go`); the
dataplane gate in `pkg/dataplane/compiler_iface.go` (`buildScreenConfig`)
applies the same default defensively. Previously the dataplane gate required
`AttackThreshold > 0`, so an unset attack-threshold silently left SYN-flood
protection disabled even when configured.

### Default thresholds for the other rate/scan screens (#3230)

The Rust screen engine (`userspace-dp/src/screen/mod.rs`, `scan.rs`) gates
icmp-flood, udp-flood, tcp port-scan, and ip ip-sweep on `threshold > 0`. Like
syn-flood before #3024, these checks had NO default: enabling one without an
explicit threshold compiled to 0 and the check was silently skipped. The config
compiler now seeds a Junos-aligned default at parse time
(`pkg/config/compiler_security.go`) for each ENABLED-but-unset check. An
explicit threshold is always preserved, and a check that is not configured stays
off (threshold 0).

| Screen check        | Default | Junos basis |
|---------------------|---------|-------------|
| `icmp flood`        | 1000    | Junos `icmp flood threshold` default of 1000 pps |
| `udp flood`         | 1000    | Junos `udp flood threshold` default of 1000 pps |
| `tcp port-scan`     | 10      | Junos flags a port scan at 10 distinct destination ports |
| `ip ip-sweep`       | 10      | Junos flags an address sweep at 10 distinct destination addresses |

Note on the scan/sweep defaults (#4114): Junos expresses the port-scan /
ip-sweep `threshold` as a MICROSECOND time WINDOW (default 5000) within which
10 distinct ports / addresses trigger detection. xpf now matches this: the
`threshold` is the detection window in microseconds and the detection COUNT is
the fixed `SCAN_DETECT_COUNT` (10) in `scan.rs`. The default is 5000 (the Junos
default window). Before #4114 xpf had these swapped — a configurable COUNT over
a hard-coded 10-second window — so a copied Junos `threshold 5000` was misread
as a count and clamped to never-fire, while the default-armed sweep false-
dropped normal browsing. The compiler emits a commit-time advisory
(`validateScreenScanSweepWindows`) when a value falls outside the Junos
[1000, 1000000] microsecond range, catching count-shaped legacy values.

### ICMP / UDP flood are measured PER DESTINATION (#4112)

Junos `icmp flood threshold N` caps the ICMP rate to a single DESTINATION IP, and
`udp flood threshold N` caps the UDP rate to a destination IP AND port; traffic to
different destinations counts INDEPENDENTLY. Before #4112 the Rust engine keyed
the ICMP/UDP flood counters by ZONE NAME only (`icmp_counters` / `udp_counters`,
`screen/mod.rs`), a per-zone AGGREGATE. That both false-dropped legitimate traffic
(two high-volume services in one zone — a DNS resolver + VoIP — SUM into one
counter and cross the threshold though no single destination is flooded) and let
an attacker spread a modest flood across many destinations while no single victim
was rate-limited as the operator expected.

#4112 gives ICMP/UDP flood the same per-destination substrate the SYN-flood path
grew in #3315 — the no-eviction count-min `SynRateSketch` (`syn_rate.rs`), reused
via `SynRateSketch::increment` (ICMP, keyed on `dst_ip`) and `increment_ip_port`
(UDP, keyed on `dst_ip` + `dst_port`):

- **PRIMARY per-destination cap** — the configured `threshold` is enforced per
  destination (ICMP) / per destination IP+port (UDP). A single flooded
  destination is still capped; distinct destinations no longer sum. The sketch is
  allocated per zone that configures the threshold (`icmp_dst_sketch` /
  `udp_dst_sketch`, `ROWS*DST_COLS*16 = 64 KiB` each, mirroring the #3315 per-dest
  sizing) and freed when the threshold is removed.
- **SECONDARY per-zone ceiling** — the per-zone ICMP/UDP flood aggregate
  (the `icmp_counter` / `udp_counter` `TokenBucket` fields on `ZoneScreenState`
  since #4969; the former standalone `icmp_counters` / `udp_counters` maps) is
  retained as a coarse zone-saturation backstop at
  `SECONDARY_FLOOD_CEILING_MULT × threshold` (currently 8×). It counts only
  per-destination-ADMITTED packets (the per-destination check short-circuits
  first), so it bounds the admitted zone-wide rate and still caps a flood spread
  thin across many under-threshold destinations — an operator relying on the
  zone-wide cap still gets it. There is no separate Junos knob for this ceiling,
  so it is derived from the single configured per-destination threshold.

Both the flow-present (`check_packet_with_zone_id`) and the flowless
(`check_flowless_screens`, non-first fragment / non-query ICMP) paths share the
`icmp_flood_drop` / `udp_flood_drop` helpers so a fragment-based flood cannot
evade the per-destination cap. A flowless non-first fragment carries no L4 port,
so the UDP cap degrades to per-destination-IP there (the best available for a
fragment).

The two paths also agree on the missing-screen-profile signal (#3082/#3908):
each None branch calls `maybe_warn_missing_profile`, so a zone that references a
screen profile undefined at snapshot-build time emits the same rate-limited
runtime WARN whether the packet is flow-bearing or flowless, while a zone with
no screen configured passes silently on both. The verdict stays `Pass` in both
cases (watch-log-only; the fail-closed-vs-pass posture is the deferred #3082
design decision).

### SYN-flood sub-thresholds: source / destination / alarm / timeout (#3315)

The Go compiler parses the full Junos `tcp syn-flood` shape (alarm/attack/
source/destination/timeout) into `config.SynFloodConfig`, but before #3315 only
`attack-threshold` crossed the userspace-dp wire — the four sub-thresholds
committed cleanly yet were operationally inert (the dataplane enforced only the
aggregate per-zone SYN counter). A config that appeared to cap per-source or
per-destination SYNs did nothing.

#3315 wires three of them across the boundary and enforces them in the Rust
screen runtime:

- **`destination-threshold`** — per-destination-IP SYN/s cap. PRIMARY,
  spoof-resistant: every SYN to a victim lands in the same sketch cells, so a
  hot destination trips regardless of how the sources are spread (or spoofed).
  It runs even when the zone is SYN-cookie active (a cookie-completing
  distributed flood must not evade `destination-threshold`).
- **`source-threshold`** — per-source-IP SYN/s cap. SECONDARY/best-effort.
  Skipped while the zone is SYN-cookie active (the cookie governs the
  high-cardinality spoofed-flood regime, where per-source is spoof-defeated and
  the sketch would over-throttle); confined this way to the sub-aggregate regime
  where source cardinality is bounded and the sketch is accurate.
- **`alarm-threshold`** — log-only rate below `attack-threshold`. Crossing it
  raises an out-of-band, ≤1/sec/zone screen ALARM event (RT_FLOW PERMIT, NOTICE
  severity, reason `syn-flood-alarm`) WITHOUT dropping the packet, like the
  scan-table-pressure alarm.
- **`timeout`** — ENFORCED (#3527; the #3315 tracked follow-up). It is NOT a
  screen-rate control: it maps to the per-zone half-open TCP session window
  (`SessionTimeouts.tcp_opening_ns`, 20 s default — the Junos
  half-completed-connection queue). `timeout N` now crosses the wire
  (`ScreenProfileSnapshot.syn_flood_timeout`, seconds) and the forwarding
  builder turns it into a per-ingress-zone override of `tcp_opening_ns`
  (`ForwardingState.session_opening_overrides` →
  `SessionTable::set_opening_overrides`). A bare-SYN (OPENING / half-open)
  session in a screened zone is then reaped on `N` seconds instead of the
  global 20 s default — so a flood that stops is forgotten on the operator's
  window, and a half-open never lingers longer than the configured queue
  bound. `session_timeout_ns` consults the override ONLY on the OPENING branch
  (never the established / closing / RST windows). HA composition (#3315 plan
  §11.1): the override is config-derived and re-derived per node from the
  snapshot — it does NOT travel on the session-sync wire. A peer-synced session
  is imported ESTABLISHED, so its OPENING branch is never taken, and identical
  config on both nodes yields the same map independently. The #3315 commit-time
  "accepted but NOT yet enforced" WARNING is removed now that the leaf is
  effective.

Enforcement order (`ZoneScreenState::syn_flood_gate` in `screen/zone.rs`
since #6437 — previously inlined in `screen/mod.rs`; the caller
`check_packet_with_zone_id_opts` runs the validated-cookie bypass first and
applies the returned `SynFloodGate` verdict): (1) the aggregate `attack-threshold` (+
`alarm-threshold`) ALWAYS counts via a single `RateCounter::increment_and_classify`
so its cookie-activation side-effect can never be skipped — it does NOT return
here; (2) the per-destination cap is evaluated BEFORE the aggregate over-attack
verdict (#4112 F19), so a per-destination trip HARD-DROPS the flooded victim even
while the zone is over `attack-threshold` and minting cookies for validated
clients; (3) the aggregate over-attack verdict then mints the SYN-cookie
challenge (or Drops when cookies are disabled) for the case where the per-dest
cap did not trip — `attack` keeps its existing cookie-mint / Drop behaviour;
(4) per-source cap (gated, skipped while cookie-active). Before #4112 the
per-destination sketch sat AFTER the over-attack early-return, so a real-client
flood that pushed the zone over `attack-threshold` took the cookie-mint branch on
every SYN and the per-destination sketch was NEVER reached — the
`destination-threshold` that exists to shield a single victim even from validated
clients was defeated in exactly the high-load regime it is configured for (a
code-vs-comment contradiction). A per-IP trip hard-drops with the existing
`syn-flood` reason id (no Go gRPC/CLI change); per-source vs per-destination is
distinguished by separate per-worker counters.

Substrate (`userspace-dp/src/screen/syn_rate.rs`): a per-zone **count-min sketch**
generic over its per-cell limiter (`SynRateSketch<C>`) — `ROWS=4` independent
seeded-hash rows × `DST_COLS=1024` / `SRC_COLS=2048` columns — with **no
eviction**. The SYN per-source/per-destination sketches use count-all
`RateCounter` cells (this section); the #5805 ICMP/UDP per-destination flood
sketches use monotonic-ns `TokenBucket` cells (see the #4112 section above). A
key always counts in its
`ROWS` cells and trips ⟺ ALL cells are over threshold (the CMS `min` read,
implemented as the AND of the per-row results, never OR/MAX). No eviction means
no Hot-Set-Lockout / Cold-Start-Eviction-Race starvation (a victim is always
tracked and its cells only increase within the sliding window). Collisions can
only OVER-count (fail-closed: never a false-negative; the only error is a
false-positive bounded by `~(load)^ROWS`).

**Per-boot seeded cell hash (#4382).** The `ROWS` row hashes fold in a per-boot
secret seed (`SynRateSketch::seed`, drawn once from
`hot_hash_seed::hot_path_hash_seed` — the same #2364 per-process secret the
session indices / flow-cache set index / ECMP / CoS SFQ hashes use) ALONGSIDE
the public per-row `ROW_SEEDS`. The row constants give row INDEPENDENCE; the
per-boot seed gives SECRECY. Without it, `cell_index`/`cell_index_ip_port` would
be a public deterministic function of the source IP, so an off-box attacker
(within their own BCP38-permitted range) could precompute which source IPs land
in a chosen victim's four cells and drive them over `source-threshold` to
throttle the victim's legitimate SYNs — a targeted false-positive. Folding the
per-boot seed makes the source→cell mapping unknowable offline and reshuffles it
on every restart, so no colliding source-IP set can be constructed. The seed is
stable for the process lifetime (a key maps to a stable cell across its whole
window — counting behaviour, thresholds, and detection are unchanged) and is
node-local (never wire/HA-synced; each node reseeds independently).

Each sketch is allocated PER
THRESHOLD, not unconditionally: the per-destination sketch only when
`destination-threshold > 0`, the per-source sketch only when
`source-threshold > 0`, and each is freed when its threshold is removed. An
**alarm-only** profile (`alarm-threshold` set, no source/destination cap)
allocates NEITHER sketch — only the tiny per-zone `syn_alarm_last_emit_sec`
cadence timestamp.

**Per-zone state consolidation (#4969).** These sketches, the SYN aggregate
counter, the SYN-cookie active-until / standby-budget / profile-generation
fields, and the ICMP/UDP flood aggregates + per-destination sketches ALL live in
one `ZoneScreenState` value per zone, stored in a single
`FxHashMap<String, ZoneScreenState>` (`ScreenState::zones` in
`userspace-dp/src/screen/mod.rs`; the `ZoneScreenState` type itself lives in
`userspace-dp/src/screen/zone.rs` since #6437) — not the ~13 parallel `FxHashMap<String, _>`
tables that preceded #4969. A `ZoneScreenState` is built by
`ZoneScreenState::from_profile`, which allocates every threshold-gated sub-state
together (`Some ⟺ configured` for the sketches). The two consequences: a
configured limiter can NEVER be silently missing on the screened path (the
pre-#4969 fail-open where a missed prepopulation step left a table entry absent
and the `if let Some(sketch)` check fell through to Pass), and a screened packet
does ONE `zones` lookup instead of re-hashing the zone name into each table.
`update_profiles` rebuilds `zones` on reconfigure, carrying over each persisting
zone's in-flight counters and reconciling its threshold-gated sub-state
(`ZoneScreenState::reconcile_substate`) — the same allocate-on-enable /
free-on-disable / preserve-across-unrelated-edit behaviour as before. The
global SYN-cookie codec, validated cache, and epoch cache stay separate
`ScreenState` fields (they are cross-zone, keyed by `zone_id`), as do the per-IP
scan/sweep trackers and the `missing_profile_*` bookkeeping. String zone-name
keys are retained; numeric zone-id keying is deferred to #4421.

Memory (per worker): `RateCounter` ≈ 16 B. The per-destination sketch costs
`ROWS*DST_COLS*16 = 64 KiB` and is allocated only when `destination-threshold`
is set; the per-source sketch costs `ROWS*SRC_COLS*16 = 128 KiB` and is
allocated only when `source-threshold` is set. A zone that configures BOTH caps
costs the **192 KiB/zone** worst case × num_workers; a zone with only one cap
costs just that cap's table; an alarm-only zone costs neither (a single `u64`).
The Go compiler emits a commit-time advisory when `attack-threshold /
source-threshold` exceeds ~1000 (the only regime where the per-source sketch can
false-throttle legitimate sources under a sub-aggregate spoofed spread).

Wire: `ScreenProfileSnapshot` gains `syn_flood_alarm_threshold`,
`syn_flood_dst_threshold`, `syn_flood_src_threshold` (Go
`pkg/dataplane/userspace/protocol.go`; Rust `userspace-dp/src/protocol/
security.rs`). All three are additive with `omitempty` (Go) / `#[serde(default)]`
(Rust), so a control plane / helper missing them decodes 0 (disabled) and version
skew degrades safely (#1961). `timeout` is intentionally NOT serialized. The
`protocol_wire_v1.json` fixture was regenerated (`XPF_PROTOCOL_WIRE_REGEN=1`,
additive-only — three new fields, zero drift on existing).

## Algorithm

```
SYN flood detected (rate > threshold)
  → Zone enters synproxy_active mode
  → Unvalidated SYN arrives
    → Check validated_clients LRU map
      → Hit: bypass cookie challenge (SCREEN_SYN_COOKIE counter incremented)
      → Miss:
        1. Generate SYN-ACK with cookie seq via bpf_tcp_raw_gen_syncookie_ipv4/v6
        2. XDP_TX the SYN-ACK back to sender
        3. Legitimate client responds with ACK containing cookie
        4. validate_syncookie checks ACK via bpf_tcp_raw_check_syncookie_ipv4/v6
        5. On success: whitelist the CLIENT (src_ip, dst_ip, dst_port — NOT
           the ephemeral source port), send RST
        6. Client reconnects (a new ephemeral port) → passes as validated →
           normal session creation

SYN rate drops below threshold/2 in a new window
  → synproxy_active deactivated
  → All SYNs pass through normally again
```

## BPF Implementation

### Kernel Helpers Used

| Helper | ID | Since | Purpose |
|--------|----|-------|---------|
| `bpf_tcp_raw_gen_syncookie_ipv4` | 204 | 5.19 | Generate IPv4 SYN cookie |
| `bpf_tcp_raw_gen_syncookie_ipv6` | 205 | 5.19 | Generate IPv6 SYN cookie |
| `bpf_tcp_raw_check_syncookie_ipv4` | 206 | 5.19 | Validate IPv4 SYN cookie |
| `bpf_tcp_raw_check_syncookie_ipv6` | 207 | 5.19 | Validate IPv6 SYN cookie |

### BPF Maps

| Map | Type | Size | Purpose |
|-----|------|------|---------|
| `validated_clients` | LRU_HASH | 65536 | Tracks sources that passed cookie validation |
| `flood_counters` | (existing) | per-zone | Extended with `synproxy_active` field |

### BPF Functions (all `__noinline` for stack budget)

| Function | File | Purpose |
|----------|------|---------|
| `send_syncookie_synack_v4` | xdp_screen.c | Build and TX SYN-ACK with cookie (58 bytes) |
| `send_syncookie_synack_v6` | xdp_screen.c | Build and TX SYN-ACK with cookie (78 bytes) |
| `validate_syncookie_v4` | xdp_screen.c | Validate ACK, whitelist source, send RST (54 bytes) |
| `validate_syncookie_v6` | xdp_screen.c | Validate ACK, whitelist source, send RST (74 bytes) |

### Global Counters

| Counter | ID | Description |
|---------|----|-------------|
| `GLOBAL_CTR_SYNCOOKIE_SENT` | 27 | SYN-ACK cookies generated and sent |
| `GLOBAL_CTR_SYNCOOKIE_VALID` | 28 | ACKs with valid cookies (source whitelisted) |
| `GLOBAL_CTR_SYNCOOKIE_INVALID` | 29 | ACKs with invalid cookies (not a cookie response) |
| `GLOBAL_CTR_SYNCOOKIE_BYPASS` | 30 | SYNs that bypassed challenge (already validated) |

### Screen Flag

`SCREEN_SYN_COOKIE` (1<<14) is set in the zone's `screen_config.flags` when
syn-cookie mode is configured. The `check_flood()` function in xdp_screen.c
checks this flag to decide between drop mode and cookie mode.

## Go Implementation

| Component | Change |
|-----------|--------|
| `pkg/config/types.go` | `FlowConfig.SynFloodProtectionMode` field |
| `pkg/config/compiler.go` | Parses `syn-flood-protection-mode syn-cookie` |
| `pkg/dataplane/compiler.go` | Sets `ScreenSynCookie` flag on screen config |
| `pkg/dataplane/types.go` | `ScreenSynCookie` constant |
| `pkg/api/metrics.go` | 4 Prometheus metrics (`xpf_screen_syncookie_total`) |
| `pkg/dataplane/userspace/protocol.go` | Userspace `BindingStatus` SYN-cookie counters |
| `pkg/cli/cli_show_security.go`, `pkg/grpcapi/server_show.go` | Userspace counters in screen statistics display |

## Userspace Dataplane Status and HA Propagation

The userspace dataplane reports per-binding SYN-cookie counters in
`BindingStatus`:

| JSON key | Meaning |
|----------|---------|
| `syn_cookie_challenges` | SYNs that entered the userspace challenge path |
| `syn_cookie_secret_unavailable` | Challenge attempts that failed closed because no SYN-cookie secret was published |
| `syn_cookie_syn_ack_sent` | SYN-cookie SYN-ACK replies admitted to the bounded local TX queue |
| `syn_cookie_ack_rst_sent` | RST replies admitted after a returning ACK validates |
| `syn_cookie_reply_budget_drops` | Cookie replies dropped to preserve forwarding TX headroom |
| `syn_cookie_ack_valid` | Session-miss ACKs that validated against a minted cookie |
| `syn_cookie_ack_invalid` | Session-miss ACKs that did not validate |
| `syn_cookie_bypass` | SYNs admitted from the local validated-client cache |

`syn_cookie_syn_ack_sent`, `syn_cookie_ack_valid`,
`syn_cookie_ack_invalid`, and `syn_cookie_bypass` are propagated as deltas into
the daemon's BPF-compatible global counters. Secret-unavailable and
reply-budget drops remain userspace-local diagnostics because they describe
helper-local fail-closed and backpressure conditions. The validated-client cache
is local, but the snapshot-published key is derived from cluster-synced root
encrypted-password material so peers with the same committed config can
validate cookies minted by the former active node inside the current,
previous, or next Unix wall-clock epoch overlap. The next-epoch candidate keeps
failover stable when peer clocks straddle a 64-second boundary. The epoch input
MUST be Unix wall-clock seconds (not `CLOCK_MONOTONIC`), since peers share only
the NTP-synced wall clock — their monotonic bases are unrelated. To avoid an OS
clock read on every minted/validated cookie under a flood (#3032), the helper
reads `SystemTime::now()` at most once per monotonic second
(`ScreenState::current_syn_cookie_full_epoch`, gated by the batch-cached
monotonic second already threaded into the screen check) and caches the derived
wall-clock seconds; every cookie in the same second reuses the cached value
because they all map to the same 64-second epoch. The epoch leaf
(`SynCookieCodec::current_full_epoch`) is a pure function of the supplied
seconds and never touches the clock. A standby peer
accepts a valid cookie ACK even when it has not locally observed the flood
threshold; ACKs outside the transmitted-epoch window are prefiltered before
SipHash, and plausible standby ACKs are rate-limited per zone. That limiter is
a monotonic-nanosecond **token bucket** (`screen/rate.rs::TokenBucket`, #3607;
capacity = refill = the per-second budget): it admits a legitimate returning
client parked at exactly the budget rate — critical right after a failover,
when the two-bucket sliding-window counter it replaced throttled such clients
to ~0 until a fully idle second (the #3607 over-throttle) — while a
sub-millisecond boundary straddle still sees at most `budget` tokens, so an
attacker cannot double the plausible-ACK validation budget across a wall-second
boundary (#2937 preserved). The same token bucket is the drop authority for the
ICMP/UDP flood per-zone aggregates, for the #5805 ICMP/UDP per-DESTINATION flood
sketch cells (`SynRateSketch<TokenBucket>`, `for_flood_dst` — a sustained
at-threshold destination must stay admitted, the same shaper argument as the
aggregate), and for the SYN-flood aggregate DROP path when `syn-cookie` is OFF
(with no cookie to bypass, a sustained-at-threshold legitimate SYN stream must be
admitted, so the bucket — not the count-all counter — is the sole drop gate on
every initial SYN). The SYN-flood aggregate that ACTIVATES cookies when
`syn-cookie` is ON, the alarm-threshold arrival-rate measurement, and the #3315
per-source/per-destination SYN sketch deliberately stay on the count-all
sliding-window `RateCounter`: there "admitted" means "skip a security response"
(the cookie challenge, the alarm, the per-IP cap), so the sustained-at-threshold
over-throttle is protective or benign rather than a bug (see `screen/rate.rs` and
`docs/research/3607-screen-rate/plan.md`).
Invalid ACKs outside a local active flood window remain ordinary session-miss
traffic instead of being counted as cookie failures.

The validated-client cache is keyed by `(zone_id, profile_generation, 4-tuple)`
(#2446). Each zone carries a SYN-cookie profile generation that is bumped
whenever a SYN-cookie-relevant profile field changes — the `syn-cookie`
enable/disable toggle or the `syn-flood` threshold, plus the zone gaining or
losing a profile (how a zone→profile rebinding manifests). The current
generation is stamped into an entry on insert and compared on consume: an entry
from an older generation is treated as a cache miss and the connection is
re-validated under the new profile, so the new profile's SYN-flood counter sees
it. This closes the window where a master-key-stable profile edit let a tuple
validated under the old profile bypass the new profile's flood gate until the
cache TTL expired. The master-key-rotation clear (`set_hash_keys`) remains as
defense in depth, and unrelated profile edits (e.g. stateless screens,
scan/sweep thresholds) do NOT bump the generation, so they cause no
re-validation churn.

If that secret material is
absent, userspace
omits the key and fails closed instead of minting predictable cookies; config
validation also warns and userspace capability admission refuses active
SYN-cookie screen profiles until the secret exists.

### On-disk state hygiene: the master key is never persisted (#3909)

The SYN-cookie master key is the secret that makes minted cookies
unforgeable — the source-validation check hashes a returning ACK against
it. The helper persists a JSON snapshot of its `ServerState` to
`state.json` (via `server::helpers::write_state`), and that file is
created with the process umask (world-readable, mode 0644). The master
key therefore carries `#[serde(skip_serializing)]` on
`ConfigSnapshot::syn_cookie_master_key`, exactly like the WireGuard
private key (`wg_local_privkey_hex`) and per-peer PSK
(`wg_preshared_key_hex`), so it is NEVER written into that world-readable
file. A local unprivileged user who could read the key would be able to
forge valid SYN cookies and defeat source validation.

No Rust-side regeneration is needed: the key is deterministic — the Go
control plane derives it from the cluster-synced root secret + cluster-id
+ screened zones (`buildSYNCookieMasterKey`,
`pkg/dataplane/userspace/screens.go`) and re-delivers it on every config
push over the control socket (`apply_snapshot`). `ServerState.snapshot`
starts `None` on boot and is never restored from `state.json`, so the
control plane always supplies the key after a restart. A fresh random
per-boot key would instead break HA: both chassis must derive the SAME
key for cross-node cookie validation to survive failover. The
skip-serialize omission is pinned by
`syn_cookie_master_key_is_skipped_in_state_snapshot`
(`userspace-dp/src/protocol/tests.rs`).

Cookie replies are host-generated flood-control frames, and since #2238 they are
classified like every other generated reply: `cookie_reply.rs` runs
`classify_generated_reply`, so the egress output filter can drop a reply
(`syn_cookie_output_filter_drops`) and the reply carries the CoS queue and DSCP
rewrite that classification selects. Only mirroring is bypassed
(`mirror_clone: false`). The legacy eBPF `XDP_TX` path bypassed all four; do not
"align" the userspace path back to that, it would reopen the #2238 output-policy
bypass for flood-control frames.

## Prometheus Metrics

```
xpf_screen_syncookie_total{type="sent"}     # SYN-ACK cookies generated
xpf_screen_syncookie_total{type="valid"}     # Valid cookie ACKs received
xpf_screen_syncookie_total{type="invalid"}   # Invalid cookie ACKs
xpf_screen_syncookie_total{type="bypass"}    # Validated sources bypassing challenge
```

## Verifier Gotchas

1. **Variable TCP header length:** `tcph->doff * 4` gives wide `var_off` (up to
   60). The BPF helper call must use constant `sizeof(struct tcphdr)` instead.

2. **MAC read ordering:** The compiler may reorder MAC reads past the
   `bpf_tcp_raw_gen_syncookie` call. Reading MACs from the packet is safe because
   `bpf_xdp_adjust_tail` does not modify the beginning of the packet.

3. **Meta offset masking:** `meta->l3_offset` and `meta->l4_offset` are masked
   with `& 0x3F` / `& 0x7F` to narrow `var_off` for the verifier.

## Limitations

- **Every screen RATE threshold is PER-WORKER, so the effective rate is
  `N_workers x configured` (#6568 member 3).** Each worker owns its
  `ScreenState` by value (`userspace-dp/src/afxdp/worker/loop_body/setup.rs`
  creates one per worker loop), so the token buckets behind `syn-flood`
  (attack-threshold, alarm-threshold, source-threshold, destination-threshold),
  `icmp` and `udp` flood, `port-scan`, `ip-sweep`, and the cookie-OFF bucket
  are counted independently per RX queue. On the 6-worker loss VFs a
  configured `attack-threshold 1024` admits up to ~6144/s before every worker
  is over its own threshold.

  This is consistent with the rest of the per-worker dataplane and is NOT a
  global rate. **Size each configured value as a per-worker ceiling**, i.e.
  divide the intended aggregate rate by the RX-queue count.

  The sibling `limit-session source-ip-based` / `destination-ip-based` leaves
  carry exactly this multiplier and have documented it since #2186
  (`docs/feature-gaps.md`); the flood/scan leaves have the same behaviour and
  did not say so, which is the gap this entry closes. It is a documentation
  fix, not a behaviour change — nothing about the enforcement moved.
- **syn-proxy mode** (stateful proxying with full TCP handshake completion) is not
  implemented. Only syn-cookie mode is supported.
- The `validated_clients` LRU map has a fixed size of 65536 entries. Under
  extremely high cardinality attacks, legitimate entries may be evicted.

### Whitelist scope and lifetime (#9419)

Step 6 above says "client reconnects", not "client retransmits the SYN", and
the distinction is load-bearing. Step 5 sends a RST, which aborts the
just-ESTABLISHED socket with `ECONNRESET`. No TCP stack retransmits a SYN from
that state — the application calls `connect()` again, which allocates a **new
ephemeral source port**. So the only shape in which the recovery step can
occur is a NEW connection from the same client.

The whitelist is therefore keyed on `(zone_id, profile_gen, src_ip, dst_ip,
dst_port)` — deliberately **no source port** — and a hit does **not** consume
the entry. It is bounded instead by:

- a TTL of one cookie epoch (`SynCookieCodec::EPOCH_SECS`, 64 s), refreshed on
  each new validation; and
- the #2446 per-zone SYN-cookie profile generation, so a SYN-cookie-relevant
  commit invalidates every prior validation.

The cookie MAC itself still binds the full 4-tuple including the source port;
only the whitelist that the validated ACK seeds is source-scoped. This matches
the eBPF ancestor's `struct validated_client_key`
(`git show 13fa1009ea:bpf/headers/xpf_common.h`), which likewise carried no
source port and lived in a TTL'd `LRU_HASH`.

Before #9419 the whitelist key included `src_port` and the lookup was a
single-use `take`. Step 6 was consequently unreachable: the reconnect arrived
on a port that had never been whitelisted, was challenged and reset again, and
every legitimate TCP client to a zone in cookie mode looped on `ECONNRESET` for
as long as an attacker held the zone above its attack threshold — strictly
worse than leaving the feature off.
- IPv6 SYN-ACK MSS is 1440 (vs 1460 for IPv4) to account for the larger header.
- Userspace SYN-cookie challenge, secret-unavailable, SYN-ACK, ACK-RST, budget,
  valid, invalid, and bypass counters are visible in helper status. Live
  HA/flood evidence is still required before BPF source removal.
