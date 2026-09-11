# pkg/flowexport

NetFlow v9 and IPFIX (NetFlow v10) exporters. Both ship session-close
events to remote collectors with per-zone direction filters and 1-in-N
session sampling. Wired off `pkg/logging.EventReader` SESSION_CLOSE
events in `pkg/daemon/daemon_flowexport.go`, not the conntrack GC
delete callback. No per-packet sampling path.

Flow record *assembly* is **entirely control-plane**: the userspace
dataplane does NOT build/format NetFlow/IPFIX records — flow records are
assembled in this package from SESSION_CLOSE `logging.EventRecord`s. The
Rust dataplane carried a dead `FlowExporter` and a write-only
`flow_export_config` field that emitted nothing; both were removed in
#2130. (The Go→Rust `flow_export` snapshot wire field is retained as
reserved/ignored to preserve the #1977 decode-safety tests.)

**#2460 — the SESSION_CLOSE events ARE now produced in userspace mode.**
Before #2460, the userspace dataplane emitted a session close ONLY as a
minimal `MSG_SESSION_CLOSE` (type 2) HA session-sync delta on the
SessionDeltaInfo channel (`handleEventStreamDelta`), never as an RT_FLOW
`SESSION_CLOSE` event on the raw dataplane-event channel that these
exporters consume — so the NetFlow/IPFIX session-close callbacks never
fired and userspace session-close export was silently non-functional
(per-packet deny/screen/filter RT_FLOW export already worked). The helper
now emits, on every session close, an ADDITIONAL RT_FLOW SESSION_CLOSE
frame (`EventFrameTypeSessionClose`, type 14) carrying the canonical
144-byte `dataplane.Event` payload on the raw channel (the trailing
`policy_id` LE u32 at [136:140] carries the admitting policy ID on close,
[140:144] reserved; #3056). The daemon decodes
it into a `Type:"SESSION_CLOSE"` `EventRecord` via
`eventReader.ProcessRawEvent`, which fires the callbacks below. The type-2
HA delta is unchanged and emitted as a 1:1 pair with the type-14 frame —
the RT_FLOW frame is additive, not a replacement, so HA session sync is
unaffected. The record carries the real 5-tuple, NAT translated tuple,
zones, and protocol. Since **#2501** (CLOSED) the AF_XDP forwarding path
maintains per-session accounting, so the frame carries the real forward AND
reverse byte/packet volume counters (both were 0 before #2501). The forward
counts populate the standard IANA `octetDeltaCount`/`packetDeltaCount`; the
reverse (server→client) counts are exported by IPFIX as the RFC 5103 biflow
reverse IEs — see "#3746 — biflow reverse volume (IPFIX)" below.

**#2465 — the exported flow StartTime is now the real session-creation
time, not a packet-count guess.** Before #2465 the NetFlow v9 / IPFIX
session-close exporters set the flow `StartTime` to
`EndTime - estimateSessionDuration(packet_count)` — a heuristic
(100ms·pkts for TCP, 50ms·pkts otherwise) that systematically mis-timed
flows (long idle sessions exported as very short; high-rate bursts
exported as long), degrading billing / audit / DDoS-reconstruction /
duration analytics. The SESSION_CLOSE RT_FLOW frame now carries the
session's real creation instant in the `created` wire field (offset 108,
absolute Unix **seconds**, little-endian u32) and the close instant in
`timestamp_ns` (offset 0, absolute Unix **nanoseconds**, little-endian
u64). The dataplane stamps the creation instant once at session install
(monotonic `CLOCK_MONOTONIC`), and the helper converts it to wall-clock
at emit time. The Go decoder surfaces `created` as
`logging.EventRecord.Created`; `flowStartTime` (manager.go) sets
`StartTime = time.Unix(Created, 0)` directly when it is non-zero (clamped
to the EndTime on clock skew). `estimateSessionDuration` is retained ONLY
as the fallback when `Created == 0` — an old-format frame, or a
synthesized close from a path that carried no creation instant (the
explicit clear-session / NAT-remap delete glue and the HA tunnel-remap
purge, which do not have the originating entry in hand). Each fallback
bumps a per-exporter `EstimatedDurations()` counter so operators can see
how often the heuristic is still in play. (Since #2501 the byte/packet
**volume** counters are real too — the forward direction on the standard
IANA counters and the reverse direction on the #3746 biflow reverse IEs.)

**#4923 — the packet-count fallback can no longer overflow StartTime
past EndTime.** `estimateSessionDuration` multiplies the uint64 packet
count by a per-packet time (100ms TCP / 50ms otherwise); above ~92.2
billion TCP packets (~184.5 billion non-TCP) that product overflowed
signed `time.Duration` to a NEGATIVE value, and subtracting a negative
duration from the record EndTime moved `StartTime` *after* EndTime —
emitting first-switched after last-switched (NetFlow) / contradictory
absolute milliseconds (IPFIX) that a collector may reject, exactly on
the legacy / HA-recovery fallback paths. `estimateSessionDuration` now
SATURATES at `maxEstimatedSessionAge` (366 days — a defensible session
ceiling ~9e12 ns below the int64 nanosecond limit) so the estimate is
always bounded and non-negative, and `flowStartTime` additionally clamps
the fallback `StartTime` to the EndTime (mirroring the `Created` skew
clamp) so `StartTime <= EndTime` holds no matter how the heuristic
evolves. Only the pathological overflow regime changes; realistic packet
counts keep the exact prior estimate.

**#2853 — the flow StartTime keeps MILLISECOND resolution.** #2465's
`created` field is integer Unix **seconds** (offset 108, u32), so every
flow opened in the same wall-clock second exported the same StartTime —
up to ~1000ms of error for short flows (DNS, single HTTP requests),
flattening IPFIX `flowStartMilliseconds` / `flowStartMicroseconds` and
making the data unusable for micro-burst analysis or sub-second billing.
The SESSION_CLOSE RT_FLOW frame now ALSO carries the creation instant's
sub-second **nanosecond** remainder (0..=999,999,999) in the
close-unused `policy_id` slot (offset 44, little-endian u32). The Go
decoder surfaces it as `logging.EventRecord.CreatedNanos` (and zeroes
`PolicyID`, since a close never carried a real policy id, so the
close-record policy-name resolution is unchanged); `flowStartTime`
combines both as `time.Unix(Created, CreatedNanos)`. The exported
`flowStartMilliseconds` (`StartTime.UnixMilli()`) and NetFlow
`uptimeMs` now reflect the true sub-second start. The fallback path
(`Created == 0`) is unchanged.

**#2526 — the exporters now carry the post-NAT (translated) tuple.**
Before #2526 both the NetFlow v9 and IPFIX templates/encoders exported
only the pre-NAT 5-tuple, so a collector saw the private endpoint of a
NAT'd flow but never the public translated address/port — no NAT
correlation for security audit / compliance / forensics. The
SESSION_CLOSE `logging.EventRecord` already carried the translated tuple
(`NATSrcAddr`/`NATDstAddr`); the daemon callbacks
(`daemon_flowexport.go`) now parse it into `SessionCloseData.NAT{Src,Dst}{IP,Port}`
and `ExportSessionClose` resolves the post-NAT tuple (`resolvePostNAT`,
`manager.go`) onto `FlowRecord.NAT{Src,Dst}{IP,Port}`.

The exported elements (IANA "IPFIX Entities" registry, RFC 5103 /
RFC 8158) are appended LAST in every template:

| Element | ID | Type | Bytes | Family |
|---|---|---|---|---|
| postNATSourceIPv4Address | 225 | ipv4Address | 4 | v4 |
| postNATDestinationIPv4Address | 226 | ipv4Address | 4 | v4 |
| postNAPTSourceTransportPort | 227 | unsigned16 | 2 | both |
| postNAPTDestinationTransportPort | 228 | unsigned16 | 2 | both |
| postNATSourceIPv6Address | 281 | ipv6Address | 16 | v6 |
| postNATDestinationIPv6Address | 282 | ipv6Address | 16 | v6 |

NetFlow v9 reuses the same IANA element type IDs in its template
FlowSet. With the #2613 drop, the #2749 re-adds of `ingressInterface`
(IE 10, 4B), `ipClassOfService` (IE 5, 1B), `tcpControlBits` (IE 6, 2B) and
`egressInterface` (IE 14, 4B), and the #3746 biflow reverse counters
(2×8B, IPFIX only) the IPv4 IPFIX record is 86 bytes (45 pre-NAT
body + 2 src/dst mask + 4 ingressInterface + 7 CoS/egress + 16 biflow
reverse + 12 post-NAT) and the IPv6 record is 134 bytes (69 + 2 + 4 + 7 + 16
+ 36); the NetFlow v9 record
sizes derive from the template via `recordSize` — the plain sum of the field
lengths, 61 v4 / 109 v6 (NetFlow `tcpFlags` is 1B not 2B; v9 carries no reverse
element), so they track the template automatically. **#4896: a v9 data record
is NOT per-record padded.** Records are contiguous at the template-advertised
width (RFC 3954); only the enclosing Data FlowSet is rounded up ONCE to a 32-bit
boundary (`dataFlowSetLen`), matching how the IPFIX sibling
(`ipfixRecordSize`/`ipfixDataSetLen`) already encodes. An earlier `recordSize`
padded each record to 4 bytes while the template still advertised the unpadded
width, so a standards-compliant collector — walking by the template width —
misdecoded every record after the first in a multi-record FlowSet. #3270: with
`export-extension flow-dir` the templates splice in `flowDirection` (IE 61, 1B)
before the post-NAT trailer — the IPFIX record grows to 87 (v4) / 135 (v6); the
v9 record grows to 62 (v4) / 110 (v6) (`ipfixRecordSize(isV6, includeDir)` /
`buildTemplateFieldsV4/V6` carry the flag).
The init-time
assertion in `ipfix.go` pins the BASE `ipfixRecordSizeV4/V6` to the sum of their
template field lengths so a template/encoder length drift fails the
process at startup (a mismatch would corrupt every record). Golden
byte-level encoder tests (`postnat_test.go`) pin the field offsets/values
and the template/encoder length agreement for v4 and v6 on both exporters.

**Zero-NAT decision: post == pre (Junos/vSRX behaviour).** The post-NAT
elements are non-optional template fields, so every record of a template
MUST carry them — they cannot be conditionally omitted per-record without
a second template. When a flow was not translated (the dataplane reports
the unspecified address `0.0.0.0` / `::` and port 0 for that half), the
converter copies the pre-NAT value into the post-NAT field so the
collector always receives a usable tuple, matching Junos/vSRX (which
always emits the post-NAT fields). The address and port halves fall back
independently, so an address-only or port-only translation reports the
translated half and the pre-NAT other half. A collector distinguishes a
NAT'd flow from a non-NAT'd flow by post != pre.

**#2613 — stop advertising fields the close path cannot populate.** The
templates previously advertised `ipClassOfService`/SrcTos (5),
`tcpControlBits`/TCPFlags (6), `flowDirection`/Direction (61),
`ingressInterface`/InputSNMP (10) and `egressInterface`/OutputSNMP (14),
but the SESSION_CLOSE builder (`ExportSessionClose`) never set
`FlowRecord.{TOS,TCPFlags,Direction,InIf,OutIf}` — and there is nowhere
to set them from. The dataplane→Go SESSION_CLOSE RT_FLOW frame is a fixed
144-byte wire shape (`pkg/logging/ringbuf.go`) that carries no DSCP/TOS,
no observed TCP flags, no per-flow direction and no egress ifindex, and
the Rust encoder hardcodes the ingress-ifindex slot to 0 on close frames
(`userspace-dp/.../codec.rs::encode_session_close_rt_flow`). So every one
of those IEs reached collectors as an authoritative zero. The five fields
were removed from both NetFlow v9 templates and the IPFIX v4/v6 templates
(and their record encoders / size constants).

**#2749 — `ingressInterface` (IE 10) restored, then `ipClassOfService` (5),
`tcpControlBits` (6) and `egressInterface`/OutputSNMP (14) restored with real
values.** The ingress half came first: #2615 stamps the closing binding's
ifindex into the `[128:132]` slot of the RT_FLOW close frame (the Rust encoder
no longer hardcodes 0); `pkg/logging/ringbuf.go` retains the raw numeric value
(`EventRecord.IngressIfindex`), the daemon callbacks copy it into
`SessionCloseData.InIf`, and `ExportSessionClose` threads it into
`FlowRecord.InIf` — a **Go-only** change (the ifindex was already on the wire).

The remaining three needed a **wire-format extension**, which #2749 added: the
SESSION_CLOSE RT_FLOW frame grew 144 → 152 bytes with an ADDITIVE `[144:152]`
block — `[144]` src ToS (DSCP<<2), `[145]` cumulative TCP control bits,
`[148:152]` egress ifindex (`[146:148]` reserved — #3270 derives flowDirection
in Go from the per-zone sampling-direction, so this byte stays reserved for a
possible future intrinsic zone-role signal).
Conntrack-side, `SessionEntry.observed_tos` / `observed_tcp_flags` are stamped
on the AF_XDP forwarding path (`account_packet` — forward DSCP, OR of TCP flags
both directions) and harvested onto the close `SessionDelta` in
`session/expire.rs` like the #2501 counters; the egress ifindex comes off the
session's `ForwardingResolution`. The Go reader decodes the block into
`EventRecord.{TOS,TCPControlBits,EgressIfindex}` (length-guarded — the minimum
frame stays 144, so the growth is rolling-upgrade-safe in BOTH directions), the
daemon callbacks copy them into `SessionCloseData.{TOS,TCPFlags,OutIf}`, and
both exporters re-advertise the IEs (placed after `ingressInterface`, before
the post-NAT trailing block so #2526 offsets are unchanged) and write the
values. Presence-with-real-value is pinned by `cos_fields_test.go`
(`TestNetflowCosFieldsPopulated` / `TestIPFIXCosFieldsPopulated`) and the
ingress pins in `ingress_interface_test.go`; the Rust side pins the stamping
(`close_delta_carries_observed_tos_and_tcp_flags`) and the wire encode
(`test_encode_session_close_rt_flow_v4_wire_layout`); the Go decode round-trip
is pinned by `TestDecodeRawEventCloseCarriesCosBlock`.

**#3939 — `protocolIdentifier` (IE 4) sourced from the record's numeric
protocol, not a name re-lookup.** The exporters previously set
`FlowRecord.Protocol` from `SessionCloseData.Protocol`, which the daemon
callbacks filled via `parseProtocol(rec.Protocol)` — a NAME→number table that
covered only `TCP`/`UDP`/`ICMP`/`ICMPv6`. Every other protocol (GRE 47, ESP 50,
AH 51, and any numeric-only protocol) fell through to `0`, so a collector saw
those tunnel/other flows all reported as protocol 0 (HOPOPT) and could not tell
an ESP tunnel from a GRE flow — tunnel-traffic capacity/security analytics were
wrong. The fix sources the exported `protocolIdentifier` directly from
`EventRecord.ProtocolNum` — the raw numeric IP protocol (0-255) the dataplane
stamps on the close frame and `pkg/logging/ringbuf.go` decodes verbatim — in
both `ExportSessionClose` builders. The daemon callbacks now also set
`SessionCloseData.Protocol = rec.ProtocolNum` (removing the lossy
`parseProtocol`), which additionally corrects the non-TCP `flowStartTime`
duration heuristic. The rendered protocol NAME (`EventRecord.Protocol`) stays a
display-only string for `show` output; only the exported numeric field changed.
Fail-on-revert is pinned by `protocol_num_test.go`
(`TestNetflowProtocolIdentifierFromProtocolNum` /
`TestIPFIXProtocolIdentifierFromProtocolNum`), which encode GRE/ESP/AH +
TCP/UDP/ICMP and assert the wire byte equals the numeric protocol; reverting to
the name lookup makes every case encode 0.

**#3270 — `flowDirection` (IE 61) populated from the per-zone
sampling-direction, opt-in.** flowDirection is exported again, but only when a
template configures `export-extension flow-dir`, and the value is a REAL signal
derived in Go — never the synthetic ingress=0 #2613 removed. The signal source
is the per-zone sampling-direction xpf already consults to DECIDE whether to
export a flow (`ExportConfig.ShouldExport`): a flow is exported because its
ingress zone has `sampling input` (observed at ingress → `0`) or its egress
zone has `sampling output` (observed at egress → `1`). `ExportConfig.FlowDirection`
mirrors that decision (RFC 5102 ingress/egress observation point; the exact
mapping Junos SRX inline active-flow-monitoring uses for input- vs
output-applied sampling). **Ingress wins ties** (both directions sampled) to
match the record's initiator-tuple anchor.

The dataplane is unchanged: it has no zone-role/trust signal, so the original
"Rust-stamp `[146]`" idea is infeasible — the reserved `[146]` byte on the
SESSION_CLOSE frame stays reserved. The daemon callback computes
`sd.Direction = lead.FlowDirection(rec.InZone, rec.OutZone)` and the v9 / IPFIX
encoders write it **only** in groups whose template enabled flow-dir
(`IncludeFlowDir`). The templates splice IE 61 in just before the post-NAT
trailer (`buildTemplateFieldsV4/V6`, `ipfixTemplateFieldsV4/V6`); a config that
did not opt in keeps the field absent. With flow-dir enabled the IPFIX record
grows by one byte (V4 70→71, V6 118→119); the v9 record absorbs the byte into
the existing 4-byte FlowSet padding.

The compiler still warns — but now only when `export-extension flow-dir` is set
with **no** `sampling input`/`output` configured anywhere
(`anySamplingDirectionConfigured`), because flowDirection would then be a
constant 0. Fail-on-revert pins: `TestFlowDirectionFromSampling` (the
mapping + ingress-wins tie-break), `TestV9TemplateFlowDirConditional` /
`TestIPFIXTemplateFlowDirConditional` (IE 61 present iff opt-in, with the
record-size delta), the encode-value pins, and the daemon end-to-end
`TestSessionCloseFlowDirectionEgress` (egress-sampled flow exports
flowDirection=1). The base-template absence (no opt-in) is still pinned by
`dropped_fields_test.go`.

**#2866 — `srcMask` / `dstMask` populated from the FIB.** The NetFlow v9
templates advertised `srcMask` (IE 9) / `dstMask` (IE 13) and the IPv6
variants (IE 29 / IE 30) and the v9 encoder wrote `FlowRecord.SrcMask` /
`.DstMask`, but `ExportSessionClose` never assigned those members, so
every flow reached collectors with a `/0` mask. (IPFIX did not advertise
the mask IEs at all.) The mask fields are the prefix length of the
routing-table entry that matches the flow's source / destination address
— the same FIB-longest-prefix-match semantics Junos/vSRX export. That
prefix length is NOT on the SESSION_CLOSE wire frame (unlike the deferred
#2749 fields, which need a dataplane wire extension), but it IS cheaply
derivable from the local FIB at export time. `routemask.go` resolves it
with `netlink.RouteGetWithOptions(ip, {FIBMatch:true})` (RTM_F_FIB_MATCH
makes the kernel report the matched FIB entry's prefix, so a default-route
match returns the real `/0` rather than echoing the queried host as a
`/32`), behind a short-TTL cache (`routeMaskCache`, default 10s) so the
per-flow close path does not issue an RTM_GETROUTE syscall per record.
The cache is also size-bounded at `routeMaskCacheMax` (8192) entries: the
TTL bounds the syscall *rate* but not the footprint, and on an
internet-facing firewall the destination-IP cardinality is effectively
unbounded, so an uncapped map would grow for the daemon's lifetime (a
slow leak). On insert at the cap, `evictLocked` first purges expired
entries (cheap, usually recovers headroom because TTLs are short) and, if
still at the cap, clears the map — a simple hard ceiling rather than
per-entry LRU bookkeeping for a syscall-amortization cache. The bound is
pinned by `TestRouteMaskCacheBounded` (inserting >cap distinct keys keeps
`len(entries)` <= cap; removing the bound flips it RED).

**#3743 — the FIB lookup runs OFF the EventReader callback.** `resolve()`
is called from `ExportSessionClose`, which runs inside the EventReader
session-close callback (`daemon_flowexport.go` `flowExportCallback` /
`ipfixExportCallback`). A *synchronous* `RTM_GETROUTE` there stalls the
event reader — and every other callback behind it, including the trace
writer — for the netlink round-trip; under high destination-IP churn the
cache thrashes and close handling becomes a netlink-bound path. So a cache
miss no longer blocks: `resolve()` returns the safe default (mask 0,
`ok=false`) immediately and schedules a bounded, deduplicated **background**
lookup (`scheduleLookupLocked` → `populate`) that warms the cache for the
NEXT flow to that prefix. A `pending` set dedups concurrent misses for the
same IP; `inflight` caps concurrent lookups at `defaultRouteMaskInflight`
(32) so a slow/loaded netlink socket cannot spawn unbounded goroutines —
once the cap is hit, further misses just return the default and are retried
on a later flow. An approximate mask (0) on the first flow to a new prefix
is the accepted trade-off for never blocking the shared event-reader path;
the common per-host / per-subnet aggregate resolves correctly from the warm
cache on the second flow onward. Pinned by
`TestRouteMaskResolveMissDoesNotLookupSynchronously` (a miss with a blocking
lookup returns the default, not the lookup's value),
`TestExportSessionCloseDoesNotBlockOnFIBLookup` (end-to-end: a blocking FIB
lookup does not stall `ExportSessionClose`) and
`TestRouteMaskCacheAsyncPopulateAndHit` (miss → default → background
populate → warm hit). Reverting to the synchronous lookup-in-`resolve`
flips these RED (the first two by blocking / returning the wrong value).

**#3744 — the route-mask lookup is scoped to the flow's VRF table and an
unresolved lookup is counted.** Before #3744 the FIB lookup was
VRF/table-blind: `fibMatchMask` issued `RouteGetWithOptions(ip,
{FIBMatch:true})` with no interface, so it always resolved against the
**main** table, and `resolveMasks` discarded the `ok` bit. In a multi-VRF
/ routing-instance deployment every flow's mask was therefore looked up in
the wrong table (a leaked or per-instance prefix resolved to the wrong
length, often `/0`), and a genuine miss was exported as a bogus `/0`
indistinguishable from a real default-route match.

*Scoping (Option A).* The SESSION_CLOSE event already carries the
ingress/egress ifindex (#2615/#2749 → `SessionCloseData.InIf`/`OutIf`),
and xpf enslaves interfaces to real l3mdev VRF master devices
(`pkg/routing/vrf.go`), so each interface's ifindex selects a distinct
kernel table. `MaskResolver` now takes an `ifindex`; `fibMatchMask` sets
`RouteGetOptions.IifIndex` when it is >0, which makes the kernel perform
an *input-path* route lookup that follows l3mdev enslavement into the
interface's VRF table. `resolveMasks(r, srcIP, dstIP, inIf, outIf)` scopes
**both** the source and destination half by the **ingress** instance
(`inIf`): Junos attributes the session to the ingress routing-instance and
next-table / rib-group leaked routes to the destination appear in that
ingress table. When the dataplane reported no ingress attribution
(`inIf==0`) it falls back to `outIf`, then to the global table
(`inIf==outIf==0`) — bit-identical to the pre-#3744 main-table lookup, so
single-VRF / default deployments are a no-op. The async #3743 cache key
widens from the 16-byte IP to `(ifindex, IP)` (`routeMaskKey`) so per-VRF
masks for the same host address do not collide; the non-blocking-callback,
bounded-inflight, dedup and size-cap invariants are unchanged.

*Unresolved bit (Option B).* The wire field is a `u8` prefix length
(0..128) with no room for an "unresolved" sentinel a collector would
understand, so an unresolved lookup is surfaced **out-of-band**:
`resolveMasks` returns the number of halves that did not resolve, and each
exporter accumulates them into a `routeMaskUnresolved atomic.Uint64`
(`RouteMaskUnresolved()` accessor, mirroring `EstimatedDurations`). Since
#3797 the first flow to any cold `(ifindex, prefix)` key resolves `0`
while the background lookup warms, so a nonzero counter is expected in
steady state; a value climbing in lockstep with exported flows is the only
operator-visible signal that an exported mask-`0` is *unresolved* versus a
real default-route `/0`.

*Documented residual.* Pure fwmark / `ip rule` PBR (`pkg/routing/rules.go`)
selects a table by mark or source address, and the mark is **not** carried
on the SESSION_CLOSE event, so an ifindex-scoped lookup cannot reproduce a
mark-only PBR decision. The dominant multi-table case — VRF /
routing-instance — IS covered; carrying the fwmark is a separate future
item if demand appears.

Pinned by `TestRouteMaskLookupScopedByIfindex` (same dst IP → different
mask per ingress ifindex, `(ifindex,IP)` key does not collide across
VRFs), `TestResolveMasksScopesByIngressInstance` (both halves scope by
`inIf`, fall back to `outIf`, then to the global table),
`TestResolveMasksMissCount` and `TestExporterRouteMaskUnresolvedCounter`
(an unresolved half increments the counter and still exports `0`, no
sentinel). Reverting the `(ifindex,IP)` key, the ingress scoping, or the
miss count flips one of these RED.

`Exporter` / `IPFIXExporter` carry a `MaskResolver` func (defaulted by
`NewExporter`/`NewIPFIXExporter` to `NewRouteMaskResolver`; nil on a
zero-value exporter → masks stay 0, the pre-#2866 behaviour and the test
seam). `ExportSessionClose` calls it for the pre-NAT src/dst IP. IPFIX
also gains the four mask IEs (9/13/29/30, 1 byte each), placed in the same
record slot as the v9 masks (after `flowEnd`, before `ingressInterface`)
so the two protocols keep a parallel layout; the IPFIX record sizes grow
by 2 bytes (v4 61→63, v6 109→111). Presence-with-real-value is pinned by
`srcmask_dstmask_test.go` (`TestNetflowSrcDstMaskPopulated` /
`TestIPFIXSrcDstMaskPopulated`: the template advertises the mask IE AND
the encoded record carries the resolved prefix length, not zero — a
deterministic injected resolver keeps the test free of a kernel-FIB
dependency).

**#3746 — biflow reverse volume (IPFIX).** Since #2501 the SESSION_CLOSE
frame carries the reverse (server→client) byte/packet counters — decoded to
`logging.EventRecord.RevSessionPkts` / `.RevSessionBytes`
(`pkg/logging/ringbuf.go`) — but the exporters wired only the forward counts
into the standard `octetDeltaCount` (IE 1) / `packetDeltaCount` (IE 2), so a
collector systematically under-reported the larger half of an asymmetric flow
(small request / large download). The IPFIX exporter now also emits the
reverse direction as the **RFC 5103 biflow reverse Information Elements**:
`reverseOctetDeltaCount` (IE 1) and `reversePacketDeltaCount` (IE 2), both
under the reverse **Private Enterprise Number 29305**.

These are the codebase's first **enterprise** IEs. `ipfixField` gained an
`enterprise uint32` column (0 = IANA, unchanged). In the **Template Set** an
enterprise field specifier is 8 bytes — the element ID with the top bit
(`0x8000`) set, the 2-byte length, and the 4-byte PEN (RFC 7011 §3.2) — while
IANA specifiers stay 4 bytes; the template encoder sizes and writes each
accordingly (`ipfixFieldSpecsLen` / `encodeIPFIXFieldSpec`). The template
record's field **count** is unchanged (each enterprise IE is one field). In
the **Data Record** the reverse counts are plain 8-byte unsigned64 values, so
the record grows by 16 bytes (v4 70→86, v6 118→134). The two reverse IEs are
spliced after the forward CoS/egress block and before the post-NAT trailer, so
the #2526 post-NAT tuple stays last and the #3270 `flowDirection` byte (when
`export-extension flow-dir` is set) still sits just before the post-NAT block.
Template IDs stay **256/257** — the content grows once (like #2526/#2749/#2866)
and a collector re-learns the template on the next refresh; an unknown-PEN
collector simply skips the 8-byte field via the template-declared length
(RFC 7011 §8), so the change is backward-safe. The #3740 stable
SourceID/ODID and the #2609 sequence-across-refresh behaviour are untouched
(still one record per session).

The counters are **always present** (like the #2526 post-NAT tuple), not
opt-in: they are core accounting data and skippable by a collector that does
not implement PEN 29305. Fail-on-revert pins in `ipfix_biflow_test.go`:
`TestIPFIXTemplateCarriesBiflowReverseIEs` (the two reverse IEs decode from
the template with the enterprise bit + PEN 29305 + length 8, in both the base
and flow-dir templates, and the Template Set length matches the bytes walked —
catching an off-by-one in the 8-byte specifier sizing),
`TestIPFIXRecordCarriesBiflowReverseCounts` (the encoded record carries the
reverse packet/byte counts at the reverse IEs' offset),
`TestIPFIXExportSessionCloseWiresReverseCounts` (the `EventRecord` reverse
counters reach the `FlowRecord`), and `TestIPFIXBiflowReverseWireLoopback`
(the IEs + counts survive the real exporter UDP wire path). Removing the
reverse IEs flips all four RED.

**NetFlow v9 reverse direction — DEFERRED.** NetFlow v9 (RFC 3954) has no
standard reverse element and no enterprise/PEN namespace, so there is no
in-record, single-record way to carry the reverse direction. The two
non-standard alternatives each break a deliberate design choice: a second
reversed-tuple record contradicts the one-record-per-session / initiator-tuple
anchor the #3270 flow-dir semantics rely on (and would be low-fidelity — the
dataplane tracks no reverse-direction post-NAT tuple or ToS), and summing both
directions into `octetDeltaCount` corrupts that IE's per-direction semantics.
So **v9 exports the initiator-direction volume only; use IPFIX for
bidirectional accounting.** `FlowRecord.RevPackets`/`RevBytes` are populated
for both exporters but consumed only by IPFIX. See the converged research plan
on #3746.

**#3748 (sub-part b) / #5312 — IPFIX sampler Options Template + record.** Before
#3748 `ipfixSetIDOptionsTemplate` (Set ID 3) was a bare constant: the IPFIX
exporter emitted DATA templates (256/257) only and never advertised the
sampling rate, so a collector receiving 1-in-N-sampled records could not
learn N and could not scale the sampled record count. The exporter now emits,
on the SAME template-refresh cadence, an **Options Template** (Set ID 3,
template ID **258** — distinct from the 256/257 data IDs) and an **Options
Data Record** (Set ID 258) carrying the sampling configuration.

**#5312 — describe FLOW selection, not packet sampling.** xpf samples 1-in-N at
**SESSION-RECORD (Flow) granularity**: `ShouldExport` applies the modulo per
SESSION_CLOSE event, selecting whole Flows, *not* 1-in-N packets in the datapath
the way Junos jflow does. #3748 originally advertised this with the PSAMP
**packet-selection** IEs (`selectorAlgorithm` 304 / `samplingPacketInterval` 305
/ `samplingPacketSpace` 306), which tell a standards-based collector this is
*packet* sampling and to renormalize each record's `octetDeltaCount` /
`packetDeltaCount` by N — inflating the already-complete per-session volume by
N× (bogus traffic/capacity/billing estimates). The record now carries the
**RFC 7014 (Flow Selection Techniques) flow-selection IEs**, the flow-granularity
analog of the PSAMP IEs, so a collector interprets the sampling correctly:

| Field | IE | Len | Role | Value |
|-------|----|----|------|-------|
| `observationDomainId` | 149 | 4 | **scope** | the group's stable ODID (#3740) |
| `flowSelectorAlgorithm` | 390 | 2 | option | `1` (systematic count-based, IANA "Flow Selector Algorithm") |
| `samplingFlowInterval` | 396 | 8 | option | `1` (Flows consecutively selected) |
| `samplingFlowSpacing` | 397 | 8 | option | `N-1` (Flows skipped between intervals) |

A collector reads flow selection as "you received 1/N of all Flows" and scales
the **population** (flow count / aggregate volume) by N, while each exported
record's per-session `octetDeltaCount` / `packetDeltaCount` stays complete and
is **NOT** renormalized by N. (The `selectorIDTotalFlowsObserved` 394 /
`selectorIDTotalFlowsSelected` 395 pair could express the same ratio with live
counters; we use the static systematic count-based interval/spacing form because
it is the direct analog of the fixed per-group config and needs no live state.)

The record is scoped by `observationDomainId` (IE 149) — the group's #3740
ODID, which also stamps the message header — so the sampling config binds to
this observation domain. `encodeIPFIXOptionsTemplateSet` /
`encodeIPFIXOptionsSamplerDataSet` build the two sets; `sendSamplerOptions`
packages them into one IPFIX Message (template first, then its data record).
The `ipfixOptionsSamplerRecordSize` (22) is pinned against the field slices at
build time (same discipline as the #2526 data-record pins), so a
template/encoder drift panics at init.

**Emitted only for sampled groups (`SamplingRate > 1`).** This matches the
`ShouldExport` gate exactly. An unsampled / export-all group (rate 0 or 1)
advertises **nothing** — a collector then correctly assumes 1-in-1 — which
also keeps the #2609 template-refresh sequence behaviour bit-identical for the
common unsampled case. The Options Template and record are precomputed once at
construction (`emitSampler` / `optionsTemplateSet` / `optionsDataSet`) since
the rate and ODID are fixed per group.

**Sequence-number accounting.** The Options Data Record rides a Set with ID
≥ 256, so it is a **Data Record** and advances the header Sequence Number by
one (RFC 7011 §3.1) — a sequence-tracking collector counts it, so skipping the
increment would look like the loss #2609 fixed. `sendSamplerOptions` captures
the current cumulative count for the message header, then increments, exactly
as `sendRecords` does. The template-only data-template refresh still carries
the cumulative count without advancing it (#2609 unchanged).

**SEMANTIC NUANCE — record-granularity sampling, expressed as flow selection
(#5312).** Because the record uses the RFC 7014 flow-selection IEs, the
semantics are unambiguous on the wire: a collector scales the **population**
(flow count / aggregate volume across the network) by N, while each exported
record's **full per-session** `octetDeltaCount` / `packetDeltaCount` stays
complete and is **NOT** renormalized by N. This is the whole point of #5312 —
the previous packet-selection IEs carried no wire signal that the per-record
volume was already complete, so a standards collector would have double-counted
by N. This is documented on `sendSamplerOptions` too.

Fail-on-revert pins in `ipfix_sampler_test.go`:
`TestIPFIXOptionsTemplateSetDecode` (Set ID 3, template 258, one scope field =
IE 149, flow-selection option IEs 390/396/397 with correct lengths + set-length
integrity, and the packet-selection IEs 304/305/306 asserted ABSENT — #5312),
`TestIPFIXOptionsSamplerDataSetDecode` (flowSelectorAlgorithm=1, interval=1 /
space=N-1 across sampled and degenerate rates), `TestIPFIXSamplerOptionsWireLoopback`
(the real exporter UDP path emits the options message after the data template,
scope == header ODID, flow-selection rate = N-1 with no packet-selection IEs, and
the record advances the sequence by one), and
`TestIPFIXSamplerOptionsAbsentWhenUnsampled` (rate 0/1 emit no options
message). Removing the sampler emission flips these RED.

**Sub-part (a) — active-timeout interim records — DEFERRED.** The related gap
that a configured `flow-active-timeout` emits no interim records (long-lived
flows under-report in-progress volume) is a separate, multi-surface
Rust + Go + wire + HA change with a delta-accounting invariant and must be its
own `make test-failover`-gated PR. It is NOT implemented here; the converged
design is recorded on #3748.

## File layout

The package is split by responsibility (#1988):

- `manager.go` — resolved export config (`ExportConfig`,
  `CollectorConfig`, `SamplingDir`), the sampling scheduler
  (`ShouldExport`), the shared `FlowRecord`/`SessionCloseData` shapes,
  and the `BuildExportConfig` / `BuildIPFIXExportConfig` /
  `BuildSamplingZones` config resolvers.
- `netflow.go` — NetFlow v9 template/record encoding and the `Exporter`
  that drives it.
- `ipfix.go` — IPFIX (v10) template/record encoding and the
  `IPFIXExporter` that drives it.
- `exporterid.go` — `stableExporterID(protocol, instance, template)`
  (#3740): the stable, nonzero 32-bit per-group id used as the v9 SourceID
  / IPFIX Observation Domain ID. See "Exporter identity" below.
- `routemask.go` — the `MaskResolver` func type and
  `NewRouteMaskResolver` (#2866): a TTL-cached, size-bounded FIB
  longest-prefix-match lookup that resolves a flow's `srcMask`/`dstMask`
  (route prefix length) at export time, plus the `resolveMasks` helper both
  exporters call. The netlink `RTM_GETROUTE` runs on a bounded background
  goroutine, never on the EventReader callback that calls `resolve()`
  (#3743): a cache miss returns the default and warms the cache for the next
  flow. The lookup is scoped to the flow's VRF table by the ingress ifindex
  and the cache is keyed by `(ifindex, IP)` (#3744); an unresolved lookup is
  counted into each exporter's `routeMaskUnresolved`
  (`RouteMaskUnresolved()`).
- `transport.go` — shared collector connection management
  (`collectorConns`: dial / fan-out write / close) and the per-family
  batch accumulator (`flowBatch`) used by both exporters. `dialCollectors`
  binds each connection to its per-collector `CollectorConfig.SourceAddress`
  (the resolved bind — #3745), surfaces any `SourceAddress`/destination
  resolve error (a misconfigured source-address is never silently dropped
  to an OS-chosen bind) and, on any mid-loop resolve or dial failure,
  closes the connections opened earlier in the loop before returning — no
  descriptor leak on partial failure. Each `collectorConn` records its
  `srcAddr` so the health snapshot can attribute a failure to the specific
  source-bound connection.

## Header sequence number — v9 vs IPFIX (#2609)

The two protocols define the header sequence number differently, and the
exporters MUST NOT share the same rule:

- **NetFlow v9 (RFC 3954)** — the header `SeqNumber` counts **export
  packets**. Every datagram, *including* a template-only refresh,
  advances the counter. `Exporter.sendTemplates()` therefore reads and
  post-increments `e.seq` exactly like a data send.
- **IPFIX / NetFlow v10 (RFC 7011 §3.1, §10.3.2)** — the header
  `SequenceNumber` is the **cumulative count of Data Records** sent in
  all prior Messages for this Observation Domain (the sequence of the
  *next* Data Record). A Message that carries only (Options) Template
  Sets contains no Data Records, so `IPFIXExporter.sendTemplates()`
  carries the **current** cumulative value WITHOUT advancing it. Emitting
  a hardcoded `0` on every periodic refresh (the pre-#2609 bug) rewound
  the header sequence, which loss/sequence-tracking collectors (pmacct,
  Elastiflow) read as packet loss or an exporter restart. Pinned by
  `TestIPFIXTemplateRefreshPreservesSequenceNumber` (fail-on-revert).

## Exporter identity — SourceID / Observation Domain ID (#3740)

The resolvers start **one exporter per (sampling-instance, template)
group** (`ResolveV9TemplateGroups` / `ResolveIPFIXTemplateGroups`), but
every exporter previously hardcoded the NetFlow v9 header **SourceID**
(RFC 3954 §5.1) and the IPFIX header **Observation Domain ID** (RFC 7011
§3.1) to `1`, and every group reuses template IDs 256/257. Two groups
pointed at the SAME collector therefore presented an identical RFC decode
key — `(exporter source IP, SourceID/ODID, templateID)` — so the collector
saw template **redefinitions** (256 under one group vs another) and two
**interleaved sequence streams** under one observation domain, read as
packet loss or an exporter restart. #3745's per-collector source-address
does not fix this by default: auto/identical source-address yields the
same source IP, and SourceID stayed 1 for both.

Each exporter now derives a **stable, nonzero 32-bit id** from its config
identity via `stableExporterID(protocol, instance, template)`
(`exporterid.go`): FNV-1a 64 over `"protocol|instance|template"`,
xor-folded to 32 bits, mapped into `[1, 0xFFFFFFFF]`. It mirrors
`config.StableTunnelEndpointID` (#1873). `NewExporter` stamps it as the v9
SourceID; `NewIPFIXExporter` as the IPFIX Observation Domain ID.

- **Template IDs stay 256/257.** A unique ODID/SourceID restores the RFC
  scoping key, so 256 under ODID-A is a different template from 256 under
  ODID-B — no per-group template-ID allocator needed.
- **Per-exporter sequence counters stay** (now correct: each group has its
  own observation domain, so its own sequence stream).
- **HA symmetry (load-bearing).** Flow export is NOT gated on RG
  mastership (`reconcileFlowExporters` has no master/standby guard), so
  both cluster nodes run exporters from the same synced config. The id is
  a pure function of config-synced fields (protocol/instance/template) and
  of NOTHING node-specific, so both nodes compute the IDENTICAL id for a
  group and a failover never presents the collector a new observation
  domain — the same argument #1873 relies on.
- **Protocol tag** (`"netflow9"` vs `"ipfix"`) is folded in so a v9 and an
  IPFIX group with the same instance/template never share a value
  (belt-and-braces; a flow-server binds one version per #2136).
- **Degenerate-default guard.** A hand-built `ExportConfig{}` with no
  instance AND no template (the singular `Build*` helpers and several unit
  tests) keeps SourceID/ODID = `1`, preserving the pre-#3740 wire for the
  unnamed single-default deployment. Real multi-group configs always carry
  a non-empty `InstanceName` (sampling instances are named), so they
  always get distinct hashed ids.

**One-time upgrade churn (release note).** For any *named* or *multi-group*
deployment the SourceID/ODID changes from `1` to the hashed value the
first time this build runs. This is the intended, collector-visible
correctness change: a collector sees a **new observation domain** once,
and any dashboards/filters keyed on `ODID=1` (or `SourceID=1`) must be
updated to the new per-group id. The truly-degenerate unnamed default
(empty instance + template) stays at `1`. This is a NetFlow/IPFIX
**wire-value** change to the external collector only — it is NOT an
internal Go↔Rust snapshot wire change (no `protocol_wire_v1.json` regen).

Fail-on-revert pins (`exporter_id_3740_test.go`, loopback UDP):
`TestNetflowV9SourceIDDistinctPerGroup` /
`TestIPFIXObservationDomainDistinctPerGroup` (two same-collector groups
differing only in template, and only in instance, emit distinct ids —
restoring the constant `1` flips them RED),
`TestStableExporterIDDegenerateDefault` (the all-empty default stays 1),
and `TestStableExporterIDHASymmetry` (deterministic id + protocol
disambiguation).

## Unusable collectors are excluded at build time (#8163)

`collectInstanceVersionCollectors` drops a `flow-server` that can never
receive a record — no `port`, or a port outside 1-65535 — before it
reaches `CollectorConfig`. The verdict is the shared
`config.FlowServerExcludedReason`, the SAME predicate the show surfaces
annotate `NOT INSTALLED` with (#7422), so the exporter and
`show security flow monitoring` cannot disagree about which collectors
are live.

Why it has to happen HERE and not further down, because the blast radius
is the whole point:

- `dialCollectors` treats a dial failure as fatal for the entire group —
  it closes every socket opened so far and returns the error.
- `NewExporter` / `NewIPFIXExporter` propagate that out of the
  constructor, so the exporter object is never built.
- `Daemon.reconcileFlowExporter` builds the full replacement set in a
  loop and `return`s on the FIRST constructor error (`daemon_flowexport.go`).

So one unusable `flow-server` disabled NetFlow **and** IPFIX export for
every template/family group, not just its own siblings. Under the #3742
build-before-swap design the previously-running exporters were kept, so a
reload left stale export up; on a boot with nothing running it published
the empty bundle and export was simply off, with a `slog.Warn` and
`Daemon.FlowExportError()` — which no show surface, REST field or metric
reads — as the only record.

Severity comes from reachability: nothing validates a flow-server port at
commit (`validateSamplingTemplateRefsStrict` checks template references
only), so `set forwarding-options sampling instance s1 family inet output
flow-server 10.0.0.2` with no `port` commits cleanly. This was an
operator typo silently disabling flow export, not a drift-only state.

Two nearby behaviours are deliberately NOT changed:

- **`reconcileFlowExporter` still returns on the first constructor
  error.** That is the #3742 availability design for a TRANSIENT failure
  (a pinned source-address bind before the source interface is up,
  collector DNS): keeping the old exporters running beats swapping in a
  degraded set. The collectors excluded above are decidable from config
  and can never succeed later, which is what makes dropping them safe and
  a dial-time tolerance unsafe.
- **`dialCollectors` still fails the group on a dial error.** A
  well-formed collector that is merely unreachable must stay fatal at
  construction; per-collector unreachability is handled afterwards by the
  #2464 write-health path below.

**#9166 — a transient failure was invisible, and nothing retried.** The
availability design above is right, and it left two gaps.

*It was invisible.* A failed build produced the SAME observation as "flow
export is not configured" on every surface: the daemon's
`FlowExportError()` had zero production readers; the
`xpf_flow_export_collector_*` family is omitted entirely when the health
slice is empty, which is exactly what a failed build produces; and `show`
renders the configuration as present, because the config IS present. So
"flow export is dead" and "flow export was never turned on" read
identically — and only one of those is worth waking someone for. NetFlow
is frequently the only record of what traversed the box, and its absence
looks exactly like a deployment where it was never enabled, which is why
nobody investigates.

`BuildState` (this package) carries `ConfiguredGroups` and `BuildFailed`
per family; the daemon fills it from a count recorded by each reconcile
BEFORE its hash gate, and the collector emits
`xpf_flowexport_configured_groups{family}` and
`xpf_flowexport_build_failed{family}` — both for both families on every
scrape, **including at zero**. That is what makes the three states three
distinguishable observations:

| observation | meaning |
|---|---|
| `configured=0, failed=0` | not configured |
| `configured>0, failed=0` | configured and healthy |
| `configured>0, failed=1` | configured, and the build FAILED |

The count of RUNNING exporters cannot stand in for `ConfiguredGroups`: on
a build failure with nothing previously running it is also 0, which is
the not-configured reading.

*Nothing retried.* `reconcileFlowExporters` runs only from the apply tail
and the boot block, so the retry cadence was "the next commit" — which on
a stable box is never, while both faults the design cites (a pinned
source bind before the interface is up, collector DNS) clear on their own
minutes later. `armFlowExportRetry` now starts a single-flight loop that
re-reconciles every 30s against the **live active config** — reading the
live config, not the config captured at failure, so a commit that removes
flow export converges the loop instead of resurrecting deleted config
(the same reason `activeConfigForRebind` exists, #4899). The loop is
cancelled and JOINED at shutdown under a bounded timeout, so a late tick
cannot reconcile against a torn-down subsystem and a pathological tick
cannot push the stop sequence past the systemd `TimeoutStopSec` and get
the process SIGKILLed before the HA takeover fence runs.

Not changed: the `d.flowHashSet = false` on the failure path. The finding
narrated that as the defect; it is the FIX — without it the next commit
would be hash-gated into a permanently dead family.

The `if fs.Port > 0` guard before `net.JoinHostPort` is kept even though
the exclusion makes `Port >= 1` on every path that reaches it. It is the
fail-loud leg: if the exclusion is ever moved or bypassed, a bare address
dies at dial with a named error, whereas an unconditional `JoinHostPort`
would emit `host:0` — which dials successfully and discards every record
silently.

## Per-collector write-health (#2464)

Flow export is forensics/compliance data; a collector going unreachable
used to be invisible — every failed UDP write in `writeAll` was
`slog.Debug`-logged and dropped while the exporter kept counting
"exported", so an operator got no warning that records were being lost.
Each `collectorConn` now tracks `WriteAttempts`, `WriteFailures`,
`LastError`/`LastErrorTime`, `LastFailureTime`, `LastSuccessTime`, a
`Healthy` flag, and the `SourceAddress` (local bind) the connection was
dialed with (#3745 — so two same-family collectors that pin distinct
sources are distinguishable in every surface). These are atomic counters
plus a mutex-guarded snapshot, race-safe against a concurrent status
reader. The export DATA path is unchanged:
writes are still attempted to every collector and failures are still
non-fatal — this is additive observability.

`writeAll` emits a state-change log ONLY on the
unhealthy↔healthy edge (a `slog.Warn` when a healthy collector first
fails, a `slog.Info` when it recovers), never once per failed write —
`writeAll` runs on the 100ms batch ticker plus each template refresh, so
a per-write warn would flood the journal (project logging rule: no
Warn/Info in a per-tick loop). The per-write `slog.Debug` line is kept
for deep tracing.

The snapshot is surfaced through `Exporter.CollectorHealth()` /
`IPFIXExporter.CollectorHealth()` → `Daemon.FlowCollectorHealth()`
(annotated with protocol / instance / template via
`ExporterCollectorHealth`) on four surfaces:
- **Prometheus** — `xpf_flow_export_collector_{write_attempts_total,
  write_failures_total,healthy,last_success_timestamp_seconds,
  last_failure_timestamp_seconds}`, labeled `{protocol,collector,source}`
  (the `source` label carries the per-collector local bind — #3745 — and
  is `""` when the OS selected it; emitted before the dataplane gate —
  exporters are control-plane).
- **REST** — `GET /api/v1/services/flow-exporters` (the JSON carries
  `source_address`, omitted when empty).
- **gRPC / CLI show** — `show flow-monitoring statistics` (gRPC ShowText
  topic `flow-monitoring-statistics`; both the remote `cli` binary and
  the in-daemon interactive CLI) — the collector line prints
  `... source <src>` for a source-bound collector (#3745).

## Bounded export batch + drop visibility (#3747)

`ExportSessionClose` does not write to the collector inline — it queues the
`FlowRecord` into the per-family accumulator `flowBatch` (`v4`/`v6`), which the
exporter `Run` goroutine drains every 100 ms and hands to the send path. Before
#3747 `flowBatch.add` appended without any bound and the batch was drained
ONLY from `Run`, so if `Run` was stopped or stalled — the reconcile window
(the exporter briefly swapped out), a blocked/slow collector write, or a
`SESSION_CLOSE` storm (scan / failover) outrunning the 100 ms flush — the
queue grew with the close-event rate: unbounded memory growth (a DoS / OOM
risk) with no depth or drop visibility to diagnose it.

The batch is now **bounded per family** by `defaultFlowBatchCap` (65 536
records/family; a test-only `capOverride` makes the drop path reachable). When
the target family is at capacity `add` **drops the incoming record**
(drop-newest) and increments an atomic `dropped` counter rather than growing
the slice. Drop-newest is deliberate: it is O(1) with no slice shift or
reallocation churn under sustained overflow, it never blocks the caller, and it
leaves the happy path (below cap) a plain append. Crucially the flow-close
callback runs on the event-reader path, so `add` MUST NOT block — dropping a
record is strictly preferable to backpressuring into the session reap/close
path. Which end is dropped barely matters for forensic value in a close storm
(all closes are near-contemporaneous); O(1) non-blocking does. A `maxDepth`
high-water mark records the worst-case backlog so a transient stall is visible
after a later drain empties the queue.

The counters are surfaced through `Exporter`/`IPFIXExporter`
`BatchDepth()` / `BatchMaxDepth()` / `BatchDropped()` →
`Daemon.FlowExportBatchStats()` (annotated with protocol / instance / template
via `ExporterBatchStats`) as the Prometheus family
`xpf_flow_export_batch_{depth,max_depth,dropped_total}`, labeled
`{protocol,instance,template}` (one bounded series per configured flow-server
group; emitted before the dataplane gate — exporters are control-plane). A
climbing `dropped_total`, or a sustained nonzero `depth`, is the operator
signal that the export drain cannot keep up.

## Retirement handoff admission lease (#4963)

`#3742` publishes the new exporter bundle BEFORE tearing the old generation
down, so the swap window itself never drops a record. But the session-close
callback loads the live bundle (`d.flowBundle.Load()`) and only *then* iterates
its groups calling `ExportSessionClose` → `flowBatch.add`. A callback that
loaded the OLD bundle *just before* the reconcile's `Store` could still call
`add` **after** the old exporter's `Run` did its FINAL `flushBatches` on ctx
cancel and returned. That late record was appended into a batch nothing would
ever drain again — permanently stranded, while every queue/collector metric
looked healthy. `#3742` fixed the swap window; this is the loaded-old-bundle
residual.

Each `flowBatch` now carries an **allocation-free admission lease**: `add`
increments an atomic `inflight` counter, then checks a `retired` flag. On
teardown the daemon calls `Exporter.Retire()` / `IPFIXExporter.Retire()`
(`flowBatch.retire`) on the OLD generation **after** publishing the new bundle
and **before** cancelling `Run`. `retire` sets `retired` then spins until
`inflight` drains — so any `add` that had already passed the gate finishes
appending and is still drained by the final flush (the record is NOT lost). An
`add` that arrives after `retired` is set is **rejected and counted** in a
distinct `handoffDropped` counter (separate from the `#3747` capacity
`Dropped`) instead of being silently stranded. `sync/atomic` sequential
consistency guarantees the ordering: an `add` that observes `retired==false`
was sequenced before `retire`'s `Store(true)`, so its `inflight++` is visible to
the drain loop, which then waits for it.

Because a retired exporter leaves the live bundle immediately, its per-exporter
`handoffDropped` would become unreadable through `FlowExportBatchStats`. Each
exporter is therefore also injected (`SetHandoffCounter`) with a pointer to one
**fixed-cardinality per-family** counter on the daemon
(`flowHandoffDropped` / `ipfixHandoffDropped`); `add` increments both on a
reject. The per-exporter value is surfaced on live exporters via
`ExporterBatchStats.HandoffDropped`, and the family totals via
`Daemon.FlowExportHandoffDropped()`. A nonzero family total is the
operator-visible signal that day-2 flow-export reconciles are losing close
records at handoff — the failure that used to be completely silent.

## Export-pipeline resiliency (#4423)

Three hardening fixes to the exporter goroutine and its sysUptime clock.

- **Per-collector write deadline + unhealthy-collector backoff (H07).**
  `writeAll` (`transport.go`) fans a packet out to every collector in the group
  SERIALLY, in the ONE per-exporter `Run` goroutine that also drives the
  template refresh, the 100 ms batch flush, and the shutdown drain. A
  connected-UDP `Write` is normally instantaneous but can block indefinitely on
  a full socket send buffer (ENOBUFS / a congested or down egress path parks
  the goroutine in the netpoller until the buffer drains). One blocked write
  therefore stalled ALL of the above INDEFINITELY — the other collectors
  starved, templates stopped refreshing, the batch backed up (see #3747, which
  bounds the resulting memory growth but does not un-stall the drain), and
  ctx-cancel shutdown hung past the unit `TimeoutStopSec`.

  Two bounds are applied. (1) Each ATTEMPTED write sets `SetWriteDeadline(now +
  collectorWriteTimeout)` (default 2 s): this does NOT eliminate the stall — it
  CAPS it, so a slow collector blocks the shared goroutine by at most the
  timeout per attempt, never indefinitely (the datagram is then dropped,
  best-effort UDP, and the collector is marked unhealthy #2464). (2) A
  per-collector `nextRetryAt` backoff gate then SKIPS an already-unhealthy
  collector until `unhealthyProbeInterval` (default 30 s) elapses, so a
  PERSISTENTLY-dead collector costs one bounded probe per interval instead of a
  fresh timeout on every flush — without which a dead collector would still
  delay the healthy collectors + the template/flush cadence by up to 2 s every
  100 ms forever. A successful re-probe clears the gate and resumes normal
  per-flush writes. Skipped writes are counted (`skipped` →
  `CollectorHealth.WriteSkipped` → `show services flow-monitoring` +
  `xpf_flow_export_collector_write_skipped_total`) so the backoff is
  observable, not a silent drop. `collectorWriteTimeout` and
  `unhealthyProbeInterval` are package `var`s so tests shrink them.
- **Template-refresh ticker clamp (M10).** `Run` built its template ticker with
  `time.NewTicker(cfg.TemplateRefreshRate)`, which PANICS on a `<= 0` duration
  — fatal under `go e.Run(ctx)`. The production resolver always fills at least
  60 s, but the public `NewExporter` / `NewIPFIXExporter` constructors accept
  any `*ExportConfig`. `templateRefreshInterval` (`transport.go`) now clamps a
  non-positive rate to `defaultTemplateRefreshRate` (60 s).
- **sysUptime anchored at device boot (M13).** The NetFlow v9 header
  `SysUptime` and the record `FirstSwitched`/`LastSwitched` fields are all
  "system uptime" relative (RFC 3954). The exporter anchored them at
  `time.Now()` taken when the exporter was CONSTRUCTED, so after a daemon
  restart (commit, crash recovery, HA failback) any flow that started before
  the restart had `StartTime` earlier than the anchor and `uptimeMs` clamped
  its `FirstSwitched` to 0 — truncating the flow age to "at boot". `bootTime`
  is now `systemBootTime()` (now − `CLOCK_BOOTTIME`), the real device boot
  instant which predates every session, via the `bootTimeFunc` seam (tests
  inject a deterministic boot). IPFIX is unaffected — it exports absolute
  `flowStart/EndMilliseconds`, not an uptime-relative value.

## Entry points

NetFlow v9:
- `Exporter` — `netflow.go`.
- `NewExporter(cfg *ExportConfig) (*Exporter, error)` — `netflow.go`.
  Takes `*ExportConfig` (never a value copy): `ExportConfig` embeds the
  live 1-in-N `sampleCounter` (`atomic.Uint64`), and copying it would
  fork the counter (a go-vet "copies lock value" failure) — see #2224.
- `Run(ctx context.Context)` — `netflow.go`. Main export loop.
- `Exporter.ExportSessionClose(rec, evt)` — emit one record.

IPFIX:
- `IPFIXExporter` — `ipfix.go`.
- `NewIPFIXExporter(cfg *ExportConfig) (*IPFIXExporter, error)` — `ipfix.go`.
  Also takes `*ExportConfig` (never a value copy) for the same #2224
  reason as `NewExporter`.
- `IPFIXExporter.Run(ctx context.Context)` — `ipfix.go`.
- `IPFIXExporter.ExportSessionClose(rec, evt)` — emit one record.

Shared:
- `ExportConfig` — `manager.go`. Resolved per-group config: the collectors that
  referenced one template **and share one address family** (#2461 + #6811), that
  template's timeouts / field options, plus the instance-shared sampling state
  (see "Per-flow-server template binding" below and "Family is part of the group
  key (#6811)").
- `ResolveV9TemplateGroups(...) []*ExportConfig` /
  `ResolveIPFIXTemplateGroups(...)` — `manager.go`. The per-template-group
  resolvers the daemon uses (#2461).
- `BuildExportConfig(svc *config.ServicesConfig, fo *config.ForwardingOptionsConfig) *ExportConfig` — `manager.go`.
  Returns nil (no v9 exporter) unless BOTH `forwarding-options sampling`
  has a flow-server AND `services flow-monitoring version9` is configured
  (#2129). This mirrors the `BuildIPFIXExportConfig` `version-ipfix` gate.
  Before #2129 the v9 exporter started on sampling alone, emitting an
  unrequested v9 stream to an IPFIX-only operator's collector. Its
  collector set now contains ONLY the flow-servers bound to v9 (#2136 —
  see "Per-flow-server export-version binding" below).
- `BuildIPFIXExportConfig(...)` / `BuildSamplingZones(...)` — `manager.go`.
- `SamplingDir` — `manager.go`. Direction enum.
- `SessionCloseData` — `manager.go`. Wire shape built from
  `logging.EventReader` SESSION_CLOSE records (in
  `pkg/daemon/daemon_flow.go`).

## Per-flow-server export-version binding (#2136)

Junos binds each `flow-server` to exactly one export version + template.
`BuildExportConfig` (v9) and `BuildIPFIXExportConfig` (IPFIX) therefore
no longer flatten every flow-server into both collector sets — they each
take only the flow-servers resolved to their own version, via the shared
`collectVersionCollectors` / `resolveFlowServerVersion` helpers in
`manager.go`. A given collector address:port appears in at most one of
the two sets, so it never receives both a NetFlow v9 (version 9) AND an
IPFIX (v10) datagram for the same flow.

Before #2136 both builders returned every flow-server, and the daemon
started both exporters against the same collector socket — each with its
own SESSION_CLOSE callback and its own independent 1-in-N counter — so a
flow-server reachable under both global version stanzas was exported
twice with mismatched sampling.

Resolution order for one flow-server (`resolveFlowServerVersion`):

1. **Explicit per-server selector wins.** A flow-server configured with
   `version9 { template … }` / `version9-template …` binds to v9; one
   configured with `version-ipfix { template … }` /
   `version-ipfix-template …` binds to IPFIX (parsed by
   `compiler_services.go` into `FlowServer.Version`). It is then bound to
   that version *only if* the matching global `services flow-monitoring`
   stanza exists (the global stanza supplies template timeouts/fields); a
   server bound to a version whose global stanza is absent exports
   nothing and does NOT silently fall back to the other version.
2. **Unbound server inherits the single configured global version.**
3. **Unbound server with BOTH global versions configured → IPFIX**
   (documented precedence). IPFIX (v10) is the IETF-standard superset of
   NetFlow v9, so an operator who enabled both but did not pin the
   collector gets the modern protocol — and, critically, exactly ONE
   datagram stream rather than the pre-#2136 double-export. To send v9 to
   such a collector, pin it explicitly with a per-server `version9`
   selector.

## Per-flow-server template binding (#2461)

After #2136 routes each flow-server to the right *version*, #2461 routes
it to the right *template*. Junos binds each flow-server to one template
under its version; before #2461 the resolver ignored that reference
entirely — it built ONE export config from the FIRST Go-map-iteration
template and broadcast it (timeouts, `flow-dir` export-extension) to every
collector of the version. A collector that asked for a specific template
silently received whichever the map yielded first, and that choice flipped
across process restarts (map order is not an operator contract).

The resolver now groups collectors by the template they referenced and
emits one `*ExportConfig` per group:

- **`ResolveV9TemplateGroups` / `ResolveIPFIXTemplateGroups`** (`manager.go`)
  return `[]*ExportConfig`, one per referenced template. The group key is
  `(version, template_name)`; **source-address is a deterministic sort
  tiebreak, NOT part of the grouping key** — collectors that share a
  template but pin different source-addresses share ONE group and each
  still receives its own source-pinned UDP connection (via
  `dialCollectors`). Each group carries the timeouts / `V9TemplateOpts` of
  the template its collectors referenced. A collector that referenced no
  template lands in the default (`TemplateName == ""`) group, which inherits
  the lone template's parameters when exactly one is configured (the common
  single-template case — unchanged) and otherwise the built-in defaults.
- **Determinism.** Groups are sorted by template name and each group's
  collectors by address, so process restarts produce identical exporter
  wiring — the map-iteration nondeterminism is gone.
- **Validation.** A flow-server referencing an UNDEFINED template is
  hard-rejected at commit / commit-check by
  `validateFlowServerTemplateReferencesStrict` (`pkg/config`). The tolerant
  load / peer-sync path downgrades it to a warning (#1960) and the resolver
  DROPS that group, so a leniently-loaded bad config exports nothing for
  that collector rather than the wrong template.
- **Per-instance sampling.** 1-in-N sampling is a sampling-INSTANCE
  property (#2462). The template groups of ONE instance share that
  instance's `sampleCounter` (a pointer); two different instances each get
  their own counter. The daemon evaluates `ShouldExport` exactly once per
  instance per SESSION_CLOSE and fans the record out to that instance's
  groups.
- `BuildExportConfig` / `BuildIPFIXExportConfig` (singular) are retained
  for single-aggregate callers and now return the first resolved group.

## Multi-sampling-instance isolation (#2462)

`forwarding-options` can define several `sampling instance <name>` blocks,
each with its own input rate, families, and flow-servers. Before #2462 the
resolver flattened EVERY instance into one global export policy:
`collectVersionCollectors` merged all instances' flow-servers into one
collector set, `samplingRate()` returned the first-nonzero `InputRate` in
Go map order, and one `sampleCounter` was shared by the whole family. Flows
from instance A exported to instance B's collectors and the effective rate
depended on map-iteration order.

The resolver now treats each instance as a first-class export policy. The
grouping key is `(instance, version, template)`:

- **Own collectors.** `collectInstanceVersionCollectors` walks ONE
  instance's flow-servers, so instance A's collectors never receive
  instance B's flows.
- **Own rate.** Each instance's `ExportConfig.SamplingRate` is its own
  `InputRate` — the first-nonzero map-order global rate is gone.
- **Own 1-in-N counter.** Each instance gets a distinct `sampleCounter`, so
  1-in-N is independent per instance (and still shared across that
  instance's template groups, the #2461 invariant scoped to one instance).
- **Attribution by family.** The only per-flow instance selector available
  is the address family: the interface `family inet { sampling { input; } }`
  stanza is a plain boolean and there is **no per-interface
  sampling-instance selector** in the config model. So `ServesInet` /
  `ServesInet6` record which families an instance has a surviving collector
  group for (a group whose template is undefined does not count; see the
  #9172 bullet below), and `ExportConfig.ServesFamily(isIPv6)` gates a record — an
  inet-only instance never exports an IPv6 flow. The daemon callback walks
  the contiguous per-instance run of groups, applies the family gate + the
  single per-instance sampling decision, then fans to that instance's
  groups.
- **The family flags describe the groups that SURVIVE (#9172, V076).** Both
  resolvers drop a template group whose template is undefined (the strict
  commit gate rejects the reference; the tolerant load / peer-sync path
  drops it). `collectInstanceVersionCollectors` derives the flags from every
  eligible flow-server, before that drop, so an instance whose only inet6
  group named an undefined template used to keep `ServesInet6`: an IPv6
  record passed the family gate, consumed a 1-in-N slot on the instance's
  shared counter, and was exported nowhere, diluting the inet group's
  effective rate below the configured 1-in-N (the rate an IPFIX collector
  reads from the #3748 sampler Options record; NetFlow v9 has no such record
  and is diluted the same way).
  `narrowToSurvivingFamilies9172` now clears a family with no surviving
  group, in both resolvers.
- **Determinism.** Instances are resolved in lexical name order
  (`sortedInstanceNames`), so restarts produce identical wiring.

### Supported vs rejected matrix

| Configuration | Result |
|---|---|
| Single sampling instance (any rate / families / collectors) | **Supported** — unchanged from pre-#2462 (the common case) |
| Two instances, different families (A: inet, B: inet6) | **Supported** — attributed by flow family |
| Two instances, different export versions (A: version9, B: version-ipfix) on the same family | **Supported** — distinct datagram streams |
| Two instances both exporting the same `(version, family)` pair | **Rejected at commit** — no per-flow instance selector exists, so the runtime cannot attribute a flow to one instance |

The reject is `validateSamplingInstanceConflictsStrict` (`pkg/config`):
strict on commit / commit-check (hard reject so the operator sees it),
lenient on load / peer-sync (downgraded to a warning via
`opts.lenientSamplingInstanceConflicts` so an already-persisted or
peer-synced config still boots — #1960; the resolver still emits both
instances' independent `ExportConfig`s, duplicating eligible flows to both
rather than bricking the load).

### Daemon wiring (one exporter per (instance, template) group)

`reconcileFlowExporters` starts **N exporters per family** — one per
`(instance, template)` group — instead of a single exporter.
`d.flowExporters` / `d.ipfixExporters` are slices; the atomic `flowBundle`
/ `ipfixBundlePtr` carry the group set; the once-registered session-close
callback walks each contiguous per-instance run, applies the family gate +
the single per-instance sampling decision, and exports to that instance's
groups. The per-family config-hash gate, transient-create-failure retry (no
hash recorded), and shutdown teardown all operate over the slice.

## Callers

`pkg/daemon/daemon_flowexport.go::reconcileFlowExporters` owns the
exporter lifecycle (#2075). It runs at boot (after the EventReader
exists) AND on every config commit from `applyConfigLocked`, and is
config-hash-gated per family so an unrelated commit never bounces a
healthy exporter (preserving its template-refresh cadence and 1-in-N
sampling counter). A commit that changes `forwarding-options sampling`
/ `services flow-monitoring` — or that ADDS / REMOVES flow export
entirely — therefore takes effect immediately, without a daemon
restart (before #2075 the exporters were started only at boot and
stopped only at shutdown).

Because the `EventReader` callback list is append-only (clear-all only,
no per-callback removal), the reconcile registers ONE stable
indirection callback per family exactly once
(`flowCBOnce`/`ipfixCBOnce`) that reads the live `(exporter, config)`
pair lock-free from an `atomic.Pointer` bundle; reconcile swaps the
bundle atomically. The callback calls `Exporter.ExportSessionClose()`
(NetFlow v9) / `IPFIXExporter.ExportSessionClose()` (IPFIX) from the
`logging.EventReader` SESSION_CLOSE event. The resolved `*ExportConfig`
is shared by pointer everywhere — in the bundle, by the callback's
`ShouldExport`, AND inside the exporter — so there is exactly ONE live
1-in-N `sampleCounter` (`atomic.Uint64`) per sampling INSTANCE (#2462;
shared across that instance's template groups, distinct between
instances). `ExportConfig` is
never copied by value: doing so would fork the atomic counter (a go-vet
"copies lock value" failure) and silently re-seed the modulo cadence the
moment any caller sampled off the copy (#2224).
`stopFlowExporter`/`stopIPFIXExporter` drain the exporter at shutdown.

## Dependencies

`pkg/config`, `pkg/logging`.

## Gotchas

- 1-in-N sampling uses a monotonic counter on `ExportConfig`. With small
  N a burst of close events can sample several consecutive flows; that's
  expected.
- NetFlow v9 templates refresh every 60 s. If a collector restarts and
  misses a refresh it sees opaque records until the next cycle —
  configure the collector to handle template re-resolution.
- Two batches are maintained inside `flowBatch` (`v4` and `v6`, split
  by family, not by zone — `transport.go`). Both flush on a 100 ms
  ticker or on shutdown. Each is **bounded** at `defaultFlowBatchCap`
  records; overflow drops (drop-newest) and increments `dropped` rather
  than growing without bound (#3747 — see "Bounded export batch" above).
- `BuildSamplingZones` resolves a zone's interface references
  (`parseIfaceRef`, `manager.go`) into (physical-name, unit) pairs to
  decide which zones have sampling enabled. The unit suffix is parsed
  strictly (#2463): a bare reference with no dot is the implicit unit 0
  (a legitimate config form), but a reference WITH a dot must carry a
  clean unsigned decimal unit after the FINAL dot — `strconv.Atoi`, no
  sign, space, empty suffix, or trailing junk. A malformed reference
  (`ge-0/0/0.1abc2`, `ge-0/0/0.foo`, `ge-0/0/0.-1`, `ge-0/0/0.`) is
  WARNED once and SKIPPED, not silently coerced. The previous
  digit-accumulation scan accepted them all — `1abc2` became unit 12,
  `foo` and an empty suffix became unit 0, `-1` became unit 1 — so
  sampling could be enabled on the wrong unit or silently on unit 0,
  diverging from the operator's interface list.
- `ExportSessionClose` builds the flow record synchronously from the
  event-reader callback. The export goroutine (started in `Run(ctx)`)
  is what actually transmits and refreshes templates; record assembly
  itself isn't offloaded.
- Collector destination and source-bind addresses are built with
  `net.JoinHostPort` (`manager.go` / `transport.go`), so an IPv6
  flow-server or `source-address` is bracketed (`[2001:db8::9]:4739`)
  and parses under `net.ResolveUDPAddr` / `net.Dial`. A plain
  `"%s:%d"` / `addr+":0"` left an IPv6 literal unbracketed and
  unparseable, so IPv6 collectors silently never dialed (#2183). IPv4
  addresses are unaffected.


## Family is part of the group key (#6811)

A sampling instance may legitimately carry BOTH address families —
`family inet { flow-server A }` and `family inet6 { flow-server B }` under one
instance — and the strict commit validator explicitly permits it (it rejects only
two DIFFERENT instances claiming the same `(version, family)`).

That shape used to cross-fan. `collectInstanceVersionCollectors` merged both
families into ONE collector slice and collapsed family into two per-INSTANCE
booleans (`servesInet` / `servesInet6`); `CollectorConfig` carried no family;
grouping keyed on template alone; and `ServesFamily` was evaluated per instance.
With both families configured both booleans were true, so the gate passed for
either family and the daemon fanned the record to **every** group of the
instance. IPv4 records reached the IPv6-only collector and IPv6 records reached
the IPv4-only one.

Nothing caught it because nothing configured the shape: the #2462 isolation tests
use family-DISJOINT instances (where the instance-level gate IS sufficient) and
the template tests use a single family.

The fix partitions family at BUILD time and gates on it at send time:

| Layer | Before | After |
|---|---|---|
| `CollectorConfig` | `Address`, `SourceAddress`, `Template` | + `IsV6` |
| dedup key | address + source + template | + family |
| group key | template | `collectorGroupKey{Template, IsV6}` |
| `ExportConfig` | `ServesInet`/`ServesInet6` (per instance) | + `GroupIsV6` (per group) |
| `flowExportCallback` | instance gate, then fan to every group | instance gate, then **per-group family gate** |

**Family is in the group key so the hot path stays a gate, not a search.** Every
group is single-family by construction, so the per-record cost is one comparison
against a precomputed flag. Keeping template-only groups and filtering
connections per record would put a collector scan on the export path for every
flow.

**`ServesInet`/`ServesInet6` deliberately stay per-INSTANCE.** They keep their
#2462 meaning — *does this instance serve this family at all* — and gate the
single sampling DECISION, which must run before `ShouldExport` so a record of an
unserved family never consumes a 1-in-N slot. `GroupIsV6` gates which groups that
decision then fans out to. Collapsing the two would either re-open the cross-fan
or change the sampling denominator.

**The same collector under both families is kept twice, not deduped.** Family is
part of a collector's identity, so `10.0.0.1:2055` configured under both families
is two destinations-with-family; collapsing them would silently stop exporting
one family to a collector the operator explicitly configured for both.

Note that `BuildExportConfig` / `BuildIPFIXExportConfig` return only the FIRST
group, so for a multi-family instance they now return a single family's
collectors. They have no production callers — the daemon uses the resolvers — but
a test reaching for "the" ExportConfig of a multi-family instance must iterate
`ResolveV9TemplateGroups` instead.
