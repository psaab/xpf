# GEMINI-049 Round-3 Medium Adjudication

- **Lane:** Medium findings (37 PENDING items)
- **Worktree:** `/home/ps/git/pi-xpf/.claude/worktrees/8869-r3med`
- **Branch:** `research/8869-r3med`
- **Report:** `/tmp/gemini-review-049.md`
- **Comparison base:** `b0f3aba21aede755573fb61714d3bfad15b795ab`
- **Current master measured:** `6fa3310c0609c4f2cb8547021db8cfa9ceda5883`
- **Product-code policy:** read-only. This lane changed only this log.

## Method

Each finding was measured against the report base and the current master. I split the alleged mechanism from its claimed consequence, checked the production reachability boundary and existing contract/tests, and filed only findings that remain RED at current master with an observable consequence. Performance/cache candidates without a measured product consequence are recorded as deferred rather than mechanically dismissed. No finding was dismissed solely because it was inconvenient to reproduce.

## Counts

| Verdict | Count |
|---|---:|
| FILED (new validated issue) | 9 |
| REFUTED | 19 |
| FIXED-SINCE | 5 |
| DEFERRED / UNRESOLVED | 4 |
| DUPLICATE | 0 |
| **Total** | **37** |

The filed issues are all labeled `bug` and `source:gemini-review-049`:

| Finding | Issue |
|---|---|
| 028 | #10432 — https://github.com/psaab/xpf/issues/10432 |
| 044 | #10434 — https://github.com/psaab/xpf/issues/10434 |
| 060 | #10433 — https://github.com/psaab/xpf/issues/10433 |
| 068 | #10436 — https://github.com/psaab/xpf/issues/10436 |
| 078 | #10435 — https://github.com/psaab/xpf/issues/10435 |
| 082 | #10439 — https://github.com/psaab/xpf/issues/10439 |
| 085 | #10438 — https://github.com/psaab/xpf/issues/10438 |
| 086 | #10437 — https://github.com/psaab/xpf/issues/10437 |
| 088 | #10440 — https://github.com/psaab/xpf/issues/10440 |

During parallel filing, #087 was transiently opened as #10441; after contract review established that it is an API enhancement rather than a validated defect, it was immediately closed as **not planned** and is not counted as filed. No open issue remains for #087.

## Verdict table

| Finding | Verdict | Evidence summary |
|---|---|---|
| 005 | REFUTED | IPv4 Total Length includes the header; the report's allegedly legal example is oversized. |
| 007 | REFUTED | Relaxed completion counters are telemetry-only and have no synchronization/control consumer. |
| 008 | REFUTED | TX unwind restores the fungible free-frame set and pending order; no locality contract exists. |
| 010 | REFUTED | The alleged >u16 extension offset cannot be represented by the parsed protocol fields; parser is fail-closed. |
| 016 | REFUTED | Lease configuration and acquire/release paths bound all production values to u32. |
| 017 | DEFERRED | Cold/error reply path does call `clock_gettime`; throughput consequence is unmeasured. |
| 018 | DEFERRED | Forced wake call sites exist; no measured throughput or CPU consequence was established. |
| 019 | DEFERRED | Metadata straddles a cache line; no applicable repository standard or profile establishes material impact. |
| 020 | DEFERRED | Arithmetic can reach the floor under some inputs; production throttle impact was not demonstrated. |
| 028 | FILED #10432 | NAT64 embedded quote rewrite uses captured quote length instead of original advertised inner length. |
| 037 | REFUTED | Parser probe passes braced, packed, and bare `then` spellings. |
| 038 | REFUTED | Current compiler retains every address value; fallback applies only when the value list is empty. |
| 040 | FIXED-SINCE | #5194 normalization is now applied consistently by catalog and dataplane compiler. |
| 044 | FILED #10434 | SNMPv3 decodes authoritative/context engine IDs but does not validate them. |
| 045 | REFUTED | NetFlow v9 counter fields are specified 32-bit wrapping fields; rollover is collector behavior, not malformed wire data. |
| 048 | REFUTED | `Agent.Start` processes packet work serially; no concurrent `lastPacket` race was found. |
| 050 | REFUTED | Failed recovery deletion returns before clearing state; only successful recovery clears the marker. |
| 056 | FIXED-SINCE | #9914 normalizes the send-bound advertise interval to the timer's default/quantum. |
| 058 | FIXED-SINCE | #9719/#2221 add bounded tombstone handling and avoid gen-0 overflow deletes in the affected path. |
| 059 | REFUTED | All production batch-failover callers validate RG count before the private uint8 encoders. |
| 060 | FILED #10433 | Timer/ACK select can choose timeout while a valid buffered ACK is already ready. |
| 064 | REFUTED | Dequeue copy retains only one bounded tail payload, not an unbounded 4096-frame or MB allocation. |
| 068 | FILED #10436 | Delayed startup NAPI callback checks only non-nil process, not process generation. |
| 070 | REFUTED | Synthetic ifindexes are confined to logical-only rows and skipped by physical TX/counter consumers. |
| 074 | FIXED-SINCE | Declared-aware netdev resolution now precedes the legacy `.0` fallback strip (#9821/#9942). |
| 077 | REFUTED | Fallback termination debt is retried and cleared by the live-name reconciliation path; no permanent debt was shown. |
| 078 | FILED #10435 | VLAN child `.network` units omit configured MTU because no `.link` is emitted. |
| 082 | FILED #10439 | Several show-text loops dereference present-but-nil tolerant-load config entries. |
| 084 | REFUTED | REST read routes are intentionally all `PermView`; #6660 pins that contract and gRPC `test-*` is a distinct command tier. |
| 085 | FILED #10438 | REST/gRPC source NAT views omit `off`/`none` actions and source match criteria. |
| 086 | FILED #10437 | REST/gRPC destination NAT views copy only singular `DestinationAddress`, dropping lists/names. |
| 087 | REFUTED | `GetRoutes` is documented as the main-table operation; all-VRF output needs an explicit schema/selector. |
| 088 | FILED #10440 | `dialPeer` probes with `context.Background`, ignoring canceled caller requests. |
| 089 | FIXED-SINCE | REST DHCP leases now uses the same delegated-prefix aggregation as gRPC (#9413). |
| 097 | REFUTED | IPv4 UDP payload max makes the claimed oversized cast unreachable through production relay input. |
| 098 | REFUTED | Unknown-zone host classification is `HostInboundDenied`, and REST/gRPC/CLI expose that admission; `HostInboundUnmatched` means no fine-grained policy, not delivery. |
| 099 | REFUTED | DHCPRELEASE is specified as client-unicast to the server; relay intentionally does not claim a broadcast-release contract. |

## Per-finding adjudication

### GEMINI-049-005 — REFUTED

**Claim/mechanism:** `userspace-dp/src/screen/stateless.rs` rejects a legal final IPv4 fragment because it checks `offset_bytes + pkt.ip_total_len > 65535` without subtracting the IP header. The same check is present at the base and current master (`:137-141`).

**Measurement/consequence split:** IPv4 Total Length includes the IPv4 header. A legal maximum datagram has total length 65,535, not payload length 65,535. For a 20-byte-IHL fragment at offset 65,512, the maximum legal fragment total length is 23, and `65,512 + 23 = 65,535`, so the current guard accepts it. The report's example uses fragment total length 43 (`65,512 + 43 = 65,555`), which is already an oversized datagram. Subtracting IHL as proposed would admit an invalid packet. The existing mixed-IHL limitation is a separate documented issue and does not validate this finding.

### GEMINI-049-007 — REFUTED

**Claim/mechanism:** `tx_completions` and related counters use `Ordering::Relaxed`, allegedly allowing stale or reordered completion accounting to drive TX backpressure. Base and current `reap_tx_completions` increment the telemetry counter with Relaxed; snapshots likewise load it Relaxed.

**Measurement/consequence split:** The counter consumers are snapshots, coordinator binding refresh, protocol telemetry, and debug reporting. TX availability/backpressure uses the owner-worker `outstanding_tx` and ring state, not the relaxed telemetry counter. Relaxed is sufficient for a monotonic diagnostic statistic with bounded read skew; no watchdog, frame-recycle, or admission decision consumes this value. The claimed packet-loss/stall consequence is therefore not RED.

### GEMINI-049-008 — REFUTED

**Claim/mechanism:** The TX error unwind allegedly reverses frame offsets incorrectly and returns the wrong frame to the free list. Base and current unwind the one failed offset to the front, then drain scratch offsets in reverse so the pending sequence is restored.

**Measurement/consequence split:** Free UMEM frame offsets are fungible; there is no allocation-locality or age contract attached to their order. The unwind path preserves ownership exactly once and restores the pending ordering expected by the transmit queue. No duplicate descriptor, lost frame, or observable ordering violation was found. The report's performance consequence is not established.

### GEMINI-049-010 — REFUTED

**Claim/mechanism:** `frag_data_off` is allegedly narrowed to `u16`, allowing jumbo extension offsets to wrap and bypass fragment screens. Base and current `ScreenPacketInfo` retain the same field type.

**Measurement/consequence split:** The parser's IPv6 payload length and extension-header lengths are protocol `u16` fields; the packet metadata is populated only from those bounded declarations. A value requiring an offset beyond the representable field is not a valid parsed packet shape. The parser rejects malformed/truncated extension chains rather than manufacturing a wrapped offset. An external jumbo/GRO buffer does not make the wire header's u16 fields exceed their bounds, so the proposed production bypass was not reachable.

### GEMINI-049-016 — REFUTED

**Claim/mechanism:** `pack_shared_cos_lease_credits` allegedly smears high bits because it packs two u64 values with a debug-only assertion. The packer itself is unchanged in the compared revisions.

**Measurement/consequence split:** The production lease configuration clamps `burst_bytes`; `max_total_leased` is bounded by the per-bank/active-shard calculation and the u32 ceiling, and acquire/release paths saturate/clamp before packing. The report's >u32 outstanding state is not reachable through the configured production paths. A direct unit call with impossible values can demonstrate a bad bit layout, but it does not establish a production token-accounting failure.

### GEMINI-049-017 — DEFERRED / UNRESOLVED

**Claim/mechanism:** `cookie_reply.rs` and `reject_reply.rs` call `monotonic_nanos()`/`clock_gettime` per generated reply instead of using a batch timestamp. Base and current source confirm those calls, but both helpers are cold, `#[cold] #[inline(never)]` exception paths.

**Measurement/consequence split:** The mechanism is real. No benchmark, profile, or packet-rate measurement showed the claimed throughput collapse, and generated replies are not the ordinary forwarding fast path. This remains a performance candidate requiring a targeted SYN/reject workload profile; no issue was filed without that consequence measurement.

### GEMINI-049-018 — DEFERRED / UNRESOLVED

**Claim/mechanism:** CoS service code has roughly ten `maybe_wake_tx(binding, true, now_ns)` call sites, allegedly forcing a `sendto` and duplicate clock reads on every batch. Base and current call sites and the forced branch exist.

**Measurement/consequence split:** The mechanism is confirmed, but its observable cost depends on bind mode, driver wakeup state, batch rate, and hardware. No throughput, CPU, or syscall-rate measurement was supplied or reproduced. This is left unresolved pending a scoped zero-copy benchmark; it is not mechanically dismissed and no issue was filed.

### GEMINI-049-019 — DEFERRED / UNRESOLVED

**Claim/mechanism:** `UserspaceDpMeta` is 96 bytes and `flow_dst_addr` crosses a 64-byte boundary (base/current layout), allegedly violating an HPC standard and causing material split-load cost.

**Measurement/consequence split:** The split layout is real. The cited `docs/engineering-standards-hpc.md` was not present in this repository, and no cache-miss profile, IPC measurement, or throughput comparison established a product consequence. The struct may be worth a measured optimization, but source layout alone does not validate the claimed degradation.

### GEMINI-049-020 — DEFERRED / UNRESOLVED

**Claim/mechanism:** `compute_v_min_lag_threshold` divides by participating workers and clamps to 24 KB, allegedly making normal 32 KB lease banks trip the throttle. Base and current formula/guards are materially the same.

**Measurement/consequence split:** The arithmetic example can reach the floor for low per-worker rates. However, the production snapshot only throttles when shared exact queues have the required active/lag state; the report did not establish that idle-peer or mixed-rate conditions cause repeated trips, nor measure hard-cap activation or throughput loss. A targeted multi-worker CoS workload is needed; no issue was filed on arithmetic alone.

### GEMINI-049-028 — FILED #10432

**Claim/mechanism:** NAT64 ICMP embedded translation derives the translated inner header length from the bytes present in the truncated quote. At base and current `userspace-dp/src/nat64.rs` v6->v4 reads the original IPv6 payload length only to cap the quote, then computes `total = 20 + actual_l4_bytes` (`:3219-3267`). The v4->v6 path similarly caps the quote from the advertised IPv4 total and writes IPv6 Payload Length from the captured `frag_hdr_len + l4_len` (`:3337-3406`).

**Consequence:** ICMP errors commonly carry only an original IP header plus eight L4 bytes. The translated embedded header then advertises the quote length rather than the original inner datagram length required by RFC 7915 §§4.2/5.2. PMTUD/error demultiplexers that validate the embedded packet can reject or misassociate the translated error. The outer quote remains safely bounded; truncation does not justify changing the inner advertised length. Filed as #10432 with acceptance for both translation directions and truncated-quote tests.

### GEMINI-049-037 — REFUTED

**Claim/mechanism:** The config parser allegedly fails to recognize braced/packed forms of `then` terms. A targeted probe against current source exercised braced `then { next term; }`, packed `then next term;`, and bare `then next;`; all parsed successfully with `NextTerm=true`. Existing `pkg/config/undeclared_keyword_consequence_8807_test.go` also pins the keyword consequence, and the related #8787/#8807 work is closed.

**Measurement/consequence split:** The claimed parser RED state is not reproducible at current master; all three report spellings produce the intended AST. No issue filed.

### GEMINI-049-038 — REFUTED

**Claim/mechanism:** NAT address matching allegedly truncates multi-value address lists to the first value. Base and current compiler code append every value in `natMatchAddressValues(m)` and only use the fallback singular field when the value list is empty.

**Measurement/consequence split:** The asserted first-only behavior does not exist in either measured revision. Multi-address and address-book values are retained for compilation; no policy match consequence was established.

### GEMINI-049-040 — FIXED-SINCE

**Claim/mechanism at base:** An explicit destination port `0`/`0-0` was normalized to the no-constraint sentinel in one compiler path but treated as a parse failure in the other, potentially desynchronizing AppIDs.

**Current measurement:** Current `pkg/appid/catalog.go` calls `NormalizeExplicitPortRange` and gates emission with `dstOK`; current `pkg/dataplane/compiler.go:818-826` applies the same normalization, and both only record `AppNames` for emittable applications. `pkg/appid/catalog_port_zero_5194_test.go` pins that explicit port-zero apps emit no catalog row/name. The base defect is fixed since #5194; no issue filed.

### GEMINI-049-044 — FILED #10434

**Claim/mechanism:** At base and current `pkg/snmp/v3.go` decodes the USM request engine ID into `_` (`:209-214`) and the scoped contextEngineID into `_` (`:335-340`). ContextName is checked, but the decoded engine IDs are not compared with the local authoritative engine.

**Consequence:** An otherwise authenticated request naming a foreign authoritative or context engine can be processed against this agent's local/default MIB context rather than receiving the RFC 3414 unknown-engine/report behavior or a foreign-context rejection. This is distinct from non-default contextName handling (#2611). Discovery with empty username must remain special. Filed as #10434 with acceptance for authoritative/context ID validation and discovery preservation.

### GEMINI-049-045 — REFUTED

**Claim/mechanism:** NetFlow v9 32-bit packet/octet counters allegedly wrap and emit malformed records. The fields are deliberately 32-bit in the NetFlow v9 wire format; natural modulo rollover is expected and collectors use sequence/rollover handling.

**Measurement/consequence split:** A 32-bit counter wrapping is not itself malformed wire data. The report supplied no collector interoperability failure, incorrect template, or unsupported rollover behavior. No issue filed.

### GEMINI-049-048 — REFUTED

**Claim/mechanism:** `Agent.Start` allegedly races on `lastPacket` or performs concurrent frame processing. Base and current start logic drains/handles packet work serially on the agent loop; `lastPacket` is updated/read within that ownership boundary.

**Measurement/consequence split:** No unsynchronized concurrent access or packet reordering was found. The claimed race and resulting handshake corruption are not RED.

### GEMINI-049-050 — REFUTED

**Claim/mechanism:** `confirmRecoveryReadFailed` allegedly clears recovery state even when deleting the recovery file fails. Base/current recovery code returns on a failed delete before clearing the marker; state is cleared only after a successful removal/write path.

**Measurement/consequence split:** The claimed failed-delete-to-clear transition is absent. A retry remains possible, so no permanent recovery-state loss was established.

### GEMINI-049-056 — FIXED-SINCE

**Claim/mechanism at base:** `sendAdvert` read raw `AdvertiseInterval` and emitted zero centiseconds for default/sub-10ms values while the local timer used a 1-second default.

**Current measurement:** `pkg/vrrp/instance_send.go:60-66` now calls `normalizeAdvertIntervalMS9914`, while `instance_timing.go:69-92` uses the same normalization for the timer: non-positive values become 1000 ms, sub-10 ms values become 10 ms, and values above the 12-bit ceiling saturate. Wire and timer values therefore agree. Fixed since #9914; no issue filed.

### GEMINI-049-058 — FIXED-SINCE

**Claim/mechanism at base:** A gen-0 delete after sender guard-cap eviction removed the receiver high-water mark, allowing a reordered older install to resurrect a session.

**Current measurement:** Current `sync_conn_gen.go` has #9719 bounded tombstone ordering and `takeDeleteGenV4` draws a fresh generation for missing sender stamps; receiver installs retain stored generations and nonzero deletes record bounded tombstones. The legacy gen-0 unconditional branch remains intentionally for rolling-upgrade semantics, but the reported cap-eviction path no longer emits gen 0. Fixed since #9719/#2221; no issue filed.

### GEMINI-049-059 — REFUTED

**Claim/mechanism:** Private batch-failover encoders narrow RG counts to uint8, allegedly allowing oversized production batches to wrap on wire. The private encoding shape exists in both revisions.

**Measurement/consequence split:** Every production caller in `sync_failover.go` validates the batch RG count before invoking the encoder (the v4/v6 and bulk paths all check count bounds). An invalid oversized count can be manufactured by a direct private helper test, but it is not reachable through the production API. No issue filed.

### GEMINI-049-060 — FILED #10433

**Claim/mechanism:** `pkg/cluster/sync_fence_ack_7147.go:493-566` uses a direct select between a buffered `waiter` and `timer.C`. If the ACK was queued before the deadline but the waiter goroutine is delayed until the timer is also ready, Go may select the timer case; the timeout arm unregisters without draining `waiter`.

**Consequence:** A valid in-deadline fence ACK can be reported as timeout, increment `FenceAcksTimedOut`, and cause a false unconfirmed-takeover outcome. Filed as #10433 with acceptance for a timeout-arm nonblocking drain/linearization and deterministic both-ready plus true-timeout tests.

### GEMINI-049-064 — REFUTED

**Claim/mechanism:** `flushPendingCallbackFrames` does `copy(queue, queue[1:])` and then reslices without clearing the trailing element. That stale-pointer mechanism is present at base and current in both dequeue sites.

**Measurement/consequence split:** For a backing array `[A,B,C,D]`, successive left-shifts leave `[D,D,D,D]` after the queue drains: the stale references retain only the final frame's object graph, not all 4,096 payloads. The queue is capped and each payload is bounded, so at most one bounded frame remains retained until overwrite/reallocation; the claimed megabytes/unbounded RSS growth is not established. Refuted as a material memory-leak finding, while recording the mechanical zeroing improvement.

### GEMINI-049-068 — FILED #10436

**Claim/mechanism:** `pkg/dataplane/userspace/process.go:303-324` schedules a goroutine that sleeps three seconds, then checks only `m.proc != nil` before calling `bootstrapNAPIQueuesAsyncLocked("startup")`. `stopLocked` increments `m.procGen` (`:423-449`), but the delayed callback captures no generation or process identity. `process_napi.go:17-31` launches load-bearing probe work.

**Consequence:** After generation G1 exits and G2 starts before G1's sleep expires, G1's callback observes G2 as non-nil and triggers startup probes against the wrong/early helper. The two-second throttle limits frequency but does not establish generation ownership. Filed as #10436 with acceptance for generation-scoped cancellation/recheck and crash-then-restart coverage.

### GEMINI-049-070 — REFUTED

**Claim/mechanism:** Synthetic logical-only interfaces receive ifindexes in the `1<<30` range, allegedly overflowing the 65,536-entry TX/counter maps. Base/current allocation remains high by design.

**Measurement/consequence split:** The synthetic value is attached only to `LogicalOnly` rows for interfaces without a physical netdev. Production TX-port and physical counter consumers gate on `LogicalOnly`/physical bindings and do not pass the synthetic index to bounded BPF maps. The report's claimed AddTxPort path is therefore unreachable; no issue filed.

### GEMINI-049-074 — FIXED-SINCE

**Claim/mechanism at base:** FRR route rendering unconditionally stripped `.0`, confusing real VLAN-0/unit-0 netdevs with Junos default-unit references.

**Current measurement:** `pkg/frr/config_render.go:264-283,359-376` now accepts `declaredNetdevs` and probes declared/resolver-owned kernel names before applying the legacy `.0` strip. The daemon builds this declared-aware map for configured and secure-tunnel interfaces (#9821/#9942), and `frr_declared_dotted_9821_test.go` pins the behavior. Fixed since the report base; no issue filed.

### GEMINI-049-077 — REFUTED

**Claim/mechanism:** If `liveConnNames` fails, unconditional `terminateIKE` failures allegedly become permanent teardown debt and wedge future commits. Base/current fallback does record failure/debt when termination fails.

**Measurement/consequence split:** The subsequent `promoteConnNames`/live-name reconciliation unions the debt with the next live set and clears debt for names no longer present; `recordTerminateDebt` is not a permanent latch. A repeated charon failure can delay a commit, but the report's permanent unrecoverable-debt consequence is not supported. No issue filed.

### GEMINI-049-078 — FILED #10435

**Claim/mechanism:** `pkg/networkd/networkd.go:826-836,877-892` emits `MTUBytes` for netdev/link units, while `generateNetwork` (`:905-1008`) has no `MTUBytes`. VLAN children intentionally receive only `.network` files, so their configured MTU is not applied.

**Consequence:** A VLAN/logical child configured at MTU 9000 can remain at the kernel default 1500; jumbo traffic fragments or PMTUD-blackholes despite an accepted configuration. Filed as #10435 with acceptance for `[Link] MTUBytes` in logical/VLAN `.network` output and generator tests.

### GEMINI-049-082 — FILED #10439

**Claim/mechanism:** `pkg/api/show_text.go` dereferences present-but-nil tolerant-load map values in SNMP, DHCP relay, firewall filter/term, dynamic-address, address-book, application, and flow-monitoring loops. The current source contains the same unguarded dereferences; application-set iteration is already nil-guarded by #5221, showing this input shape is supported.

**Consequence:** A nil config slot can panic the affected REST show-text handler, yielding an HTTP failure/500 and a logged stack (Go `net/http` recovers handler panics; this evidence does not claim daemon process death). Repeated requests can produce repeated error/log churn. Filed as #10439 with acceptance for nil-safe iteration preserving valid siblings and successful responses.

### GEMINI-049-084 — REFUTED

**Claim/mechanism:** REST `GET /api/v1/security/match` is `PermView` while gRPC `test-policy:` is `PermControl`, allegedly allowing low-privilege policy reconnaissance.

**Measurement/consequence split:** The REST contract explicitly declares every route a `PermView` read/show route (`pkg/api/authz.go:99-103`), and #6660 documentation plus `read_authz_6660_test.go:168-175` pins every REST read route—including security match—to that tier. gRPC `test-policy`, `test-routing`, and `test-zone` are top-level CLI `test` commands intentionally charged `PermControl`; this is not a REST read-tier bypass. The mechanism (different transport tiers) is real, but the alleged unauthorized REST access is not a defect under the established contract.

### GEMINI-049-085 — FILED #10438

**Claim/mechanism:** `pkg/api/nat.go:169-198` and `pkg/grpcapi/server_nat.go:33-63` set source NAT `Type` only for interface/pool actions. They omit `then source-nat off` and actionless/none states. The structured `NATSourceInfo` schemas also have no source-match field, but this filing does not treat that additive schema question as an independently proven regression.

**Consequence:** REST/gRPC inspection cannot distinguish a configured NAT exemption from an incomplete/actionless rule, impairing automation and security audits. The concrete defect is the empty action/type; it concerns observability, not dataplane enforcement. Filed as #10438 with acceptance for shared `SourceRuleAction` rendering of `off`, `interface`, `pool`, and `none`; any source-match schema extension requires a separate contract decision.

### GEMINI-049-086 — FILED #10437

**Claim/mechanism:** `pkg/api/nat.go:201-235` and `pkg/grpcapi/server_nat.go:65-94` copy only scalar `rule.Match.DestinationAddress`. Plural `DestinationAddresses` and `DestinationAddressNames` are retained by the parser and rendered by `pkg/natshow.RuleMatchDestination`, but are absent from these API responses.

**Consequence:** A destination NAT rule matching multiple prefixes or an address-book name is returned blank/first-only, so API consumers cannot reconstruct its actual scope and can make false policy-compliance decisions. Filed as #10437 with acceptance for canonical complete rendering and REST/gRPC parity tests.

### GEMINI-049-087 — REFUTED

**Claim/mechanism:** `pkg/grpcapi/server_routing.go:GetRoutes` calls the main-table `s.routing.GetRoutes`, while an all-table helper exists elsewhere; the report treats omission of VRFs as a bug.

**Measurement/consequence split:** The called operation is explicitly documented as reading the main kernel routing table, and the v1 protobuf has neither a table selector nor table identity. There is no established contract that this RPC means “all VRFs”; flattening all tables would be ambiguous. Supporting all-table/selector output is a possible API enhancement, not a validated defect. The transient #10441 opened during parallel filing was closed as not planned after this evidence was checked.

### GEMINI-049-088 — FILED #10440

**Claim/mechanism:** `pkg/grpcapi/server_diag.go:28-119` declares `dialPeer()` without a context and creates each liveness probe with `context.WithTimeout(context.Background(), 2s)` (`:77-81`). Current callers still invoke it before their caller-scoped RPC; `server_show.go:655-663` documents that the full probe budget is not covered by the outer context.

**Consequence:** A canceled/short-deadline request can continue dialing and probing for up to the per-fabric budget after the client is gone. The probe invokes peer `GetStatus`, which takes the session-walk limiter and scans session state, wasting control-plane work under cancellation storms. Filed as #10440 with acceptance for caller-context propagation through all dial/probe paths.

### GEMINI-049-089 — FIXED-SINCE

**Claim/mechanism at base:** REST DHCP leases queried only `s.dhcp.Leases()` and had no PD field, while gRPC included `DelegatedPrefixes` (#5382).

**Current measurement:** `pkg/api/dhcp.go:14-56` now calls `restDHCPLeases(s.dhcp.Leases(), s.dhcp.DelegatedPrefixes())`, delegates aggregation to `grpcapi.BuildDHCPLeasesResponse`, and attaches `DelegatedPrefixes` to each REST row. `pkg/api/types.go:559-581` defines the PD fields. Fixed since #9413; no issue filed.

### GEMINI-049-097 — REFUTED

**Claim/mechanism:** DHCP relay raw-L2 frame construction allegedly casts an oversized payload to u16 when interface MTU is unset. The helper has the reported cast shape at base/current.

**Measurement/consequence split:** A valid IPv4/UDP datagram is bounded to 65,535 total bytes, so UDP payload is at most 65,507 bytes and the production serialized DHCP packet cannot reach the claimed `totalLen > 65,535` through a valid protocol input. The report's oversized payload requires an impossible/malformed helper-only argument; no reachable relay consequence was established.

### GEMINI-049-098 — REFUTED

**Claim/mechanism:** For an unknown `FromZone` to `junos-host`, `policymatch` sets `HostInboundUnmatched`, allegedly meaning local delivery, while Rust installs an empty host-inbound sentinel for unzoned interfaces.

**Measurement/consequence split:** `HostInboundUnmatched` means no fine-grained security policy matched; it does not mean the packet bypasses the host gate. For a nonempty unknown zone, `viewsForZone` returns no views and `ClassifyHostInbound` deliberately classifies an empty view; `classifyOneView` returns `HostInboundDenied` (the `HostInboundNotComputed` guard applies only to nil config or an empty zone string). REST/gRPC include this admission object and the CLI renders `Describe()` as denied. The Rust empty sentinel therefore agrees with the simulator's host admission. The report's claimed `NotComputed` probe and false-permit consequence are incorrect; no issue filed.

### GEMINI-049-099 — REFUTED

**Claim/mechanism:** DHCP relay drops DHCPRELEASE from client-facing broadcast input and allegedly causes lease exhaustion. Base/current intentionally omit RELEASE from `clientRequestRelayable`.

**Measurement/consequence split:** RFC 2131 §4.4.4 specifies DHCPRELEASE as a unicast message sent to the server to which the client is bound; the relay's documented client-broadcast relay set is for discovery/request/inform/decline flows. The report relies on nonstandard client behavior outside that contract and supplied no product requirement to relay broadcast RELEASE. No issue filed.

## Verification record

- The scoped parser proof `TMPDIR=/home/ps/git/pi-xpf/.tmp-med go test ./pkg/config -run 'TestTheTwelveUndeclaredKeywordsHaveNoSilentDrop8807|TestFilterAction_NextTerm_CommitsAndMarks' -count=1` ran real tests and passed (`ok github.com/psaab/xpf/pkg/config 0.145s`).
- Issue filing responses and URLs are recorded above; all nine open issues carry the required labels.
- The transient #10441 for #087 was closed as not planned before this log was finalized.
- No formatter, linter, project-wide build, or project-wide test suite was run in this lane. The parent lane owns final repository-wide validation.
