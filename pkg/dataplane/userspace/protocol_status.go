package userspace

import (
	"encoding/json"
	"time"
)

type ProcessStatus struct {
	PID                              int `json:"pid"`
	ConfigSnapshotProtocolVersion    int `json:"config_snapshot_protocol_version,omitempty"`
	InjectPacketTupleProtocolVersion int `json:"inject_packet_tuple_protocol_version,omitempty"`
	// SessionExportPagingProtocolVersion is the owner-RG session export PAGING
	// contract the helper implements (#9344). 0 (or absent) means no paging.
	//
	// A helper reporting 0 honours SessionExportRequest.Max by TRUNCATING and
	// reports no ControlResponse.SessionExportMore bit, so a caller must ask it
	// for the unbounded set (Max=0) rather than page it. That fallback keeps
	// the pre-#9344 behaviour exactly, including its 64 MiB failure — which
	// #9322 made diagnosable — instead of trading a loud failure for a silent
	// truncation, and a truncated window is what #5085's authoritative receiver
	// turns into deleted live sessions on the peer.
	//
	// An explicit version rather than a probe: an answer of exactly Max deltas
	// with SessionExportMore false is EITHER a new helper whose page consumed
	// the window exactly OR an old helper that dropped the remainder, and the
	// probe that would separate them is unsafe on the old helper (it ignores
	// the unknown `continuation` field and runs a second full export).
	SessionExportPagingProtocolVersion int `json:"session_export_paging_protocol_version,omitempty"`
	// SessionDeltaSchemaFingerprint is the helper's DERIVED session-open delta
	// schema identity (#7194). 0 == not advertised (helper predates the field),
	// which CompareSessionDeltaSchema treats as unknown-and-deferred rather
	// than as a mismatch.
	SessionDeltaSchemaFingerprint uint64 `json:"session_delta_schema_fingerprint,omitempty"`
	// LinkedLibxdpVersion is the build host's libxdp (pkg-config) the helper
	// statically linked, and LinkedLibbpfVersion the full version of the vendored
	// libbpf it linked. BuildHostLibbpfVersion is the build host's libbpf
	// (pkg-config); it is not linked, and it does not identify what libxdp was
	// compiled against (#9726). Empty from a helper that predates them.
	LinkedLibxdpVersion    string                `json:"linked_libxdp_version,omitempty"`
	LinkedLibbpfVersion    string                `json:"linked_libbpf_version,omitempty"`
	BuildHostLibbpfVersion string                `json:"build_host_libbpf_version,omitempty"`
	StartedAt              time.Time             `json:"started_at"`
	ControlSocket          string                `json:"control_socket"`
	StateFile              string                `json:"state_file"`
	Workers                int                   `json:"workers"`
	RingEntries            int                   `json:"ring_entries"`
	HelperMode             string                `json:"helper_mode"`
	IOUringPlanned         bool                  `json:"io_uring_planned"`
	IOUringActive          bool                  `json:"io_uring_active,omitempty"`
	IOUringMode            string                `json:"io_uring_mode,omitempty"`
	IOUringLastError       string                `json:"io_uring_last_error,omitempty"`
	Enabled                bool                  `json:"enabled"`
	ForwardingArmed        bool                  `json:"forwarding_armed,omitempty"`
	Capabilities           UserspaceCapabilities `json:"capabilities"`
	// LastSnapshotRejectReasons is the manager-owned (#3261) diagnostic
	// recording why the most recent snapshot build carries unrepresentable
	// policy content that the helper integrity preflight rejects (previous-good
	// retained / fresh-boot default-deny — never fail-open). It is STAMPED by
	// recordHelperStatusLocked from m.lastSnapshotRejectReasons, NOT reported
	// by the helper (which strips the unknown PolicyContentRejected field on
	// round-trip). Empty means the last build was fully representable. Surfaced
	// as xpf_userspace_policy_content_rejected so the Go/Rust status skew
	// (ForwardingSupported=true while the helper rejected the snapshot) is
	// observable.
	LastSnapshotRejectReasons []string `json:"last_snapshot_reject_reasons,omitempty"`
	// ZoneIDCollisions is the manager-owned (#3719) diagnostic listing every
	// security zone the last snapshot build QUARANTINED because its StableZoneID
	// collided with an earlier-sorting zone. The strict commit path rejects a
	// collision, but a lenient/HA-sync/pre-#3075-persisted config keeps booting
	// with the colliding zone dropped from the dataplane (fail-closed: its
	// interfaces are unzoned and its traffic denied) so two zones never share a
	// numeric id. Like LastSnapshotRejectReasons it is stamped by
	// recordHelperStatusLocked from m.lastZoneIDCollisions (the helper cannot
	// carry it), surfaced as xpf_userspace_zone_id_collision so an operator is
	// paged until one zone is renamed. Empty means no active collision.
	ZoneIDCollisions       []string  `json:"zone_id_collisions,omitempty"`
	LastSnapshotGeneration uint64    `json:"last_snapshot_generation"`
	LastFIBGeneration      uint32    `json:"last_fib_generation,omitempty"`
	LastSnapshotAt         time.Time `json:"last_snapshot_at,omitempty"`
	InterfaceAddresses     int       `json:"interface_addresses,omitempty"`
	NeighborEntries        int       `json:"neighbor_entries,omitempty"`
	SessionTableEntries    uint64    `json:"session_table_entries,omitempty"`
	MaxSessions            uint64    `json:"max_sessions,omitempty"`
	// #1760: aggregate NAT reverse-key displacement events summed across
	// the per-worker session tables -- the latent 1:N collision (#1758)
	// made observable. Near-precise upper bound on live collisions (counts
	// displacement events, not distinct flow-pairs). Nonzero triggers the
	// structural-fix research; does NOT resolve #1760. omitempty for
	// mixed Rust/Go daemon back-compat.
	NatReverseKeyCollisions uint64 `json:"nat_reverse_key_collisions,omitempty"`
	// NatReverseKeyCollisionsDistinctSrc is the DIFFERENT-SOURCE subset of the
	// counter above (#6751). The aggregate cannot separate the cross-session
	// leak from one host reusing an ephemeral port, and only the former is what
	// PAT-on-collision would fix.
	NatReverseKeyCollisionsDistinctSrc uint64 `json:"nat_reverse_key_collisions_distinct_src,omitempty"`
	// #1861: aggregate at-cap install refusals (SessionTable create_drops,
	// write-only/invisible before #1861), pair-admission preflight
	// refusals (one per refused flow at the new-flow transaction
	// boundary), and post-preflight partial-install residuals (expected
	// 0 forever; nonzero = preflight/install pairing bug). omitempty for
	// mixed Rust/Go daemon back-compat (older helpers omit the keys).
	SessionCreateDrops             uint64 `json:"session_create_drops,omitempty"`
	SessionInstallAdmissionRefused uint64 `json:"session_install_admission_refused,omitempty"`
	SessionInstallPartial          uint64 `json:"session_install_partial,omitempty"`
	FlowCacheCapacity              uint64 `json:"flow_cache_capacity,omitempty"`
	NeighborCacheCapacity          uint64 `json:"neighbor_cache_capacity,omitempty"`
	NeighborGeneration             uint64 `json:"neighbor_generation,omitempty"`
	// ManagerNeighborGeneration is the helper's ACK (#6034) of the highest
	// authoritative manager-neighbor REPLACE generation it has applied. It
	// echoes the NeighborGeneration the manager stamps on each
	// update_neighbors replace (distinct from NeighborGeneration above, which
	// is the dynamic ARP/NDP resolver epoch). The send path advances its
	// cached neighbor view only when this ACK confirms the replace landed
	// (>= the sent generation); a lower value means the helper fenced the
	// replace as stale, so the manager retains retry debt and re-diffs on the
	// next regeneration. omitempty for mixed Rust/Go back-compat: an older
	// helper omits it (decodes 0), which the send path treats as "no ACK
	// support, assume applied" to preserve pre-#6034 behavior.
	ManagerNeighborGeneration uint64      `json:"manager_neighbor_generation,omitempty"`
	RouteEntries              int         `json:"route_entries,omitempty"`
	WorkerHeartbeats          []time.Time `json:"worker_heartbeats,omitempty"`
	// #869: per-worker busy/idle runtime telemetry.
	WorkerRuntime []WorkerRuntimeStatus `json:"worker_runtime,omitempty"`
	HAGroups      []HAGroupStatus       `json:"ha_groups,omitempty"`
	Fabrics       []FabricSnapshot      `json:"fabrics,omitempty"`
	Queues        []QueueStatus         `json:"queues,omitempty"`
	Bindings      []BindingStatus       `json:"bindings,omitempty"`
	// #802: focused per-binding ring-pressure view. Projected from
	// Bindings by the Rust helper; parallel rather than replacement.
	PerBinding []BindingCountersSnapshot `json:"per_binding,omitempty"`
	// #1249: bounded low-frequency diagnostic map from active flow-cache
	// entries to the worker/RX queue that currently owns them. This is
	// status/debug data only, not a production metric or scheduler input.
	FlowWorkerMap          []FlowWorkerStatus `json:"flow_worker_map,omitempty"`
	FlowWorkerMapTruncated bool               `json:"flow_worker_map_truncated,omitempty"`
	// #1248: per-CoS-queue active flow distribution by egress ifindex,
	// queue, and worker. This is the class-specific {a_i} source for
	// mixed-workload fairness diagnostics.
	CoSActiveFlowCounts          []CoSActiveFlowCountStatus `json:"cos_active_flow_counts,omitempty"`
	CoSActiveFlowCountsTruncated bool                       `json:"cos_active_flow_counts_truncated,omitempty"`
	RecentSessionDeltas          []SessionDeltaInfo         `json:"recent_session_deltas,omitempty"`
	RecentExceptions             []ExceptionStatus          `json:"recent_exceptions,omitempty"`
	EventStream                  *EventStreamStatus         `json:"event_stream,omitempty"`
	EventStreamSent              uint64                     `json:"event_stream_sent,omitempty"`
	EventStreamDropped           uint64                     `json:"event_stream_dropped,omitempty"`
	// #1642: the Rust helper serializes these three flat event-stream
	// fields on ProcessStatus (protocol/control.rs) alongside _sent /
	// _dropped, but the Go side only declared _sent / _dropped, so
	// connected / seq / acked were silently dropped. The nested
	// *EventStreamStatus above carries different, Go-populated counters
	// (frames_read, decode_errors) the Rust helper never emits. JSON tags
	// MUST match Rust serde rename(...) exactly.
	EventStreamConnected bool   `json:"event_stream_connected,omitempty"`
	EventStreamSeq       uint64 `json:"event_stream_seq,omitempty"`
	EventStreamAcked     uint64 `json:"event_stream_acked,omitempty"`
	// EventStreamWriteStalls counts I/O cycles in which the helper's
	// event-stream socket-write backlog hit its cap and the helper stopped
	// draining the bounded channel because the daemon reader was wedged
	// (#2381). A growing value means dataplane telemetry is being shed at the
	// bounded channel (counted via EventStreamDropped) because this consumer
	// is not draining the socket; the forwarding plane is unaffected. JSON tag
	// MUST match the Rust serde rename(...) exactly.
	EventStreamWriteStalls uint64 `json:"event_stream_write_stalls,omitempty"`
	// EventStreamReplayEvictions counts accepted RT_FLOW / dataplane-telemetry
	// frames the helper evicted from its replay buffer when the buffer wrapped
	// at capacity before the daemon ACKed them (#2382). These frames were
	// already counted in EventStreamSent at enqueue but are permanently lost
	// after reconnect, so a growing value means telemetry was dropped via
	// replay-buffer eviction (a disconnected or non-ACKing daemon let the
	// window wrap). It is distinct from ACK-trim (acknowledged-frame removal,
	// which is NOT a loss and is NOT counted here). JSON tag MUST match the
	// Rust serde rename(...) exactly.
	EventStreamReplayEvictions uint64 `json:"event_stream_replay_evictions,omitempty"`
	// EventStreamInvalidAcks counts MSG_ACK control frames the helper rejected
	// because the daemon ACKed a sequence outside the valid [acked_seq,
	// next_seq] window — a backward ACK (seq < acked) or a future ACK of a
	// sequence never allocated (seq > next) (#2959). The helper fails closed
	// and ignores such an ACK (watermark + replay buffer left intact), so a
	// growing value means a buggy, mixed-version, or corrupted daemon-side
	// listener is emitting impossible ACK watermarks. JSON tag MUST match the
	// Rust serde rename(...) exactly.
	EventStreamInvalidAcks uint64 `json:"event_stream_invalid_acks,omitempty"`
	// #2512: per-kind producer-side accounting for the RT_FLOW SESSION_CLOSE
	// (type 14) and SESSION_CREATE (type 15) frames. Before #2512 these were
	// emitted via a bare `try_send` that bypassed the helper's per-kind rate
	// limiter, queue budget, and sent/dropped counters, so a dropped
	// close/create was invisible. _Sent counts frames accepted onto the event
	// channel; _Dropped sums rate-limited + queue-full + disconnected drops
	// for that kind. A dropped SESSION_CLOSE loses only one flow-export/syslog
	// record — the type-2 HA session-sync close delta rides a separate,
	// never-rate-limited frame, so consumer session state self-heals via the
	// 1s session sweep. JSON tags MUST match the Rust serde rename(...).
	EventStreamSessionCloseSent     uint64                    `json:"event_stream_session_close_sent,omitempty"`
	EventStreamSessionCloseDropped  uint64                    `json:"event_stream_session_close_dropped,omitempty"`
	EventStreamSessionCreateSent    uint64                    `json:"event_stream_session_create_sent,omitempty"`
	EventStreamSessionCreateDropped uint64                    `json:"event_stream_session_create_dropped,omitempty"`
	CoSInterfaces                   []CoSInterfaceStatus      `json:"cos_interfaces,omitempty"`
	PolicyRuleCounters              []PolicyRuleCounterStatus `json:"policy_rule_counters,omitempty"`
	// NATRuleCounters carries the userspace dataplane's per-rule SNAT/DNAT/
	// static-NAT translation hit counters keyed by the compiler-assigned
	// counter ID (#2218). The Go control plane mirrors these into the legacy
	// bpfShim nat_rule_counters offset map so Manager.ReadNATRuleCounter (and
	// thus `show security nat source/destination/static rule`) reports the
	// live translation count instead of a perpetual 0.
	NATRuleCounters    []NATRuleCounterStatus            `json:"nat_rule_counters,omitempty"`
	FilterTermCounters []FirewallFilterTermCounterStatus `json:"filter_term_counters,omitempty"`
	// #3651: per-zone ingress/egress traffic (packet + byte) volume, summed
	// across every worker/binding by the helper (ProcessStatus-level
	// pre-summed sparse block, one row per zone with nonzero traffic keyed by
	// the stable zone id). syncBPFCountersLocked mirrors each row into the
	// legacy bpfShim zone-counter offset map via ReplaceZoneCounterOffsets so
	// Manager.ReadZoneCounters (and thus `show security zones` Traffic
	// statistics, REST /security/zones, and the Prometheus collector) reports
	// live per-zone volume instead of ErrCounterNotPopulated ("not
	// available"). ZoneCounterLayoutVersion selects the decode path (0/absent =
	// pre-#3651 helper, no per-zone data); ZoneCounterOverflowActive means the
	// configured zone count exceeded the helper's dense hot-path slot capacity
	// so some zones went uncounted. JSON tags MUST match the Rust serde
	// rename(...) exactly.
	ZoneCounterLayoutVersion  uint32                     `json:"zone_counter_layout_version,omitempty"`
	ZoneCounterOverflowActive bool                       `json:"zone_counter_overflow_active,omitempty"`
	ZoneTrafficCounters       []ZoneTrafficCounterStatus `json:"zone_traffic_counters,omitempty"`
	// #3651: per-zone SYN/ICMP/UDP flood-EVENT counts, summed across every
	// worker by the helper (a second ProcessStatus-level pre-summed sparse
	// block, one row per zone with nonzero flood drops keyed by the stable zone
	// id). syncBPFCountersLocked mirrors each row into the legacy bpfShim
	// flood-counter offset map via ReplaceFloodCounterOffsets so
	// Manager.ReadFloodCounters (and thus `show security screen ids-option
	// statistics`) reports live per-zone flood counts instead of
	// ErrCounterNotPopulated ("not available"). FloodCounterLayoutVersion
	// selects the decode path (0/absent = helper with no per-zone flood
	// accounting); FloodCounterOverflowActive means the configured zone count
	// exceeded the helper's dense slot capacity so some zones went uncounted.
	// JSON tags MUST match the Rust serde rename(...) exactly.
	FloodCounterLayoutVersion  uint32                    `json:"flood_counter_layout_version,omitempty"`
	FloodCounterOverflowActive bool                      `json:"flood_counter_overflow_active,omitempty"`
	ZoneFloodCounters          []ZoneFloodCounterStatus  `json:"zone_flood_counters,omitempty"`
	ThreeColorPolicerCounters  []ThreeColorPolicerStatus `json:"three_color_policer_counters,omitempty"`
	SourceNATPools             []SourceNATPoolStatus     `json:"source_nat_pools,omitempty"`
	LastResolution             *PacketResolution         `json:"last_resolution,omitempty"`
	SlowPath                   SlowPathStatus            `json:"slow_path,omitempty"`
	LastCacheFlushAt           uint64                    `json:"last_cache_flush_at,omitempty"`    // monotonic secs (#312)
	DataplaneMode              string                    `json:"dataplane_mode,omitempty"`         // Current active mode: "ebpf_only", "userspace_compat", "userspace_strict"
	ConfiguredMode             string                    `json:"configured_mode,omitempty"`        // Desired mode from config
	EntryPrograms              map[int]string            `json:"entry_programs,omitempty"`         // ifindex -> attached XDP program name
	DegradedPathCounters       map[string]uint64         `json:"degraded_path_counters,omitempty"` // reason_name -> count
	// #1636 option C: proactive-neighbor-warm telemetry. WarmDrops counts
	// warm requests dropped because the bounded warmer queue was full
	// (transient); WarmDisconnected counts requests dropped because the
	// warmer worker thread died (fatal — warming disabled until restart).
	NeighborWarmDropsTotal        uint64 `json:"neighbor_warm_drops_total,omitempty"`
	NeighborWarmDisconnectedTotal uint64 `json:"neighbor_warm_disconnected_total,omitempty"`
	// #1782 cold-start capture instrumentation. NegNeighFastFailTotal is
	// the per-binding-summed count of neg-neigh-cache fast-fails (the H1
	// amplifier signal); PendingNeighDuplicateDropsTotal is the count of
	// pending_neigh sibling drops where the (egress_ifindex, next_hop)
	// key was already pending (the H5 sibling-drop signal).
	// DynamicNeighborKeys is a debug dump of every key in the helper's
	// dynamic_neighbors mirror ("ifindex ip"), surfaced as the per-key
	// xpf_userspace_dynamic_neighbor_present gauge so the capture harness
	// can confirm the t0' next-hop miss (the H2 fingerprint). It is gated
	// behind the helper's XPF_DEBUG_NEIGHBOR_KEYS env var and is empty by
	// default — an empty slice (and an absent gauge family) does NOT mean
	// the mirror is empty, only that the debug dump was not enabled. All
	// are omitempty for wire-compat with older helpers.
	NegNeighFastFailTotal           uint64 `json:"neg_neigh_fast_fail_total,omitempty"`
	PendingNeighDuplicateDropsTotal uint64 `json:"pending_neigh_duplicate_drops_total,omitempty"`
	// #1902: GRE-decapped MissingNeighbor packets refused pending_neigh
	// admission — buffering the outer UMEM frame with the post-decap
	// inner meta would retry-TX a mis-rewritten outer packet once the
	// neighbor resolves.
	PendingNeighDecapDropsTotal uint64 `json:"pending_neigh_decap_drops_total,omitempty"`
	// #7106: buffers the helper RETAINED (leaked) at io_uring ring teardown
	// because the bounded drain could not prove the kernel had finished with
	// them. Normally 0; non-zero means a ring was retired with writes it could
	// not prove terminal, and their buffers were deliberately not freed rather
	// than risk the kernel writing into a freed allocation.
	// #8447: source-NAT rule-match outcomes. Consulted counts every packet that
	// REACHED the match path, including ones that matched nothing — it is what
	// makes a zero in the other three readable, because without it "nothing
	// matched" and "nothing arrived" are the same number. Zero from an older
	// helper that predates the counters; JSON tags MUST match the Rust serde
	// names.
	SourceNATMatchConsultedTotal   uint64 `json:"source_nat_match_consulted_total,omitempty"`
	SourceNATMatchMatchedTotal     uint64 `json:"source_nat_match_matched_total,omitempty"`
	SourceNATMatchUnavailableTotal uint64 `json:"source_nat_match_unavailable_total,omitempty"`
	SourceNATMatchNoMatchTotal     uint64 `json:"source_nat_match_no_match_total,omitempty"`
	IoUringRetainedBuffersTotal    uint64 `json:"io_uring_retained_buffers_total,omitempty"`
	IoUringRetainedBytesTotal      uint64 `json:"io_uring_retained_bytes_total,omitempty"`
	// #2375: MissingNeighbor packets for a NEW distinct (egress_ifindex,
	// next_hop) refused because pending_neigh is at MAX_PENDING_NEIGH
	// distinct hops (distinct-hop neighbor exhaustion — the
	// scan/upstream-outage failure mode). Separate from
	// PendingNeighDuplicateDropsTotal (the key was already pending —
	// normal cold-start coalescing).
	PendingNeighCapacityDropsTotal uint64 `json:"pending_neigh_capacity_drops_total,omitempty"`
	// #5673: cumulative data-path neighbor learns refused because the shared
	// dynamic-neighbor map's target shard was at MAX_DYNAMIC_NEIGHBORS_PER_SHARD.
	// Source-address learning runs on RX before screen/policy admission, so a
	// rising value is the always-on signal that the aggregate cap is bounding a
	// spoofed-source pre-policy flood (CPU/memory DoS) rather than letting it
	// inflate the map.
	DynamicNeighborLearnCapDropsTotal uint64   `json:"dynamic_neighbor_learn_cap_drops_total,omitempty"`
	DynamicNeighborKeys               []string `json:"dynamic_neighbor_keys,omitempty"`
	// #1789: total failed USERSPACE_SESSIONS BPF-map publishes (per-binding
	// worker-poll sites summed with the shared no-binding sites: HA upsert,
	// session-glue worker publish, post-reconcile replay, activation/reverse
	// prewarm). A failed publish means the XDP shim never learns the session
	// key and takes the NO_SESSION degraded path (drop in STRICT mode), so a
	// rising value is the cause-side signal for rising shim no-session
	// fallbacks (session map at capacity, stale fd after reconcile). Surfaced
	// as xpf_userspace_session_publish_errors_total. Omitempty for wire
	// compat with older helpers.
	SessionPublishErrorsTotal uint64 `json:"session_publish_errors_total,omitempty"`
	// #4800 new-flow-install contention surface. These six counters plus
	// the depth high-water are what let a connection-rate run name the
	// saturated cross-worker synchronization point rather than infer one
	// from a flattened new-flows/sec curve.
	//
	// SharedSessionPublishesTotal is the publish-leg new-flow rate.
	// SharedSessionPublishLock{Acquisitions,Contended}Total are the
	// shared-map mutex pair scoped to publish_shared_session alone; their
	// ratio is the publish leg's blocked fraction.
	// SessionReplication{Upserts,Enqueued}Total give the replication call
	// rate and, as Enqueued/Upserts, the N-way sibling fan-out multiplier.
	// SessionReplicationLockContendedTotal is the blocked subset of those
	// enqueues (denominator: Enqueued).
	// SessionReplicationQueueDepthSum accumulates the per-call deepest
	// sibling-queue depth. Divided by SessionReplicationUpsertsTotal over
	// the same window it is the MEAN worst-sibling depth per replicated
	// flow — the differenceable backlog statistic, and the only one any
	// verdict may rest on.
	// SessionReplicationQueueDepthMax is a MONOTONIC PROCESS-LIFETIME
	// high-water gauge — never rate() it, and never difference it either:
	// it cannot fall, so a zero delta means "no backlog" OR "a backlog up
	// to the previous all-time high", and one spike leaves the absolute
	// value elevated for the life of the helper. It is operator context
	// only. Contention means producers collided on the queue mutex; depth
	// means the consuming worker is not draining as fast as producers
	// enqueue. Different failure modes, different fixes.
	//
	// The NAT-allocator leg of the same question is per pool and lives on
	// SourceNATPoolStatus.LiveLock*, not here. Omitempty for wire compat
	// with older helpers; JSON tags MUST match the Rust serde rename(...)
	// exactly (protocol/control.rs).
	SharedSessionPublishesTotal               uint64 `json:"shared_session_publishes_total,omitempty"`
	SharedSessionPublishLockAcquisitionsTotal uint64 `json:"shared_session_publish_lock_acquisitions_total,omitempty"`
	SharedSessionPublishLockContendedTotal    uint64 `json:"shared_session_publish_lock_contended_total,omitempty"`
	SessionReplicationUpsertsTotal            uint64 `json:"session_replication_upserts_total,omitempty"`
	SessionReplicationEnqueuedTotal           uint64 `json:"session_replication_enqueued_total,omitempty"`
	SessionReplicationLockContendedTotal      uint64 `json:"session_replication_lock_contended_total,omitempty"`
	SessionReplicationQueueDepthSum           uint64 `json:"session_replication_queue_depth_sum,omitempty"`
	SessionReplicationQueueDepthMax           uint64 `json:"session_replication_queue_depth_max,omitempty"`
	// #9169: the FOURTH #4800 site. Every session delta -- Open as well as
	// Close -- allocates its wire sequence number and encodes its frame inside
	// the helper's process-global producer_seq_lock, because #3878 F-152
	// requires the allocation and the channel enqueue to be atomic together.
	// That makes it a cross-worker serialization point on the new-flow path,
	// and it was absent from docs/userspace-newflow-ceiling.md's three-site
	// model -- so a run that saturated here would have reported a plateau with
	// every named site cold and nothing to attribute it to. (Counterfactual:
	// that harness has not been run. The bound is static.)
	//
	// A pair, always read together: a contended count without its denominator
	// is not interpretable, and "never taken" is a different finding from
	// "taken but never blocked". The helper's I/O-thread replay-gap allocation
	// takes the same mutex and is deliberately excluded from the denominator
	// (not a producer, once per reconnect); its blocking effect still shows up
	// as producer contention.
	//
	// Omitempty for wire compat with older helpers; JSON tags MUST match the
	// Rust serde rename(...) exactly (protocol/status.rs).
	EventStreamProducerSeqLockAcquisitionsTotal uint64 `json:"event_stream_producer_seq_lock_acquisitions_total,omitempty"`
	EventStreamProducerSeqLockContendedTotal    uint64 `json:"event_stream_producer_seq_lock_contended_total,omitempty"`
	// DnatPublishErrorsTotal counts failed dnat_table reverse-SNAT BPF-map
	// publishes across userspace workers (#2244). The dnat_table is the
	// reverse lookup the embedded-ICMP NAT path consults to map an inbound
	// ICMP error (PMTUD Packet Too Big / Time Exceeded / traceroute) back
	// to the original pre-NAT source; a failed publish (map at capacity,
	// EINVAL) silently omits the record so the error is dropped or
	// mis-delivered. A rising value is the cause-side signal for dnat_table
	// map-capacity pressure. Surfaced as
	// xpf_userspace_dnat_publish_errors_total. Omitempty for wire compat
	// with older helpers.
	DnatPublishErrorsTotal uint64 `json:"dnat_publish_errors_total,omitempty"`
	// SyncedImportCapDropsTotal counts peer-synced session imports rejected by
	// the coordinator's aggregate admission bound (#5674). Locally-created
	// sessions are capped per worker at max_sessions; peer-synced imports were
	// previously uncapped and fanned out to every worker command queue+table, so
	// a peer under session-table pressure (or a compromised peer) could drive
	// this node past its own aggregate session ceiling and multiply that state
	// across all workers — an availability/DoS the local admission bound is meant
	// to prevent. The bound is this appliance's own aggregate ENTRY ceiling
	// (2 * worker_count * max_sessions — 2x the logical session ceiling, because
	// each admitted forward publishes a forward plus a synthesized reverse
	// companion). 2N is the FORWARD-key admission threshold, not an absolute map
	// maximum — a lone reverse import bypasses the gate, so occupancy can
	// momentarily reach 2N+1. A rising value means a peer's import would push
	// THIS appliance past its own aggregate entry ceiling — receiver-local, so a
	// larger asymmetric peer (more workers/max_sessions than this receiver) can
	// legitimately trip a smaller receiver's cap without exceeding its own
	// ceiling. A symmetric-pair failover (N logical sessions = 2N entries)
	// exactly fits and never trips it. Surfaced as
	// xpf_userspace_synced_import_cap_drops_total.
	// Omitempty for wire compat with older helpers.
	SyncedImportCapDropsTotal uint64 `json:"synced_import_cap_drops_total,omitempty"`
	// #1760 W3': shared-map NAT reverse-key displacement events — a
	// publish_shared_session insert into shared_nat_sessions displaced a
	// DIFFERENT forward session's entry at the same reverse key (two live
	// forward NAT sessions mapping onto one reply tuple — the #1758/#1760
	// latent 1:N collision). The shared map is the single choke point all
	// transit forward NAT sessions pass through, including
	// MissingNeighborSeed installs the per-worker
	// nat_reverse_key_collisions counter cannot see. Event count, not a
	// pair census. Surfaced as
	// xpf_userspace_session_nat_reverse_key_shared_displacements_total.
	// Omitempty for wire compat with older helpers.
	NatReverseKeySharedDisplacementsTotal uint64 `json:"nat_reverse_key_shared_displacements_total,omitempty"`
	// InterfaceSNATPATCollisionsTotal is #6751 PR 2/3: interface-mode SNAT
	// identity-mint conflicts that took the PAT probe. Interface SNAT used
	// to preserve the source port unconditionally, so two internal hosts
	// picking one port to one server produced BYTE-IDENTICAL reverse keys
	// and the replies for both went to whichever session installed first.
	// The mint now reserves the translated reverse identity and moves the
	// LATER collider's port. A nonzero value here is that shape actually
	// occurring. Surfaced as
	// xpf_userspace_interface_snat_pat_collisions_total. Omitempty for wire
	// compat with older helpers.
	InterfaceSNATPATCollisionsTotal uint64 `json:"interface_snat_pat_collisions_total,omitempty"`

	// NAT64FragCrossDomainMissesTotal is #7056 (#5798 required-fix #5):
	// fragment-association misses where a same-datagram entry existed under a
	// DIFFERENT ingress security domain. The fail-closed refusal is #6835's;
	// this is the observability half required-fix #5 asked for. Before it,
	// such a miss was indistinguishable from a reorder, a TTL straddle, a
	// shard eviction or a config-generation bump — all of which land on
	// nat64_frag_dropped. This is the only one of that group that describes
	// the TRAFFIC rather than cache pressure.
	NAT64FragCrossDomainMissesTotal uint64 `json:"nat64_frag_cross_domain_misses_total,omitempty"`

	// NAT64FragProtocolAliasMissesTotal is #7056's sibling leg: same ingress
	// domain, different upper-layer protocol — a TCP and a UDP datagram that
	// collided on (src, dst, ident) and were separated by the #5798 `protocol`
	// key field. Kept DISTINCT from the cross-domain counter because the two
	// are different operator stories; one total would answer neither.
	NAT64FragProtocolAliasMissesTotal uint64 `json:"nat64_frag_protocol_alias_misses_total,omitempty"`
	// InterfaceSNATIdentityExhaustionTotal is #6751 PR 2/3: interface-mode
	// SNAT admissions that failed CLOSED because no free translated
	// identity existed for their (egress address, remote endpoint) — every
	// port in 1024-65535 taken, a port-less protocol whose single identity
	// was owned, or a peer-synced import whose identity a local flow held.
	// Fail-closed is deliberate: admitting an unowned duplicate is the
	// misdelivery #6751 closes. Surfaced as
	// xpf_userspace_interface_snat_identity_exhaustion_total.
	InterfaceSNATIdentityExhaustionTotal uint64 `json:"interface_snat_identity_exhaustion_total,omitempty"`
	// InterfaceSNATSyncIdentityConflictDropsTotal is #6751 PR 2/3:
	// peer-synced interface-SNAT imports DROPPED because a different live
	// flow on this node already owns the translated identity the active
	// assigned. Fail-closed is the safer posture -- the standby never
	// holds a session it cannot own -- but it is an HA-FIDELITY loss, not
	// a data-path drop, so it is its own series: a non-zero value means
	// individual synced flows will not survive a failover onto this node.
	// Surfaced as
	// xpf_userspace_interface_snat_sync_identity_conflict_drops_total.
	InterfaceSNATSyncIdentityConflictDropsTotal uint64 `json:"interface_snat_sync_identity_conflict_drops_total,omitempty"`
	// InterfaceSNATRegistryCapExhaustionTotal is #6751 PR 2/3:
	// interface-mode SNAT admissions that failed CLOSED because the
	// identity registry could create no further state (the 256
	// retained-allocator cap with nothing reclaimable, or a per-address
	// tracked-flow cap). Read it apart from the identity counter: this one
	// says raise capacity, that one says one remote's identity space is
	// genuinely full. Surfaced as
	// xpf_userspace_interface_snat_registry_cap_exhaustion_total.
	InterfaceSNATRegistryCapExhaustionTotal uint64 `json:"interface_snat_registry_cap_exhaustion_total,omitempty"`
	// #1807: total worker-command-queue poison recoveries (a helper
	// thread panicked while holding a worker command mutex; the
	// committed queue was recovered and the poison cleared — uniform
	// policy in afxdp/worker_queue.rs, extends #1790). Nonzero means a
	// worker panic happened and the command queues kept flowing instead
	// of going permanently deaf. Surfaced as
	// xpf_userspace_worker_command_queue_poison_recoveries_total.
	// Omitempty-free on the Rust side (always serialized); plain decode
	// here defaults to 0 for older helpers.
	WorkerCommandQueuePoisonRecoveries uint64 `json:"worker_command_queue_poison_recoveries,omitempty"`
	// #6929: worker commands dropped because the target per-worker
	// command queue was already at MAX_PENDING_WORKER_COMMANDS (4096).
	// Distinct from the poison counter above on purpose: a poison
	// recovery loses nothing, a capacity drop discards a command.
	// Expected steady state is 0 — the consumer takes the whole deque
	// per poll and cannot be outrun — so a rising value means a worker
	// stopped draining (a contained #925 supervisor panic left the
	// record, and its producers, behind). Surfaced as
	// xpf_userspace_worker_command_queue_drops_total.
	WorkerCommandQueueDrops uint64 `json:"worker_command_queue_drops,omitempty"`
	// #8586: the DELETE-specific split of the aggregate above.
	// `Dropped - DropRepaired` is the unattributed remainder — a refused
	// cross-worker DeleteSynced whose owning worker could not be identified, so
	// nothing ran #8576's NAT teardown on its behalf.
	SessionDeleteReplicaDropped      uint64 `json:"session_delete_replica_dropped,omitempty"`
	SessionDeleteReplicaDropRepaired uint64 `json:"session_delete_replica_drop_repaired,omitempty"`
	// PeerDeleteRefusedLocalOwned is #9048: peer DeleteSynced commands the
	// helper REFUSED because the key named a LIVE LOCAL session this node is
	// actively forwarding for — the delete-side mirror of the install-side
	// clobber guard in upsert_synced_with_origin.
	//
	// Nonzero means the cluster is, or recently was, DUAL-PRIMARY for some
	// redundancy group. The delta emitter is gated on IsPrimaryForRGFn, so in
	// normal operation exactly one node emits deletes and the receiver's
	// entries at those keys carry a peer-synced origin — the guard is inert
	// and this stays flat at 0. It is the ONLY surface that reports the
	// refusal: the refusal itself is silent by design, because the condition
	// that produces it produces one per closing flow, so a log line would be
	// a storm exactly when the cluster is already in trouble. Decodes to 0
	// for an older helper that does not send the key.
	PeerDeleteRefusedLocalOwned uint64 `json:"peer_delete_refused_local_owned,omitempty"`
	// #2402/#6641: shared-session mutex poison recoveries (a worker
	// thread panicked while holding a shared-session or owner-RG-index
	// mutex; the committed map was recovered and the poison cleared --
	// afxdp/shared_ops.rs, mirroring the #1807 worker-queue policy).
	// Nonzero means a worker panic happened and the HA session state
	// survived it instead of being silently emptied at failover (the
	// #2402 bug the recovery policy exists to prevent). Surfaced as
	// xpf_userspace_shared_session_poison_recoveries_total. Decodes to 0
	// for an older helper that does not send the key.
	SharedSessionPoisonRecoveries uint64 `json:"shared_session_poison_recoveries,omitempty"`

	// SessionInstallStaleIgnored is xpf_userspace_session_install_stale_ignored_total
	// (#2170/#7398): stale-generation session INSTALLS refused by the helper's
	// in-memory SyncedSessionEntry guard. The authoritative guard is the Go
	// cluster apply layer; this is the helper-side back-stop, so nonzero means a
	// delayed peer install arrived after a newer generation was committed and the
	// helper declined to regress it. Decodes to 0 for a helper that predates
	// #7398, which reads the same as "never happened".
	SessionInstallStaleIgnored uint64 `json:"session_install_stale_ignored,omitempty"`

	// SessionDeleteStaleIgnored is xpf_userspace_session_delete_stale_ignored_total
	// (#2170/#7398): the DELETE half of the same guard. Nonzero means a delete
	// for a generation older than the committed entry was ignored rather than
	// being allowed to remove a session a newer generation installed.
	SessionDeleteStaleIgnored uint64 `json:"session_delete_stale_ignored,omitempty"`

	// SyncedImportReserveRefused is xpf_userspace_synced_import_reserve_refused_total
	// (#6600/#7398): peer-synced imports refused because this node could not
	// reserve the translated NAT port the session names. Sustained growth means
	// the standby cannot hold the primary's translations, so those flows will not
	// survive a failover — which is why it is worth an operator's attention
	// BEFORE the failover rather than after.
	SyncedImportReserveRefused uint64 `json:"synced_import_reserve_refused,omitempty"`

	// SyncedImportUnknownRoutingDomain is
	// xpf_userspace_synced_import_unknown_routing_domain_total (#7160/#2387):
	// peer-synced imports refused because the helper runs routing instances and
	// the request named no ingress identity to resolve the session's routing
	// domain from. Importing under domain 0 would file the session in the
	// DEFAULT instance's identity space, where a reply that resolved its own
	// domain reaches it, so the helper refuses instead. Sustained growth on a
	// VRF cluster means those flows will NOT be taken over on failover; always
	// 0 on a single-instance node.
	SyncedImportUnknownRoutingDomain uint64 `json:"synced_import_unknown_routing_domain,omitempty"`

	// SyncedImportZoneUnresolved is xpf_userspace_synced_import_zone_unresolved_total.
	// Decodes to 0 against a helper that predates #7209, which reads the same as
	// "never happened" — acceptable here because the metric is diagnostic rather
	// than a gate, and an old helper genuinely has no degraded imports to report.
	SyncedImportZoneUnresolved uint64 `json:"synced_import_zone_unresolved,omitempty"`

	// SyncedImportUnpublished is xpf_userspace_synced_import_unpublished_total:
	// peer-synced imports the helper's local-replace guard ADMITTED but could
	// not publish, because no kernel session map existed at the time.
	//
	// Nonzero is expected, not a fault. The map is absent on a standby taking
	// bulk sync before its first snapshot apply and between a worker teardown
	// and the next bring-up; every reconcile opens by capturing the whole
	// shared synced map and replays it once the new map is up, so those
	// imports are published shortly afterwards rather than lost.
	//
	// It exists as the instrument for #7209: taking sync_session off the
	// helper's snapshot-wide mutex opens a window in which such an import is
	// acked to Go as installed and then neither published nor replayed. Decodes
	// to 0 against a helper predating the field.
	SyncedImportUnpublished uint64 `json:"synced_import_unpublished,omitempty"`
	// #2315: GRE-decap frames dropped by the RFC 6040 §4.2 decap-side ECN
	// combine because the outer header carried a CE mark over an inner
	// packet that was Not-ECT (the illegal combination — a congested
	// router CE-marked a packet whose endpoints never negotiated ECN).
	// RFC 6040 mandates a drop here rather than silently clearing the
	// bogus CE. Surfaced as
	// xpf_userspace_gre_decap_ecn_illegal_drops_total. Omitempty for wire
	// compat with older helpers (defaults to 0).
	GreDecapEcnIllegalDropsTotal uint64 `json:"gre_decap_ecn_illegal_drops_total,omitempty"`
	// #2317: WireGuard-decap inner packets dropped by the SAME RFC 6040
	// §4.2 decap-side ECN combine, for the WG path. The WG decap site
	// captures the outer ECN out-of-band via recvmsg + IP_RECVTOS /
	// IPV6_RECVTCLASS (the kernel UDP socket strips the outer IP header
	// before userspace) and feeds it into the same combine. Surfaced as
	// xpf_userspace_wg_decap_ecn_illegal_drops_total. Omitempty for wire
	// compat with older helpers (defaults to 0).
	WgDecapEcnIllegalDropsTotal uint64 `json:"wg_decap_ecn_illegal_drops_total,omitempty"`
	// #2331: native-GRE encap frames dropped because the fully built outer
	// datagram (outer IP + GRE[+key] + inner) exceeded the resolved
	// transport/egress MTU while the IPv4 outer carries DF=1 (the only
	// outer the native encap builder emits). A DF-set oversized outer
	// cannot be fragmented downstream and would silently blackhole every
	// inner flow with no PMTUD signal — so the builder refuses to emit it.
	// Surfaced as xpf_userspace_gre_encap_df_oversize_drops_total. PMTUD /
	// PTB signalling for this path landed in #2330 (TX dispatcher): when a
	// PTB is owed the pre-build decision emits it and skips the encap, so
	// this counts only the residual where none is owed -- a non-DF IPv4
	// inner (#8942: the old "deferred to #2330" read as an open gap).
	// Omitempty for wire compat with older helpers (defaults to 0).
	GreEncapDfOversizeDropsTotal uint64 `json:"gre_encap_df_oversize_drops_total,omitempty"`
	// #2782: native-GRE decap frames dropped because the GRE
	// Checksum-Present (C) bit was set but the GRE checksum failed to
	// verify (or the header was truncated past the 4-byte
	// Checksum+Reserved1 field). Per RFC 2784 §2.1 + RFC 2890 a
	// checksummed peer (e.g. a vSRX with GRE checksum enabled) is now
	// decapped after skipping+validating the checksum field instead of
	// being silently blackholed; only a frame the path corrupted is
	// dropped here. Surfaced as
	// xpf_userspace_gre_decap_checksum_invalid_drops_total. Omitempty for
	// wire compat with older helpers (defaults to 0).
	GreDecapChecksumInvalidDropsTotal uint64 `json:"gre_decap_checksum_invalid_drops_total,omitempty"`
	// #6842: native-GRE frames REFUSED for decap because the GRE version
	// field was non-zero while the outer tuple named a configured GRE
	// tunnel endpoint. RFC 2784/2890 GRE is version 0; RFC 2637 (PPTP)
	// enhanced GRE is version 1 and re-purposes the 32-bit Key as
	// "Payload Length (16) | Call ID (16)", plus an Acknowledgment-Number
	// field the RFC 2890 field order does not skip, so a version-blind
	// parse would promote attacker-chosen bytes as the inner packet. A
	// REFUSAL, not a drop: the frame continues on the ordinary
	// transit/host-inbound path, and ordinary TRANSIT PPTP is not counted.
	// Surfaced as
	// xpf_userspace_gre_decap_unsupported_version_refusals_total. Omitempty
	// for wire compat with older helpers (defaults to 0).
	GreDecapUnsupportedVersionRefusalsTotal uint64 `json:"gre_decap_unsupported_version_refusals_total,omitempty"`
	// #2472: locally-generated ICMP Time Exceeded / PTB / `reject` error
	// replies dropped because the per-reason token bucket was empty. Each
	// reason has an independent global-per-reason bucket (Linux
	// icmp_msgs_per_sec model, default 1000/s + 1000 burst) so an
	// error-amplification / reflection flood (low-TTL stream, oversized-DF
	// flood, rejected-flow flood, or a routing loop) cannot drive unbounded
	// generated-error emission. Surfaced as
	// xpf_userspace_time_exceeded_rate_limited_total,
	// xpf_userspace_packet_too_big_rate_limited_total, and
	// xpf_userspace_reject_rate_limited_total. Omitempty for wire compat with
	// older helpers (defaults to 0).
	TimeExceededRateLimitedTotal uint64 `json:"time_exceeded_rate_limited_total,omitempty"`
	PacketTooBigRateLimitedTotal uint64 `json:"packet_too_big_rate_limited_total,omitempty"`
	RejectRateLimitedTotal       uint64 `json:"reject_rate_limited_total,omitempty"`
	// #1769: on-demand neighbor-resolver telemetry. The resolver fires
	// when a MissingNeighbor negative-cache fast-fail nudges a wedged dst
	// (single-key RTM_GETNEIGH + epoch-guarded cache or probe-on-stale).
	// QueueDepth is a live gauge; the rest are monotonic counters. These
	// are the operator-visible signal for the #1769 stuck-state.
	NeighborResolverQueueDepth        uint64 `json:"neighbor_resolver_queue_depth,omitempty"`
	NeighborResolverEnqueueDropsTotal uint64 `json:"neighbor_resolver_enqueue_drops_total,omitempty"`
	NeighborResolverDisconnectedTotal uint64 `json:"neighbor_resolver_disconnected_total,omitempty"`
	NeighborResolverGetAttemptsTotal  uint64 `json:"neighbor_resolver_get_attempts_total,omitempty"`
	NeighborResolverGetResolvedTotal  uint64 `json:"neighbor_resolver_get_resolved_total,omitempty"`
	NeighborResolverProbeOnStaleTotal uint64 `json:"neighbor_resolver_probe_on_stale_total,omitempty"`
	NeighborResolverGetFailuresTotal  uint64 `json:"neighbor_resolver_get_failures_total,omitempty"`
	NeighborResolverEpochRejectsTotal uint64 `json:"neighbor_resolver_epoch_rejects_total,omitempty"`
	// #1772: neighbor/ARP resolution LATENCY telemetry. Complements the
	// #1769 count-only resolver telemetry above with TIMING so the
	// intermittent slow-new-connection symptom is visible. The bucket
	// slices are NON-cumulative per-bucket sample counts on a 16-bucket
	// pow2-ns ladder (bucket i upper bound 2^(16+i) ns; bucket 15 = +Inf;
	// the 3 s blackout class lands in bucket 15).
	NeighborPendingDwellBuckets      []uint64 `json:"neighbor_pending_dwell_buckets,omitempty"`
	NeighborPendingDwellSumNs        uint64   `json:"neighbor_pending_dwell_sum_ns,omitempty"`
	NeighborPendingDwellCount        uint64   `json:"neighbor_pending_dwell_count,omitempty"`
	NeighborResolverGetRttBuckets    []uint64 `json:"neighbor_resolver_get_rtt_buckets,omitempty"`
	NeighborResolverGetRttSumNs      uint64   `json:"neighbor_resolver_get_rtt_sum_ns,omitempty"`
	NeighborResolverGetRttCount      uint64   `json:"neighbor_resolver_get_rtt_count,omitempty"`
	NeighborPendingTimeoutDropsTotal uint64   `json:"neighbor_pending_timeout_drops_total,omitempty"`
	NeighborPendingMaxDepth          uint64   `json:"neighbor_pending_max_depth,omitempty"`
	// #1771 §2.6: per-key resolver + §2.5 ENOBUFS-re-dump telemetry.
	// GetBackoffAttempts is the subset of resolver GET attempts that were
	// backoff RETRIES (key re-admitted after the per-key rate-limit
	// window) — invariant N1 (§2.4): these keep firing while a key is
	// negatively cached. The Netlink* counters instrument the monitor
	// thread's lost-notification self-heal: ENOBUFS receives, throttled
	// upsert-only re-dumps issued, and entries actually (re)added by
	// re-dump replies. PendingKeys / NegNeighKeys are gauges summed over
	// the per-binding ~65ms debug-tick snapshots: distinct unresolved
	// next-hop keys buffered in pending_neigh, and keys held in the
	// negative caches (lazy-TTL upper bound). All decode to 0 for older
	// helpers (keys absent).
	NeighborResolverGetBackoffAttemptsTotal uint64 `json:"neighbor_resolver_get_backoff_attempts_total,omitempty"`
	NeighborNetlinkEnobufsTotal             uint64 `json:"neighbor_netlink_enobufs_total,omitempty"`
	NeighborNetlinkRedumpsTotal             uint64 `json:"neighbor_netlink_redumps_total,omitempty"`
	NeighborNetlinkRedumpUpsertsTotal       uint64 `json:"neighbor_netlink_redump_upserts_total,omitempty"`
	NeighborPendingKeys                     uint64 `json:"neighbor_pending_keys,omitempty"`
	NegNeighKeys                            uint64 `json:"neg_neigh_keys,omitempty"`
	// WgTunnels carries the #1865 per-WG-tunnel telemetry rows. Keyed
	// by tunnel NAME (Tunnel) — TunnelEndpointID is informational only
	// (#1873: positional ids renumber across commits). Absent/empty for
	// non-WG deployments and for older helpers (key omitted on the
	// Rust side when no tunnel is configured).
	WgTunnels []WgTunnelStatus `json:"wg_tunnels,omitempty"`
	// #3773 (M13): fabric-link skip diagnostics. FabricLinkSkippedMalformed
	// counts fabric links dropped during a forwarding build/refresh for a
	// MALFORMED value (invalid parent ifindex, unparseable peer address, or a
	// non-empty local/peer MAC that failed to parse) — a config/environment
	// fault the operator must fix. FabricLinkUnresolvedPeer counts links
	// dropped because a peer/local MAC was UNRESOLVED (an empty MAC field
	// awaiting neighbor/interface resolution — the expected late-resolution
	// SyncFabricState transient). Distinct counters so a benign unresolved
	// peer is not conflated with a genuine misconfiguration. Both surfaced as
	// xpf_userspace_fabric_link_skipped_malformed_total and
	// xpf_userspace_fabric_link_unresolved_peer_total. Omitempty for wire
	// compat with older helpers (default 0).
	FabricLinkSkippedMalformedTotal uint64 `json:"fabric_link_skipped_malformed_total,omitempty"`
	FabricLinkUnresolvedPeerTotal   uint64 `json:"fabric_link_unresolved_peer_total,omitempty"`
	// #9654: whether the learned-route import is capped in the forwarding state
	// the helper's live workers serve NOW. A pointer because absence must read
	// as UNKNOWN. The helper omits the key when no worker is live. A helper that
	// predates the field never sends it, yet still enforces capped forwarding.
	// A plain bool would report both as "not capped".
	LearnedRouteImportCapped *bool `json:"learned_route_import_capped,omitempty"`
}

// MarshalJSON intentionally uses a value receiver so both ProcessStatus values
// and *ProcessStatus pointers emit the temporary legacy alias during the
// rolling-upgrade window.
func (s ProcessStatus) MarshalJSON() ([]byte, error) {
	type processStatusAlias ProcessStatus
	aux := struct {
		*processStatusAlias
		LegacyFallbackCounters map[string]uint64 `json:"fallback_counters,omitempty"`
	}{
		processStatusAlias: (*processStatusAlias)(&s),
	}
	if len(s.DegradedPathCounters) > 0 {
		// encoding/json never mutates input maps, so sharing the map keeps the
		// legacy alias byte-for-byte consistent with the primary field.
		aux.LegacyFallbackCounters = s.DegradedPathCounters
	}
	return json.Marshal(aux)
}

func (s *ProcessStatus) UnmarshalJSON(data []byte) error {
	type processStatusAlias ProcessStatus
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	var aux processStatusAlias
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	*s = ProcessStatus(aux)
	if _, ok := raw["degraded_path_counters"]; ok {
		return nil
	}
	if legacyRaw, ok := raw["fallback_counters"]; ok {
		var legacy map[string]uint64
		if err := json.Unmarshal(legacyRaw, &legacy); err != nil {
			return err
		}
		s.DegradedPathCounters = legacy
	}
	return nil
}

// #869: WorkerRuntimeStatus mirrors the Rust WorkerRuntimeStatus;
// each entry is one AF_XDP worker thread's cumulative runtime counters,
// refreshed on the worker's ~1s publish cadence.  All fields omit when
// zero so older daemons parse correctly.
type WorkerRuntimeStatus struct {
	WorkerID    uint32 `json:"worker_id,omitempty"`
	TID         uint64 `json:"tid,omitempty"`
	WallNS      uint64 `json:"wall_ns,omitempty"`
	ActiveNS    uint64 `json:"active_ns,omitempty"`
	IdleSpinNS  uint64 `json:"idle_spin_ns,omitempty"`
	IdleBlockNS uint64 `json:"idle_block_ns,omitempty"`
	ThreadCPUNS uint64 `json:"thread_cpu_ns,omitempty"`
	WorkLoops   uint64 `json:"work_loops,omitempty"`
	IdleLoops   uint64 `json:"idle_loops,omitempty"`
	// SessionVolumeHighWater (#7919) is the monotonic high-water of per-session
	// volume (fwd+rev packets) this worker has seen in ITS OWN session table on
	// the conntrack-mirror refresh walk.
	//
	// A POINTER on purpose. Every worker holds a copy of every session, but only
	// the worker whose packets land accounts for one, so "which workers' tables
	// ever hold volume" is the axis that separates accounting from mirroring.
	// An OLD helper omits the key entirely, and an absent answer must read as
	// UNKNOWN rather than as a measured zero — a missing answer decoded as 0
	// would manufacture exactly the evidence this field exists to gather. nil
	// means "this helper does not report it"; a non-nil 0 cannot occur, because
	// the helper skips the key while the value is 0 (both cases mean "no
	// positive evidence of volume", and neither is a measurement).
	SessionVolumeHighWater *uint64 `json:"session_volume_high_water,omitempty"`
	// #1240: cumulative v8 per-worker queue-lease acquire calls and
	// granted bytes. Scrape with rate() and compare against per-worker
	// TX throughput to diagnose token-acquisition imbalance.
	CoSQueueLeaseAcquireV8Calls        uint64 `json:"cos_queue_lease_acquire_v8_calls,omitempty"`
	CoSQueueLeaseAcquireV8GrantedBytes uint64 `json:"cos_queue_lease_acquire_v8_granted_bytes,omitempty"`
	// #1782 Step-1 (plan §5.2 mechanism (i)): cumulative CoS timer-wheel
	// ticks advanced by advance_cos_timer_wheel across this worker's
	// bindings, plus the largest single-call advance ever observed (a
	// monotonic high-water mark). One cold drain catching up a
	// multi-minute per-worker idle lag appears as a single
	// multi-million-tick max sample. omitempty for mixed-version
	// back-compat with pre-Step-1 helpers.
	CoSWheelTicksAdvancedTotal uint64 `json:"cos_wheel_ticks_advanced_total,omitempty"`
	CoSWheelTicksAdvancedMax   uint64 `json:"cos_wheel_ticks_advanced_max,omitempty"`
	// #1782 Step-1 (plan §5.2 mechanism (ii)): per-cause v8 queue-lease
	// under-grant attribution, counted at the CoS exact-guarantee
	// selector sites when the post-top-up queue tokens still cannot
	// cover the head frame. A v8-attributed subset of the per-queue
	// drain_park_queue_tokens counter. Surfaced as the single
	// xpf_userspace_worker_cos_queue_lease_undergrant_total family with
	// a cause label.
	CoSQueueLeaseUndergrantSeqlockGiveUp  uint64 `json:"cos_queue_lease_undergrant_seqlock_give_up,omitempty"`
	CoSQueueLeaseUndergrantCapZero        uint64 `json:"cos_queue_lease_undergrant_cap_zero,omitempty"`
	CoSQueueLeaseUndergrantEpochRotated   uint64 `json:"cos_queue_lease_undergrant_epoch_rotated,omitempty"`
	CoSQueueLeaseUndergrantShareExhausted uint64 `json:"cos_queue_lease_undergrant_share_exhausted,omitempty"`
	CoSQueueLeaseUndergrantClassCap       uint64 `json:"cos_queue_lease_undergrant_class_cap,omitempty"`
	CoSQueueLeaseUndergrantOutstandingCap uint64 `json:"cos_queue_lease_undergrant_outstanding_cap,omitempty"`
	SessionTableEntries                   uint64 `json:"session_table_entries,omitempty"`
	MaxSessions                           uint64 `json:"max_sessions,omitempty"`
	// #1760: cumulative NAT reverse-key displacement events on this
	// worker's SessionTable nat_reverse_index (#1758). omitempty for
	// mixed-version back-compat.
	NatReverseKeyCollisions uint64 `json:"nat_reverse_key_collisions,omitempty"`
	// NatReverseKeyCollisionsDistinctSrc is the DIFFERENT-SOURCE subset of the
	// counter above (#6751). The aggregate cannot separate the cross-session
	// leak from one host reusing an ephemeral port, and only the former is what
	// PAT-on-collision would fix.
	NatReverseKeyCollisionsDistinctSrc uint64 `json:"nat_reverse_key_collisions_distinct_src,omitempty"`
	// #7919: by-key session-lookup misses on this worker's table, split by
	// cause. The dataplane has published these on the wire since the #7919
	// instrumentation landed; nothing on this side decoded them, so a counter
	// added FOR live diagnosis was readable only from Rust unit tests.
	//
	// PER-WORKER on purpose, and they must not be summed into a single
	// process-wide number. The measured symptom is not uniform -- on the
	// reporting box one of three concurrent flows accounted correctly while
	// the other two froze -- and a total cannot separate "one worker is
	// missing everything" from "every worker misses occasionally". Those are
	// different bugs with different fixes, and the split is the whole reason
	// the counters exist.
	//
	// Causes: NoHandle = the key is not in the index at all; StaleHandle = a
	// handle resolved but pointed outside the slab; KeyMismatch = a handle
	// resolved to a LIVE record whose stored key differs from the one asked
	// for. omitempty for mixed-version back-compat.
	SessionLookupMissNoHandle    uint64 `json:"session_lookup_miss_no_handle,omitempty"`
	SessionLookupMissStaleHandle uint64 `json:"session_lookup_miss_stale_handle,omitempty"`
	SessionLookupMissKeyMismatch uint64 `json:"session_lookup_miss_key_mismatch,omitempty"`
	// #1861: per-worker install-refusal trio (see the ProcessStatus
	// aggregate fields for semantics). omitempty for back-compat.
	SessionCreateDrops             uint64 `json:"session_create_drops,omitempty"`
	SessionInstallAdmissionRefused uint64 `json:"session_install_admission_refused,omitempty"`
	SessionInstallPartial          uint64 `json:"session_install_partial,omitempty"`
	// #4800: cumulative locally-learned transit forward-flow installs on
	// this worker — its share of the SNAT-allocate / publish_shared_session
	// / replicate_session_upsert path. Divided by the run window this is
	// the worker's new-flows/sec; compared ACROSS workers it separates a
	// genuine cross-worker lock bound from one saturated RX queue.
	// omitempty for mixed-version back-compat.
	NewFlowInstalls uint64 `json:"new_flow_installs,omitempty"`
	// #925 Phase 1+2 (catch+report+observe): Dead == true means the
	// worker_loop panicked and the supervisor caught it. Set-only
	// today — cleared only by daemon restart. Phase 2 surfaces this
	// on Prometheus as `xpf_userspace_worker_dead` (this PR). A
	// hypothetical Phase 3 (respawn, deferred indefinitely) would
	// clear this by replacing WorkerRuntimeAtomics on relaunch.
	// PanicMessage holds the rendered payload for operator diagnosis.
	Dead         bool   `json:"dead,omitempty"`
	PanicMessage string `json:"panic_message,omitempty"`
	// Rolling last-window delta for CPU/wall/active counters. Under
	// the normal ~1 Hz worker publish cadence the rotated window is
	// ~60-61s wide (one publish-tick of overshoot past the 60s
	// threshold); a stalled publisher can widen it further. WindowNS
	// carries the exact measured width so consumers should always
	// divide by it rather than assuming a fixed denominator. All
	// zero until ~60s after worker start.
	ThreadCPUNS60s uint64 `json:"thread_cpu_ns_60s,omitempty"`
	WallNS60s      uint64 `json:"wall_ns_60s,omitempty"`
	ActiveNS60s    uint64 `json:"active_ns_60s,omitempty"`
	WindowNS       uint64 `json:"window_ns,omitempty"`

	// === #1635 cold-path histogram surface (sparse v3) ===
	//
	// Mirrors the Rust WorkerRuntimeStatus cold_path_* fields. All
	// slice fields use omitempty so an empty histogram (older Rust
	// daemon, or a worker with no samples this window) omits the field
	// from the wire; the Go emitter skips on empty. Per
	// feedback_wire_protocol_both_sides.
	//
	// #1635 replaces the v1 dense [16-slot] arrays with a SPARSE
	// active-slot encoding: parallel arrays, one entry per active
	// (from_zone, to_zone) pair. ColdPathLayoutVersion selects the
	// emission path (0/absent = no data / pre-#1635; 3 = sparse).
	//
	// Aggregated PER WORKER: when a worker owns multiple bindings, the
	// published values reflect the cross-binding merge performed at the
	// publish tick (sum for histogram data, OR for builder_collision).
	ColdPathLayoutVersion uint32 `json:"cold_path_layout_version,omitempty"`
	// Legacy v1 dense fields, retained READ-ONLY so a new Go collector
	// still emits correct v1 metrics when paired with a pre-#1635 Rust
	// daemon (plan §3.2 row "v1 Rust / v3 Go"). Current daemons leave
	// these empty. Per feedback_wire_protocol_both_sides.
	ColdPathHist      [][]uint64 `json:"cold_path_hist,omitempty"`
	ColdPathSumNS     []uint64   `json:"cold_path_sum_ns,omitempty"`
	ColdPathSamples   []uint64   `json:"cold_path_samples,omitempty"`
	ColdPathFirstKey  []uint64   `json:"cold_path_first_key,omitempty"`
	ColdPathAliasSeen []bool     `json:"cold_path_alias_seen,omitempty"`
	// Parallel sparse arrays (index i describes one active zone-pair).
	ColdPathActiveSlotIDs          []uint32   `json:"cold_path_active_slot_ids,omitempty"`
	ColdPathActiveZoneFrom         []uint32   `json:"cold_path_active_zone_from,omitempty"`
	ColdPathActiveZoneTo           []uint32   `json:"cold_path_active_zone_to,omitempty"`
	ColdPathActiveSamples          []uint64   `json:"cold_path_active_samples,omitempty"`
	ColdPathActiveSumNS            []uint64   `json:"cold_path_active_sum_ns,omitempty"`
	ColdPathActiveBuckets          [][]uint64 `json:"cold_path_active_buckets,omitempty"`
	ColdPathActiveBuilderCollision []bool     `json:"cold_path_active_builder_collision,omitempty"`
	// True if a configured zone-pair could not be assigned a slot —
	// either the 255-slot capacity was exhausted OR the pair references
	// a zone-id outside the 0..=64 direct-table range.
	ColdPathOverflowActive        bool   `json:"cold_path_overflow_active,omitempty"`
	ColdPathSamplePhase           uint64 `json:"cold_path_sample_phase,omitempty"`
	ColdPathWrapperUnderflowCount uint64 `json:"cold_path_wrapper_underflow_count,omitempty"`
	ColdPathNSPerTSCQ32           uint64 `json:"cold_path_ns_per_tsc_q32,omitempty"`
	ColdPathWrapperNSBaseline     uint64 `json:"cold_path_wrapper_ns_baseline,omitempty"`
	// "tsc" / "clock_gettime" / "" (Unset). Harness gates Table
	// publication on == "tsc" for every worker.
	ColdPathClockSource string `json:"cold_path_clock_source,omitempty"`
	// #1621 plan v2: monotonic count of snapshot() calls at the
	// coordinator status path that exhausted their retry budget.
	// Surfaced as xpf_userspace_worker_cold_path_snapshot_failed_total.
	ColdPathSnapshotFailed uint64 `json:"cold_path_snapshot_failed,omitempty"`
}

type SlowPathStatus struct {
	Active bool `json:"active"`
	// Degraded (#2471): the slow-path worker is active but the live TUN MTU is
	// below the configured data-interface MTU because the MTU-programming ioctl
	// failed. Jumbo reinjection is refused (see MTUDroppedPackets); a bare
	// Active without this would mislead an operator into thinking the slow path
	// is healthy while jumbo frames silently drop.
	Degraded bool `json:"degraded,omitempty"`
	// LiveMTU (#2471): the MTU the live TUN device is actually programmed with.
	// Equals the desired MTU on success; falls back to 1500 when programming
	// failed. Frames longer than this are refused at enqueue.
	LiveMTU            int32  `json:"live_mtu,omitempty"`
	DeviceName         string `json:"device_name,omitempty"`
	Mode               string `json:"mode,omitempty"`
	LastError          string `json:"last_error,omitempty"`
	QueuedPackets      uint64 `json:"queued_packets,omitempty"`
	InjectedPackets    uint64 `json:"injected_packets,omitempty"`
	InjectedBytes      uint64 `json:"injected_bytes,omitempty"`
	DroppedPackets     uint64 `json:"dropped_packets,omitempty"`
	DroppedBytes       uint64 `json:"dropped_bytes,omitempty"`
	RateLimitedPackets uint64 `json:"rate_limited_packets,omitempty"`
	QueueFullPackets   uint64 `json:"queue_full_packets,omitempty"`
	WriteErrors        uint64 `json:"write_errors,omitempty"`
	// MTUDroppedPackets (#2471): frames refused at enqueue because they exceed
	// the live TUN MTU. Non-zero while Degraded is the operator-visible proof
	// that jumbo reinjection is being dropped by the firewall, not the kernel.
	MTUDroppedPackets uint64 `json:"mtu_dropped_packets,omitempty"`
}

type PacketResolution struct {
	Disposition    string `json:"disposition"`
	LocalIfindex   int    `json:"local_ifindex,omitempty"`
	EgressIfindex  int    `json:"egress_ifindex,omitempty"`
	IngressIfindex int    `json:"ingress_ifindex,omitempty"`
	NextHop        string `json:"next_hop,omitempty"`
	NeighborMAC    string `json:"neighbor_mac,omitempty"`
	SrcIP          string `json:"src_ip,omitempty"`
	DstIP          string `json:"dst_ip,omitempty"`
	SrcPort        uint16 `json:"src_port,omitempty"`
	DstPort        uint16 `json:"dst_port,omitempty"`
	FromZone       string `json:"from_zone,omitempty"`
	ToZone         string `json:"to_zone,omitempty"`
}

type FlowTupleStatus struct {
	AddrFamily uint8  `json:"addr_family,omitempty"`
	Protocol   uint8  `json:"protocol,omitempty"`
	SrcIP      string `json:"src_ip,omitempty"`
	DstIP      string `json:"dst_ip,omitempty"`
	SrcPort    uint16 `json:"src_port,omitempty"`
	DstPort    uint16 `json:"dst_port,omitempty"`
}

type FlowWorkerStatus struct {
	Slot                uint32          `json:"slot,omitempty"`
	QueueID             uint32          `json:"queue_id,omitempty"`
	WorkerID            uint32          `json:"worker_id,omitempty"`
	Interface           string          `json:"interface,omitempty"`
	Ifindex             int             `json:"ifindex,omitempty"`
	IngressIfindex      int             `json:"ingress_ifindex,omitempty"`
	EgressIfindex       int             `json:"egress_ifindex,omitempty"`
	TxIfindex           int             `json:"tx_ifindex,omitempty"`
	SessionKey          FlowTupleStatus `json:"session_key,omitempty"`
	ForwardWireKey      FlowTupleStatus `json:"forward_wire_key,omitempty"`
	ReverseCanonicalKey FlowTupleStatus `json:"reverse_canonical_key,omitempty"`
	CoSQueueID          *uint8          `json:"cos_queue_id,omitempty"`
	DSCPRewrite         *uint8          `json:"dscp_rewrite,omitempty"`
	AgeEpochs           uint16          `json:"age_epochs,omitempty"`
	ObservedBytes       uint64          `json:"observed_bytes,omitempty"`
}

type ExceptionStatus struct {
	Timestamp        time.Time `json:"timestamp"`
	Slot             uint32    `json:"slot"`
	QueueID          uint32    `json:"queue_id"`
	WorkerID         uint32    `json:"worker_id"`
	Interface        string    `json:"interface,omitempty"`
	Ifindex          int       `json:"ifindex,omitempty"`
	IngressIfindex   int       `json:"ingress_ifindex,omitempty"`
	Reason           string    `json:"reason"`
	PacketLength     uint32    `json:"packet_length,omitempty"`
	AddrFamily       uint8     `json:"addr_family,omitempty"`
	Protocol         uint8     `json:"protocol,omitempty"`
	ConfigGeneration uint64    `json:"config_generation,omitempty"`
	FIBGeneration    uint32    `json:"fib_generation,omitempty"`
	SrcIP            string    `json:"src_ip,omitempty"`
	DstIP            string    `json:"dst_ip,omitempty"`
	SrcPort          uint16    `json:"src_port,omitempty"`
	DstPort          uint16    `json:"dst_port,omitempty"`
	FromZone         string    `json:"from_zone,omitempty"`
	ToZone           string    `json:"to_zone,omitempty"`
	RuleName         string    `json:"rule_name,omitempty"`
	PoolName         string    `json:"pool_name,omitempty"`
}

// #7919: the per-session counter QUERY — a READ-ONLY diagnostic that reports
// what EACH worker's own session table holds for one 5-tuple.
//
// WHY IT EXISTS. `show security flow session` reports a session's volume from
// the shared BPF conntrack mirror. When a row reads Pkts: 0 for a flow that is
// demonstrably moving traffic, two explanations survive and need opposite
// fixes: the owning worker's table holds the volume and the mirror lost it, or
// no worker's table holds it and the mirror is faithfully reporting nothing
// that was ever accounted. Nothing else can separate them — the shared session
// table carries no counters, and the per-worker high-water is monotonic over
// the process lifetime, so a large value on a worker whose current flow reads 0
// may be residue from an earlier flow that worker owned.
type SessionCounterQuery struct {
	SrcIP    string `json:"src_ip"`
	DstIP    string `json:"dst_ip"`
	SrcPort  uint16 `json:"src_port"`
	DstPort  uint16 `json:"dst_port"`
	Protocol uint8  `json:"protocol"`
}

// SessionCounterRow is one worker's reply. Three states are distinct and none
// may be collapsed: Answered=false (it did not reply before the deadline — not
// an answer), Answered && !Found (it replied: it does not hold this session),
// and Answered && Found (it holds it; Counters are what its copy says).
type SessionCounterRow struct {
	WorkerID   uint32 `json:"worker_id"`
	Answered   bool   `json:"answered"`
	Found      bool   `json:"found"`
	Replica    bool   `json:"replica"`
	FwdPackets uint64 `json:"fwd_packets"`
	FwdBytes   uint64 `json:"fwd_bytes"`
	RevPackets uint64 `json:"rev_packets"`
	RevBytes   uint64 `json:"rev_bytes"`
}
