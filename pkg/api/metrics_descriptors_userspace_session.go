package api

import "github.com/prometheus/client_golang/prometheus"

func (c *xpfCollector) initUserspaceSessionDescriptors() {
	c.userspaceSessionTableEntries = prometheus.NewDesc(
		"xpf_userspace_session_table_entries",
		"Aggregate live userspace session-table entries across workers.",
		nil, nil,
	)
	c.userspaceSessionTableCapacity = prometheus.NewDesc(
		"xpf_userspace_session_table_capacity",
		"Aggregate userspace session-table capacity across workers.",
		nil, nil,
	)
	// #8447: source-NAT rule-match outcomes. Consulted is the denominator that
	// makes the other three readable — it counts every packet that REACHED the
	// match path, including ones that matched nothing, so a zero elsewhere can
	// be told from "nothing arrived". Emitted unconditionally for the same
	// reason the collision counters below are: a published 0 is a real signal,
	// an absent series is not.
	c.userspaceSourceNATMatchConsulted = prometheus.NewDesc(
		"xpf_userspace_source_nat_match_consulted_total",
		"Packets that reached the source-NAT rule-match path, whatever the outcome.",
		nil, nil,
	)
	c.userspaceSourceNATMatchMatched = prometheus.NewDesc(
		"xpf_userspace_source_nat_match_matched_total",
		"Source-NAT rule matches that produced a translation decision.",
		nil, nil,
	)
	c.userspaceSourceNATMatchUnavailable = prometheus.NewDesc(
		"xpf_userspace_source_nat_match_unavailable_total",
		"Source-NAT rule matches that could not produce a translation.",
		nil, nil,
	)
	c.userspaceSourceNATMatchNoMatch = prometheus.NewDesc(
		"xpf_userspace_source_nat_match_no_match_total",
		"Packets that reached source-NAT and matched no rule.",
		nil, nil,
	)
	c.userspaceNatReverseKeyCollisions = prometheus.NewDesc(
		"xpf_userspace_session_nat_reverse_key_collisions_total",
		"Aggregate NAT reverse-key (nat_reverse_index) 1:N collision "+
			"displacement events across userspace workers (#1758/#1760 "+
			"latent corruption made observable). Event count, not a "+
			"census (replica fanout over-counts; standing and seed-path "+
			"collisions under-count — pair with the shared displacements "+
			"counter). >=1 means at least one real collision occurred "+
			"and is the structural-fix revisit trigger.",
		nil, nil,
	)
	c.userspaceNatReverseKeyCollisionsDistinctSrc = prometheus.NewDesc(
		"xpf_userspace_session_nat_reverse_key_collisions_distinct_src_total",
		"#6751: the subset of the aggregate above where the colliding "+
			"sessions came from DIFFERENT internal sources — the "+
			"cross-session return-traffic leak, and the only population "+
			"PAT-on-collision would fix. The aggregate also counts one host "+
			"reusing an ephemeral port while its previous session is still "+
			"resident. Read them together: a nonzero aggregate with zero "+
			"here is same-source reuse, not a leak.",
		nil, nil,
	)
	c.userspaceNatReverseKeySharedDisplacements = prometheus.NewDesc(
		"xpf_userspace_session_nat_reverse_key_shared_displacements_total",
		"Shared-map NAT reverse-key displacement events: a "+
			"publish_shared_session insert displaced a DIFFERENT forward "+
			"session's entry at the same reverse key (#1760 latent 1:N "+
			"reverse-path corruption). The shared map is the choke point "+
			"all transit forward NAT sessions pass through (including "+
			"MissingNeighborSeed installs invisible to the per-worker "+
			"counter). Event count, not a pair census: >=1 means at "+
			"least one real collision occurred; standing collisions "+
			"against an already-unindexed session are not counted.",
		nil, nil,
	)
	c.userspaceNAT64FragCrossDomainMisses = prometheus.NewDesc(
		"xpf_userspace_nat64_frag_cross_domain_misses_total",
		"#7056 (#5798 required-fix #5): fragment-association lookups that "+
			"MISSED because a same-datagram association exists under a "+
			"DIFFERENT ingress security domain, so the #5798 authority-scoped "+
			"key refused it. The refusal itself is the fail-closed behaviour "+
			"and is not a defect; this series exists because such a miss was "+
			"previously indistinguishable from a reorder, a TTL straddle, a "+
			"shard eviction or a config-generation bump, all of which land on "+
			"the same drop counter. It is the only one of that group that "+
			"describes the TRAFFIC rather than cache pressure: a nonzero and "+
			"rising value means fragments are arriving in one security domain "+
			"bearing the identity of a datagram admitted in another.",
		nil, nil,
	)
	c.userspaceNAT64FragProtocolAliasMisses = prometheus.NewDesc(
		"xpf_userspace_nat64_frag_protocol_alias_misses_total",
		"#7056: the sibling of the cross-domain series — a same-datagram "+
			"association exists under the SAME ingress domain but a different "+
			"upper-layer protocol, i.e. a TCP and a UDP datagram collided on "+
			"(src, dst, ident) and were separated by the #5798 `protocol` key "+
			"field. Kept as a DISTINCT series rather than folded into the "+
			"cross-domain total because the two are different operator "+
			"stories: this one is ordinary identifier reuse between protocols, "+
			"not a domain-crossing attempt.",
		nil, nil,
	)
	c.userspaceFragMaxLifetimeEvictions = prometheus.NewDesc(
		"xpf_userspace_frag_max_lifetime_evictions_total",
		"#9901 (F-010): fragment associations reclaimed by the ABSOLUTE "+
			"lifetime bound (10s from install) rather than the 2s idle TTL. "+
			"An idle-TTL expiry is routine churn; an absolute expiry means "+
			"one key was consulted continuously for the whole maximum "+
			"lifetime — the sustained same-key fragment stream the bound "+
			"exists to stop.",
		nil, nil,
	)
	c.userspaceEgressMTUUnknownForward = prometheus.NewDesc(
		"xpf_userspace_egress_mtu_unknown_forward_total",
		"#9901 (F-074): forwarded frames whose egress-MTU decision ran with "+
			"NO known MTU (mtu == 0) and took the documented fail-open "+
			"Forward arm. The decision is deliberate, but silence about it "+
			"hid unknown-MTU configurations (missing egress row / unknown "+
			"tunnel kind) behind healthy-looking forwards.",
		nil, nil,
	)
	c.userspaceInterfaceSNATPATCollisions = prometheus.NewDesc(
		"xpf_userspace_interface_snat_pat_collisions_total",
		"#6751: interface-mode source-NAT admissions whose PRESERVED "+
			"source port was already owned for the same (egress "+
			"address, remote endpoint) identity, so the LATER flow was "+
			"PAT'd onto a free port. Before #6751 both flows kept the "+
			"port and produced one indistinguishable reverse tuple, so "+
			"replies for both reached whichever session installed "+
			"first. Nonzero here means that shape occurred and was "+
			"disambiguated; only the later flow's wire port moved.",
		nil, nil,
	)
	c.userspaceInterfaceSNATIdentityExhaustion = prometheus.NewDesc(
		"xpf_userspace_interface_snat_identity_exhaustion_total",
		"#6751: interface-mode source-NAT admissions dropped because no "+
			"free translated identity existed for their (egress "+
			"address, remote endpoint) — every candidate port taken, a "+
			"port-less protocol (GRE/ESP/OSPF) whose single identity "+
			"was owned, or a peer-synced import colliding with a local "+
			"flow. Fail-closed by design: admitting a duplicate would "+
			"reintroduce the cross-session misdelivery.",
		nil, nil,
	)
	c.userspaceInterfaceSNATSyncConflictDrops = prometheus.NewDesc(
		"xpf_userspace_interface_snat_sync_identity_conflict_drops_total",
		"#6751: peer-synced interface-mode source-NAT session imports "+
			"dropped because a DIFFERENT live flow on this node already "+
			"owns the translated identity the active node assigned. "+
			"Fail-closed by design -- the standby never holds a session "+
			"it cannot own -- but it is an HA-fidelity loss rather than a "+
			"data-path drop: a non-zero value means those individual "+
			"flows will not survive a failover onto this node.",
		nil, nil,
	)
	c.userspaceInterfaceSNATRegistryCap = prometheus.NewDesc(
		"xpf_userspace_interface_snat_registry_cap_exhaustion_total",
		"#6751: interface-mode source-NAT admissions dropped because the "+
			"identity registry could create no further state — the "+
			"retained-allocator cap with nothing reclaimable, or a "+
			"per-egress-address tracked-flow cap. Distinct from "+
			"identity exhaustion: this says capacity, that says one "+
			"remote's identity space is full.",
		nil, nil,
	)
	c.userspaceSessionCreateDrops = prometheus.NewDesc(
		"xpf_userspace_session_create_drops_total",
		"Aggregate session installs refused at the max_sessions cap "+
			"across userspace workers (#1861).",
		nil, nil,
	)
	c.userspaceSessionInstallAdmissionRefused = prometheus.NewDesc(
		"xpf_userspace_session_install_admission_refused_total",
		"Aggregate new flows refused (trigger packet dropped, Junos "+
			"parity) by the #1861 forward+reverse pair-admission "+
			"preflight at/near max_sessions, across userspace workers.",
		nil, nil,
	)
	c.userspaceSessionInstallPartial = prometheus.NewDesc(
		"xpf_userspace_session_install_partial_total",
		"Aggregate post-preflight partial session installs across "+
			"userspace workers (#1861 release residual arms; expected 0 "+
			"forever — nonzero means a preflight/install pairing bug).",
		nil, nil,
	)
	// #4800: the process-global publish + replication legs of the
	// new-flow-install contention surface. Each contended counter ships
	// with the acquisition counter that is its denominator, because a
	// contention rate alone cannot distinguish a saturated lock from a
	// merely busy one. The NAT-allocator leg is per pool and lives on the
	// xpf_userspace_source_nat_pool_live_lock_* family instead.
	c.userspaceSharedSessionPublishes = prometheus.NewDesc(
		"xpf_userspace_shared_session_publishes_total",
		"Sessions published into the helper's cross-worker shared session "+
			"maps — one per locally-learned transit flow (forward and "+
			"reverse), promote, HA import and tunnel install. The "+
			"publish-leg new-flow rate, and the call-count denominator for "+
			"the publish lock counters below (#4800).",
		nil, nil,
	)
	// #9169: the FOURTH #4800 contention site. Every session delta — Open as
	// well as Close — allocates its wire sequence number and encodes its frame
	// inside the helper's process-global producer_seq_lock, because #3878 F-152
	// requires the seq allocation and the channel enqueue to be atomic
	// together. docs/userspace-newflow-ceiling.md named three sites and not
	// this one, so a run that saturated here would have reported a plateau with
	// every named site cold -- a counterfactual, not a measured result; that
	// harness has not been run.
	c.userspaceEventStreamProducerSeqLockAcquired = prometheus.NewDesc(
		"xpf_userspace_event_stream_producer_seq_lock_acquisitions_total",
		"Acquisitions of the helper's process-global event-stream "+
			"producer_seq_lock taken by a PRODUCER — one per session delta "+
			"(Open and Close alike) and one per lossless-retry attempt. The "+
			"denominator for the contention counter below. The I/O thread's "+
			"replay-gap FullResync allocation takes the same mutex and is "+
			"deliberately excluded: it is not a producer and fires once per "+
			"reconnect, so counting it would dilute the ratio with the "+
			"observer (#9169 / #4800).",
		nil, nil,
	)
	c.userspaceEventStreamProducerSeqLockBlocked = prometheus.NewDesc(
		"xpf_userspace_event_stream_producer_seq_lock_contended_total",
		"Subset of event-stream producer_seq_lock acquisitions that found "+
			"the mutex already held and had to block. The frame ENCODE runs "+
			"inside this critical section, so the hold time is not just an "+
			"atomic; divided by ..._acquisitions_total this is the "+
			"session-delta leg's share of new-flow-install serialization "+
			"(#9169 / #4800).",
		nil, nil,
	)
	c.userspaceSharedSessionPublishLockAcquired = prometheus.NewDesc(
		"xpf_userspace_shared_session_publish_lock_acquisitions_total",
		"Shared-session map mutex acquisitions taken by the helper's "+
			"session-publish path (up to three per publish: sessions, "+
			"nat_sessions, forward_wire_sessions). Scoped to publish only — "+
			"removals, HA promote/demote prewarm and read-side lookups take "+
			"the same mutexes but are deliberately excluded so this stays "+
			"the clean denominator for publish contention (#4800).",
		nil, nil,
	)
	c.userspaceSharedSessionPublishLockBlocked = prometheus.NewDesc(
		"xpf_userspace_shared_session_publish_lock_contended_total",
		"Subset of session-publish shared-map mutex acquisitions that found "+
			"the mutex already held and had to block. Divided by "+
			"..._publish_lock_acquisitions_total this is the publish leg's "+
			"share of new-flow-install serialization (#4800).",
		nil, nil,
	)
	c.userspaceSessionReplicationUpserts = prometheus.NewDesc(
		"xpf_userspace_session_replication_upserts_total",
		"Calls to the helper's sibling session-replication fan-out — one "+
			"per session replicated to every sibling worker's command "+
			"queue (#4800).",
		nil, nil,
	)
	c.userspaceSessionReplicationEnqueued = prometheus.NewDesc(
		"xpf_userspace_session_replication_enqueued_total",
		"Individual UpsertSynced commands enqueued by the sibling "+
			"session-replication fan-out. Divided by "+
			"..._replication_upserts_total this recovers the N-way fan-out "+
			"multiplier (the sibling worker count) without the consumer "+
			"having to know it out of band; it is also the denominator for "+
			"the replication contention counter (#4800).",
		nil, nil,
	)
	c.userspaceSessionReplicationLockBlocked = prometheus.NewDesc(
		"xpf_userspace_session_replication_lock_contended_total",
		"Subset of sibling command-queue mutex acquisitions in the session-"+
			"replication fan-out that found the queue already held and had "+
			"to block. Scoped to replication; the tunnel, TX-drain, HA and "+
			"cross-binding CoS enqueues take the same mutexes and are "+
			"excluded (#4800).",
		nil, nil,
	)
	c.userspaceSessionReplicationQueueDepthSum = prometheus.NewDesc(
		"xpf_userspace_session_replication_queue_depth_sum",
		"Sum of the per-call deepest sibling command-queue depth observed at "+
			"session-replication push time. Divided by "+
			"..._replication_upserts_total over the same window this is the "+
			"MEAN worst-sibling depth per replicated flow — the "+
			"differenceable backlog statistic, and the only depth reading a "+
			"verdict may rest on. DEPTH says the consuming worker is not "+
			"draining as fast as producers enqueue, which is a different "+
			"failure from producers colliding on the queue mutex and has a "+
			"different remedy (#4800).",
		nil, nil,
	)
	c.userspaceSessionReplicationQueueDepthMax = prometheus.NewDesc(
		"xpf_userspace_session_replication_queue_depth_max",
		"Monotonic PROCESS-LIFETIME high-water sibling command-queue depth "+
			"observed at session-replication push time. OPERATOR CONTEXT "+
			"ONLY. Do not rate() it, and do not difference it either: it "+
			"cannot fall, so a zero delta means \"no backlog\" OR \"a "+
			"backlog up to the previous all-time high\", and one spike "+
			"leaves the absolute value elevated for the life of the helper. "+
			"Use ..._queue_depth_sum / ..._upserts_total for any per-window "+
			"backlog question (#4800).",
		nil, nil,
	)
	c.userspaceSessionPublishErrors = prometheus.NewDesc(
		"xpf_userspace_session_publish_errors_total",
		"Failed USERSPACE_SESSIONS BPF-map publishes across all helper "+
			"paths (worker poll, HA upsert, session-glue, post-reconcile "+
			"replay, activation/reverse prewarm). A failed publish means "+
			"the XDP shim never learns the session key and takes the "+
			"NO_SESSION degraded path (drop in STRICT mode); a rising "+
			"value attributes shim no-session fallbacks to publish "+
			"failures (session map at capacity, stale fd after "+
			"reconcile) (#1789).",
		nil, nil,
	)
	c.userspacePolicyRevokedSessions = prometheus.NewDesc(
		"xpf_userspace_policy_revoked_sessions_total",
		"Cumulative established sessions revoked because the live zone policy "+
			"denied them. This counts sessions, not dropped packets (#10021).",
		nil, nil,
	)
	c.userspaceDnatPublishErrors = prometheus.NewDesc(
		"xpf_userspace_dnat_publish_errors_total",
		"Failed dnat_table reverse-SNAT BPF-map publishes across "+
			"userspace workers. The dnat_table backs embedded-ICMP NAT "+
			"reversal — the reverse lookup that maps an inbound ICMP "+
			"error (PMTUD Packet Too Big / Time Exceeded / traceroute) "+
			"back to the original pre-NAT source. A failed publish (map "+
			"at capacity, EINVAL, kernel resource exhaustion) silently "+
			"omits the reverse record, so the error is dropped or "+
			"mis-delivered; a rising value attributes that loss to "+
			"dnat_table map-capacity pressure (#2244).",
		nil, nil,
	)
	c.userspaceSyncedImportCapDrops = prometheus.NewDesc(
		"xpf_userspace_synced_import_cap_drops_total",
		"Peer-synced session imports rejected by the coordinator's "+
			"aggregate admission bound. Locally-created sessions are "+
			"capped per worker at max_sessions; peer-synced imports were "+
			"uncapped and fanned out to every worker command queue+table, "+
			"so a peer under session-table pressure (or a compromised "+
			"peer) could drive this node past its own aggregate session "+
			"ceiling and multiply that state across all workers. The "+
			"import path now bounds the shared synced map at this "+
			"appliance's own aggregate ENTRY ceiling "+
			"(2 * worker_count * max_sessions -- 2x the logical session "+
			"ceiling, because each admitted forward publishes a forward "+
			"plus a synthesized reverse companion) and drop-newest-rejects "+
			"an over-ceiling import; a rising value means a peer's import "+
			"would push THIS appliance past its own aggregate entry "+
			"ceiling (2N) — receiver-local, so a larger asymmetric peer "+
			"can legitimately trip a smaller receiver. A symmetric-pair "+
			"failover (N logical sessions = 2N entries) exactly fits and "+
			"never trips it (#5674).",
		nil, nil,
	)
	c.userspaceWorkerCommandQueuePoisonRecoveries = prometheus.NewDesc(
		"xpf_userspace_worker_command_queue_poison_recoveries_total",
		"Worker command-queue mutex poison recoveries across all "+
			"helper producer/consumer sites (worker poll, HA enqueues, "+
			"session replication, activation prewarm, tunnel install, "+
			"cross-binding shaped-TX redirect). A poisoned mutex means "+
			"a worker thread panicked while holding the lock; recovery "+
			"keeps the committed queue and clears the poison so the "+
			"queues keep flowing instead of going permanently deaf. "+
			"A nonzero value indicates a contained worker panic "+
			"occurred (#1807, extends #1790).",
		nil, nil,
	)
	c.userspaceWorkerCommandQueueDrops = prometheus.NewDesc(
		"xpf_userspace_worker_command_queue_drops_total",
		"Worker commands discarded because the target per-worker "+
			"command queue was already at its 4096-entry cap. Distinct "+
			"from the poison-recovery counter: a recovery keeps the "+
			"committed queue and loses nothing, a capacity drop "+
			"discards a command. The expected steady-state value is 0 "+
			"— the consumer drains the whole deque per poll and cannot "+
			"be outrun by a sustained producer — so a rising value "+
			"means some worker has stopped draining and its producers "+
			"are still enqueueing to it (#6929).",
		nil, nil,
	)
	c.userspaceSyncedImportUnpublished = prometheus.NewDesc(
		"xpf_userspace_synced_import_unpublished_total",
		"Peer-synced session imports the helper's local-replace guard "+
			"ADMITTED but could not publish to the kernel session map, "+
			"because no session map existed at the time. Counts the GAP "+
			"only: declining to publish because the PEER owns the "+
			"redundancy group is the correct outcome and is not counted, "+
			"and a counter folding the two together would sit "+
			"permanently nonzero on a healthy node. Nonzero is expected "+
			"rather than a fault -- the map is absent on a standby "+
			"taking bulk sync before its first snapshot apply and "+
			"between a worker teardown and the next bring-up, and every "+
			"reconcile opens by capturing the whole shared synced map "+
			"and replaying it once the new map is up, so those imports "+
			"are published shortly after rather than lost. It exists as "+
			"the instrument for #7209: taking sync_session off the "+
			"helper's snapshot-wide mutex opens a window where such an "+
			"import is acked to Go as installed and then neither "+
			"published nor replayed, with no signal today.",
		nil, nil,
	)
	c.userspaceSyncedImportZoneUnresolved = prometheus.NewDesc(
		"xpf_userspace_synced_import_zone_unresolved_total",
		"Peer-synced session imports whose (from-zone, to-zone) pair "+
			"could not be resolved locally, so the source-NAT "+
			"reservation was booked WITHOUT the #6211 zone narrowing. "+
			"The session itself is installed correctly: the translated "+
			"address and port come off the HA wire and are never "+
			"recomputed, so nothing is mistranslated. What is lost is "+
			"the narrowing that decides WHICH rule's allocator holds "+
			"the reservation — with one pool-mode rule owning that "+
			"address the result is identical and this is purely "+
			"informational, but where two rules' pools both contain it "+
			"in separate allocators the booking may sit in a different "+
			"allocator than the active node's, and a later re-upsert "+
			"that does resolve books a SECOND reservation, both live "+
			"until teardown and both counting against max_tracked_flows. "+
			"Nonzero is not itself a fault: it is expected while a "+
			"config apply is in flight (sync_session reads the "+
			"published forwarding view by design, #7209) and on a "+
			"standby's first sync before any snapshot is applied. "+
			"Sustained growth on a settled config means the two nodes' "+
			"zone configuration has drifted.",
		nil, nil,
	)
	// #7398: three counters the Coordinator computed and never surfaced.
	// Wiring is only half the job — a nil *prometheus.Desc field COMPILES and
	// only fails as a segfault inside pkg/api, so a green build proves nothing
	// about the descriptor. The metric-count guard is what actually binds these.
	c.userspaceSessionInstallStaleIgnored = prometheus.NewDesc(
		"xpf_userspace_session_install_stale_ignored_total",
		"Stale-generation peer session INSTALLS refused by the helper's "+
			"in-memory SyncedSessionEntry guard (#2170). The authoritative "+
			"guard is the Go cluster apply layer; this is the helper-side "+
			"back-stop, so nonzero means a delayed peer install arrived after "+
			"a newer generation had been committed and the helper declined to "+
			"regress it. Expected to be 0 outside config churn.",
		nil, nil,
	)
	c.userspaceSessionDeleteStaleIgnored = prometheus.NewDesc(
		"xpf_userspace_session_delete_stale_ignored_total",
		"Stale-generation peer session DELETES refused by the same "+
			"helper-side generation guard (#2170). Nonzero means a delete for "+
			"a generation older than the committed entry was ignored rather "+
			"than allowed to remove a session a newer generation installed.",
		nil, nil,
	)
	c.userspaceSyncedImportReserveRefused = prometheus.NewDesc(
		"xpf_userspace_synced_import_reserve_refused_total",
		"Peer-synced imports refused because this node could not reserve "+
			"the translated NAT port the session names (#6600). Sustained "+
			"growth means the standby cannot hold the primary's translations, "+
			"so those flows will NOT survive a failover — this is the "+
			"pre-failover warning, not a post-mortem.",
		nil, nil,
	)
	// #10512: policy-delete micro-batch gate-lease holds — the empirical leg
	// of the tree-consistent timing position (average hold must read
	// ms-typical; max bounds the pathological case).
	c.userspacePolicyBatchCount = prometheus.NewDesc(
		"xpf_userspace_policy_batch_count_total",
		"Policy-delete micro-batches that reached a Finalizing gate lease (#10512).",
		nil, nil,
	)
	c.userspacePolicyBatchHoldNs = prometheus.NewDesc(
		"xpf_userspace_policy_batch_hold_ns_total",
		"Total gate-lease hold nanoseconds across counted policy-delete micro-batches (#10512).",
		nil, nil,
	)
	c.userspacePolicyBatchHoldMaxNs = prometheus.NewDesc(
		"xpf_userspace_policy_batch_hold_max_ns",
		"Max single gate-lease hold in nanoseconds across policy-delete micro-batches (#10512, lifetime max).",
		nil, nil,
	)
	c.userspaceSyncedImportUnknownRoutingDomain = prometheus.NewDesc(
		"xpf_userspace_synced_import_unknown_routing_domain_total",
		"Peer-synced imports refused because this node runs routing "+
			"instances and the request named no ingress identity to resolve "+
			"the session's routing domain from (#7160). Importing under "+
			"domain 0 would file the session in the DEFAULT instance's "+
			"identity space, where a reply that resolved its own domain "+
			"reaches it. Sustained growth on a VRF cluster means those flows "+
			"will NOT be taken over on failover; always 0 on a "+
			"single-instance node.",
		nil, nil,
	)
	c.userspaceSharedSessionPoisonRecoveries = prometheus.NewDesc(
		"xpf_userspace_shared_session_poison_recoveries_total",
		"Shared-session mutex poison recoveries across every "+
			"shared-session and owner-RG-index site (publish, remove, "+
			"lookups, index maintenance, and the #5154 HA import "+
			"generation-guard reads). A poisoned mutex means a worker "+
			"thread panicked while holding the lock; recovery keeps the "+
			"committed map and clears the poison, so HA promotion "+
			"proceeds with the EXISTING synced sessions instead of "+
			"treating the table as empty and dropping every one of them "+
			"at failover (#2402). A nonzero value indicates a contained "+
			"worker panic (#925 supervisor) that HA state survived; the "+
			"recovery is self-healing, so this counter is the only "+
			"durable record of it (#6641).",
		nil, nil,
	)
	// #9900: frame-ownership violation counters. Kernel-fault signals
	// (TX completion skew/invalid/duplicate, fill invalid) plus the
	// dead-worker shed and request-path fault counters. All zero on a
	// healthy dataplane; all emitted unconditionally so 0 is a real
	// signal, not an absent series.
	c.userspaceTxCompletionSkew = prometheus.NewDesc(
		"xpf_userspace_tx_completion_skew_total",
		"TX completions reaped beyond outstanding_tx, including completions "+
			"drained at gauge 0 (#9900 F-092).",
		nil, nil,
	)
	c.userspaceTxCompletionInvalid = prometheus.NewDesc(
		"xpf_userspace_tx_completion_invalid_total",
		"Reaped completion offsets dropped instead of recycled: not an "+
			"aligned in-region frame base (#9900 F-092).",
		nil, nil,
	)
	c.userspaceTxCompletionDuplicate = prometheus.NewDesc(
		"xpf_userspace_tx_completion_duplicate_total",
		"Aligned in-region completions dropped for lack of submit "+
			"ownership: duplicate or stale deliveries (#9900 F-092).",
		nil, nil,
	)
	c.userspaceFillInvalid = prometheus.NewDesc(
		"xpf_userspace_fill_invalid_total",
		"Fill-ring offsets dropped instead of submitted: frame base "+
			"outside the owned region (#9900 F-091/F-092).",
		nil, nil,
	)
	c.userspaceWorkerCommandQueueShed = prometheus.NewDesc(
		"xpf_userspace_worker_command_queue_shed_total",
		"Worker commands shed because the target worker is dead "+
			"(recorded panic, thread exited) — distinct from live-queue "+
			"drops (#9900 F-093).",
		nil, nil,
	)
	c.userspaceServerStatePoisonRecoveries = prometheus.NewDesc(
		"xpf_userspace_server_state_poison_recoveries_total",
		"ServerState mutex poison recoveries; each one quarantined the "+
			"daemon for a supervisor restart (#9900 F-094).",
		nil, nil,
	)
	c.userspaceServerHandlerPanics = prometheus.NewDesc(
		"xpf_userspace_server_handler_panics_total",
		"Request-handler panics contained per-connection; each one "+
			"quarantined the daemon for a supervisor restart (#9900 F-094).",
		nil, nil,
	)
}
