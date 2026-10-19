package api

import (
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// Prometheus emitters for the userspace dataplane's DYNAMIC BUFFER telemetry.
// Split out of metrics_userspace.go for the #7700 modularity floor; this is a
// move, not a behaviour change — every emitter is still driven from
// collectUserspaceStatus in that file.

func (c *xpfCollector) emitUserspaceDynamicBufferMetrics(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	if status.MaxSessions > 0 {
		c.emitConstMetric(ch, c.userspaceSessionTableEntries,
			prometheus.GaugeValue,
			float64(status.SessionTableEntries))
		c.emitConstMetric(ch, c.userspaceSessionTableCapacity,
			prometheus.GaugeValue,
			float64(status.MaxSessions))
	}

	// #1760: NAT reverse-key 1:N collision displacement counter. Emitted
	// unconditionally (cumulative CounterValue, not gated on a session-
	// table denominator) so a 0 is a real published "no collisions" signal
	// rather than an absent series.
	// #8447: emitted unconditionally, same doctrine — a published 0 for
	// `consulted` is the finding (nothing reached source-NAT), and an absent
	// series would be indistinguishable from a helper that predates it.
	c.emitConstMetric(ch, c.userspaceSourceNATMatchConsulted,
		prometheus.CounterValue,
		float64(status.SourceNATMatchConsultedTotal))
	c.emitConstMetric(ch, c.userspaceSourceNATMatchMatched,
		prometheus.CounterValue,
		float64(status.SourceNATMatchMatchedTotal))
	c.emitConstMetric(ch, c.userspaceSourceNATMatchUnavailable,
		prometheus.CounterValue,
		float64(status.SourceNATMatchUnavailableTotal))
	c.emitConstMetric(ch, c.userspaceSourceNATMatchNoMatch,
		prometheus.CounterValue,
		float64(status.SourceNATMatchNoMatchTotal))
	c.emitConstMetric(ch, c.userspaceNatReverseKeyCollisions,
		prometheus.CounterValue,
		float64(status.NatReverseKeyCollisions))
	// #6751: emitted unconditionally for the same reason — a published 0
	// beside a nonzero aggregate is the informative reading (the observed
	// collisions were same-source port reuse, not a cross-session leak).
	c.emitConstMetric(ch, c.userspaceNatReverseKeyCollisionsDistinctSrc,
		prometheus.CounterValue,
		float64(status.NatReverseKeyCollisionsDistinctSrc))

	// #1861: install-refusal trio. Emitted unconditionally (cumulative
	// CounterValue) so a 0 is a real "no refusals" signal rather than an
	// absent series.
	c.emitConstMetric(ch, c.userspaceSessionCreateDrops,
		prometheus.CounterValue,
		float64(status.SessionCreateDrops))
	c.emitConstMetric(ch, c.userspaceSessionInstallAdmissionRefused,
		prometheus.CounterValue,
		float64(status.SessionInstallAdmissionRefused))
	c.emitConstMetric(ch, c.userspaceSessionInstallPartial,
		prometheus.CounterValue,
		float64(status.SessionInstallPartial))
	c.emitConstMetric(ch, c.userspacePptpUnassociatedPackets, prometheus.CounterValue,
		float64(status.PptpUnassociatedPackets))
	c.emitConstMetric(ch, c.userspacePptpExpiredIdle, prometheus.CounterValue,
		float64(status.PptpExpiredIdle))
	c.emitConstMetric(ch, c.userspacePptpHandleCollisions, prometheus.CounterValue,
		float64(status.PptpHandleCollisions))
	c.emitConstMetric(ch, c.userspacePptpAllocatorCollisions, prometheus.CounterValue,
		float64(status.PptpAllocatorCollisions))

	// #1789: failed USERSPACE_SESSIONS BPF-map publishes. Also emitted
	// unconditionally so a 0 is a real "no publish failures" signal
	// rather than an absent series.
	c.emitConstMetric(ch, c.userspaceSessionPublishErrors,
		prometheus.CounterValue,
		float64(status.SessionPublishErrorsTotal))
	// #10021: established-session revocations are a standalone session
	// signal, not part of the packet-counted "Packets dropped" total.
	c.emitConstMetric(ch, c.userspacePolicyRevokedSessions,
		prometheus.CounterValue,
		float64(status.PolicyRevokedSessionsTotal))
	// #11503: process-global unzoned-policy cause counters are exported as
	// direction-specific packet-denial totals.
	c.emitConstMetric(ch, c.userspaceUnzonedIngressDenied,
		prometheus.CounterValue,
		float64(status.UnzonedIngressDeniedTotal))
	c.emitConstMetric(ch, c.userspaceUnzonedEgressDenied,
		prometheus.CounterValue,
		float64(status.UnzonedEgressDeniedTotal))
	// #4800: the publish + replication legs of the new-flow-install
	// contention surface. Emitted unconditionally and always as complete
	// (denominator, contended) pairs — a missing series would be
	// indistinguishable from a scrape failure, and a contended series
	// without its denominator is not interpretable at all.
	c.emitConstMetric(ch, c.userspaceSharedSessionPublishes,
		prometheus.CounterValue,
		float64(status.SharedSessionPublishesTotal))
	c.emitConstMetric(ch, c.userspaceSharedSessionPublishLockAcquired,
		prometheus.CounterValue,
		float64(status.SharedSessionPublishLockAcquisitionsTotal))
	// #9169: site 4. Emitted here rather than beside the other event-stream
	// series because it belongs to the #4800 contention surface, and that
	// surface's rule is that every (denominator, contended) pair is emitted
	// unconditionally and together — a contended series without its
	// denominator is not interpretable, and a missing series is
	// indistinguishable from a scrape failure.
	c.emitConstMetric(ch, c.userspaceEventStreamProducerSeqLockAcquired,
		prometheus.CounterValue,
		float64(status.EventStreamProducerSeqLockAcquisitionsTotal))
	c.emitConstMetric(ch, c.userspaceEventStreamProducerSeqLockBlocked,
		prometheus.CounterValue,
		float64(status.EventStreamProducerSeqLockContendedTotal))
	c.emitConstMetric(ch, c.userspaceSharedSessionPublishLockBlocked,
		prometheus.CounterValue,
		float64(status.SharedSessionPublishLockContendedTotal))
	c.emitConstMetric(ch, c.userspaceSessionReplicationUpserts,
		prometheus.CounterValue,
		float64(status.SessionReplicationUpsertsTotal))
	c.emitConstMetric(ch, c.userspaceSessionReplicationEnqueued,
		prometheus.CounterValue,
		float64(status.SessionReplicationEnqueuedTotal))
	c.emitConstMetric(ch, c.userspaceSessionReplicationLockBlocked,
		prometheus.CounterValue,
		float64(status.SessionReplicationLockContendedTotal))
	c.emitConstMetric(ch, c.userspaceSessionReplicationQueueDepthSum,
		prometheus.CounterValue,
		float64(status.SessionReplicationQueueDepthSum))
	c.emitConstMetric(ch, c.userspaceSessionReplicationQueueDepthMax,
		prometheus.GaugeValue,
		float64(status.SessionReplicationQueueDepthMax))

	// #2244: failed dnat_table reverse-SNAT BPF-map publishes. Also
	// emitted unconditionally so a 0 is a real "no reverse-NAT publish
	// failures" signal rather than an absent series.
	c.emitConstMetric(ch, c.userspaceDnatPublishErrors,
		prometheus.CounterValue,
		float64(status.DnatPublishErrorsTotal))

	// #5674: peer-synced session imports rejected by the coordinator's
	// aggregate admission bound. Also emitted unconditionally so a 0 is a real
	// "no over-ceiling synced imports rejected" signal rather than an absent
	// series.
	c.emitConstMetric(ch, c.userspaceSyncedImportCapDrops,
		prometheus.CounterValue,
		float64(status.SyncedImportCapDropsTotal))

	// #1760 W3': shared-map NAT reverse-key displacement events. Emitted
	// unconditionally so a 0 is a real "no collisions" signal rather
	// than an absent series.
	c.emitConstMetric(ch, c.userspaceNatReverseKeySharedDisplacements,
		prometheus.CounterValue,
		float64(status.NatReverseKeySharedDisplacementsTotal))

	// #6751 PR 2/3: interface-mode SNAT identity registry. Emitted
	// unconditionally: a published 0 is the informative reading (no two
	// flows contended, nothing failed closed), not an absent series.
	c.emitConstMetric(ch, c.userspaceInterfaceSNATPATCollisions,
		prometheus.CounterValue,
		float64(status.InterfaceSNATPATCollisionsTotal))
	// #13283: NAT parse/validation failures, partitioned by the builder.
	c.emitConstMetric(ch, c.userspaceNATParseErrorsTotal,
		prometheus.CounterValue,
		float64(status.SourceNATParseErrors),
		"source")
	c.emitConstMetric(ch, c.userspaceNATParseErrorsTotal,
		prometheus.CounterValue,
		float64(status.DestinationNATParseErrors),
		"destination")
	c.emitConstMetric(ch, c.userspaceNATParseErrorsTotal,
		prometheus.CounterValue,
		float64(status.StaticNATParseErrors),
		"static")
	// #7056: emitted unconditionally like the sibling above — a published 0 is
	// the informative reading (no alias was ever refused), not an absent series.
	c.emitConstMetric(ch, c.userspaceNAT64FragCrossDomainMisses,
		prometheus.CounterValue,
		float64(status.NAT64FragCrossDomainMissesTotal))
	c.emitConstMetric(ch, c.userspaceNAT64OverBudgetTotal,
		prometheus.CounterValue,
		float64(status.NAT64OverBudgetTotal))
	c.emitConstMetric(ch, c.userspaceNAT64OverBudgetPrefixes,
		prometheus.GaugeValue,
		float64(status.NAT64OverBudgetPrefixes))
	c.emitConstMetric(ch, c.userspaceNAT64DeterministicDowngrades,
		prometheus.CounterValue,
		float64(status.NAT64DeterministicV6DowngradesTotal))
	// #10729 X2-F6: emitted unconditionally like the #7056 siblings — a
	// published 0 means no v6 chain has been declined for AH yet.
	c.emitConstMetric(ch, c.userspaceIPv6AHFlowlessTotal,
		prometheus.CounterValue,
		float64(status.IPv6AHFlowlessTotal))
	c.emitConstMetric(ch, c.userspaceNAT64FragProtocolAliasMisses,
		prometheus.CounterValue,
		float64(status.NAT64FragProtocolAliasMissesTotal))
	// #9901: packet-identity counters, emitted unconditionally like the
	// #7056 siblings above — a published 0 is the informative reading.
	c.emitConstMetric(ch, c.userspaceFragMaxLifetimeEvictions,
		prometheus.CounterValue,
		float64(status.FragMaxLifetimeEvictionsTotal))
	c.emitConstMetric(ch, c.userspaceEgressMTUUnknownForward,
		prometheus.CounterValue,
		float64(status.EgressMTUUnknownForwardTotal))
	c.emitConstMetric(ch, c.userspacePTBUnbuildable,
		prometheus.CounterValue,
		float64(status.PTBUnbuildableTotal))
	c.emitConstMetric(ch, c.userspaceEmbeddedQuoteSubminimalRefused,
		prometheus.CounterValue,
		float64(status.EmbeddedQuoteSubminimalRefusedTotal))
	c.emitConstMetric(ch, c.userspaceEmbeddedErrorPerSessionSuppressed,
		prometheus.CounterValue,
		float64(status.EmbeddedErrorPerSessionSuppressedTotal))
	c.emitConstMetric(ch, c.userspaceNATReverseAmbiguous,
		prometheus.CounterValue,
		float64(status.NATReverseAmbiguousTotal))
	c.emitConstMetric(ch, c.userspaceInterfaceSNATIdentityExhaustion,
		prometheus.CounterValue,
		float64(status.InterfaceSNATIdentityExhaustionTotal))
	c.emitConstMetric(ch, c.userspaceInterfaceSNATSyncConflictDrops,
		prometheus.CounterValue,
		float64(status.InterfaceSNATSyncIdentityConflictDropsTotal))
	c.emitConstMetric(ch, c.userspaceInterfaceSNATRegistryCap,
		prometheus.CounterValue,
		float64(status.InterfaceSNATRegistryCapExhaustionTotal))

	// #1807: worker-command-queue poison recoveries. Also emitted
	// unconditionally so a 0 is a real "no worker panics" signal rather
	// than an absent series.
	c.emitConstMetric(ch, c.userspaceWorkerCommandQueuePoisonRecoveries,
		prometheus.CounterValue,
		float64(status.WorkerCommandQueuePoisonRecoveries))

	// #6929: per-worker command-queue capacity drops. Emitted
	// unconditionally for the same reason as its #1807 neighbour: 0 is the
	// expected value and a real signal, so an absent series would be
	// indistinguishable from a helper that never reports.
	c.emitConstMetric(ch, c.userspaceWorkerCommandQueueDrops,
		prometheus.CounterValue,
		float64(status.WorkerCommandQueueDrops))

	// #2402/#6641: shared-session poison recoveries. Emitted
	// unconditionally for the same reason as its #1807 twin above: a 0 is
	// a real "no worker panic touched HA session state" signal, and an
	// absent series would be indistinguishable from a helper that never
	// reports.
	c.emitConstMetric(ch, c.userspaceSharedSessionPoisonRecoveries,
		prometheus.CounterValue,
		float64(status.SharedSessionPoisonRecoveries))

	// #9900: frame-ownership violation counters, emitted unconditionally
	// like their neighbours — 0 is the expected healthy value and a real
	// signal for each.
	c.emitConstMetric(ch, c.userspaceTxCompletionSkew,
		prometheus.CounterValue,
		float64(status.TxCompletionSkew))
	c.emitConstMetric(ch, c.userspaceTxCompletionInvalid,
		prometheus.CounterValue,
		float64(status.TxCompletionInvalid))
	c.emitConstMetric(ch, c.userspaceTxCompletionDuplicate,
		prometheus.CounterValue,
		float64(status.TxCompletionDuplicate))
	c.emitConstMetric(ch, c.userspaceFillInvalid,
		prometheus.CounterValue,
		float64(status.FillInvalid))
	c.emitConstMetric(ch, c.userspaceWorkerCommandQueueShed,
		prometheus.CounterValue,
		float64(status.WorkerCommandQueueShed))
	c.emitConstMetric(ch, c.userspaceServerStatePoisonRecoveries,
		prometheus.CounterValue,
		float64(status.ServerStatePoisonRecoveries))
	c.emitConstMetric(ch, c.userspaceServerHandlerPanics,
		prometheus.CounterValue,
		float64(status.ServerHandlerPanics))

	// #7398: emitted unconditionally like their neighbours. A 0 here is a real
	// "no stale install/delete was refused, no import lost its reservation"
	// signal; an absent series would be indistinguishable from a helper that
	// never reports, which is the state these three were in before #7398.
	c.emitConstMetric(ch, c.userspaceSessionInstallStaleIgnored,
		prometheus.CounterValue,
		float64(status.SessionInstallStaleIgnored))
	c.emitConstMetric(ch, c.userspaceSessionDeleteStaleIgnored,
		prometheus.CounterValue,
		float64(status.SessionDeleteStaleIgnored))
	c.emitConstMetric(ch, c.userspaceSyncedImportReserveRefused,
		prometheus.CounterValue,
		float64(status.SyncedImportReserveRefused))
	c.emitConstMetric(ch, c.userspaceSyncedImportMirrorRefused,
		prometheus.CounterValue,
		float64(status.SyncedImportMirrorRefused))
	c.emitConstMetric(ch, c.userspaceMirrorRestoreRepublished,
		prometheus.CounterValue,
		float64(status.MirrorRestoreRepublished))
	c.emitConstMetric(ch, c.userspaceMirrorRestoreDeleted,
		prometheus.CounterValue,
		float64(status.MirrorRestoreDeleted))
	c.emitConstMetric(ch, c.userspaceMirrorRestoreFailed,
		prometheus.CounterValue,
		float64(status.MirrorRestoreFailed))
	// #7160: emitted unconditionally like its neighbours — a 0 is the real
	// "every synced import resolved its routing domain" signal, and an absent
	// series is indistinguishable from a helper that never reports.
	c.emitConstMetric(ch, c.userspaceSyncedImportUnknownRoutingDomain,
		prometheus.CounterValue,
		float64(status.SyncedImportUnknownRoutingDomain))
	// #10720 F4: a 0 is the informative "no incomplete synced keys refused"
	// value; the series is emitted on every scrape.
	c.emitConstMetric(ch, c.userspaceSyncedImportIncompleteKey,
		prometheus.CounterValue,
		float64(status.SyncedImportIncompleteKey))
	// #10512: emitted unconditionally like their neighbours. All three are
	// lifetime-monotonic (count, summed holds, max hold), so CounterValue is
	// exact, not approximate.
	c.emitConstMetric(ch, c.userspacePolicyBatchCount,
		prometheus.CounterValue,
		float64(status.PolicyBatchCount))
	c.emitConstMetric(ch, c.userspacePolicyBatchHoldNs,
		prometheus.CounterValue,
		float64(status.PolicyBatchHoldNs))
	c.emitConstMetric(ch, c.userspacePolicyBatchHoldMaxNs,
		prometheus.GaugeValue,
		float64(status.PolicyBatchHoldMaxNs))

	// #7209: peer-synced imports that skipped #6211's zone narrowing.
	// Emitted unconditionally, for the same reason as its neighbours: a 0
	// is a real "every synced import resolved its zones" signal, and an
	// absent series is indistinguishable from a helper that never reports.
	c.emitConstMetric(ch, c.userspaceSyncedImportZoneUnresolved,
		prometheus.CounterValue,
		float64(status.SyncedImportZoneUnresolved))

	// #7209: imports admitted by the local-replace guard with no kernel
	// session map to publish into. Emitted unconditionally like its
	// neighbours: a 0 is the real "every admitted import reached the map"
	// signal, and an absent series cannot be told from a helper that never
	// reports it.
	c.emitConstMetric(ch, c.userspaceSyncedImportUnpublished,
		prometheus.CounterValue,
		float64(status.SyncedImportUnpublished))

	// #2315: GRE-decap RFC 6040 4.2 illegal-combination drops (outer CE
	// over a Not-ECT inner). Emitted unconditionally so a 0 is a real
	// "no illegal combinations seen" signal rather than an absent series.
	c.emitConstMetric(ch, c.userspaceGreDecapEcnIllegalDrops,
		prometheus.CounterValue,
		float64(status.GreDecapEcnIllegalDropsTotal))

	// #10695: Rust's IPsec-inner status counters, including the four D14
	// zone-gate refusals, are exported independently so each cause remains
	// distinguishable. Emit zeros too: absence must not look like a healthy
	// helper that reported zero activity.
	c.emitConstMetric(ch, c.userspaceZoneGateUnzoned,
		prometheus.CounterValue,
		float64(status.ZoneGateUnzonedTotal))
	c.emitConstMetric(ch, c.userspaceZoneGateAmbiguous,
		prometheus.CounterValue,
		float64(status.ZoneGateAmbiguousTotal))
	c.emitConstMetric(ch, c.userspaceZoneGateStale,
		prometheus.CounterValue,
		float64(status.ZoneGateStaleTotal))
	c.emitConstMetric(ch, c.userspaceZoneGateNoGeneration,
		prometheus.CounterValue,
		float64(status.ZoneGateNoGenerationTotal))
	c.emitConstMetric(ch, c.userspaceIpsecInnerParseDrops,
		prometheus.CounterValue,
		float64(status.IpsecInnerParseDropsTotal))
	c.emitConstMetric(ch, c.userspaceIpsecInnerEcnIllegalDrops,
		prometheus.CounterValue,
		float64(status.IpsecInnerEcnIllegalDrops))
	c.emitConstMetric(ch, c.userspaceIpsecInnerWorkerQueueFull,
		prometheus.CounterValue,
		float64(status.IpsecInnerWorkerQueueFullTotal))
	c.emitConstMetric(ch, c.userspaceIpsecInnerVerdictQueueFull,
		prometheus.CounterValue,
		float64(status.IpsecInnerVerdictQueueFullTotal))
	c.emitConstMetric(ch, c.userspaceIpsecInnerVerdictQueueContended,
		prometheus.CounterValue,
		float64(status.IpsecInnerVerdictQueueContendedTotal))
	c.emitConstMetric(ch, c.userspaceIpsecInnerSlabExhausted,
		prometheus.CounterValue,
		float64(status.IpsecInnerSlabExhaustedTotal))
	c.emitConstMetric(ch, c.userspaceIpsecInnerWorkerRetired,
		prometheus.CounterValue,
		float64(status.IpsecInnerWorkerRetiredTotal))
	c.emitConstMetric(ch, c.userspaceIpsecInnerWorkerOrphanReaped,
		prometheus.CounterValue,
		float64(status.IpsecInnerWorkerOrphanReapedTotal))
	c.emitConstMetric(ch, c.userspaceIpsecInnerOrphanProvisional,
		prometheus.CounterValue,
		float64(status.IpsecInnerOrphanProvisionalTotal))
	c.emitConstMetric(ch, c.userspaceIpsecInnerPermitForwardArmed,
		prometheus.CounterValue,
		float64(status.IpsecInnerPermitForwardArmedTotal))
	// #2317: WG-decap RFC 6040 4.2 illegal-combination drops (outer CE,
	// recvmsg-captured, over a Not-ECT inner). Emitted unconditionally so
	// a 0 is a real "no illegal combinations seen" signal rather than an
	// absent series.
	c.emitConstMetric(ch, c.userspaceWgDecapEcnIllegalDrops,
		prometheus.CounterValue,
		float64(status.WgDecapEcnIllegalDropsTotal))

	// #2331: native-GRE encap local-MTU oversize drops. Emitted
	// unconditionally so a 0 is a real "no oversized outer datagrams
	// refused" signal rather than an absent series. Nonzero flags inner
	// flows whose encapped size exceeds the local transport/egress MTU.
	c.emitConstMetric(ch, c.userspaceGreEncapDfOversizeDrops,
		prometheus.CounterValue,
		float64(status.GreEncapDfOversizeDropsTotal))

	// #2782: native-GRE decap checksum-invalid drops (C bit set but the
	// GRE checksum failed to verify, or the header was truncated past the
	// Checksum+Reserved1 field). Emitted unconditionally so a 0 is a real
	// "no corrupt checksummed GRE frames seen" signal rather than an
	// absent series. Nonzero flags a checksummed GRE peer delivering
	// corrupt frames / a truncated GRE header.
	c.emitConstMetric(ch, c.userspaceGreDecapChecksumInvalidDrops,
		prometheus.CounterValue,
		float64(status.GreDecapChecksumInvalidDropsTotal))

	// #6842: native-GRE decap refusals for a non-zero GRE version (RFC 2637
	// / PPTP enhanced GRE is version 1) where the outer tuple named a
	// configured GRE endpoint. Emitted unconditionally so a 0 is a real "no
	// PPTP offered to a GRE endpoint" signal rather than an absent series.
	// Nonzero flags a peer offering PPTP to a tunnel xpf cannot terminate.
	c.emitConstMetric(ch, c.userspaceGreDecapUnsupportedVersionRefusals,
		prometheus.CounterValue,
		float64(status.GreDecapUnsupportedVersionRefusalsTotal))

	// #10865: GRE PT/nibble mismatch refusals at a configured endpoint.
	// Emitted unconditionally so 0 means no matching endpoint refused a
	// mismatched packet. This is not a drop counter; ordinary transit is not
	// counted.
	c.emitConstMetric(ch, c.userspaceGreDecapPtNibbleMismatchRefusals,
		prometheus.CounterValue,
		float64(status.GreDecapPtNibbleMismatchRefusalsTotal))

	c.emitConstMetric(ch, c.userspaceGreOuterFragDrops,
		prometheus.CounterValue,
		float64(status.GreOuterFragDropsTotal))

	// #15095: reassembled-but-decap-refused GRE datagrams. Emitted
	// unconditionally so 0 means no completed reassembly was refused.
	ch <- prometheus.MustNewConstMetric(
		c.userspaceGreReassembledDecapRefusals,
		prometheus.CounterValue,
		float64(status.GreReassembledDecapRefusalsTotal),
	)

	// #2472: locally-generated error-reply per-reason token-bucket drops.
	// Emitted unconditionally so a 0 is a real "no generated errors
	// rate-limited" signal rather than an absent series. Nonzero flags an
	// error-amplification / reflection flood (or a routing loop) being
	// clamped.
	c.emitConstMetric(ch, c.userspaceTimeExceededRateLimited,
		prometheus.CounterValue,
		float64(status.TimeExceededRateLimitedTotal))
	c.emitConstMetric(ch, c.userspacePacketTooBigRateLimited,
		prometheus.CounterValue,
		float64(status.PacketTooBigRateLimitedTotal))
	c.emitConstMetric(ch, c.userspaceRejectRateLimited,
		prometheus.CounterValue,
		float64(status.RejectRateLimitedTotal))

	var activeFlows, flowCapacity uint64
	for _, b := range status.Bindings {
		activeFlows += uint64(b.ActiveFlowCount)
		flowCapacity += uint64(b.FlowCacheCapacity)
		if b.FlowCacheCapacity == 0 {
			continue
		}
		c.emitConstMetric(ch, c.bindingFlowCacheCapacity,
			prometheus.GaugeValue,
			float64(b.FlowCacheCapacity),
			strconv.FormatUint(uint64(b.Slot), 10),
			strconv.FormatUint(uint64(b.QueueID), 10),
			strconv.FormatUint(uint64(b.WorkerID), 10),
			b.Interface)
	}
	if flowCapacity == 0 {
		flowCapacity = status.FlowCacheCapacity
	}
	if flowCapacity > 0 {
		c.emitConstMetric(ch, c.userspaceFlowCacheActiveFlows,
			prometheus.GaugeValue,
			float64(activeFlows))
		c.emitConstMetric(ch, c.userspaceFlowCacheCapacity,
			prometheus.GaugeValue,
			float64(flowCapacity))
	}
}
