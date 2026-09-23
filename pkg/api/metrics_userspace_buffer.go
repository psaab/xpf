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
		ch <- prometheus.MustNewConstMetric(
			c.userspaceSessionTableEntries,
			prometheus.GaugeValue,
			float64(status.SessionTableEntries),
		)
		ch <- prometheus.MustNewConstMetric(
			c.userspaceSessionTableCapacity,
			prometheus.GaugeValue,
			float64(status.MaxSessions),
		)
	}

	// #1760: NAT reverse-key 1:N collision displacement counter. Emitted
	// unconditionally (cumulative CounterValue, not gated on a session-
	// table denominator) so a 0 is a real published "no collisions" signal
	// rather than an absent series.
	// #8447: emitted unconditionally, same doctrine — a published 0 for
	// `consulted` is the finding (nothing reached source-NAT), and an absent
	// series would be indistinguishable from a helper that predates it.
	ch <- prometheus.MustNewConstMetric(
		c.userspaceSourceNATMatchConsulted,
		prometheus.CounterValue,
		float64(status.SourceNATMatchConsultedTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.userspaceSourceNATMatchMatched,
		prometheus.CounterValue,
		float64(status.SourceNATMatchMatchedTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.userspaceSourceNATMatchUnavailable,
		prometheus.CounterValue,
		float64(status.SourceNATMatchUnavailableTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.userspaceSourceNATMatchNoMatch,
		prometheus.CounterValue,
		float64(status.SourceNATMatchNoMatchTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.userspaceNatReverseKeyCollisions,
		prometheus.CounterValue,
		float64(status.NatReverseKeyCollisions),
	)
	// #6751: emitted unconditionally for the same reason — a published 0
	// beside a nonzero aggregate is the informative reading (the observed
	// collisions were same-source port reuse, not a cross-session leak).
	ch <- prometheus.MustNewConstMetric(
		c.userspaceNatReverseKeyCollisionsDistinctSrc,
		prometheus.CounterValue,
		float64(status.NatReverseKeyCollisionsDistinctSrc),
	)

	// #1861: install-refusal trio. Emitted unconditionally (cumulative
	// CounterValue) so a 0 is a real "no refusals" signal rather than an
	// absent series.
	ch <- prometheus.MustNewConstMetric(
		c.userspaceSessionCreateDrops,
		prometheus.CounterValue,
		float64(status.SessionCreateDrops),
	)
	ch <- prometheus.MustNewConstMetric(
		c.userspaceSessionInstallAdmissionRefused,
		prometheus.CounterValue,
		float64(status.SessionInstallAdmissionRefused),
	)
	ch <- prometheus.MustNewConstMetric(
		c.userspaceSessionInstallPartial,
		prometheus.CounterValue,
		float64(status.SessionInstallPartial),
	)

	// #1789: failed USERSPACE_SESSIONS BPF-map publishes. Also emitted
	// unconditionally so a 0 is a real "no publish failures" signal
	// rather than an absent series.
	ch <- prometheus.MustNewConstMetric(
		c.userspaceSessionPublishErrors,
		prometheus.CounterValue,
		float64(status.SessionPublishErrorsTotal),
	)
	// #10021: established-session revocations are a standalone session
	// signal, not part of the packet-counted "Packets dropped" total.
	ch <- prometheus.MustNewConstMetric(
		c.userspacePolicyRevokedSessions,
		prometheus.CounterValue,
		float64(status.PolicyRevokedSessionsTotal),
	)
	// #4800: the publish + replication legs of the new-flow-install
	// contention surface. Emitted unconditionally and always as complete
	// (denominator, contended) pairs — a missing series would be
	// indistinguishable from a scrape failure, and a contended series
	// without its denominator is not interpretable at all.
	ch <- prometheus.MustNewConstMetric(
		c.userspaceSharedSessionPublishes,
		prometheus.CounterValue,
		float64(status.SharedSessionPublishesTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.userspaceSharedSessionPublishLockAcquired,
		prometheus.CounterValue,
		float64(status.SharedSessionPublishLockAcquisitionsTotal),
	)
	// #9169: site 4. Emitted here rather than beside the other event-stream
	// series because it belongs to the #4800 contention surface, and that
	// surface's rule is that every (denominator, contended) pair is emitted
	// unconditionally and together — a contended series without its
	// denominator is not interpretable, and a missing series is
	// indistinguishable from a scrape failure.
	ch <- prometheus.MustNewConstMetric(
		c.userspaceEventStreamProducerSeqLockAcquired,
		prometheus.CounterValue,
		float64(status.EventStreamProducerSeqLockAcquisitionsTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.userspaceEventStreamProducerSeqLockBlocked,
		prometheus.CounterValue,
		float64(status.EventStreamProducerSeqLockContendedTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.userspaceSharedSessionPublishLockBlocked,
		prometheus.CounterValue,
		float64(status.SharedSessionPublishLockContendedTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.userspaceSessionReplicationUpserts,
		prometheus.CounterValue,
		float64(status.SessionReplicationUpsertsTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.userspaceSessionReplicationEnqueued,
		prometheus.CounterValue,
		float64(status.SessionReplicationEnqueuedTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.userspaceSessionReplicationLockBlocked,
		prometheus.CounterValue,
		float64(status.SessionReplicationLockContendedTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.userspaceSessionReplicationQueueDepthSum,
		prometheus.CounterValue,
		float64(status.SessionReplicationQueueDepthSum),
	)
	ch <- prometheus.MustNewConstMetric(
		c.userspaceSessionReplicationQueueDepthMax,
		prometheus.GaugeValue,
		float64(status.SessionReplicationQueueDepthMax),
	)

	// #2244: failed dnat_table reverse-SNAT BPF-map publishes. Also
	// emitted unconditionally so a 0 is a real "no reverse-NAT publish
	// failures" signal rather than an absent series.
	ch <- prometheus.MustNewConstMetric(
		c.userspaceDnatPublishErrors,
		prometheus.CounterValue,
		float64(status.DnatPublishErrorsTotal),
	)

	// #5674: peer-synced session imports rejected by the coordinator's
	// aggregate admission bound. Also emitted unconditionally so a 0 is a real
	// "no over-ceiling synced imports rejected" signal rather than an absent
	// series.
	ch <- prometheus.MustNewConstMetric(
		c.userspaceSyncedImportCapDrops,
		prometheus.CounterValue,
		float64(status.SyncedImportCapDropsTotal),
	)

	// #1760 W3': shared-map NAT reverse-key displacement events. Emitted
	// unconditionally so a 0 is a real "no collisions" signal rather
	// than an absent series.
	ch <- prometheus.MustNewConstMetric(
		c.userspaceNatReverseKeySharedDisplacements,
		prometheus.CounterValue,
		float64(status.NatReverseKeySharedDisplacementsTotal),
	)

	// #6751 PR 2/3: interface-mode SNAT identity registry. Emitted
	// unconditionally: a published 0 is the informative reading (no two
	// flows contended, nothing failed closed), not an absent series.
	ch <- prometheus.MustNewConstMetric(
		c.userspaceInterfaceSNATPATCollisions,
		prometheus.CounterValue,
		float64(status.InterfaceSNATPATCollisionsTotal),
	)
	// #7056: emitted unconditionally like the sibling above — a published 0 is
	// the informative reading (no alias was ever refused), not an absent series.
	ch <- prometheus.MustNewConstMetric(
		c.userspaceNAT64FragCrossDomainMisses,
		prometheus.CounterValue,
		float64(status.NAT64FragCrossDomainMissesTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.userspaceNAT64FragProtocolAliasMisses,
		prometheus.CounterValue,
		float64(status.NAT64FragProtocolAliasMissesTotal),
	)
	// #9901: packet-identity counters, emitted unconditionally like the
	// #7056 siblings above — a published 0 is the informative reading.
	ch <- prometheus.MustNewConstMetric(
		c.userspaceFragMaxLifetimeEvictions,
		prometheus.CounterValue,
		float64(status.FragMaxLifetimeEvictionsTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.userspaceEgressMTUUnknownForward,
		prometheus.CounterValue,
		float64(status.EgressMTUUnknownForwardTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.userspaceEmbeddedQuoteSubminimalRefused,
		prometheus.CounterValue,
		float64(status.EmbeddedQuoteSubminimalRefusedTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.userspaceEmbeddedErrorPerSessionSuppressed,
		prometheus.CounterValue,
		float64(status.EmbeddedErrorPerSessionSuppressedTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.userspaceInterfaceSNATIdentityExhaustion,
		prometheus.CounterValue,
		float64(status.InterfaceSNATIdentityExhaustionTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.userspaceInterfaceSNATSyncConflictDrops,
		prometheus.CounterValue,
		float64(status.InterfaceSNATSyncIdentityConflictDropsTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.userspaceInterfaceSNATRegistryCap,
		prometheus.CounterValue,
		float64(status.InterfaceSNATRegistryCapExhaustionTotal),
	)

	// #1807: worker-command-queue poison recoveries. Also emitted
	// unconditionally so a 0 is a real "no worker panics" signal rather
	// than an absent series.
	ch <- prometheus.MustNewConstMetric(
		c.userspaceWorkerCommandQueuePoisonRecoveries,
		prometheus.CounterValue,
		float64(status.WorkerCommandQueuePoisonRecoveries),
	)

	// #6929: per-worker command-queue capacity drops. Emitted
	// unconditionally for the same reason as its #1807 neighbour: 0 is the
	// expected value and a real signal, so an absent series would be
	// indistinguishable from a helper that never reports.
	ch <- prometheus.MustNewConstMetric(
		c.userspaceWorkerCommandQueueDrops,
		prometheus.CounterValue,
		float64(status.WorkerCommandQueueDrops),
	)

	// #2402/#6641: shared-session poison recoveries. Emitted
	// unconditionally for the same reason as its #1807 twin above: a 0 is
	// a real "no worker panic touched HA session state" signal, and an
	// absent series would be indistinguishable from a helper that never
	// reports.
	ch <- prometheus.MustNewConstMetric(
		c.userspaceSharedSessionPoisonRecoveries,
		prometheus.CounterValue,
		float64(status.SharedSessionPoisonRecoveries),
	)

	// #9900: frame-ownership violation counters, emitted unconditionally
	// like their neighbours — 0 is the expected healthy value and a real
	// signal for each.
	ch <- prometheus.MustNewConstMetric(
		c.userspaceTxCompletionSkew,
		prometheus.CounterValue,
		float64(status.TxCompletionSkew),
	)
	ch <- prometheus.MustNewConstMetric(
		c.userspaceTxCompletionInvalid,
		prometheus.CounterValue,
		float64(status.TxCompletionInvalid),
	)
	ch <- prometheus.MustNewConstMetric(
		c.userspaceTxCompletionDuplicate,
		prometheus.CounterValue,
		float64(status.TxCompletionDuplicate),
	)
	ch <- prometheus.MustNewConstMetric(
		c.userspaceFillInvalid,
		prometheus.CounterValue,
		float64(status.FillInvalid),
	)
	ch <- prometheus.MustNewConstMetric(
		c.userspaceWorkerCommandQueueShed,
		prometheus.CounterValue,
		float64(status.WorkerCommandQueueShed),
	)
	ch <- prometheus.MustNewConstMetric(
		c.userspaceServerStatePoisonRecoveries,
		prometheus.CounterValue,
		float64(status.ServerStatePoisonRecoveries),
	)
	ch <- prometheus.MustNewConstMetric(
		c.userspaceServerHandlerPanics,
		prometheus.CounterValue,
		float64(status.ServerHandlerPanics),
	)

	// #7398: emitted unconditionally like their neighbours. A 0 here is a real
	// "no stale install/delete was refused, no import lost its reservation"
	// signal; an absent series would be indistinguishable from a helper that
	// never reports, which is the state these three were in before #7398.
	ch <- prometheus.MustNewConstMetric(
		c.userspaceSessionInstallStaleIgnored,
		prometheus.CounterValue,
		float64(status.SessionInstallStaleIgnored),
	)
	ch <- prometheus.MustNewConstMetric(
		c.userspaceSessionDeleteStaleIgnored,
		prometheus.CounterValue,
		float64(status.SessionDeleteStaleIgnored),
	)
	ch <- prometheus.MustNewConstMetric(
		c.userspaceSyncedImportReserveRefused,
		prometheus.CounterValue,
		float64(status.SyncedImportReserveRefused),
	)
	// #7160: emitted unconditionally like its neighbours — a 0 is the real
	// "every synced import resolved its routing domain" signal, and an absent
	// series is indistinguishable from a helper that never reports.
	ch <- prometheus.MustNewConstMetric(
		c.userspaceSyncedImportUnknownRoutingDomain,
		prometheus.CounterValue,
		float64(status.SyncedImportUnknownRoutingDomain),
	)
	// #10512: emitted unconditionally like their neighbours. All three are
	// lifetime-monotonic (count, summed holds, max hold), so CounterValue is
	// exact, not approximate.
	ch <- prometheus.MustNewConstMetric(
		c.userspacePolicyBatchCount,
		prometheus.CounterValue,
		float64(status.PolicyBatchCount),
	)
	ch <- prometheus.MustNewConstMetric(
		c.userspacePolicyBatchHoldNs,
		prometheus.CounterValue,
		float64(status.PolicyBatchHoldNs),
	)
	ch <- prometheus.MustNewConstMetric(
		c.userspacePolicyBatchHoldMaxNs,
		prometheus.GaugeValue,
		float64(status.PolicyBatchHoldMaxNs),
	)

	// #7209: peer-synced imports that skipped #6211's zone narrowing.
	// Emitted unconditionally, for the same reason as its neighbours: a 0
	// is a real "every synced import resolved its zones" signal, and an
	// absent series is indistinguishable from a helper that never reports.
	ch <- prometheus.MustNewConstMetric(
		c.userspaceSyncedImportZoneUnresolved,
		prometheus.CounterValue,
		float64(status.SyncedImportZoneUnresolved),
	)

	// #7209: imports admitted by the local-replace guard with no kernel
	// session map to publish into. Emitted unconditionally like its
	// neighbours: a 0 is the real "every admitted import reached the map"
	// signal, and an absent series cannot be told from a helper that never
	// reports it.
	ch <- prometheus.MustNewConstMetric(
		c.userspaceSyncedImportUnpublished,
		prometheus.CounterValue,
		float64(status.SyncedImportUnpublished),
	)

	// #2315: GRE-decap RFC 6040 4.2 illegal-combination drops (outer CE
	// over a Not-ECT inner). Emitted unconditionally so a 0 is a real
	// "no illegal combinations seen" signal rather than an absent series.
	ch <- prometheus.MustNewConstMetric(
		c.userspaceGreDecapEcnIllegalDrops,
		prometheus.CounterValue,
		float64(status.GreDecapEcnIllegalDropsTotal),
	)

	// #2317: WG-decap RFC 6040 4.2 illegal-combination drops (outer CE,
	// recvmsg-captured, over a Not-ECT inner). Emitted unconditionally so
	// a 0 is a real "no illegal combinations seen" signal rather than an
	// absent series.
	ch <- prometheus.MustNewConstMetric(
		c.userspaceWgDecapEcnIllegalDrops,
		prometheus.CounterValue,
		float64(status.WgDecapEcnIllegalDropsTotal),
	)

	// #2331: native-GRE encap DF-set oversized-outer drops. Emitted
	// unconditionally so a 0 is a real "no oversized DF outers refused"
	// signal rather than an absent series. Nonzero flags inner flows whose
	// encapped size exceeds the tunnel path MTU.
	ch <- prometheus.MustNewConstMetric(
		c.userspaceGreEncapDfOversizeDrops,
		prometheus.CounterValue,
		float64(status.GreEncapDfOversizeDropsTotal),
	)

	// #2782: native-GRE decap checksum-invalid drops (C bit set but the
	// GRE checksum failed to verify, or the header was truncated past the
	// Checksum+Reserved1 field). Emitted unconditionally so a 0 is a real
	// "no corrupt checksummed GRE frames seen" signal rather than an
	// absent series. Nonzero flags a checksummed GRE peer delivering
	// corrupt frames / a truncated GRE header.
	ch <- prometheus.MustNewConstMetric(
		c.userspaceGreDecapChecksumInvalidDrops,
		prometheus.CounterValue,
		float64(status.GreDecapChecksumInvalidDropsTotal),
	)

	// #6842: native-GRE decap refusals for a non-zero GRE version (RFC 2637
	// / PPTP enhanced GRE is version 1) where the outer tuple named a
	// configured GRE endpoint. Emitted unconditionally so a 0 is a real "no
	// PPTP offered to a GRE endpoint" signal rather than an absent series.
	// Nonzero flags a peer offering PPTP to a tunnel xpf cannot terminate.
	ch <- prometheus.MustNewConstMetric(
		c.userspaceGreDecapUnsupportedVersionRefusals,
		prometheus.CounterValue,
		float64(status.GreDecapUnsupportedVersionRefusalsTotal),
	)

	// #2472: locally-generated error-reply per-reason token-bucket drops.
	// Emitted unconditionally so a 0 is a real "no generated errors
	// rate-limited" signal rather than an absent series. Nonzero flags an
	// error-amplification / reflection flood (or a routing loop) being
	// clamped.
	ch <- prometheus.MustNewConstMetric(
		c.userspaceTimeExceededRateLimited,
		prometheus.CounterValue,
		float64(status.TimeExceededRateLimitedTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.userspacePacketTooBigRateLimited,
		prometheus.CounterValue,
		float64(status.PacketTooBigRateLimitedTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.userspaceRejectRateLimited,
		prometheus.CounterValue,
		float64(status.RejectRateLimitedTotal),
	)

	var activeFlows, flowCapacity uint64
	for _, b := range status.Bindings {
		activeFlows += uint64(b.ActiveFlowCount)
		flowCapacity += uint64(b.FlowCacheCapacity)
		if b.FlowCacheCapacity == 0 {
			continue
		}
		ch <- prometheus.MustNewConstMetric(
			c.bindingFlowCacheCapacity,
			prometheus.GaugeValue,
			float64(b.FlowCacheCapacity),
			strconv.FormatUint(uint64(b.Slot), 10),
			strconv.FormatUint(uint64(b.QueueID), 10),
			strconv.FormatUint(uint64(b.WorkerID), 10),
			b.Interface,
		)
	}
	if flowCapacity == 0 {
		flowCapacity = status.FlowCacheCapacity
	}
	if flowCapacity > 0 {
		ch <- prometheus.MustNewConstMetric(
			c.userspaceFlowCacheActiveFlows,
			prometheus.GaugeValue,
			float64(activeFlows),
		)
		ch <- prometheus.MustNewConstMetric(
			c.userspaceFlowCacheCapacity,
			prometheus.GaugeValue,
			float64(flowCapacity),
		)
	}
}
