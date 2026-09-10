package api

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// fetchUserspaceStatus performs the SINGLE per-scrape userspace-dp control-
// socket Status() round trip whose result is shared by every collector that
// consumes it (collectFilterCounters + collectUserspaceStatus). #5317: before
// this each of those collectors issued its own Status() request, so one
// /metrics scrape did two serialized `status` RPCs on the control socket —
// doubling contention with session installs during bulk sync (CLAUDE.md
// "Control socket contention"). Fetching once also gives both metric families a
// COHERENT snapshot instead of two A/B-skewed reads.
//
// Returns nil when the dataplane does not expose a Status() surface OR the
// round trip failed. Both collectors degrade to their prior no-status behavior
// on nil — collectFilterCounters skips the userspace merge (empty term index,
// map path unaffected), collectUserspaceStatus emits nothing — identical to when
// each fetched Status() itself.
func fetchUserspaceStatus(dp apiRuntimeDataPlane) *dpuserspace.ProcessStatus {
	// #2114/#6743-F1: probe the PUBLISHED BACKEND, not the daemon's live
	// indirection — the indirection declares only apiRuntimeDataPlane, so
	// asserting Status() on it returns !ok for a healthy userspace helper
	// and suppresses every userspace metric family. Unwrap is the identity
	// for a plain backend, nil once the daemon has disowned one.
	provider, ok := dataplane.Unwrap(dp).(interface {
		Status() (dpuserspace.ProcessStatus, error)
	})
	if !ok {
		return nil
	}
	status, err := provider.Status()
	if err != nil {
		return nil
	}
	return &status
}

// #709 + #869: single Status() call per scrape, then dispatch to
// CoS owner profile + worker runtime collectors.  Both features need
// the same ProcessStatus; calling Status() twice per scrape is
// wasteful on the userspace-dp control socket. #5317: the round trip is
// now performed ONCE by Collect (via fetchUserspaceStatus) and the snapshot
// passed in here, shared with collectFilterCounters — a nil pointer means the
// helper exposes no Status() surface or the single round trip failed, so this
// collector emits nothing (the prior status-error behavior).
func (c *xpfCollector) collectUserspaceStatus(ch chan<- prometheus.Metric, statusPtr *dpuserspace.ProcessStatus) {
	if statusPtr == nil {
		return
	}
	status := *statusPtr
	c.emitCoSOwnerProfile(ch, status)
	c.emitCoSDrainPhaseTelemetry(ch, status)
	c.emitCoSParkReasonTelemetry(ch, status)
	c.emitCoSWaterfillTelemetry(ch, status)
	c.emitCoSLeaseClaimFlow(ch, status)
	c.emitCoSEqualFlowEnforcement(ch, status)
	c.emitCoSSojourn(ch, status)
	c.emitCoSFlowFairOccupancy(ch, status)
	c.emitWorkerRuntime(ch, status)
	c.emitUserspaceDynamicBufferMetrics(ch, status)
	c.emitUserspaceEventStream(ch, status)
	c.emitBindingActiveFlowCount(ch, status)
	c.emitBindingTXCompletionTelemetry(ch, status)
	c.emitBindingVMinThrottleCounters(ch, status)
	c.emitBindingSlowPathReinjectCounters(ch, status)
	c.emitCoSActiveFlowCount(ch, status)
	c.emitThreeColorPolicerCounters(ch, status)
	c.emitUserspaceSourceNATPoolMetrics(ch, status)
	c.emitFairnessRSSGauges(ch, status)
	c.emitFairnessThroughputGauges(ch, status)
	c.emitNeighborWarmCounters(ch, status)
	c.emitNeighborColdStartCapture(ch, status)
	c.emitWireguardTelemetry(ch, status)
	c.emitPolicyContentRejected(ch, status)
	c.emitZoneIDCollision(ch, status)
	c.emitRejectObservability(ch, status)
	c.emitFabricSkipCounters(ch, status)
	c.emitDropClassCounters(ch, status)
}

// emitDropClassCounters exposes the #4743 per-binding drop-class counters as
// aggregate Prometheus series (#4768): martian-destination NoRoute drops and
// over-limit IPv6 extension-header fail-closed drops, each summed across
// bindings. #4766 already surfaces these as "Martian drops:" / "IPv6 ext-header
// drops:" status rows; this adds the scrape surface. Both are emitted
// unconditionally so a 0 is a real "no such drops" signal, not an absent
// series (matching the reject-observability convention above). martian_dropped
// is a sub-breakout of route_miss_packets (every martian drop also bumps the
// route miss), so the martian series is always <= the route-miss volume.
func (c *xpfCollector) emitDropClassCounters(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	var martian, ipv6ExtHeader uint64
	for _, b := range status.Bindings {
		martian += b.MartianDropped
		ipv6ExtHeader += b.IPv6ExtHeaderDropped
	}
	ch <- prometheus.MustNewConstMetric(c.userspaceMartianDropped, prometheus.CounterValue, float64(martian))
	ch <- prometheus.MustNewConstMetric(c.userspaceIPv6ExtHeaderDropped, prometheus.CounterValue, float64(ipv6ExtHeader))
}

// emitFabricSkipCounters exposes the #3773 (M13) fabric-link skip
// diagnostics: a fabric link dropped during a forwarding build/refresh for a
// MALFORMED value (invalid parent ifindex / unparseable peer address /
// non-empty unparseable local|peer MAC) vs an UNRESOLVED peer/local MAC (empty
// MAC awaiting neighbor/interface resolution — the expected SyncFabricState
// transient). Both emitted unconditionally so a 0 is a real "no fabric
// skipped" signal rather than an absent series.
func (c *xpfCollector) emitFabricSkipCounters(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	ch <- prometheus.MustNewConstMetric(
		c.fabricLinkSkippedMalformedTotal,
		prometheus.CounterValue,
		float64(status.FabricLinkSkippedMalformedTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.fabricLinkUnresolvedPeerTotal,
		prometheus.CounterValue,
		float64(status.FabricLinkUnresolvedPeerTotal),
	)
}

// emitRejectObservability exposes the #3657 source-split reject reply
// telemetry: sent, TX-frame reply-budget drops, egress output-filter drops,
// and (#3661) rate-limit drops, each labeled source=policy|filter. These
// per-BindingStatus counters (wired by #3615/#3661) are summed across
// bindings. The aggregate xpf_userspace_reject_rate_limited_total is emitted
// elsewhere and stays for back-compat; #3661 splits the rate-limit drop leg
// by source at the helper consume site (both sources still share the one
// global-per-reason bucket, so policy+filter sum to the aggregate). All eight
// series are emitted unconditionally so a 0 is a real "no reject activity"
// signal (alerting can distinguish policy-reject from filter-reject
// starvation, and success from suppression).
func (c *xpfCollector) emitRejectObservability(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	var policySent, filterSent uint64
	var policyBudget, filterBudget uint64
	var policyOutputFilter, filterOutputFilter uint64
	var policyRateLimit, filterRateLimit uint64
	for _, b := range status.Bindings {
		policySent += b.PolicyRejectSent
		filterSent += b.FilterRejectSent
		policyBudget += b.PolicyRejectReplyBudgetDrops
		filterBudget += b.FilterRejectReplyBudgetDrops
		policyOutputFilter += b.PolicyRejectOutputFilterDrops
		filterOutputFilter += b.FilterRejectOutputFilterDrops
		policyRateLimit += b.PolicyRejectRateLimitDrops
		filterRateLimit += b.FilterRejectRateLimitDrops
	}
	emit := func(desc *prometheus.Desc, policy, filter uint64) {
		ch <- prometheus.MustNewConstMetric(desc, prometheus.CounterValue, float64(policy), "policy")
		ch <- prometheus.MustNewConstMetric(desc, prometheus.CounterValue, float64(filter), "filter")
	}
	emit(c.userspaceRejectSent, policySent, filterSent)
	emit(c.userspaceRejectReplyBudgetDrops, policyBudget, filterBudget)
	emit(c.userspaceRejectOutputFilterDrops, policyOutputFilter, filterOutputFilter)
	emit(c.userspaceRejectRateLimitedBySource, policyRateLimit, filterRateLimit)
}

// emitPolicyContentRejected exposes the #3261 0/1 gauge: 1 while the last
// userspace snapshot build carried unrepresentable policy content the helper
// integrity preflight rejects (previous-good retained / fresh-boot
// default-deny — never fail-open). Emitted unconditionally so 0 is a real
// "representable" signal, not an absent series.
func (c *xpfCollector) emitPolicyContentRejected(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	v := 0.0
	if len(status.LastSnapshotRejectReasons) > 0 {
		v = 1.0
	}
	ch <- prometheus.MustNewConstMetric(c.userspacePolicyContentRejected, prometheus.GaugeValue, v)
}

// emitZoneIDCollision exposes the #3719 0/1 gauge: 1 while the last userspace
// snapshot build quarantined one or more security zones whose StableZoneID
// collided (lenient / HA-sync / pre-#3075-persisted path). The dataplane is
// fail-closed (the later-sorting zone is dropped, never merged), but zone
// isolation is degraded until one zone is renamed. Emitted unconditionally so 0
// is a real "all zones distinct" signal, not an absent series.
func (c *xpfCollector) emitZoneIDCollision(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	v := 0.0
	if len(status.ZoneIDCollisions) > 0 {
		v = 1.0
	}
	ch <- prometheus.MustNewConstMetric(c.userspaceZoneIDCollision, prometheus.GaugeValue, v)
}

// emitWireguardTelemetry exposes the #1865 per-WG-tunnel telemetry
// rows. Every counter series is emitted unconditionally per configured
// tunnel — a 0 is a real "no drops" signal, not an absent series
// (matching the #1771 §2.6 convention) — EXCEPT the last-handshake
// gauge, which is absent until the first handshake completes (0 is the
// in-band "never" sentinel on the wire). The tunnel label is the
// tunnel NAME: stable across commits, unlike the positional
// tunnel_endpoint_id (#1873).
func (c *xpfCollector) emitWireguardTelemetry(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	for _, t := range status.WgTunnels {
		counter := func(desc *prometheus.Desc, v uint64, labels ...string) {
			ch <- prometheus.MustNewConstMetric(
				desc, prometheus.CounterValue, float64(v), labels...)
		}
		// Completions by role: role=responder is the helper's
		// hs_responses_created (the single responder-completion
		// increment site — session installed at msg2 creation).
		counter(c.wgHandshakesCompletedTotal, t.HsCompletionsInitiator, t.Tunnel, "initiator")
		counter(c.wgHandshakesCompletedTotal, t.HsResponsesCreated, t.Tunnel, "responder")
		counter(c.wgHandshakeInitiationsCreatedTotal, t.HsInitiationsCreated, t.Tunnel)
		counter(c.wgHandshakeInitiationBuildFailuresTotal, t.HsInitiationBuildFailures, t.Tunnel)
		counter(c.wgHandshakeRequestsArmedTotal, t.HsRequestsArmed, t.Tunnel)

		for _, r := range []struct {
			reason string
			v      uint64
		}{
			{"mac1_mismatch", t.HsRxDropsMac1Mismatch},
			{"malformed", t.HsRxDropsMalformed},
			{"crypto", t.HsRxDropsCrypto},
			{"unknown_peer", t.HsRxDropsUnknownPeer},
			{"stale_response", t.HsRxDropsStaleResponse},
			{"index_exhausted", t.HsRxDropsIndexExhausted},
			{"replayed_init", t.HsRxDropsReplayedInit},
			{"cookie_unsupported", t.HsRxCookieUnsupported},
			// #4094 PR-A responder under-load cookie gate drops.
			{"under_load_no_mac2", t.HsRxUnderLoadNoMac2},
			{"cookie_reply_budget", t.HsCookieReplyBudgetDrops},
			{"unknown_type", t.RxUnknownType},
		} {
			counter(c.wgHandshakeRxDropsTotal, r.v, t.Tunnel, r.reason)
		}

		// #4094 PR-A responder cookie mechanism working signals: challenges
		// issued and primed peers that completed under load. #4094 PR-B adds
		// the initiator half — cookie-replies we consumed to arm a valid
		// MAC2 on our next initiation.
		counter(c.wgCookieRepliesTotal, t.HsCookieRepliesSent, t.Tunnel, "sent")
		counter(c.wgCookieRepliesTotal, t.HsRxUnderLoadMac2Ok, t.Tunnel, "mac2_ok")
		counter(c.wgCookieRepliesTotal, t.HsRxCookieConsumed, t.Tunnel, "consumed")

		counter(c.wgTransportPacketsTotal, t.EncapPackets, t.Tunnel, "encap")
		counter(c.wgTransportPacketsTotal, t.DecapPackets, t.Tunnel, "decap")
		counter(c.wgTransportBytesTotal, t.EncapBytes, t.Tunnel, "encap")
		counter(c.wgTransportBytesTotal, t.DecapBytes, t.Tunnel, "decap")
		counter(c.wgKeepalivesReceivedTotal, t.DecapKeepalives, t.Tunnel)

		for _, r := range []struct {
			reason string
			v      uint64
		}{
			{"malformed_header", t.DecapDropsMalformedHeader},
			{"unknown_session", t.DecapDropsUnknownSession},
			{"counter_ceiling", t.DecapDropsCounterCeiling},
			{"crypto", t.DecapDropsCrypto},
			{"replay", t.DecapDropsReplay},
			{"allowed_ips", t.DecapDropsAllowedIPs},
			{"malformed_inner", t.DecapDropsMalformedInner},
			{"buffer", t.DecapDropsBuffer},
			{"unsteered_port", t.RxUnsteeredTransportDrops},
			{"expired", t.DecapDropsExpired},
		} {
			counter(c.wgTransportDropsTotal, r.v, t.Tunnel, "decap", r.reason)
		}
		for _, r := range []struct {
			reason string
			v      uint64
		}{
			{"no_session", t.EncapDropsNoSession},
			{"unconfirmed", t.EncapDropsUnconfirmed},
			{"rekey_required", t.EncapDropsRekeyRequired},
			{"mtu", t.EncapMtuDrops},
			{"other", t.EncapDropsOther},
			{"expired", t.EncapDropsExpired},
		} {
			counter(c.wgTransportDropsTotal, r.v, t.Tunnel, "encap", r.reason)
		}

		for _, k := range []struct {
			kind string
			v    uint64
		}{
			{"handshake", t.HsSendErrors},
			{"transport", t.TransportSendErrors},
			{"tun_write", t.TunWriteErrors},
			{"tun_rx_no_endpoint", t.TunRxDropsNoEndpoint},
		} {
			counter(c.wgSendErrorsTotal, k.v, t.Tunnel, k.kind)
		}

		// #1888 S5 timer telemetry.
		counter(c.wgRekeysInitiatedTotal, t.RekeysInitiatedAge, t.Tunnel, "age")
		counter(c.wgRekeysInitiatedTotal, t.RekeysInitiatedDeadPeer, t.Tunnel, "dead_peer")
		counter(c.wgRekeysInitiatedTotal, t.RekeysInitiatedKeepaliveNoSession, t.Tunnel, "keepalive_no_session")
		counter(c.wgKeepalivesSentTotal, t.KeepalivesTxPassive, t.Tunnel, "passive")
		counter(c.wgKeepalivesSentTotal, t.KeepalivesTxPersistent, t.Tunnel, "persistent")
		counter(c.wgSessionsExpiredTotal, t.SessionsExpired, t.Tunnel)
		counter(c.wgHandshakeAttemptsAbortedTotal, t.PendingAbortedAttemptWindow, t.Tunnel)
		// #7936 endpoint resolver. Emitted for every WG tunnel, including one
		// with no DNS endpoints at all: a tunnel of IP literals starts no
		// resolver and reports zeros, and a zero series is the honest answer —
		// suppressing it would make "no resolver" and "resolver never ran"
		// indistinguishable from the absence of the metric.
		counter(c.wgEndpointResolutionsTotal, t.EndpointResolveOk, t.Tunnel, "ok")
		counter(c.wgEndpointResolutionsTotal, t.EndpointResolveFail, t.Tunnel, "fail")
		counter(c.wgEndpointResolutionsTotal, t.EndpointFamilyMismatch, t.Tunnel, "family_mismatch")
		counter(c.wgEndpointResolutionsTotal, t.EndpointChanged, t.Tunnel, "changed")

		// #1434 multi-peer: one confirmed-session gauge per peer,
		// labeled by tunnel + peer pubkey.
		for _, p := range t.Peers {
			confirmed := 0.0
			if p.SessionConfirmed {
				confirmed = 1.0
			}
			ch <- prometheus.MustNewConstMetric(
				c.wgSessionConfirmed, prometheus.GaugeValue, confirmed, t.Tunnel, p.PeerPubkeyHex)
		}
		if t.LastHandshakeUnixSecs > 0 {
			ch <- prometheus.MustNewConstMetric(
				c.wgLastHandshakeTimeSeconds,
				prometheus.GaugeValue,
				float64(t.LastHandshakeUnixSecs),
				t.Tunnel,
			)
		}
	}
}

func (c *xpfCollector) emitThreeColorPolicerCounters(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	for _, p := range status.ThreeColorPolicerCounters {
		emitColor := func(color string, packets, bytes uint64) {
			ch <- prometheus.MustNewConstMetric(
				c.threeColorPolicerPacketsTotal,
				prometheus.CounterValue,
				float64(packets),
				p.Name,
				color,
			)
			ch <- prometheus.MustNewConstMetric(
				c.threeColorPolicerBytesTotal,
				prometheus.CounterValue,
				float64(bytes),
				p.Name,
				color,
			)
		}
		emitColor("green", p.GreenPackets, p.GreenBytes)
		emitColor("yellow", p.YellowPackets, p.YellowBytes)
		emitColor("red", p.RedPackets, p.RedBytes)
		ch <- prometheus.MustNewConstMetric(
			c.threeColorPolicerDropsTotal,
			prometheus.CounterValue,
			float64(p.DropPackets),
			p.Name,
		)
		ch <- prometheus.MustNewConstMetric(
			c.threeColorPolicerDropBytes,
			prometheus.CounterValue,
			float64(p.DropBytes),
			p.Name,
		)
	}
}

func (c *xpfCollector) emitUserspaceSourceNATPoolMetrics(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	for _, pool := range status.SourceNATPools {
		labels := []string{pool.PoolName, pool.RuleName}
		ch <- prometheus.MustNewConstMetric(
			c.userspaceSNATPoolLiveFlows,
			prometheus.GaugeValue,
			float64(pool.LiveFlows),
			labels...,
		)
		ch <- prometheus.MustNewConstMetric(
			c.userspaceSNATPoolUsedPorts,
			prometheus.GaugeValue,
			float64(pool.UsedPorts),
			labels...,
		)
		ch <- prometheus.MustNewConstMetric(
			c.userspaceSNATPoolPersistentLeases,
			prometheus.GaugeValue,
			float64(pool.PersistentLeases),
			labels...,
		)
		ch <- prometheus.MustNewConstMetric(
			c.userspaceSNATPoolAllocationsTotal,
			prometheus.CounterValue,
			float64(pool.AllocationsTotal),
			labels...,
		)
		ch <- prometheus.MustNewConstMetric(
			c.userspaceSNATPoolReusesTotal,
			prometheus.CounterValue,
			float64(pool.ReusesTotal),
			labels...,
		)
		ch <- prometheus.MustNewConstMetric(
			c.userspaceSNATPoolPersistentAdmittedTotal,
			prometheus.CounterValue,
			float64(pool.PersistentAdmittedTotal),
			labels...,
		)
		ch <- prometheus.MustNewConstMetric(
			c.userspaceSNATPoolPersistentDeclinedTotal,
			prometheus.CounterValue,
			float64(pool.PersistentDeclinedTotal),
			labels...,
		)
		ch <- prometheus.MustNewConstMetric(
			c.userspaceSNATPoolExhaustionsTotal,
			prometheus.CounterValue,
			float64(pool.ExhaustionTotal),
			labels...,
		)
		// #4800: the (denominator, contended) pair for this pool's residual
		// live-state mutex. Emitted unconditionally so the connection-rate
		// harness sees an explicit 0 from a pool that never contended,
		// rather than a missing series it would have to disambiguate from a
		// scrape failure.
		ch <- prometheus.MustNewConstMetric(
			c.userspaceSNATPoolLiveLockAcquisitionsTotal,
			prometheus.CounterValue,
			float64(pool.LiveLockAcquisitionsTotal),
			labels...,
		)
		ch <- prometheus.MustNewConstMetric(
			c.userspaceSNATPoolLiveLockContendedTotal,
			prometheus.CounterValue,
			float64(pool.LiveLockContendedTotal),
			labels...,
		)
	}
}

func (c *xpfCollector) emitUserspaceEventStream(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	if status.EventStream == nil {
		return
	}
	es := status.EventStream
	ch <- prometheus.MustNewConstMetric(c.userspaceEventStreamFramesTotal,
		prometheus.CounterValue, float64(es.FramesRead), "read")
	ch <- prometheus.MustNewConstMetric(c.userspaceEventStreamFramesTotal,
		prometheus.CounterValue, float64(es.FramesWritten), "written")
	ch <- prometheus.MustNewConstMetric(c.userspaceEventStreamProducerFramesTotal,
		prometheus.CounterValue, float64(status.EventStreamSent), "sent")
	ch <- prometheus.MustNewConstMetric(c.userspaceEventStreamProducerFramesTotal,
		prometheus.CounterValue, float64(status.EventStreamDropped), "dropped")
	// #2381: I/O cycles in which the helper hit the write-backlog cap and
	// stopped draining the bounded channel (stalled daemon reader). Surfaced
	// under the producer metric with a distinct "write_stalled" label so a
	// wedged consumer is observable instead of silently OOMing the helper.
	ch <- prometheus.MustNewConstMetric(c.userspaceEventStreamProducerFramesTotal,
		prometheus.CounterValue, float64(status.EventStreamWriteStalls), "write_stalled")
	// #2382: accepted RT_FLOW / dataplane-telemetry frames evicted from the
	// helper's replay buffer when it wrapped at capacity before the daemon
	// ACKed them. These were counted under the "sent" label at enqueue but are
	// permanently lost — a real telemetry-loss signal. Surfaced under the
	// producer metric with a distinct "replay_evicted" label so the loss is
	// observable (it is NOT ACK-trim, which is normal acknowledged removal).
	ch <- prometheus.MustNewConstMetric(c.userspaceEventStreamProducerFramesTotal,
		prometheus.CounterValue, float64(status.EventStreamReplayEvictions), "replay_evicted")
	// #2959: MSG_ACK control frames rejected because the daemon ACKed a
	// sequence outside the valid [acked_seq, next_seq] window (a backward or
	// future ACK from a buggy/mixed-version/corrupted listener). The helper
	// fails closed and ignores them; surfaced under the producer metric with a
	// distinct "invalid_ack" label so an impossible-ACK peer is observable.
	ch <- prometheus.MustNewConstMetric(c.userspaceEventStreamProducerFramesTotal,
		prometheus.CounterValue, float64(status.EventStreamInvalidAcks), "invalid_ack")
	// #2512: per-kind producer accounting for the RT_FLOW SESSION_CLOSE
	// (type 14) and SESSION_CREATE (type 15) frames, which now ride the same
	// helper-side rate limiter + queue budget as deny/screen/filter instead of
	// a bare unaccounted try_send. Surfaced under the producer metric with
	// distinct labels so a rate-limited or budget-shed close/create is
	// observable (a dropped close loses only a flow-export record; the type-2
	// HA close delta is a separate, never-rate-limited frame).
	ch <- prometheus.MustNewConstMetric(c.userspaceEventStreamProducerFramesTotal,
		prometheus.CounterValue, float64(status.EventStreamSessionCloseSent), "session_close_sent")
	ch <- prometheus.MustNewConstMetric(c.userspaceEventStreamProducerFramesTotal,
		prometheus.CounterValue, float64(status.EventStreamSessionCloseDropped), "session_close_dropped")
	ch <- prometheus.MustNewConstMetric(c.userspaceEventStreamProducerFramesTotal,
		prometheus.CounterValue, float64(status.EventStreamSessionCreateSent), "session_create_sent")
	ch <- prometheus.MustNewConstMetric(c.userspaceEventStreamProducerFramesTotal,
		prometheus.CounterValue, float64(status.EventStreamSessionCreateDropped), "session_create_dropped")
	ch <- prometheus.MustNewConstMetric(c.userspaceEventStreamDecodeErrorsTotal,
		prometheus.CounterValue, float64(es.DecodeErrors))
	ch <- prometheus.MustNewConstMetric(c.userspaceEventStreamSequenceGapsTotal,
		prometheus.CounterValue, float64(es.SeqGaps))

	for _, item := range []struct {
		label string
		count uint64
	}{
		{"policy_deny", es.PolicyDenyEvents},
		{"screen_drop", es.ScreenDropEvents},
		{"screen_alarm", es.ScreenAlarmEvents},
		{"filter_log", es.FilterLogEvents},
		{"session_close", es.SessionCloseEvents},
		{"session_create", es.SessionCreateEvents},
	} {
		ch <- prometheus.MustNewConstMetric(c.userspaceEventStreamDataplaneEventsTotal,
			prometheus.CounterValue, float64(item.count), item.label)
	}
	for _, item := range []struct {
		label string
		count uint64
	}{
		{"policy_deny", es.PolicyDenyDrops},
		{"screen_drop", es.ScreenDropDrops},
		{"filter_log", es.FilterLogDrops},
		{"session_close", es.SessionCloseDrops},
		{"session_create", es.SessionCreateDrops},
	} {
		ch <- prometheus.MustNewConstMetric(c.userspaceEventStreamDataplaneDropsTotal,
			prometheus.CounterValue, float64(item.count), item.label)
	}
	ch <- prometheus.MustNewConstMetric(c.userspaceEventStreamUnknownDropsTotal,
		prometheus.CounterValue, float64(es.UnknownFrameDrops))
}
