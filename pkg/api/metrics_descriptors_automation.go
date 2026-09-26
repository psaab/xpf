package api

import "github.com/prometheus/client_golang/prometheus"

func (c *xpfCollector) initAutomationDescriptors() {
	c.eventActionsCommitted = prometheus.NewDesc(
		"xpf_event_actions_committed_total",
		"Total event-options change-configuration remediation actions "+
			"that committed successfully (#2157). INCLUDES the "+
			"committed-with-apply-debt subset (#5063): the generation was "+
			"promoted, is active, and the dataplane armed even when a "+
			"best-effort subsystem stayed in debt.",
		nil, nil,
	)
	c.eventActionsCommittedWithDebt = prometheus.NewDesc(
		"xpf_event_actions_committed_with_debt_total",
		"Subset of xpf_event_actions_committed_total whose commit "+
			"promoted+armed the generation but left a BEST-EFFORT subsystem "+
			"(networkd write / Kea restart / host-inbound nft) in debt "+
			"(#5063). The change is LIVE — this is not a rejection — but a "+
			"nonzero value means a committed remediation applied with a "+
			"recoverable subsystem hiccup worth investigating.",
		nil, nil,
	)
	c.eventActionsRejected = prometheus.NewDesc(
		"xpf_event_actions_rejected_total",
		"Total event-options remediation actions rejected as a "+
			"permanent failure — a malformed/unknown command, a "+
			"candidate apply error, or a commit-check failure. The "+
			"batch is transactional (#2139): a rejected action applies "+
			"NOTHING (the candidate is discarded).",
		nil, nil,
	)
	c.eventActionsRetried = prometheus.NewDesc(
		"xpf_event_actions_retried_total",
		"Total retry attempts for event-options remediation actions "+
			"deferred because the config lock was held by another "+
			"session (#2157). The action is retried with bounded "+
			"backoff rather than dropped.",
		nil, nil,
	)
	c.eventActionsDropped = prometheus.NewDesc(
		"xpf_event_actions_dropped_total",
		"Total event-options remediation actions dropped (NOT applied). "+
			"reason=lock_held: the config lock stayed held past the "+
			"retry deadline. reason=queue_full: the bounded action queue "+
			"was full of OTHER policies' actions and this one could not fit "+
			"(#2157; a same-policy dedup is counted separately as "+
			"xpf_event_actions_superseded_total, #5853). reason=stale: at "+
			"commit time the policy had been removed or redefined, or its 30s "+
			"cooldown was now active — the action was revalidated and dropped "+
			"rather than committing a batch no active policy authorizes "+
			"(#3750). reason=global_budget: the cross-policy commit-attempt "+
			"budget reached four actions in its rolling minute (#10871). "+
			"A nonzero lock_held/queue_full value means automated remediation "+
			"was lost — investigate the lock holder; stale is expected under "+
			"operator config churn or duplicate events.",
		[]string{"reason"}, nil,
	)
	c.eventActionsSuperseded = prometheus.NewDesc(
		"xpf_event_actions_superseded_total",
		"Total event-options remediation actions SUPERSEDED by a newer "+
			"same-policy trigger while queued (#5853). The dedup keeps at "+
			"most one pending action per policy, so a burst from one policy "+
			"cannot fill the bounded queue and starve other policies. This is "+
			"benign — nothing is lost, the newer equivalent action still "+
			"runs — and is expected under duplicate events; it is NOT a "+
			"capacity drop (see reason=queue_full on "+
			"xpf_event_actions_dropped_total).",
		nil, nil,
	)
	c.eventAttributesInvalid = prometheus.NewDesc(
		"xpf_event_attributes_match_invalid_total",
		"Total times a malformed or unknown-field attributes-match line "+
			"was hit at runtime, causing the policy to fail CLOSED (not "+
			"fire). Strict commit rejects these (#2141); a nonzero value "+
			"means a config persisted by an older binary booted through a "+
			"lenient load with a bad line — fix it on the next commit.",
		nil, nil,
	)
	c.eventPlantClassInvalid = prometheus.NewDesc(
		"xpf_event_plant_class_invalid_total",
		"Total event-options remediation payloads refused because their "+
			"recorded planting class was missing, unknown, or denied at "+
			"fire time; nonzero means legacy or stale automation was "+
			"quarantined (#9984).",
		nil, nil,
	)
	c.eventActionQueueDepth = prometheus.NewDesc(
		"xpf_event_action_queue_depth",
		"Current number of event-options remediation actions queued "+
			"but not yet applied by the single action worker (#2157). "+
			"A persistently nonzero depth means actions are backing up "+
			"behind a held config lock.",
		nil, nil,
	)
	c.eventStreamSubscriberDropped = prometheus.NewDesc(
		"xpf_event_stream_subscriber_dropped_total",
		"Total security/audit event records dropped by the EventBuffer "+
			"fan-out because a subscriber's channel was full (#5064). A "+
			"slow REST-SSE / gRPC event-stream / CLI-monitor consumer sheds "+
			"records non-blocking; a nonzero, climbing value means a live "+
			"forensic stream is gapped. Subscribers also see the gap in-band "+
			"via the record's monotonic BufSeq and an Overrun flag.",
		nil, nil,
	)
	c.eventStreamSubscriberRefusals = prometheus.NewDesc(
		"xpf_event_stream_subscriber_refusals_total",
		"Total EventBuffer TrySubscribe requests rejected at the shared "+
			"subscriber cap across REST SSE and gRPC event streams (#10910).",
		nil, nil,
	)
	c.feedSecondsSinceSuccess = prometheus.NewDesc(
		"xpf_feed_seconds_since_last_success",
		"Seconds since a dynamic-address feed last fetched successfully. "+
			"Climbs while the feed cannot be refreshed; the last-good "+
			"snapshot is retained indefinitely by default (#2050). -1 "+
			"means the feed has never had a successful fetch (no snapshot "+
			"installed; fail-closed).",
		[]string{"feed"}, nil,
	)
	c.feedStale = prometheus.NewDesc(
		"xpf_feed_stale",
		"1 while a dynamic-address feed's last-good snapshot is being "+
			"retained as stale (a fetch has failed since the last good "+
			"one and the snapshot is still enforced); 0 while fresh "+
			"(#2050).",
		[]string{"feed"}, nil,
	)
}
