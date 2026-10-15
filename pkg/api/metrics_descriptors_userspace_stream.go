package api

import "github.com/prometheus/client_golang/prometheus"

func (c *xpfCollector) initUserspaceStreamDescriptors() {
	c.userspaceFlowCacheActiveFlows = prometheus.NewDesc(
		"xpf_userspace_flow_cache_active_flows",
		"Aggregate active userspace flow-cache entries across bindings.",
		nil, nil,
	)
	c.userspaceFlowCacheCapacity = prometheus.NewDesc(
		"xpf_userspace_flow_cache_capacity",
		"Aggregate userspace flow-cache capacity across bindings.",
		nil, nil,
	)
	c.userspaceEventStreamFramesTotal = prometheus.NewDesc(
		"xpf_userspace_event_stream_frames_total",
		"Daemon-side userspace event-stream frames by direction.",
		[]string{"direction"}, nil,
	)
	c.userspaceEventStreamProducerFramesTotal = prometheus.NewDesc(
		"xpf_userspace_event_stream_producer_frames_total",
		"Userspace helper event-stream producer counters by outcome.",
		[]string{"outcome"}, nil,
	)
	c.userspaceEventStreamDecodeErrorsTotal = prometheus.NewDesc(
		"xpf_userspace_event_stream_decode_errors_total",
		"Daemon-side userspace event-stream decode errors.",
		nil, nil,
	)
	c.userspaceEventStreamSequenceGapsTotal = prometheus.NewDesc(
		"xpf_userspace_event_stream_sequence_gaps_total",
		"Daemon-side userspace event-stream sequence gaps.",
		nil, nil,
	)
	c.userspaceEventStreamDataplaneEventsTotal = prometheus.NewDesc(
		"xpf_userspace_event_stream_dataplane_events_total",
		"Decoded RT_FLOW dataplane events received over the userspace event stream.",
		[]string{"type"}, nil,
	)
	c.userspaceEventStreamDataplaneDropsTotal = prometheus.NewDesc(
		"xpf_userspace_event_stream_dataplane_event_drops_total",
		"RT_FLOW dataplane events dropped by the userspace event-stream decoder.",
		[]string{"type"}, nil,
	)
	c.userspaceEventStreamUnknownDropsTotal = prometheus.NewDesc(
		"xpf_userspace_event_stream_unknown_frame_drops_total",
		"Userspace event-stream frames dropped because their frame type is unknown.",
		nil, nil,
	)
	c.userspaceEventStreamResyncsTotal = prometheus.NewDesc(
		"xpf_userspace_event_stream_resyncs_total",
		"Daemon-side userspace event-stream full resyncs by trigger reason.",
		[]string{"reason"}, nil,
	)
	c.userspaceEventStreamDisconnectsTotal = prometheus.NewDesc(
		"xpf_userspace_event_stream_disconnects_total",
		"Daemon-side userspace event-stream disconnect triggers by reason.",
		[]string{"reason"}, nil,
	)
	c.userspaceEventStreamState = prometheus.NewDesc(
		"xpf_userspace_event_stream_state",
		"Current userspace event-stream state values: connected, paused, events_since_ack, sequence, and acked sequence.",
		[]string{"state"}, nil,
	)
}
