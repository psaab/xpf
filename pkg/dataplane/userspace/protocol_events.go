package userspace

type EventStreamStatus struct {
	FramesRead             uint64 `json:"frames_read,omitempty"`
	FramesWritten          uint64 `json:"frames_written,omitempty"`
	DecodeErrors           uint64 `json:"decode_errors,omitempty"`
	SeqGaps                uint64 `json:"seq_gaps,omitempty"`
	SessionSyncResyncs     uint64 `json:"session_sync_resyncs,omitempty"`     // #2874/#5483
	DecodeResyncSuppressed uint64 `json:"decode_resync_suppressed,omitempty"` // #6130
	PolicyDenyEvents       uint64 `json:"policy_deny_events,omitempty"`
	ScreenDropEvents       uint64 `json:"screen_drop_events,omitempty"`
	ScreenAlarmEvents      uint64 `json:"screen_alarm_events,omitempty"`
	FilterLogEvents        uint64 `json:"filter_log_events,omitempty"`
	SessionCloseEvents     uint64 `json:"session_close_events,omitempty"`  // #2460/#2510
	SessionCreateEvents    uint64 `json:"session_create_events,omitempty"` // #2508/#2510
	PolicyDenyDrops        uint64 `json:"policy_deny_drops,omitempty"`
	ScreenDropDrops        uint64 `json:"screen_drop_drops,omitempty"`
	FilterLogDrops         uint64 `json:"filter_log_drops,omitempty"`
	SessionCloseDrops      uint64 `json:"session_close_drops,omitempty"`  // #2460/#2510
	SessionCreateDrops     uint64 `json:"session_create_drops,omitempty"` // #2508/#2510
	UnknownFrameDrops      uint64 `json:"unknown_frame_drops,omitempty"`
	Paused                 bool   `json:"paused,omitempty"`           // #9915 F-125: last Pause/Resume request state
	EventsSinceAck         uint64 `json:"events_since_ack,omitempty"` // #9915 F-125: applied events since last ACK flush; resets ~100ms (sawtooth, not a gauge)
}

// ---------------------------------------------------------------------------
// Event stream wire format (binary framed, helper → daemon push stream).
// ---------------------------------------------------------------------------

// EventFrameHeaderSize is the byte length of every event stream frame header.
const EventFrameHeaderSize = 16

// Event stream message types.
const (
	EventTypeSessionOpen     uint8 = 1
	EventTypeSessionClose    uint8 = 2
	EventTypeSessionUpdate   uint8 = 3
	EventTypeAck             uint8 = 4  // daemon → helper
	EventTypePause           uint8 = 5  // daemon → helper
	EventTypeResume          uint8 = 6  // daemon → helper
	EventTypeDrainRequest    uint8 = 7  // daemon → helper (target seq in header)
	EventTypeDrainComplete   uint8 = 8  // helper → daemon
	EventTypeFullResync      uint8 = 9  // helper → daemon
	EventTypeKeepalive       uint8 = 10 // helper → daemon (idle heartbeat)
	EventFrameTypePolicyDeny uint8 = 11 // helper → daemon (RT_FLOW policy deny)
	EventFrameTypeScreenDrop uint8 = 12 // helper → daemon (RT_FLOW screen drop)
	EventFrameTypeFilterLog  uint8 = 13 // helper → daemon (RT_FLOW filter log)
	// #2460: RT_FLOW SESSION_CLOSE on the raw dataplane-event channel,
	// carrying the canonical 144-byte dataplane.Event payload (#3056) with the
	// event-type byte = dataplane.EventTypeSessionClose (2). Routed through
	// the same decodeDataplaneEventPayload → eventReader.ProcessRawEvent
	// path as the deny/screen/filter frames so the NetFlow/IPFIX
	// session-close exporters fire. ADDITIVE to the minimal type-2
	// EventTypeSessionClose HA session-sync delta — both are produced per
	// close; the HA sync path is unchanged.
	EventFrameTypeSessionClose uint8 = 14 // helper → daemon (RT_FLOW session close)
	// #2508: RT_FLOW SESSION_CREATE on the raw dataplane-event channel,
	// carrying the canonical 144-byte dataplane.Event payload (#3056) with the
	// event-type byte = dataplane.EventTypeSessionOpen (1). Emitted by the
	// helper ONLY for sessions admitted by a policy configured with
	// `then log session-init` — there is no flowexport consumer of session
	// opens, so this frame is gated entirely at the producer. Routed
	// through the same decodeDataplaneEventPayload → ProcessRawEvent path;
	// logEvent then formats it as an RT_FLOW_SESSION_CREATE syslog record.
	EventFrameTypeSessionCreate uint8 = 15 // helper → daemon (RT_FLOW session create)
)

// Session event flag bits in the Flags byte of SessionOpen/Update/Close payloads.
const (
	SessionEventFlagFabricRedirect uint8 = 1 << 0
	SessionEventFlagFabricIngress  uint8 = 1 << 1
	SessionEventFlagIsReverse      uint8 = 1 << 2
	// #2785: per-policy `then log` selection carried on the open frame so a
	// synced session logs the same RT_FLOW records after failover. Must match
	// FLAG_LOG_SESSION_INIT/CLOSE in userspace-dp/src/event_stream/codec.rs.
	SessionEventFlagLogSessionInit  uint8 = 1 << 3
	SessionEventFlagLogSessionClose uint8 = 1 << 4
	// #4565: NAT64 cross-family marker carried on the open frame so a peer-
	// PROMOTED session rebuilds its reverse (v4->v6) BIB after failover. Must
	// match FLAG_NAT64 in userspace-dp/src/event_stream/codec.rs.
	SessionEventFlagNat64 uint8 = 1 << 5
)
