// Package logging implements dataplane event reading.
package logging

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/psaab/xpf/pkg/appid"
	"github.com/psaab/xpf/pkg/dataplane"
)

// EventCallback is called for each processed event record.
type EventCallback func(rec EventRecord, raw []byte)

// EventSource reads raw RT_FLOW event records from a runtime source.
type EventSource interface {
	ReadEvent() ([]byte, error)
	Close() error
}

// rawEvent mirrors the fixed 144-byte RT_FLOW event wire shape produced by the
// runtime event sources. The decoder below still reads by offset so that port
// byte order stays explicit.
type rawEvent struct {
	Timestamp      uint64
	SrcIP          [16]byte
	DstIP          [16]byte
	SrcPort        uint16
	DstPort        uint16
	PolicyID       uint32
	IngressZone    uint16
	EgressZone     uint16
	EventType      uint8
	Protocol       uint8
	Action         uint8
	AddrFamily     uint8
	SessionPackets uint64
	SessionBytes   uint64
	NATSrcIP       [16]byte
	NATDstIP       [16]byte
	NATSrcPort     uint16
	NATDstPort     uint16
	Created        uint32
	RevPackets     uint64
	RevBytes       uint64
	IngressIfindex uint32
	AppID          uint16
	CloseReason    uint8
	// #2508: per-policy RT_FLOW SYSLOG log gate (was reserved padding).
	// Carried only on the userspace-dp SESSION_CREATE/SESSION_CLOSE
	// frames: 1 == the admitting policy was configured with
	// `then log session-init`/`session-close`, so emit the per-policy
	// RT_FLOW SYSLOG record; 0 == suppress the SYSLOG record. This gates
	// ONLY the syslog/local-log/slog consumers — the registered callbacks
	// (the global NetFlow/IPFIX session-close exporter, #2460) always run.
	// For all other event types (deny/screen/filter) this byte is 0 and
	// unread (those frames are unconditionally logged).
	LogSyslog uint8
	// #3056: the admitting policy's ID on a SESSION_CLOSE frame, in the
	// trailing [136:140] slot. Every non-close frame carries the policy id in
	// [44:48] (PolicyID above), but #2853 repurposed [44:48] on a close for the
	// created-subsec-nanos, so the close frame uses this slot. The decoders read
	// [136:140] only on a SESSION_CLOSE. PadEvent2 keeps the struct 8-byte
	// aligned at 144 bytes to match the wire payload.
	PolicyIDClose uint32
	PadEvent2     [4]uint8
}

const (
	// #3056: 144 (was 136). The trailing [136:140] u32 carries the admitting
	// policy ID on a SESSION_CLOSE frame; [140:144] is reserved padding (the
	// rawEvent / dataplane.Event mirrors carry uint64 fields, so the struct
	// aligns to 8 and the size must be a multiple of 8).
	rawEventWireSize   = 144
	rawEventStructSize = int(unsafe.Sizeof(rawEvent{}))
	// rawEventLogSyslogOffset is the wire offset of the #2508 per-policy
	// RT_FLOW SYSLOG log gate (offset 135).
	rawEventLogSyslogOffset = 135
	// rawEventPolicyCloseOffset is the wire offset of the #3056 admitting policy
	// ID on a SESSION_CLOSE frame (LE u32 at [136:140]).
	rawEventPolicyCloseOffset = 136
	// #2749: the EXTENDED SESSION_CLOSE frame grew 144 -> 152 to carry a
	// class-of-service / interface-attribution block at [144:152]: [144] src
	// ToS byte, [145] accumulated TCP control bits, [146] flow direction
	// (reserved, deferred), [147] reserved, [148:152] egress ifindex (LE u32).
	// The growth is ADDITIVE: the minimum-frame acceptance stays at
	// rawEventWireSize (144) so a new daemon still accepts an old helper's
	// 144-byte frames, and these slots are read ONLY when the frame actually
	// carries them (len >= rawEventExtSize) AND only on a SESSION_CLOSE. An old
	// daemon ignores the trailing 8 bytes. Both rolling-upgrade directions are
	// safe (#1961 both-sides wire discipline).
	rawEventExtSize      = 152
	rawEventTOSOffset    = 144
	rawEventTCPBitOffset = 145
	rawEventEgressOffset = 148
	// #4915: the EXTENDED SESSION_CREATE/SESSION_CLOSE frame grew 152 -> 160 to
	// carry the dataplane's STABLE session id (LE u64) at [152:160]. The
	// userspace-dp encoders (encode_session_create_rt_flow /
	// encode_session_close_rt_flow) stamp the same id a session's create and
	// close records share, so a SIEM can join them and disambiguate a reused
	// 5-tuple. The growth is ADDITIVE with the same both-sides discipline as the
	// #2749 [144:152] block: the minimum-frame acceptance stays at
	// rawEventWireSize (144), and the slot is read ONLY when the frame carries it
	// (len >= rawEventSessionIDSize) AND only on a SESSION_CREATE/CLOSE, so a
	// short legacy (<= 152-byte) frame degrades to SessionID 0 ("unknown") rather
	// than misparsing. Both rolling-upgrade directions stay safe.
	rawEventSessionIDSize   = 160
	rawEventSessionIDOffset = 152
)

var _ [rawEventWireSize]struct{} = [rawEventStructSize]struct{}{}

const (
	closeReasonNone    = 0
	closeReasonTimeout = 1
	closeReasonTCPFIN  = 2
	closeReasonTCPRST  = 3
	closeReasonAgeOut  = 4
	closeReasonPolicy  = 5
	// #3610: a host-inbound-traffic admission deny. Carried in the RT_FLOW
	// reason byte on a POLICY_DENY event (the userspace-dp
	// emit_host_inbound_deny_event rides the policy-deny wire kind with this
	// distinct reason). Must equal the Rust RT_FLOW_CLOSE_REASON_HOST_INBOUND
	// (userspace-dp/src/afxdp/event_emit.rs). Lets the structured
	// RT_FLOW_SESSION_DENY record and operators tell a control-plane
	// host-inbound drop apart from a transit security-policy deny.
	closeReasonHostInbound = 6
)

const (
	actionDeny   = 0
	actionPermit = 1
	actionReject = 2
	// actionNotApplicable flags the binary-log action byte on a SESSION_CLOSE,
	// which carries no forwarding decision. Its wire action byte is
	// intentionally 0, which the raw encoding would stamp as "deny" (actionDeny)
	// and mislead binary forensic consumers into reading a normal close as a
	// drop (#4914). The standard and structured text formatters OMIT the action
	// field on a close (#2513); the fixed-shape binary record cannot omit a
	// field, so it carries this explicit "not applicable" sentinel instead of a
	// bogus 0.
	actionNotApplicable = 0xFF
)

const (
	eventTypeSessionOpen  = 1
	eventTypeSessionClose = 2
	eventTypePolicyDeny   = 3
	eventTypeScreenDrop   = 4
	eventTypeFilterLog    = 6
)

const (
	addrFamilyInet  = 2
	addrFamilyInet6 = 10
)

const protoICMPv6 = 58

const (
	screenSynFlood        = 1 << 0
	screenICMPFlood       = 1 << 1
	screenUDPFlood        = 1 << 2
	screenPortScan        = 1 << 3
	screenIPSweep         = 1 << 4
	screenLandAttack      = 1 << 5
	screenPingOfDeath     = 1 << 6
	screenTearDrop        = 1 << 7
	screenTCPSynFin       = 1 << 8
	screenTCPNoFlag       = 1 << 9
	screenTCPFinNoAck     = 1 << 10
	screenWinNuke         = 1 << 11
	screenIPSourceRoute   = 1 << 12
	screenSynFrag         = 1 << 13
	screenSynCookie       = 1 << 14
	screenSessionLimitSrc = 1 << 15
	screenSessionLimitDst = 1 << 16
	// Bits 17-19 mirror the userspace-dp screen reason flags added after the
	// original eBPF parity set (kept in lockstep with dataplane.ScreenFlagNames;
	// the cross-package count is asserted by TestRawEventContractMatchesDataplaneEvent):
	// ICMP fragment, IP malformed (#2146 fail-closed parse), and scan-table
	// pressure (#2234 bounded-eviction operator alarm — not a packet drop).
	screenICMPFragment      = 1 << 17
	screenIPMalformed       = 1 << 18
	screenScanTablePressure = 1 << 19
)

var screenFlagNames = map[uint32]string{
	screenSynFlood:          "SYN flood",
	screenICMPFlood:         "ICMP flood",
	screenUDPFlood:          "UDP flood",
	screenPortScan:          "port scan",
	screenIPSweep:           "IP sweep",
	screenLandAttack:        "LAND attack",
	screenPingOfDeath:       "ping of death",
	screenTearDrop:          "tear drop",
	screenTCPSynFin:         "TCP SYN+FIN",
	screenTCPNoFlag:         "TCP no-flag",
	screenTCPFinNoAck:       "TCP FIN-no-ACK",
	screenWinNuke:           "WinNuke",
	screenIPSourceRoute:     "IP source-route",
	screenSynFrag:           "SYN fragment",
	screenSynCookie:         "SYN cookie",
	screenSessionLimitSrc:   "session limit (source)",
	screenSessionLimitDst:   "session limit (destination)",
	screenICMPFragment:      "ICMP fragment",
	screenIPMalformed:       "IP malformed",
	screenScanTablePressure: "scan-table pressure",
}

// EventReader reads events from an EventSource.
type EventReader struct {
	source        EventSource
	buffer        *EventBuffer
	syslogMu      sync.RWMutex
	syslogClients []*SyslogClient
	localMu       sync.RWMutex
	localWriters  []*LocalLogWriter
	callbackMu    sync.RWMutex
	callbacks     []EventCallback
	zoneNamesMu   sync.RWMutex
	zoneNames     map[uint16]string // zone ID -> zone name
	policyNamesMu sync.RWMutex
	policyNames   map[uint32]string // rule_id -> policy name
	ifNamesMu     sync.RWMutex
	ifNames       map[uint32]string // ifindex -> interface name
	appNamesMu    sync.RWMutex
	appNames      map[uint16]string // app_id -> application name
	sessionSeq    uint64            // #4915: per-EVENT monotonic ordinal (EventSeq), NOT a session id
}

// NewEventReader creates a new event reader for the given event source.
func NewEventReader(source EventSource, buffer *EventBuffer) *EventReader {
	return &EventReader{
		source: source,
		buffer: buffer,
	}
}

// SetZoneNames updates the zone ID to name mapping (goroutine-safe).
func (er *EventReader) SetZoneNames(names map[uint16]string) {
	er.zoneNamesMu.Lock()
	er.zoneNames = names
	er.zoneNamesMu.Unlock()
}

func (er *EventReader) resolveZoneName(id uint16) string {
	er.zoneNamesMu.RLock()
	name := er.zoneNames[id]
	er.zoneNamesMu.RUnlock()
	if name != "" {
		return name
	}
	return fmt.Sprintf("%d", id)
}

// SetPolicyNames updates the rule ID to policy name mapping (goroutine-safe).
func (er *EventReader) SetPolicyNames(names map[uint32]string) {
	er.policyNamesMu.Lock()
	er.policyNames = names
	er.policyNamesMu.Unlock()
}

func (er *EventReader) resolvePolicyName(id uint32) string {
	// #3057: the implicit default-policy carries a reserved sentinel ID that can
	// never equal a real configured policy ID. Render it as the fixed
	// pseudo-policy name authoritatively (even before any policyNames map has
	// been published) so a default-deny/reject RT_FLOW record never aliases the
	// first configured policy (real ID 0).
	if id == dataplane.DefaultPolicySentinelID {
		return dataplane.DefaultPolicyName
	}
	er.policyNamesMu.RLock()
	name := er.policyNames[id]
	er.policyNamesMu.RUnlock()
	if name != "" {
		return name
	}
	return fmt.Sprintf("%d", id)
}

// SetIfNames updates the ifindex to interface name mapping (goroutine-safe).
func (er *EventReader) SetIfNames(names map[uint32]string) {
	er.ifNamesMu.Lock()
	er.ifNames = names
	er.ifNamesMu.Unlock()
}

func (er *EventReader) resolveIfName(ifindex uint32) string {
	if ifindex == 0 {
		return ""
	}
	er.ifNamesMu.RLock()
	name := er.ifNames[ifindex]
	er.ifNamesMu.RUnlock()
	return name
}

// SetAppNames updates the app ID to application name mapping (goroutine-safe).
func (er *EventReader) SetAppNames(names map[uint16]string) {
	er.appNamesMu.Lock()
	er.appNames = names
	er.appNamesMu.Unlock()
}

func (er *EventReader) resolveAppName(id uint16) string {
	if id == 0 {
		return "UNKNOWN"
	}
	er.appNamesMu.RLock()
	name := er.appNames[id]
	er.appNamesMu.RUnlock()
	if name != "" {
		return name
	}
	return "UNKNOWN"
}

// AddCallback registers a callback that will be invoked for every event.
// The raw byte slice is the original ring buffer sample data.
func (er *EventReader) AddCallback(cb EventCallback) {
	er.callbackMu.Lock()
	er.callbacks = append(er.callbacks, cb)
	er.callbackMu.Unlock()
}

// ClearCallbacks removes all registered callbacks.
func (er *EventReader) ClearCallbacks() {
	er.callbackMu.Lock()
	er.callbacks = nil
	er.callbackMu.Unlock()
}

// CallbackCount returns the number of registered callbacks. Used by the
// daemon flow-exporter reconcile tests to assert the once-registered
// indirection callback is never leaked across repeated reconciles
// (#2075).
func (er *EventReader) CallbackCount() int {
	er.callbackMu.RLock()
	n := len(er.callbacks)
	er.callbackMu.RUnlock()
	return n
}

// SetSyslogClients replaces the set of syslog clients (goroutine-safe).
func (er *EventReader) SetSyslogClients(clients []*SyslogClient) {
	er.syslogMu.Lock()
	er.syslogClients = clients
	er.syslogMu.Unlock()
}

// SyslogClientCount reports how many syslog clients are currently installed
// (goroutine-safe). Observability/testability only — lets a caller confirm a
// teardown actually cleared the clients (e.g. a day-2 commit that removes all
// streams must not leave lingering clients forwarding to a deleted receiver).
func (er *EventReader) SyslogClientCount() int {
	er.syslogMu.RLock()
	defer er.syslogMu.RUnlock()
	return len(er.syslogClients)
}

// SyslogClients returns the currently installed syslog clients (goroutine-safe).
//
// #6829 F2: the sibling of SyslogClientCount, exposing the clients themselves
// rather than just how many. applySyslogConfig computes each stream's facility
// on one side of the client construction and assigns it on the other — the
// compute/assign split that silently drops a value — and a COUNT cannot observe
// which facility was installed. Deleting either half left the whole package
// green before this existed.
func (er *EventReader) SyslogClients() []*SyslogClient {
	er.syslogMu.RLock()
	defer er.syslogMu.RUnlock()
	return append([]*SyslogClient(nil), er.syslogClients...)
}

// LocalWriterCount reports how many local log writers are currently installed
// (goroutine-safe). Observability/testability only — lets a caller confirm that
// event mode installed a local writer (and that a stream-mode reload cleared
// it), e.g. an in-process CLI commit reaching event-mode parity with the daemon
// reconcile (#5738).
func (er *EventReader) LocalWriterCount() int {
	er.localMu.RLock()
	defer er.localMu.RUnlock()
	return len(er.localWriters)
}

// SetLocalWriters replaces the set of local log writers (goroutine-safe).
func (er *EventReader) SetLocalWriters(writers []*LocalLogWriter) {
	er.localMu.Lock()
	er.localWriters = writers
	er.localMu.Unlock()
}

// ReplaceLocalWriters atomically swaps local writers and closes old ones.
func (er *EventReader) ReplaceLocalWriters(writers []*LocalLogWriter) {
	er.localMu.Lock()
	old := er.localWriters
	er.localWriters = writers
	er.localMu.Unlock()
	for _, w := range old {
		w.Close()
	}
}

// ReplaceSyslogClients atomically swaps syslog clients and closes old ones.
func (er *EventReader) ReplaceSyslogClients(clients []*SyslogClient) {
	er.syslogMu.Lock()
	old := er.syslogClients
	er.syslogClients = clients
	er.syslogMu.Unlock()
	for _, c := range old {
		c.Close()
	}
}

// ForwardLogMsg sends a pre-formatted message to all configured syslog clients
// and local log writers. Used by the aggregation reporter.
func (er *EventReader) ForwardLogMsg(severity int, msg string) {
	er.syslogMu.RLock()
	clients := er.syslogClients
	er.syslogMu.RUnlock()
	for _, c := range clients {
		if c.ShouldSend(severity) {
			_ = c.Send(severity, msg)
		}
	}

	er.localMu.RLock()
	writers := er.localWriters
	er.localMu.RUnlock()
	for _, lw := range writers {
		// #3478 M05: don't discard the aggregator's local-writer error.
		// LocalLogWriter.Send already counts the drop (DroppedWrites) and
		// emits a rate-limited WARN; surface it here at Debug so the
		// per-aggregation context is available without spamming the hot path.
		if err := lw.Send(severity, msg); err != nil {
			slog.Debug("aggregation report local log write failed", "err", err)
		}
	}
}

// Run starts reading events. It blocks until ctx is cancelled.
func (er *EventReader) Run(ctx context.Context) {
	if er.source == nil {
		slog.Warn("event source is nil, event reader not starting")
		return
	}

	slog.Info("event reader started")

	// Close the source when context is done
	go func() {
		<-ctx.Done()
		er.source.Close()
	}()

	for {
		data, err := er.source.ReadEvent()
		if err != nil {
			select {
			case <-ctx.Done():
				slog.Info("event reader stopped")
				return
			default:
				slog.Error("event source read error", "err", err)
				return
			}
		}

		if len(data) < rawEventWireSize {
			continue
		}

		er.logEvent(data)
	}
}

// ProcessRawEvent feeds an RT_FLOW-format event record through the
// same enrichment, buffering, callback, and syslog/local-log fanout path used
// by the eBPF ring-buffer reader. Userspace transports should call this rather
// than adding decoded records directly to EventBuffer.
func (er *EventReader) ProcessRawEvent(data []byte) bool {
	if len(data) < rawEventWireSize {
		return false
	}
	er.logEvent(data)
	return true
}

// eventTimeFromWire converts an on-wire RT_FLOW timestamp into the
// EventRecord.Time the logging path should record. The wire timestamp is an
// absolute Unix value in NANOSECONDS, emitted by the userspace-dp producer at
// the moment the forwarding decision was made (#2465/#2470). When it is
// present (nonzero) and fits an int64, use it so the logged record reflects
// DECISION time rather than receive time. A zero/absent timestamp (an
// old-format frame or a synthesized event) or one that would overflow int64
// falls back to time.Now(). This is the single source of truth shared by
// logEvent (the live ProcessRawEvent path) and DecodeRawEventRecord.
func eventTimeFromWire(wireTS uint64) time.Time {
	if wireTS > 0 && wireTS <= uint64(1<<63-1) {
		return time.Unix(0, int64(wireTS))
	}
	return time.Now()
}

func (er *EventReader) logEvent(data []byte) {
	var evt rawEvent
	evt.Timestamp = binary.LittleEndian.Uint64(data[0:8])
	copy(evt.SrcIP[:], data[8:24])
	copy(evt.DstIP[:], data[24:40])
	evt.SrcPort = binary.BigEndian.Uint16(data[40:42])
	evt.DstPort = binary.BigEndian.Uint16(data[42:44])
	evt.PolicyID = binary.LittleEndian.Uint32(data[44:48])
	evt.IngressZone = binary.LittleEndian.Uint16(data[48:50])
	evt.EgressZone = binary.LittleEndian.Uint16(data[50:52])
	evt.EventType = data[52]
	evt.Protocol = data[53]
	evt.Action = data[54]
	evt.AddrFamily = data[55]

	// Parse NAT fields (offsets 72..112) if data is long enough
	if len(data) >= 112 {
		copy(evt.NATSrcIP[:], data[72:88])
		copy(evt.NATDstIP[:], data[88:104])
		evt.NATSrcPort = binary.BigEndian.Uint16(data[104:106])
		evt.NATDstPort = binary.BigEndian.Uint16(data[106:108])
		evt.Created = binary.LittleEndian.Uint32(data[108:112])
	}

	var srcStr, dstStr, natSrcStr, natDstStr string
	if evt.AddrFamily == addrFamilyInet6 {
		srcIP := net.IP(evt.SrcIP[:])
		dstIP := net.IP(evt.DstIP[:])
		srcStr = fmt.Sprintf("[%s]:%d", srcIP, evt.SrcPort)
		dstStr = fmt.Sprintf("[%s]:%d", dstIP, evt.DstPort)
		natSrcIP := net.IP(evt.NATSrcIP[:])
		natDstIP := net.IP(evt.NATDstIP[:])
		natSrcStr = fmt.Sprintf("[%s]:%d", natSrcIP, evt.NATSrcPort)
		natDstStr = fmt.Sprintf("[%s]:%d", natDstIP, evt.NATDstPort)
	} else {
		srcIP := net.IP(evt.SrcIP[:4])
		dstIP := net.IP(evt.DstIP[:4])
		srcStr = fmt.Sprintf("%s:%d", srcIP, evt.SrcPort)
		dstStr = fmt.Sprintf("%s:%d", dstIP, evt.DstPort)
		natSrcIP := net.IP(evt.NATSrcIP[:4])
		natDstIP := net.IP(evt.NATDstIP[:4])
		natSrcStr = fmt.Sprintf("%s:%d", natSrcIP, evt.NATSrcPort)
		natDstStr = fmt.Sprintf("%s:%d", natDstIP, evt.NATDstPort)
	}

	eventName := eventTypeName(evt.EventType)
	actionStr := actionName(evt.Action)
	protoStr := protoName(evt.Protocol)

	// Build EventRecord. #2511: honor the on-wire decision-time stamp via the
	// shared eventTimeFromWire guard (falls back to time.Now() when absent) so
	// the live ProcessRawEvent path records the same DECISION time that
	// DecodeRawEventRecord already does, completing the #2470 producer pair.
	rec := EventRecord{
		Time:        eventTimeFromWire(evt.Timestamp),
		Type:        eventName,
		SrcAddr:     srcStr,
		DstAddr:     dstStr,
		Protocol:    protoStr,
		ProtocolNum: evt.Protocol,
		Action:      actionStr,
		PolicyID:    evt.PolicyID,
		InZone:      evt.IngressZone,
		OutZone:     evt.EgressZone,
		NATSrcAddr:  natSrcStr,
		NATDstAddr:  natDstStr,
		InZoneName:  er.resolveZoneName(evt.IngressZone),
		OutZoneName: er.resolveZoneName(evt.EgressZone),
	}

	if evt.EventType == eventTypeSessionClose {
		rec.SessionPkts = binary.LittleEndian.Uint64(data[56:64])
		rec.SessionBytes = binary.LittleEndian.Uint64(data[64:72])
		// #2465: surface the absolute session-creation Unix seconds for the
		// flow exporters (a real StartTime instead of the packet-count guess).
		rec.Created = evt.Created
		// #2853: the [44:48] policy_id slot is repurposed on a SESSION_CLOSE
		// frame to carry the creation instant's sub-second nanosecond
		// remainder. Reinterpret it as CreatedNanos so the flow exporters keep
		// millisecond StartTime resolution.
		rec.CreatedNanos = evt.PolicyID
		// #3056: the admitting policy ID rides the trailing [136:140] slot on a
		// SESSION_CLOSE (because #2853 took [44:48]). Resolve PolicyID from there
		// so the RT_FLOW_SESSION_CLOSE record and the NetFlow/IPFIX close
		// exporters name the admitting policy instead of policy 0. A short
		// (legacy 136-byte) frame leaves it 0. The policy-name resolution below
		// reads rec.PolicyID, so it follows this value.
		rec.PolicyID = 0
		evt.PolicyID = 0
		if len(data) >= rawEventWireSize {
			rec.PolicyID = binary.LittleEndian.Uint32(data[rawEventPolicyCloseOffset : rawEventPolicyCloseOffset+4])
		}
		// Compute elapsed time from session creation
		if evt.Created > 0 {
			nowSec := uint32(evt.Timestamp / 1000000000)
			if nowSec > evt.Created {
				rec.ElapsedTime = nowSec - evt.Created
			}
		}
	}
	if evt.EventType == eventTypeScreenDrop {
		rec.ScreenCheck = screenFlagName(evt.PolicyID)
	}
	if evt.EventType != eventTypeSessionClose && len(data) >= rawEventWireSize {
		rec.RuleID = binary.LittleEndian.Uint32(data[56:60])
		rec.TermID = binary.LittleEndian.Uint32(data[60:64])
		rec.OwnerRGID = int16(binary.LittleEndian.Uint16(data[64:66]))
		if evt.EventType == eventTypeFilterLog && data[134] != 0 {
			rec.Reason = filterLogSourceName(data[134])
		} else if data[134] != closeReasonNone {
			rec.Reason = closeReasonName(data[134])
		}
	}

	// Parse extended fields (offset 112+)
	var closeReasonCode uint8
	if len(data) >= rawEventWireSize {
		rec.RevSessionPkts = binary.LittleEndian.Uint64(data[112:120])
		rec.RevSessionBytes = binary.LittleEndian.Uint64(data[120:128])
		ifindex := binary.LittleEndian.Uint32(data[128:132])
		appID := binary.LittleEndian.Uint16(data[132:134])
		closeReasonCode = data[134]

		rec.IngressIface = er.resolveIfName(ifindex)
		// #2749: retain the raw numeric ifindex so the flow exporters can
		// populate ingressInterface (NetFlow IE 10 / IPFIX ingressInterface),
		// which is an SNMP ifIndex value, not the resolved name.
		rec.IngressIfindex = ifindex
		rec.AppName = er.resolveAppName(appID)
		rec.CloseReason = closeReasonName(closeReasonCode)
	}

	// #2749: the SESSION_CLOSE class-of-service / interface-attribution block
	// rides the additive [144:152] slots. Read it ONLY on a close frame that
	// actually carries the extended length, so a short legacy (144-byte) frame
	// or a non-close event leaves the fields at their 0 ("unknown") default.
	if evt.EventType == eventTypeSessionClose && len(data) >= rawEventExtSize {
		rec.TOS = data[rawEventTOSOffset]
		rec.TCPControlBits = data[rawEventTCPBitOffset]
		rec.EgressIfindex = binary.LittleEndian.Uint32(
			data[rawEventEgressOffset : rawEventEgressOffset+4])
	}

	// Resolve policy name (skip for screen drops which repurpose policy_id).
	// #3056: read rec.PolicyID, not evt.PolicyID — they match for every
	// non-close frame, but on a SESSION_CLOSE evt.PolicyID was zeroed (it held
	// the #2853 created-subsec-nanos) and rec.PolicyID now carries the admitting
	// policy ID from the trailing [136:140] slot, so the close record resolves
	// the admitting policy name instead of policy 0.
	if evt.EventType != eventTypeScreenDrop {
		rec.PolicyName = er.resolvePolicyName(rec.PolicyID)
	}

	// #4915: stamp the per-EVENT monotonic ordinal into EventSeq (it increments
	// on every event, session or not). SessionID becomes the dataplane's STABLE
	// per-session identity ONLY for a SESSION_CREATE / SESSION_CLOSE frame that
	// carries the additive [152:160] slot (len >= 160), so a session's create and
	// close records correlate and a reused 5-tuple is disambiguated. For every
	// other event (deny/screen/filter — which have no session) AND for a short
	// legacy session frame from a pre-#4915 helper (len < 160), SessionID falls
	// back to the per-event ordinal, byte-identical to the pre-#4915 behavior.
	// This keeps the change strictly additive on the wire: nothing observable
	// changes until a new helper emits a 160-byte session frame, at which point
	// its create and close carry the same real id.
	rec.EventSeq = atomic.AddUint64(&er.sessionSeq, 1)
	if (evt.EventType == eventTypeSessionOpen || evt.EventType == eventTypeSessionClose) &&
		len(data) >= rawEventSessionIDSize {
		rec.SessionID = binary.LittleEndian.Uint64(
			data[rawEventSessionIDOffset : rawEventSessionIDOffset+8])
	} else {
		rec.SessionID = rec.EventSeq
	}

	// #2508: per-policy RT_FLOW SYSLOG gate. The userspace-dp
	// SESSION_CREATE/SESSION_CLOSE frames carry a "should-log-to-syslog"
	// bit in the final payload byte: it is set ONLY when the admitting
	// policy was configured with `then log session-init`/`session-close`.
	// When the bit is clear, suppress the human-facing log consumers
	// (security-log buffer, slog, syslog clients, local event writers) but
	// STILL run the registered callbacks below — the global NetFlow/IPFIX
	// session-close exporter (#2460) accounts every close regardless. For
	// every other event type the byte is 0 and this gate never fires
	// (those frames are unconditionally logged); session opens are
	// producer-gated in the helper, so a SESSION_CREATE frame that reaches
	// here always has the bit set.
	//
	// This gate is SCOPED to the userspace-dp event-stream path
	// (`er.source == nil`, i.e. records fed via ProcessRawEvent) — the ONLY
	// producer that sets the per-policy log bit. A source-based EventReader
	// (`er.source != nil`, the kernel/ring-buffer reader created at
	// pkg/daemon/daemon_run.go) does NOT carry the per-policy bit (the byte
	// defaults to 0), so it must NEVER be gated by this check or its session
	// logs would be unconditionally suppressed.
	suppressSyslogLog := false
	if er.source == nil &&
		(evt.EventType == eventTypeSessionClose || evt.EventType == eventTypeSessionOpen) &&
		len(data) > rawEventLogSyslogOffset &&
		data[rawEventLogSyslogOffset] == 0 {
		suppressSyslogLog = true
	}

	// Store in buffer
	if er.buffer != nil && !suppressSyslogLog {
		er.buffer.Add(rec)
	}

	// Invoke registered callbacks
	er.callbackMu.RLock()
	cbs := er.callbacks
	er.callbackMu.RUnlock()
	for _, cb := range cbs {
		cb(rec, data)
	}

	// #2508: the registered callbacks (NetFlow/IPFIX, #2460) have now seen
	// the event. When the per-policy SYSLOG gate is closed, stop here so the
	// human-facing log consumers (slog, syslog clients, local event writers)
	// never emit a per-policy RT_FLOW record the operator did not request.
	if suppressSyslogLog {
		return
	}

	// Log to slog (existing behavior) — use resolved zone names
	inZone := rec.InZoneName
	if inZone == "" {
		inZone = fmt.Sprintf("%d", evt.IngressZone)
	}
	outZone := rec.OutZoneName
	if outZone == "" {
		outZone = fmt.Sprintf("%d", evt.EgressZone)
	}
	if evt.EventType == eventTypeSessionClose {
		// #4796: on a SESSION_CLOSE, evt.PolicyID was zeroed above (#2853
		// repurposes the [44:48] slot for the created-subsec-nanos) and only
		// rec.PolicyID is repopulated from the trailing [136:140] admitting-
		// policy slot (#3056). Logging evt.PolicyID here always emitted
		// policy_id=0 for every session close. rec.PolicyID is the same field
		// PolicyName resolution and the RT_FLOW_SESSION_CLOSE record already
		// use, so this keeps the slog line consistent with them.
		//
		// #4914: OMIT action on a close. The wire action byte is intentionally
		// 0 for a session close, so actionName(evt.Action) renders "deny" —
		// logging it here classified every normal termination as a drop and
		// drove false drop alerts / broken correlation. The standard and
		// structured RT_FLOW_SESSION_CLOSE lines already omit action (#2513);
		// this generic slog branch was the residual sink still emitting it.
		// Carry the close reason instead, which is what the structured line
		// surfaces.
		slog.Info("firewall event",
			"type", eventName,
			"src", srcStr,
			"dst", dstStr,
			"proto", protoStr,
			"policy_id", rec.PolicyID,
			"reason", rec.CloseReason,
			"ingress_zone", inZone,
			"egress_zone", outZone,
			"session_packets", rec.SessionPkts,
			"session_bytes", rec.SessionBytes)
	} else if evt.EventType == eventTypeScreenDrop {
		slog.Info("firewall event",
			"type", eventName,
			"screen_check", rec.ScreenCheck,
			"src", srcStr,
			"dst", dstStr,
			"proto", protoStr,
			"action", actionStr,
			"ingress_zone", inZone)
	} else {
		slog.Info("firewall event",
			"type", eventName,
			"src", srcStr,
			"dst", dstStr,
			"proto", protoStr,
			"action", actionStr,
			"policy_id", evt.PolicyID,
			"ingress_zone", inZone,
			"egress_zone", outZone)
	}

	// Forward to syslog clients
	er.syslogMu.RLock()
	clients := er.syslogClients
	er.syslogMu.RUnlock()

	if len(clients) > 0 {
		severity := eventSeverity(evt.EventType, evt.Action)
		catBit := eventCategory(evt.EventType)
		// Cache formatted messages lazily per format type
		var stdMsg, structMsg string
		var binMsg []byte
		for _, c := range clients {
			if !c.ShouldSendEvent(severity, catBit) {
				continue
			}
			if c.Format == "binary" {
				if binMsg == nil {
					binMsg = formatBinaryRecord(&evt, &rec, severity, closeReasonCode)
				}
				if err := c.SendBinary(binMsg); err != nil {
					slog.Debug("syslog binary send failed", "err", err)
				}
				continue
			}
			var msg string
			if c.Format == "structured" {
				if structMsg == "" {
					structMsg = formatStructuredMsg(rec, evt.Protocol)
				}
				msg = structMsg
			} else {
				if stdMsg == "" {
					stdMsg = formatSyslogMsg(rec)
				}
				msg = stdMsg
			}
			if err := c.Send(severity, msg); err != nil {
				slog.Debug("syslog send failed", "err", err)
			}
		}
	}

	// Forward to local log writers (event mode)
	er.localMu.RLock()
	localWriters := er.localWriters
	er.localMu.RUnlock()

	if len(localWriters) > 0 {
		severity := eventSeverity(evt.EventType, evt.Action)
		catBit := eventCategory(evt.EventType)
		// Cache formatted bodies lazily per format type, mirroring the syslog
		// fanout above. #3409: the event-mode local writer now honors all four
		// formats instead of branching on `binary` and writing standard text
		// for everything else (which silently no-op'd structured / sd-syslog).
		var stdMsg, structMsg string
		var localBinMsg []byte
		for _, lw := range localWriters {
			if !lw.ShouldSendEvent(severity, catBit) {
				continue
			}
			if lw.Format == "binary" {
				if localBinMsg == nil {
					localBinMsg = formatBinaryRecord(&evt, &rec, severity, closeReasonCode)
				}
				if err := lw.SendBinary(localBinMsg); err != nil {
					slog.Debug("local log binary write failed", "err", err)
				}
				continue
			}
			// Body selection matches the syslog fanout: `structured` emits the
			// Junos RT_FLOW structured body; `sd-syslog` and the standard
			// default share the RFC 3164 body, with sd-syslog wrapped in an
			// RFC 5424 envelope by LocalLogWriter.Send.
			var msg string
			if lw.Format == "structured" {
				if structMsg == "" {
					structMsg = formatStructuredMsg(rec, evt.Protocol)
				}
				msg = structMsg
			} else {
				if stdMsg == "" {
					stdMsg = formatSyslogMsg(rec)
				}
				msg = stdMsg
			}
			if err := lw.Send(severity, msg); err != nil {
				slog.Debug("local log write failed", "err", err)
			}
		}
	}
}

// DecodeRawEventRecord decodes the fixed RT_FLOW event wire shape
// used by the eBPF ring buffer and by the userspace event-stream adapter.
// It is decode-only; transports that need EventBuffer, callback, local-log,
// and syslog fanout must call EventReader.ProcessRawEvent instead.
func DecodeRawEventRecord(data []byte) (EventRecord, bool) {
	if len(data) < rawEventWireSize {
		return EventRecord{}, false
	}

	var evt rawEvent
	evt.Timestamp = binary.LittleEndian.Uint64(data[0:8])
	copy(evt.SrcIP[:], data[8:24])
	copy(evt.DstIP[:], data[24:40])
	evt.SrcPort = binary.BigEndian.Uint16(data[40:42])
	evt.DstPort = binary.BigEndian.Uint16(data[42:44])
	evt.PolicyID = binary.LittleEndian.Uint32(data[44:48])
	evt.IngressZone = binary.LittleEndian.Uint16(data[48:50])
	evt.EgressZone = binary.LittleEndian.Uint16(data[50:52])
	evt.EventType = data[52]
	evt.Protocol = data[53]
	evt.Action = data[54]
	evt.AddrFamily = data[55]
	evt.SessionPackets = binary.LittleEndian.Uint64(data[56:64])
	evt.SessionBytes = binary.LittleEndian.Uint64(data[64:72])
	copy(evt.NATSrcIP[:], data[72:88])
	copy(evt.NATDstIP[:], data[88:104])
	evt.NATSrcPort = binary.BigEndian.Uint16(data[104:106])
	evt.NATDstPort = binary.BigEndian.Uint16(data[106:108])
	evt.Created = binary.LittleEndian.Uint32(data[108:112])
	evt.RevPackets = binary.LittleEndian.Uint64(data[112:120])
	evt.RevBytes = binary.LittleEndian.Uint64(data[120:128])
	evt.IngressIfindex = binary.LittleEndian.Uint32(data[128:132])
	evt.AppID = binary.LittleEndian.Uint16(data[132:134])
	evt.CloseReason = data[134]

	var srcStr, dstStr, natSrcStr, natDstStr string
	switch evt.AddrFamily {
	case addrFamilyInet6:
		srcIP := net.IP(evt.SrcIP[:])
		dstIP := net.IP(evt.DstIP[:])
		srcStr = fmt.Sprintf("[%s]:%d", srcIP, evt.SrcPort)
		dstStr = fmt.Sprintf("[%s]:%d", dstIP, evt.DstPort)
		natSrcIP := net.IP(evt.NATSrcIP[:])
		natDstIP := net.IP(evt.NATDstIP[:])
		natSrcStr = fmt.Sprintf("[%s]:%d", natSrcIP, evt.NATSrcPort)
		natDstStr = fmt.Sprintf("[%s]:%d", natDstIP, evt.NATDstPort)
	case addrFamilyInet:
		srcIP := net.IP(evt.SrcIP[:4])
		dstIP := net.IP(evt.DstIP[:4])
		srcStr = fmt.Sprintf("%s:%d", srcIP, evt.SrcPort)
		dstStr = fmt.Sprintf("%s:%d", dstIP, evt.DstPort)
		natSrcIP := net.IP(evt.NATSrcIP[:4])
		natDstIP := net.IP(evt.NATDstIP[:4])
		natSrcStr = fmt.Sprintf("%s:%d", natSrcIP, evt.NATSrcPort)
		natDstStr = fmt.Sprintf("%s:%d", natDstIP, evt.NATDstPort)
	default:
		return EventRecord{}, false
	}

	rec := EventRecord{
		Time:            eventTimeFromWire(evt.Timestamp),
		Type:            eventTypeName(evt.EventType),
		SrcAddr:         srcStr,
		DstAddr:         dstStr,
		Protocol:        protoName(evt.Protocol),
		ProtocolNum:     evt.Protocol,
		Action:          actionName(evt.Action),
		PolicyID:        evt.PolicyID,
		InZone:          evt.IngressZone,
		OutZone:         evt.EgressZone,
		NATSrcAddr:      natSrcStr,
		NATDstAddr:      natDstStr,
		SessionPkts:     evt.SessionPackets,
		SessionBytes:    evt.SessionBytes,
		RevSessionPkts:  evt.RevPackets,
		RevSessionBytes: evt.RevBytes,
		CloseReason:     closeReasonName(evt.CloseReason),
		// #2465: carry the absolute session-creation Unix seconds so the
		// NetFlow/IPFIX exporters can set a real flow StartTime instead of the
		// packet-count heuristic. 0 = unknown (old frame / synthesized close).
		Created: evt.Created,
	}
	if evt.EventType == eventTypeSessionClose {
		// #2853: the [44:48] policy_id slot is repurposed on a SESSION_CLOSE
		// frame to carry the creation instant's sub-second nanosecond remainder.
		// Reinterpret it as CreatedNanos so the flow exporters keep millisecond
		// StartTime resolution.
		rec.CreatedNanos = evt.PolicyID
		// #3056: the admitting policy ID rides the trailing [136:140] slot on a
		// SESSION_CLOSE (because #2853 took [44:48]). Resolve PolicyID from there
		// so the NetFlow/IPFIX close exporters and any consumer of this decoded
		// record name the admitting policy instead of policy 0. A short (legacy
		// 136-byte) frame already returned false above (len < rawEventWireSize).
		rec.PolicyID = binary.LittleEndian.Uint32(
			data[rawEventPolicyCloseOffset : rawEventPolicyCloseOffset+4])
		// #2749: the class-of-service / interface-attribution block rides the
		// additive [144:152] slots, present only on the extended close frame.
		if len(data) >= rawEventExtSize {
			rec.TOS = data[rawEventTOSOffset]
			rec.TCPControlBits = data[rawEventTCPBitOffset]
			rec.EgressIfindex = binary.LittleEndian.Uint32(
				data[rawEventEgressOffset : rawEventEgressOffset+4])
		}
	}
	if evt.EventType != eventTypeSessionClose {
		rec.SessionPkts = 0
		rec.SessionBytes = 0
		rec.RuleID = binary.LittleEndian.Uint32(data[56:60])
		rec.TermID = binary.LittleEndian.Uint32(data[60:64])
		rec.OwnerRGID = int16(binary.LittleEndian.Uint16(data[64:66]))
		if evt.EventType == eventTypeFilterLog && evt.CloseReason != 0 {
			rec.Reason = filterLogSourceName(evt.CloseReason)
		} else if evt.CloseReason != closeReasonNone {
			rec.Reason = closeReasonName(evt.CloseReason)
		}
	}
	if evt.EventType == eventTypeScreenDrop {
		rec.ScreenCheck = screenFlagName(evt.PolicyID)
	}
	// #4915: the dataplane's stable session id rides the additive [152:160] slot
	// on a SESSION_CREATE / SESSION_CLOSE frame. Read it ONLY when the frame
	// carries the extended length (len >= rawEventSessionIDSize) AND only on a
	// session frame, so a short legacy (<= 152-byte) frame or a non-session event
	// leaves SessionID at its 0 ("unknown") default. This is the SAME id the
	// live logEvent path decodes, so the two producers stay in lockstep.
	if (evt.EventType == eventTypeSessionOpen || evt.EventType == eventTypeSessionClose) &&
		len(data) >= rawEventSessionIDSize {
		rec.SessionID = binary.LittleEndian.Uint64(
			data[rawEventSessionIDOffset : rawEventSessionIDOffset+8])
	}
	return rec, true
}

// eventCategory maps event types to category bitmask values.
func eventCategory(eventType uint8) uint8 {
	switch eventType {
	case eventTypeSessionOpen, eventTypeSessionClose:
		return CategorySession
	case eventTypePolicyDeny:
		return CategoryPolicy
	case eventTypeScreenDrop:
		return CategoryScreen
	case eventTypeFilterLog:
		return CategoryFirewall
	default:
		return CategoryAll // unknown events pass all category filters
	}
}

// eventSeverity maps event types to syslog severity levels.
//
// A screen event must be classified by BOTH type and action (#2298): the
// scan-table-pressure saturation alarm (#2234) is emitted as a screen event
// with action=PERMIT — the packet still forwards, it is an informational
// alarm, not a drop. Logging it at SyslogError is contradictory and would
// page drop-severity alerts. Such an alarm is surfaced at SyslogNotice; only
// a screen event that actually dropped (action=DENY/REJECT) stays at
// SyslogError.
func eventSeverity(eventType, action uint8) int {
	switch eventType {
	case eventTypeScreenDrop:
		if action == actionPermit {
			return SyslogNotice
		}
		return SyslogError
	case eventTypePolicyDeny:
		return SyslogWarning
	case eventTypeFilterLog:
		return SyslogInfo
	default:
		return SyslogInfo
	}
}

// formatSyslogMsg formats an EventRecord as a syslog message body.
func formatSyslogMsg(rec EventRecord) string {
	inZone := rec.InZoneName
	if inZone == "" {
		inZone = fmt.Sprintf("%d", rec.InZone)
	}
	outZone := rec.OutZoneName
	if outZone == "" {
		outZone = fmt.Sprintf("%d", rec.OutZone)
	}
	if rec.Type == "SCREEN_DROP" {
		return fmt.Sprintf("RT_FLOW %s screen=%s src=%s dst=%s proto=%s action=%s zone=%s",
			rec.Type, rec.ScreenCheck, rec.SrcAddr, rec.DstAddr, rec.Protocol, rec.Action, inZone)
	}
	if rec.Type == "SESSION_CLOSE" {
		// A session close is not a forwarding decision, so it carries no
		// permit/deny/reject action (the wire action byte is intentionally 0
		// for closes; see userspace-dp encode_session_close_rt_flow). Rendering
		// the 0 byte via actionName would print action=deny and mislead
		// incident response into reading normal session termination as a drop
		// (#2513). Omit action entirely — like the structured RT_FLOW_SESSION_
		// CLOSE line, which carries a close reason instead. The close reason is
		// surfaced on the structured line; the standard line keeps the volume
		// counters operators use here.
		return fmt.Sprintf("RT_FLOW %s src=%s dst=%s proto=%s policy=%d zone=%s->%s pkts=%d bytes=%d",
			rec.Type, rec.SrcAddr, rec.DstAddr, rec.Protocol,
			rec.PolicyID, inZone, outZone, rec.SessionPkts, rec.SessionBytes)
	}
	if rec.Type == "SESSION_OPEN" {
		// A session open (RT_FLOW_SESSION_CREATE) is a permit-and-create
		// event, not a forwarding decision, so it carries no permit/deny/
		// reject action (the wire action byte is intentionally 0 for creates;
		// see userspace-dp encode_session_create_rt_flow). Rendering the 0
		// byte via actionName would print action=deny and mislead incident
		// response into reading a successful permit-and-open as a drop (#2593,
		// the SESSION_CREATE sibling of #2513). Omit action entirely — like
		// the structured RT_FLOW_SESSION_CREATE line, which never carried one.
		// The standard line keeps the proto/policy/zone fields operators read.
		return fmt.Sprintf("RT_FLOW %s src=%s dst=%s proto=%s policy=%d zone=%s->%s",
			rec.Type, rec.SrcAddr, rec.DstAddr, rec.Protocol,
			rec.PolicyID, inZone, outZone)
	}
	if rec.Type == "FILTER_LOG" {
		source := rec.Reason
		if source == "" {
			source = "unknown"
		}
		return fmt.Sprintf("RT_FLOW %s src=%s dst=%s proto=%s action=%s zone=%s->%s source=%s filter=%d term=%d",
			rec.Type, rec.SrcAddr, rec.DstAddr, rec.Protocol, rec.Action,
			inZone, outZone, source, rec.RuleID, rec.TermID)
	}
	return fmt.Sprintf("RT_FLOW %s src=%s dst=%s proto=%s action=%s policy=%d zone=%s->%s",
		rec.Type, rec.SrcAddr, rec.DstAddr, rec.Protocol, rec.Action,
		rec.PolicyID, inZone, outZone)
}

// formatStructuredMsg formats an EventRecord as a Junos-compatible structured
// syslog message with RT_FLOW_SESSION_CREATE/CLOSE/DENY event tags.
// Output matches vSRX RT_FLOW format with [junos@2636.1.1.1.2.129 ...] wrapping.
func formatStructuredMsg(rec EventRecord, protoNum uint8) string {
	// Split addr:port pairs
	srcIP, srcPort := splitAddrPort(rec.SrcAddr)
	dstIP, dstPort := splitAddrPort(rec.DstAddr)
	natSrcIP, natSrcPort := splitAddrPort(rec.NATSrcAddr)
	natDstIP, natDstPort := splitAddrPort(rec.NATDstAddr)

	policyName := rec.PolicyName
	if policyName == "" {
		policyName = fmt.Sprintf("%d", rec.PolicyID)
	}
	appName := rec.AppName
	if appName == "" {
		appName = "UNKNOWN"
	}
	inIface := rec.IngressIface
	if inIface == "" {
		inIface = "N/A"
	}

	switch rec.Type {
	case "SESSION_OPEN":
		return fmt.Sprintf("RT_FLOW - RT_FLOW_SESSION_CREATE "+
			"[junos@2636.1.1.1.2.129 "+
			"source-address=\"%s\" source-port=\"%s\" "+
			"destination-address=\"%s\" destination-port=\"%s\" "+
			"connection-tag=\"0\" service-name=\"%s\" "+
			"nat-source-address=\"%s\" nat-source-port=\"%s\" "+
			"nat-destination-address=\"%s\" nat-destination-port=\"%s\" "+
			"nat-connection-tag=\"0\" "+
			"src-nat-rule-type=\"N/A\" src-nat-rule-name=\"N/A\" "+
			"dst-nat-rule-type=\"N/A\" dst-nat-rule-name=\"N/A\" "+
			"protocol-id=\"%d\" policy-name=\"%s\" "+
			"source-zone-name=\"%s\" destination-zone-name=\"%s\" "+
			"session-id=\"%d\" "+
			"username=\"N/A\" roles=\"N/A\" "+
			"packet-incoming-interface=\"%s\" application=\"%s\"]",
			srcIP, srcPort, dstIP, dstPort,
			appName,
			natSrcIP, natSrcPort, natDstIP, natDstPort,
			protoNum, policyName,
			rec.InZoneName, rec.OutZoneName,
			rec.SessionID,
			inIface, appName)

	case "SESSION_CLOSE":
		reason := rec.CloseReason
		if reason == "" {
			reason = "N/A"
		}
		return fmt.Sprintf("RT_FLOW - RT_FLOW_SESSION_CLOSE "+
			"[junos@2636.1.1.1.2.129 "+
			"reason=\"%s\" "+
			"source-address=\"%s\" source-port=\"%s\" "+
			"destination-address=\"%s\" destination-port=\"%s\" "+
			"connection-tag=\"0\" service-name=\"%s\" "+
			"nat-source-address=\"%s\" nat-source-port=\"%s\" "+
			"nat-destination-address=\"%s\" nat-destination-port=\"%s\" "+
			"nat-connection-tag=\"0\" "+
			"src-nat-rule-type=\"N/A\" src-nat-rule-name=\"N/A\" "+
			"dst-nat-rule-type=\"N/A\" dst-nat-rule-name=\"N/A\" "+
			"protocol-id=\"%d\" policy-name=\"%s\" "+
			"source-zone-name=\"%s\" destination-zone-name=\"%s\" "+
			"session-id=\"%d\" "+
			"packets-from-client=\"%d\" bytes-from-client=\"%d\" "+
			"packets-from-server=\"%d\" bytes-from-server=\"%d\" "+
			"elapsed-time=\"%d\" "+
			"packet-incoming-interface=\"%s\" application=\"%s\"]",
			reason,
			srcIP, srcPort, dstIP, dstPort,
			appName,
			natSrcIP, natSrcPort, natDstIP, natDstPort,
			protoNum, policyName,
			rec.InZoneName, rec.OutZoneName,
			rec.SessionID,
			rec.SessionPkts, rec.SessionBytes,
			rec.RevSessionPkts, rec.RevSessionBytes,
			rec.ElapsedTime,
			inIface, appName)

	case "POLICY_DENY":
		// #3610: render the on-wire reason instead of a hardcoded string. For a
		// transit security-policy deny the reason byte is closeReasonPolicy, so
		// rec.Reason is "Rejected by policy" — byte-identical to the prior output.
		// For a host-inbound-traffic admission deny the byte is
		// closeReasonHostInbound, so the record shows "Denied by
		// host-inbound-traffic", letting incident response tell a control-plane
		// host-inbound drop apart from a transit policy deny (was conflated).
		reason := rec.Reason
		if reason == "" {
			reason = "Rejected by policy"
		}
		return fmt.Sprintf("RT_FLOW - RT_FLOW_SESSION_DENY "+
			"[junos@2636.1.1.1.2.129 "+
			"source-address=\"%s\" source-port=\"%s\" "+
			"destination-address=\"%s\" destination-port=\"%s\" "+
			"connection-tag=\"0\" service-name=\"None\" "+
			"protocol-id=\"%d\" policy-name=\"%s\" "+
			"source-zone-name=\"%s\" destination-zone-name=\"%s\" "+
			"session-id=\"%d\" "+
			"packet-incoming-interface=\"%s\" application=\"%s\" "+
			"reason=\"%s\"]",
			srcIP, srcPort, dstIP, dstPort,
			protoNum, policyName,
			rec.InZoneName, rec.OutZoneName,
			rec.SessionID,
			inIface, appName, reason)

	default:
		return formatSyslogMsg(rec)
	}
}

// splitAddrPort splits "10.0.1.5:443" or "[::1]:443" into IP and port strings.
func splitAddrPort(addr string) (string, string) {
	if addr == "" {
		return "0.0.0.0", "0"
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, "0"
	}
	return host, port
}

func eventTypeName(t uint8) string {
	switch t {
	case eventTypeSessionOpen:
		return "SESSION_OPEN"
	case eventTypeSessionClose:
		return "SESSION_CLOSE"
	case eventTypePolicyDeny:
		return "POLICY_DENY"
	case eventTypeScreenDrop:
		return "SCREEN_DROP"
	case eventTypeFilterLog:
		return "FILTER_LOG"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", t)
	}
}

func filterLogSourceName(reason uint8) string {
	switch reason {
	case 1:
		return "pbr"
	case 2:
		return "input"
	case 3:
		return "output"
	case 4:
		return "cached-output"
	case 5:
		return "lo0"
	default:
		return fmt.Sprintf("unknown(%d)", reason)
	}
}

func actionName(a uint8) string {
	switch a {
	case actionPermit:
		return "permit"
	case actionDeny:
		return "deny"
	case actionReject:
		return "reject"
	default:
		return fmt.Sprintf("unknown(%d)", a)
	}
}

// protoName renders an IP protocol number for the security event log (RT_FLOW /
// ring buffer surface). The named protocol SET is owned by appid.ProtocolName
// (the #2949/#3037 SSOT shared with REST, gRPC, and the app-id catalog) so
// GRE/ESP/IPIP/IPv6 sessions display named (gre/esp/ipip/ipv6) instead of
// numeric, matching the other operator surfaces (#3040). Casing is an
// event-log-local concern: this surface has always rendered upper-case
// (TCP/UDP/ICMP/ICMPv6), so the canonical lowercase name is upper-cased here.
// ICMPv6 keeps its mixed-case spelling to match the historical rendering (the
// trace-filter contract test asserts "ICMPv6"). Unknown protocols fall back to
// the numeric form the old 4-protocol helper used.
func protoName(p uint8) string {
	name := appid.ProtocolName(p)
	if name == "" {
		return fmt.Sprintf("%d", p)
	}
	if p == protoICMPv6 {
		return "ICMPv6"
	}
	return strings.ToUpper(name)
}

func screenFlagName(flag uint32) string {
	if name, ok := screenFlagNames[flag]; ok {
		return name
	}
	return fmt.Sprintf("screen(0x%x)", flag)
}

// Binary log format constants.
const (
	binaryLogMagicHi    = 0xBF
	binaryLogMagicLo    = 0x52
	binaryLogVersion    = 1
	binaryLogHeaderSize = 143 // fixed portion before variable-length strings
)

// formatBinaryRecord encodes an event into a compact binary log record.
//
// Wire format:
//
//	Fixed header (143 bytes):
//	  [0:2]     Magic 0xBF52 (big-endian)
//	  [2]       Version (1)
//	  [3:5]     Total record length (uint16 big-endian, includes header)
//	  [5]       EventType
//	  [6]       Protocol number
//	  [7]       Action (0=deny, 1=permit, 2=reject, 255=n/a for a
//	            SESSION_CLOSE, which carries no forwarding decision)
//	  [8]       AddrFamily (2=IPv4, 10=IPv6)
//	  [9]       Severity (syslog level)
//	  [10:18]   Timestamp (uint64 LE, Unix nanoseconds)
//	  [18:34]   SrcIP [16]byte
//	  [34:50]   DstIP [16]byte
//	  [50:52]   SrcPort (big-endian)
//	  [52:54]   DstPort (big-endian)
//	  [54:58]   PolicyID (LE)
//	  [58:60]   IngressZone ID (LE)
//	  [60:62]   EgressZone ID (LE)
//	  [62:78]   NATSrcIP [16]byte
//	  [78:94]   NATDstIP [16]byte
//	  [94:96]   NATSrcPort (big-endian)
//	  [96:98]   NATDstPort (big-endian)
//	  [98:106]  SessionPkts (LE)
//	  [106:114] SessionBytes (LE)
//	  [114:122] RevSessionPkts (LE)
//	  [122:130] RevSessionBytes (LE)
//	  [130:134] ElapsedTime seconds (LE)
//	  [134:142] SessionID (LE)
//	  [142]     CloseReason code
//	Variable section (uint8 length + UTF-8 bytes each):
//	  InZoneName, OutZoneName, PolicyName, AppName, IngressIface
func formatBinaryRecord(evt *rawEvent, rec *EventRecord, severity int, closeReason uint8) []byte {
	inZone := truncStr(rec.InZoneName, 255)
	outZone := truncStr(rec.OutZoneName, 255)
	policyName := truncStr(rec.PolicyName, 255)
	appName := truncStr(rec.AppName, 255)
	iface := truncStr(rec.IngressIface, 255)

	varLen := 5 + len(inZone) + len(outZone) + len(policyName) + len(appName) + len(iface)
	totalLen := binaryLogHeaderSize + varLen

	buf := make([]byte, totalLen)

	// Magic (big-endian)
	buf[0] = binaryLogMagicHi
	buf[1] = binaryLogMagicLo
	// Version
	buf[2] = binaryLogVersion
	// Total record length (big-endian)
	binary.BigEndian.PutUint16(buf[3:5], uint16(totalLen))
	// Event fields
	buf[5] = evt.EventType
	buf[6] = evt.Protocol
	// #4914: a SESSION_CLOSE carries no forwarding decision — its wire action
	// byte is intentionally 0, which as a raw actionDeny would tell a binary
	// forensic consumer that a normal termination was a drop. Flag it "not
	// applicable" so tooling does not attribute closes to a deny. Every other
	// event type keeps its real action byte.
	if evt.EventType == eventTypeSessionClose {
		buf[7] = actionNotApplicable
	} else {
		buf[7] = evt.Action
	}
	buf[8] = evt.AddrFamily
	buf[9] = uint8(severity)
	// Timestamp
	binary.LittleEndian.PutUint64(buf[10:18], uint64(rec.Time.UnixNano()))
	// IPs (raw bytes, network order)
	copy(buf[18:34], evt.SrcIP[:])
	copy(buf[34:50], evt.DstIP[:])
	// Ports (big-endian, as parsed from BPF)
	binary.BigEndian.PutUint16(buf[50:52], evt.SrcPort)
	binary.BigEndian.PutUint16(buf[52:54], evt.DstPort)
	// PolicyID. #4914: encode rec.PolicyID, not evt.PolicyID. They match for
	// every non-close frame, but on a SESSION_CLOSE evt.PolicyID was zeroed by
	// logEvent (#2853 repurposes the [44:48] slot for the created-subsec-nanos)
	// and only rec.PolicyID carries the admitting policy from the trailing
	// [136:140] slot (#3056). Encoding evt.PolicyID stamped policy_id=0 on every
	// binary session-close record; rec.PolicyID matches the resolved PolicyName
	// and the standard/structured RT_FLOW_SESSION_CLOSE lines.
	binary.LittleEndian.PutUint32(buf[54:58], rec.PolicyID)
	// Zone IDs
	binary.LittleEndian.PutUint16(buf[58:60], evt.IngressZone)
	binary.LittleEndian.PutUint16(buf[60:62], evt.EgressZone)
	// NAT IPs
	copy(buf[62:78], evt.NATSrcIP[:])
	copy(buf[78:94], evt.NATDstIP[:])
	// NAT ports
	binary.BigEndian.PutUint16(buf[94:96], evt.NATSrcPort)
	binary.BigEndian.PutUint16(buf[96:98], evt.NATDstPort)
	// Session stats
	binary.LittleEndian.PutUint64(buf[98:106], rec.SessionPkts)
	binary.LittleEndian.PutUint64(buf[106:114], rec.SessionBytes)
	binary.LittleEndian.PutUint64(buf[114:122], rec.RevSessionPkts)
	binary.LittleEndian.PutUint64(buf[122:130], rec.RevSessionBytes)
	// Elapsed time
	binary.LittleEndian.PutUint32(buf[130:134], rec.ElapsedTime)
	// Session ID
	binary.LittleEndian.PutUint64(buf[134:142], rec.SessionID)
	// Close reason
	buf[142] = closeReason

	// Variable section: length-prefixed strings
	off := binaryLogHeaderSize
	off = putLenStr(buf, off, inZone)
	off = putLenStr(buf, off, outZone)
	off = putLenStr(buf, off, policyName)
	off = putLenStr(buf, off, appName)
	putLenStr(buf, off, iface)

	return buf
}

func truncStr(s string, max int) string {
	if len(s) > max {
		return s[:max]
	}
	return s
}

func putLenStr(buf []byte, off int, s string) int {
	buf[off] = uint8(len(s))
	copy(buf[off+1:], s)
	return off + 1 + len(s)
}

func closeReasonName(reason uint8) string {
	switch reason {
	case closeReasonTimeout:
		return "idle Timeout"
	case closeReasonTCPFIN:
		return "TCP FIN"
	case closeReasonTCPRST:
		return "TCP RST"
	case closeReasonAgeOut:
		return "aged out"
	case closeReasonPolicy:
		return "Rejected by policy"
	case closeReasonHostInbound:
		// #3610: a control-plane host-inbound-traffic admission deny (distinct
		// from a transit security-policy deny).
		return "Denied by host-inbound-traffic"
	default:
		return "N/A"
	}
}
