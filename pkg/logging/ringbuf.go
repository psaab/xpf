// Package logging implements dataplane event reading.
package logging

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/psaab/xpf/pkg/dataplane"
)

// EventCallback is called for each processed event record.
type EventCallback func(rec EventRecord, raw []byte)

// EventReader reads events from a dataplane EventSource.
type EventReader struct {
	source        dataplane.EventSource
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
	sessionSeq    uint64            // monotonic session ID counter
}

// NewEventReader creates a new event reader for the given event source.
func NewEventReader(source dataplane.EventSource, buffer *EventBuffer) *EventReader {
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

// SetSyslogClients replaces the set of syslog clients (goroutine-safe).
func (er *EventReader) SetSyslogClients(clients []*SyslogClient) {
	er.syslogMu.Lock()
	er.syslogClients = clients
	er.syslogMu.Unlock()
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
		_ = lw.Send(severity, msg)
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

		if len(data) < int(unsafe.Sizeof(dataplane.Event{})) {
			continue
		}

		er.logEvent(data)
	}
}

func (er *EventReader) logEvent(data []byte) {
	var evt dataplane.Event
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
	if evt.AddrFamily == dataplane.AFInet6 {
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

	// Build EventRecord
	rec := EventRecord{
		Time:        time.Now(),
		Type:        eventName,
		SrcAddr:     srcStr,
		DstAddr:     dstStr,
		Protocol:    protoStr,
		Action:      actionStr,
		PolicyID:    evt.PolicyID,
		InZone:      evt.IngressZone,
		OutZone:     evt.EgressZone,
		NATSrcAddr:  natSrcStr,
		NATDstAddr:  natDstStr,
		InZoneName:  er.resolveZoneName(evt.IngressZone),
		OutZoneName: er.resolveZoneName(evt.EgressZone),
	}

	if evt.EventType == dataplane.EventTypeSessionClose {
		rec.SessionPkts = binary.LittleEndian.Uint64(data[56:64])
		rec.SessionBytes = binary.LittleEndian.Uint64(data[64:72])
		// Compute elapsed time from session creation
		if evt.Created > 0 {
			nowSec := uint32(evt.Timestamp / 1000000000)
			if nowSec > evt.Created {
				rec.ElapsedTime = nowSec - evt.Created
			}
		}
	}
	if evt.EventType == dataplane.EventTypeScreenDrop {
		rec.ScreenCheck = screenFlagName(evt.PolicyID)
	}

	// Parse extended fields (offset 112+)
	var closeReasonCode uint8
	if len(data) >= 136 {
		rec.RevSessionPkts = binary.LittleEndian.Uint64(data[112:120])
		rec.RevSessionBytes = binary.LittleEndian.Uint64(data[120:128])
		ifindex := binary.LittleEndian.Uint32(data[128:132])
		appID := binary.LittleEndian.Uint16(data[132:134])
		closeReasonCode = data[134]

		rec.IngressIface = er.resolveIfName(ifindex)
		rec.AppName = er.resolveAppName(appID)
		rec.CloseReason = closeReasonName(closeReasonCode)
	}

	// Resolve policy name (skip for screen drops which repurpose policy_id)
	if evt.EventType != dataplane.EventTypeScreenDrop {
		rec.PolicyName = er.resolvePolicyName(evt.PolicyID)
	}

	// Assign monotonic session ID
	rec.SessionID = atomic.AddUint64(&er.sessionSeq, 1)

	// Store in buffer
	if er.buffer != nil {
		er.buffer.Add(rec)
	}

	// Invoke registered callbacks
	er.callbackMu.RLock()
	cbs := er.callbacks
	er.callbackMu.RUnlock()
	for _, cb := range cbs {
		cb(rec, data)
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
	if evt.EventType == dataplane.EventTypeSessionClose {
		slog.Info("firewall event",
			"type", eventName,
			"src", srcStr,
			"dst", dstStr,
			"proto", protoStr,
			"action", actionStr,
			"policy_id", evt.PolicyID,
			"ingress_zone", inZone,
			"egress_zone", outZone,
			"session_packets", rec.SessionPkts,
			"session_bytes", rec.SessionBytes)
	} else if evt.EventType == dataplane.EventTypeScreenDrop {
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
		severity := eventSeverity(evt.EventType)
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
		severity := eventSeverity(evt.EventType)
		catBit := eventCategory(evt.EventType)
		var stdMsg string
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
			if stdMsg == "" {
				stdMsg = formatSyslogMsg(rec)
			}
			if err := lw.Send(severity, stdMsg); err != nil {
				slog.Debug("local log write failed", "err", err)
			}
		}
	}
}

// DecodeRawEventRecord decodes the fixed dataplane.Event RT_FLOW wire shape
// used by the eBPF ring buffer and by the userspace event-stream adapter. It
// intentionally skips name resolution and syslog fanout; callers receiving the
// same wire payload over a non-ringbuf transport can feed the normal
// EventBuffer without inventing a second event schema.
func DecodeRawEventRecord(data []byte) (EventRecord, bool) {
	if len(data) < int(unsafe.Sizeof(dataplane.Event{})) {
		return EventRecord{}, false
	}

	var evt dataplane.Event
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
	case dataplane.AFInet6:
		srcIP := net.IP(evt.SrcIP[:])
		dstIP := net.IP(evt.DstIP[:])
		srcStr = fmt.Sprintf("[%s]:%d", srcIP, evt.SrcPort)
		dstStr = fmt.Sprintf("[%s]:%d", dstIP, evt.DstPort)
		natSrcIP := net.IP(evt.NATSrcIP[:])
		natDstIP := net.IP(evt.NATDstIP[:])
		natSrcStr = fmt.Sprintf("[%s]:%d", natSrcIP, evt.NATSrcPort)
		natDstStr = fmt.Sprintf("[%s]:%d", natDstIP, evt.NATDstPort)
	case dataplane.AFInet:
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
		Time:            time.Now(),
		Type:            eventTypeName(evt.EventType),
		SrcAddr:         srcStr,
		DstAddr:         dstStr,
		Protocol:        protoName(evt.Protocol),
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
	}
	if evt.Timestamp > 0 && evt.Timestamp <= uint64(1<<63-1) {
		rec.Time = time.Unix(0, int64(evt.Timestamp))
	}
	if evt.EventType == dataplane.EventTypeScreenDrop {
		rec.ScreenCheck = screenFlagName(evt.PolicyID)
	}
	return rec, true
}

// eventCategory maps event types to category bitmask values.
func eventCategory(eventType uint8) uint8 {
	switch eventType {
	case dataplane.EventTypeSessionOpen, dataplane.EventTypeSessionClose:
		return CategorySession
	case dataplane.EventTypePolicyDeny:
		return CategoryPolicy
	case dataplane.EventTypeScreenDrop:
		return CategoryScreen
	case dataplane.EventTypeFilterLog:
		return CategoryFirewall
	default:
		return CategoryAll // unknown events pass all category filters
	}
}

// eventSeverity maps event types to syslog severity levels.
func eventSeverity(eventType uint8) int {
	switch eventType {
	case dataplane.EventTypeScreenDrop:
		return SyslogError
	case dataplane.EventTypePolicyDeny:
		return SyslogWarning
	case dataplane.EventTypeFilterLog:
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
		return fmt.Sprintf("RT_FLOW %s src=%s dst=%s proto=%s action=%s policy=%d zone=%s->%s pkts=%d bytes=%d",
			rec.Type, rec.SrcAddr, rec.DstAddr, rec.Protocol, rec.Action,
			rec.PolicyID, inZone, outZone, rec.SessionPkts, rec.SessionBytes)
	}
	if rec.Type == "FILTER_LOG" {
		return fmt.Sprintf("RT_FLOW %s src=%s dst=%s proto=%s action=%s zone=%s",
			rec.Type, rec.SrcAddr, rec.DstAddr, rec.Protocol, rec.Action, inZone)
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
		return fmt.Sprintf("RT_FLOW - RT_FLOW_SESSION_DENY "+
			"[junos@2636.1.1.1.2.129 "+
			"source-address=\"%s\" source-port=\"%s\" "+
			"destination-address=\"%s\" destination-port=\"%s\" "+
			"connection-tag=\"0\" service-name=\"None\" "+
			"protocol-id=\"%d\" policy-name=\"%s\" "+
			"source-zone-name=\"%s\" destination-zone-name=\"%s\" "+
			"session-id=\"%d\" "+
			"packet-incoming-interface=\"%s\" application=\"%s\" "+
			"reason=\"Rejected by policy\"]",
			srcIP, srcPort, dstIP, dstPort,
			protoNum, policyName,
			rec.InZoneName, rec.OutZoneName,
			rec.SessionID,
			inIface, appName)

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
	case dataplane.EventTypeSessionOpen:
		return "SESSION_OPEN"
	case dataplane.EventTypeSessionClose:
		return "SESSION_CLOSE"
	case dataplane.EventTypePolicyDeny:
		return "POLICY_DENY"
	case dataplane.EventTypeScreenDrop:
		return "SCREEN_DROP"
	case dataplane.EventTypeFilterLog:
		return "FILTER_LOG"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", t)
	}
}

func actionName(a uint8) string {
	switch a {
	case dataplane.ActionPermit:
		return "permit"
	case dataplane.ActionDeny:
		return "deny"
	case dataplane.ActionReject:
		return "reject"
	default:
		return fmt.Sprintf("unknown(%d)", a)
	}
}

func protoName(p uint8) string {
	switch p {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 1:
		return "ICMP"
	case dataplane.ProtoICMPv6:
		return "ICMPv6"
	default:
		return fmt.Sprintf("%d", p)
	}
}

func screenFlagName(flag uint32) string {
	if name, ok := dataplane.ScreenFlagNames[flag]; ok {
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
//	  [7]       Action (0=permit, 1=deny, 2=reject)
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
func formatBinaryRecord(evt *dataplane.Event, rec *EventRecord, severity int, closeReason uint8) []byte {
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
	buf[7] = evt.Action
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
	// PolicyID
	binary.LittleEndian.PutUint32(buf[54:58], evt.PolicyID)
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
	case dataplane.CloseReasonTimeout:
		return "idle Timeout"
	case dataplane.CloseReasonTCPFIN:
		return "TCP FIN"
	case dataplane.CloseReasonTCPRST:
		return "TCP RST"
	case dataplane.CloseReasonAgeOut:
		return "aged out"
	case dataplane.CloseReasonPolicy:
		return "Rejected by policy"
	default:
		return "N/A"
	}
}
