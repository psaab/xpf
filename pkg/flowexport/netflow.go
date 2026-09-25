package flowexport

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/psaab/xpf/pkg/logging"
	"golang.org/x/sys/unix"
)

// bootTimeFunc resolves the device boot instant used as the NetFlow v9
// sysUptime reference (the NetFlow v9 header SysUptime and the FirstSwitched /
// LastSwitched record fields are all "system uptime" relative — RFC 3954 §5.1
// / §8). It is a seam so tests can inject a deterministic boot time. Defaults
// to systemBootTime; overridden only by tests.
var bootTimeFunc = systemBootTime

// systemBootTime returns the wall-clock instant the machine booted, computed
// from CLOCK_BOOTTIME (seconds-since-boot) subtracted from now (#4423 M13).
//
// The exporter previously anchored sysUptime at time.Now() taken when the
// exporter was CONSTRUCTED. After a daemon restart (config commit, crash
// recovery, HA failback) that anchor moves forward to the restart instant, so
// any flow that STARTED before the restart — a long-lived session, an
// HA-synced session carrying an earlier creation timestamp — has StartTime
// earlier than the anchor and uptimeMs clamps its FirstSwitched to 0,
// truncating the flow age to "at boot". Anchoring at the real device boot
// (which predates every session) makes FirstSwitched/LastSwitched and the
// header SysUptime carry the true device-relative uptime instead. On the rare
// error path we fall back to time.Now() (the pre-fix behaviour), never a zero
// time.
func systemBootTime() time.Time {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return time.Now()
	}
	uptime := time.Duration(ts.Sec)*time.Second + time.Duration(ts.Nsec)*time.Nanosecond
	if uptime <= 0 {
		return time.Now()
	}
	return time.Now().Add(-uptime)
}

// NetFlow v9 field type IDs (RFC 3954).
const (
	fieldInBytes       = 1
	fieldInPkts        = 2
	fieldProtocol      = 4
	fieldSrcTos        = 5
	fieldTCPFlags      = 6
	fieldL4SrcPort     = 7
	fieldIPv4SrcAddr   = 8
	fieldSrcMask       = 9
	fieldInputSNMP     = 10
	fieldL4DstPort     = 11
	fieldIPv4DstAddr   = 12
	fieldDstMask       = 13
	fieldOutputSNMP    = 14
	fieldLastSwitched  = 21
	fieldFirstSwitched = 22
	fieldIPv6SrcAddr   = 27
	fieldIPv6DstAddr   = 28
	fieldIPv6SrcMask   = 29
	fieldIPv6DstMask   = 30
	fieldDirection     = 61
	fieldIPv4Ident     = 54
	// RFC 5103 / RFC 8158 post-NAT (translated) tuple. NetFlow v9 templates
	// carry the same IANA element type IDs as IPFIX (#2526). IPv4 addresses
	// 225/226 (4B), transport ports 227/228 (2B, family-agnostic), IPv6
	// addresses 281/282 (16B).
	fieldPostNatSrcIPv4   = 225
	fieldPostNatDstIPv4   = 226
	fieldPostNapatSrcPort = 227
	fieldPostNapatDstPort = 228
	fieldPostNatSrcIPv6   = 281
	fieldPostNatDstIPv6   = 282
)

// Template IDs for IPv4 and IPv6.
const (
	templateIDv4 = 256
	templateIDv6 = 257
)

// flowsetIDTemplate is the FlowSet ID for template records.
const flowsetIDTemplate = 0

// Maximum UDP payload size for NetFlow packets.
const maxPayload = 1400

// templateField describes a single field in a v9 template.
type templateField struct {
	fieldType uint16
	fieldLen  uint16
}

// V9TemplateOptions controls which optional fields are included in v9
// templates.
//
// #3270: IncludeFlowDir toggles fieldDirection (IE 61) in the v9 template
// again. Unlike the pre-#2613 version (which exported a synthetic zero), the
// field now carries a REAL per-flow value derived in Go from the per-zone
// sampling-direction (ExportConfig.FlowDirection): a flow whose ingress zone
// has `sampling input` is ingress (0), a flow selected only by its egress
// zone's `sampling output` is egress (1). It is opt-in: only a template that
// configured `export-extension flow-dir` advertises IE 61, so a config that
// did not request it keeps the field absent (no synthetic-zero regression).
type V9TemplateOptions struct {
	IncludeFlowDir bool // #3270: advertise + populate flowDirection (IE 61)
}

// netflowTemplateFieldsV4/V6 are the BASE templates (flow-dir absent), emitted
// when `export-extension flow-dir` is not configured. #2613 dropped
// SrcTos/TCPFlags/Direction/InputSNMP/OutputSNMP; #2749 re-introduced
// SrcTos/TCPFlags/InputSNMP/OutputSNMP with real values; #3270 re-introduces
// flowDirection (IE 61) but only conditionally — buildTemplateFieldsV4/V6
// splice it in before the post-NAT trailer when IncludeFlowDir is set, so the
// base slices stay flow-dir-free.
var (
	netflowTemplateFieldsV4 = []templateField{
		{fieldIPv4SrcAddr, 4},
		{fieldIPv4DstAddr, 4},
		{fieldL4SrcPort, 2},
		{fieldL4DstPort, 2},
		{fieldProtocol, 1},
		{fieldInPkts, 8},
		{fieldInBytes, 8},
		{fieldFirstSwitched, 4},
		{fieldLastSwitched, 4},
		{fieldSrcMask, 1},
		{fieldDstMask, 1},
		// #2749: ingressInterface (IN_SNMP, IE 10) re-introduced with a REAL
		// value — the ingress ifindex carried on the SESSION_CLOSE frame
		// since #2615. Placed before the post-NAT tuple so the latter stays
		// the trailing block (#2526 invariant); the proto->packet-counter
		// adjacency the #2613 fail-on-revert pin checks is preserved either way.
		{fieldInputSNMP, 4},
		// #2749: class-of-service + egress interface re-introduced with REAL
		// values from the extended SESSION_CLOSE frame ([144:152]). srcTos
		// (IE 5, 1B) = forward DSCP<<2; tcpFlags (IE 6, 1B) = cumulative TCP
		// control bits; OutputSNMP (IE 14, 4B) = egress ifindex. Placed after
		// ingressInterface and before the post-NAT tuple so the latter stays
		// the trailing block (#2526) and the proto->packet-counter adjacency the
		// #2613 fail-on-revert pin checks is preserved. #3270: flowDirection
		// (IE 61) is NOT in this base slice — buildTemplateFieldsV4 splices it
		// in (just after OutputSNMP, before the post-NAT trailer) when
		// IncludeFlowDir is set.
		{fieldSrcTos, 1},
		{fieldTCPFlags, 1},
		{fieldOutputSNMP, 4},
		// #2526: post-NAT (translated) tuple, appended last.
		{fieldPostNatSrcIPv4, 4},
		{fieldPostNatDstIPv4, 4},
		{fieldPostNapatSrcPort, 2},
		{fieldPostNapatDstPort, 2},
	}
	netflowTemplateFieldsV6 = []templateField{
		{fieldIPv6SrcAddr, 16},
		{fieldIPv6DstAddr, 16},
		{fieldL4SrcPort, 2},
		{fieldL4DstPort, 2},
		{fieldProtocol, 1},
		{fieldInPkts, 8},
		{fieldInBytes, 8},
		{fieldFirstSwitched, 4},
		{fieldLastSwitched, 4},
		{fieldIPv6SrcMask, 1},
		{fieldIPv6DstMask, 1},
		// #2749: ingressInterface (IN_SNMP, IE 10) — see the V4 template note.
		{fieldInputSNMP, 4},
		// #2749: srcTos (IE 5) / tcpFlags (IE 6) / OutputSNMP (IE 14) — see V4.
		{fieldSrcTos, 1},
		{fieldTCPFlags, 1},
		{fieldOutputSNMP, 4},
		// #2526: post-NAT (translated) tuple, appended last (v6 addrs 16B).
		{fieldPostNatSrcIPv6, 16},
		{fieldPostNatDstIPv6, 16},
		{fieldPostNapatSrcPort, 2},
		{fieldPostNapatDstPort, 2},
	}
)

// DefaultV9TemplateOptions returns the default template options: flow-dir is
// OFF (#3270). flow-dir is opt-in via `export-extension flow-dir`, so the
// default template matches a config that did not request any extension.
func DefaultV9TemplateOptions() V9TemplateOptions {
	return V9TemplateOptions{IncludeFlowDir: false}
}

// spliceFlowDir returns base with a {fieldDirection,1} field inserted before
// the trailing post-NAT block (the first IE >= fieldPostNatSrcIPv4), keeping
// the #2526 post-NAT trailer last. base is not mutated.
func spliceFlowDir(base []templateField) []templateField {
	idx := len(base)
	for i, f := range base {
		if f.fieldType >= fieldPostNatSrcIPv4 {
			idx = i
			break
		}
	}
	out := make([]templateField, 0, len(base)+1)
	out = append(out, base[:idx]...)
	out = append(out, templateField{fieldDirection, 1})
	out = append(out, base[idx:]...)
	return out
}

// buildTemplateFieldsV4 returns the IPv4 template fields. #3270: flowDirection
// (IE 61) is spliced in before the post-NAT trailer when IncludeFlowDir is set.
func buildTemplateFieldsV4(opts V9TemplateOptions) []templateField {
	if opts.IncludeFlowDir {
		return spliceFlowDir(netflowTemplateFieldsV4)
	}
	return netflowTemplateFieldsV4
}

// buildTemplateFieldsV6 returns the IPv6 template fields. See buildTemplateFieldsV4.
func buildTemplateFieldsV6(opts V9TemplateOptions) []templateField {
	if opts.IncludeFlowDir {
		return spliceFlowDir(netflowTemplateFieldsV6)
	}
	return netflowTemplateFieldsV6
}

// recordSize computes the data record size from template fields: the plain
// sum of the field lengths, with NO per-record padding.
//
// This is deliberately the UNPADDED width — it equals what the template FlowSet
// advertises (each field's real fieldLen) and therefore the stride a
// standards-compliant collector uses to walk consecutive records. Per RFC 3954
// a Data FlowSet's records are contiguous at the template-advertised width;
// only the ENCLOSING FlowSet may carry terminal padding to a 32-bit boundary
// (added once in dataFlowSetLen). Padding each record here (the #4896 bug) put
// 2-3 zero bytes between records while the template still advertised the
// unpadded width, so every record after the first was misdecoded by the
// collector. The IPFIX sibling (ipfixRecordSize / ipfixDataSetLen) already uses
// the exact template width with no per-record padding; this restores parity.
func recordSize(fields []templateField) int {
	size := 0
	for _, f := range fields {
		size += int(f.fieldLen)
	}
	return size
}

// nfHeader is the 20-byte NetFlow v9 packet header.
type nfHeader struct {
	Version   uint16
	Count     uint16
	SysUptime uint32 // milliseconds since boot; wraps mod 2^32 (~49.7 d, see NetflowSysUptimeWrapMs)
	UnixSecs  uint32
	SeqNumber uint32
	SourceID  uint32
}

func encodeHeaderInto(b []byte, h nfHeader) {
	binary.BigEndian.PutUint16(b[0:2], h.Version)
	binary.BigEndian.PutUint16(b[2:4], h.Count)
	binary.BigEndian.PutUint32(b[4:8], h.SysUptime)
	binary.BigEndian.PutUint32(b[8:12], h.UnixSecs)
	binary.BigEndian.PutUint32(b[12:16], h.SeqNumber)
	binary.BigEndian.PutUint32(b[16:20], h.SourceID)
}

func encodeHeader(h nfHeader) []byte {
	b := make([]byte, 20)
	encodeHeaderInto(b, h)
	return b
}

// encodeTemplateFlowSet builds a template FlowSet containing both v4 and v6 templates.
func encodeTemplateFlowSet(opts V9TemplateOptions) []byte {
	v4fields := buildTemplateFieldsV4(opts)
	v6fields := buildTemplateFieldsV6(opts)

	// FlowSet header (4 bytes) + 2 template headers (4 each) + field entries
	totalLen := 4 + (4 + len(v4fields)*4) + (4 + len(v6fields)*4)

	b := make([]byte, totalLen)
	off := 0

	// FlowSet header: ID=0 (template), Length
	binary.BigEndian.PutUint16(b[off:off+2], flowsetIDTemplate)
	binary.BigEndian.PutUint16(b[off+2:off+4], uint16(totalLen))
	off += 4

	// IPv4 template
	binary.BigEndian.PutUint16(b[off:off+2], templateIDv4)
	binary.BigEndian.PutUint16(b[off+2:off+4], uint16(len(v4fields)))
	off += 4
	for _, f := range v4fields {
		binary.BigEndian.PutUint16(b[off:off+2], f.fieldType)
		binary.BigEndian.PutUint16(b[off+2:off+4], f.fieldLen)
		off += 4
	}

	// IPv6 template
	binary.BigEndian.PutUint16(b[off:off+2], templateIDv6)
	binary.BigEndian.PutUint16(b[off+2:off+4], uint16(len(v6fields)))
	off += 4
	for _, f := range v6fields {
		binary.BigEndian.PutUint16(b[off:off+2], f.fieldType)
		binary.BigEndian.PutUint16(b[off+2:off+4], f.fieldLen)
		off += 4
	}

	return b
}

// encodeDataFlowSet builds a data FlowSet from a batch of records.
// All records in a batch must be the same AF (v4 or v6).
func encodeDataFlowSet(records []FlowRecord, bootTime time.Time, opts V9TemplateOptions) []byte {
	if len(records) == 0 {
		return nil
	}
	tmplID, fields, recSize := netflowTemplateConfig(records[0].IsIPv6, opts)
	totalLen := dataFlowSetLen(len(records), recSize)
	b := make([]byte, totalLen)
	encodeDataFlowSetInto(b, records, bootTime, tmplID, fields, recSize, opts.IncludeFlowDir)
	return b
}

func netflowTemplateConfig(isV6 bool, opts V9TemplateOptions) (uint16, []templateField, int) {
	if isV6 {
		fields := buildTemplateFieldsV6(opts)
		return templateIDv6, fields, recordSize(fields)
	}
	fields := buildTemplateFieldsV4(opts)
	return templateIDv4, fields, recordSize(fields)
}

// dataFlowSetLen is the on-wire length of a Data FlowSet: the 4-byte FlowSet
// header plus recordCount CONTIGUOUS records (each recSize = the unpadded
// template width), rounded up ONCE to a 32-bit boundary. That final rounding is
// the RFC 3954 terminal FlowSet padding — the only padding a v9 Data FlowSet
// may carry — and it is included in the FlowSet Length field the encoder writes.
func dataFlowSetLen(recordCount, recSize int) int {
	totalLen := 4 + recordCount*recSize
	pad := (4 - totalLen%4) % 4
	return totalLen + pad
}

func encodeDataFlowSetInto(b []byte, records []FlowRecord, bootTime time.Time,
	tmplID uint16, fields []templateField, recSize int, includeDir bool,
) {
	if len(records) == 0 {
		return
	}
	totalLen := dataFlowSetLen(len(records), recSize)
	binary.BigEndian.PutUint16(b[0:2], tmplID)
	binary.BigEndian.PutUint16(b[2:4], uint16(totalLen))
	off := 4
	isV6 := records[0].IsIPv6
	_ = fields // template field set is derived per family + IncludeFlowDir
	for _, r := range records {
		if isV6 {
			off = encodeRecordV6(b, off, r, bootTime, recSize, includeDir)
		} else {
			off = encodeRecordV4(b, off, r, bootTime, recSize, includeDir)
		}
	}
	clear(b[off:totalLen])
}

func encodeRecordV4(b []byte, off int, r FlowRecord, bootTime time.Time,
	recSize int, includeDir bool,
) int {
	startOff := off
	src4 := r.SrcIP.To4()
	dst4 := r.DstIP.To4()
	if src4 == nil {
		src4 = net.IPv4zero.To4()
	}
	if dst4 == nil {
		dst4 = net.IPv4zero.To4()
	}
	copy(b[off:off+4], src4)
	off += 4
	copy(b[off:off+4], dst4)
	off += 4
	binary.BigEndian.PutUint16(b[off:off+2], r.SrcPort)
	off += 2
	binary.BigEndian.PutUint16(b[off:off+2], r.DstPort)
	off += 2
	b[off] = r.Protocol
	off++
	// #2613: SrcTos/TCPFlags/Direction/InputSNMP/OutputSNMP are no longer in
	// the template (no wire data backs them on the close path).
	binary.BigEndian.PutUint64(b[off:off+8], r.Packets)
	off += 8
	binary.BigEndian.PutUint64(b[off:off+8], r.Bytes)
	off += 8
	binary.BigEndian.PutUint32(b[off:off+4], uptimeMs(bootTime, r.StartTime))
	off += 4
	binary.BigEndian.PutUint32(b[off:off+4], uptimeMs(bootTime, r.EndTime))
	off += 4
	b[off] = r.SrcMask
	off++
	b[off] = r.DstMask
	off++
	// #2749: ingressInterface (IN_SNMP, IE 10) — the SNMP ifIndex of the
	// session's ingress binding (real value via #2615). Written before the
	// post-NAT tuple to match the template field order.
	binary.BigEndian.PutUint32(b[off:off+4], r.InIf)
	off += 4
	// #2749: srcTos (IE 5) / tcpFlags (IE 6) / OutputSNMP (IE 14) — real
	// class-of-service + egress attribution from the extended close frame.
	b[off] = r.TOS
	off++
	b[off] = r.TCPFlags
	off++
	binary.BigEndian.PutUint32(b[off:off+4], r.OutIf)
	off += 4
	// #3270: flowDirection (IE 61, 1B) — 0 ingress / 1 egress, derived from the
	// per-zone sampling-direction. Written only when the template advertises it
	// (IncludeFlowDir), before the post-NAT trailer.
	if includeDir {
		b[off] = r.Direction
		off++
	}
	// #2526: post-NAT (translated) tuple — 225/226/227/228.
	natSrc4 := r.NATSrcIP.To4()
	natDst4 := r.NATDstIP.To4()
	if natSrc4 == nil {
		natSrc4 = net.IPv4zero.To4()
	}
	if natDst4 == nil {
		natDst4 = net.IPv4zero.To4()
	}
	copy(b[off:off+4], natSrc4)
	off += 4
	copy(b[off:off+4], natDst4)
	off += 4
	binary.BigEndian.PutUint16(b[off:off+2], r.NATSrcPort)
	off += 2
	binary.BigEndian.PutUint16(b[off:off+2], r.NATDstPort)
	off += 2
	return startOff + recSize
}

func encodeRecordV6(b []byte, off int, r FlowRecord, bootTime time.Time,
	recSize int, includeDir bool,
) int {
	startOff := off
	src16 := r.SrcIP.To16()
	dst16 := r.DstIP.To16()
	if src16 == nil {
		src16 = net.IPv6zero
	}
	if dst16 == nil {
		dst16 = net.IPv6zero
	}
	copy(b[off:off+16], src16)
	off += 16
	copy(b[off:off+16], dst16)
	off += 16
	binary.BigEndian.PutUint16(b[off:off+2], r.SrcPort)
	off += 2
	binary.BigEndian.PutUint16(b[off:off+2], r.DstPort)
	off += 2
	b[off] = r.Protocol
	off++
	// #2613: dropped class-of-service/TCP flags/direction/interface fields.
	binary.BigEndian.PutUint64(b[off:off+8], r.Packets)
	off += 8
	binary.BigEndian.PutUint64(b[off:off+8], r.Bytes)
	off += 8
	binary.BigEndian.PutUint32(b[off:off+4], uptimeMs(bootTime, r.StartTime))
	off += 4
	binary.BigEndian.PutUint32(b[off:off+4], uptimeMs(bootTime, r.EndTime))
	off += 4
	b[off] = r.SrcMask
	off++
	b[off] = r.DstMask
	off++
	// #2749: ingressInterface (IN_SNMP, IE 10) — see encodeRecordV4.
	binary.BigEndian.PutUint32(b[off:off+4], r.InIf)
	off += 4
	// #2749: srcTos (IE 5) / tcpFlags (IE 6) / OutputSNMP (IE 14) — see V4.
	b[off] = r.TOS
	off++
	b[off] = r.TCPFlags
	off++
	binary.BigEndian.PutUint32(b[off:off+4], r.OutIf)
	off += 4
	// #3270: flowDirection (IE 61, 1B) — see encodeRecordV4.
	if includeDir {
		b[off] = r.Direction
		off++
	}
	// #2526: post-NAT (translated) tuple — 281/282 (16B) + 227/228 (2B).
	natSrc16 := r.NATSrcIP.To16()
	natDst16 := r.NATDstIP.To16()
	if natSrc16 == nil {
		natSrc16 = net.IPv6zero
	}
	if natDst16 == nil {
		natDst16 = net.IPv6zero
	}
	copy(b[off:off+16], natSrc16)
	off += 16
	copy(b[off:off+16], natDst16)
	off += 16
	binary.BigEndian.PutUint16(b[off:off+2], r.NATSrcPort)
	off += 2
	binary.BigEndian.PutUint16(b[off:off+2], r.NATDstPort)
	off += 2
	return startOff + recSize
}

// NetflowSysUptimeWrapMs is the NetFlow v9 sysUptime wrap period in
// milliseconds (#10726 A9-F5). SysUptime and the FirstSwitched/LastSwitched
// record fields are uint32 milliseconds since boot (RFC 3954 §5.1/§8), so on
// a host up longer than 2^32 ms (~49.7 days) they wrap to zero and keep
// counting. Collectors MUST NOT read a SysUptime decrease (or a
// FirstSwitched smaller than a previously seen value from the same exporter)
// as a device reboot — correlate with the packet UnixSecs and sequence
// number to disambiguate wrap from restart. An exported constant (rather
// than a comment alone) so collector-side tooling and tests can reference
// the exact boundary.
const NetflowSysUptimeWrapMs = uint64(1) << 32

func uptimeMs(boot, t time.Time) uint32 {
	d := t.Sub(boot)
	if d < 0 {
		return 0
	}
	return uint32(d.Milliseconds() % int64(NetflowSysUptimeWrapMs))
}

// Exporter sends NetFlow v9 packets to configured collectors.
type Exporter struct {
	cfg             *ExportConfig
	bootTime        time.Time
	sourceID        uint32
	fieldsV4        []templateField
	fieldsV6        []templateField
	recSizeV4       int
	recSizeV6       int
	templateFlowSet []byte

	mu    sync.Mutex
	seq   uint32
	conns *collectorConns

	// #2866: resolves the per-flow src/dst route prefix length (NetFlow IE
	// 9/13, IPv6 IE 29/30) from the FIB at export time. Nil on a zero-value
	// exporter (masks stay 0, the pre-#2866 behaviour); the daemon reconcile
	// path sets it via NewRouteMaskResolver so production records carry the
	// real matching-route prefix length.
	MaskResolver MaskResolver

	// Batching: accumulate records, flush periodically
	batch flowBatch

	// Stats
	exportedFlows atomic.Uint64
	exportedPkts  atomic.Uint64
	// #2465: count of session-close flows whose StartTime fell back to the
	// packet-count heuristic because the close event carried no real
	// session-creation timestamp (rec.Created == 0). A high value relative to
	// exportedFlows means most flows are still being timed by the old guess —
	// operator-visible signal that the dataplane is not stamping creation
	// times (e.g. all closes arriving via the explicit-delete / HA-purge path).
	estimatedDurations atomic.Uint64
	// #3744: count of route-mask HALVES (src and/or dst) that did not resolve
	// to a FIB route at export time — the mask was exported as an unresolved 0
	// rather than a real matched-route prefix length. Since #3743 the FIRST
	// flow to any cold (ifindex,prefix) key resolves 0 while the background
	// lookup warms, so a nonzero value is expected in steady state; a value
	// climbing in lockstep with exportedFlows means masks are chronically
	// unresolved (no route / churn faster than the TTL / wrong VRF scope) —
	// the only operator-visible signal that an exported mask-0 is unresolved
	// versus a real default-route /0.
	routeMaskUnresolved atomic.Uint64
}

// NewExporter creates a new NetFlow v9 exporter. cfg is held by pointer
// (never copied) because ExportConfig embeds the live 1-in-N
// sampleCounter (atomic.Uint64); copying it would fork the counter and
// silently re-seed the sampling cadence (#2224). The caller (the daemon
// reconcile path) shares the same *ExportConfig with the session-close
// callback so there is exactly one counter per exporter.
func NewExporter(cfg *ExportConfig) (*Exporter, error) {
	e := &Exporter{
		cfg: cfg,
		// #4423 M13: anchor sysUptime at real device boot, not exporter-
		// construction time, so a session that started before a daemon restart
		// is not truncated to FirstSwitched=0.
		bootTime: bootTimeFunc(),
		// #3740: stable per-group SourceID (RFC 3954 §5.1) derived from the
		// config identity so two same-collector groups no longer collide on
		// SourceID=1. HA-symmetric (pure function of config-synced fields).
		sourceID:     stableExporterID("netflow9", cfg.InstanceName, cfg.TemplateName),
		fieldsV4:     buildTemplateFieldsV4(cfg.V9TemplateOpts),
		fieldsV6:     buildTemplateFieldsV6(cfg.V9TemplateOpts),
		MaskResolver: NewRouteMaskResolver(0),
	}
	e.recSizeV4 = recordSize(e.fieldsV4)
	e.recSizeV6 = recordSize(e.fieldsV6)
	e.templateFlowSet = encodeTemplateFlowSet(cfg.V9TemplateOpts)

	conns, err := dialCollectors(cfg.Collectors)
	if err != nil {
		return nil, err
	}
	e.conns = conns

	return e, nil
}

// Run starts the exporter's background goroutines. Blocks until ctx is cancelled.
func (e *Exporter) Run(ctx context.Context) {
	// Send initial template
	e.sendTemplates()

	// #4423 M10: clamp a non-positive refresh rate so NewTicker never panics.
	templateTicker := time.NewTicker(templateRefreshInterval(e.cfg.TemplateRefreshRate))
	defer templateTicker.Stop()

	batchTicker := time.NewTicker(100 * time.Millisecond)
	defer batchTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Flush remaining batches
			e.flushBatches()
			return
		case <-templateTicker.C:
			e.sendTemplates()
		case <-batchTicker.C:
			e.flushBatches()
		}
	}
}

// ExportSessionClose converts a session-close event into a flow record and queues it.
func (e *Exporter) ExportSessionClose(rec logging.EventRecord, evt SessionCloseData) {
	// #2465: use the real session-creation timestamp for StartTime when the
	// close event carries one; fall back to the packet-count heuristic only
	// when it is absent (and count that for operator visibility).
	startTime, usedEstimate := flowStartTime(rec, evt.Protocol)
	if usedEstimate {
		e.estimatedDurations.Add(1)
	}
	// #2526: resolve the post-NAT tuple with pre-NAT fallback so every
	// exported record carries the RFC 5103 post-NAT fields (post == pre when
	// the flow was not translated).
	natSrcIP, natDstIP, natSrcPort, natDstPort := resolvePostNAT(
		evt.SrcIP, evt.DstIP, evt.SrcPort, evt.DstPort,
		evt.NATSrcIP, evt.NATDstIP, evt.NATSrcPort, evt.NATDstPort)
	// #2866: resolve src/dst route prefix lengths (NetFlow IE 9/13, IPv6 IE
	// 29/30) from the FIB. Masks default to 0 when no resolver is wired.
	// #3744: scope the lookup to the flow's ingress VRF table (evt.InIf, with
	// evt.OutIf as a fallback) and count any unresolved half so an exported
	// mask-0 can be told apart from a real default-route /0.
	srcMask, dstMask, maskMisses := resolveMasks(e.MaskResolver, evt.SrcIP, evt.DstIP, evt.InIf, evt.OutIf)
	if maskMisses > 0 {
		e.routeMaskUnresolved.Add(maskMisses)
	}
	fr := FlowRecord{
		SrcIP:   evt.SrcIP,
		DstIP:   evt.DstIP,
		SrcPort: evt.SrcPort,
		DstPort: evt.DstPort,
		// #3939: source protocolIdentifier (IE 4) from the record's raw numeric
		// IP protocol (rec.ProtocolNum, 0-255) — NOT a protocol-NAME re-lookup.
		// The daemon callback derived evt.Protocol via a name table that only
		// covered TCP/UDP/ICMP/ICMPv6, so GRE (47), ESP (50), AH (51) and every
		// other protocol exported as 0 and were misattributed at the collector.
		// rec.ProtocolNum is the authoritative number the dataplane stamped.
		Protocol:  rec.ProtocolNum,
		Packets:   rec.SessionPkts,
		Bytes:     rec.SessionBytes,
		StartTime: startTime,
		EndTime:   rec.Time,
		IsIPv6:    evt.IsIPv6,
		SrcMask:   srcMask,
		DstMask:   dstMask,
		// #2749: ingress ifindex (SNMP ifIndex) -> NetFlow IE 10; plus the
		// re-introduced srcTos (IE 5) / tcpFlags (IE 6) / OutputSNMP (IE 14).
		InIf:     evt.InIf,
		TOS:      evt.TOS,
		TCPFlags: evt.TCPFlags,
		OutIf:    evt.OutIf,
		// #3270: flowDirection (IE 61), derived from sampling-direction in the
		// daemon callback. Encoded only when the group enabled flow-dir.
		Direction:  evt.Direction,
		NATSrcIP:   natSrcIP,
		NATDstIP:   natDstIP,
		NATSrcPort: natSrcPort,
		NATDstPort: natDstPort,
	}

	e.batch.add(fr)
}

// EstimatedDurations returns the count of exported session-close flows whose
// StartTime was derived from the packet-count heuristic (#2465) rather than a
// real session-creation timestamp.
func (e *Exporter) EstimatedDurations() uint64 {
	return e.estimatedDurations.Load()
}

// RouteMaskUnresolved returns the count of exported route-mask halves (#3744)
// that did not resolve to a FIB route and were exported as an unresolved 0
// rather than a real matched-route prefix length. See routeMaskUnresolved.
func (e *Exporter) RouteMaskUnresolved() uint64 {
	return e.routeMaskUnresolved.Load()
}

// BatchDepth returns the current number of flow records pending in the export
// batch (both families combined). Normally near 0 — the Run goroutine drains
// every 100ms; a sustained nonzero value means the drain cannot keep up
// (stalled Run / slow collector / close storm) (#3747).
func (e *Exporter) BatchDepth() uint64 { return e.batch.depth() }

// BatchMaxDepth returns the high-water mark of the pending batch depth (#3747).
func (e *Exporter) BatchMaxDepth() uint64 { return e.batch.MaxDepth() }

// BatchDropped returns the cumulative count of flow records dropped because
// the export batch was at capacity (#3747). A climbing value means records
// are being lost to a stalled/overrun drain rather than growing memory
// without bound.
func (e *Exporter) BatchDropped() uint64 { return e.batch.Dropped() }

// Retire quiesces the exporter's batch admission lease ahead of the final
// flush that Run performs on ctx cancel. It flips the batch to retired and
// waits for in-flight session-close adds to finish (so those records are still
// drained by the final flush), after which any late session-close callback
// that loaded the pre-reconcile bundle is rejected and counted rather than
// silently stranded (#4963). The daemon reconcile calls this on the OLD
// exporter generation AFTER publishing the new bundle and BEFORE cancelling
// the old Run.
func (e *Exporter) Retire() { e.batch.retire() }

// HandoffDropped returns the count of session-close records this exporter
// rejected because they arrived after it was retired (#4963).
func (e *Exporter) HandoffDropped() uint64 { return e.batch.HandoffDropped() }

// SetHandoffCounter injects a fixed-cardinality family-level counter that the
// batch also increments on a handoff reject, so drops on a retired-and-
// discarded exporter stay observable after it leaves the live bundle (#4963).
// Called once at construction before Run starts.
func (e *Exporter) SetHandoffCounter(c *atomic.Uint64) { e.batch.setSharedHandoff(c) }

// Stats returns export statistics.
func (e *Exporter) Stats() (flows, packets uint64) {
	return e.exportedFlows.Load(), e.exportedPkts.Load()
}

// CollectorHealth returns a per-collector write-health snapshot (#2464):
// write attempts/failures, last error and the last success/failure
// timestamps for every collector this exporter writes to.
func (e *Exporter) CollectorHealth() []CollectorHealth {
	return e.conns.health()
}

// Close shuts down all collector connections.
func (e *Exporter) Close() {
	e.conns.close()
}

func (e *Exporter) sendTemplates() {
	e.mu.Lock()
	seq := e.seq
	e.seq++
	e.mu.Unlock()

	now := time.Now()
	hdr := nfHeader{
		Version:   9,
		Count:     2, // 2 templates
		SysUptime: uptimeMs(e.bootTime, now),
		UnixSecs:  uint32(now.Unix()),
		SeqNumber: seq,
		SourceID:  e.sourceID,
	}

	pkt := make([]byte, 20+len(e.templateFlowSet))
	encodeHeaderInto(pkt[:20], hdr)
	copy(pkt[20:], e.templateFlowSet)
	e.conns.writeAll(pkt, "netflow template send failed")
}

func (e *Exporter) flushBatches() {
	v4, v6 := e.batch.drain()

	if len(v4) > 0 {
		e.sendRecords(v4)
	}
	if len(v6) > 0 {
		e.sendRecords(v6)
	}
}

func (e *Exporter) sendRecords(records []FlowRecord) {
	if len(records) == 0 {
		return
	}

	isV6 := records[0].IsIPv6
	var (
		fields  []templateField
		recSize int
		tmplID  uint16
	)
	if isV6 {
		fields = e.fieldsV6
		recSize = e.recSizeV6
		tmplID = templateIDv6
	} else {
		fields = e.fieldsV4
		recSize = e.recSizeV4
		tmplID = templateIDv4
	}

	// Split into chunks that fit in maxPayload.
	// Reserve 20 bytes for the v9 header + 4 bytes for the FlowSet header + up
	// to 3 bytes for the RFC 3954 terminal FlowSet padding (recSize is now the
	// unpadded record width, so dataFlowSetLen may round the set up by up to 3
	// bytes — reserving them here keeps 20+dataLen <= maxPayload).
	maxRecords := (maxPayload - 20 - 4 - 3) / recSize
	if maxRecords < 1 {
		maxRecords = 1
	}

	for i := 0; i < len(records); i += maxRecords {
		end := i + maxRecords
		if end > len(records) {
			end = len(records)
		}
		batch := records[i:end]
		dataLen := dataFlowSetLen(len(batch), recSize)

		e.mu.Lock()
		seq := e.seq
		e.seq++
		e.mu.Unlock()

		now := time.Now()
		hdr := nfHeader{
			Version:   9,
			Count:     uint16(len(batch)),
			SysUptime: uptimeMs(e.bootTime, now),
			UnixSecs:  uint32(now.Unix()),
			SeqNumber: seq,
			SourceID:  e.sourceID,
		}

		pkt := make([]byte, 20+dataLen)
		encodeHeaderInto(pkt[:20], hdr)
		encodeDataFlowSetInto(pkt[20:], batch, e.bootTime,
			tmplID, fields, recSize, e.cfg.V9TemplateOpts.IncludeFlowDir)
		if e.conns.writeAll(pkt, "netflow data send failed") {
			e.exportedFlows.Add(uint64(len(batch)))
			e.exportedPkts.Add(1)
		}
	}
}
