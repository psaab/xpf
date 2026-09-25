package flowexport

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/psaab/xpf/pkg/logging"
)

// IPFIX field Information Element IDs (IANA-assigned, RFC 5102).
const (
	ipfixOctetDeltaCount          = 1
	ipfixPacketDeltaCount         = 2
	ipfixProtocolIdentifier       = 4
	ipfixIPClassOfService         = 5 // #2749 ipClassOfService (IE 5), unsigned8
	ipfixTCPControlBits           = 6 // #2749 tcpControlBits (IE 6), unsigned16
	ipfixSourceTransportPort      = 7
	ipfixSourceIPv4Address        = 8
	ipfixSourceIPv4PrefixLength   = 9 // #2866 srcMask (IE 9), unsigned8
	ipfixIngressInterface         = 10
	ipfixDestinationTransportPort = 11
	ipfixDestinationIPv4Address   = 12
	ipfixDestIPv4PrefixLength     = 13 // #2866 dstMask (IE 13), unsigned8
	ipfixEgressInterface          = 14 // #2749 egressInterface (IE 14), unsigned32
	ipfixSourceIPv6Address        = 27
	ipfixDestinationIPv6Address   = 28
	ipfixSourceIPv6PrefixLength   = 29 // #2866 srcMask v6 (IE 29), unsigned8
	ipfixDestIPv6PrefixLength     = 30 // #2866 dstMask v6 (IE 30), unsigned8
	ipfixFlowDirection            = 61 // #3270 flowDirection (IE 61), unsigned8
	ipfixFlowStartMilliseconds    = 152
	ipfixFlowEndMilliseconds      = 153
	// #2749: ipClassOfService (5), tcpControlBits (6), ingressInterface (10) and
	// egressInterface (14) are advertised with real values. #3270: flowDirection
	// (61) is advertised conditionally (opt-in `export-extension flow-dir`),
	// populated from the per-zone sampling-direction.
	// ipfixApplicationId (95) is reserved for a future app-id record field.
	// RFC 5103 post-NAT (translated) tuple elements. IPv4 addresses 225/226
	// (ipv4Address, 4B); transport ports 227/228 (unsigned16, 2B), which are
	// family-agnostic and reused for IPv6. IPv6 addresses 281/282
	// (ipv6Address, 16B) per RFC 8158. Confirmed against the IANA "IP Flow
	// Information Export (IPFIX) Entities" registry (#2526).
	ipfixPostNatSourceIPv4Address      = 225
	ipfixPostNatDestinationIPv4Address = 226
	ipfixPostNapatSourceTransportPort  = 227
	ipfixPostNapatDestTransportPort    = 228
	ipfixPostNatSourceIPv6Address      = 281
	ipfixPostNatDestinationIPv6Address = 282
	// #3746: RFC 5103 biflow reverse counters. The reverse of an IANA IE is
	// expressed with the SAME element ID under the reverse Private Enterprise
	// Number 29305, so reverseOctetDeltaCount reuses IE 1 (octetDeltaCount) and
	// reversePacketDeltaCount reuses IE 2 (packetDeltaCount). In the Template
	// Set an enterprise field specifier sets the top (enterprise) bit of the
	// element ID and appends the 4-byte PEN (RFC 7011 §3.2); the Data Record
	// value is a plain 8-byte unsigned64. Confirmed against the IANA "IPFIX
	// Entities" registry and RFC 5103.
	ipfixReverseOctetDeltaCount  = 1
	ipfixReversePacketDeltaCount = 2
)

// ipfixReversePEN is the RFC 5103 reverse Private Enterprise Number. An IPFIX
// enterprise Information Element carries it in the Template Set field
// specifier (RFC 7011 §3.2); a collector that does not grok 29305 skips the
// field using the template-declared length (RFC 7011 §8) — no corruption.
const ipfixReversePEN uint32 = 29305

// ipfixEnterpriseBit is the top bit of an IPFIX Information Element identifier
// that marks a field specifier as enterprise-scoped (RFC 7011 §3.2). When set,
// the field specifier is 8 bytes (2B elementID|bit, 2B length, 4B PEN) instead
// of the 4-byte IANA form.
const ipfixEnterpriseBit uint16 = 0x8000

// #3748/#5312: RFC 7014 (Flow Selection Techniques) FLOW-selection Information
// Elements carried by the Options Data Record that advertises the group's
// 1-in-N sampling configuration to a collector. xpf samples at SESSION-RECORD
// (Flow) granularity — ShouldExport applies the 1-in-N modulo per SESSION_CLOSE
// event, selecting whole Flows, not packets. The PSAMP packet-selection IEs
// (selectorAlgorithm 304 / samplingPacketInterval 305 / samplingPacketSpace 306)
// would tell a standards collector this is PACKET sampling and to renormalize
// each record's octet/packet counters by N — inflating the already-complete
// per-session volume (#5312). The RFC 7014 flow-selection IEs describe the
// population the sampler actually ran on: whole Flow records.
const (
	// observationDomainId (IE 149, unsigned32) — the SCOPE field of the
	// sampler Options Template. Its value is the group's stable Observation
	// Domain ID (#3740), which also stamps the message header, so the record
	// scopes the sampling config to this observation domain.
	ipfixObservationDomainID = 149
	// flowSelectorAlgorithm (IE 390, unsigned16, RFC 7014 §5) — the Flow
	// selection algorithm, taken from the IANA "Flow Selector Algorithm"
	// registry. Flow-granularity analog of PSAMP selectorAlgorithm (IE 304).
	ipfixFlowSelectorAlgorithm = 390
	// samplingFlowInterval (IE 396, unsigned64, RFC 7014 §5) — number of Flows
	// consecutively selected (1 for 1-in-N systematic count-based flow sampling).
	ipfixSamplingFlowInterval = 396
	// samplingFlowSpacing (IE 397, unsigned64, RFC 7014 §5) — number of Flows
	// skipped between two sampling intervals (N-1 for 1-in-N).
	ipfixSamplingFlowSpacing = 397
)

// ipfixFlowSelectorAlgorithmSystematicCount is the IANA "Flow Selector
// Algorithm" (RFC 7014) registry value for Systematic count-based Sampling:
// select samplingFlowInterval Flows, then skip samplingFlowSpacing Flows. It
// shares value 1 with the PSAMP "Selection Method" registry, but the
// surrounding RFC 7014 flow-selection IEs make a collector treat it as FLOW
// selection, not packet selection. xpf's 1-in-N is expressed as interval=1,
// space=N-1 (#5312).
const ipfixFlowSelectorAlgorithmSystematicCount uint16 = 1

// IPFIX Set IDs (RFC 7011 Section 3.3.2).
const (
	ipfixSetIDTemplate        = 2
	ipfixSetIDOptionsTemplate = 3
	// Data set IDs >= 256
)

// IPFIX template IDs.
const (
	ipfixTemplateIDv4 = 256
	ipfixTemplateIDv6 = 257
	// #3748: the sampler Options Template ID. Distinct from the 256/257 data
	// template IDs so a collector never confuses the options record with a
	// flow record.
	ipfixOptionsTemplateIDSampler = 258
)

// ipfixField defines a template field. enterprise is 0 for a standard IANA
// Information Element (4-byte Template Set field specifier) and the Private
// Enterprise Number for an RFC 7011 §3.2 enterprise IE (8-byte specifier:
// elementID|0x8000, length, 4-byte PEN). The Data Record value length is
// `length` in both cases (#3746 added the first enterprise IEs — the RFC 5103
// biflow reverse counters under PEN 29305).
type ipfixField struct {
	elementID  uint16
	length     uint16
	enterprise uint32
}

// #2749: the IPFIX templates advertise ipClassOfService (5), tcpControlBits
// (6), ingressInterface (10) and egressInterface (14) with REAL values from
// the extended SESSION_CLOSE wire frame. #3270: flowDirection (IE 61) is
// advertised CONDITIONALLY — only when `export-extension flow-dir` is set on
// the template — and populated in Go from the per-zone sampling-direction
// (ExportConfig.FlowDirection). The base ipfixTemplateV4/V6 slices below are
// the flow-dir-ABSENT templates; ipfixTemplateFieldsV4/V6 splice IE 61 in
// before the post-NAT trailer when includeDir is set, so a config that did not
// opt in keeps the field absent (no #2613 synthetic-zero regression).

// ipfixTemplateV4 defines the IPv4 IPFIX base template fields (flow-dir absent).
var ipfixTemplateV4 = []ipfixField{
	{ipfixSourceIPv4Address, 4, 0},
	{ipfixDestinationIPv4Address, 4, 0},
	{ipfixSourceTransportPort, 2, 0},
	{ipfixDestinationTransportPort, 2, 0},
	{ipfixProtocolIdentifier, 1, 0},
	{ipfixPacketDeltaCount, 8, 0},
	{ipfixOctetDeltaCount, 8, 0},
	{ipfixFlowStartMilliseconds, 8, 0},
	{ipfixFlowEndMilliseconds, 8, 0},
	// #2866: src/dst route prefix lengths (IE 9 / IE 13) populated with the
	// FIB longest-prefix-match mask. Placed in the same slot as the NetFlow
	// v9 srcMask/dstMask (after FlowEnd, before ingressInterface) so the two
	// protocols keep a parallel record layout.
	{ipfixSourceIPv4PrefixLength, 1, 0},
	{ipfixDestIPv4PrefixLength, 1, 0},
	// #2749: ingressInterface (IE 10) re-introduced with a REAL value — the
	// ingress ifindex on the SESSION_CLOSE frame since #2615. Placed before
	// the post-NAT tuple so the latter stays the trailing block (#2526
	// invariant).
	{ipfixIngressInterface, 4, 0},
	// #2749: class-of-service + egress interface re-introduced with REAL
	// values from the extended SESSION_CLOSE frame ([144:152]).
	// ipClassOfService (IE 5, 1B) = forward DSCP<<2; tcpControlBits (IE 6, 2B,
	// unsigned16) = cumulative TCP control bits; egressInterface (IE 14, 4B) =
	// egress ifindex. Placed after ingressInterface and before the post-NAT
	// tuple so the latter stays the trailing block (#2526). #3270: flowDirection
	// (IE 61) is spliced in here by ipfixTemplateFieldsV4 when flow-dir is
	// enabled; it is NOT in this base slice.
	{ipfixIPClassOfService, 1, 0},
	{ipfixTCPControlBits, 2, 0},
	{ipfixEgressInterface, 4, 0},
	// #3746: RFC 5103 biflow reverse counters (enterprise PEN 29305, 8B each).
	// reversePacketDeltaCount (IE 2) then reverseOctetDeltaCount (IE 1),
	// mirroring the forward packets-then-bytes layout above. Placed after the
	// forward CoS/egress block and before the post-NAT trailing block so #2526
	// keeps the post-NAT tuple last. These are the first enterprise IEs in the
	// template, so each occupies an 8-byte field specifier in the Template Set.
	{ipfixReversePacketDeltaCount, 8, ipfixReversePEN},
	{ipfixReverseOctetDeltaCount, 8, ipfixReversePEN},
	// #2526: post-NAT (translated) tuple, appended last.
	{ipfixPostNatSourceIPv4Address, 4, 0},
	{ipfixPostNatDestinationIPv4Address, 4, 0},
	{ipfixPostNapatSourceTransportPort, 2, 0},
	{ipfixPostNapatDestTransportPort, 2, 0},
}

// ipfixTemplateV6 defines the IPv6 IPFIX template fields.
var ipfixTemplateV6 = []ipfixField{
	{ipfixSourceIPv6Address, 16, 0},
	{ipfixDestinationIPv6Address, 16, 0},
	{ipfixSourceTransportPort, 2, 0},
	{ipfixDestinationTransportPort, 2, 0},
	{ipfixProtocolIdentifier, 1, 0},
	{ipfixPacketDeltaCount, 8, 0},
	{ipfixOctetDeltaCount, 8, 0},
	{ipfixFlowStartMilliseconds, 8, 0},
	{ipfixFlowEndMilliseconds, 8, 0},
	// #2866: src/dst route prefix lengths (IPv6 variants IE 29 / IE 30).
	{ipfixSourceIPv6PrefixLength, 1, 0},
	{ipfixDestIPv6PrefixLength, 1, 0},
	// #2749: ingressInterface (IE 10) — see the V4 template note.
	{ipfixIngressInterface, 4, 0},
	// #2749: ipClassOfService (IE 5) / tcpControlBits (IE 6) / egressInterface
	// (IE 14) — see the V4 template note.
	{ipfixIPClassOfService, 1, 0},
	{ipfixTCPControlBits, 2, 0},
	{ipfixEgressInterface, 4, 0},
	// #3746: RFC 5103 biflow reverse counters (PEN 29305, 8B each) — see the
	// V4 template note. Family-agnostic; the same IEs precede the post-NAT
	// trailer here.
	{ipfixReversePacketDeltaCount, 8, ipfixReversePEN},
	{ipfixReverseOctetDeltaCount, 8, ipfixReversePEN},
	// #2526: post-NAT (translated) tuple, appended last. v6 addresses use the
	// 16-byte RFC 8158 elements; ports reuse the family-agnostic 227/228.
	{ipfixPostNatSourceIPv6Address, 16, 0},
	{ipfixPostNatDestinationIPv6Address, 16, 0},
	{ipfixPostNapatSourceTransportPort, 2, 0},
	{ipfixPostNapatDestTransportPort, 2, 0},
}

// ipfixRecordSizeV4 is the byte size of a single IPv4 IPFIX data record.
// #2613 dropped TOS(1)+TCPflags(2)+direction(1)+ingressIf(4)+egressIf(4)=12
// from the former 69-byte record. pre-NAT body = 45; #2526 post-NAT tuple
// (4+4+2+2) = 12 → 57. #2749 re-added ingressInterface (IE 10, 4B) with a
// real value → 61. #2866 added srcMask+dstMask (IE 9/13, 1B each) → 63.
// #2749 re-added ipClassOfService(1)+tcpControlBits(2)+egressInterface(4) = 7
// with real values → 70. #3746 added the RFC 5103 biflow reverse counters
// (reversePacketDeltaCount + reverseOctetDeltaCount, 8B each) → 86. The
// enterprise IEs are 8-byte DATA values (only their Template Set field
// specifiers are wider).
// 4+4+2+2+1+8+8+8+8 + 1+1 + 4 + 1+2+4 + 8+8 + 4+4+2+2 = 86
const ipfixRecordSizeV4 = 86

// ipfixRecordSizeV6 is the byte size of a single IPv6 IPFIX data record.
// #2613 dropped the same 12 unpopulated bytes from the former 117. pre-NAT
// body = 69; #2526 post-NAT tuple (16+16+2+2) = 36 → 105. #2749 re-added
// ingressInterface (IE 10, 4B) with a real value → 109. #2866 added the IPv6
// srcMask+dstMask (IE 29/30, 1B each) → 111.
// #2749 re-added ipClassOfService(1)+tcpControlBits(2)+egressInterface(4) = 7
// with real values → 118. #3746 added the RFC 5103 biflow reverse counters
// (8B each) → 134.
// 16+16+2+2+1+8+8+8+8 + 1+1 + 4 + 1+2+4 + 8+8 + 16+16+2+2 = 134
const ipfixRecordSizeV6 = 134

// ipfixRecordSizeV4 / V6 must equal the sum of their (base) template field
// lengths. A drift between the template (what the collector parses) and the
// encoder (record size) corrupts every record — pin it at build time (#2526).
var _ = func() struct{} {
	if ipfixSumLen(ipfixTemplateV4) != ipfixRecordSizeV4 {
		panic("ipfixRecordSizeV4 != sum(ipfixTemplateV4)")
	}
	if ipfixSumLen(ipfixTemplateV6) != ipfixRecordSizeV6 {
		panic("ipfixRecordSizeV6 != sum(ipfixTemplateV6)")
	}
	return struct{}{}
}()

func ipfixSumLen(fs []ipfixField) int {
	n := 0
	for _, f := range fs {
		n += int(f.length)
	}
	return n
}

// ipfixSpliceFlowDir returns base with a {ipfixFlowDirection,1} field inserted
// before the trailing post-NAT block (first IE >= ipfixPostNatSourceIPv4Address),
// keeping the #2526 post-NAT trailer last. base is not mutated.
func ipfixSpliceFlowDir(base []ipfixField) []ipfixField {
	idx := len(base)
	for i, f := range base {
		if f.elementID >= ipfixPostNatSourceIPv4Address {
			idx = i
			break
		}
	}
	out := make([]ipfixField, 0, len(base)+1)
	out = append(out, base[:idx]...)
	out = append(out, ipfixField{ipfixFlowDirection, 1, 0})
	out = append(out, base[idx:]...)
	return out
}

// ipfixFieldSpecLen returns the encoded Template Set field-specifier width for
// f: 8 bytes for an enterprise IE (elementID|0x8000, length, 4-byte PEN;
// RFC 7011 §3.2), 4 bytes for a standard IANA IE. Note this is the TEMPLATE
// specifier width, not the DATA record value length (which is f.length in both
// cases) — #3746.
func ipfixFieldSpecLen(f ipfixField) int {
	if f.enterprise != 0 {
		return 8
	}
	return 4
}

// ipfixFieldSpecsLen sums the Template Set field-specifier widths of fs.
func ipfixFieldSpecsLen(fs []ipfixField) int {
	n := 0
	for _, f := range fs {
		n += ipfixFieldSpecLen(f)
	}
	return n
}

// encodeIPFIXFieldSpec writes f's Template Set field specifier at b[off:] and
// returns the next offset. An enterprise IE (RFC 7011 §3.2) sets the top bit of
// the Information Element identifier and appends the 4-byte PEN (#3746).
func encodeIPFIXFieldSpec(b []byte, off int, f ipfixField) int {
	if f.enterprise != 0 {
		binary.BigEndian.PutUint16(b[off:off+2], f.elementID|ipfixEnterpriseBit)
		binary.BigEndian.PutUint16(b[off+2:off+4], f.length)
		binary.BigEndian.PutUint32(b[off+4:off+8], f.enterprise)
		return off + 8
	}
	binary.BigEndian.PutUint16(b[off:off+2], f.elementID)
	binary.BigEndian.PutUint16(b[off+2:off+4], f.length)
	return off + 4
}

// ipfixTemplateFieldsV4 returns the IPv4 IPFIX template fields, splicing in
// flowDirection (IE 61) before the post-NAT trailer when includeDir is set
// (#3270).
func ipfixTemplateFieldsV4(includeDir bool) []ipfixField {
	if includeDir {
		return ipfixSpliceFlowDir(ipfixTemplateV4)
	}
	return ipfixTemplateV4
}

// ipfixTemplateFieldsV6 returns the IPv6 IPFIX template fields. See
// ipfixTemplateFieldsV4.
func ipfixTemplateFieldsV6(includeDir bool) []ipfixField {
	if includeDir {
		return ipfixSpliceFlowDir(ipfixTemplateV6)
	}
	return ipfixTemplateV6
}

// ipfixRecordSize returns the encoded record size for the given family and
// flow-dir state (#3270): the base size plus one byte when flowDirection is
// advertised.
func ipfixRecordSize(isV6, includeDir bool) int {
	base := ipfixRecordSizeV4
	if isV6 {
		base = ipfixRecordSizeV6
	}
	if includeDir {
		return base + 1
	}
	return base
}

// ipfixHeader is the 16-byte IPFIX message header (RFC 7011 Section 3.1).
type ipfixHeader struct {
	Version        uint16 // always 10
	Length         uint16 // total message length including header
	ExportTime     uint32 // epoch seconds
	SequenceNumber uint32 // cumulative number of data records
	ObservationID  uint32 // observation domain ID
}

func encodeIPFIXHeader(h ipfixHeader) []byte {
	b := make([]byte, 16)
	encodeIPFIXHeaderInto(b, h)
	return b
}

func encodeIPFIXHeaderInto(b []byte, h ipfixHeader) {
	binary.BigEndian.PutUint16(b[0:2], h.Version)
	binary.BigEndian.PutUint16(b[2:4], h.Length)
	binary.BigEndian.PutUint32(b[4:8], h.ExportTime)
	binary.BigEndian.PutUint32(b[8:12], h.SequenceNumber)
	binary.BigEndian.PutUint32(b[12:16], h.ObservationID)
}

// encodeIPFIXTemplateSet builds an IPFIX template set with the base templates
// (flow-dir absent). Retained for callers/tests that exercise the default
// no-extension template.
func encodeIPFIXTemplateSet() []byte {
	return encodeIPFIXTemplateSetDir(false)
}

// encodeIPFIXTemplateSetDir builds an IPFIX template set containing v4 and v6
// templates, advertising flowDirection (IE 61) when includeDir is set (#3270).
func encodeIPFIXTemplateSetDir(includeDir bool) []byte {
	v4 := ipfixTemplateFieldsV4(includeDir)
	v6 := ipfixTemplateFieldsV6(includeDir)
	// Set header (4 bytes) + 2 template record headers (4 each) + field
	// specifiers (4 bytes each IANA IE, 8 bytes each enterprise IE — #3746).
	// The template record header carries the FIELD COUNT (len), which is
	// unchanged; only the per-specifier byte width differs.
	totalLen := 4 + (4 + ipfixFieldSpecsLen(v4)) + (4 + ipfixFieldSpecsLen(v6))

	b := make([]byte, totalLen)
	off := 0

	// Set header: Set ID = 2 (Template Set), Length
	binary.BigEndian.PutUint16(b[off:off+2], ipfixSetIDTemplate)
	binary.BigEndian.PutUint16(b[off+2:off+4], uint16(totalLen))
	off += 4

	// IPv4 template record header
	binary.BigEndian.PutUint16(b[off:off+2], ipfixTemplateIDv4)
	binary.BigEndian.PutUint16(b[off+2:off+4], uint16(len(v4)))
	off += 4
	for _, f := range v4 {
		off = encodeIPFIXFieldSpec(b, off, f)
	}

	// IPv6 template record header
	binary.BigEndian.PutUint16(b[off:off+2], ipfixTemplateIDv6)
	binary.BigEndian.PutUint16(b[off+2:off+4], uint16(len(v6)))
	off += 4
	for _, f := range v6 {
		off = encodeIPFIXFieldSpec(b, off, f)
	}

	return b
}

// #3748/#5312: the sampler Options Template scope + option fields (RFC 7011 §4 /
// RFC 7014 §5). The single scope field (observationDomainId, IE 149) binds the
// record to an Observation Domain; the option fields carry the FLOW-selection
// sampling configuration. All are standard IANA IEs (4-byte Template Set
// specifiers).
var (
	ipfixOptionsSamplerScope = []ipfixField{
		{ipfixObservationDomainID, 4, 0},
	}
	ipfixOptionsSamplerFields = []ipfixField{
		{ipfixFlowSelectorAlgorithm, 2, 0},
		{ipfixSamplingFlowInterval, 8, 0},
		{ipfixSamplingFlowSpacing, 8, 0},
	}
)

// ipfixOptionsSamplerRecordSize is the byte size of the sampler Options Data
// Record: observationDomainId(4) + flowSelectorAlgorithm(2) + samplingFlowInterval(8)
// + samplingFlowSpacing(8) = 22. Pinned against the field slices at build time so
// a template/encoder drift panics at init (#3748), mirroring the #2526 data-record
// pins.
const ipfixOptionsSamplerRecordSize = 22

var _ = func() struct{} {
	if ipfixSumLen(ipfixOptionsSamplerScope)+ipfixSumLen(ipfixOptionsSamplerFields) != ipfixOptionsSamplerRecordSize {
		panic("ipfixOptionsSamplerRecordSize != sum(scope+option fields)")
	}
	return struct{}{}
}()

// encodeIPFIXOptionsTemplateSet builds the sampler Options Template Set (Set ID
// 3, RFC 7011 §3.4.2.2). The Options Template Record header is 6 bytes —
// Template ID, Field Count, Scope Field Count — unlike the 4-byte Data Template
// Record header. Field Count is scope + option fields; Scope Field Count is the
// number of leading scope fields (#3748).
func encodeIPFIXOptionsTemplateSet() []byte {
	scope := ipfixOptionsSamplerScope
	opts := ipfixOptionsSamplerFields
	// Set header (4) + Options Template Record header (6) + field specifiers.
	totalLen := 4 + 6 + ipfixFieldSpecsLen(scope) + ipfixFieldSpecsLen(opts)

	b := make([]byte, totalLen)
	off := 0

	// Set header: Set ID = 3 (Options Template Set), Length.
	binary.BigEndian.PutUint16(b[off:off+2], ipfixSetIDOptionsTemplate)
	binary.BigEndian.PutUint16(b[off+2:off+4], uint16(totalLen))
	off += 4

	// Options Template Record header: Template ID, Field Count, Scope Field Count.
	binary.BigEndian.PutUint16(b[off:off+2], ipfixOptionsTemplateIDSampler)
	binary.BigEndian.PutUint16(b[off+2:off+4], uint16(len(scope)+len(opts)))
	binary.BigEndian.PutUint16(b[off+4:off+6], uint16(len(scope)))
	off += 6

	for _, f := range scope {
		off = encodeIPFIXFieldSpec(b, off, f)
	}
	for _, f := range opts {
		off = encodeIPFIXFieldSpec(b, off, f)
	}
	return b
}

// encodeIPFIXOptionsSamplerDataSet builds the sampler Options Data Set (a Data
// Set whose Set ID equals the Options Template ID, 258). It carries one record
// scoped to odid, advertising 1-in-N FLOW (session-record) sampling as RFC 7014
// systematic count-based flow selection: flowSelectorAlgorithm=1,
// samplingFlowInterval=1, samplingFlowSpacing=samplingRate-1. samplingRate <= 1
// (unsampled) yields space=0 (1-in-1), but callers only emit this set when
// sampling is active (see IPFIXExporter.emitSampler) (#3748/#5312).
func encodeIPFIXOptionsSamplerDataSet(odid uint32, samplingRate int) []byte {
	var space uint64
	if samplingRate > 1 {
		space = uint64(samplingRate - 1)
	}
	totalLen := 4 + ipfixOptionsSamplerRecordSize
	b := make([]byte, totalLen)
	off := 0

	// Set header: Set ID = Options Template ID (>= 256, so this is a Data Set).
	binary.BigEndian.PutUint16(b[off:off+2], ipfixOptionsTemplateIDSampler)
	binary.BigEndian.PutUint16(b[off+2:off+4], uint16(totalLen))
	off += 4

	// Record: observationDomainId (scope), then the RFC 7014 flow-selection
	// option fields.
	binary.BigEndian.PutUint32(b[off:off+4], odid)
	off += 4
	binary.BigEndian.PutUint16(b[off:off+2], ipfixFlowSelectorAlgorithmSystematicCount)
	off += 2
	binary.BigEndian.PutUint64(b[off:off+8], 1) // samplingFlowInterval = 1
	off += 8
	binary.BigEndian.PutUint64(b[off:off+8], space) // samplingFlowSpacing = N-1
	off += 8
	return b
}

// encodeIPFIXDataSet builds an IPFIX data set from a batch of records with the
// base (flow-dir absent) layout. Retained for callers/tests.
func encodeIPFIXDataSet(records []FlowRecord) []byte {
	return encodeIPFIXDataSetDir(records, false)
}

// encodeIPFIXDataSetDir builds an IPFIX data set, encoding flowDirection
// (IE 61) when includeDir is set (#3270).
func encodeIPFIXDataSetDir(records []FlowRecord, includeDir bool) []byte {
	if len(records) == 0 {
		return nil
	}
	isV6 := records[0].IsIPv6
	var tmplID uint16
	if isV6 {
		tmplID = ipfixTemplateIDv6
	} else {
		tmplID = ipfixTemplateIDv4
	}
	recSize := ipfixRecordSize(isV6, includeDir)

	totalLen := ipfixDataSetLen(len(records), recSize)
	b := make([]byte, totalLen)
	encodeIPFIXDataSetInto(b, records, tmplID, recSize, includeDir)
	return b
}

func ipfixDataSetLen(recordCount, recSize int) int {
	return 4 + recordCount*recSize
}

func encodeIPFIXDataSetInto(b []byte, records []FlowRecord, tmplID uint16, recSize int, includeDir bool) {
	if len(records) == 0 {
		return
	}
	totalLen := ipfixDataSetLen(len(records), recSize)
	binary.BigEndian.PutUint16(b[0:2], tmplID)
	binary.BigEndian.PutUint16(b[2:4], uint16(totalLen))
	off := 4
	isV6 := records[0].IsIPv6
	for _, r := range records {
		if isV6 {
			off = encodeIPFIXRecordV6(b, off, r, includeDir)
		} else {
			off = encodeIPFIXRecordV4(b, off, r, includeDir)
		}
	}
	clear(b[off:totalLen])
}

func encodeIPFIXRecordV4(b []byte, off int, r FlowRecord, includeDir bool) int {
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
	// #2613: ipClassOfService/tcpControlBits/flowDirection/ingress+egress
	// interface are no longer in the template (no wire data) — go straight to
	// the counters/timestamps the close frame actually carries.
	binary.BigEndian.PutUint64(b[off:off+8], r.Packets)
	off += 8
	binary.BigEndian.PutUint64(b[off:off+8], r.Bytes)
	off += 8
	binary.BigEndian.PutUint64(b[off:off+8], uint64(r.StartTime.UnixMilli()))
	off += 8
	binary.BigEndian.PutUint64(b[off:off+8], uint64(r.EndTime.UnixMilli()))
	off += 8
	// #2866: src/dst route prefix lengths (IE 9 / IE 13).
	b[off] = r.SrcMask
	off++
	b[off] = r.DstMask
	off++
	// #2749: ingressInterface (IE 10) — the SNMP ifIndex of the session's
	// ingress binding (real value via #2615). Written before the post-NAT
	// tuple to match the template field order.
	binary.BigEndian.PutUint32(b[off:off+4], r.InIf)
	off += 4
	// #2749: ipClassOfService (IE 5, 1B) / tcpControlBits (IE 6, 2B) /
	// egressInterface (IE 14, 4B) — real class-of-service + egress attribution.
	b[off] = r.TOS
	off++
	binary.BigEndian.PutUint16(b[off:off+2], uint16(r.TCPFlags))
	off += 2
	binary.BigEndian.PutUint32(b[off:off+4], r.OutIf)
	off += 4
	// #3746: RFC 5103 biflow reverse counters (PEN 29305) — 8-byte unsigned64
	// DATA values (the enterprise bit + PEN live only in the Template Set).
	// reversePacketDeltaCount (IE 2) then reverseOctetDeltaCount (IE 1), matching
	// the template order. Written before the flow-dir byte so the base and
	// flow-dir templates both agree with the encoder.
	binary.BigEndian.PutUint64(b[off:off+8], r.RevPackets)
	off += 8
	binary.BigEndian.PutUint64(b[off:off+8], r.RevBytes)
	off += 8
	// #3270: flowDirection (IE 61, unsigned8) — 0 ingress / 1 egress, derived
	// from the per-zone sampling-direction. Written only when the template
	// advertises it (includeDir), before the post-NAT trailer.
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
	return off
}

func encodeIPFIXRecordV6(b []byte, off int, r FlowRecord, includeDir bool) int {
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
	binary.BigEndian.PutUint64(b[off:off+8], uint64(r.StartTime.UnixMilli()))
	off += 8
	binary.BigEndian.PutUint64(b[off:off+8], uint64(r.EndTime.UnixMilli()))
	off += 8
	// #2866: src/dst route prefix lengths (IPv6 variants IE 29 / IE 30).
	b[off] = r.SrcMask
	off++
	b[off] = r.DstMask
	off++
	// #2749: ingressInterface (IE 10) — see encodeIPFIXRecordV4.
	binary.BigEndian.PutUint32(b[off:off+4], r.InIf)
	off += 4
	// #2749: ipClassOfService (IE 5) / tcpControlBits (IE 6) / egressInterface
	// (IE 14) — see encodeIPFIXRecordV4.
	b[off] = r.TOS
	off++
	binary.BigEndian.PutUint16(b[off:off+2], uint16(r.TCPFlags))
	off += 2
	binary.BigEndian.PutUint32(b[off:off+4], r.OutIf)
	off += 4
	// #3746: RFC 5103 biflow reverse counters (PEN 29305) — see
	// encodeIPFIXRecordV4.
	binary.BigEndian.PutUint64(b[off:off+8], r.RevPackets)
	off += 8
	binary.BigEndian.PutUint64(b[off:off+8], r.RevBytes)
	off += 8
	// #3270: flowDirection (IE 61, unsigned8) — see encodeIPFIXRecordV4.
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
	return off
}

// IPFIXExporter sends IPFIX (NetFlow v10) messages to configured collectors.
type IPFIXExporter struct {
	cfg         *ExportConfig
	sourceID    uint32
	templateSet []byte
	// includeDir mirrors cfg.IncludeFlowDir, resolved once at construction so
	// the template set and every data record agree on whether flowDirection
	// (IE 61) is present (#3270).
	includeDir bool

	// #3748: sampler Options Template (Set ID 3) + Options Data Record (Set ID
	// 258) advertising the group's 1-in-N sampling rate. Precomputed at
	// construction (rate is fixed per group) and re-sent on the template-refresh
	// cadence. emitSampler gates emission on SamplingRate > 1 — an unsampled
	// group (rate 0/1, export-all) advertises nothing (a collector then assumes
	// 1-in-1, which is correct), matching the ShouldExport sampling gate.
	emitSampler        bool
	optionsTemplateSet []byte
	optionsDataSet     []byte

	mu    sync.Mutex
	seq   uint32 // cumulative data record count
	conns *collectorConns

	// #2866: resolves per-flow src/dst route prefix lengths (IPFIX
	// sourceIPv4PrefixLength IE 9 / destinationIPv4PrefixLength IE 13 and the
	// IPv6 variants IE 29/30) from the FIB. See Exporter.MaskResolver.
	MaskResolver MaskResolver

	batch flowBatch

	exportedFlows atomic.Uint64
	exportedPkts  atomic.Uint64
	// #2465: see Exporter.estimatedDurations — count of close flows whose
	// StartTime fell back to the packet-count heuristic (no real creation ts).
	estimatedDurations atomic.Uint64
	// #3744: see Exporter.routeMaskUnresolved — count of route-mask halves
	// exported as an unresolved 0 (no FIB route / cold cache) rather than a
	// real matched-route prefix length.
	routeMaskUnresolved atomic.Uint64
}

// NewIPFIXExporter creates a new IPFIX exporter. cfg is held by pointer
// (never copied) for the same reason as NewExporter: ExportConfig
// embeds the live 1-in-N sampleCounter (atomic.Uint64) and copying it
// would fork the counter, re-seeding the sampling cadence (#2224).
func NewIPFIXExporter(cfg *ExportConfig) (*IPFIXExporter, error) {
	// #3740: stable per-group Observation Domain ID (RFC 7011 §3.1) derived
	// from the config identity so two same-collector groups no longer collide
	// on ODID=1 (template redefinitions + interleaved sequence streams).
	// HA-symmetric (pure function of config-synced fields — both cluster nodes
	// compute the same ODID). Also the scope value of the #3748 sampler record.
	sourceID := stableExporterID("ipfix", cfg.InstanceName, cfg.TemplateName)
	e := &IPFIXExporter{
		cfg:          cfg,
		sourceID:     sourceID,
		includeDir:   cfg.IncludeFlowDir,
		templateSet:  encodeIPFIXTemplateSetDir(cfg.IncludeFlowDir),
		MaskResolver: NewRouteMaskResolver(0),
	}

	// #3748: advertise the 1-in-N sampling rate via an Options Template +
	// Options Data Record only when the group is actually sampled (rate > 1),
	// matching the ShouldExport gate. Precompute both (the rate and ODID are
	// fixed per group) so the refresh path just re-sends the bytes.
	if cfg.SamplingRate > 1 {
		e.emitSampler = true
		e.optionsTemplateSet = encodeIPFIXOptionsTemplateSet()
		e.optionsDataSet = encodeIPFIXOptionsSamplerDataSet(sourceID, cfg.SamplingRate)
	}

	conns, err := dialCollectors(cfg.Collectors)
	if err != nil {
		return nil, err
	}
	e.conns = conns

	return e, nil
}

// Run starts the IPFIX exporter. Blocks until ctx is cancelled.
func (e *IPFIXExporter) Run(ctx context.Context) {
	e.sendTemplates()

	// #4423 M10: clamp a non-positive refresh rate so NewTicker never panics.
	templateTicker := time.NewTicker(templateRefreshInterval(e.cfg.TemplateRefreshRate))
	defer templateTicker.Stop()

	batchTicker := time.NewTicker(100 * time.Millisecond)
	defer batchTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			e.flushBatches()
			return
		case <-templateTicker.C:
			e.sendTemplates()
		case <-batchTicker.C:
			e.flushBatches()
		}
	}
}

// ExportSessionClose queues a flow record for IPFIX export.
func (e *IPFIXExporter) ExportSessionClose(rec logging.EventRecord, evt SessionCloseData) {
	// #2465: prefer the real session-creation timestamp for StartTime; fall
	// back to the packet-count heuristic (and count it) only when absent.
	startTime, usedEstimate := flowStartTime(rec, evt.Protocol)
	if usedEstimate {
		e.estimatedDurations.Add(1)
	}
	// #2526: resolve the post-NAT tuple with pre-NAT fallback so every
	// exported record carries the RFC 5103 / RFC 8158 post-NAT fields
	// (post == pre when the flow was not translated).
	natSrcIP, natDstIP, natSrcPort, natDstPort := resolvePostNAT(
		evt.SrcIP, evt.DstIP, evt.SrcPort, evt.DstPort,
		evt.NATSrcIP, evt.NATDstIP, evt.NATSrcPort, evt.NATDstPort)
	// #2866: resolve src/dst route prefix lengths from the FIB (0/0 with no
	// resolver wired). #3744: scope to the flow's ingress VRF table (evt.InIf,
	// evt.OutIf fallback) and count any unresolved half.
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
		Protocol: rec.ProtocolNum,
		Packets:  rec.SessionPkts,
		Bytes:    rec.SessionBytes,
		// #3746: RFC 5103 biflow reverse (server→client) volume. Since #2501
		// the SESSION_CLOSE frame carries the reverse counters (decoded to
		// rec.RevSessionPkts/RevSessionBytes); they are encoded as the reverse
		// IPFIX IEs (PEN 29305). Already in scope here — no SessionCloseData
		// plumbing needed.
		RevPackets: rec.RevSessionPkts,
		RevBytes:   rec.RevSessionBytes,
		StartTime:  startTime,
		EndTime:    rec.Time,
		IsIPv6:     evt.IsIPv6,
		SrcMask:    srcMask,
		DstMask:    dstMask,
		NATSrcIP:   natSrcIP,
		NATDstIP:   natDstIP,
		NATSrcPort: natSrcPort,
		NATDstPort: natDstPort,
		// #2749: ingress ifindex (SNMP ifIndex) -> IPFIX ingressInterface; plus
		// the re-introduced ipClassOfService (IE 5) / tcpControlBits (IE 6) /
		// egressInterface (IE 14).
		InIf:     evt.InIf,
		TOS:      evt.TOS,
		TCPFlags: evt.TCPFlags,
		OutIf:    evt.OutIf,
		// #3270: flowDirection (IE 61), derived from sampling-direction in the
		// daemon callback. Encoded only when the group enabled flow-dir.
		Direction: evt.Direction,
	}

	e.batch.add(fr)
}

// Stats returns export statistics.
func (e *IPFIXExporter) Stats() (flows, packets uint64) {
	return e.exportedFlows.Load(), e.exportedPkts.Load()
}

// EstimatedDurations returns the count of exported session-close flows whose
// StartTime was derived from the packet-count heuristic (#2465) rather than a
// real session-creation timestamp.
func (e *IPFIXExporter) EstimatedDurations() uint64 {
	return e.estimatedDurations.Load()
}

// RouteMaskUnresolved returns the count of exported route-mask halves (#3744)
// exported as an unresolved 0 rather than a real matched-route prefix length.
// See Exporter.RouteMaskUnresolved.
func (e *IPFIXExporter) RouteMaskUnresolved() uint64 {
	return e.routeMaskUnresolved.Load()
}

// BatchDepth returns the current number of flow records pending in the export
// batch (both families combined). See Exporter.BatchDepth (#3747).
func (e *IPFIXExporter) BatchDepth() uint64 { return e.batch.depth() }

// BatchMaxDepth returns the high-water mark of the pending batch depth (#3747).
func (e *IPFIXExporter) BatchMaxDepth() uint64 { return e.batch.MaxDepth() }

// BatchDropped returns the cumulative count of flow records dropped because
// the export batch was at capacity. See Exporter.BatchDropped (#3747).
func (e *IPFIXExporter) BatchDropped() uint64 { return e.batch.Dropped() }

// Retire quiesces the exporter's batch admission lease ahead of the final
// flush on ctx cancel — the IPFIX equivalent of Exporter.Retire (#4963).
func (e *IPFIXExporter) Retire() { e.batch.retire() }

// HandoffDropped returns the count of session-close records this exporter
// rejected because they arrived after it was retired (#4963).
func (e *IPFIXExporter) HandoffDropped() uint64 { return e.batch.HandoffDropped() }

// SetHandoffCounter injects a fixed-cardinality family-level handoff-drop
// counter — the IPFIX equivalent of Exporter.SetHandoffCounter (#4963).
func (e *IPFIXExporter) SetHandoffCounter(c *atomic.Uint64) { e.batch.setSharedHandoff(c) }

// CollectorHealth returns a per-collector write-health snapshot (#2464).
func (e *IPFIXExporter) CollectorHealth() []CollectorHealth {
	return e.conns.health()
}

// Close shuts down all collector connections.
func (e *IPFIXExporter) Close() {
	e.conns.close()
}

func (e *IPFIXExporter) sendTemplates() {
	// RFC 7011 §3.1 / §10.3.2: the IPFIX Sequence Number is the cumulative
	// count of Data Records sent in all prior Messages for this Observation
	// Domain (the value of the NEXT Data Record's sequence). A Message that
	// carries only (Options) Template Sets contains no Data Records, so it
	// MUST NOT advance the counter — but it MUST carry the current cumulative
	// value, not 0. Emitting 0 on every periodic template refresh rewinds the
	// header sequence, which loss/sequence-tracking collectors (pmacct,
	// Elastiflow) read as packet loss or an exporter restart (#2609). Read
	// e.seq under e.mu WITHOUT incrementing it (no data records are sent).
	e.mu.Lock()
	seq := e.seq
	e.mu.Unlock()

	now := time.Now()
	hdr := ipfixHeader{
		Version:        10,
		Length:         uint16(16 + len(e.templateSet)),
		ExportTime:     uint32(now.Unix()),
		SequenceNumber: seq,
		ObservationID:  e.sourceID,
	}

	pkt := make([]byte, 16+len(e.templateSet))
	encodeIPFIXHeaderInto(pkt[:16], hdr)
	copy(pkt[16:], e.templateSet)
	e.conns.writeAll(pkt, "ipfix template send failed")

	// #3748: on the same refresh cadence, advertise the 1-in-N sampling
	// configuration (Options Template + Options Data Record) for sampled groups.
	if e.emitSampler {
		e.sendSamplerOptions()
	}
}

// sendSamplerOptions emits the sampler Options Template Set (Set ID 3, template
// ID 258) followed by its Options Data Record (Set ID 258) in one IPFIX Message,
// advertising the group's 1-in-N sampling rate as RFC 7014 systematic
// count-based FLOW selection (#3748/#5312). Called on the template-refresh
// cadence for sampled groups.
//
// FLOW-granularity representation (#5312): xpf samples 1-in-N at SESSION-RECORD
// granularity — ShouldExport applies the modulo per SESSION_CLOSE event,
// selecting whole Flows, not 1-in-N packets in the datapath as Junos jflow
// does. The record therefore carries the RFC 7014 flow-selection IEs
// (flowSelectorAlgorithm=1 / samplingFlowInterval=1 / samplingFlowSpacing=N-1),
// NOT the PSAMP packet-selection IEs (selectorAlgorithm / samplingPacketInterval
// / samplingPacketSpace). A standards collector reads flow selection as "you
// received 1/N of all Flows" and scales the POPULATION (flow count, aggregate
// volume) by N, while each exported record's octetDeltaCount / packetDeltaCount
// stays the complete per-session volume and is NOT renormalized by N. The
// packet-selection IEs would have wrongly implied the opposite — per-record
// counter renormalization — which is the #5312 defect this replaces.
//
// The Options Data Record is a Data Record (it rides a Set with ID >= 256), so
// it advances the header Sequence Number by one, consistent with the #2609
// convention in sendRecords: capture the current cumulative count for THIS
// message's header, then increment for the record it carries. A collector that
// tracks sequence numbers counts this record too, so skipping the increment
// would look like the loss #2609 fixed.
func (e *IPFIXExporter) sendSamplerOptions() {
	body := make([]byte, 0, len(e.optionsTemplateSet)+len(e.optionsDataSet))
	body = append(body, e.optionsTemplateSet...)
	body = append(body, e.optionsDataSet...)

	e.mu.Lock()
	seq := e.seq
	e.seq++ // the Options Data Record counts toward the sequence (RFC 7011 §3.1)
	e.mu.Unlock()

	now := time.Now()
	hdr := ipfixHeader{
		Version:        10,
		Length:         uint16(16 + len(body)),
		ExportTime:     uint32(now.Unix()),
		SequenceNumber: seq,
		ObservationID:  e.sourceID,
	}

	pkt := make([]byte, 16+len(body))
	encodeIPFIXHeaderInto(pkt[:16], hdr)
	copy(pkt[16:], body)
	e.conns.writeAll(pkt, "ipfix options template send failed")
}

func (e *IPFIXExporter) flushBatches() {
	v4, v6 := e.batch.drain()

	if len(v4) > 0 {
		e.sendRecords(v4)
	}
	if len(v6) > 0 {
		e.sendRecords(v6)
	}
}

func (e *IPFIXExporter) sendRecords(records []FlowRecord) {
	if len(records) == 0 {
		return
	}

	isV6 := records[0].IsIPv6
	var tmplID uint16
	if isV6 {
		tmplID = ipfixTemplateIDv6
	} else {
		tmplID = ipfixTemplateIDv4
	}
	recSize := ipfixRecordSize(isV6, e.includeDir)

	// Reserve 16 bytes for IPFIX header + 4 bytes for set header
	maxRecords := (maxPayload - 16 - 4) / recSize
	if maxRecords < 1 {
		maxRecords = 1
	}

	for i := 0; i < len(records); i += maxRecords {
		end := i + maxRecords
		if end > len(records) {
			end = len(records)
		}
		batch := records[i:end]
		dataLen := ipfixDataSetLen(len(batch), recSize)

		e.mu.Lock()
		seq := e.seq
		e.seq += uint32(len(batch))
		e.mu.Unlock()

		now := time.Now()
		hdr := ipfixHeader{
			Version:        10,
			Length:         uint16(16 + dataLen),
			ExportTime:     uint32(now.Unix()),
			SequenceNumber: seq,
			ObservationID:  e.sourceID,
		}

		pkt := make([]byte, 16+dataLen)
		encodeIPFIXHeaderInto(pkt[:16], hdr)
		encodeIPFIXDataSetInto(pkt[16:], batch, tmplID, recSize, e.includeDir)
		if e.conns.writeAll(pkt, "ipfix data send failed") {
			e.exportedFlows.Add(uint64(len(batch)))
			e.exportedPkts.Add(1)
		}
	}
}
