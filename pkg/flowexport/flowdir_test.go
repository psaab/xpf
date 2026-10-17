package flowexport

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// #3270 fail-on-revert pins: flowDirection (IE 61) is advertised + populated
// (from the per-zone sampling-direction) when `export-extension flow-dir` is
// enabled, and ABSENT otherwise (no #2613 synthetic-zero regression).

// flowDirRecord builds a FlowRecord with a distinctive Direction value and a
// post-NAT src whose first byte differs from the Direction sentinel, so the
// encode-value pins fail (read the post-NAT byte instead) if the conditional
// encoder write is reverted.
func flowDirRecord(v6 bool, dir uint8) FlowRecord {
	now := time.Unix(1_700_000_000, 0)
	r := FlowRecord{
		SrcPort: 40000, DstPort: 80, Protocol: 6,
		TOS: 0xB8, TCPFlags: 0x13, Direction: dir,
		InIf: 0xDEADBEEF, OutIf: 0xFEEDFACE,
		Packets: 0x1122334455667788, Bytes: 0x99AABBCCDDEEFF00,
		StartTime: now, EndTime: now,
		SrcMask: 24, DstMask: 32,
	}
	if v6 {
		r.IsIPv6 = true
		r.SrcIP = net.ParseIP("fd00::1")
		r.DstIP = net.ParseIP("2001:db8::200")
		r.NATSrcIP = r.SrcIP
		r.NATDstIP = r.DstIP
	} else {
		r.SrcIP = net.IPv4(10, 0, 1, 100)
		r.DstIP = net.IPv4(172, 16, 80, 200)
		r.NATSrcIP = r.SrcIP
		r.NATDstIP = r.DstIP
	}
	return r
}

// TestFlowDirectionFromSampling pins the per-zone sampling-direction →
// flowDirection mapping, including the ingress-wins tie-break. Reverting the
// FlowDirection method (or the ingress-first ordering) flips a case RED.
func TestFlowDirectionFromSampling(t *testing.T) {
	dirs := map[uint16]SamplingDir{
		1: {Input: true},
		2: {Output: true},
		3: {Input: true, Output: true},
	}
	ec := &ExportConfig{SamplingZones: FamilySamplingDirs{V4: dirs, V6: dirs}}
	for _, tc := range []struct {
		name            string
		inZone, outZone uint16
		isV6            bool
		want            uint8
	}{
		{"ingress input-sampled", 1, 9, false, 0},
		{"egress output-sampled only", 9, 2, false, 1},
		{"both sampled: ingress wins", 1, 2, false, 0},
		{"ingress zone both flags: input wins", 3, 9, false, 0},
		{"neither sampled", 9, 9, false, 0},
		{"v6 ingress input-sampled", 1, 9, true, 0},
		{"v6 egress output-sampled only", 9, 2, true, 1},
	} {
		if got := ec.FlowDirection(tc.inZone, tc.outZone, tc.isV6); got != tc.want {
			t.Errorf("%s: FlowDirection(%d,%d) = %d, want %d",
				tc.name, tc.inZone, tc.outZone, got, tc.want)
		}
	}
}

// TestV9TemplateFlowDirConditionalEncode pins that with IncludeFlowDir the v9
// record carries the real Direction byte at the IE 61 offset, and that the
// record/template sizes account for it.
func TestV9TemplateFlowDirConditionalEncode(t *testing.T) {
	boot := time.Unix(1_700_000_000, 0)
	opts := V9TemplateOptions{IncludeFlowDir: true}
	for _, tc := range []struct {
		name string
		v6   bool
	}{
		{"v4", false},
		{"v6", true},
	} {
		fields := buildTemplateFieldsV4(opts)
		if tc.v6 {
			fields = buildTemplateFieldsV6(opts)
		}
		dirOff, ok := netflowFieldBodyOffset(fields, fieldDirection)
		if !ok {
			t.Fatalf("%s: template missing fieldDirection (61) with IncludeFlowDir", tc.name)
		}
		fs := encodeDataFlowSet([]FlowRecord{flowDirRecord(tc.v6, 1)}, boot, opts)
		recSize := recordSize(fields)
		if wantLen := dataFlowSetLen(1, recSize); len(fs) != wantLen {
			t.Fatalf("%s: flowset len = %d, want %d", tc.name, len(fs), wantLen)
		}
		if got := fs[4+dirOff]; got != 1 {
			t.Errorf("%s: encoded flowDirection = 0x%02x, want 0x01 (encoder write reverted)", tc.name, got)
		}
	}
}

// v9FieldLenSum sums the declared field lengths (the parsed-by-collector
// width, before the FlowSet's 4-byte record padding).
func v9FieldLenSum(fields []templateField) int {
	n := 0
	for _, f := range fields {
		n += int(f.fieldLen)
	}
	return n
}

// TestV9TemplateFlowDirAbsentWithoutKnob pins that enabling flow-dir adds
// exactly one declared field byte to the v9 template (the IE 61 unsigned8) and
// that the default template carries none. The padded recordSize can be
// unchanged (the 4-byte FlowSet padding may absorb the byte), so this compares
// the declared field-length sum, not the padded size.
func TestV9TemplateFlowDirAbsentWithoutKnob(t *testing.T) {
	off := DefaultV9TemplateOptions()
	on := V9TemplateOptions{IncludeFlowDir: true}
	for _, v6 := range []bool{false, true} {
		base := buildTemplateFieldsV4(off)
		dir := buildTemplateFieldsV4(on)
		if v6 {
			base = buildTemplateFieldsV6(off)
			dir = buildTemplateFieldsV6(on)
		}
		if got := v9FieldLenSum(dir) - v9FieldLenSum(base); got != 1 {
			t.Errorf("v6=%v: flow-dir adds %d declared bytes, want 1", v6, got)
		}
		if _, ok := netflowFieldBodyOffset(base, fieldDirection); ok {
			t.Errorf("v6=%v: default template must not advertise flowDirection (61)", v6)
		}
	}
}

// TestIPFIXTemplateFlowDirConditional pins IPFIX IE 61 presence/value/size: it
// is absent in the base template, present with includeDir, and the encoded
// record carries the real Direction byte at the IE 61 offset.
func TestIPFIXTemplateFlowDirConditional(t *testing.T) {
	for _, tc := range []struct {
		name string
		v6   bool
		base int
	}{
		{"v4", false, ipfixRecordSizeV4},
		{"v6", true, ipfixRecordSizeV6},
	} {
		// Base template: IE 61 absent.
		baseFields := ipfixTemplateFieldsV4(false)
		dirFields := ipfixTemplateFieldsV4(true)
		if tc.v6 {
			baseFields = ipfixTemplateFieldsV6(false)
			dirFields = ipfixTemplateFieldsV6(true)
		}
		if _, ok := ipfixFieldBodyOffset(baseFields, ipfixFlowDirection); ok {
			t.Errorf("%s: base template must not advertise flowDirection (61)", tc.name)
		}
		dirOff, ok := ipfixFieldBodyOffset(dirFields, ipfixFlowDirection)
		if !ok {
			t.Fatalf("%s: flow-dir template missing flowDirection (61)", tc.name)
		}

		// Record-size pin: base + 1.
		if got := ipfixRecordSize(tc.v6, true); got != tc.base+1 {
			t.Errorf("%s: ipfixRecordSize(dir) = %d, want %d", tc.name, got, tc.base+1)
		}

		// Encode value pin.
		ds := encodeIPFIXDataSetDir([]FlowRecord{flowDirRecord(tc.v6, 1)}, true)
		if got := len(ds); got != 4+tc.base+1 {
			t.Fatalf("%s: encoded len = %d, want %d", tc.name, got, 4+tc.base+1)
		}
		if got := ds[4+dirOff]; got != 1 {
			t.Errorf("%s: encoded flowDirection = 0x%02x, want 0x01 (encoder write reverted)", tc.name, got)
		}

		// Base encode must NOT include the byte (record one shorter).
		dsBase := encodeIPFIXDataSet([]FlowRecord{flowDirRecord(tc.v6, 1)})
		if got := len(dsBase); got != 4+tc.base {
			t.Errorf("%s: base encoded len = %d, want %d (flow-dir leaked into base)", tc.name, got, 4+tc.base)
		}
	}
}

// TestIPFIXRecordSizeWithDir pins the concrete with-dir record sizes: base
// (#3746 added the 16-byte biflow reverse counters) + 1 flow-dir byte —
// IPFIX V4 87 / V6 135.
func TestIPFIXRecordSizeWithDir(t *testing.T) {
	if got := ipfixRecordSize(false, true); got != 87 {
		t.Errorf("ipfixRecordSize(v4, dir) = %d, want 87", got)
	}
	if got := ipfixRecordSize(true, true); got != 135 {
		t.Errorf("ipfixRecordSize(v6, dir) = %d, want 135", got)
	}
	// Build-time invariant: with-dir template field-length sum equals size.
	if sum := ipfixSumLen(ipfixTemplateFieldsV4(true)); sum != 87 {
		t.Errorf("sum(ipfixTemplateFieldsV4(dir)) = %d, want 87", sum)
	}
	if sum := ipfixSumLen(ipfixTemplateFieldsV6(true)); sum != 135 {
		t.Errorf("sum(ipfixTemplateFieldsV6(dir)) = %d, want 135", sum)
	}
	// Encoded template byte-walk: IE 61 advertised with includeDir.
	ts := encodeIPFIXTemplateSetDir(true)
	if !templateSetHasIE(ts, ipfixFlowDirection) {
		t.Error("encodeIPFIXTemplateSetDir(true): flowDirection (61) not in encoded template set")
	}
	if templateSetHasIE(encodeIPFIXTemplateSet(), ipfixFlowDirection) {
		t.Error("encodeIPFIXTemplateSet() base: flowDirection (61) must be absent")
	}
}

// templateSetHasIE walks an encoded IPFIX template set and reports whether the
// given element ID is advertised in any template record. #3746: field
// specifiers are 4 bytes for an IANA IE and 8 bytes for an enterprise IE
// (top bit of the element ID set + a 4-byte PEN), so the walk masks the
// enterprise bit for the comparison and advances by the specifier width.
func templateSetHasIE(ts []byte, ie uint16) bool {
	off := 4 // skip set header
	for off+4 <= len(ts) {
		off += 2 // skip template ID
		count := int(binary.BigEndian.Uint16(ts[off : off+2]))
		off += 2
		for i := 0; i < count && off+4 <= len(ts); i++ {
			raw := binary.BigEndian.Uint16(ts[off : off+2])
			enterprise := raw&0x8000 != 0
			if raw&0x7fff == ie {
				return true
			}
			if enterprise {
				off += 8
			} else {
				off += 4
			}
		}
	}
	return false
}
