package flowexport

// #16126 STEP 0: golden wire bytes captured BEFORE any refactor.
//
// This file was written against the pre-refactor tree (current master
// 974028945c, issue-verified at 0976d8be74) BEFORE the shared FlowRecord
// enrichment core (buildFlowRecord / exporterCore) existed. Its only job
// is to freeze the exact bytes the two stateful encoders put on the wire
// for deterministic inputs, so the refactor is proven byte-identical by
// comparison rather than by inspection:
//
//   - NetFlow v9: template packets increment the header sequence by one
//     per MESSAGE, data packets carry Count=len(batch) and the template
//     FlowSet carries both v4+v6 templates.
//   - IPFIX: template packets carry the CURRENT cumulative data-record
//     count WITHOUT advancing it (#2609), data packets advance it by
//     len(batch), and the sampler Options Data Record advances it by one.
//
// Nothing here may be "fixed" to match a refactored implementation: if a
// post-refactor run changes a byte, either the refactor or the golden is
// wrong, and the diff must be explained before either moves. The golden
// sections include a semantic anchor (the sequence number of every
// packet) so a regenerated golden cannot silently bless a sequence
// regression: regenerating must reproduce the same anchors, which are
// derived from the RFC semantics documented above, not from the bytes.
//
// Determinism: bootTimeFunc is pinned (v9 First/LastSwitched become a
// function of the frozen boot instant and record times), record/event
// times are fixed, and the wall-clock header stamps (v9 SysUptime/
// UnixSecs, IPFIX ExportTime) that sendTemplates/sendRecords take from
// time.Now() are masked to 0xFF before comparison. Length and every
// unmasked byte, including all sequence numbers, are compared exactly.
//
// The enrichment goldens feed the same session-close event through BOTH
// exporters and compare the queued FlowRecord field-by-field. That is
// the pre-refactor twin behaviour buildFlowRecord must reproduce: note
// it also freezes the one intentional divergence -- IPFIX populates
// RevPackets/RevBytes from the close event, v9 leaves them zero.
//
// Update (only for a deliberate, reviewed wire change):
//
//	GOLDEN_16126_UPDATE=1 go test ./pkg/flowexport/ -run 'TestGolden|TestBuildFlowRecord' -count=1

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"runtime"

	"github.com/psaab/xpf/pkg/logging"
)

// goldenEpoch is the frozen close/export instant for every golden cell.
var goldenEpoch = time.Unix(1_700_000_000, 123_000_000).UTC()

// goldenBoot is the pinned device-boot instant: exactly 10_000 seconds
// (10_000_000 ms) before the flow start used below, inside the ~49.7-day
// uint32 sysUptime window.
var goldenBoot = goldenEpoch.Add(-10_000 * time.Second)

type goldenMask struct{ off, length int }

func maskWireBytes(pkt []byte, masks []goldenMask) []byte {
	out := append([]byte(nil), pkt...)
	for _, m := range masks {
		for i := m.off; i < m.off+m.length && i < len(out); i++ {
			out[i] = 0xFF
		}
	}
	return out
}

// v9 header: SysUptime u32 @4, UnixSecs u32 @8. Seq @12 is golden-compared.
var goldenV9Masks = []goldenMask{{4, 4}, {8, 4}}

// IPFIX header: ExportTime u32 @4. Seq @8 is golden-compared.
var goldenIPFIXMasks = []goldenMask{{4, 4}}

// goldenStubConn records every Write payload; no socket is involved.
type goldenStubConn struct {
	net.Conn
	mu  sync.Mutex
	buf [][]byte
}

func (c *goldenStubConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.buf = append(c.buf, append([]byte(nil), p...))
	return len(p), nil
}

func (c *goldenStubConn) Close() error               { return nil }
func (c *goldenStubConn) SetWriteDeadline(time.Time) error { return nil }
func (c *goldenStubConn) LocalAddr() net.Addr        { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1} }

func (c *goldenStubConn) packets() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([][]byte(nil), c.buf...)
}

func goldenConns(c net.Conn) *collectorConns {
	return &collectorConns{conns: []*collectorConn{{conn: c, addr: "golden", healthy: true}}}
}

func goldenPinBoot(t *testing.T) {
	t.Helper()
	orig := bootTimeFunc
	bootTimeFunc = func() time.Time { return goldenBoot }
	t.Cleanup(func() { bootTimeFunc = orig })
}

// goldenFile is the parsed testdata/golden_16126.txt corpus.
type goldenFile struct {
	sections map[string]string
	order    []string
}

func goldenPath(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "testdata", "golden_16126.txt")
}

func loadGoldenOrUpdate(t *testing.T) *goldenFile {
	t.Helper()
	if os.Getenv("GOLDEN_16126_UPDATE") == "1" {
		return &goldenFile{sections: map[string]string{}}
	}
	return loadGolden(t)
}

func loadGolden(t *testing.T) *goldenFile {
	t.Helper()
	b, err := os.ReadFile(goldenPath(t))
	if err != nil {
		t.Fatalf("golden: read baseline (create it once with GOLDEN_16126_UPDATE=1): %v", err)
	}
	g := &goldenFile{sections: map[string]string{}}
	var cur string
	var body strings.Builder
	flush := func() {
		if cur != "" {
			g.sections[cur] = strings.TrimRight(body.String(), "\n")
		}
		body.Reset()
	}
	for _, ln := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(ln, "=== ") && strings.HasSuffix(ln, " ===") {
			flush()
			cur = strings.TrimSuffix(strings.TrimPrefix(ln, "=== "), " ===")
			g.order = append(g.order, cur)
			continue
		}
		body.WriteString(ln)
		body.WriteByte('\n')
	}
	flush()
	return g
}

func (g *goldenFile) check(t *testing.T, name, got string) {
	t.Helper()
	if os.Getenv("GOLDEN_16126_UPDATE") == "1" {
		goldensMu.Lock()
		goldensGot[name] = got
		goldensMu.Unlock()
		return
	}
	want, ok := g.sections[name]
	if !ok {
		t.Fatalf("golden: section %q missing from testdata/golden_16126.txt (run with GOLDEN_16126_UPDATE=1 only for a deliberate wire change)", name)
	}
	if got == want {
		return
	}
	gl, wl := strings.Split(got, "\n"), strings.Split(want, "\n")
	for i := 0; i < len(gl) || i < len(wl); i++ {
		var gv, wv string
		if i < len(gl) {
			gv = gl[i]
		}
		if i < len(wl) {
			wv = wl[i]
		}
		if gv != wv {
			t.Fatalf("golden: section %q line %d differs\n got: %s\nwant: %s\n(full got %d lines, want %d lines; a byte change here needs a reviewed explanation, not a blind regeneration)",
				name, i+1, gv, wv, len(gl), len(wl))
		}
	}
	t.Fatalf("golden: section %q differs", name)
}

var (
	goldensMu  sync.Mutex
	goldensGot = map[string]string{}
)

// TestMain-free golden flush: TestGoldenFlush runs last (file order is
// not guaranteed, so each golden test registers and this one writes).
func flushGoldens(t *testing.T) {
	t.Helper()
	if os.Getenv("GOLDEN_16126_UPDATE") != "1" {
		return
	}
	goldensMu.Lock()
	defer goldensMu.Unlock()
	if len(goldensGot) == 0 {
		return
	}
	path := goldenPath(t)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("golden: mkdir: %v", err)
	}
	// Merge with sections already flushed by an earlier test in this run.
	merged := map[string]string{}
	if b0, err := os.ReadFile(path); err == nil {
		var cur string
		var body strings.Builder
		flushOld := func() {
			if cur != "" {
				merged[cur] = strings.TrimRight(body.String(), "\n")
			}
			body.Reset()
		}
		for _, ln := range strings.Split(string(b0), "\n") {
			if strings.HasPrefix(ln, "=== ") && strings.HasSuffix(ln, " ===") {
				flushOld()
				cur = strings.TrimSuffix(strings.TrimPrefix(ln, "=== "), " ===")
				continue
			}
			body.WriteString(ln)
			body.WriteByte('\n')
		}
		flushOld()
	}
	for n, v := range goldensGot {
		merged[n] = v
	}
	goldensGot = merged
	var b strings.Builder
	names := make([]string, 0, len(goldensGot))
	for n := range goldensGot {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(&b, "=== %s ===\n%s\n", n, goldensGot[n])
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatalf("golden: write: %v", err)
	}
	t.Logf("golden: updated %s (%d sections)", path, len(names))
	// A second write in the same process must be a no-op diff.
	goldensGot = map[string]string{}
}

func renderPackets(pkts [][]byte, masks []goldenMask, seqOff int) string {
	var b strings.Builder
	for i, p := range pkts {
		seq := uint32(0)
		if len(p) >= seqOff+4 {
			seq = binary.BigEndian.Uint32(p[seqOff : seqOff+4])
		}
		fmt.Fprintf(&b, "pkt %d len=%d seq=%d hex=%s\n", i, len(p), seq,
			hex.EncodeToString(maskWireBytes(p, masks)))
	}
	return strings.TrimRight(b.String(), "\n")
}

func goldenRecord(dir bool, v6, nat, rev bool, i int) FlowRecord {
	src, dst := net.IPv4(10, 0, 0, 1), net.IPv4(192, 0, 2, 2)
	ns, nd := src, dst
	sp, dp := uint16(12345), uint16(443)
	nsp, ndp := sp, dp
	if v6 {
		src, dst = net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2")
		ns, nd = src, dst
	}
	if nat {
		if v6 {
			ns, nd = net.ParseIP("2001:db8::99"), net.ParseIP("2001:db8::98")
		} else {
			ns, nd = net.IPv4(172, 16, 0, 9), net.IPv4(172, 16, 0, 10)
		}
		nsp, ndp = 40000, 8443
	}
	r := FlowRecord{
		SrcIP: src, DstIP: dst, SrcPort: sp + uint16(i), DstPort: dp,
		Protocol: 6, TOS: 0xB8, TCPFlags: 0x1B, InIf: 7, OutIf: 9,
		Packets: uint64(1000 + i), Bytes: uint64(60000 + i*10),
		StartTime:  goldenEpoch.Add(-time.Minute),
		EndTime:    goldenEpoch,
		SrcMask:    24, DstMask: 25, IsIPv6: v6,
		NATSrcIP: ns, NATDstIP: nd, NATSrcPort: nsp, NATDstPort: ndp,
	}
	if dir {
		r.Direction = 1
	}
	if rev {
		r.RevPackets, r.RevBytes = 555, 777000
	}
	return r
}

func goldenRecords(dir bool, v6 bool, n int) []FlowRecord {
	out := make([]FlowRecord, n)
	for i := range out {
		out[i] = goldenRecord(dir, v6, i%2 == 1, true, i)
	}
	return out
}

func goldenRenderRecord(r FlowRecord) string {
	return fmt.Sprintf("src=%s dst=%s sport=%d dport=%d proto=%d tos=%d flags=%d dir=%d in=%d out=%d pkts=%d bytes=%d revpkts=%d revbytes=%d start=%d end=%d srcmask=%d dstmask=%d v6=%v natsrc=%s natdst=%s natsport=%d natdport=%d",
		ipStr(r.SrcIP), ipStr(r.DstIP), r.SrcPort, r.DstPort, r.Protocol, r.TOS, r.TCPFlags, r.Direction,
		r.InIf, r.OutIf, r.Packets, r.Bytes, r.RevPackets, r.RevBytes,
		r.StartTime.UnixMilli(), r.EndTime.UnixMilli(), r.SrcMask, r.DstMask, r.IsIPv6,
		ipStr(r.NATSrcIP), ipStr(r.NATDstIP), r.NATSrcPort, r.NATDstPort)
}

func ipStr(ip net.IP) string {
	if ip == nil {
		return "<nil>"
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4.String()
	}
	return ip.To16().String()
}

// --- NetFlow v9 golden -------------------------------------------------

func TestGoldenNetFlowV9Wire(t *testing.T) {
	goldenPinBoot(t)
	g := loadGoldenOrUpdate(t)
	defer flushGoldens(t)

	newExp := func(dir bool) (*Exporter, *goldenStubConn) {
		conn := &goldenStubConn{}
		e := &Exporter{
			cfg:             &ExportConfig{V9TemplateOpts: V9TemplateOptions{IncludeFlowDir: dir}},
			bootTime:        bootTimeFunc(),
			sourceID:        0x0A0B0C0D,
			fieldsV4:        buildTemplateFieldsV4(V9TemplateOptions{IncludeFlowDir: dir}),
			fieldsV6:        buildTemplateFieldsV6(V9TemplateOptions{IncludeFlowDir: dir}),
			templateFlowSet: encodeTemplateFlowSet(V9TemplateOptions{IncludeFlowDir: dir}),
			conns:           goldenConns(conn),
		}
		e.recSizeV4 = recordSize(e.fieldsV4)
		e.recSizeV6 = recordSize(e.fieldsV6)
		return e, conn
	}

	for _, dir := range []bool{false, true} {
		tag := "nodir"
		if dir {
			tag = "dir"
		}
		e, conn := newExp(dir)
		// Empty flush: no packet, no sequence consumed.
		e.sendRecords(nil)
		e.flushBatches()
		if n := len(conn.packets()); n != 0 {
			t.Fatalf("v9 %s: empty send emitted %d packets", tag, n)
		}
		e.sendTemplates() // seq 0
		e.sendRecords(goldenRecords(dir, false, 3)) // seq 1
		// Overflow: more records than one maxPayload datagram holds.
		recSize := e.recSizeV4
		maxRec := (maxPayload - 20 - 4 - 3) / recSize
		over := maxRec + 2
		e.sendRecords(goldenRecords(dir, false, over)) // seq 2,3
		e.sendRecords(goldenRecords(dir, true, 2))     // v6, seq 4
		e.sendTemplates()                              // seq 5
		// Anchors: per-MESSAGE increments 0..5; data counts are len(batch).
		pkts := conn.packets()
		wantSeq := []uint32{0, 1, 2, 3, 4, 5}
		if len(pkts) != len(wantSeq) {
			t.Fatalf("v9 %s: got %d packets, want %d (template,batch,overflow x2,v6,template)", tag, len(pkts), len(wantSeq))
		}
		for i, p := range pkts {
			if got := binary.BigEndian.Uint32(p[12:16]); got != wantSeq[i] {
				t.Fatalf("v9 %s pkt %d seq=%d want %d (per-message cadence)", tag, i, got, wantSeq[i])
			}
		}
		if c := binary.BigEndian.Uint16(pkts[1][2:4]); int(c) != 3 {
			t.Fatalf("v9 %s data pkt count=%d want 3", tag, c)
		}
		g.check(t, "netflow-v9-"+tag, renderPackets(pkts, goldenV9Masks, 12))

		// Encoding helpers (no exporter state) under the same golden.
		enc := encodeDataFlowSet(goldenRecords(dir, false, 2), goldenBoot, V9TemplateOptions{IncludeFlowDir: dir})
		g.check(t, "netflow-v9-"+tag+"-dataflowset",
			fmt.Sprintf("len=%d hex=%s", len(enc), hex.EncodeToString(enc)))
		ts := encodeTemplateFlowSet(V9TemplateOptions{IncludeFlowDir: dir})
		g.check(t, "netflow-v9-"+tag+"-templateflowset",
			fmt.Sprintf("len=%d hex=%s", len(ts), hex.EncodeToString(ts)))
	}
}

// --- IPFIX golden ------------------------------------------------------

func TestGoldenIPFIXWire(t *testing.T) {
	goldenPinBoot(t)
	g := loadGoldenOrUpdate(t)
	defer flushGoldens(t)

	newExp := func(dir, sampler bool) (*IPFIXExporter, *goldenStubConn) {
		conn := &goldenStubConn{}
		e := &IPFIXExporter{
			cfg:         &ExportConfig{IncludeFlowDir: dir},
			sourceID:    0x0A0B0C0D,
			includeDir:  dir,
			templateSet: encodeIPFIXTemplateSetDir(dir),
			conns:       goldenConns(conn),
		}
		if sampler {
			e.emitSampler = true
			e.optionsTemplateSet = encodeIPFIXOptionsTemplateSet()
			e.optionsDataSet = encodeIPFIXOptionsSamplerDataSet(0x0A0B0C0D, 10)
		}
		return e, conn
	}

	for _, tc := range []struct {
		tag     string
		dir     bool
		sampler bool
	}{
		{"nodir", false, false},
		{"dir", true, false},
		{"sampler", false, true},
	} {
		e, conn := newExp(tc.dir, tc.sampler)
		e.sendRecords(nil) // empty: no packet, no seq advance
		e.flushBatches()
		if n := len(conn.packets()); n != 0 {
			t.Fatalf("ipfix %s: empty send emitted %d packets", tc.tag, n)
		}
		e.sendTemplates() // seq 0 (template-only, no advance); sampler options follows at seq 0 then advances to 1
		cur := uint32(0)
		if tc.sampler {
			cur = 1
		}
		e.sendRecords(goldenRecords(tc.dir, false, 3)) // seq cur, advances +3
		cur += 3
		e.sendTemplates() // seq cur, no advance (sampler: options at cur, then cur++)
		if tc.sampler {
			cur++
		}
		recSize := ipfixRecordSize(false, tc.dir)
		maxRec := (maxPayload - 16 - 4) / recSize
		over := maxRec + 2
		e.sendRecords(goldenRecords(tc.dir, false, over)) // maxRec + 2 records in 2 datagrams
		e.sendRecords(goldenRecords(tc.dir, true, 2))     // v6
		pkts := conn.packets()
		// Anchor the whole cadence semantically before comparing bytes.
		// Packet order: [tmpl (+sampler-opts)] data3 [tmpl (+sampler-opts)] overflow-a overflow-b v6.
		want := []uint32{0}
		c := uint32(0)
		if tc.sampler {
			want = append(want, 0)
			c = 1
		}
		want = append(want, c) // data3 header
		c += 3
		want = append(want, c) // template refresh header
		if tc.sampler {
			want = append(want, c) // sampler options header
			c++
		}
		want = append(want, c) // overflow datagram 1 (maxRec records)
		c += uint32(maxRec)
		want = append(want, c) // overflow datagram 2 (2 records)
		c += 2
		want = append(want, c) // v6 data (2 records)
		_ = cur
		if len(pkts) != len(want) {
			t.Fatalf("ipfix %s: got %d packets want %d: %v", tc.tag, len(pkts), len(want), want)
		}
		for i, p := range pkts {
			if len(p) < 16 {
				t.Fatalf("ipfix %s pkt %d short %d", tc.tag, i, len(p))
			}
			if got := binary.BigEndian.Uint32(p[8:12]); got != want[i] {
				t.Fatalf("ipfix %s pkt %d seq=%d want %d (template no-advance / data +count cadence)", tc.tag, i, got, want[i])
			}
		}
		g.check(t, "ipfix-"+tc.tag, renderPackets(pkts, goldenIPFIXMasks, 8))

		ds := encodeIPFIXDataSetDir(goldenRecords(tc.dir, false, 2), tc.dir)
		g.check(t, "ipfix-"+tc.tag+"-dataset",
			fmt.Sprintf("len=%d hex=%s", len(ds), hex.EncodeToString(ds)))
		ts := encodeIPFIXTemplateSetDir(tc.dir)
		g.check(t, "ipfix-"+tc.tag+"-templateset",
			fmt.Sprintf("len=%d hex=%s", len(ts), hex.EncodeToString(ts)))
		if tc.sampler {
			g.check(t, "ipfix-sampler-optionstemplate",
				fmt.Sprintf("len=%d hex=%s", len(e.optionsTemplateSet), hex.EncodeToString(e.optionsTemplateSet)))
			g.check(t, "ipfix-sampler-optionsdata",
				fmt.Sprintf("len=%d hex=%s", len(e.optionsDataSet), hex.EncodeToString(e.optionsDataSet)))
		}
	}
}

// --- Enrichment golden -------------------------------------------------

func goldenCloseEvent() (logging.EventRecord, SessionCloseData) {
	rec := logging.EventRecord{
		Time: goldenEpoch, Type: "SESSION_CLOSE",
		Created: uint32(goldenEpoch.Add(-time.Minute).Unix()), CreatedNanos: 123_000_000,
		ProtocolNum: 47, SessionPkts: 111, SessionBytes: 22222,
		RevSessionPkts: 33, RevSessionBytes: 4444,
	}
	evt := SessionCloseData{
		SrcIP: net.IPv4(10, 1, 2, 3), DstIP: net.IPv4(192, 0, 2, 9),
		SrcPort: 5000, DstPort: 53, Protocol: 17, IsIPv6: false,
		NATSrcIP: net.IPv4(172, 16, 9, 9), NATDstPort: 5353,
		InIf: 3, OutIf: 4, TOS: 0x28, TCPFlags: 0x12, Direction: 1,
	}
	return rec, evt
}

func TestGoldenEnrichmentTwin(t *testing.T) {
	g := loadGoldenOrUpdate(t)
	defer flushGoldens(t)
	rec, evt := goldenCloseEvent()

	nf := &Exporter{}
	nf.ExportSessionClose(rec, evt)
	v4, _ := nf.batch.drain()
	if len(v4) != 1 {
		t.Fatalf("v9 enrichment: %d records", len(v4))
	}
	g.check(t, "enrich-netflow", goldenRenderRecord(v4[0]))

	ip := &IPFIXExporter{}
	ip.ExportSessionClose(rec, evt)
	v4b, _ := ip.batch.drain()
	if len(v4b) != 1 {
		t.Fatalf("ipfix enrichment: %d records", len(v4b))
	}
	g.check(t, "enrich-ipfix", goldenRenderRecord(v4b[0]))

	// Missing-created + skew cells enrich identically (StartTime=close).
	rec2 := rec
	rec2.Created, rec2.CreatedNanos = 0, 0
	nf2 := &Exporter{}
	nf2.ExportSessionClose(rec2, evt)
	r2, _ := nf2.batch.drain()
	g.check(t, "enrich-netflow-nocreated", goldenRenderRecord(r2[0]))
}
