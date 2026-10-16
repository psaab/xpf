package nfqueue

import (
	"encoding/binary"
	"net"
	"testing"
)

// RED batch: IP classifier for the S5 capture actor (r6 §4.3 per-flow FIFO
// keys, r5 §6.8 fragment contract inputs). The actor builds FlowKey and
// FragmentKey/Fragment from ClassifyCapturePayload; unparseable input must
// fail loudly so the actor can fall back instead of mis-keying a flow.

func classifyV4Packet(t *testing.T, id uint16, flagsFrag uint16, proto byte, src, dst net.IP, extra ...byte) []byte {
	t.Helper()
	hdr := make([]byte, 20)
	hdr[0] = 0x45
	binary.BigEndian.PutUint16(hdr[2:4], uint16(20+len(extra)))
	binary.BigEndian.PutUint16(hdr[4:6], id)
	binary.BigEndian.PutUint16(hdr[6:8], flagsFrag)
	hdr[8] = 64
	hdr[9] = proto
	copy(hdr[12:16], src.To4())
	copy(hdr[16:20], dst.To4())
	return append(hdr, extra...)
}

func classifyV6Packet(t *testing.T, next byte, src, dst net.IP, body ...byte) []byte {
	t.Helper()
	hdr := make([]byte, 40)
	hdr[0] = 0x60
	binary.BigEndian.PutUint16(hdr[4:6], uint16(len(body)))
	hdr[6] = next
	hdr[7] = 64
	copy(hdr[8:24], src.To16())
	copy(hdr[24:40], dst.To16())
	return append(hdr, body...)
}

func TestClassifyV4TCPWhole9506(t *testing.T) {
	pkt := classifyV4Packet(t, 0x1234, 0x4000, 6, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"),
		0x00, 0x50, 0x01, 0xbb, 0xde, 0xad, 0xbe, 0xef)
	got, err := ClassifyCapturePayload(pkt)
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if got.Version != 4 || got.IsFragment {
		t.Fatalf("v4 whole = version %d frag %v", got.Version, got.IsFragment)
	}
	if !got.HasPorts || got.SrcPort != 80 || got.DstPort != 443 {
		t.Fatalf("ports = %v %d->%d", got.HasPorts, got.SrcPort, got.DstPort)
	}
	if got.Proto != 6 {
		t.Fatalf("proto = %d", got.Proto)
	}
	again, err := ClassifyCapturePayload(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if got.FlowKey == "" || got.FlowKey != again.FlowKey {
		t.Fatalf("flow key not stable: %q vs %q", got.FlowKey, again.FlowKey)
	}
}

func TestClassifyV4FragmentsShareDatagramKey9506(t *testing.T) {
	src, dst := net.ParseIP("10.1.0.1"), net.ParseIP("10.1.0.2")
	first := classifyV4Packet(t, 77, 0x2000, 17, src, dst, 0x00, 0x35, 0x00, 0x35, 0xaa, 0xbb)
	second := classifyV4Packet(t, 77, 0x0001, 17, src, dst, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33)
	a, err := ClassifyCapturePayload(first)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	b, err := ClassifyCapturePayload(second)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if !a.IsFragment || !a.FragMore || a.FragOffset != 0 || a.FragID != 77 {
		t.Fatalf("first frag = %+v", a)
	}
	if !b.IsFragment || b.FragMore || b.FragOffset != 8 || b.FragID != 77 {
		t.Fatalf("second frag = %+v", b)
	}
	if a.FlowKey != b.FlowKey {
		t.Fatalf("datagram keys differ: %q vs %q", a.FlowKey, b.FlowKey)
	}
	if b.HasPorts {
		t.Fatal("non-first fragment must not report ports")
	}
	key, ok := a.FragmentKey(3, 0, 9)
	if !ok {
		t.Fatal("fragment key refused for a fragment")
	}
	if key.Version != 4 || key.Tunnel != 3 || key.Generation != 9 || key.ID != 77 {
		t.Fatalf("fragment key = %+v", key)
	}
	piece, ok := b.FragmentPiece(second)
	if !ok || piece.Offset != 8 || piece.More || len(piece.Data) != 8 {
		t.Fatalf("second piece = %+v ok=%v", piece, ok)
	}
}

func TestClassifyV4DFWholeIsNotFragment9506(t *testing.T) {
	pkt := classifyV4Packet(t, 9, 0x4000, 1, net.ParseIP("10.2.0.1"), net.ParseIP("10.2.0.2"), 0x08, 0x00, 0x11, 0x22)
	got, err := ClassifyCapturePayload(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if got.IsFragment {
		t.Fatal("DF whole packet classified as fragment")
	}
	if _, ok := got.FragmentKey(1, 0, 1); ok {
		t.Fatal("fragment key accepted for a whole packet")
	}
}

// #13977: CaptureClassification.FlowKey describes only the inner datagram or
// transport tuple. Non-fragment CaptureFrames use it as the owner of
// CapturePipeline's per-flow FIFO and retirement state, so those keys must
// include the admitted tunnel/VRF/queue/generation scope. Fragments bypass
// that FIFO and retain their independent FragmentKey scope.
func TestClassifyFlowScopeKeySeparatesCaptureBoundaries13977(t *testing.T) {
	pkt := classifyV4Packet(t, 0x2222, 0x4000, 6, net.ParseIP("10.3.0.1"), net.ParseIP("10.3.0.2"),
		0x00, 0x50, 0x01, 0xbb, 0xde, 0xad, 0xbe, 0xef)
	got, err := ClassifyCapturePayload(pkt)
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	base := scopedCaptureFlowKey(got.FlowKey, 7, 0, 3, 9)
	scopes := map[string]string{
		"base":              base,
		"different tunnel":  scopedCaptureFlowKey(got.FlowKey, 8, 0, 3, 9),
		"different vrf":     scopedCaptureFlowKey(got.FlowKey, 7, 1, 3, 9),
		"different queue":   scopedCaptureFlowKey(got.FlowKey, 7, 0, 3, 10),
		"different gen":     scopedCaptureFlowKey(got.FlowKey, 7, 0, 4, 9),
		"different queue#2": scopedCaptureFlowKey(got.FlowKey, 7, 0, 3, 11),
	}
	seen := make(map[string]string, len(scopes))
	for name, key := range scopes {
		if key == "" {
			t.Fatalf("%s: empty scoped flow key", name)
		}
		if other, dup := seen[key]; dup {
			t.Fatalf("scoped flow keys collide for %s and %s: %q", other, name, key)
		}
		seen[key] = name
	}
	if again := scopedCaptureFlowKey(got.FlowKey, 7, 0, 3, 9); again != base {
		t.Fatalf("scoped flow key not stable: %q vs %q", base, again)
	}
	if q0 := scopedCaptureFlowKey(got.FlowKey, 7, 0, 3, 0); q0 == base {
		t.Fatalf("queue-0 scoped key unexpectedly equals queue-9 key %q", base)
	}
	// Fragment frames bypass the per-flow FIFO, but their existing sibling
	// identity remains scoped by tunnel, VRF, and capture generation.
	firstFrag := classifyV4Packet(t, 77, 0x2000, 17, net.ParseIP("10.3.0.1"), net.ParseIP("10.3.0.2"),
		0x00, 0x35, 0x00, 0x35, 0xaa, 0xbb)
	frag, err := ClassifyCapturePayload(firstFrag)
	if err != nil {
		t.Fatalf("Classify frag: %v", err)
	}
	baseFragment, ok := frag.FragmentKey(7, 0, 3)
	if !ok {
		t.Fatal("FragmentKey refused fragment")
	}
	otherTunnel, _ := frag.FragmentKey(8, 0, 3)
	otherVRF, _ := frag.FragmentKey(7, 1, 3)
	otherGeneration, _ := frag.FragmentKey(7, 0, 4)
	if baseFragment == otherTunnel || baseFragment == otherVRF || baseFragment == otherGeneration {
		t.Fatal("fragment identity collides across tunnel/VRF/generation")
	}
}

// This regression uses only the pre-existing CaptureFrame API. On the
// unfixed pipeline, queue and generation values were ignored by flow identity.
func TestCapturePipelineFlowFIFOSeparatesQueueGeneration13977(t *testing.T) {
	p := &CapturePipeline{flows: make(map[string]*flowState)}
	first := CaptureFrame{FlowKey: "same-inner-tuple", Generation: 3, QueueNumber: 9}
	second := CaptureFrame{FlowKey: "same-inner-tuple", Generation: 4, QueueNumber: 10}
	p.enqueueFlowLocked(first)
	p.enqueueFlowLocked(second)
	if len(p.flows) != 2 {
		t.Fatalf("per-flow FIFOs = %d, want 2 across queue/generation scopes", len(p.flows))
	}
}
func TestCapturePipelineFlowFIFOSeparatesCaptureScopes13977(t *testing.T) {
	p := &CapturePipeline{flows: make(map[string]*flowState)}
	base := CaptureFrame{FlowKey: "inner-flow", Tunnel: 7, Generation: 3, QueueNumber: 9}
	otherTunnel := base
	otherTunnel.Tunnel = 8
	otherGeneration := base
	otherGeneration.Generation = 4
	otherQueue := base
	otherQueue.QueueNumber = 10
	for _, frame := range []CaptureFrame{base, otherTunnel, otherGeneration, otherQueue} {
		p.enqueueFlowLocked(frame)
	}
	if len(p.flows) != 4 {
		t.Fatalf("per-flow FIFOs = %d, want 4 for distinct tunnel/generation/queue scopes", len(p.flows))
	}
	for _, frame := range []CaptureFrame{base, otherTunnel, otherGeneration, otherQueue} {
		key := scopedCaptureFlowKey(frame.FlowKey, frame.Tunnel, frame.VRF, frame.Generation, frame.QueueNumber)
		if p.flows[key] == nil || len(p.flows[key].frames) != 1 {
			t.Fatalf("capture scope (%d,%d,%d) does not own an independent FIFO", frame.Tunnel, frame.Generation, frame.QueueNumber)
		}
	}
}
func TestClassifyV6TCPWhole9506(t *testing.T) {
	body := []byte{0x01, 0xbb, 0x00, 0x50, 0xde, 0xad, 0xbe, 0xef}
	pkt := classifyV6Packet(t, 6, net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2"), body...)
	got, err := ClassifyCapturePayload(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 6 || got.IsFragment {
		t.Fatalf("v6 whole = %+v", got)
	}
	if !got.HasPorts || got.SrcPort != 443 || got.DstPort != 80 {
		t.Fatalf("ports = %+v", got)
	}
}

func TestClassifyV6FragmentChain9506(t *testing.T) {
	src, dst := net.ParseIP("2001:db8::3"), net.ParseIP("2001:db8::4")
	fragHdr := func(offMF uint16, id uint32) []byte {
		h := make([]byte, 8)
		h[0] = 17
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(b, offMF)
		h[2], h[3] = b[0], b[1]
		binary.BigEndian.PutUint32(h[4:8], id)
		return h
	}
	first := classifyV6Packet(t, 44, src, dst, append(fragHdr(0x0001, 99), 0x00, 0x35, 0x00, 0x35, 0xaa, 0xbb)...)
	second := classifyV6Packet(t, 44, src, dst, append(fragHdr(0x0010, 99), 0xcc, 0xdd, 0xee, 0xff)...)
	a, err := ClassifyCapturePayload(first)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	b, err := ClassifyCapturePayload(second)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if !a.IsFragment || !a.FragMore || a.FragOffset != 0 || a.FragID != 99 {
		t.Fatalf("first frag = %+v", a)
	}
	if !b.IsFragment || b.FragMore || b.FragOffset != 16 || b.FragID != 99 {
		t.Fatalf("second frag = %+v", b)
	}
	if a.FlowKey != b.FlowKey {
		t.Fatalf("datagram keys differ: %q vs %q", a.FlowKey, b.FlowKey)
	}
	if !a.HasPorts || a.SrcPort != 53 {
		t.Fatalf("first frag ports = %+v", a)
	}
}

func TestClassifyV6AtomicFragment9506(t *testing.T) {
	src, dst := net.ParseIP("2001:db8::5"), net.ParseIP("2001:db8::6")
	h := make([]byte, 8)
	h[0] = 6
	binary.BigEndian.PutUint32(h[4:8], 7)
	pkt := classifyV6Packet(t, 44, src, dst, append(h, 0x00, 0x50, 0x01, 0xbb)...)
	got, err := ClassifyCapturePayload(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if !got.IsFragment || got.FragMore || got.FragOffset != 0 || got.FragID != 7 {
		t.Fatalf("atomic frag = %+v", got)
	}
}

func TestClassifyMalformedFailsLoud9506(t *testing.T) {
	vectors := map[string][]byte{
		"empty":   {},
		"one":     {0x45},
		"short4":  {0x45, 0x00, 0x00, 0x14},
		"ihl":     append([]byte{0x46}, make([]byte, 10)...),
		"version": {0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		"short6":  append([]byte{0x60}, make([]byte, 20)...),
	}
	for name, v := range vectors {
		if _, err := ClassifyCapturePayload(v); err == nil {
			t.Fatalf("%s: expected error, got nil", name)
		}
	}
	// Truncation at every prefix of a valid packet must error, never panic.
	full := classifyV4Packet(t, 1, 0x4000, 6, net.ParseIP("10.3.0.1"), net.ParseIP("10.3.0.2"), 0x00, 0x50, 0x01, 0xbb)
	for i := range 20 {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("prefix %d panicked: %v", i, r)
				}
			}()
			_, _ = ClassifyCapturePayload(full[:i])
		}()
	}
	if _, err := ClassifyCapturePayload(full); err != nil {
		t.Fatalf("full packet: %v", err)
	}
}

func TestClassifyV6NonTransportProtocols10897(t *testing.T) {
	src, dst := net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2")
	for _, tc := range []struct {
		name  string
		proto byte
	}{
		{name: "hop-by-hop", proto: 59},
		{name: "destination-options", proto: 59},
		{name: "icmpv6", proto: 58},
		{name: "esp", proto: 50},
	} {
		t.Run(tc.name, func(t *testing.T) {
			first := tc.proto
			body := []byte{1, 2, 3, 4}
			if tc.name == "hop-by-hop" || tc.name == "destination-options" {
				first = 0
				if tc.name == "destination-options" {
					first = 60
				}
				body = []byte{tc.proto, 0, 0, 0, 0, 0, 0, 0}
			}
			packet := classifyV6Packet(t, first, src, dst, body...)
			got, err := ClassifyCapturePayload(packet)
			if err != nil {
				t.Fatalf("ClassifyCapturePayload: %v", err)
			}
			if got.Version != 6 || got.Proto != tc.proto || got.IsFragment {
				t.Fatalf("classification = %+v, want v6 proto %d unfragmented", got, tc.proto)
			}
			if got.HasPorts {
				t.Fatalf("non-TCP/UDP proto %d unexpectedly has ports: %+v", tc.proto, got)
			}
			if got.FlowKey == "" {
				t.Fatal("non-TCP/UDP packet has no flow key")
			}
		})
	}
}

func TestClassifyV6FragmentNonTransportProtocols10897(t *testing.T) {
	src, dst := net.ParseIP("2001:db8::3"), net.ParseIP("2001:db8::4")
	for _, tc := range []struct {
		name  string
		proto byte
	}{
		{name: "icmpv6", proto: 58},
		{name: "destination-options", proto: 60},
		{name: "esp", proto: 50},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fragmentHeader := make([]byte, 8)
			fragmentHeader[0] = tc.proto
			binary.BigEndian.PutUint16(fragmentHeader[2:4], 1)
			binary.BigEndian.PutUint32(fragmentHeader[4:8], 10897)
			packet := classifyV6Packet(t, 44, src, dst,
				append(fragmentHeader, 1, 2, 3, 4)...)

			got, err := ClassifyCapturePayload(packet)
			if err != nil {
				t.Fatalf("ClassifyCapturePayload: %v", err)
			}
			if got.Version != 6 || got.Proto != tc.proto || !got.IsFragment ||
				!got.FragMore || got.FragOffset != 0 || got.FragID != 10897 {
				t.Fatalf("classification = %+v, want first v6 fragment proto %d", got, tc.proto)
			}
			if got.HasPorts {
				t.Fatalf("non-TCP/UDP fragment proto %d unexpectedly has ports: %+v", tc.proto, got)
			}
			if _, ok := got.FragmentKey(7, 2, 9); !ok {
				t.Fatal("fragment classification has no fragment key")
			}
			piece, ok := got.FragmentPiece(packet)
			if !ok || !piece.More || piece.Offset != 0 ||
				string(piece.Data) != string([]byte{1, 2, 3, 4}) {
				t.Fatalf("fragment piece = %+v, ok=%v", piece, ok)
			}
		})
	}
}

// #13976: a Fragment header behind a walked extension chain must classify
// as a fragment. Before the fix only an immediate NextHeader==44 was
// recognised, so HBH/Routing/DstOpts/AH -> Fragment packets escaped
// IsFragment (no FragmentKey, ordinary flow queue instead of the
// enforcing fragment path).
func TestClassifyV6FragmentBehindExtChain13976(t *testing.T) {
	src, dst := net.ParseIP("2001:db8::7"), net.ParseIP("2001:db8::8")
	ext := func(next, hdrExtLen byte) []byte {
		h := make([]byte, (int(hdrExtLen)+1)*8)
		h[0] = next
		h[1] = hdrExtLen
		return h
	}
	frag := func(next byte, offMF uint16, id uint32, tail ...byte) []byte {
		h := make([]byte, 8)
		h[0] = next
		binary.BigEndian.PutUint16(h[2:4], offMF)
		binary.BigEndian.PutUint32(h[4:8], id)
		return append(h, tail...)
	}
	udp := []byte{0x00, 0x35, 0x00, 0x35, 0xaa, 0xbb}
	cases := []struct {
		name string
		pkt  []byte
	}{
		{"hbh-first", classifyV6Packet(t, 0, src, dst, append(ext(44, 0), frag(17, 0x0001, 42, udp...)...)...)},
		{"routing-first", classifyV6Packet(t, 43, src, dst, append(ext(44, 0), frag(17, 0x0001, 42, udp...)...)...)},
		{"dstopts-first", classifyV6Packet(t, 60, src, dst, append(ext(44, 0), frag(17, 0x0001, 42, udp...)...)...)},
		{"ah-first", classifyV6Packet(t, 51, src, dst, append([]byte{44, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, frag(17, 0x0001, 42, udp...)...)...)},
		{"mobility-first", classifyV6Packet(t, 135, src, dst, append(ext(44, 0), frag(17, 0x0001, 42, udp...)...)...)},
		{"hip-first", classifyV6Packet(t, 139, src, dst, append(ext(44, 0), frag(17, 0x0001, 42, udp...)...)...)},
		{"shim6-first", classifyV6Packet(t, 140, src, dst, append(ext(44, 0), frag(17, 0x0001, 42, udp...)...)...)},
		{"exp253-first", classifyV6Packet(t, 253, src, dst, append(ext(44, 0), frag(17, 0x0001, 42, udp...)...)...)},
		{"exp254-first", classifyV6Packet(t, 254, src, dst, append(ext(44, 0), frag(17, 0x0001, 42, udp...)...)...)},
		{"multi-hop", classifyV6Packet(t, 0, src, dst, append(append(ext(43, 0), ext(44, 1)...), frag(6, 0x0011, 7, 0x00, 0x50, 0x01, 0xbb, 0, 0, 0, 0)...)...)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ClassifyCapturePayload(tc.pkt)
			if err != nil {
				t.Fatalf("Classify: %v", err)
			}
			if !got.IsFragment || !got.FragMore || got.FragID == 0 {
				t.Fatalf("classification = %+v, want fragment behind ext chain", got)
			}
			if _, ok := got.FragmentKey(1, 0, 1); !ok {
				t.Fatalf("no fragment key for %+v", got)
			}
			if got.FragOffset == 0 {
				if !got.HasPorts {
					t.Fatalf("first fragment behind chain must expose ports: %+v", got)
				}
			} else if got.HasPorts {
				t.Fatalf("non-first fragment must not expose ports: %+v", got)
			}
			piece, ok := got.FragmentPiece(tc.pkt)
			if !ok || piece.Offset != got.FragOffset || len(piece.Data) == 0 {
				t.Fatalf("piece = %+v ok=%v class=%+v", piece, ok, got)
			}
		})
	}
	// Non-first fragment behind chain: offset preserved.
	nonFirst := classifyV6Packet(t, 0, src, dst, append(ext(44, 0), frag(17, 0x0009, 42, 1, 2, 3, 4)...)...)
	got, err := ClassifyCapturePayload(nonFirst)
	if err != nil || !got.IsFragment || got.FragOffset != 8 || got.HasPorts {
		t.Fatalf("non-first behind chain = %+v err=%v", got, err)
	}
	// Negatives: chains without Fragment stay unfragmented and keep ports.
	noFrag := classifyV6Packet(t, 0, src, dst, append(ext(6, 0), udp...)...)
	got, err = ClassifyCapturePayload(noFrag)
	if err != nil || got.IsFragment || !got.HasPorts || got.SrcPort != 53 {
		t.Fatalf("no-frag chain = %+v err=%v", got, err)
	}
	// Truncated / over-long chains fail closed.
	for name, pkt := range map[string][]byte{
		"trunc-ext":   classifyV6Packet(t, 0, src, dst, 44),
		"overrun-ext": classifyV6Packet(t, 0, src, dst, 44, 5, 0, 0),
		"trunc-frag-behind": classifyV6Packet(t, 0, src, dst,
			append(ext(44, 0), 17, 0)...),
	} {
		if _, err := ClassifyCapturePayload(pkt); err == nil {
			t.Fatalf("%s: expected error", name)
		}
	}
	// Over-limit: 8 extension headers before Fragment exceeds the
	// 8-iteration bound (the Fragment would be the 9th header).
	var over []byte
	for range 8 {
		over = append(over, ext(60, 0)...)
	}
	over = append(over, ext(44, 0)...)
	over = append(over, frag(17, 1, 9, udp...)...)
	if _, err := ClassifyCapturePayload(classifyV6Packet(t, 60, src, dst, over...)); err == nil {
		t.Fatal("over-limit chain: expected error")
	}
	// Boundary parity with Rust MAX_IPV6_EXT_HEADERS=8: six extension
	// headers then a Fragment as the 7th header (terminal on the 8th
	// iteration) still resolves as a fragment.
	var atBound []byte
	for range 6 {
		atBound = append(atBound, ext(60, 0)...)
	}
	atBound = append(atBound, ext(44, 0)...)
	atBound = append(atBound, frag(17, 0x0001, 43, udp...)...)
	got, err = ClassifyCapturePayload(classifyV6Packet(t, 60, src, dst, atBound...))
	if err != nil || !got.IsFragment || got.FragID != 43 || !got.HasPorts {
		t.Fatalf("fragment within bound = %+v err=%v, want resolved fragment", got, err)
	}
	// Seven extension headers then a Fragment as the 8th header: the
	// fragment is declared at the walk bound. The sibling Rust walker
	// records the sighting but returns OverLimit (its non-fragment
	// consumers fail closed); this capture classifier likewise cannot
	// adjudicate past the bound, so it must fail closed rather than
	// classify — and must never return a plain (non-fragment) verdict
	// that would be submitted for adjudication.
	var atLimit []byte
	for range 7 {
		atLimit = append(atLimit, ext(60, 0)...)
	}
	atLimit = append(atLimit, ext(44, 0)...)
	atLimit = append(atLimit, frag(17, 0x0001, 44, udp...)...)
	if _, err := ClassifyCapturePayload(classifyV6Packet(t, 60, src, dst, atLimit...)); err == nil {
		t.Fatal("fragment as 8th header: expected over-limit error")
	}
}
