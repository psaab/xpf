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
		{name: "hop-by-hop", proto: 0},
		{name: "destination-options", proto: 60},
		{name: "icmpv6", proto: 58},
		{name: "esp", proto: 50},
	} {
		t.Run(tc.name, func(t *testing.T) {
			packet := classifyV6Packet(t, tc.proto, src, dst, 1, 2, 3, 4)
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
