package grpcapi

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

func TestPageTokenV4RoundTrip(t *testing.T) {
	key := dataplane.SessionKey{
		SrcIP:    [4]byte{10, 0, 1, 100},
		DstIP:    [4]byte{192, 168, 1, 1},
		SrcPort:  12345,
		DstPort:  80,
		Protocol: 6,
	}
	token := encodePageTokenV4(key)
	kind, keyBytes, err := parsePageToken(token)
	if err != nil {
		t.Fatalf("parsePageToken: %v", err)
	}
	if kind != "v4" {
		t.Fatalf("expected kind=v4, got %s", kind)
	}
	decoded, err := decodeSessionKeyV4(keyBytes)
	if err != nil {
		t.Fatalf("decodeSessionKeyV4: %v", err)
	}
	if decoded.SrcIP != key.SrcIP {
		t.Errorf("SrcIP mismatch: %v != %v", decoded.SrcIP, key.SrcIP)
	}
	if decoded.DstIP != key.DstIP {
		t.Errorf("DstIP mismatch: %v != %v", decoded.DstIP, key.DstIP)
	}
	if decoded.SrcPort != key.SrcPort {
		t.Errorf("SrcPort mismatch: %d != %d", decoded.SrcPort, key.SrcPort)
	}
	if decoded.DstPort != key.DstPort {
		t.Errorf("DstPort mismatch: %d != %d", decoded.DstPort, key.DstPort)
	}
	if decoded.Protocol != key.Protocol {
		t.Errorf("Protocol mismatch: %d != %d", decoded.Protocol, key.Protocol)
	}
}

func TestPageTokenV6RoundTrip(t *testing.T) {
	key := dataplane.SessionKeyV6{
		SrcIP:    [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		DstIP:    [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
		SrcPort:  54321,
		DstPort:  443,
		Protocol: 6,
	}
	token := encodePageTokenV6(key)
	kind, keyBytes, err := parsePageToken(token)
	if err != nil {
		t.Fatalf("parsePageToken: %v", err)
	}
	if kind != "v6" {
		t.Fatalf("expected kind=v6, got %s", kind)
	}
	decoded, err := decodeSessionKeyV6(keyBytes)
	if err != nil {
		t.Fatalf("decodeSessionKeyV6: %v", err)
	}
	if decoded.SrcIP != key.SrcIP {
		t.Errorf("SrcIP mismatch: %v != %v", decoded.SrcIP, key.SrcIP)
	}
	if decoded.DstIP != key.DstIP {
		t.Errorf("DstIP mismatch: %v != %v", decoded.DstIP, key.DstIP)
	}
	if decoded.SrcPort != key.SrcPort {
		t.Errorf("SrcPort mismatch: %d != %d", decoded.SrcPort, key.SrcPort)
	}
	if decoded.DstPort != key.DstPort {
		t.Errorf("DstPort mismatch: %d != %d", decoded.DstPort, key.DstPort)
	}
	if decoded.Protocol != key.Protocol {
		t.Errorf("Protocol mismatch: %d != %d", decoded.Protocol, key.Protocol)
	}
}

func TestPageTokenV6Start(t *testing.T) {
	token := encodePageTokenV6Start()
	kind, keyBytes, err := parsePageToken(token)
	if err != nil {
		t.Fatalf("parsePageToken: %v", err)
	}
	if kind != "v6start" {
		t.Fatalf("expected kind=v6start, got %s", kind)
	}
	if keyBytes != nil {
		t.Fatalf("expected nil keyBytes, got %v", keyBytes)
	}
}

func TestPageTokenInvalid(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{"not base64", "!!!invalid!!!"},
		{"bad prefix", "Y2F0Og"}, // base64("cat:")
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := parsePageToken(tc.token)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestSessionFilterMatchV4(t *testing.T) {
	f := &sessionFilter{
		zoneNames:    make(map[uint16]string),
		zoneIfaces:   make(map[uint16][]string),
		egressIfaces: make(map[sessionEgressKey]string),
	}

	key := dataplane.SessionKey{
		SrcIP:    [4]byte{10, 0, 1, 100},
		DstIP:    [4]byte{192, 168, 1, 1},
		SrcPort:  12345,
		DstPort:  80,
		Protocol: 6,
	}
	val := dataplane.SessionValue{
		IngressZone: 1,
		EgressZone:  2,
	}

	// No filters — should match.
	if !f.matchV4(key, val) {
		t.Error("unfiltered should match")
	}

	// Reverse entry — should not match.
	reverseVal := val
	reverseVal.IsReverse = 1
	if f.matchV4(key, reverseVal) {
		t.Error("reverse entry should not match")
	}

	// Zone filter — should not match wrong zone.
	fZone := &sessionFilter{
		zoneFilter:   99,
		zoneNames:    make(map[uint16]string),
		zoneIfaces:   make(map[uint16][]string),
		egressIfaces: make(map[sessionEgressKey]string),
	}
	if fZone.matchV4(key, val) {
		t.Error("zone filter should reject non-matching zone")
	}

	// Protocol filter — should match TCP.
	fProto := &sessionFilter{
		proto:        6,
		hasProto:     true,
		zoneNames:    make(map[uint16]string),
		zoneIfaces:   make(map[uint16][]string),
		egressIfaces: make(map[sessionEgressKey]string),
	}
	if !fProto.matchV4(key, val) {
		t.Error("protocol filter tcp should match proto 6")
	}
	fProtoUDP := &sessionFilter{
		proto:        17,
		hasProto:     true,
		zoneNames:    make(map[uint16]string),
		zoneIfaces:   make(map[uint16][]string),
		egressIfaces: make(map[sessionEgressKey]string),
	}
	if fProtoUDP.matchV4(key, val) {
		t.Error("protocol filter udp should not match proto 6")
	}
}
