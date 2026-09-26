package lldp

import (
	"net"
	"testing"
	"time"
)

// TestMaxTTLFloodRecoversOnNextNeighbor_10898 uses fake receive times to prove
// that 64 still-live maximum-TTL advertisements cannot squat on the interface
// cap after the flood stops. A new maximum-TTL peer is admitted on its first
// frame, before any spoofed entry expires; its legal wire TTL remains intact.
func TestMaxTTLFloodRecoversOnNextNeighbor_10898(t *testing.T) {
	const maxWireTTL = 0xffff

	m := New()
	floodStart := time.Unix(1_800_000_000, 0)
	keys := make([]neighborKey, maxNeighborsPerInterface)
	for i := range maxNeighborsPerInterface {
		mac := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, byte(i)}
		frame, err := BuildFrame(mac, "spoofed-port", maxWireTTL, "flood", "")
		if err != nil {
			t.Fatalf("BuildFrame flood peer %d: %v", i, err)
		}
		n := ParseTLVs(frame[ethHdrLen:])
		if n == nil || n.TTL != maxWireTTL {
			t.Fatalf("maximum-TTL flood peer %d did not parse at full TTL: %+v", i, n)
		}
		n.Interface = "eth0"
		n.LastSeen = floodStart.Add(time.Duration(i) * time.Second)
		n.ExpiresAt = n.LastSeen.Add(time.Duration(n.TTL) * time.Second)
		keys[i] = neighborKeyFor(n.Interface, n)
		if !m.learnNeighbor(keys[i], n) {
			t.Fatalf("maximum-TTL flood peer %d was not admitted within cap", i)
		}
	}
	if got := len(m.Neighbors()); got != maxNeighborsPerInterface {
		t.Fatalf("flood filled %d entries, want cap %d", got, maxNeighborsPerInterface)
	}

	// The flood stops while all 64 entries remain valid. The first later
	// neighbor frame must be admitted immediately; it must not wait for the
	// attacker-controlled 65535-second TTL or the 10-second expiry tick.
	floodEnd := floodStart.Add((maxNeighborsPerInterface - 1) * time.Second)
	firstPostFloodFrame := floodEnd.Add(time.Second)
	for _, n := range m.Neighbors() {
		if !n.ExpiresAt.After(firstPostFloodFrame) {
			t.Fatalf("fixture: spoofed peer expired before recovery time: %+v", n)
		}
	}

	legitMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x01, 0x00, 0x01}
	frame, err := BuildFrame(legitMAC, "legit-port", maxWireTTL, "legitimate", "")
	if err != nil {
		t.Fatalf("BuildFrame legitimate peer: %v", err)
	}
	legit := ParseTLVs(frame[ethHdrLen:])
	if legit == nil || legit.TTL != maxWireTTL {
		t.Fatalf("valid maximum-TTL peer did not parse at full TTL: %+v", legit)
	}
	legit.Interface = "eth0"
	legit.LastSeen = firstPostFloodFrame
	legit.ExpiresAt = legit.LastSeen.Add(time.Duration(legit.TTL) * time.Second)
	legitKey := neighborKeyFor(legit.Interface, legit)
	if !m.learnNeighbor(legitKey, legit) {
		t.Fatal("first neighbor after flood was not admitted")
	}

	neighbors := m.Neighbors()
	if len(neighbors) != maxNeighborsPerInterface {
		t.Fatalf("post-flood admission changed bounded table size: got %d, want %d", len(neighbors), maxNeighborsPerInterface)
	}
	m.mu.RLock()
	_, oldestStillPresent := m.neighbors[keys[0]]
	storedLegit := m.neighbors[legitKey]
	m.mu.RUnlock()
	if oldestStillPresent {
		t.Fatal("post-flood admission did not evict the least-recently-seen spoofed peer")
	}
	if storedLegit == nil || storedLegit.TTL != maxWireTTL ||
		!storedLegit.ExpiresAt.Equal(firstPostFloodFrame.Add(maxWireTTL*time.Second)) {
		t.Fatalf("legal maximum-TTL peer was not preserved with full expiry: %+v", storedLegit)
	}
}
