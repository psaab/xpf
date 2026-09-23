package dataplane

import "testing"

// No bare probe: the store hands (key, domain, id) straight to the
// helper-first peer surface without consulting the local mirror.
func TestDeleteClusterScopedThreadsIdentity10512(t *testing.T) {
	dp := &peerRecorderDP{}
	s := NewDataPlaneSessionStore(dp)
	key := SessionKey{Protocol: 6, SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2}, SrcPort: 1234, DstPort: 80}
	if err := s.DeleteClusterScopedV4(key, 100007, 0xF10512); err != nil {
		t.Fatalf("scoped delete failed: %v", err)
	}
	if len(dp.peerScopedV4) != 1 {
		t.Fatalf("helper got %d scoped deletes, want 1", len(dp.peerScopedV4))
	}
	got := dp.peerScopedV4[0]
	if got.key != key || got.domain != 100007 || got.id != 0xF10512 {
		t.Fatalf("helper got %+v, want (key, 100007, 0xF10512)", got)
	}
	key6 := SessionKeyV6{Protocol: 6, SrcPort: 1234, DstPort: 80}
	key6.SrcIP[15] = 1
	key6.DstIP[15] = 2
	if err := s.DeleteClusterScopedV6(key6, 200007, 0xC10512); err != nil {
		t.Fatalf("scoped v6 delete failed: %v", err)
	}
	if len(dp.peerScopedV6) != 1 {
		t.Fatalf("helper got %d scoped v6 deletes, want 1", len(dp.peerScopedV6))
	}
	got6 := dp.peerScopedV6[0]
	if got6.key != key6 || got6.domain != 200007 || got6.id != 0xC10512 {
		t.Fatalf("helper got %+v, want (key, 200007, 0xC10512)", got6)
	}
}

type noScopedCapabilityDP10512 struct {
	DataPlane
}

// A dataplane without the peer-delete capability errors LOUDLY — never
// falls back to an unconditional delete.
func TestDeleteClusterScopedWithoutCapabilityErrors10512(t *testing.T) {
	s := NewDataPlaneSessionStore(&noScopedCapabilityDP10512{})
	key := SessionKey{Protocol: 6, SrcPort: 1, DstPort: 2}
	if err := s.DeleteClusterScopedV4(key, 7, 0xF10512); err == nil {
		t.Fatal("a dataplane without the scoped capability must error, not fall back")
	}
}
