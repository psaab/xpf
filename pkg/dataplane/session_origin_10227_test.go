package dataplane

import "testing"

func TestPutClusterSyncedStampsOrigin10227(t *testing.T) {
	key := SessionKey{Protocol: 6, SrcPort: 1000, DstPort: 80}
	dp := &sessionStoreTestDP{v4: map[SessionKey]SessionValue{}}
	if err := (dataPlaneSessionStore{dp: dp}).PutClusterSyncedV4(key, SessionValue{}); err != nil {
		t.Fatalf("PutClusterSyncedV4: %v", err)
	}
	got, ok := dp.v4[key]
	if !ok {
		t.Fatal("synced row was not installed")
	}
	if got.Flags&SessFlagClusterSynced == 0 {
		t.Fatalf("synced row flags=%#x, want SessFlagClusterSynced", got.Flags)
	}
}

func TestPutClusterSyncedV6StampsOrigin10227(t *testing.T) {
	key := SessionKeyV6{
		Protocol: 6,
		SrcIP:    [16]byte{0x20, 0x01, 0x0d, 0xb8, 1},
		DstIP:    [16]byte{0x20, 0x01, 0x0d, 0xb8, 2},
		SrcPort:  1000,
		DstPort:  80,
	}
	dp := &sessionStoreTestDP{v6: map[SessionKeyV6]SessionValueV6{}}
	if err := (dataPlaneSessionStore{dp: dp}).PutClusterSyncedV6(key, SessionValueV6{}); err != nil {
		t.Fatalf("PutClusterSyncedV6: %v", err)
	}
	got, ok := dp.v6[key]
	if !ok {
		t.Fatal("synced IPv6 row was not installed")
	}
	if got.Flags&SessFlagClusterSynced == 0 {
		t.Fatalf("synced IPv6 row flags=%#x, want SessFlagClusterSynced", got.Flags)
	}
}

func TestUnmappedBulkReconcileDeletesOnlySyncedOrigin10227(t *testing.T) {
	localKey := SessionKey{Protocol: 6, SrcPort: 1001, DstPort: 80}
	syncedKey := SessionKey{Protocol: 6, SrcPort: 1002, DstPort: 80}
	dp := &sessionStoreTestDP{v4: map[SessionKey]SessionValue{
		localKey:  {IngressZone: 77},
		syncedKey: {IngressZone: 77, Flags: SessFlagClusterSynced},
	}}
	result, err := (dataPlaneSessionStore{dp: dp}).ReconcileClusterBulk(ClusterBulkReconcileInput{
		ReceivedV4:     map[SessionKey]struct{}{},
		ReceivedV6:     map[SessionKeyV6]struct{}{},
		ShouldSyncZone: func(uint16) bool { return false },
		IsZoneMapped:   func(uint16) bool { return false },
	})
	if err != nil {
		t.Fatalf("ReconcileClusterBulk: %v", err)
	}
	if result.DeletedV4 != 1 {
		t.Fatalf("DeletedV4=%d, want one synced stale row", result.DeletedV4)
	}
	if _, ok := dp.v4[localKey]; !ok {
		t.Fatal("unmapped node-local row was deleted")
	}
	if _, ok := dp.v4[syncedKey]; ok {
		t.Fatal("unmapped synced stale row survived")
	}
}

func TestUnmappedBulkReconcileDeletesOnlySyncedOriginV6_10227(t *testing.T) {
	localKey := SessionKeyV6{
		Protocol: 6,
		SrcIP:    [16]byte{0x20, 0x01, 0x0d, 0xb8, 3},
		DstIP:    [16]byte{0x20, 0x01, 0x0d, 0xb8, 4},
		SrcPort:  1001,
		DstPort:  80,
	}
	syncedKey := localKey
	syncedKey.SrcPort = 1002
	dp := &sessionStoreTestDP{v6: map[SessionKeyV6]SessionValueV6{
		localKey:  {IngressZone: 77},
		syncedKey: {IngressZone: 77, Flags: SessFlagClusterSynced},
	}}
	result, err := (dataPlaneSessionStore{dp: dp}).ReconcileClusterBulk(ClusterBulkReconcileInput{
		ReceivedV4:     map[SessionKey]struct{}{},
		ReceivedV6:     map[SessionKeyV6]struct{}{},
		ShouldSyncZone: func(uint16) bool { return false },
		IsZoneMapped:   func(uint16) bool { return false },
	})
	if err != nil {
		t.Fatalf("ReconcileClusterBulk: %v", err)
	}
	if result.DeletedV6 != 1 {
		t.Fatalf("DeletedV6=%d, want one synced stale IPv6 row", result.DeletedV6)
	}
	if _, ok := dp.v6[localKey]; !ok {
		t.Fatal("unmapped node-local IPv6 row was deleted")
	}
	if _, ok := dp.v6[syncedKey]; ok {
		t.Fatal("unmapped synced stale IPv6 row survived")
	}
}

func TestClusterSyncedOriginSurvivesBPFMirrorProjection10227(t *testing.T) {
	v4 := SessionValue{Flags: SessFlagClusterSynced}
	if got := v4.toBPF().sessionValue().Flags; got&SessFlagClusterSynced == 0 {
		t.Fatalf("v4 BPF mirror flags=%#x, origin bit was lost", got)
	}
	v6 := SessionValueV6{Flags: SessFlagClusterSynced}
	if got := v6.toBPF().sessionValue().Flags; got&SessFlagClusterSynced == 0 {
		t.Fatalf("v6 BPF mirror flags=%#x, origin bit was lost", got)
	}
}
