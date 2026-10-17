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

// #14357: ReconcileClusterBulk must purge a peer-synced row that the per-row
// predicate judged not-locally-owned (unattributable in a multi-RG zone),
// even though its zone is mapped. Before the fix the mapped-zone origin
// guard (and the zone-approximation predicate) kept every such stale row.
//
// FAIL-ON-REVERT: revert the syncedNotOwned guard in ReconcileClusterBulk
// (or pass a zone-approximation ShouldSync predicate) and the stale rows
// survive.
func TestMultiRGPeerSyncedMirrorRowPurgedAtBulkEnd14357(t *testing.T) {
	const zone = 42
	stale4 := SessionKey{Protocol: 6, SrcPort: 2101, DstPort: 80}
	received4 := SessionKey{Protocol: 6, SrcPort: 2102, DstPort: 80}
	local4 := SessionKey{Protocol: 6, SrcPort: 2103, DstPort: 80}
	stale6 := SessionKeyV6{Protocol: 6, SrcIP: [16]byte{0x20, 1, 0xdb, 8, 1}, DstIP: [16]byte{0x20, 1, 0xdb, 8, 2}, SrcPort: 2101, DstPort: 80}
	received6 := SessionKeyV6{Protocol: 6, SrcIP: [16]byte{0x20, 1, 0xdb, 8, 3}, DstIP: [16]byte{0x20, 1, 0xdb, 8, 4}, SrcPort: 2102, DstPort: 80}
	local6 := SessionKeyV6{Protocol: 6, SrcIP: [16]byte{0x20, 1, 0xdb, 8, 5}, DstIP: [16]byte{0x20, 1, 0xdb, 8, 6}, SrcPort: 2103, DstPort: 80}

	// Mirror fidelity: values have passed through toBPF().sessionValue() +
	// ScrubNodeLocal, so fold/ifindex are zero and only IngressZone + the
	// ClusterSynced origin bit survive.
	mirror4 := func(flags uint16) SessionValue {
		v := SessionValue{IngressZone: zone, IngressIfaceFold: 0x2202, IngressIfindex: 99, Flags: flags}.toBPF().sessionValue()
		v.ScrubNodeLocal()
		return v
	}
	mirror6 := func(flags uint16) SessionValueV6 {
		v := SessionValueV6{IngressZone: zone, IngressIfaceFold: 0x2202, IngressIfindex: 99, Flags: flags}.toBPF().sessionValue()
		v.ScrubNodeLocal()
		return v
	}
	synced4, synced6 := mirror4(SessFlagClusterSynced), mirror6(SessFlagClusterSynced)
	if synced4.IngressIfaceFold != 0 || synced4.IngressIfindex != 0 || synced4.Flags&SessFlagClusterSynced == 0 {
		t.Fatalf("v4 mirror fixture wrong: %+v", synced4)
	}
	if synced6.IngressIfaceFold != 0 || synced6.IngressIfindex != 0 || synced6.Flags&SessFlagClusterSynced == 0 {
		t.Fatalf("v6 mirror fixture wrong: %+v", synced6)
	}

	dp := &sessionStoreTestDP{
		v4: map[SessionKey]SessionValue{stale4: synced4, received4: synced4, local4: mirror4(0)},
		v6: map[SessionKeyV6]SessionValueV6{stale6: synced6, received6: synced6, local6: mirror6(0)},
	}
	// Exactly the corrected cluster predicates: cluster-synced mirror rows
	// in a multi-RG zone are not locally owned; local rows keep zone answer.
	notOwnedV4 := func(v SessionValue) bool { return v.Flags&SessFlagClusterSynced == 0 }
	notOwnedV6 := func(v SessionValueV6) bool { return v.Flags&SessFlagClusterSynced == 0 }
	result, err := (dataPlaneSessionStore{dp: dp}).ReconcileClusterBulk(ClusterBulkReconcileInput{
		ReceivedV4:     map[SessionKey]struct{}{received4: {}},
		ReceivedV6:     map[SessionKeyV6]struct{}{received6: {}},
		ShouldSyncZone: func(uint16) bool { return true },
		ShouldSyncV4:   notOwnedV4,
		ShouldSyncV6:   notOwnedV6,
		IsZoneMapped:   func(uint16) bool { return true },
	})
	if err != nil {
		t.Fatalf("ReconcileClusterBulk: %v", err)
	}
	if result.DeletedV4 != 1 || result.DeletedV6 != 1 {
		t.Fatalf("deleted v4=%d v6=%d, want 1/1 stale peer rows", result.DeletedV4, result.DeletedV6)
	}
	if _, ok := dp.v4[stale4]; ok {
		t.Fatal("stale peer v4 row survived BulkEnd")
	}
	if _, ok := dp.v6[stale6]; ok {
		t.Fatal("stale peer v6 row survived BulkEnd")
	}
	if _, ok := dp.v4[received4]; !ok {
		t.Fatal("received peer v4 row was deleted")
	}
	if _, ok := dp.v6[received6]; !ok {
		t.Fatal("received peer v6 row was deleted")
	}
	if _, ok := dp.v4[local4]; !ok {
		t.Fatal("local v4 row was deleted")
	}
	if _, ok := dp.v6[local6]; !ok {
		t.Fatal("local v6 row was deleted")
	}
}

func TestSourceNatProvenanceFlagsRoundTrip12187(t *testing.T) {
	const unrelatedFlags = SessFlagSNAT | SessFlagDNAT | SessFlagClusterSynced
	for _, tc := range []struct {
		name       string
		provenance uint8
		want       uint8
	}{
		{name: "unknown", provenance: SourceNatProvenanceUnknown, want: SourceNatProvenanceUnknown},
		{name: "dynamic", provenance: SourceNatProvenanceDynamic, want: SourceNatProvenanceDynamic},
		{name: "static", provenance: SourceNatProvenanceStatic, want: SourceNatProvenanceStatic},
		{name: "future value is unknown", provenance: 3, want: SourceNatProvenanceUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			flags := WithSourceNatProvenance(unrelatedFlags|SessFlagStaticNAT, tc.provenance)
			if got := SourceNatProvenanceFromFlags(flags); got != tc.want {
				t.Fatalf("decoded provenance=%d, want %d (flags=%#x)", got, tc.want, flags)
			}
			if flags&unrelatedFlags != unrelatedFlags {
				t.Fatalf("unrelated flags %#x were not preserved in %#x", unrelatedFlags, flags)
			}
			wantStatic := tc.want == SourceNatProvenanceStatic
			if gotStatic := flags&SessFlagStaticNAT != 0; gotStatic != wantStatic {
				t.Fatalf("static flag=%v, want %v (flags=%#x)", gotStatic, wantStatic, flags)
			}
			if got := (SessionValue{Flags: flags}).toBPF().sessionValue().Flags; got != flags {
				t.Fatalf("IPv4 BPF mirror flags=%#x, want %#x", got, flags)
			}
			if got := (SessionValueV6{Flags: flags}).toBPF().sessionValue().Flags; got != flags {
				t.Fatalf("IPv6 BPF mirror flags=%#x, want %#x", got, flags)
			}
		})
	}

	if got := SourceNatProvenanceFromFlags(SessFlagStaticNAT); got != SourceNatProvenanceUnknown {
		t.Fatalf("marker-clear legacy static bit decoded as provenance %d, want unknown", got)
	}
	if got := WithSourceNatProvenance(SessFlagStaticNAT, SourceNatProvenanceUnknown); got&SessFlagStaticNAT != 0 {
		t.Fatalf("unknown provenance retained stale static flag: %#x", got)
	}
}
