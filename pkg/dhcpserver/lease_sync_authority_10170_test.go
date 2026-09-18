package dhcpserver

import "testing"

func TestMergeLeasesByAuthorityDoesNotSeedUnservedPeerRG10170(t *testing.T) {
	local := []SyncLease{
		{Family: 4, Address: "10.0.2.10", ValidLife: 100, HWAddress: "aa:02"},
		{Family: 4, Address: "10.0.3.10", ValidLife: 100, HWAddress: "aa:03"},
	}
	peer := LeaseSyncSnapshot{
		Received: true, Generation: 7,
		Leases: []SyncLease{
			{Family: 4, Address: "10.0.2.20", ValidLife: 100, HWAddress: "bb:02"},
			{Family: 4, Address: "10.0.3.20", ValidLife: 100, HWAddress: "bb:03"},
		},
		Scopes: []LeaseScopeAuthority{
			{Family: 4, CIDR: "10.0.2.0/24", RGID: 2, Generation: 7, Served: true, Applied: true},
			{Family: 4, CIDR: "10.0.3.0/24", RGID: 3, Generation: 7, Served: true, Applied: true},
		},
	}
	authority := LeaseSyncAuthority{Scopes: []LeaseScopeAuthority{
		{Family: 4, CIDR: "10.0.2.0/24", RGID: 2, Served: true},
		{Family: 4, CIDR: "10.0.3.0/24", RGID: 3, Served: false},
	}}
	got := mergeLeasesByAuthority(local, peer, 4, authority, true)
	for _, lease := range got {
		if lease.Address == "10.0.3.10" || lease.Address == "10.0.3.20" {
			t.Fatalf("unserved RG3 lease survived authority filter: %#v", got)
		}
	}
	if len(got) != 2 {
		t.Fatalf("expected local+peer RG2 rows only, got %#v", got)
	}
}

func TestMergeLeasesByAuthorityFallsBackWithoutApplyProof10170(t *testing.T) {
	local := []SyncLease{{Family: 4, Address: "10.0.3.10", ValidLife: 100, HWAddress: "aa"}}
	peer := LeaseSyncSnapshot{Received: true, Generation: 7, Leases: []SyncLease{{Family: 4, Address: "10.0.3.20", ValidLife: 100, HWAddress: "bb"}}, Scopes: []LeaseScopeAuthority{{Family: 4, CIDR: "10.0.3.0/24", Generation: 7, Served: true, Applied: false}}}
	authority := LeaseSyncAuthority{Scopes: []LeaseScopeAuthority{{Family: 4, CIDR: "10.0.3.0/24", Served: false}}}
	got := mergeLeasesByAuthority(local, peer, 4, authority, false)
	if len(got) != 2 {
		t.Fatalf("unproven peer scope must retain conservative union, got %#v", got)
	}
}

func TestPeerLeasesForAuthorityMatchesPostStartFilter10170(t *testing.T) {
	peer := LeaseSyncSnapshot{Received: true, Generation: 3, Leases: []SyncLease{{Family: 4, Address: "10.0.2.5"}, {Family: 4, Address: "10.0.3.5"}}, Scopes: []LeaseScopeAuthority{{Family: 4, CIDR: "10.0.2.0/24", Generation: 3, Served: true, Applied: true}, {Family: 4, CIDR: "10.0.3.0/24", Generation: 3, Served: true, Applied: true}}}
	authority := LeaseSyncAuthority{Scopes: []LeaseScopeAuthority{{Family: 4, CIDR: "10.0.2.0/24", Served: true}, {Family: 4, CIDR: "10.0.3.0/24", Served: false}}}
	got := PeerLeasesForAuthority(peer, 4, authority)
	if len(got) != 1 || got[0].Address != "10.0.2.5" {
		t.Fatalf("post-start filter diverged from authority merge: %#v", got)
	}
}
