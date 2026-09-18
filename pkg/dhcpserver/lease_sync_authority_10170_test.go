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

func TestMergeLeasesByAuthorityRejectsGenerationMismatch10170(t *testing.T) {
	local := []SyncLease{{Family: 4, Address: "10.0.4.10", ValidLife: 100, HWAddress: "aa"}}
	peer := LeaseSyncSnapshot{
		Received:   true,
		Generation: 8,
		Leases:     []SyncLease{{Family: 4, Address: "10.0.4.20", ValidLife: 100, HWAddress: "bb"}},
		Scopes: []LeaseScopeAuthority{{
			Family: 4, CIDR: "10.0.4.0/24", RGID: 2, Generation: 7, Served: true, Applied: true,
		}},
	}
	authority := LeaseSyncAuthority{Scopes: []LeaseScopeAuthority{{Family: 4, CIDR: "10.0.4.0/24", RGID: 2, Served: true}}}
	if got := mergeLeasesByAuthority(local, peer, 4, authority, true); len(got) != 2 {
		t.Fatalf("generation-mismatched proof must retain conservative union, got %#v", got)
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

func TestMergeLeasesByAuthorityRetainsOmittedScopeUnderSkew10170(t *testing.T) {
	local := []SyncLease{
		{Family: 4, Address: "10.0.2.10", HWAddress: "aa:02"},
		{Family: 4, Address: "10.0.9.10", HWAddress: "aa:09"},
	}
	peer := LeaseSyncSnapshot{
		Received: true, Generation: 8,
		Leases: []SyncLease{
			{Family: 4, Address: "10.0.2.20", HWAddress: "bb:02"},
			{Family: 4, Address: "10.0.9.20", HWAddress: "bb:09"},
		},
		Scopes: []LeaseScopeAuthority{
			{Family: 4, CIDR: "10.0.2.0/24", RGID: 2, Generation: 8, Served: true, Applied: true},
			{Family: 4, CIDR: "10.0.9.0/24", RGID: 9, Generation: 8, Served: true, Applied: true},
		},
	}
	// The receiver's lagging config emits only .2. The sender's extra .9
	// proof must not authorize deletion of the receiver's live .9 lease.
	authority := LeaseSyncAuthority{Scopes: []LeaseScopeAuthority{
		{Family: 4, CIDR: "10.0.2.0/24", RGID: 2, Served: true},
	}}
	got := mergeLeasesByAuthority(local, peer, 4, authority, true)
	if !containsLeaseAddress10170(got, "10.0.9.10") || !containsLeaseAddress10170(got, "10.0.9.20") {
		t.Fatalf("receiver-omitted scope was narrowed under config skew: %#v", got)
	}
}

func TestMergeLeasesByAuthorityRejectsMovedRGProof10170(t *testing.T) {
	local := []SyncLease{{Family: 4, Address: "10.0.2.10", HWAddress: "aa"}}
	peer := LeaseSyncSnapshot{
		Received: true, Generation: 4,
		Leases: []SyncLease{{Family: 4, Address: "10.0.2.20", HWAddress: "bb"}},
		Scopes: []LeaseScopeAuthority{{Family: 4, CIDR: "10.0.2.0/24", RGID: 2, Generation: 4, Served: true, Applied: true}},
	}
	authority := LeaseSyncAuthority{Scopes: []LeaseScopeAuthority{{Family: 4, CIDR: "10.0.2.0/24", RGID: 3, Served: true}}}
	if got := mergeLeasesByAuthority(local, peer, 4, authority, true); len(got) != 2 {
		t.Fatalf("same CIDR with moved RG must retain conservative union, got %#v", got)
	}
	matched, eligible := partitionPeerScopes(peer.Scopes, authority.Scopes)
	if len(matched) != 0 || len(eligible) != 0 {
		t.Fatalf("moved RG proof was accepted as a local scope match: matched=%+v eligible=%+v", matched, eligible)
	}
}

func containsLeaseAddress10170(leases []SyncLease, address string) bool {
	for _, lease := range leases {
		if lease.Address == address {
			return true
		}
	}
	return false
}
