package dhcpserver

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// #16854: a peer that masters only a DHCP-less RG must not push its stale
// memfile-fallback rows, and a receiver must treat the peer's explicit
// Served:false scope as negative proof even when the sender is an older
// binary that still pushes the rows.

func TestGetSyncLeasesWithSourceReportsMemfileFallback16854(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	dir := t.TempDir()
	memfile := filepath.Join(dir, "kea-leases4.csv")
	expire := now.Unix() + 1800
	csv := "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state\n" +
		"10.0.61.77,aa:bb:cc:dd:ee:77,01:aa:bb:cc:dd:ee:77,3600," +
		strconv.FormatInt(expire, 10) + ",2,0,0,stale-host,0\n"
	if err := os.WriteFile(memfile, []byte(csv), 0644); err != nil {
		t.Fatal(err)
	}
	m := New()
	m.unitActive = func(string) (bool, error) { return false, nil }
	m.SetLeaseSyncSeamsForTesting(nil, filepath.Join(dir, "missing.sock"), "", memfile, "")

	leases, live, err := m.GetSyncLeases4WithSource(context.Background(), now)
	if err != nil {
		t.Fatalf("GetSyncLeases4WithSource: %v", err)
	}
	if live {
		t.Fatal("memfile fallback must report live=false")
	}
	if len(leases) != 1 || leases[0].Address != "10.0.61.77" {
		t.Fatalf("fallback rows = %+v", leases)
	}
}

func TestMergeLeasesByAuthorityExcludesServedFalsePeerRows16854(t *testing.T) {
	local := []SyncLease{{Family: 4, Address: "10.0.61.10", HWAddress: "aa:10"}}
	peer := LeaseSyncSnapshot{
		Received: true, Generation: 7,
		Leases: []SyncLease{
			{Family: 4, Address: "10.0.61.77", HWAddress: "bb:77"},
			{Family: 4, Address: "10.0.99.5", HWAddress: "bb:99"},
		},
		Scopes: []LeaseScopeAuthority{
			{Family: 4, CIDR: "10.0.61.0/24", RGID: 2, Generation: 7, Served: false, Applied: false},
		},
	}
	authority := LeaseSyncAuthority{Scopes: []LeaseScopeAuthority{
		{Family: 4, CIDR: "10.0.61.0/24", RGID: 2, Served: true},
	}}
	got := mergeLeasesByAuthority(local, peer, 4, authority, true)
	for _, lease := range got {
		if lease.Address == "10.0.61.77" {
			t.Fatalf("peer stale row in Served:false scope survived: %+v", got)
		}
	}
	// The local live row and the peer row in an unknown scope survive.
	if !containsLeaseAddress10170(got, "10.0.61.10") || !containsLeaseAddress10170(got, "10.0.99.5") {
		t.Fatalf("negative proof dropped rows outside the scope: %+v", got)
	}
}

func TestPeerLeasesForAuthorityExcludesServedFalsePeerRows16854(t *testing.T) {
	peer := LeaseSyncSnapshot{
		Received: true, Generation: 7,
		Leases: []SyncLease{
			{Family: 4, Address: "10.0.61.77", HWAddress: "bb:77"},
			{Family: 4, Address: "10.0.99.5", HWAddress: "bb:99"},
		},
		Scopes: []LeaseScopeAuthority{
			{Family: 4, CIDR: "10.0.61.0/24", RGID: 2, Generation: 7, Served: false, Applied: false},
		},
	}
	authority := LeaseSyncAuthority{Scopes: []LeaseScopeAuthority{
		{Family: 4, CIDR: "10.0.61.0/24", RGID: 2, Served: true},
	}}
	got := PeerLeasesForAuthority(peer, 4, authority)
	if len(got) != 1 || got[0].Address != "10.0.99.5" {
		t.Fatalf("post-start seed kept a Served:false peer row: %+v", got)
	}
}

// Positive control (#10170): Served:true without Applied is unproven, not
// negative — the conservative whole union is retained.
func TestMergeLeasesByAuthorityServedUnappliedKeepsUnion16854(t *testing.T) {
	local := []SyncLease{{Family: 4, Address: "10.0.61.10", HWAddress: "aa:10"}}
	peer := LeaseSyncSnapshot{
		Received: true, Generation: 7,
		Leases: []SyncLease{{Family: 4, Address: "10.0.61.77", HWAddress: "bb:77"}},
		Scopes: []LeaseScopeAuthority{
			{Family: 4, CIDR: "10.0.61.0/24", RGID: 2, Generation: 7, Served: true, Applied: false},
		},
	}
	authority := LeaseSyncAuthority{Scopes: []LeaseScopeAuthority{
		{Family: 4, CIDR: "10.0.61.0/24", RGID: 2, Served: true},
	}}
	if got := mergeLeasesByAuthority(local, peer, 4, authority, true); len(got) != 2 {
		t.Fatalf("Served:true/Applied:false must retain the union, got %+v", got)
	}
}

// #17886: a peer snapshot mixing one positive (Served:true/Applied:true) scope
// with one negative (Served:false) scope must still exclude the stale row in
// the negative scope. Before the fix the positive branch returned
// peerLeasesForScopes directly and never applied negative filtering.
func TestMixedPositiveNegativeScopesExcludeNegative17886(t *testing.T) {
	local := []SyncLease{{Family: 4, Address: "10.0.61.10", HWAddress: "aa:10"}}
	peer := LeaseSyncSnapshot{
		Received: true, Generation: 7,
		Leases: []SyncLease{
			{Family: 4, Address: "10.0.61.77", HWAddress: "bb:77"},
			{Family: 4, Address: "10.0.62.77", HWAddress: "bb:99"},
		},
		Scopes: []LeaseScopeAuthority{
			{Family: 4, CIDR: "10.0.61.0/24", RGID: 2, Generation: 7, Served: true, Applied: true},
			{Family: 4, CIDR: "10.0.62.0/24", RGID: 3, Generation: 7, Served: false, Applied: false},
		},
	}
	authority := LeaseSyncAuthority{Scopes: []LeaseScopeAuthority{
		{Family: 4, CIDR: "10.0.61.0/24", RGID: 2, Served: true},
		{Family: 4, CIDR: "10.0.62.0/24", RGID: 3, Served: true},
	}}
	if got := PeerLeasesForAuthority(peer, 4, authority); len(got) != 1 || got[0].Address != "10.0.61.77" {
		t.Fatalf("mixed snapshot post-start seed = %+v, want only 10.0.61.77", got)
	}
	got := mergeLeasesByAuthority(local, peer, 4, authority, true)
	for _, lease := range got {
		if lease.Address == "10.0.62.77" {
			t.Fatalf("mixed snapshot merge kept negative-scope peer row: %+v", got)
		}
	}
	if !containsLeaseAddress10170(got, "10.0.61.10") || !containsLeaseAddress10170(got, "10.0.61.77") {
		t.Fatalf("mixed snapshot merge dropped local or positive peer row: %+v", got)
	}
}

// #17886: a live unit whose control socket transiently fails is not proof that
// it stopped serving. Falling back to its stale memfile would publish an
// authoritative empty snapshot and replace the peer's last good set.
func TestGetSyncLeasesActiveSocketFailureDoesNotFallback17886(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	dir := t.TempDir()
	memfile := filepath.Join(dir, "kea-leases4.csv")
	expire := now.Unix() + 1800
	csv := "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state\n" +
		"10.0.61.77,aa:bb:cc:dd:ee:77,01:aa:bb:cc:dd:ee:77,3600," +
		strconv.FormatInt(expire, 10) + ",2,0,0,stale-host,0\n"
	if err := os.WriteFile(memfile, []byte(csv), 0644); err != nil {
		t.Fatal(err)
	}
	m := New()
	m.SetLeaseSyncSeamsForTesting(nil, filepath.Join(dir, "missing.sock"), "", memfile, "")
	m.unitActive = func(string) (bool, error) { return true, nil }

	leases, live, err := m.GetSyncLeases4WithSource(context.Background(), now)
	if err == nil {
		t.Fatalf("active Kea with failed socket read must not publish memfile fallback: live=%v leases=%+v", live, leases)
	}
	if live || len(leases) != 0 {
		t.Fatalf("untrusted fallback result = live=%v leases=%+v, want no snapshot data", live, leases)
	}
}
