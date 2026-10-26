package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/ddns"
)

// #2691 P1b / #2664 daemon-level per-RG DDNS writer gate tests. They exercise
// ddnsReconcileOptions: the lease→RG resolver (by stable pool-subnet CIDR) and
// the per-RG gate (master[RGOwner]). These prove a node MASTER for one RG but
// not another publishes only its own RG's leases — the partial-demotion
// correctness the issue calls out.

// scopeClusterDaemon builds a two-RG cluster daemon with RG-owned DHCP pools:
//   - reth0 (RG1) carries the 10.0.1.0/24 pool (group g1).
//   - reth1 (RG2) carries the 10.0.2.0/24 pool (group g2).
func scopeClusterDaemon(t *testing.T) *Daemon {
	t.Helper()
	store := testStoreWithSetConfig(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-6611",
		"set chassis cluster control-interface em0",
		"set chassis cluster peer-address 10.99.0.2",
		"set interfaces em0 unit 0 family inet address 10.99.0.1/24",
		"set chassis cluster node 0",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set chassis cluster redundancy-group 2 node 0 priority 200",
		"set interfaces reth0 redundant-ether-options redundancy-group 1",
		"set interfaces reth0 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/0 gigether-options redundant-parent reth0",
		"set interfaces reth1 redundant-ether-options redundancy-group 2",
		"set interfaces reth1 unit 0 family inet address 10.0.2.1/24",
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
		"set system services dhcp-local-server group g1 interface reth0.0",
		"set system services dhcp-local-server group g1 pool p1 address-range low 10.0.1.10 high 10.0.1.200",
		"set system services dhcp-local-server group g1 pool p1 subnet 10.0.1.0/24",
		"set system services dhcp-local-server group g2 interface reth1.0",
		"set system services dhcp-local-server group g2 pool p2 address-range low 10.0.2.10 high 10.0.2.200",
		"set system services dhcp-local-server group g2 pool p2 subnet 10.0.2.0/24",
		"set system services dhcp-local-server dynamic-dns enable",
		"set system services dhcp-local-server dynamic-dns domain example.com",
		"set system services dhcp-local-server dynamic-dns backend rfc2136",
		"set system services dhcp-local-server dynamic-dns update-server 192.0.2.53",
	})
	d := &Daemon{
		rgStates: make(map[int]*rgStateMachine),
		cluster:  cluster.NewManager(0, 1),
		store:    store,
	}
	return d
}

func TestDDNSReconcileOptionsResolvesLeaseToRG(t *testing.T) {
	d := scopeClusterDaemon(t)
	cfg := d.store.ActiveConfig()
	opts := d.ddnsReconcileOptions(cfg)
	if opts.Resolver == nil || opts.Gate == nil {
		t.Fatal("cluster daemon must produce a non-nil per-RG gate + resolver")
	}

	// A 10.0.1.x lease attributes to RG1; a 10.0.2.x lease to RG2.
	s1, ok1 := opts.Resolver(ddns.Lease{Family: 4, Address: "10.0.1.50"})
	if !ok1 || s1.RGOwner != 1 {
		t.Fatalf("10.0.1.50 must attribute to RG1, got rg=%d ok=%v", s1.RGOwner, ok1)
	}
	s2, ok2 := opts.Resolver(ddns.Lease{Family: 4, Address: "10.0.2.50"})
	if !ok2 || s2.RGOwner != 2 {
		t.Fatalf("10.0.2.50 must attribute to RG2, got rg=%d ok=%v", s2.RGOwner, ok2)
	}
	// An address in NO known pool subnet, with RG-owned pools present, is
	// fail-closed (ok=false).
	if _, ok := opts.Resolver(ddns.Lease{Family: 4, Address: "10.9.9.9"}); ok {
		t.Fatal("an address in no known pool subnet must be unattributable (fail-closed) when RG-owned pools exist")
	}
}

func TestDDNSReconcileGatePartialMaster(t *testing.T) {
	d := scopeClusterDaemon(t)
	// Node is MASTER for RG1, BACKUP for RG2.
	d.getOrCreateRGState(1).SetCluster(true)
	d.getOrCreateRGState(2).SetCluster(false)

	cfg := d.store.ActiveConfig()
	opts := d.ddnsReconcileOptions(cfg)

	// The gate admits RG1's scope, rejects RG2's scope — the #2664 invariant:
	// publish only the RG you own.
	if !opts.Gate(ddns.ScopeKey{Family: ddns.FamilyV4, RGOwner: 1}) {
		t.Fatal("node MASTER for RG1 must admit RG1's scope")
	}
	if opts.Gate(ddns.ScopeKey{Family: ddns.FamilyV4, RGOwner: 2}) {
		t.Fatal("node BACKUP for RG2 must REJECT RG2's scope (no double-write)")
	}
}

func TestDDNSReconcileGateStandaloneNilOpts(t *testing.T) {
	// A standalone daemon (no cluster) produces zero options — every scope
	// writable, byte-for-byte today's behaviour.
	d := &Daemon{rgStates: make(map[int]*rgStateMachine)}
	opts := d.ddnsReconcileOptions(nil)
	if opts.Gate != nil || opts.Resolver != nil {
		t.Fatal("standalone daemon must produce nil gate + resolver (all scopes writable)")
	}
}

// TestDDNSOverlappingPoolAttributionDeterministic proves the #2664 review MINOR
// fix: when two pools with OVERLAPPING subnets belong to DIFFERENT RGs, an
// address in the overlap attributes to the MOST-SPECIFIC (longest-prefix) pool,
// DETERMINISTICALLY across rebuilds — not the random first map-iteration match
// (which would flap the gate between passes). Here RG1 owns 10.0.0.0/16 and RG2
// owns the more-specific 10.0.2.0/24; 10.0.2.50 must always attribute to RG2.
func TestDDNSOverlappingPoolAttributionDeterministic(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-6611",
		"set chassis cluster control-interface em0",
		"set chassis cluster peer-address 10.99.0.2",
		"set interfaces em0 unit 0 family inet address 10.99.0.1/24",
		"set chassis cluster node 0",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set chassis cluster redundancy-group 2 node 0 priority 200",
		"set interfaces reth0 redundant-ether-options redundancy-group 1",
		"set interfaces reth0 unit 0 family inet address 10.0.0.1/16",
		"set interfaces ge-0/0/0 gigether-options redundant-parent reth0",
		"set interfaces reth1 redundant-ether-options redundancy-group 2",
		"set interfaces reth1 unit 0 family inet address 10.0.2.1/24",
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
		// RG1's broad pool (10.0.0.0/16) and RG2's specific pool (10.0.2.0/24).
		"set system services dhcp-local-server group g1 interface reth0.0",
		"set system services dhcp-local-server group g1 pool p1 address-range low 10.0.0.10 high 10.0.255.250",
		"set system services dhcp-local-server group g1 pool p1 subnet 10.0.0.0/16",
		"set system services dhcp-local-server group g2 interface reth1.0",
		"set system services dhcp-local-server group g2 pool p2 address-range low 10.0.2.10 high 10.0.2.250",
		"set system services dhcp-local-server group g2 pool p2 subnet 10.0.2.0/24",
		"set system services dhcp-local-server dynamic-dns enable",
		"set system services dhcp-local-server dynamic-dns domain example.com",
	})
	d := &Daemon{
		rgStates: make(map[int]*rgStateMachine),
		cluster:  cluster.NewManager(0, 1),
		store:    store,
	}
	cfg := d.store.ActiveConfig()

	// Rebuild many times: Go map iteration over ls.Groups is randomized, so an
	// unsorted first-match would attribute non-deterministically. The sorted
	// (longest-prefix-first) build must yield RG2 EVERY time for 10.0.2.50.
	for i := 0; i < 50; i++ {
		opts := d.ddnsReconcileOptions(cfg)
		s, ok := opts.Resolver(ddns.Lease{Family: 4, Address: "10.0.2.50"})
		if !ok || s.RGOwner != 2 {
			t.Fatalf("iter %d: 10.0.2.50 in the overlap must attribute to the more-specific RG2, got rg=%d ok=%v", i, s.RGOwner, ok)
		}
		// An address in RG1's broad pool but OUTSIDE RG2's specific pool stays RG1.
		s1, ok1 := opts.Resolver(ddns.Lease{Family: 4, Address: "10.0.5.50"})
		if !ok1 || s1.RGOwner != 1 {
			t.Fatalf("iter %d: 10.0.5.50 (only in RG1's pool) must attribute to RG1, got rg=%d ok=%v", i, s1.RGOwner, ok1)
		}
	}
}
