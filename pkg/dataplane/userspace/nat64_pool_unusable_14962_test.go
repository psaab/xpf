package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14962 (D27-01): two fail-open legs around NAT64 pools.
//
// Leg 1: buildNAT64Snapshots never consulted
// config.SourceNATPoolUnusableReason, so a NAT64 rule-set referencing an
// unusable source pool (missing, empty, invalid member, bad port range)
// shipped its raw pool addresses with no unusable marker. Rust then either
// SKIPPED the whole rule on an unparseable member ('rules continue) — so a
// destination inside the prefix fell through to NoPrefixMatch and was
// ROUTED as ordinary IPv6 — or minted from a pool the SNAT path had already
// declared unusable. The SNAT builder has stamped PoolUnusable since #6812;
// NAT64 must carry the same verdict.
//
// Leg 2: reportInterfaceSNATPoolOverlaps detects NAT64 pool overlaps with
// interface-SNAT egress addresses (#14367) but only quarantined
// snap.SourceNAT. A NAT64 finding was logged and then translated anyway, so
// the NAT64 allocator and the interface allocator could mint the same
// (address, port). NAT64 now carries PoolUnusable/PoolUnusableReason and the
// report quarantines snap.NAT64 by rule name.

func nat64PoolCfg14962(pool *config.NATPool, poolName string) *config.Config {
	cfg := &config.Config{}
	cfg.Security.NAT.SourcePools = map[string]*config.NATPool{}
	if pool != nil {
		cfg.Security.NAT.SourcePools[poolName] = pool
	}
	cfg.Security.NAT.NAT64 = []*config.NAT64RuleSet{
		{Name: "rs64", Prefix: "64:ff9b::/96", SourcePool: poolName},
	}
	return cfg
}

func TestBuildNAT64SnapshotsPropagatesPoolUnusable14962(t *testing.T) {
	for _, tc := range []struct {
		name       string
		pool       *config.NATPool
		poolName   string
		wantReason string
	}{
		{
			name:       "missing pool",
			pool:       nil,
			poolName:   "ghost",
			wantReason: "missing_pool",
		},
		{
			name:       "empty pool",
			pool:       &config.NATPool{Name: "p64"},
			poolName:   "p64",
			wantReason: "empty_pool",
		},
		{
			name:       "invalid member poisons whole pool",
			pool:       &config.NATPool{Name: "p64", Addresses: []string{"198.51.100.1", "not-an-ip"}},
			poolName:   "p64",
			wantReason: "invalid_pool",
		},
		{
			name:       "invalid port range",
			pool:       &config.NATPool{Name: "p64", Addresses: []string{"198.51.100.1"}, PortRangeInvalidSpec: "0-70000"},
			poolName:   "p64",
			wantReason: "invalid_port_range",
		},
		{
			name:       "healthy pool stays usable",
			pool:       &config.NATPool{Name: "p64", Addresses: []string{"198.51.100.1"}},
			poolName:   "p64",
			wantReason: "",
		},
		{
			name:       "no source pool configured stays usable empty",
			pool:       nil,
			poolName:   "",
			wantReason: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snaps := buildNAT64Snapshots(nat64PoolCfg14962(tc.pool, tc.poolName))
			if len(snaps) != 1 {
				t.Fatalf("snapshots = %d, want 1 (rule must not be dropped)", len(snaps))
			}
			s := snaps[0]
			if tc.wantReason == "" {
				if s.PoolUnusable || s.PoolUnusableReason != "" {
					t.Fatalf("PoolUnusable=%v reason=%q, want usable (legitimate pool must be untouched)",
						s.PoolUnusable, s.PoolUnusableReason)
				}
				return
			}
			if !s.PoolUnusable {
				t.Fatalf("PoolUnusable=false reason=%q, want true/%q — the NAT64 builder never "+
					"consulted SourceNATPoolUnusableReason, so Rust installs/mints from a pool "+
					"the SNAT path already declared unusable (or skips the rule and routes the "+
					"synthetic destination as IPv6)", s.PoolUnusableReason, tc.wantReason)
			}
			if s.PoolUnusableReason != tc.wantReason {
				t.Fatalf("PoolUnusableReason=%q, want %q (same SSOT vocabulary as the SNAT snapshot)",
					s.PoolUnusableReason, tc.wantReason)
			}
		})
	}
}

// The quarantine leg: a NAT64 pool that coincides with an interface-SNAT
// egress address must be marked unusable on snap.NAT64 (not only logged),
// while a disjoint NAT64 pool and the unrelated SNAT pool stay usable.
func TestReportQuarantinesNAT64OnInterfaceSNATOverlap14962(t *testing.T) {
	snap := overlapSnapshot(ifaceModeRule(), poolRuleOn("198.51.100.7"), wanUnit())
	snap.NAT64 = []NAT64RuleSnapshot{
		{Name: "n64-overlap", Prefix: "64:ff9b::/96", PoolAddresses: []string{overlapEgress}},
		{Name: "n64-clean", Prefix: "64:ff9b:1::/96", PoolAddresses: []string{"198.51.100.9"}},
	}
	reportInterfaceSNATPoolOverlaps(snap)
	byName := map[string]NAT64RuleSnapshot{}
	for _, r := range snap.NAT64 {
		byName[r.Name] = r
	}
	over := byName["n64-overlap"]
	if !over.PoolUnusable || over.PoolUnusableReason != poolUnusableReasonIfaceOverlap {
		t.Fatalf("n64-overlap: PoolUnusable=%v reason=%q, want true/%q — the detector finds "+
			"NAT64 overlaps (#14367) but the report only quarantined snap.SourceNAT, so NAT64 "+
			"kept minting the colliding (address, port)", over.PoolUnusable, over.PoolUnusableReason, poolUnusableReasonIfaceOverlap)
	}
	if clean := byName["n64-clean"]; clean.PoolUnusable {
		t.Fatalf("n64-clean: PoolUnusable=true reason=%q, want false — disjoint NAT64 pool must stay usable", clean.PoolUnusableReason)
	}
	for _, r := range snap.SourceNAT {
		if r.PoolUnusable {
			t.Fatalf("source rule %q quarantined (reason %q) by a NAT64 finding; only the NAT64 rule may be marked", r.Name, r.PoolUnusableReason)
		}
	}
}

// A NAT64 rule already unusable for its own definition reason keeps that
// more specific reason when the overlap also fires (SNAT precedent in
// reportInterfaceSNATPoolOverlaps).
func TestReportNAT64OverlapPreservesDefinitionReason14962(t *testing.T) {
	snap := overlapSnapshot(ifaceModeRule(), nil, wanUnit())
	snap.NAT64 = []NAT64RuleSnapshot{{
		Name: "n64", Prefix: "64:ff9b::/96", PoolAddresses: []string{overlapEgress},
		PoolUnusable: true, PoolUnusableReason: "invalid_pool",
	}}
	reportInterfaceSNATPoolOverlaps(snap)
	if snap.NAT64[0].PoolUnusableReason != "invalid_pool" {
		t.Fatalf("reason=%q, want preserved %q", snap.NAT64[0].PoolUnusableReason, "invalid_pool")
	}
}
