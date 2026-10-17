package nat

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14623 — Rust expand_pool_address (userspace-dp/src/nat/source/expand.rs)
// keeps only the first occurrence of each pool address (seen-set in the
// production caller, source/mod.rs), so an overlapping pool member does not
// create a second allocator position. Go expandPoolV4 appended verbatim, so
// every pool index after a duplicate shifted by one: the forward lookup named
// a different external address than the dataplane translates to, and the
// reverse lookup named a different subscriber (or not-found) — the #5794
// invariant-8 forensic failure on the lawful-intercept surface.
//
// Witness pool: [203.0.113.1/32, 203.0.113.0/30]
//   Rust (deduped):  [203.0.113.1, 203.0.113.0, 203.0.113.2, 203.0.113.3]
//   Go pre-fix:      [203.0.113.1, 203.0.113.0, 203.0.113.1, 203.0.113.2, 203.0.113.3]
//
// With block-size 512 over ports 1024-2047 (2 blocks/IP) and subscribers
// 100.64.0.0/29 (8 hosts, exactly the deduped capacity 4 IPs x 2 blocks):
//   forward 100.64.0.4 -> ip_idx 2 -> 203.0.113.2, block 1024-1535
//   forward 100.64.0.6 -> ip_idx 3 -> 203.0.113.3, block 1024-1535
//   reverse 203.0.113.2:1024 -> 100.64.0.4
//   reverse 203.0.113.3:1024 -> 100.64.0.6
// Pre-fix Go instead: forward .4->.1, .6->.2; reverse .2:1024->100.64.0.6 and
// .3:1024->not-found.

func dedupeView14623() AppliedView {
	pool := &config.NATPool{
		Name:      "cgn-pool",
		Addresses: []string{"203.0.113.1/32", "203.0.113.0/30"},
		PortLow:   1024,
		PortHigh:  2047,
		Deterministic: &config.DeterministicNATConfig{
			BlockSize:   512,
			HostAddress: "100.64.0.0/29",
		},
	}
	cfg := &config.Config{}
	cfg.Security.NAT.SourcePools = map[string]*config.NATPool{"cgn-pool": pool}
	return AppliedView{Config: cfg, Generation: 1, Available: true}
}

func TestDeterministicPoolExpansionDedupesOverlappingMembers14623(t *testing.T) {
	pool := &config.NATPool{
		Name:      "p",
		Addresses: []string{"203.0.113.1/32", "203.0.113.0/30"},
	}
	got, lerr := expandPoolV4(pool, ModeV4)
	if lerr != nil {
		t.Fatalf("expandPoolV4: %v", lerr)
	}
	want := []string{"203.0.113.1", "203.0.113.0", "203.0.113.2", "203.0.113.3"}
	if len(got) != len(want) {
		t.Fatalf("expandPoolV4 = %v, want deduped %v (Rust first-occurrence ordering)", got, want)
	}
	for i, w := range want {
		if got[i].String() != w {
			t.Fatalf("expandPoolV4[%d] = %s, want %s (full pool %v)", i, got[i], w, got)
		}
	}
}

func TestDeterministicPoolExpansionDedupesBareAndPrepended14623(t *testing.T) {
	// Bare duplicate, bare+/32 duplicate, and a pool.Address prepend that
	// duplicates the first Addresses member all collapse to first occurrence.
	cases := []struct {
		name string
		pool *config.NATPool
		want []string
	}{
		{
			name: "bare duplicate",
			pool: &config.NATPool{Name: "p", Addresses: []string{"203.0.113.1", "203.0.113.1", "203.0.113.2"}},
			want: []string{"203.0.113.1", "203.0.113.2"},
		},
		{
			name: "bare and /32 duplicate",
			pool: &config.NATPool{Name: "p", Addresses: []string{"203.0.113.1", "203.0.113.1/32", "203.0.113.2"}},
			want: []string{"203.0.113.1", "203.0.113.2"},
		},
		{
			name: "pool.Address prepend duplicate",
			pool: &config.NATPool{Name: "p", Address: "203.0.113.1", Addresses: []string{"203.0.113.1/32", "203.0.113.0/30"}},
			want: []string{"203.0.113.1", "203.0.113.0", "203.0.113.2", "203.0.113.3"},
		},
		{
			name: "control no overlap",
			pool: &config.NATPool{Name: "p", Addresses: []string{"203.0.113.1", "203.0.113.2"}},
			want: []string{"203.0.113.1", "203.0.113.2"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, lerr := expandPoolV4(tc.pool, ModeV4)
			if lerr != nil {
				t.Fatalf("expandPoolV4: %v", lerr)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("expandPoolV4 = %v, want %v", got, tc.want)
			}
			for i, w := range tc.want {
				if got[i].String() != w {
					t.Fatalf("expandPoolV4[%d] = %s, want %s (full pool %v)", i, got[i], w, got)
				}
			}
		})
	}
}

func TestDeterministicOverlappingPoolForwardReverse14623(t *testing.T) {
	view := dedupeView14623()

	fwd, err := LookupForward(view, "cgn-pool", "100.64.0.4")
	if err != nil {
		t.Fatalf("forward 100.64.0.4: %v", err)
	}
	if fwd.ExternalIP != "203.0.113.2" || fwd.PortLow != 1024 || fwd.PortHigh != 1535 {
		t.Fatalf("forward 100.64.0.4 = %+v, want 203.0.113.2 block 1024-1535 (Rust ip_idx 2)", fwd)
	}
	fwd, err = LookupForward(view, "cgn-pool", "100.64.0.6")
	if err != nil {
		t.Fatalf("forward 100.64.0.6: %v", err)
	}
	if fwd.ExternalIP != "203.0.113.3" || fwd.PortLow != 1024 || fwd.PortHigh != 1535 {
		t.Fatalf("forward 100.64.0.6 = %+v, want 203.0.113.3 block 1024-1535 (Rust ip_idx 3)", fwd)
	}

	rev, err := LookupReverse(view, "cgn-pool", "203.0.113.2", 1024)
	if err != nil {
		t.Fatalf("reverse 203.0.113.2:1024: %v", err)
	}
	if rev.InternalHost != "100.64.0.4" {
		t.Fatalf("reverse 203.0.113.2:1024 = %s, want 100.64.0.4", rev.InternalHost)
	}
	rev, err = LookupReverse(view, "cgn-pool", "203.0.113.3", 1024)
	if err != nil {
		t.Fatalf("reverse 203.0.113.3:1024: %v", err)
	}
	if rev.InternalHost != "100.64.0.6" {
		t.Fatalf("reverse 203.0.113.3:1024 = %s, want 100.64.0.6", rev.InternalHost)
	}
}

// Control: mode 2 mirrors Rust NAT64 parse_pool_v4, which pushes each parsed
// host verbatim (no seen-set). Deduping there would diverge from the NAT64
// dataplane's pool indexing and its pool-bounded host_count, so expandPoolV4
// must leave mode-2 membership untouched.
func TestDeterministicNAT64PoolExpansionDoesNotDedupe14623(t *testing.T) {
	pool := &config.NATPool{
		Name:      "p",
		Addresses: []string{"203.0.113.1", "203.0.113.1/32"},
	}
	got, lerr := expandPoolV4(pool, ModeV6)
	if lerr != nil {
		t.Fatalf("expandPoolV4 mode2: %v", lerr)
	}
	if len(got) != 2 || got[0].String() != "203.0.113.1" || got[1].String() != "203.0.113.1" {
		t.Fatalf("expandPoolV4 mode2 = %v, want verbatim [203.0.113.1 203.0.113.1] (parse_pool_v4)", got)
	}
}
