package api

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #4752: deterministic-CGNAT pools have no port-utilization observability —
// the pool-wide xpf_nat_pool_used_ports counter is meaningless because ports
// are pre-partitioned into fixed per-subscriber blocks. These tests pin the
// block-occupancy math and the two gauges that expose it:
//   xpf_nat_deterministic_pool_blocks_total     (capacity denominator)
//   xpf_nat_deterministic_pool_blocks_allocated (provisioned-subscriber
//                                                 numerator)
// so an operator can chart allocated/total and alarm as it approaches 1.0.

// TestDeterministicPoolBlockMath pins the pure block-capacity helpers so a
// future refactor cannot silently miscompute utilization. Mutating either
// formula (e.g. dropping the len(Addresses) factor, or the floor) turns a case
// RED.
func TestDeterministicPoolBlockMath(t *testing.T) {
	tests := []struct {
		name          string
		pool          *config.NATPool
		wantTotal     int
		wantAllocated int
	}{
		{
			// Task example: port-range 1024-65535 (64512 ports), block-size
			// 512 -> floor(64512/512) = 126 blocks per pool IP. One pool
			// address -> 126 total blocks. Subscriber /26 -> 64 blocks.
			name: "ipv4-single-address",
			pool: &config.NATPool{
				Addresses: []string{"203.0.113.5/32"},
				Deterministic: &config.DeterministicNATConfig{
					BlockSize:   512,
					HostAddress: "100.64.0.0/26",
				},
			},
			wantTotal:     126,
			wantAllocated: 64,
		},
		{
			// Two pool addresses double the block capacity. Subscriber /25 =
			// 128 blocks (<= 252 capacity).
			name: "ipv4-two-addresses",
			pool: &config.NATPool{
				Addresses: []string{"203.0.113.1/32", "203.0.113.2/32"},
				Deterministic: &config.DeterministicNATConfig{
					BlockSize:   512,
					HostAddress: "100.64.0.0/25",
				},
			},
			wantTotal:     252,
			wantAllocated: 128,
		},
		{
			// Explicit non-default port range: 4000-4999 (1000 ports),
			// block-size 100 -> 10 blocks per IP, one address -> 10 total.
			// Subscriber /29 = 8 blocks.
			name: "ipv4-explicit-port-range",
			pool: &config.NATPool{
				Addresses: []string{"198.51.100.7/32"},
				PortLow:   4000,
				PortHigh:  4999,
				Deterministic: &config.DeterministicNATConfig{
					BlockSize:   100,
					HostAddress: "100.64.0.0/29",
				},
			},
			wantTotal:     10,
			wantAllocated: 8,
		},
		{
			// IPv6 subscriber prefix: 1<<(128-ones) overflows Go's shift
			// width, so the dataplane caps provisioned blocks at capacity ->
			// allocated == total (fully provisioned). Eight pool addresses,
			// block-size 2016 -> floor(64512/2016) = 32 blocks/IP -> 256.
			name: "ipv6-subscriber-prefix",
			pool: &config.NATPool{
				Addresses: []string{
					"203.0.113.1/32", "203.0.113.2/32", "203.0.113.3/32",
					"203.0.113.4/32", "203.0.113.5/32", "203.0.113.6/32",
					"203.0.113.7/32", "203.0.113.8/32",
				},
				Deterministic: &config.DeterministicNATConfig{
					BlockSize:   2016,
					HostAddress: "2001:db8::/32",
				},
			},
			wantTotal:     256,
			wantAllocated: 256,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotTotal := deterministicPoolBlockCapacity(tc.pool, "p", nil)
			if gotTotal != tc.wantTotal {
				t.Errorf("deterministicPoolBlockCapacity = %d, want %d", gotTotal, tc.wantTotal)
			}
			gotAlloc := deterministicSubscriberCapacity(tc.pool, "p", nil)
			// The emission clamps allocated to total; assert the clamped value
			// (matches what the gauge reports).
			if gotAlloc > gotTotal {
				gotAlloc = gotTotal
			}
			if gotAlloc != tc.wantAllocated {
				t.Errorf("allocated blocks = %d, want %d", gotAlloc, tc.wantAllocated)
			}
		})
	}
}

// TestDeterministicPoolBlockCapacityInvalid pins the fail-safe: a
// non-deterministic or malformed pool yields 0 capacity (no bogus gauge).
func TestDeterministicPoolBlockCapacityInvalid(t *testing.T) {
	cases := map[string]*config.NATPool{
		"nil":               nil,
		"not-deterministic": {Addresses: []string{"203.0.113.5/32"}},
		"zero-block-size":   {Addresses: []string{"203.0.113.5/32"}, Deterministic: &config.DeterministicNATConfig{BlockSize: 0, HostAddress: "100.64.0.0/26"}},
		"block-exceeds-range": {
			Addresses:     []string{"203.0.113.5/32"},
			PortLow:       4000,
			PortHigh:      4099, // 100 ports
			Deterministic: &config.DeterministicNATConfig{BlockSize: 200, HostAddress: "100.64.0.0/29"},
		},
	}
	for name, pool := range cases {
		t.Run(name, func(t *testing.T) {
			if got := deterministicPoolBlockCapacity(pool, "p", nil); got != 0 {
				t.Errorf("deterministicPoolBlockCapacity(%s) = %d, want 0", name, got)
			}
		})
	}
}

// TestCollectNATPoolMetricsDeterministicBlocks drives the real
// collectNATPoolMetrics over a committed config with one deterministic and one
// plain source pool, and asserts the block gauges emit for the deterministic
// pool only, with the correct capacity/occupancy values.
func TestCollectNATPoolMetricsDeterministicBlocks(t *testing.T) {
	store := newConfigStore(t, t.TempDir())
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if _, err := store.LoadSet(strings.Join([]string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		// Deterministic pool: 1 address, default range 1024-65535 (64512),
		// block-size 512 -> 126 blocks; subscriber /26 -> 64 allocated.
		"set security nat source pool det address 203.0.113.5/32",
		"set security nat source pool det port deterministic block-size 512",
		"set security nat source pool det port deterministic host address 100.64.0.0/26",
		// Plain (non-deterministic) pool: must NOT emit the block gauges.
		"set security nat source pool plain address 203.0.113.9/32",
		"set security nat source rule-set rs from zone trust",
		"set security nat source rule-set rs to zone untrust",
		"set security nat source rule-set rs rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set rs rule r1 then source-nat pool det",
	}, "\n")); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	c := newCollector(&Server{store: store})
	dp := &descriptorCoverageDP{
		Manager: dataplane.New(),
		apply: &dataplane.ApplyResult{
			PoolIDs: map[string]uint8{"det": 0, "plain": 1},
		},
	}

	ch := make(chan prometheus.Metric)
	go func() {
		c.collectNATPoolMetrics(ch, dp, &dpuserspace.ProcessStatus{})
		close(ch)
	}()

	type key struct {
		desc *prometheus.Desc
		pool string
	}
	got := map[key]float64{}
	for m := range ch {
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("metric.Write: %v", err)
		}
		var pool string
		for _, l := range pb.GetLabel() {
			if l.GetName() == "pool" {
				pool = l.GetValue()
			}
		}
		got[key{m.Desc(), pool}] = pb.GetGauge().GetValue()
	}

	if v := got[key{c.natPoolDetBlocksTotal, "det"}]; v != 126 {
		t.Errorf("blocks_total{pool=det} = %v, want 126", v)
	}
	if v := got[key{c.natPoolDetBlocksAllocated, "det"}]; v != 64 {
		t.Errorf("blocks_allocated{pool=det} = %v, want 64", v)
	}
	// The plain pool must not emit deterministic block gauges (low-noise
	// contract: block utilization is a deterministic-only concept).
	if _, ok := got[key{c.natPoolDetBlocksTotal, "plain"}]; ok {
		t.Error("plain (non-deterministic) pool must not emit xpf_nat_deterministic_pool_blocks_total")
	}
	if _, ok := got[key{c.natPoolDetBlocksAllocated, "plain"}]; ok {
		t.Error("plain (non-deterministic) pool must not emit xpf_nat_deterministic_pool_blocks_allocated")
	}
}
