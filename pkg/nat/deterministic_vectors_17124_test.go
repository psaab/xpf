package nat

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #17124 (R4-Q47-08): shared deterministic-NAT golden vectors.
//
// This test loads userspace-dp/tests/fixtures/deterministic_nat_vectors_v1.json
// — the SAME file the Rust test deterministic_nat_vectors_fixture_17124
// (userspace-dp/src/nat/allocator/tests_deterministic_vectors_17124.rs)
// from tests/fixtures/. Neither side keeps a copied table, so mutating
// any expected value in the fixture turns BOTH tests RED.
//
// Each vector drives the production Go surface end to end: the pool spec
// is installed as a config.NATPool, poolParams/expandPoolV4 derive the
// allocator pool, and LookupForward/LookupReverse answer the forward and
// reverse rows. The rows include the three historical divergences:
// #9498 (reverse-wrap), #14623/#14624 (duplicate pool) and #15283
// (narrowed port range).

type detVectorFixture17124 struct {
	ID         string   `json:"id"`
	Mode       int      `json:"mode"`
	PoolSpec   []string `json:"pool_spec"`
	PoolExpand []string `json:"pool_expanded"`
	PoolLen    *int     `json:"pool_len"`
	PortLow    int      `json:"port_low"`
	PortHigh   int      `json:"port_high"`
	BlockSize  int      `json:"block_size"`
	HostPrefix string   `json:"host_prefix"`
	Forward    []struct {
		Subscriber string  `json:"subscriber"`
		ExternalIP *string `json:"external_ip"`
		SubIdx     *int    `json:"sub_idx"`
		IPIdx      *int    `json:"ip_idx"`
		BlockIdx   *int    `json:"block_idx"`
		PortLow    *int    `json:"port_low"`
		PortHigh   *int    `json:"port_high"`
	} `json:"forward"`
	Reverse []struct {
		ExternalIP string  `json:"external_ip"`
		Port       int     `json:"port"`
		Subscriber *string `json:"subscriber"`
		BlockLow   *int    `json:"block_low"`
		BlockHigh  *int    `json:"block_high"`
	} `json:"reverse"`
}

func loadDetVectors17124(t *testing.T) []detVectorFixture17124 {
	t.Helper()
	path := filepath.Join("..", "..", "userspace-dp", "tests", "fixtures", "deterministic_nat_vectors_v1.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read shared fixture %s: %v", path, err)
	}
	var doc struct {
		Vectors []detVectorFixture17124 `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse shared fixture: %v", err)
	}
	if len(doc.Vectors) < 8 {
		t.Fatalf("shared fixture carries %d vectors, want at least 8", len(doc.Vectors))
	}
	return doc.Vectors
}

func detVectorView17124(v detVectorFixture17124) AppliedView {
	pool := &config.NATPool{
		Name:      "vec-pool",
		Addresses: append([]string(nil), v.PoolSpec...),
		PortLow:   v.PortLow,
		PortHigh:  v.PortHigh,
		Deterministic: &config.DeterministicNATConfig{
			BlockSize:   v.BlockSize,
			HostAddress: v.HostPrefix,
		},
	}
	cfg := &config.Config{}
	cfg.Security.NAT.SourcePools = map[string]*config.NATPool{"vec-pool": pool}
	if v.Mode == 2 {
		cfg.Security.NAT.NAT64 = []*config.NAT64RuleSet{{
			Name:       "v6-to-v4",
			Prefix:     "64:ff9b::/96",
			SourcePool: "vec-pool",
		}}
	}
	return AppliedView{Config: cfg, Generation: 1, Available: true}
}

func TestDeterministicNATVectorsSharedFixture17124(t *testing.T) {
	vectors := loadDetVectors17124(t)
	ids := map[string]bool{}
	fwdChecked, revChecked := 0, 0
	for _, v := range vectors {
		v := v
		if ids[v.ID] {
			t.Fatalf("duplicate vector id %q", v.ID)
		}
		ids[v.ID] = true
		t.Run(v.ID, func(t *testing.T) {
			view := detVectorView17124(v)
			pool := view.Config.Security.NAT.SourcePools["vec-pool"]

			// Pool expansion pin (ordered allocator pool).
			mode := ModeV4
			if v.Mode == 2 {
				mode = ModeV6
			}
			gotPool, lerr := expandPoolV4(pool, mode)
			if lerr != nil {
				t.Fatalf("expandPoolV4(%v) = %v", v.PoolSpec, lerr)
			}
			if v.PoolExpand != nil {
				if len(gotPool) != len(v.PoolExpand) {
					t.Fatalf("pool expansion = %v, want %v", gotPool, v.PoolExpand)
				}
				for i, want := range v.PoolExpand {
					if gotPool[i].String() != want {
						t.Fatalf("pool[%d] = %s, want %s (full pool %v)", i, gotPool[i], want, gotPool)
					}
				}
			}
			if v.PoolLen != nil && len(gotPool) != *v.PoolLen {
				t.Fatalf("pool len = %d, want %d", len(gotPool), *v.PoolLen)
			}

			for _, row := range v.Forward {
				fwdChecked++
				fwd, ferr := LookupForward(view, "vec-pool", row.Subscriber)
				if row.ExternalIP == nil {
					if ferr == nil {
						t.Errorf("forward %s = %+v, want failure (vector %s)", row.Subscriber, fwd, v.ID)
					}
					continue
				}
				if ferr != nil {
					t.Errorf("forward %s: unexpected error %v (vector %s)", row.Subscriber, ferr, v.ID)
					continue
				}
				if fwd.ExternalIP != *row.ExternalIP {
					t.Errorf("forward %s external = %s, want %s (vector %s)", row.Subscriber, fwd.ExternalIP, *row.ExternalIP, v.ID)
				}
				if row.PortLow != nil && (int(fwd.PortLow) != *row.PortLow || int(fwd.PortHigh) != *row.PortHigh) {
					t.Errorf("forward %s block = %d-%d, want %d-%d (vector %s)", row.Subscriber, fwd.PortLow, fwd.PortHigh, *row.PortLow, *row.PortHigh, v.ID)
				}
				if row.BlockIdx != nil && int(fwd.BlockIndex) != *row.BlockIdx {
					t.Errorf("forward %s block_idx = %d, want %d (vector %s)", row.Subscriber, fwd.BlockIndex, *row.BlockIdx, v.ID)
				}
				if int(fwd.BlockSize) != v.BlockSize {
					t.Errorf("forward %s block_size = %d, want %d", row.Subscriber, fwd.BlockSize, v.BlockSize)
				}
			}
			for _, row := range v.Reverse {
				revChecked++
				rev, rerr := LookupReverse(view, "vec-pool", row.ExternalIP, uint16(row.Port))
				if row.Subscriber == nil {
					if rerr == nil {
						t.Errorf("reverse %s:%d = %+v, want failure (vector %s)", row.ExternalIP, row.Port, rev, v.ID)
					}
					continue
				}
				if rerr != nil {
					t.Errorf("reverse %s:%d: unexpected error %v (vector %s)", row.ExternalIP, row.Port, rerr, v.ID)
					continue
				}
				if rev.InternalHost != *row.Subscriber {
					t.Errorf("reverse %s:%d = %s, want %s (vector %s)", row.ExternalIP, row.Port, rev.InternalHost, *row.Subscriber, v.ID)
				}
				if row.BlockLow != nil && (int(rev.PortLow) != *row.BlockLow || int(rev.PortHigh) != *row.BlockHigh) {
					t.Errorf("reverse %s:%d block = %d-%d, want %d-%d (vector %s)", row.ExternalIP, row.Port, rev.PortLow, rev.PortHigh, *row.BlockLow, *row.BlockHigh, v.ID)
				}
			}
		})
	}
	if fwdChecked < 20 || revChecked < 15 {
		t.Fatalf("shared fixture exercised only %d forward / %d reverse rows", fwdChecked, revChecked)
	}
	for _, needle := range []string{"9498", "14623", "15283", "14624"} {
		found := false
		for id := range ids {
			if len(id) >= len(needle) {
				for i := 0; i+len(needle) <= len(id); i++ {
					if id[i:i+len(needle)] == needle {
						found = true
					}
				}
			}
		}
		if !found {
			t.Fatalf("shared fixture lost the #%s divergence vector", needle)
		}
	}
}
