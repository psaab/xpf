package nfqueue

import (
	"errors"
	"sort"
	"testing"
	"time"
)

const (
	phase0FragmentPayload = 8 * 1024
	phase0FragmentSize    = 1400
	phase0StalledFlows    = 100
	phase0FragmentSamples = 128
	phase0FragmentWarmup  = 8
	phase0FragmentOps     = 64
)

// TestMeasureFragments9506 is M4 from the Phase-0 plan. It feeds the bounded
// pool v4 and v6 fragment payloads, measures completion insertion with 100
// stalled flows, and applies the p99 <= 5x baseline kill gate. The input is a
// synthetic capture of the six-fragment shape; lower-lo MTU/kernel-generated
// XFRM fragments remain a loss-cluster validation item. This cell intentionally
// does not authorize the assembled copy: an eventual production path must
// release exactly the retained/original fragment set or drop overlaps.
func TestMeasureFragments9506(t *testing.T) {
	t.Log("M4 status: synthetic FragPool cell is GREEN; real lower-lo-MTU kernel fragment capture remains UNMET and cluster-gated")
	for _, version := range []uint8{4, 6} {
		baseline := fragmentCompletionSamples(t, version, false)
		loaded := fragmentCompletionSamples(t, version, true)
		if len(baseline) != phase0FragmentSamples || len(loaded) != phase0FragmentSamples {
			t.Fatalf("M4 IPv%d sample count baseline=%d loaded=%d", version, len(baseline), len(loaded))
		}
		baseP99 := percentile99(baseline)
		loadedP99 := percentile99(loaded)
		t.Logf("M4 ip_version=%d baseline_p99_ns=%d loaded_p99_ns=%d ratio=%.2f", version, baseP99, loadedP99, float64(loadedP99)/float64(maxInt64(baseP99, 1)))
		if loadedP99 > 5*maxInt64(baseP99, 1) {
			t.Fatalf("M4 IPv%d HOL gate: loaded p99=%d > 5x baseline p99=%d", version, loadedP99, baseP99)
		}
	}
	pool, err := NewFragPool(4, 8)
	if err != nil {
		t.Fatal(err)
	}
	key := testFragmentKey(4, 999)
	for i := 0; i < 4; i++ {
		if _, err := pool.Insert(key, Fragment{Offset: uint32(i * 100), More: true, Data: []byte{byte(i)}}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Insert(key, Fragment{Offset: 400, More: true, Data: []byte{9}}); !errors.Is(err, ErrFragmentCapacity) {
		t.Fatalf("M4 over-cap error=%v, want ErrFragmentCapacity", err)
	}
	if got := pool.Stats(); got.Flows != 0 || got.CapacityDrops != 1 {
		t.Fatalf("M4 over-cap stats=%+v", got)
	}
	if complete, err := pool.Insert(testFragmentKey(4, 1000), Fragment{More: false, Data: []byte("survives")}); !complete || err != nil {
		t.Fatalf("M4 pool after over-cap: complete=%t err=%v", complete, err)
	}
}

func fragmentCompletionSamples(t *testing.T, version uint8, loaded bool) []int64 {
	samples := make([]int64, 0, phase0FragmentSamples)
	for sample := 0; sample < phase0FragmentSamples+phase0FragmentWarmup; sample++ {
		pool, err := NewFragPool(8, phase0StalledFlows+phase0FragmentOps+8)
		if err != nil {
			t.Fatal(err)
		}
		if loaded {
			for flow := 0; flow < phase0StalledFlows; flow++ {
				key := testFragmentKey(version, uint32(10000+flow))
				for frag := 0; frag < phase0FragmentCount()-1; frag++ {
					if _, err := pool.Insert(key, Fragment{Offset: uint32(frag * phase0FragmentSize), More: true, Data: fragmentBytes(frag)}); err != nil {
						t.Fatalf("M4 loaded IPv%d flow=%d frag=%d: %v", version, flow, frag, err)
					}
				}
			}
		}
		for op := 0; op < phase0FragmentOps; op++ {
			key := testFragmentKey(version, uint32(20000+sample*phase0FragmentOps+op))
			for frag := 0; frag < phase0FragmentCount()-1; frag++ {
				if _, err := pool.Insert(key, Fragment{Offset: uint32(frag * phase0FragmentSize), More: true, Data: fragmentBytes(frag)}); err != nil {
					t.Fatalf("M4 setup IPv%d op=%d frag=%d: %v", version, op, frag, err)
				}
			}
		}
		start := time.Now()
		for op := 0; op < phase0FragmentOps; op++ {
			key := testFragmentKey(version, uint32(20000+sample*phase0FragmentOps+op))
			if complete, err := pool.Insert(key, Fragment{Offset: uint32((phase0FragmentCount() - 1) * phase0FragmentSize), More: false, Data: fragmentBytes(phase0FragmentCount() - 1)}); err != nil || !complete {
				t.Fatalf("M4 completion IPv%d loaded=%t op=%d complete=%t err=%v", version, loaded, op, complete, err)
			}
		}
		if sample >= phase0FragmentWarmup {
			samples = append(samples, time.Since(start).Nanoseconds()/phase0FragmentOps)
		}
	}
	return samples
}

func phase0FragmentCount() int {
	count := phase0FragmentPayload / phase0FragmentSize
	if phase0FragmentPayload%phase0FragmentSize != 0 {
		count++
	}
	return count
}

func fragmentBytes(index int) []byte {
	offset := index * phase0FragmentSize
	length := phase0FragmentSize
	if remaining := phase0FragmentPayload - offset; remaining < length {
		length = remaining
	}
	data := make([]byte, length)
	for i := range data {
		data[i] = byte(index + i)
	}
	return data
}

func percentile99(samples []int64) int64 {
	values := append([]int64(nil), samples...)
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	index := (99*len(values) + 99) / 100
	if index > len(values) {
		index = len(values)
	}
	return values[index-1]
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
