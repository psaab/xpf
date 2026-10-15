package api

// #13292 (D4-09): io_uring retained-buffer leak counters (#7106) and the
// StateWriter io_uring_active gauge are populated in ProcessStatus by the
// helper but were never exported to Prometheus. RED on pre-fix master: the
// collector fields do not exist, so this file fails to compile / emits none
// of the three series.

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

func TestUserspaceIoUringRetainedAndActiveEmit13292(t *testing.T) {
	c := newCollector(nil)
	status := dpuserspace.ProcessStatus{
		IOUringActive:               true,
		IoUringRetainedBuffersTotal: 7,
		IoUringRetainedBytesTotal:   8192,
	}
	ch := make(chan prometheus.Metric)
	go func() {
		c.emitUserspaceIoUring13292(ch, status)
		close(ch)
	}()
	var got []prometheus.Metric
	for m := range ch {
		got = append(got, m)
	}
	if len(got) != 3 {
		t.Fatalf("emitted %d metrics, want 3 (active gauge + retained buffers/bytes counters)", len(got))
	}
	assertCounterClose(t, got, c.userspaceIoUringRetainedBuffers, nil, 7)
	assertCounterClose(t, got, c.userspaceIoUringRetainedBytes, nil, 8192)
	assertGaugeClose(t, got, c.userspaceIoUringActive, nil, 1)

	// Inactive must publish 0, not omit the series: silent fallback from
	// io_uring to sync writes is exactly what this gauge must surface.
	c2 := newCollector(nil)
	ch2 := make(chan prometheus.Metric)
	go func() {
		c2.emitUserspaceIoUring13292(ch2, dpuserspace.ProcessStatus{IOUringActive: false})
		close(ch2)
	}()
	var got2 []prometheus.Metric
	for m := range ch2 {
		got2 = append(got2, m)
	}
	if len(got2) != 3 {
		t.Fatalf("inactive: emitted %d metrics, want 3", len(got2))
	}
	assertGaugeClose(t, got2, c2.userspaceIoUringActive, nil, 0)
	assertCounterClose(t, got2, c2.userspaceIoUringRetainedBuffers, nil, 0)
	assertCounterClose(t, got2, c2.userspaceIoUringRetainedBytes, nil, 0)

	// Descriptor registration: Describe must declare all three, mirroring
	// TestColdPathDescriptorsAreDescribed coverage for sibling families.
	dch := make(chan *prometheus.Desc)
	go func() {
		c.Describe(dch)
		close(dch)
	}()
	seen := map[*prometheus.Desc]bool{}
	for d := range dch {
		seen[d] = true
	}
	for _, d := range []*prometheus.Desc{c.userspaceIoUringActive, c.userspaceIoUringRetainedBuffers, c.userspaceIoUringRetainedBytes} {
		if d == nil || !seen[d] {
			t.Fatalf("descriptor %v not declared in Describe", d)
		}
	}
}
