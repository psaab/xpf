package api

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

func TestUserspaceHASplitBrainCountersEmit13291(t *testing.T) {
	c := newCollector(nil)
	status := dpuserspace.ProcessStatus{
		PeerDeleteRefusedLocalOwned:      31,
		SessionDeleteReplicaDropped:      32,
		SessionDeleteReplicaDropRepaired: 33,
	}
	ch := make(chan prometheus.Metric)
	go func() {
		c.emitUserspaceStatus13280(ch, status)
		close(ch)
	}()
	var got []prometheus.Metric
	for m := range ch {
		got = append(got, m)
	}
	// #18856 derivation for the shared emitter (S5Reinject is nil): the old
	// count had 14 unlabeled singles, including #16561 (e6db5f8d82)
	// SharedWireFallbackScans. #17144 (ff1adf0c7f; emitter change
	// ab87d2dc32) adds TunnelPurgeDeleteRefused (+1), making 15 singles.
	// Then 3 split-brain counters + 3 HATransitionDropped labels + 2
	// HATransitionStaleSkipped labels + 7 WG-uncovered outcomes + 1 WG
	// queue-poison counter + #18281 (668ab4cdc4) TupleGate poison (+1)
	// = 32. The 30 -> 32 delta is one series each from #17144 and #18281;
	// #17144's series is already included in the 15-single subtotal.
	if len(got) != 32 {
		t.Fatalf("emitted %d metrics, want 32 (including WG uncovered, three HA split-brain counters, and #16561, #17144, and #18281 status series)", len(got))
	}
	for _, tc := range []struct {
		desc  *prometheus.Desc
		value float64
	}{
		{c.userspacePeerDeleteRefusedLocalOwned, 31},
		{c.userspaceSessionDeleteReplicaDropped, 32},
		{c.userspaceSessionDeleteReplicaDropRepaired, 33},
	} {
		assertCounterClose(t, got, tc.desc, nil, tc.value)
	}
	dch := make(chan *prometheus.Desc, 512)
	go func() {
		c.Describe(dch)
		close(dch)
	}()
	registered := make(map[string]bool)
	for d := range dch {
		registered[d.String()] = true
	}
	for _, desc := range []*prometheus.Desc{
		c.userspacePeerDeleteRefusedLocalOwned,
		c.userspaceSessionDeleteReplicaDropped,
		c.userspaceSessionDeleteReplicaDropRepaired,
	} {
		if !registered[desc.String()] {
			t.Errorf("Describe did not register %s", desc)
		}
	}
}
