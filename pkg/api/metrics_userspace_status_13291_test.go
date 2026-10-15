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
	if len(got) != 17 {
		t.Fatalf("emitted %d metrics, want 17 (including three HA split-brain counters)", len(got))
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
