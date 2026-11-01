package api

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	xnft "github.com/psaab/xpf/pkg/nftables"
)

// #18728: the kernel lo0 chain's per-family implicit-discard counter is
// exported as xpf_lo0_implicit_discard_hits_total{family}, and never under
// xpf_lo0_counter_hits_total (where an empty or colliding `counter` label
// would mislabel it or fail Gather). Emitted with the dataplane unloaded,
// like the `then count` lo0 series, because the kernel chain does not depend
// on it.
func TestLo0ImplicitDiscardHitsExported18728(t *testing.T) {
	orig := readLo0Counters
	defer func() { readLo0Counters = orig }()
	readLo0Counters = func() ([]xnft.Lo0Count, error) {
		return []xnft.Lo0Count{
			{Counter: "ssh-hits", Packets: 12},
			{ImplicitDiscardFamily: "inet", Packets: 7},
			{ImplicitDiscardFamily: "inet6", Packets: 3},
		}, nil
	}
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(newCollector(&Server{}))
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	implicit := map[string]float64{}
	countLabels := map[string]float64{}
	for _, mf := range mfs {
		for _, m := range mf.GetMetric() {
			labels := map[string]string{}
			for _, l := range m.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			switch mf.GetName() {
			case "xpf_lo0_implicit_discard_hits_total":
				implicit[labels["family"]] = m.GetCounter().GetValue()
			case "xpf_lo0_counter_hits_total":
				countLabels[labels["counter"]] = m.GetCounter().GetValue()
			}
		}
	}
	if implicit["inet"] != 7 || implicit["inet6"] != 3 || len(implicit) != 2 {
		t.Fatalf("xpf_lo0_implicit_discard_hits_total = %v, want inet=7 inet6=3", implicit)
	}
	if len(countLabels) != 1 || countLabels["ssh-hits"] != 12 {
		t.Fatalf("xpf_lo0_counter_hits_total = %v, want only ssh-hits=12 (the implicit rows must not appear here)", countLabels)
	}
}
