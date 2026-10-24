package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #16460: a leniently-loaded filter with two same-named terms `t` (a
// discard and an accept) must print each instance's OWN hit counter
// (30 under the first, 70 under the second), never the summed 100
// under both. Pre-fix the Go counter index summed both rows onto the
// name key and each instance rendered the total.
//
// The config is built in memory (not via the store) because a strict
// commit rejects the duplicate (#15192); the lenient shape reaches
// `show firewall` only from a persisted/peer-synced config, whose
// Terms slice preserves both instances in order. Building it in memory
// is the exact value a lenient LoadConfig would hand to this renderer.
//
// Distinct-name control: t1/t2 print 30 and 70 (the pre-existing
// behaviour, unchanged).

func dupTermConfig16460() *config.Config {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"edge": {
			Name: "edge",
			Terms: []*config.FirewallFilterTerm{
				{Name: "t", Action: "discard", Count: "hits"},
				{Name: "t", Action: "accept", Count: "hits"},
			},
		},
		"ctrl": {
			Name: "ctrl",
			Terms: []*config.FirewallFilterTerm{
				{Name: "t1", Action: "discard", Count: "hits"},
				{Name: "t2", Action: "accept", Count: "hits"},
			},
		},
	}
	return cfg
}

func dupTermStatus16460() dpuserspace.ProcessStatus {
	return dpuserspace.ProcessStatus{
		FilterTermCounters: []dpuserspace.FirewallFilterTermCounterStatus{
			{Family: "inet", FilterName: "edge", TermName: "t", TermOrdinal: 0, Packets: 30, Bytes: 3000},
			{Family: "inet", FilterName: "edge", TermName: "t", TermOrdinal: 1, Packets: 70, Bytes: 7000},
			{Family: "inet", FilterName: "ctrl", TermName: "t1", TermOrdinal: 0, Packets: 30, Bytes: 3000},
			{Family: "inet", FilterName: "ctrl", TermName: "t2", TermOrdinal: 1, Packets: 70, Bytes: 7000},
		},
	}
}

func TestShowFirewallDupTermPrintsPerInstanceCounters16460(t *testing.T) {
	s := &Server{
		dp: &firewallFilterShowUserspaceDP{
			Manager: dataplane.New(),
			status:  dupTermStatus16460(),
		},
	}
	var buf strings.Builder
	s.showFirewall(dupTermConfig16460(), &buf)
	out := buf.String()

	if strings.Contains(out, "Hit count: 100 packets") {
		t.Fatalf("output printed the summed 100 under a term instance (#16460):\n%s", out)
	}
	if got := strings.Count(out, "Hit count: 30 packets, 3000 bytes"); got != 2 {
		t.Fatalf("output has %d '30' hit counts, want 2 (edge instance 1 + ctrl t1):\n%s", got, out)
	}
	if got := strings.Count(out, "Hit count: 70 packets, 7000 bytes"); got != 2 {
		t.Fatalf("output has %d '70' hit counts, want 2 (edge instance 2 + ctrl t2):\n%s", got, out)
	}
	// Order pin: within `edge`, 30 precedes 70 (instance order).
	edge := out[strings.Index(out, "Filter: edge"):]
	if i30, i70 := strings.Index(edge, "Hit count: 30"), strings.Index(edge, "Hit count: 70"); i30 < 0 || i70 < 0 || i30 > i70 {
		t.Fatalf("edge instances out of order (30@%d, 70@%d):\n%s", i30, i70, out)
	}
}

func TestShowFirewallFilterDupTermPrintsPerInstanceCounters16460(t *testing.T) {
	s := &Server{
		dp: &firewallFilterShowUserspaceDP{
			Manager: dataplane.New(),
			status:  dupTermStatus16460(),
		},
	}
	resp, err := s.showFirewallFilter(
		&pb.ShowTextRequest{Topic: "firewall-filter:edge:inet"},
		dupTermConfig16460(),
		&strings.Builder{},
	)
	if err != nil {
		t.Fatalf("showFirewallFilter() error = %v", err)
	}
	out := resp.GetOutput()
	if strings.Contains(out, "Hit count: 100 packets") {
		t.Fatalf("output printed the summed 100 under a term instance (#16460):\n%s", out)
	}
	if got := strings.Count(out, "Hit count: 30 packets, 3000 bytes"); got != 1 {
		t.Fatalf("output has %d '30' hit counts, want 1:\n%s", got, out)
	}
	if got := strings.Count(out, "Hit count: 70 packets, 7000 bytes"); got != 1 {
		t.Fatalf("output has %d '70' hit counts, want 1:\n%s", got, out)
	}
}
