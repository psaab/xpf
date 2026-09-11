package api

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// TestLearnedRouteImportCappedEmittedOnlyWhenKnown9654: 1 for capped, 0 for
// uncapped, and NO series when the helper did not report the flag.
func TestLearnedRouteImportCappedEmittedOnlyWhenKnown9654(t *testing.T) {
	c := &xpfCollector{learnedRouteImportCapped: prometheus.NewDesc("xpf_learned_route_import_capped", "h", nil, nil)}
	yes, no := true, false
	for _, tc := range []struct {
		name  string
		flag  *bool
		want  float64
		emits bool
	}{
		{"unknown", nil, 0, false},
		{"capped", &yes, 1, true},
		{"uncapped", &no, 0, true},
	} {
		ch := make(chan prometheus.Metric, 4)
		c.emitLearnedRouteImportCapped(ch, dpuserspace.ProcessStatus{LearnedRouteImportCapped: tc.flag})
		close(ch)
		var got []prometheus.Metric
		for m := range ch {
			got = append(got, m)
		}
		if !tc.emits {
			if len(got) != 0 {
				t.Errorf("%s: emitted %d series, want none (an unknown flag must not read as 0)", tc.name, len(got))
			}
			continue
		}
		if len(got) != 1 {
			t.Fatalf("%s: emitted %d series, want 1", tc.name, len(got))
		}
		assertGaugeClose(t, got, c.learnedRouteImportCapped, nil, tc.want)
	}
}
