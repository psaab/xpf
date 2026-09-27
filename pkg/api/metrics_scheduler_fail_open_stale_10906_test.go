package api

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/psaab/xpf/pkg/scheduler"
)

// TestSchedulerFailOpenStaleMetricNamesTheDataplaneRisk10906 drives the real
// scheduler latch through its bounded-age transition, then gathers the API
// metrics. The new name describes the last-known schedule risk; the old series
// remains a deprecated alias with the identical value for existing alerts.
func TestSchedulerFailOpenStaleMetricNamesTheDataplaneRisk10906(t *testing.T) {
	for _, tc := range []struct {
		name  string
		stale bool
		want  float64
	}{
		{name: "healthy", want: 0},
		{name: "aged failed republish", stale: true, want: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Unix(1, 0).UTC()
			sched, _ := scheduler.NewPrimed(nil, nil, now)
			if tc.stale {
				republishErr := errors.New("republish unavailable")
				sched.RecordRepublishResult(republishErr, now)
				sched.RecordRepublishResult(republishErr, now.Add(scheduler.RepublishFailClosedAge))
				if !sched.RepublishFailClosed() {
					t.Fatal("scheduler did not latch after an aged failed republish")
				}
			}

			reg := prometheus.NewPedanticRegistry()
			reg.MustRegister(newCollector(&Server{
				schedulerRepublishFailClosedFn: sched.RepublishFailClosed,
			}))
			families, err := reg.Gather()
			if err != nil {
				t.Fatalf("Gather: %v", err)
			}

			got := map[string]float64{}
			help := map[string]string{}
			for _, family := range families {
				switch family.GetName() {
				case "xpf_scheduler_republish_fail_open_stale", "xpf_scheduler_republish_fail_closed":
					if len(family.GetMetric()) != 1 {
						t.Fatalf("%s: got %d samples, want one", family.GetName(), len(family.GetMetric()))
					}
					got[family.GetName()] = family.GetMetric()[0].GetGauge().GetValue()
					help[family.GetName()] = family.GetHelp()
				}
			}

			const newName = "xpf_scheduler_republish_fail_open_stale"
			const oldName = "xpf_scheduler_republish_fail_closed"
			for _, name := range []string{newName, oldName} {
				value, ok := got[name]
				if !ok {
					t.Fatalf("%s not emitted", name)
				}
				if value != tc.want {
					t.Errorf("%s = %v, want %v", name, value, tc.want)
				}
			}
			if got[newName] != got[oldName] {
				t.Fatalf("deprecated alias value %v differs from honest gauge %v", got[oldName], got[newName])
			}
			if !strings.Contains(help[newName], "last-known schedule") || !strings.Contains(help[newName], "permit that may continue forwarding") {
				t.Errorf("new gauge help does not explain the stale permit risk: %q", help[newName])
			}
			if !strings.HasPrefix(help[oldName], "DEPRECATED alias") {
				t.Errorf("legacy gauge help is not marked deprecated: %q", help[oldName])
			}
		})
	}
}
