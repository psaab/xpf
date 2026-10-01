package ipmon

import (
	"context"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/rpm"
)

func TestTakeoverBurstFailureBypassesOverlayDebounce11414(t *testing.T) {
	actuated := make(chan []config.RouteOverlayEntry, 4)
	var e *Engine
	e = New(func(context.Context) bool {
		actuated <- e.ActiveOverlay()
		return true
	})
	e.debounce = DefaultDebounce
	e.throttle = 0
	e.Apply(&config.IPMonitoringConfig{Policies: map[string]*config.IPMonitoringPolicy{
		"wan-failover": {
			Name:          "wan-failover",
			MatchRPMProbe: "WAN",
			PreferredRoutes: []*config.PreferredRoute{
				{Destination: "0.0.0.0/0", NextHop: "172.16.80.1"},
			},
		},
	}}, nil)
	e.SetPublishEnabled(false)
	e.Start()
	defer e.Stop()

	select {
	case overlay := <-actuated:
		if len(overlay) != 0 {
			t.Fatalf("standby publish = %+v, want baseline", overlay)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("standby gate did not immediately publish the baseline")
	}
	e.SetPublishEnabled(true)
	select {
	case overlay := <-actuated:
		if len(overlay) != 0 {
			t.Fatalf("promotion publish = %+v, want no overlay before first verdict", overlay)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("takeover gate did not immediately publish the baseline")
	}

	e.HandleTransition(rpm.Transition{
		ProbeName:     "WAN",
		TestName:      "t",
		Status:        "fail",
		TakeoverBurst: true,
		Results:       []*rpm.ProbeResult{{ProbeName: "WAN", TestName: "t", LastStatus: "fail"}},
	})
	select {
	case overlay := <-actuated:
		if len(overlay) != 1 || overlay[0].NextHop != "172.16.80.1" {
			t.Fatalf("takeover failure publish = %+v, want preferred route immediately", overlay)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("fresh takeover failure waited for the ordinary overlay debounce")
	}
}
