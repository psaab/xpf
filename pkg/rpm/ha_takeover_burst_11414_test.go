package rpm

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// A newly promoted node has no standby probe verdict to seed ip-monitoring
// with. Its initial failure verdict must therefore be established from a
// bounded takeover burst, not by waiting for multiple normal test intervals.
func TestTakeoverProbeBurstReachesFailureBeforeRegularTestInterval11414(t *testing.T) {
	m := New()
	m.probeFn = func(context.Context, *config.RPMTest, string) (time.Duration, error) {
		return 0, errors.New("path unavailable")
	}
	transitions := make(chan Transition, 4)
	m.SetTransitionCallback(func(tr Transition) { transitions <- tr })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer m.StopAll()

	test := func(name string) *config.RPMTest {
		return &config.RPMTest{
			Name:                name,
			Target:              "192.0.2.1",
			TestInterval:        60,
			ThresholdSuccessive: 3,
		}
	}
	cfg := &config.RPMConfig{Probes: map[string]*config.RPMProbe{
		"WAN":   {Name: "WAN", Tests: map[string]*config.RPMTest{"default": test("default")}},
		"plain": {Name: "plain", Tests: map[string]*config.RPMTest{"default": test("default")}},
	}}
	m.ApplyWithProbeBurst(ctx, cfg, map[string]struct{}{"WAN": {}}, nil)

	select {
	case tr := <-transitions:
		if tr.ProbeName != "WAN" || tr.Status != "fail" || !tr.TakeoverBurst {
			t.Fatalf("takeover verdict = %+v, want WAN fail marked as takeover burst", tr)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("takeover did not reach a failed RPM verdict before the 60s normal interval")
	}
	select {
	case tr := <-transitions:
		t.Fatalf("unselected probe was accelerated: %+v", tr)
	case <-time.After(100 * time.Millisecond):
	}
}
