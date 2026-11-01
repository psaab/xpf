package api

import (
	"math"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// The collector asserts the liveness surface on the published backend, which
// in production is the adapter, so the adapter must carry it.
var _ helperLivenessProvider = (*dpuserspace.LegacyDataPlaneAdapter)(nil)
var _ helperLivenessProvider = (*dpuserspace.Manager)(nil)

type fakeLiveness18685 struct {
	apiRuntimeDataPlane
	age      time.Duration
	notReady bool
	kills    uint64
}

func (f fakeLiveness18685) HelperAnswerAge() time.Duration { return f.age }
func (f fakeLiveness18685) HelperElectionNotReady() bool   { return f.notReady }
func (f fakeLiveness18685) HelperWedgeKills() uint64       { return f.kills }

// TestHelperLivenessFamiliesEmitted18685: the three #18685 families are
// emitted from the provider, including while the helper is not answering.
func TestHelperLivenessFamiliesEmitted18685(t *testing.T) {
	c := &xpfCollector{}
	c.initGlobalDescriptors()
	ch := make(chan prometheus.Metric, 8)
	c.collectHelperLiveness(ch, fakeLiveness18685{age: 42 * time.Second, notReady: true, kills: 3})
	close(ch)
	got := 0
	for range ch {
		got++
	}
	if got != 3 {
		t.Fatalf("emitted %d helper liveness metrics, want 3", got)
	}
}

// TestHelperAnswerAgeUndefinedIsNaN18704: with no live helper generation the
// age is undefined, and the gauge says so with NaN instead of reading 0, which
// would look like "just answered".
func TestHelperAnswerAgeUndefinedIsNaN18704(t *testing.T) {
	c := &xpfCollector{}
	c.initGlobalDescriptors()
	ch := make(chan prometheus.Metric, 8)
	c.collectHelperLiveness(ch, fakeLiveness18685{age: -1})
	close(ch)
	for m := range ch {
		if m.Desc() != c.helperAnswerAgeSeconds {
			continue
		}
		var out dto.Metric
		if err := m.Write(&out); err != nil {
			t.Fatal(err)
		}
		if v := out.GetGauge().GetValue(); !math.IsNaN(v) {
			t.Fatalf("answer age with no live generation = %v, want NaN", v)
		}
		return
	}
	t.Fatal("answer age not emitted")
}
