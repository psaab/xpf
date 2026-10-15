package api

import (
	"os"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// metrics_zone_overflow_6845_test.go — #6845.
//
// `ProcessStatus.ZoneCounterOverflowActive` was decoded by the Go control plane
// and consumed by NOTHING — no CLI, no REST, no gRPC, no Prometheus. When the
// helper's 63-slot per-zone table overflows, zones past capacity are never
// registered, read as `ErrCounterNotPopulated`, and render as "not available"
// on every surface.
//
// Nothing is misreported by that: an overflowed zone degrades to "not known"
// rather than publishing a false 0. What is missing is the ability to tell WHY,
// because `unpopulated` is three-way ambiguous by construction — pre-#3651
// helper, overflow (traffic genuinely missed), or an idle zone. Only the middle
// one needs action, and the bit separating it was already on the wire.
//
// These cells bind the surfacing, since a decoded-but-unread field is exactly
// what regressed here and a field that no test reads regresses again silently.

// TestZoneCounterOverflowGaugeTracksTheStatus6845 is PAIRED. The overflow leg
// alone is satisfied by a gauge hardwired to 1, which would tell every healthy
// operator to go reduce their zone count; the healthy leg alone is satisfied by
// one hardwired to 0, which is the pre-#6845 blindness with a series attached.
func TestZoneCounterOverflowGaugeTracksTheStatus6845(t *testing.T) {
	for _, tc := range []struct {
		name     string
		overflow bool
		want     float64
	}{
		{"overflowed", true, 1},
		{"healthy", false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := gatherZoneOverflow6845(t, &dpuserspace.ProcessStatus{
				ZoneCounterOverflowActive: tc.overflow,
			})
			if !ok {
				t.Fatalf("xpf_zone_counters_overflow_active was not emitted from a " +
					"status that was successfully read; the operator cannot tell an " +
					"overflowed zone from an idle one, which is #6845")
			}
			if got != tc.want {
				t.Errorf("gauge = %v, want %v — it does not track "+
					"ZoneCounterOverflowActive, so it reports the same value whether "+
					"or not zones are going uncounted", got, tc.want)
			}
		})
	}
}

// TestZoneCounterOverflowGaugeAbsentWithNoStatus6845 pins the absence contract,
// which differs deliberately from its sibling gauge.
//
// `xpf_zone_counters_unpopulated_zones` is CONFIG-derived and is emitted above
// the dataplane gate, so it keeps reporting through a degraded boot. This one is
// a property of the RUNNING helper's slot table: with no helper there is no slot
// table, so a 0 would be a false all-clear about a machine that was never asked.
// Absent must mean "no helper to ask"; 0 must mean "the helper said no overflow".
//
// FAIL-ON-REVERT: emit the gauge unconditionally (e.g. hoist it out of
// collectUserspaceStatus, or default it to 0 when the status pointer is nil) and
// this reds.
func TestZoneCounterOverflowGaugeAbsentWithNoStatus6845(t *testing.T) {
	if _, ok := gatherZoneOverflow6845(t, nil); ok {
		t.Error("xpf_zone_counters_overflow_active was emitted with NO helper " +
			"status read; a 0 there is a false all-clear — it asserts there is no " +
			"overflow on a machine nothing asked")
	}
}

// gatherZoneOverflow6845 drives the real collector path.
//
// A PLAIN registry, not a pedantic one: a hand-maintained Describe list written
// to satisfy a registry is a second inventory that drifts.
//
// The Describe ⊇ Collect contract is NOT dropped, it is owned elsewhere:
// metrics_descriptor_coverage_test.go runs the REAL Collect through a pedantic
// registry over the whole collector (#1726), so a descriptor emitted here and not
// declared in Describe reds there. Splitting the two questions keeps each cell
// able to fail for one reason.
func gatherZoneOverflow6845(t *testing.T, status *dpuserspace.ProcessStatus) (float64, bool) {
	t.Helper()
	c := newCollector(&Server{})
	reg := prometheus.NewRegistry()
	reg.MustRegister(&zoneOverflowOnlyCollector6845{c: c, status: status})
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != "xpf_zone_counters_overflow_active" {
			continue
		}
		ms := mf.GetMetric()
		if len(ms) != 1 {
			t.Fatalf("metric count = %d, want 1", len(ms))
		}
		return ms[0].GetGauge().GetValue(), true
	}
	return 0, false
}

// zoneOverflowOnlyCollector6845 drives emitZoneCounterOverflow with the same
// *ProcessStatus the production Collect hands it, including nil — which is where
// the absence contract lives, in the emitter itself rather than inherited from a
// sibling's early return.
//
// The WIRING half — that Collect actually calls it — is bound separately by
// TestCollectStillCallsTheOverflowEmitter6845 below, because a cell that calls
// the emitter cannot see whether anything else does.
type zoneOverflowOnlyCollector6845 struct {
	c      *xpfCollector
	status *dpuserspace.ProcessStatus
}

func (z *zoneOverflowOnlyCollector6845) Describe(ch chan<- *prometheus.Desc) {
	ch <- z.c.zoneCountersOverflowActive
}

func (z *zoneOverflowOnlyCollector6845) Collect(ch chan<- prometheus.Metric) {
	z.c.emitZoneCounterOverflow(ch, z.status)
}

// TestCollectStillCallsTheOverflowEmitter6845 is the WIRING cell.
//
// Every cell above calls emitZoneCounterOverflow directly, so a Collect that
// stopped calling it would pass all of them while the series vanished from every
// scrape — the decoded-but-unread state this issue exists to fix, one layer up.
// Collect cannot be driven from a unit test without a loaded dataplane, so the
// call is asserted at the source with comments stripped.
//
// FAIL-ON-REVERT: delete the c.emitZoneCounterOverflow(ch, userspaceStatus) line
// from Collect and this reds.
func TestCollectStillCallsTheOverflowEmitter6845(t *testing.T) {
	src := stripComments6845(readAPISource6845(t, "metrics.go"))
	const call = "c.emitZoneCounterOverflow(ch, userspaceStatus)"
	if !strings.Contains(src, call) {
		t.Fatalf("Collect does not call emitZoneCounterOverflow; " +
			"xpf_zone_counters_overflow_active is emitted by nothing, which is " +
			"exactly the decoded-but-unread state #6845 fixes")
	}
	// It must sit AFTER the status fetch, or it would be handed a nil status on
	// every scrape and the gauge would be permanently absent — indistinguishable
	// from "no helper", and wrong on a healthy box.
	fetch := strings.Index(src, "userspaceStatus = fetchUserspaceStatus(dp)")
	if fetch < 0 {
		t.Fatal("could not find the status fetch to order against")
	}
	if strings.Index(src, call) < fetch {
		t.Error("emitZoneCounterOverflow is called BEFORE the status is fetched, " +
			"so it would always receive nil and the gauge would never be emitted")
	}
}

func readAPISource6845(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

func stripComments6845(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(s, "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}
