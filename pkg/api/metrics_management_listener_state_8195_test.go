package api

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/psaab/xpf/pkg/sysservices"
)

// collectManagementListenerState8195 gathers xpf_management_listener_state and
// keys it "surface|address|state", so a cell can assert one series without
// depending on emission order.
func collectManagementListenerState8195(t *testing.T, ls sysservices.Listeners) map[string]float64 {
	t.Helper()
	s := &Server{managementListenersFn: func() sysservices.Listeners { return ls }}
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(newCollector(s))
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	out := map[string]float64{}
	for _, mf := range mfs {
		if mf.GetName() != "xpf_management_listener_state" {
			continue
		}
		for _, m := range mf.GetMetric() {
			var surface, addr, state string
			for _, l := range m.GetLabel() {
				switch l.GetName() {
				case "surface":
					surface = l.GetValue()
				case "address":
					addr = l.GetValue()
				case "state":
					state = l.GetValue()
				}
			}
			out[surface+"|"+addr+"|"+state] = m.GetGauge().GetValue()
		}
	}
	return out
}

// TestManagementListenerStateIsExported8195 is the #8195 gate.
//
// The circular case is what this exists for: the gRPC listener's state has one
// consumer, `show system services`, and that is reached OVER the gRPC listener.
// When it fails, the surface that reports the failure is the surface that is
// down. A Prometheus series scraped over the SEPARATE HTTP listener is the
// non-circular observer.
//
// xpf_management_listener_down already existed and is untouched. It cannot
// answer this: it is HTTP-only (mgmtListenerDown reads effectiveHTTPListener),
// address-less, and collapses Disabled and Listening into the same 0.
func TestManagementListenerStateIsExported8195(t *testing.T) {
	rows := []struct {
		name string
		ls   sysservices.Listeners
		// want maps "surface|address|state" -> expected value.
		want map[string]float64
	}{
		{
			name: "both listening carries both addresses",
			ls: sysservices.Listeners{
				GRPC: sysservices.Listener{Addr: "127.0.0.1:50051", State: sysservices.StateListening},
				HTTP: sysservices.Listener{Addr: "127.0.0.1:8080", State: sysservices.StateListening},
			},
			want: map[string]float64{
				"grpc|127.0.0.1:50051|listening": 1,
				"grpc|127.0.0.1:50051|failed":    0,
				"grpc|127.0.0.1:50051|disabled":  0,
				"http|127.0.0.1:8080|listening":  1,
			},
		},
		{
			// THE case. The gRPC leg failed; xpf_management_listener_down would
			// read 0, because it reads the HTTP leg.
			name: "a FAILED gRPC listener is visible with its address",
			ls: sysservices.Listeners{
				GRPC: sysservices.Listener{Addr: "127.0.0.1:50051", State: sysservices.StateFailed},
				HTTP: sysservices.Listener{Addr: "127.0.0.1:8080", State: sysservices.StateListening},
			},
			want: map[string]float64{
				"grpc|127.0.0.1:50051|failed":    1,
				"grpc|127.0.0.1:50051|listening": 0,
				"http|127.0.0.1:8080|listening":  1,
				"http|127.0.0.1:8080|failed":     0,
			},
		},
		{
			// Disabled must be distinguishable from Listening. Under the bare
			// 0/1 both read 0, so an operator cannot tell a deliberately-off
			// REST listener from a serving one.
			name: "a DISABLED http listener is not the same as a serving one",
			ls: sysservices.Listeners{
				GRPC: sysservices.Listener{Addr: "127.0.0.1:50051", State: sysservices.StateListening},
				HTTP: sysservices.Listener{State: sysservices.StateDisabled},
			},
			want: map[string]float64{
				"http||disabled":  1,
				"http||listening": 0,
				"http||failed":    0,
			},
		},
	}

	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			got := collectManagementListenerState8195(t, row.ls)
			for key, want := range row.want {
				v, ok := got[key]
				if !ok {
					t.Errorf("no series for %q — an ABSENT series reads as healthy "+
						"to an alert, which is the failure this metric exists to "+
						"remove; got %v", key, got)
					continue
				}
				if v != want {
					t.Errorf("%s = %v, want %v", key, v, want)
				}
			}
		})
	}
}

// TestManagementListenerStateEmitsEveryState8195 pins the state-set shape.
//
// Every state gets a series, not only the current one. A collector that emitted
// just the active state would make an alert on `state{state="failed"} == 1`
// silently un-evaluable while the listener is healthy — the series would not
// exist, and an absent series is indistinguishable from a healthy one at the
// point an alert reads it.
func TestManagementListenerStateEmitsEveryState8195(t *testing.T) {
	got := collectManagementListenerState8195(t, sysservices.Listeners{
		GRPC:  sysservices.Listener{Addr: "a", State: sysservices.StateListening},
		HTTP:  sysservices.Listener{Addr: "b", State: sysservices.StateListening},
		HTTPS: sysservices.Listener{Addr: "c", State: sysservices.StateStale},
	})
	for _, want := range []string{
		"grpc|a|listening", "grpc|a|failed", "grpc|a|disabled", "grpc|a|stale",
		"http|b|listening", "http|b|failed", "http|b|disabled", "http|b|stale",
		"https|c|listening", "https|c|failed", "https|c|disabled", "https|c|stale",
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing series %q — %d emitted: %v", want, len(got), got)
		}
	}
	if len(got) != 12 {
		t.Errorf("emitted %d series, want exactly 12 (3 surfaces x 4 states): %v",
			len(got), got)
	}
	// #14582: the stale HTTPS leg must carry value 1 on its stale series, so
	// an alert on state="stale" fires for a loopback-fallback/vanished bind.
	if got["https|c|stale"] != 1 || got["https|c|listening"] != 0 {
		t.Errorf("https stale series = %v (listening %v), want stale=1 listening=0: %v",
			got["https|c|stale"], got["https|c|listening"], got)
	}
}

// TestManagementListenerStateAbsentWithoutTheSeam8195 is the control that stops
// the collector emitting a fabricated snapshot when the daemon has not supplied
// one. A zero-value Listeners would render both legs as StateDisabled — which
// is a CLAIM (the operator turned them off) rather than the truth (we do not
// know), and it would read as healthy.
func TestManagementListenerStateAbsentWithoutTheSeam8195(t *testing.T) {
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(newCollector(&Server{})) // seam deliberately nil
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() == "xpf_management_listener_state" {
			t.Fatalf("emitted %d listener-state series with no seam wired — a "+
				"zero-value Listeners renders both legs as DISABLED, which is a "+
				"CLAIM (the operator turned them off) rather than the truth (we "+
				"do not know), and it reads as healthy",
				len(mf.GetMetric()))
		}
	}
}
