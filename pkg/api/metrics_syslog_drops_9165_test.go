package api

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/psaab/xpf/pkg/logging"
)

// #9165, the second half: `DroppedWrites`/`DroppedDials`/`DroppedCooldown` had
// ZERO production readers. A counted drop reached an operator through exactly
// one channel — the logging package's own ≤1/s slog.Warn — so a warning that
// had already been rate-limited away left nothing behind. A counter nobody
// reads is indistinguishable from no counter, which is why the missing reader
// is half the defect and not a follow-up.

func gather9165(t *testing.T, c *xpfCollector) []*dto.MetricFamily {
	t.Helper()
	reg := prometheus.NewPedanticRegistry()
	if err := reg.Register(c); err != nil {
		t.Fatalf("register: %v", err)
	}
	mfs, err := reg.Gather()
	if err != nil {
		// A collector whose Describe omits a Desc it later emits fails here.
		t.Fatalf("gather: %v", err)
	}
	return mfs
}

func syslogDropSeries9165(t *testing.T, mfs []*dto.MetricFamily) map[string]float64 {
	t.Helper()
	out := map[string]float64{}
	for _, mf := range mfs {
		if mf.GetName() != "xpf_syslog_messages_dropped_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			var parts []string
			for _, l := range m.GetLabel() {
				parts = append(parts, l.GetName()+"="+l.GetValue())
			}
			out[strings.Join(parts, ",")] = m.GetCounter().GetValue()
		}
	}
	return out
}

func collectorWithSyslogDrops9165(stats []logging.SyslogDropStat) *xpfCollector {
	return newCollector(&Server{
		syslogDropsFn: func() []logging.SyslogDropStat { return stats },
	})
}

// THE READER EXISTS and reports what the client counted.
func TestSyslogDropCountersReachAScrape9165(t *testing.T) {
	c := collectorWithSyslogDrops9165([]logging.SyslogDropStat{
		{RemoteAddr: "10.0.0.9:514", Protocol: "udp", Writes: 7},
	})
	got := syslogDropSeries9165(t, gather9165(t, c))

	if v, ok := got["addr=10.0.0.9:514,protocol=udp,reason=write,sink=security"]; !ok || v != 7 {
		t.Fatalf("the UDP write-drop counter did not reach the scrape (got %v, present=%v); "+
			"series seen: %v", v, ok, got)
	}
}

// All three reasons are emitted even at zero. A series that appears only once
// it becomes non-zero cannot be alerted on with increase() — there is no prior
// sample to compare against — and its absence is indistinguishable from a
// scrape that never reached this code.
func TestEveryDropReasonIsEmittedEvenAtZero9165(t *testing.T) {
	c := collectorWithSyslogDrops9165([]logging.SyslogDropStat{
		{RemoteAddr: "10.0.0.9:514", Protocol: "udp", Writes: 1},
	})
	got := syslogDropSeries9165(t, gather9165(t, c))
	for _, reason := range []string{"write", "dial", "cooldown"} {
		if _, ok := got["addr=10.0.0.9:514,protocol=udp,reason="+reason+",sink=security"]; !ok {
			t.Errorf("reason=%s is not emitted at zero, so it cannot be rated", reason)
		}
	}
}

// The protocol label is what makes a UDP-only silence legible as a transport
// property. Two collectors on different transports must not collapse into one
// series.
func TestCollectorsAreDistinguishedByAddrAndProtocol9165(t *testing.T) {
	c := collectorWithSyslogDrops9165([]logging.SyslogDropStat{
		{RemoteAddr: "10.0.0.9:514", Protocol: "udp", Writes: 3},
		{RemoteAddr: "10.0.0.10:514", Protocol: "tcp", Writes: 5, Dials: 2},
	})
	got := syslogDropSeries9165(t, gather9165(t, c))
	if got["addr=10.0.0.9:514,protocol=udp,reason=write,sink=security"] != 3 {
		t.Errorf("udp collector series wrong: %v", got)
	}
	if got["addr=10.0.0.10:514,protocol=tcp,reason=write,sink=security"] != 5 {
		t.Errorf("tcp collector write series wrong: %v", got)
	}
	if got["addr=10.0.0.10:514,protocol=tcp,reason=dial,sink=security"] != 2 {
		t.Errorf("tcp collector dial series wrong: %v", got)
	}
}

// CONTROL — an unwired hook emits nothing rather than a phantom zero series.
// A box with no remote syslog configured must not look like a box whose
// collectors are healthy.
func TestNoSyslogHookEmitsNothing9165(t *testing.T) {
	c := newCollector(&Server{})
	if got := syslogDropSeries9165(t, gather9165(t, c)); len(got) != 0 {
		t.Errorf("an unwired hook emitted %d series: %v", len(got), got)
	}
}

// BIND THE WIRING: every cell above constructs a Server literal and sets
// srv.syslogDropsFn directly, so all of them stay green if
// `NewServer` stops copying Config.SyslogDropsFn onto the field. That
// assignment is the only path production uses.
func TestNewServerCopiesTheSyslogDropHook9165(t *testing.T) {
	srv := NewServer(Config{
		SyslogDropsFn: func() []logging.SyslogDropStat {
			return []logging.SyslogDropStat{
				{RemoteAddr: "10.0.0.9:514", Protocol: "udp", Writes: 4},
			}
		},
	})
	if srv.syslogDropsFn == nil {
		t.Fatal("NewServer dropped Config.SyslogDropsFn, so the daemon's hook " +
			"never reaches the collector and the family is permanently absent")
	}
	got := syslogDropSeries9165(t, gather9165(t, newCollector(srv)))
	if got["addr=10.0.0.9:514,protocol=udp,reason=write,sink=security"] != 4 {
		t.Errorf("hook did not reach the scrape through NewServer: %v", got)
	}
}

// #16769: the same collector on both sinks must not collapse into one
// series — a system-syslog drop and a security-stream drop to the same
// addr:port are different losses.
func TestSyslogDropsDistinguishedBySink16769(t *testing.T) {
	c := collectorWithSyslogDrops9165([]logging.SyslogDropStat{
		{Sink: "security", RemoteAddr: "10.0.0.9:514", Protocol: "udp", Writes: 3},
		{Sink: "system", RemoteAddr: "10.0.0.9:514", Protocol: "udp", Writes: 7},
	})
	got := syslogDropSeries9165(t, gather9165(t, c))
	if got["addr=10.0.0.9:514,protocol=udp,reason=write,sink=security"] != 3 {
		t.Errorf("security sink series wrong: %v", got)
	}
	if got["addr=10.0.0.9:514,protocol=udp,reason=write,sink=system"] != 7 {
	}
}
