package api

import (
	"encoding/json"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #18529: the four #18520 handshake-relay counters must reach Prometheus.
// Distinct values so a crossed wire fails on its own field.
func TestHandshakeRelayCountersExport18529(t *testing.T) {
	const payload = `{"handshake_relay_outbox_drops_total":101,"handshake_relay_refused_total":103,"handshake_relay_lock_attempts_total":107,"handshake_relay_lock_contended_total":109}`
	var status dpuserspace.ProcessStatus
	if err := json.Unmarshal([]byte(payload), &status); err != nil {
		t.Fatalf("decode helper status: %v", err)
	}
	if status.HandshakeRelayOutboxDropsTotal != 101 || status.HandshakeRelayRefusedTotal != 103 ||
		status.HandshakeRelayLockAttemptsTotal != 107 || status.HandshakeRelayLockContendedTotal != 109 {
		t.Fatalf("decoded handshake relay counters = %+v, want 101/103/107/109", status)
	}

	collector := newCollector(nil)
	ch := make(chan prometheus.Metric)
	go func() {
		collector.emitUserspaceDynamicBufferMetrics(ch, status)
		close(ch)
	}()
	var metrics []prometheus.Metric
	for metric := range ch {
		metrics = append(metrics, metric)
	}
	assertCounterClose(t, metrics, collector.userspaceHandshakeRelayOutboxDrops, nil, 101)
	assertCounterClose(t, metrics, collector.userspaceHandshakeRelayRefused, nil, 103)
	assertCounterClose(t, metrics, collector.userspaceHandshakeRelayLockAttempts, nil, 107)
	assertCounterClose(t, metrics, collector.userspaceHandshakeRelayLockContended, nil, 109)

	for _, tc := range []struct {
		want string
		desc *prometheus.Desc
	}{
		{"xpf_userspace_handshake_relay_outbox_drops_total", collector.userspaceHandshakeRelayOutboxDrops},
		{"xpf_userspace_handshake_relay_refused_total", collector.userspaceHandshakeRelayRefused},
		{"xpf_userspace_handshake_relay_lock_attempts_total", collector.userspaceHandshakeRelayLockAttempts},
		{"xpf_userspace_handshake_relay_lock_contended_total", collector.userspaceHandshakeRelayLockContended},
	} {
		if tc.desc == nil {
			t.Fatalf("%s descriptor is nil", tc.want)
		}
		if got, ok := fqNameOf(tc.desc.String()); !ok || got != tc.want {
			t.Errorf("descriptor fqName = %q (ok=%v), want %q", got, ok, tc.want)
		}
	}
}
