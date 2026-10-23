package api

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/ddns"
)

// noopDDNSUpdater15992 satisfies ddns.DNSUpdater for gauge-wiring tests.
type noopDDNSUpdater15992 struct{}

func (noopDDNSUpdater15992) UpsertLease(context.Context, ddns.LeaseDNSRecord) error { return nil }
func (noopDDNSUpdater15992) DeleteLease(context.Context, ddns.LeaseDNSRecord) error { return nil }

// TestDDNSUnsignedNonLoopbackMetrics15992 pins #15992's live alarm: real
// managers reconciled with a non-loopback unsigned server surface a 1
// gauge on both DDNS families for as long as the posture persists, and 0
// once it clears — driven through Reconcile/Stats, not preconstructed stats.
func TestDDNSUnsignedNonLoopbackMetrics15992(t *testing.T) {
	gauge := func(metrics []prometheus.Metric, name string) (float64, bool) {
		for _, m := range metrics {
			if descName(m.Desc()) != name {
				continue
			}
			var dm dto.Metric
			if err := m.Write(&dm); err != nil {
				t.Fatalf("metric Write: %v", err)
			}
			if g := dm.GetGauge(); g != nil {
				return g.GetValue(), true
			}
		}
		return 0, false
	}
	collect := func(fn func(ch chan<- prometheus.Metric)) []prometheus.Metric {
		ch := make(chan prometheus.Metric, 64)
		fn(ch)
		close(ch)
		var out []prometheus.Metric
		for m := range ch {
			out = append(out, m)
		}
		return out
	}
	nowFn := func() time.Time { return time.Unix(1_700_000_000, 0) }
	dir := t.TempDir()

	// Surface B: reconcile a real manager into the unsigned posture.
	mgr := ddns.NewManagerForTesting(nil, noopDDNSUpdater15992{},
		filepath.Join(dir, "state.json"), filepath.Join(dir, "l4.csv"), filepath.Join(dir, "l6.csv"),
		"node0", nowFn, nil)
	unsignedCfg := &config.DHCPServerConfig{DynamicDNS: &config.DHCPDynamicDNSConfig{
		Enabled: true, Domain: "example.com", TTLSeconds: 300, UpdateServer: "192.0.2.53",
	}}
	if err := mgr.Reconcile(context.Background(), unsignedCfg); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	leaseSrv := &Server{ddnsStatsFn: func() *ddns.Stats { s := mgr.Stats(); return &s }}
	c1 := newCollector(leaseSrv)
	if v, ok := gauge(collect(c1.collectDDNSMetrics), "xpf_dhcp_ddns_unsigned_nonloopback_active"); !ok || v != 1 {
		t.Errorf("lease unsigned gauge = %v (ok=%v), want 1", v, ok)
	}

	// Surface A: reconcile a real manager with an unsigned provider catalog.
	sa := newSurfaceAManager15992(t, dir)
	catalog := map[string]*config.DDNSProvider{"p1": {Backend: "rfc2136", UpdateServer: "192.0.2.53"}}
	observe := func(context.Context, ddns.SurfaceAScope) (ddns.AddressObservation, bool) {
		return ddns.AddressObservation{}, false
	}
	if err := sa.Reconcile(context.Background(), nil, observe, nil, catalog); err != nil {
		t.Fatalf("surface-a reconcile: %v", err)
	}
	saSrv := &Server{surfaceAStatsFn: func() *ddns.SurfaceAStats { s := sa.Stats(); return &s }}
	c2 := newCollector(saSrv)
	if v, ok := gauge(collect(c2.collectSurfaceADDNSMetrics), "xpf_ddns_surface_a_unsigned_nonloopback_active"); !ok || v != 1 {
		t.Errorf("surface-a unsigned gauge = %v (ok=%v), want 1", v, ok)
	}

	// Control: clearing the posture emits 0, not a missing series.
	loopbackCfg := &config.DHCPServerConfig{DynamicDNS: &config.DHCPDynamicDNSConfig{
		Enabled: true, Domain: "example.com", TTLSeconds: 300, UpdateServer: "127.0.0.1",
	}}
	if err := mgr.Reconcile(context.Background(), loopbackCfg); err != nil {
		t.Fatalf("reconcile loopback: %v", err)
	}
	c3 := newCollector(leaseSrv)
	if v, ok := gauge(collect(c3.collectDDNSMetrics), "xpf_dhcp_ddns_unsigned_nonloopback_active"); !ok || v != 0 {
		t.Errorf("inactive unsigned gauge = %v (ok=%v), want 0", v, ok)
	}
}

func newSurfaceAManager15992(t *testing.T, dir string) *ddns.SurfaceAManager {
	t.Helper()
	return ddns.NewSurfaceAManagerForTesting(filepath.Join(dir, "iface.json"), noopDDNSUpdater15992{}, func() time.Time { return time.Unix(1_700_000_000, 0) })
}
