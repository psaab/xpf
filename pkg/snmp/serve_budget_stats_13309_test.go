package snmp

import (
	"net"
	"testing"
	"time"
)

// #13309 (D6-10): shed requests and source-bucket evictions must be
// readable outside package snmp via Agent.ServeBudgetStats, so pkg/api
// can export xpf_snmp_requests_shed_total and
// xpf_snmp_source_bucket_evictions_total.
func TestSNMPServeBudgetStatsExposed13309(t *testing.T) {
	a := &Agent{serveBudget: newSNMPServeBudget()}
	frozen := time.Unix(1700000000, 0)
	a.serveBudget.now = func() time.Time { return frozen }
	src := net.ParseIP("192.0.2.1")
	// Drain the per-source burst: every further request is shed.
	for i := range snmpServeBurstPerSource {
		if !a.serveBudget.allow(src) {
			t.Fatalf("request %d refused before burst exhausted", i)
		}
	}
	for range 3 {
		if a.serveBudget.allow(src) {
			t.Fatal("request past burst admitted")
		}
	}
	shed, evictions, sources := a.ServeBudgetStats()
	if shed != 3 {
		t.Errorf("shed = %d, want 3", shed)
	}
	if evictions != 0 {
		t.Errorf("evictions = %d, want 0", evictions)
	}
	if sources != 1 {
		t.Errorf("tracked sources = %d, want 1", sources)
	}

	// Fill the source table, then a newcomer must evict one incumbent.
	b := newSNMPServeBudget()
	b.now = func() time.Time { return frozen }
	for i := range snmpServeMaxSources {
		b.allow(net.IPv4(10, byte(i>>16), byte(i>>8), byte(i)))
	}
	b.allow(net.ParseIP("198.51.100.1"))
	ag := &Agent{serveBudget: b}
	shed, evictions, sources = ag.ServeBudgetStats()
	if evictions != 1 {
		t.Errorf("evictions = %d, want 1 after full-table newcomer", evictions)
	}
	if sources != snmpServeMaxSources {
		t.Errorf("tracked sources = %d, want %d", sources, snmpServeMaxSources)
	}

	// A bare agent (nil budget) reports zeros, never panics.
	var bare Agent
	if s, e, n := bare.ServeBudgetStats(); s != 0 || e != 0 || n != 0 {
		t.Errorf("bare agent ServeBudgetStats = %d/%d/%d, want 0/0/0", s, e, n)
	}
}
