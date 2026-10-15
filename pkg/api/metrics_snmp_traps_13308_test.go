package api

import "testing"

func TestSNMPTrapMetrics13308(t *testing.T) {
	s := &Server{snmpTrapStatsFn: func() (uint64, uint64, uint64) { return 7, 5, 2 }}
	for _, tc := range []struct {
		name string
		want float64
	}{
		{"xpf_snmp_traps_enqueued_total", 7},
		{"xpf_snmp_traps_sent_total", 5},
		{"xpf_snmp_traps_dropped_total", 2},
	} {
		got, ok := gatherSingleSample6802(t, s, tc.name)
		if !ok {
			t.Errorf("%s was not emitted", tc.name)
		} else if got != tc.want {
			t.Errorf("%s = %v, want %v", tc.name, got, tc.want)
		}
	}
	if _, ok := gatherSingleSample6802(t, &Server{}, "xpf_snmp_traps_dropped_total"); ok {
		t.Error("SNMP trap metric emitted without a stats source")
	}
}
