package api

import "testing"

// TestHostInboundTCPlooseMetrics10752 binds the #10752 loose-posture signal:
// the disabled gauge tracks the wired fn, the failures counter tracks its
// value, and both omit (not zero) when unwired.
func TestHostInboundTCPlooseMetrics10752(t *testing.T) {
	for _, tc := range []struct {
		name     string
		disabled bool
		want     float64
	}{
		{"disabled", true, 1},
		{"not-disabled", false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{hostInboundTCPlooseDisabledFn: func() bool { return tc.disabled }}
			got, ok := gatherSingleSample6802(t, s, "xpf_host_inbound_tcp_loose_disabled")
			if !ok {
				t.Fatal("xpf_host_inbound_tcp_loose_disabled was not emitted")
			}
			if got != tc.want {
				t.Fatalf("gauge = %v, want %v", got, tc.want)
			}
		})
	}
	s := &Server{hostInboundTCPloosePostureFailuresFn: func() uint64 { return 7 }}
	got, ok := gatherSingleSample6802(t, s, "xpf_host_inbound_tcp_loose_posture_failures_total")
	if !ok {
		t.Fatal("xpf_host_inbound_tcp_loose_posture_failures_total was not emitted")
	}
	if got != 7 {
		t.Fatalf("counter = %v, want 7", got)
	}
	unwired := &Server{}
	for _, name := range []string{
		"xpf_host_inbound_tcp_loose_disabled",
		"xpf_host_inbound_tcp_loose_posture_failures_total",
	} {
		if _, ok := gatherSingleSample6802(t, unwired, name); ok {
			t.Errorf("%s was emitted with no fn wired; must omit, not publish 0", name)
		}
	}
}
