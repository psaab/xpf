package userspace

import "testing"

func TestPredefinedTimeouts16815(t *testing.T) {
	for _, tc := range []struct {
		name, port string
		timeout    uint32
	}{
		{"junos-snmp-agentx", "705", 7560},
		{"junos-wxcontrol", "3578", 7560},
		{"junos-mail", "25", 0},
		{"junos-smtp", "25", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			terms, ok := expandUserspacePolicyApplications(appTimeoutCfg(nil), []string{tc.name})
			if !ok || len(terms) != 1 {
				t.Fatalf("predefined expansion = %+v, ok=%v", terms, ok)
			}
			if term := terms[0]; term.Protocol != "tcp" || term.DestinationPort != tc.port || term.InactivityTimeout != tc.timeout {
				t.Fatalf("predefined snapshot = %+v, want tcp/%s timeout %d", term, tc.port, tc.timeout)
			}
		})
	}
}

func TestPredefinedYmsg16815(t *testing.T) {
	terms, ok := expandUserspacePolicyApplications(appTimeoutCfg(nil), []string{"junos-ymsg"})
	if !ok || len(terms) != 4 {
		t.Fatalf("ymsg expansion = %+v, ok=%v; want all four capture terms", terms, ok)
	}
	want := map[string]bool{"tcp/5000-5010": true, "tcp/5050": true, "udp/5000-5010": true, "udp/5050": true}
	for _, term := range terms {
		key := term.Protocol + "/" + term.DestinationPort
		if !want[key] || term.SourcePort != "" || term.InactivityTimeout != 0 {
			t.Fatalf("unexpected or repeated ymsg term: %+v", term)
		}
		delete(want, key)
	}
	if len(want) != 0 {
		t.Fatalf("missing ymsg tuples: %v", want)
	}
}
