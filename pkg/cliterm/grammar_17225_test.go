package cliterm

import "testing"

// #17225: the deterministic-NAT pool selector and the chassis-cluster
// subsystem grammar were transcribed per CLI surface, and strictness
// fixes landed on one copy only (#13199 local natPoolArg stayed
// lenient; #15775 remote clusterSubsystemView ignored trailing tokens
// after a valid leaf). The grammar now lives here once; these tables
// pin the strict form both surfaces share.

func TestParseNATPoolSelector17225(t *testing.T) {
	if name, err := ParseNATPoolSelector(nil); err != nil || name != "" {
		t.Fatalf("ParseNATPoolSelector(nil) = %q, %v; want empty selector", name, err)
	}
	if name, err := ParseNATPoolSelector([]string{"pool", "web"}); err != nil || name != "web" {
		t.Fatalf("ParseNATPoolSelector(pool web) = %q, %v; want web", name, err)
	}
	for _, rest := range [][]string{
		{"pool"},
		{"bogus"},
		{"poo", "web"},
		{"pool", "web", "extra"},
		{"pool", ""},
	} {
		if name, err := ParseNATPoolSelector(rest); err == nil || name != "" {
			t.Errorf("ParseNATPoolSelector(%q) = %q, %v; want an error", rest, name, err)
		}
	}
}

func TestClusterSubsystemViewTrailingTokens17225(t *testing.T) {
	// A valid leaf followed by junk must error on every subsystem
	// (#15775 residual), as must a wrong leaf with trailing tokens.
	for _, tc := range []struct {
		sub  string
		rest []string
	}{
		{"control-plane", []string{"statistics", "junk"}},
		{"control-plane", []string{"statistics", "junk", "more"}},
		{"fabric", []string{"statistics", "junk"}},
		{"ip-monitoring", []string{"status", "junk"}},
		{"data-plane", []string{"statistics", "junk"}},
		{"data-plane", []string{"interfaces", "junk"}},
		{"data-plane", []string{"fairness", "junk"}},
		{"control-plane", []string{"foobaz"}},
		{"data-plane", []string{"foobaz"}},
		{"ip-monitoring", []string{"foobaz"}},
		{"fabric", []string{"foobaz"}},
		{"bogus", nil},
		// fence-status is dispatched before the subsystem view on
		// both surfaces; it is not a subsystem.
		{"fence-status", nil},
		{"fence-status", []string{"extra"}},
	} {
		if topic, filter, err := ClusterSubsystemView(tc.sub, tc.rest); err == nil {
			t.Errorf("ClusterSubsystemView(%q, %v) = (%q, %q), nil; want an error", tc.sub, tc.rest, topic, filter)
		}
	}
}

func TestClusterSubsystemViewRecognizedAndBare17225(t *testing.T) {
	cases := []struct {
		sub        string
		rest       []string
		wantTopic  string
		wantFilter string
	}{
		{"control-plane", nil, "chassis-cluster-control-plane-statistics", ""},
		{"control-plane", []string{"statistics"}, "chassis-cluster-control-plane-statistics", ""},
		{"data-plane", nil, "chassis-cluster-data-plane-statistics", ""},
		{"data-plane", []string{"statistics"}, "chassis-cluster-data-plane-statistics", ""},
		{"data-plane", []string{"interfaces"}, "chassis-cluster-data-plane-interfaces", ""},
		{"data-plane", []string{"fairness"}, "chassis-cluster-data-plane-fairness", ""},
		{"data-plane", []string{"flows"}, "chassis-cluster-data-plane-flows", ""},
		{"data-plane", []string{"flows", "limit", "20"}, "chassis-cluster-data-plane-flows", "limit 20"},
		{"ip-monitoring", nil, "chassis-cluster-ip-monitoring-status", ""},
		{"ip-monitoring", []string{"status"}, "chassis-cluster-ip-monitoring-status", ""},
		{"fabric", nil, "chassis-cluster-fabric-statistics", ""},
		{"fabric", []string{"statistics"}, "chassis-cluster-fabric-statistics", ""},
	}
	for _, tc := range cases {
		topic, filter, err := ClusterSubsystemView(tc.sub, tc.rest)
		if err != nil {
			t.Errorf("ClusterSubsystemView(%q, %v): unexpected error: %v", tc.sub, tc.rest, err)
			continue
		}
		if topic != tc.wantTopic || filter != tc.wantFilter {
			t.Errorf("ClusterSubsystemView(%q, %v) = (%q, %q); want (%q, %q)",
				tc.sub, tc.rest, topic, filter, tc.wantTopic, tc.wantFilter)
		}
	}
}
