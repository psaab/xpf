package main

import (
	"testing"

	"github.com/psaab/xpf/pkg/cliterm"
)

// #5459: `show chassis cluster <subsystem> <arg>` must reject an
// UNRECOGNIZED sub-arg with a usage error instead of silently falling
// back to the subsystem's default statistics/status view (which returned
// a valid-looking result with exit 0 for operator typos). A bare
// subsystem with NO sub-arg keeps its historical default view.
//
// cliterm.ClusterSubsystemView is the shared token-validation helper
// the remote-CLI dispatch (handleShow) delegates to; asserting on it
// directly avoids needing a live gRPC client.

func TestClusterSubsystemView_UnknownArgErrors(t *testing.T) {
	// A present-but-unrecognized token must error for every subsystem.
	cases := []struct {
		sub  string
		rest []string
	}{
		{"control-plane", []string{"foobaz"}},
		{"data-plane", []string{"foobaz"}},
		{"ip-monitoring", []string{"foobaz"}},
		{"fabric", []string{"foobaz"}},
		// Near-miss typos of real tokens must also error.
		{"control-plane", []string{"statisitcs"}},
		{"data-plane", []string{"interface"}},
		{"ip-monitoring", []string{"stat"}},
		{"fabric", []string{"stats"}},
	}
	for _, tc := range cases {
		topic, filter, err := cliterm.ClusterSubsystemView(tc.sub, tc.rest)
		if err == nil {
			t.Errorf("ClusterSubsystemView(%q, %v): expected error for unknown arg, got topic=%q filter=%q nil err (typo suppression regression)",
				tc.sub, tc.rest, topic, filter)
		}
	}
}

func TestClusterSubsystemView_RecognizedArgs(t *testing.T) {
	// Recognized sub-args must render exactly the pre-#5459 topic/filter.
	cases := []struct {
		sub        string
		rest       []string
		wantTopic  string
		wantFilter string
	}{
		{"control-plane", []string{"statistics"}, "chassis-cluster-control-plane-statistics", ""},
		{"data-plane", []string{"statistics"}, "chassis-cluster-data-plane-statistics", ""},
		{"data-plane", []string{"interfaces"}, "chassis-cluster-data-plane-interfaces", ""},
		{"data-plane", []string{"fairness"}, "chassis-cluster-data-plane-fairness", ""},
		{"data-plane", []string{"flows"}, "chassis-cluster-data-plane-flows", ""},
		{"data-plane", []string{"flows", "limit", "20"}, "chassis-cluster-data-plane-flows", "limit 20"},
		{"ip-monitoring", []string{"status"}, "chassis-cluster-ip-monitoring-status", ""},
		{"fabric", []string{"statistics"}, "chassis-cluster-fabric-statistics", ""},
	}
	for _, tc := range cases {
		topic, filter, err := cliterm.ClusterSubsystemView(tc.sub, tc.rest)
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

func TestClusterSubsystemView_BareSubsystemKeepsDefault(t *testing.T) {
	// A bare subsystem (no sub-arg) keeps its historical default view and
	// must NOT newly error — the #5459 bug is an UNKNOWN arg, not a
	// missing arg.
	cases := []struct {
		sub       string
		wantTopic string
	}{
		{"control-plane", "chassis-cluster-control-plane-statistics"},
		{"data-plane", "chassis-cluster-data-plane-statistics"},
		{"ip-monitoring", "chassis-cluster-ip-monitoring-status"},
		{"fabric", "chassis-cluster-fabric-statistics"},
	}
	for _, tc := range cases {
		topic, filter, err := cliterm.ClusterSubsystemView(tc.sub, nil)
		if err != nil {
			t.Errorf("ClusterSubsystemView(%q, nil): unexpected error for bare subsystem: %v", tc.sub, err)
			continue
		}
		if topic != tc.wantTopic || filter != "" {
			t.Errorf("ClusterSubsystemView(%q, nil) = (%q, %q); want (%q, \"\")",
				tc.sub, topic, filter, tc.wantTopic)
		}
	}
}
