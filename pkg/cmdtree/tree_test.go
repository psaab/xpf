package cmdtree

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func contains(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func TestConfigLoadRescueCompletion(t *testing.T) {
	cands := CompleteFromTree(ConfigTopLevel, []string{"load"}, "", nil)
	if !contains(cands, "rescue") {
		t.Fatalf("config-mode load completions = %v, missing rescue", cands)
	}
}

func TestCompleteFromTree_PlaceholderWithChildrenDescends(t *testing.T) {
	cands := CompleteFromTree(OperationalTree, []string{"show", "route", "10.0.0.1"}, "", nil)
	if !contains(cands, "exact") || !contains(cands, "longer") || !contains(cands, "orlonger") {
		t.Fatalf("expected destination modifiers after placeholder, got %v", cands)
	}
	if contains(cands, "summary") {
		t.Fatalf("unexpected sibling completions after destination placeholder: %v", cands)
	}
}

func TestCompleteFromTree_PlaceholderWithoutChildrenStaysLevel(t *testing.T) {
	cands := CompleteFromTree(OperationalTree, []string{"ping", "8.8.8.8"}, "", nil)
	if !contains(cands, "count") || !contains(cands, "source") || !contains(cands, "size") {
		t.Fatalf("expected ping option completions after host placeholder, got %v", cands)
	}
}

func TestCompleteFromTree_RequestFailoverSupportsNodeAfterRGValue(t *testing.T) {
	cfg := &config.Config{
		Chassis: config.ChassisConfig{
			Cluster: &config.ClusterConfig{
				RedundancyGroups: []*config.RedundancyGroup{
					{ID: 1},
				},
			},
		},
	}

	cands := CompleteFromTree(
		OperationalTree,
		[]string{"request", "chassis", "cluster", "failover", "redundancy-group", "1"},
		"",
		cfg,
	)
	if !contains(cands, "node") {
		t.Fatalf("expected 'node' completion after redundancy-group value, got %v", cands)
	}
}

func TestCompleteFromTree_ShowRouteTableDynamicNames(t *testing.T) {
	cfg := &config.Config{
		RoutingInstances: []*config.RoutingInstanceConfig{
			{Name: "blue"},
		},
	}

	cands := CompleteFromTree(OperationalTree, []string{"show", "route", "table"}, "", cfg)
	if !contains(cands, "inet.0") || !contains(cands, "inet6.0") {
		t.Fatalf("expected default table names, got %v", cands)
	}
	if !contains(cands, "blue.inet.0") || !contains(cands, "blue.inet6.0") {
		t.Fatalf("expected per-instance table names, got %v", cands)
	}
}

func TestCompleteFromTree_UniquePrefixWordsDescend(t *testing.T) {
	cands := CompleteFromTree(OperationalTree, []string{"sh", "sec"}, "", nil)
	if !contains(cands, "flow") || !contains(cands, "nat") {
		t.Fatalf("expected security subtree completions after unique prefixes, got %v", cands)
	}
}

func TestCompleteFromTree_AmbiguousLastConsumedPrefixReturnsMatches(t *testing.T) {
	cands := CompleteFromTree(OperationalTree, []string{"show", "s"}, "", nil)
	if !contains(cands, "security") || !contains(cands, "services") || !contains(cands, "system") {
		t.Fatalf("expected ambiguous show subtree matches, got %v", cands)
	}
}

func TestLookupDesc_ResolvesUniquePrefixWords(t *testing.T) {
	if got := LookupDesc([]string{"show", "sec"}, "flow", false); got != "Show security flow information" {
		t.Fatalf("LookupDesc() = %q, want %q", got, "Show security flow information")
	}
}

func TestLookupDesc_ConfigModeResolvesUniquePrefixWords(t *testing.T) {
	if got := LookupDesc([]string{"com"}, "confirmed", true); got != "Automatically rollback if not confirmed" {
		t.Fatalf("LookupDesc() = %q, want %q", got, "Automatically rollback if not confirmed")
	}
}

// #11832: remote `?` help must keep walking after a value consumed by a typed
// option, so subsequent options retain their descriptions.
func TestLookupDesc_ContinuesAfterTypedLeafValue_11832(t *testing.T) {
	got := LookupDesc(
		[]string{"show", "security", "flow", "session", "destination-port", "443"},
		"source-port",
		false,
	)
	if got != "Filter by source port" {
		t.Fatalf("LookupDesc after destination-port value = %q, want %q", got, "Filter by source port")
	}
}

// #1319 PR 1 retired the cmdtree config-mode typed-leaf overlay
// (ConfigClassOfServiceSchedulers) and the unit-test-only
// CompleteFromTreeWithDesc(ConfigTopLevel, "set", ...) coverage that went
// with it — that path is NOT the one the live config-mode `set ... ?`
// completer uses (it routes through config.CompleteSetPathWithValues over
// setSchema), so testing it was a false-coverage trap. The symptom-1
// completion behaviour is now pinned at the real frontend boundary in
// pkg/cli (completeConfigWithDesc) and pkg/grpcapi (completeConfigPairs).

// TestCompleteFromTree_RequestSystemDynamicDNS is the #3276 cmdtree SSOT proof:
// `request system dynamic-dns` completes to the update/check verbs, so tab
// completion + `?` help expose the operator force-now/check-now command across
// the local CLI, remote CLI, and gRPC. Revert the cmdtree node → RED.
func TestCompleteFromTree_RequestSystemDynamicDNS(t *testing.T) {
	cands := CompleteFromTree(OperationalTree, []string{"request", "system", "dynamic-dns"}, "", nil)
	if !contains(cands, "update") || !contains(cands, "check") {
		t.Fatalf("expected update/check completions under request system dynamic-dns, got %v", cands)
	}
}

// #4228 Gap 7: the vSRX CoS show commands are registered in the operational
// tree with tab-completion + descriptions.
func TestCompleteFromTree_ShowClassOfServiceGap7(t *testing.T) {
	cands := CompleteFromTree(OperationalTree, []string{"show", "class-of-service"}, "", nil)
	for _, want := range []string{"interface", "classifier", "scheduler-map", "forwarding-class"} {
		if !contains(cands, want) {
			t.Fatalf("expected %q under show class-of-service, got %v", want, cands)
		}
	}

	// classifier type filter completes to the two supported code-point types.
	cands = CompleteFromTree(OperationalTree, []string{"show", "class-of-service", "classifier", "type"}, "", nil)
	if !contains(cands, "dscp") || !contains(cands, "ieee-802.1") {
		t.Fatalf("expected dscp/ieee-802.1 under classifier type, got %v", cands)
	}

	// Descriptions are present for the new leaves.
	if got := LookupDesc([]string{"show", "class-of-service"}, "forwarding-class", false); got == "" {
		t.Fatalf("missing description for show class-of-service forwarding-class")
	}
}

func TestCompleteFromTree_ShowInterfacesQueueGap7(t *testing.T) {
	cands := CompleteFromTree(OperationalTree, []string{"show", "interfaces"}, "", nil)
	if !contains(cands, "queue") {
		t.Fatalf("expected 'queue' under show interfaces, got %v", cands)
	}
}

// The classifier/scheduler-map DynamicFn surface the configured names.
func TestCompleteFromTree_ShowClassOfServiceDynamicNames(t *testing.T) {
	cfg := &config.Config{
		ClassOfService: &config.ClassOfServiceConfig{
			DSCPClassifiers: map[string]*config.CoSDSCPClassifier{
				"wan-classifier": {Name: "wan-classifier"},
			},
			IEEE8021Classifiers: map[string]*config.CoSIEEE8021Classifier{
				"wan-pcp": {Name: "wan-pcp"},
			},
			SchedulerMaps: map[string]*config.CoSSchedulerMap{
				"bandwidth-limit": {Name: "bandwidth-limit"},
			},
		},
	}
	cands := CompleteFromTree(OperationalTree, []string{"show", "class-of-service", "classifier"}, "", cfg)
	if !contains(cands, "wan-classifier") || !contains(cands, "wan-pcp") {
		t.Fatalf("expected configured classifier names, got %v", cands)
	}
	cands = CompleteFromTree(OperationalTree, []string{"show", "class-of-service", "scheduler-map"}, "", cfg)
	if !contains(cands, "bandwidth-limit") {
		t.Fatalf("expected configured scheduler-map name, got %v", cands)
	}
}
