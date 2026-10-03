package routing

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func compileSharedMemberFBF11589(t *testing.T) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, command := range []string{
		"set routing-instances member-ri instance-type vrf",
		"set routing-instances member-ri interface ge-0/0/1.0",
		"set routing-instances steer-ri instance-type forwarding",
		"set firewall family inet filter shared-fbf term steer from source-address 192.0.2.0/24",
		"set firewall family inet filter shared-fbf term steer then routing-instance steer-ri",
		"set interfaces ge-0/0/1 unit 0 family inet filter input shared-fbf",
		"set interfaces ge-0/0/2 unit 0 family inet filter input shared-fbf",
	} {
		path, err := config.ParseSetCommand(command)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", command, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", command, err)
		}
	}
	compiled, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	return compiled
}

// #11589: the real lenient compiler must preserve the valid non-member steer,
// suppress only the member attachment, and expose that dropped steer as
// degraded to the existing PBR health metrics.
func TestCompiledLenientMemberFBFSharedFilterIsIsolatedAndDegraded11589(t *testing.T) {
	cfg := compileSharedMemberFBF11589(t)

	if got := cfg.Firewall.FiltersInet["shared-fbf"].Terms[0].RoutingInstance; got != "steer-ri" {
		t.Fatalf("authored shared filter lost its valid non-member FBF action: got %q, want steer-ri", got)
	}
	if got := cfg.Interfaces.Interfaces["ge-0/0/2"].Units[0].FilterInputV4; got != "shared-fbf" {
		t.Fatalf("non-member attachment must keep shared filter, got %q", got)
	}
	if got := cfg.Interfaces.Interfaces["ge-0/0/1"].Units[0].FilterInputV4; got == "" || got == "shared-fbf" {
		t.Fatalf("member attachment must use a separate suppressed clone, got %q", got)
	}

	rules, degraded := PBRBuildRulesAndStats(cfg)
	if len(rules) != 1 || rules[0].Instance != "steer-ri" || rules[0].IifName != "ge-0-0-2" {
		t.Fatalf("only the non-member attachment should retain the steer: rules=%+v", rules)
	}
	if degraded < 1 {
		t.Fatalf("suppressed lenient member FBF must report degraded >= 1, got %d", degraded)
	}
}

// The compiled lenient path must retain the degradation signal after the
// compiler has removed member-only FBF terms from the cloned filter.
func TestCompiledLenientMemberFBFReportsPBRDegradation11589(t *testing.T) {
	cfg := compileSharedMemberFBF11589(t)
	_, degraded := PBRBuildRulesAndStats(cfg)
	if degraded < 1 {
		t.Fatalf("PBRBuildRulesAndStats(CompileConfigLenient(tree)) degraded = %d, want >= 1", degraded)
	}
}
