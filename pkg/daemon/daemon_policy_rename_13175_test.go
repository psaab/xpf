package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

func TestExpandPolicyRenameAncestryMultiZone13175(t *testing.T) {
	oldCfg := policyRenameEvaluatorConfig("p", config.PolicyPermit)
	oldCfg.Security.Policies[1].Policies = oldCfg.Security.Policies[1].Policies[:1]
	oldCfg.Security.GlobalPolicies = []*config.Policy{{
		Name: "g", Action: config.PolicyPermit,
		Match: config.PolicyMatch{FromZones: []string{"lan", "wan"}, ToZones: []string{"lan", "wan"}},
	}}
	newCfg := policyRenameEvaluatorConfig("p", config.PolicyPermit)
	newCfg.Security.Zones = map[string]*config.ZoneConfig{
		"lan2": {Name: "lan2"}, "other": {Name: "other"}, "wan2": {Name: "wan2"},
	}
	for _, pair := range newCfg.Security.Policies {
		if pair.FromZone == "lan" {
			pair.FromZone = "lan2"
		}
		if pair.ToZone == "wan" {
			pair.ToZone = "wan2"
		}
	}
	newCfg.Security.GlobalPolicies = []*config.Policy{{
		Name: "g", Action: config.PolicyPermit,
		Match: config.PolicyMatch{FromZones: []string{"lan2", "wan2"}, ToZones: []string{"lan2", "wan2"}},
	}}
	descriptors := []configstore.RenameDescriptor{
		policyZoneDescriptor("lan", "lan2"), policyZoneDescriptor("wan", "wan2"),
	}
	bindings, wire, ok := expandPolicyRenameAncestry(oldCfg, newCfg, descriptors)
	if !ok {
		t.Fatal("simultaneous zone renames rejected")
	}
	if len(wire) != 6 {
		t.Fatalf("want two zone-pair and four scoped-global ancestry rows, got %d: %+v", len(wire), wire)
	}
	foundPair := false
	globalPairs := make(map[[4]string]bool)
	for _, row := range wire {
		switch row.SourceRuleID {
		case "lan->wan/p":
			foundPair = row.DestinationFromZone == "lan2" && row.DestinationToZone == "wan2"
		case "junos-global->junos-global/g":
			globalPairs[[4]string{
				row.SourceFromZone, row.SourceToZone,
				row.DestinationFromZone, row.DestinationToZone,
			}] = true
		}
	}
	wantGlobalPairs := [][4]string{
		{"lan", "lan", "lan2", "lan2"},
		{"lan", "wan", "lan2", "wan2"},
		{"wan", "lan", "wan2", "lan2"},
		{"wan", "wan", "wan2", "wan2"},
	}
	for _, pair := range wantGlobalPairs {
		if !globalPairs[pair] {
			t.Errorf("missing scoped-global ancestry %q->%q => %q->%q: %+v",
				pair[0], pair[1], pair[2], pair[3], wire)
		}
	}
	if !foundPair || len(globalPairs) != 4 {
		t.Fatalf("missing composed ancestry (zonePair=%v globalRows=%d): %+v",
			foundPair, len(globalPairs), wire)
	}
	if len(bindings) != 2 {
		t.Fatalf("want two nonzero zone-pair bindings; got %d", len(bindings))
	}
	if _, ok := bindings[dpuserspace.PolicyIDsByStableKey(oldCfg)["lan->wan/p"]]; !ok {
		t.Fatal("missing zone-pair binding")
	}
}

func TestExpandGlobalPolicyRenameRejectsNarrowedZoneScope13175(t *testing.T) {
	build := func(name string, fromZones []string) *config.Config {
		cfg := &config.Config{}
		cfg.Security.Zones = map[string]*config.ZoneConfig{
			"lan": {Name: "lan"}, "wan": {Name: "wan"},
		}
		cfg.Security.DefaultPolicy = config.PolicyDeny
		cfg.Security.PolicyRematchExtensive = true
		cfg.Security.GlobalPolicies = []*config.Policy{{
			Name: name, Action: config.PolicyPermit,
			Match: config.PolicyMatch{FromZones: fromZones},
		}}
		return cfg
	}
	desc := configstore.RenameDescriptor{
		SourcePath:      []string{"global", "policy", "gp1"},
		DestinationPath: []string{"global", "policy", "gp2"},
	}
	_, _, ok := expandPolicyRenameAncestry(
		build("gp1", []string{"lan", "wan"}),
		build("gp2", []string{"lan"}),
		[]configstore.RenameDescriptor{desc},
	)
	if ok {
		t.Fatal("global policy rename accepted narrowed from-zone scope")
	}
}

func TestExpandGlobalPolicyRenamePreservesMappedZoneScope13175(t *testing.T) {
	oldCfg := &config.Config{}
	oldCfg.Security.Zones = map[string]*config.ZoneConfig{
		"lan": {Name: "lan"}, "wan": {Name: "wan"},
	}
	oldCfg.Security.DefaultPolicy = config.PolicyDeny
	oldCfg.Security.PolicyRematchExtensive = true
	oldCfg.Security.GlobalPolicies = []*config.Policy{{
		Name: "gp1", Action: config.PolicyPermit,
		Match: config.PolicyMatch{FromZones: []string{"lan", "wan"}},
	}}
	newCfg := &config.Config{}
	newCfg.Security.Zones = map[string]*config.ZoneConfig{
		"lan2": {Name: "lan2"}, "wan": {Name: "wan"},
	}
	newCfg.Security.DefaultPolicy = config.PolicyDeny
	newCfg.Security.PolicyRematchExtensive = true
	newCfg.Security.GlobalPolicies = []*config.Policy{{
		Name: "gp2", Action: config.PolicyPermit,
		Match: config.PolicyMatch{FromZones: []string{"lan2", "wan"}},
	}}
	desc := configstore.RenameDescriptor{
		SourcePath:      []string{"global", "policy", "gp1"},
		DestinationPath: []string{"global", "policy", "gp2"},
	}
	zoneDesc := policyZoneDescriptor("lan", "lan2")
	_, wire, ok := expandPolicyRenameAncestry(oldCfg, newCfg, []configstore.RenameDescriptor{desc, zoneDesc})
	if !ok {
		t.Fatal("global policy rename with correctly mapped zone scope was rejected")
	}
	for _, row := range wire {
		if row.SourceRuleID == "junos-global->junos-global/gp1" {
			if row.DestinationRuleID != "junos-global->junos-global/gp2" {
				t.Fatalf("wrong global policy destination: %+v", row)
			}
			return
		}
	}
	t.Fatalf("no global policy rename ancestry: %+v", wire)
}
