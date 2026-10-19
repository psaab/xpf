package config

import (
	"strings"
	"testing"
)

// #15256 cohort: A85-01 screen Junos spellings, A85-04 port-mirroring
// silent acceptance, A85-02 trap-group categories, A85-03 docs (docs
// asserted by inspection in docs/log/15256.md, not here).
//
// FAIL-ON-REVERT: removing the icmp ip-sweep / tcp tcp-no-flag arms
// makes the Junos spellings strict-reject again; removing the
// port-mirroring shape gate / closedWorld makes every probe case
// commit clean; removing the category validator makes `linkk` commit
// clean and the zero-trap advisory disappear.

func strict15256(t *testing.T, tree *ConfigTree) (*Config, error) {
	t.Helper()
	if err := SchemaValidate(tree, nil); err != nil {
		return nil, err
	}
	return CompileConfig(tree)
}

func TestScreen15256_JunosSpellingsAccepted(t *testing.T) {
	cases := []struct {
		name  string
		lines []string
		check func(*ScreenProfile) bool
		what  string
	}{
		{"icmp ip-sweep", []string{"set security screen ids-option s1 icmp ip-sweep threshold 5000"}, func(p *ScreenProfile) bool { return p.IP.IPSweepThreshold == 5000 }, "IPSweepThreshold=5000"},
		{"icmp ip-sweep default", []string{"set security screen ids-option s1 icmp ip-sweep"}, func(p *ScreenProfile) bool { return p.IP.IPSweepThreshold > 0 }, "IPSweepThreshold>0"},
		{"tcp tcp-no-flag", []string{"set security screen ids-option s1 tcp tcp-no-flag"}, func(p *ScreenProfile) bool { return p.TCP.NoFlag }, "NoFlag=true"},
		// Controls: legacy spellings keep working.
		{"ip ip-sweep control", []string{"set security screen ids-option s1 ip ip-sweep threshold 5000"}, func(p *ScreenProfile) bool { return p.IP.IPSweepThreshold == 5000 }, "IPSweepThreshold=5000"},
		{"tcp no-flag control", []string{"set security screen ids-option s1 tcp no-flag"}, func(p *ScreenProfile) bool { return p.TCP.NoFlag }, "NoFlag=true"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := strict15256(t, buildTree(t, tc.lines))
			if err != nil {
				t.Fatalf("strict commit rejected Junos spelling: %v", err)
			}
			p := cfg.Security.Screen["s1"]
			if p == nil || !tc.check(p) {
				t.Fatalf("profile = %+v, want %s", p, tc.what)
			}
		})
	}
	// Hierarchical spelling.
	tree, perrs := NewParser("security { screen { ids-option s1 { icmp { ip-sweep { threshold 5000; } } tcp { tcp-no-flag; } } } }").Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err := strict15256(t, tree)
	if err != nil {
		t.Fatalf("hier Junos spellings rejected: %v", err)
	}
	if cfg.Security.Screen["s1"].IP.IPSweepThreshold != 5000 || !cfg.Security.Screen["s1"].TCP.NoFlag {
		t.Fatalf("hier profile = %+v, want sweep 5000 + NoFlag", cfg.Security.Screen["s1"])
	}
}

func TestScreen15256_UnknownStillRejected(t *testing.T) {
	_, err := strict15256(t, buildTree(t, []string{"set security screen ids-option s1 icmp pong-death"}))
	if err == nil || !strings.Contains(err.Error(), "pong-death") {
		t.Fatalf("err = %v, want pong-death rejection", err)
	}
}

func TestPortMirroring15256_ProbeCasesRefusedOrWarn(t *testing.T) {
	valid := []string{
		"set forwarding-options port-mirroring instance pm1 input ingress interface ge-0/0/0.0",
		"set forwarding-options port-mirroring instance pm1 output interface ge-0/0/1.0",
	}
	// Control stays green strict with no warnings.
	cfg, err := strict15256(t, buildTree(t, valid))
	if err != nil {
		t.Fatalf("control rejected: %v", err)
	}
	if inst := cfg.ForwardingOptions.PortMirroring.Instances["pm1"]; inst == nil || len(inst.Input) != 1 || inst.Output != "ge-0/0/1.0" {
		t.Fatalf("control instance = %+v", inst)
	}
	probes := []struct{ name, extra, want string }{
		{"unknown instance child", "set forwarding-options port-mirroring instance pm1 bogus-stmt foo", "bogus-stmt"},
		{"family", "set forwarding-options port-mirroring instance pm1 family inet", "family"},
		{"egress", "set forwarding-options port-mirroring instance pm1 input egress interface ge-0/0/2.0", "egress"},
		{"zero ingress", "", "no ingress"},
		{"global form", "set forwarding-options port-mirroring input ingress interface ge-0/0/0.0", "input"},
	}
	for _, tc := range probes {
		t.Run(tc.name, func(t *testing.T) {
			lines := valid
			if tc.name == "zero ingress" {
				lines = []string{"set forwarding-options port-mirroring instance pm1 output interface ge-0/0/1.0"}
			} else if tc.name == "global form" {
				lines = []string{tc.extra}
			} else {
				lines = append(append([]string{}, valid...), tc.extra)
			}
			_, err := strict15256(t, buildTree(t, lines))
			if err == nil {
				t.Fatalf("probe %q committed clean strict, want refusal", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("probe %q err = %v, want mention of %q", tc.name, err, tc.want)
			}
			// Lenient warns and boots.
			cfg, err := CompileConfigLenient(buildTree(t, lines))
			if err != nil {
				t.Fatalf("probe %q lenient must boot: %v", tc.name, err)
			}
			found := false
			for _, w := range cfg.Warnings {
				if strings.Contains(w, tc.want) || strings.Contains(w, "port-mirroring") {
					found = true
				}
			}
			if tc.name == "global form" {
				// closedWorld rejects at SchemaValidate only; lenient
				// CompileConfig has no schema gate — at minimum the
				// instance-less form must not silently succeed strict.
				return
			}
			if !found {
				t.Fatalf("probe %q lenient warnings = %v, want port-mirroring warning", tc.name, cfg.Warnings)
			}
		})
	}
}

func TestTrapGroup15256_Categories(t *testing.T) {
	// Typo rejected strict (both SchemaValidate enum and compiler gate).
	_, err := strict15256(t, buildTree(t, []string{
		"set snmp trap-group g1 targets 10.0.0.1",
		"set snmp trap-group g1 categories linkk",
	}))
	if err == nil || !strings.Contains(err.Error(), "linkk") {
		t.Fatalf("linkk err = %v, want rejection naming linkk", err)
	}
	if _, err := CompileConfig(buildTree(t, []string{
		"set snmp trap-group g1 targets 10.0.0.1",
		"set snmp trap-group g1 categories linkk",
	})); err == nil {
		t.Fatal("CompileConfig alone accepted linkk")
	}
	// Valid-but-unemitted commits with advisory.
	cfg, err := strict15256(t, buildTree(t, []string{
		"set snmp trap-group g1 targets 10.0.0.1",
		"set snmp trap-group g1 categories authentication",
	}))
	if err != nil {
		t.Fatalf("authentication rejected: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "will receive no traps") {
			found = true
		}
	}
	if !found {
		t.Fatalf("warnings = %v, want zero-trap advisory", cfg.Warnings)
	}
	// Control: link commits without the advisory.
	cfg, err = strict15256(t, buildTree(t, []string{
		"set snmp trap-group g1 targets 10.0.0.1",
		"set snmp trap-group g1 categories link",
	}))
	if err != nil {
		t.Fatalf("link control rejected: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "will receive no traps") {
			t.Fatalf("link control got zero-trap advisory: %v", cfg.Warnings)
		}
	}
}
