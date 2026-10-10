package dataplane

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func sourceNATTree12525(t *testing.T, action string, scopeCommands ...string) *config.ConfigTree {
	t.Helper()
	commands := []string{
		"set security nat source pool pool1 address 192.0.2.10",
	}
	commands = append(commands, scopeCommands...)
	commands = append(commands,
		"set security nat source rule-set RS rule r1 "+action)

	tree := &config.ConfigTree{}
	for _, command := range commands {
		path, err := config.ParseSetCommand(command)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", command, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", command, err)
		}
	}
	return tree
}

func sourceNATConfig12525(t *testing.T, action string, scopeCommands ...string) *config.Config {
	t.Helper()
	cfg, err := config.CompileConfig(sourceNATTree12525(t, action, scopeCommands...))
	if err != nil {
		t.Fatalf("config.CompileConfig: %v", err)
	}
	return cfg
}

func validateSourceNAT12525(cfg *config.Config) (*CompileResult, error) {
	result := newValidationResult()
	return result, validateBeforeMutateWithResult(discardingDataPlane{}, cfg, result)
}

func TestCompileNATNonZoneSourceNATScopes12525(t *testing.T) {
	cases := []struct {
		name   string
		scopes []string
	}{
		{
			name: "to-interface",
			scopes: []string{
				"set security zones security-zone trust",
				"set security nat source rule-set RS from zone trust",
				"set security nat source rule-set RS to interface ge-0/0/1.0",
			},
		},
		{
			name: "to-routing-instance",
			scopes: []string{
				"set security zones security-zone trust",
				"set security nat source rule-set RS from zone trust",
				"set security nat source rule-set RS to routing-instance VR1",
			},
		},
		{
			name: "unscoped-to-side",
			scopes: []string{
				"set security zones security-zone trust",
				"set security nat source rule-set RS from zone trust",
			},
		},
		{
			name: "from-interface",
			scopes: []string{
				"set security zones security-zone untrust",
				"set security nat source rule-set RS from interface ge-0/0/0.0",
				"set security nat source rule-set RS to zone untrust",
			},
		},
		{
			name: "from-routing-instance",
			scopes: []string{
				"set security zones security-zone untrust",
				"set security nat source rule-set RS from routing-instance VR1",
				"set security nat source rule-set RS to zone untrust",
			},
		},
		{
			name: "ordinary-zoned",
			scopes: []string{
				"set security zones security-zone trust",
				"set security zones security-zone untrust",
				"set security nat source rule-set RS from zone trust",
				"set security nat source rule-set RS to zone untrust",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := sourceNATConfig12525(t, "then source-nat pool pool1", tc.scopes...)
			result, err := validateSourceNAT12525(cfg)
			if err != nil {
				t.Fatalf("compileNAT rejected valid %s source-NAT scope: %v", tc.name, err)
			}
			if poolID, ok := result.PoolIDs["pool1"]; !ok || poolID != 0 {
				t.Fatalf("pool1 ID = %d (present=%t), want present ID 0 after source-NAT compile", poolID, ok)
			}
		})
	}
}

func TestCompileNATRejectsZoneLessScopelessSourceNAT12525(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.NAT.Source = []*config.NATRuleSet{{
		Name: "empty",
		Rules: []*config.NATRule{{
			Name: "r1",
			Then: config.NATThen{PoolName: "pool1"},
		}},
	}}
	_, err := validateSourceNAT12525(cfg)
	if err == nil || !strings.Contains(err.Error(), `source NAT from-zone "" not found`) {
		t.Fatalf("zero-value source-NAT rule-set error = %v, want fail-closed empty from-zone rejection", err)
	}
}

func TestCompileNATRetainsNamedZoneValidation12525(t *testing.T) {
	for _, tc := range []struct {
		name, fromZone, toZone, want string
	}{
		{"from-zone", "missing", "untrust", `source NAT from-zone "missing" not found`},
		{"to-zone", "trust", "missing", `source NAT to-zone "missing" not found`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Security.Zones = map[string]*config.ZoneConfig{
				"trust":   {},
				"untrust": {},
			}
			cfg.Security.NAT.Source = []*config.NATRuleSet{{
				Name:     "unknown",
				FromZone: tc.fromZone,
				ToZone:   tc.toZone,
			}}
			_, err := validateSourceNAT12525(cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("unknown named-zone error = %v, want %s", err, tc.want)
			}
		})
	}
}

func TestCompileNAT12085ScopeRows12525(t *testing.T) {
	// These self-contained rows cover #12085's to-interface,
	// to-routing-instance, and unscoped source-NAT forms. Config compilation
	// is exercised here so the empty unscoped row receives only
	// compiler-owned provenance.
	cases := []struct {
		name   string
		scopes []string
	}{
		{
			name: "to-interface",
			scopes: []string{
				"set security nat source rule-set RS to interface ge-0/0/1.0",
			},
		},
		{
			name: "to-routing-instance",
			scopes: []string{
				"set security nat source rule-set RS to routing-instance VR1",
			},
		},
		{name: "unscoped"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := sourceNATConfig12525(t, "then source-nat interface", tc.scopes...)
			rs := cfg.Security.NAT.Source[0]
			if rs.FromZone != "" || rs.ToZone != "" {
				t.Fatalf("non-zone matrix row carried a zone scope: %+v", rs)
			}
			if !rs.HasNATFromScopeStamp() || !rs.HasNATToScopeStamp() {
				t.Fatalf("config compiler did not retain per-side scope provenance: %+v", rs)
			}
			if tc.name == "unscoped" && (rs.FromInterface != "" || rs.ToInterface != "" ||
				rs.FromRoutingInstance != "" || rs.ToRoutingInstance != "") {
				t.Fatalf("fixture's unscoped row did not remain all-empty: %+v", rs)
			}
			if _, err := validateSourceNAT12525(cfg); err != nil {
				t.Fatalf("compileNAT rejected #12085 %s scope row: %v", tc.name, err)
			}
		})
	}
}

func TestCompileNAT12085UnscopedScopeSurvivesLenientCompile12525(t *testing.T) {
	// Store.SyncApply recompiles peer-synced source text through the lenient
	// compiler; that compiler must create the same private unscoped stamp.
	tree := sourceNATTree12525(t, "then source-nat interface")
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("config.CompileConfigLenient: %v", err)
	}
	rs := cfg.Security.NAT.Source[0]
	if rs.FromZone != "" || rs.ToZone != "" || rs.FromInterface != "" ||
		rs.ToInterface != "" || rs.FromRoutingInstance != "" ||
		rs.ToRoutingInstance != "" || !rs.HasNATFromScopeStamp() ||
		!rs.HasNATToScopeStamp() {
		t.Fatalf("lenient compiler did not retain per-side provenance for all-empty unscoped row: %+v", rs)
	}
	if _, err := validateSourceNAT12525(cfg); err != nil {
		t.Fatalf("compileNAT rejected peer-sync compiled unscoped row: %v", err)
	}
}

func TestCompileNATFailsClosedWhenUnscopedStampIsLost12525(t *testing.T) {
	cfg := sourceNATConfig12525(t, "then source-nat interface")
	if !cfg.Security.NAT.Source[0].HasNATFromScopeStamp() ||
		!cfg.Security.NAT.Source[0].HasNATToScopeStamp() {
		t.Fatal("config compiler did not stamp both absent sides of the all-empty unscoped rule-set")
	}

	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal compiled config: %v", err)
	}
	var roundTripped config.Config
	if err := json.Unmarshal(encoded, &roundTripped); err != nil {
		t.Fatalf("unmarshal compiled config: %v", err)
	}
	if roundTripped.Security.NAT.Source[0].HasNATFromScopeStamp() ||
		roundTripped.Security.NAT.Source[0].HasNATToScopeStamp() {
		t.Fatal("unscoped compiler provenance unexpectedly survived JSON serialization")
	}
	_, err = validateSourceNAT12525(&roundTripped)
	if err == nil || !strings.Contains(err.Error(), `source NAT from-zone "" not found`) {
		t.Fatalf("missing-provenance error = %v, want fail-closed empty from-zone rejection", err)
	}
}
func TestCompileNATRejectsPresentEmptyScopes12525(t *testing.T) {
	cases := []struct {
		name       string
		scopes     []string
		deactivate string
	}{
		{name: "to-zone-empty", scopes: []string{`set security nat source rule-set RS to zone ""`}},
		{name: "both-zones-empty", scopes: []string{`set security nat source rule-set RS from zone ""`, `set security nat source rule-set RS to zone ""`}},
		{name: "deactivated-to-leaf", scopes: []string{"set security nat source rule-set RS from zone trust", "set security nat source rule-set RS to zone untrust"}, deactivate: "set security nat source rule-set RS to zone untrust"},
		{name: "to-interface-empty", scopes: []string{"set security nat source rule-set RS from zone trust", `set security nat source rule-set RS to interface ""`}},
		{name: "to-routing-instance-empty", scopes: []string{"set security nat source rule-set RS from zone trust", `set security nat source rule-set RS to routing-instance ""`}},
		{name: "from-interface-empty", scopes: []string{`set security nat source rule-set RS from interface ""`, "set security nat source rule-set RS to zone untrust"}},
		{name: "lenient-to-zone-bracket-empty", scopes: []string{"set security nat source rule-set RS from zone trust", "set security nat source rule-set RS to zone [ ]"}},
		{name: "one-sided-from-trust-to-empty", scopes: []string{"set security nat source rule-set RS from zone trust", `set security nat source rule-set RS to zone ""`}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := sourceNATTree12525(t, "then source-nat pool pool1", tc.scopes...)
			if tc.deactivate != "" {
				path, err := config.ParseSetCommand(tc.deactivate)
				if err != nil {
					t.Fatalf("ParseSetCommand(%q): %v", tc.deactivate, err)
				}
				if err := tree.DeactivatePath(path); err != nil {
					t.Fatalf("DeactivatePath(%q): %v", tc.deactivate, err)
				}
			}
			if _, err := config.CompileConfig(tree); err == nil ||
				!strings.Contains(err.Error(), "#7525") {
				t.Fatalf("strict compile error = %v, want #7525-style empty-scope rejection", err)
			}

			cfg, err := config.CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient CompileConfig: %v", err)
			}
			if !strings.Contains(strings.Join(cfg.Warnings, "\n"), "#7525") {
				t.Fatalf("lenient compile did not warn about the present-empty scope: %v", cfg.Warnings)
			}
			if len(cfg.Security.NAT.Source) != 0 {
				t.Fatalf("lenient compile widened the empty scope into source NAT rule-sets: %+v", cfg.Security.NAT.Source)
			}
			if _, err := validateSourceNAT12525(cfg); err != nil {
				t.Fatalf("dataplane pre-pass rejected the fail-closed lenient result: %v", err)
			}
		})
	}
}

func TestCompileNATFailsClosedWhenFromStampIsLost12525(t *testing.T) {
	cfg := sourceNATConfig12525(t, "then source-nat interface",
		"set security nat source rule-set RS to interface ge-0/0/1.0")
	rs := cfg.Security.NAT.Source[0]
	if !rs.HasNATFromScopeStamp() || !rs.HasNATToScopeStamp() {
		t.Fatalf("compiled source NAT did not carry both valid sides: %+v", rs)
	}

	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal compiled config: %v", err)
	}
	var roundTripped config.Config
	if err := json.Unmarshal(encoded, &roundTripped); err != nil {
		t.Fatalf("unmarshal compiled config: %v", err)
	}
	rs = roundTripped.Security.NAT.Source[0]
	if rs.HasNATFromScopeStamp() || !rs.HasNATToScopeStamp() {
		t.Fatalf("round-trip did not lose only the absent from-side stamp: %+v", rs)
	}
	_, err = validateSourceNAT12525(&roundTripped)
	if err == nil || !strings.Contains(err.Error(), `source NAT from-zone "" not found`) {
		t.Fatalf("lost from-stamp error = %v, want per-side fail-closed rejection", err)
	}
}

func TestCompileNATFailsClosedWhenToStampIsLost12525(t *testing.T) {
	cfg := sourceNATConfig12525(t, "then source-nat interface",
		"set security zones security-zone trust",
		"set security nat source rule-set RS from zone trust")
	rs := cfg.Security.NAT.Source[0]
	if !rs.HasNATFromScopeStamp() || !rs.HasNATToScopeStamp() {
		t.Fatalf("compiled source NAT did not carry both valid sides: %+v", rs)
	}

	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal compiled config: %v", err)
	}
	var roundTripped config.Config
	if err := json.Unmarshal(encoded, &roundTripped); err != nil {
		t.Fatalf("unmarshal compiled config: %v", err)
	}
	rs = roundTripped.Security.NAT.Source[0]
	if !rs.HasNATFromScopeStamp() || rs.HasNATToScopeStamp() {
		t.Fatalf("round-trip did not lose only the absent to-side stamp: %+v", rs)
	}
	_, err = validateSourceNAT12525(&roundTripped)
	if err == nil || !strings.Contains(err.Error(), `source NAT to-zone "" not found`) {
		t.Fatalf("lost to-stamp error = %v, want per-side fail-closed rejection", err)
	}
}
func TestCompileNATAssignsInterfaceModeCountersWithoutToZone12525(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, command := range []string{
		"set security nat source rule-set RS-iface to interface ge-0/0/1.0",
		"set security nat source rule-set RS-iface rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set RS-iface rule r1 then source-nat interface",
		"set security nat source rule-set RS-ri to routing-instance VR1",
		"set security nat source rule-set RS-ri rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set RS-ri rule r1 then source-nat interface",
		"set security nat source rule-set RS-any rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set RS-any rule r1 then source-nat interface",
	} {
		path, err := config.ParseSetCommand(command)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", command, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", command, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("config.CompileConfig: %v", err)
	}

	var logs bytes.Buffer
	oldLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(oldLogger) })

	result := newValidationResult()
	if err := compileNAT(&natWriteTripwireDP{}, cfg, result); err != nil {
		t.Fatalf("compileNAT: %v", err)
	}
	finalizeNATCounterIDs(result)
	for _, ruleSet := range []string{"RS-iface", "RS-ri", "RS-any"} {
		key := NATCounterKey(NATCounterTypeSource, ruleSet, "r1")
		if id, ok := result.NATCounterIDs[key]; !ok || id == 0 {
			t.Errorf("interface-mode rule %s/r1 counter = (%d, %t), want non-zero Translation-hits ID", ruleSet, id, ok)
		}
	}
	if strings.Contains(logs.String(), "to-zone has no interfaces") {
		t.Fatalf("non-zone egress scopes produced the misleading to-zone warning: %s", logs.String())
	}
}

func TestCompileNATRejectsPresentEmptyFromScopesForOtherKinds12525(t *testing.T) {
	cases := []struct {
		name, command, kind string
	}{
		{
			name:    "destination-from-interface",
			command: `set security nat destination rule-set RD from interface ""`,
			kind:    "destination",
		},
		{
			name:    "static-from-routing-instance",
			command: `set security nat static rule-set RS from routing-instance ""`,
			kind:    "static",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := &config.ConfigTree{}
			path, err := config.ParseSetCommand(tc.command)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", tc.command, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath(%q): %v", tc.command, err)
			}
			if _, err := config.CompileConfig(tree); err == nil ||
				!strings.Contains(err.Error(), "#7525") {
				t.Fatalf("strict compile error = %v, want #7525 empty-scope rejection", err)
			}

			cfg, err := config.CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient CompileConfig: %v", err)
			}
			if !strings.Contains(strings.Join(cfg.Warnings, "\n"), "#7525") {
				t.Fatalf("lenient compile did not warn about present-empty scope: %v", cfg.Warnings)
			}
			switch tc.kind {
			case "destination":
				if cfg.Security.NAT.Destination != nil && len(cfg.Security.NAT.Destination.RuleSets) != 0 {
					t.Fatalf("lenient compile widened destination NAT scope: %+v", cfg.Security.NAT.Destination.RuleSets)
				}
			case "static":
				if len(cfg.Security.NAT.Static) != 0 {
					t.Fatalf("lenient compile widened static NAT scope: %+v", cfg.Security.NAT.Static)
				}
			}
		})
	}
}
