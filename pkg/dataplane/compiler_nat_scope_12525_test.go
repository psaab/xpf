package dataplane

import (
	"encoding/json"
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
		if err := tree.SetPath(strings.Fields(command)[1:]); err != nil {
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
	// These rows mirror the to-interface, to-routing-instance, and unscoped
	// cases in origin/fix/12085-campaign-pub:
	// userspace-dp/tests/fixtures/nat_iface_scope_12085.json. Unlike the
	// snapshot fixture, config compilation is exercised here so the empty
	// unscoped row receives only compiler-owned provenance.
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
			if !rs.HasNATScopeStamp() {
				t.Fatalf("config compiler did not stamp scope provenance: %+v", rs)
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
		rs.ToRoutingInstance != "" || !rs.HasNATScopeStamp() {
		t.Fatalf("lenient compiler did not retain provenance for all-empty unscoped row: %+v", rs)
	}
	if _, err := validateSourceNAT12525(cfg); err != nil {
		t.Fatalf("compileNAT rejected peer-sync compiled unscoped row: %v", err)
	}
}
func TestCompileNATFailsClosedWhenUnscopedStampIsLost12525(t *testing.T) {
	cfg := sourceNATConfig12525(t, "then source-nat interface")
	if !cfg.Security.NAT.Source[0].HasNATScopeStamp() {
		t.Fatal("config compiler did not stamp the all-empty unscoped rule-set")
	}

	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal compiled config: %v", err)
	}
	var roundTripped config.Config
	if err := json.Unmarshal(encoded, &roundTripped); err != nil {
		t.Fatalf("unmarshal compiled config: %v", err)
	}
	if roundTripped.Security.NAT.Source[0].HasNATScopeStamp() {
		t.Fatal("unscoped compiler provenance unexpectedly survived JSON serialization")
	}
	_, err = validateSourceNAT12525(&roundTripped)
	if err == nil || !strings.Contains(err.Error(), `source NAT from-zone "" not found`) {
		t.Fatalf("missing-provenance error = %v, want fail-closed empty from-zone rejection", err)
	}
}
