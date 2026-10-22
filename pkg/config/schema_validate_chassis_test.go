package config_test

// #1319 PR 2 — per-leaf validation matrix for the chassis-cluster typed
// leaves. Each annotated leaf is exercised table-driven through the
// SchemaValidate gate with in-range, boundary (min/max and one past each),
// and garbage values, using the flat-set shape (the primary `set ...`
// symptom-2 path). Hierarchical-shape coverage, the deployed-config
// regression, and the documented packed-one-liner exception follow below.
//
// Ranges under test are source-cited in pkg/config/schema.go next to each
// leaf annotation.

import (
	"fmt"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// chassisLeafCase describes one typed leaf: a flat-set command template
// with a %s value slot, the leaf keyword expected in rejection errors,
// plus accepted / rejected values.
type chassisLeafCase struct {
	name     string
	template string
	leaf     string
	accept   []string
	reject   []string
}

var chassisLeafMatrix = []chassisLeafCase{
	{
		name:     "cluster-id",
		leaf:     "cluster-id",
		template: "set chassis cluster cluster-id %s",
		accept:   []string{"0", "1", "22", "255"},
		reject:   []string{"-1", "256", "asd", ""},
	},
	{
		name:     "node",
		leaf:     "node",
		template: "set chassis cluster node %s",
		accept:   []string{"0", "1"},
		reject:   []string{"-1", "2", "asd", ""},
	},
	{
		name:     "reth-count",
		leaf:     "reth-count",
		template: "set chassis cluster reth-count %s",
		accept:   []string{"1", "2", "128"},
		reject:   []string{"0", "129", "asd", ""},
	},
	{
		// Runtime accepts any >0 ms; ceiling is the Duration-conversion
		// overflow point (config.MaxDurationMillis = 9223372036854).
		name:     "heartbeat-interval",
		leaf:     "heartbeat-interval",
		template: "set chassis cluster heartbeat-interval %s",
		accept:   []string{"1", "100", "200", "1000", "10000", "99999", "9223372036854"},
		reject:   []string{"0", "-1", "9223372036855", "200ms", "asd", ""},
	},
	{
		// Min-only: runtime honors any count >0 (no wire encoding).
		name:     "heartbeat-threshold",
		leaf:     "heartbeat-threshold",
		template: "set chassis cluster heartbeat-threshold %s",
		accept:   []string{"1", "3", "5", "8", "255", "256", "100000"},
		reject:   []string{"0", "-1", "asd", ""},
	},
	{
		// 40959 is the last ms value encoding to the 12-bit max 4095 cs;
		// 40960 is the first that aliases to 0 (Codex HIGH-2, PR #1845).
		name:     "reth-advertise-interval",
		leaf:     "reth-advertise-interval",
		template: "set chassis cluster reth-advertise-interval %s",
		accept:   []string{"10", "30", "100", "40950", "40951", "40959"},
		reject:   []string{"0", "9", "40960", "asd", ""},
	},
	{
		// Runtime accepts any positive duration; ceiling is the
		// Duration-conversion overflow point.
		name:     "takeover-hold-time",
		leaf:     "takeover-hold-time",
		template: "set chassis cluster takeover-hold-time %s",
		accept:   []string{"0", "5000", "3600000", "3600001", "9223372036854"},
		reject:   []string{"-1", "9223372036855", "asd", ""},
	},
	{
		name:     "peer-fencing",
		leaf:     "peer-fencing",
		template: "set chassis cluster peer-fencing %s",
		// #7147 added disable-rg-confirmed. It MUST be in accept: without a
		// row here the schema could reject the value the runtime branches on
		// and the whole policy would be uncommittable, while every test that
		// uses the Go constant directly stayed green.
		accept: []string{"disable-rg", "disable-rg-confirmed"},
		// The near-misses are deliberate: "disable-rg-confirm" and
		// "disable-rg confirmed" are the two spellings an operator actually
		// types, and a validator loosened to a prefix or substring match would
		// accept both while still passing every accept row above.
		reject: []string{"disable", "DISABLE-RG", "fence", "disable-rg-confirm",
			"disable-rg-confirmedx", "confirmed", ""},
	},
	{
		name:     "redundancy-group node priority",
		leaf:     "priority",
		template: "set chassis cluster redundancy-group 1 node 0 priority %s",
		accept:   []string{"1", "100", "200", "254"},
		reject:   []string{"0", "255", "-5", "asd", ""},
	},
	{
		// Min-only: the runtime uses any configured count >0 verbatim as
		// the burst length (Junos caps at 16; xpf does not).
		name:     "gratuitous-arp-count",
		leaf:     "gratuitous-arp-count",
		template: "set chassis cluster redundancy-group 1 gratuitous-arp-count %s",
		accept:   []string{"1", "3", "8", "16", "17", "1000"},
		reject:   []string{"0", "-1", "asd", ""},
	},
	{
		name:     "ip-monitoring global-weight",
		leaf:     "global-weight",
		template: "set chassis cluster redundancy-group 1 ip-monitoring global-weight %s",
		accept:   []string{"0", "100", "255"},
		reject:   []string{"-1", "256", "asd", ""},
	},
	{
		name:     "ip-monitoring global-threshold",
		leaf:     "global-threshold",
		template: "set chassis cluster redundancy-group 1 ip-monitoring global-threshold %s",
		accept:   []string{"0", "100", "255"},
		reject:   []string{"-1", "256", "asd", ""},
	},
	{
		name:     "ip-monitoring target weight",
		leaf:     "weight",
		template: "set chassis cluster redundancy-group 1 ip-monitoring family inet 10.0.61.254 weight %s",
		accept:   []string{"0", "100", "255"},
		reject:   []string{"-1", "256", "asd", ""},
	},
}

func TestSchemaValidate_ChassisCluster_Matrix(t *testing.T) {
	for _, tc := range chassisLeafMatrix {
		t.Run(tc.name, func(t *testing.T) {
			for _, v := range tc.accept {
				cmd := strings.TrimSpace(fmt.Sprintf(tc.template, v))
				if err := flatSchemaCheck(t, cmd); err != nil {
					t.Errorf("accept %q: unexpected error: %v", cmd, err)
				}
			}
			for _, v := range tc.reject {
				cmd := strings.TrimSpace(fmt.Sprintf(tc.template, v))
				err := flatSchemaCheck(t, cmd)
				if err == nil {
					t.Errorf("reject %q: expected error, got nil", cmd)
					continue
				}
				// The error must carry the leaf keyword so the operator
				// can find the offending statement.
				if !strings.Contains(err.Error(), tc.leaf) {
					t.Errorf("reject %q: error should reference %q: %v", cmd, tc.leaf, err)
				}
			}
		})
	}
}

// The canonical deployed cluster config shape (docs/ha-cluster-userspace.conf)
// must keep validating — hierarchical blocks, the packed `node 0 priority
// 200;` one-liner shape included. This is the regression guard for the
// killed Phase-3a mistake (blind Junos ranges would have rejected
// heartbeat-interval 200).
func TestSchemaValidate_ChassisCluster_DeployedConfigShapeAccepted(t *testing.T) {
	if err := schemaCheck(t, `chassis {
    cluster {
        authentication-key test-cluster-psk-6611;
        cluster-id 22;
        reth-count 2;
        heartbeat-interval 200;
        heartbeat-threshold 5;
        redundancy-group 1 {
            node 0 priority 200;
            node 1 priority 100;
            gratuitous-arp-count 8;
        }
    }
}`); err != nil {
		t.Fatalf("deployed-shape chassis config must validate: %v", err)
	}
}

// Hierarchical nested shape is validated like flat-set.
func TestSchemaValidate_ChassisCluster_HierarchicalRejectsOutOfRange(t *testing.T) {
	err := schemaCheck(t, `chassis {
    cluster {
        authentication-key test-cluster-psk-6611;
        redundancy-group 1 {
            node 0 {
                priority 300;
            }
        }
    }
}`)
	if err == nil {
		t.Fatal("expected error for nested priority 300, got nil")
	}
	if !strings.Contains(err.Error(), "priority") {
		t.Fatalf("error should reference priority: %v", err)
	}
}

func TestSchemaValidate_ChassisCluster_HierarchicalRejectsGarbageInterval(t *testing.T) {
	err := schemaCheck(t, `chassis {
    cluster {
        authentication-key test-cluster-psk-6611;
        heartbeat-interval fast;
    }
}`)
	if err == nil {
		t.Fatal("expected error for heartbeat-interval fast, got nil")
	}
	if !strings.Contains(err.Error(), "heartbeat-interval") || !strings.Contains(err.Error(), "fast") {
		t.Fatalf("error should cite leaf and value: %v", err)
	}
}

// #4880: the hierarchical packed one-liner `node 0 priority <v>;` carries the
// priority INSIDE the instance node's own Keys. The walker's compiler-faithful
// rule consumes only the identity tokens of a named-instance container and
// ignores the rest, so this shape still slips past the typed-leaf schema gate
// (SchemaValidate) — that walker limitation is unchanged. But compileChassis
// reads the inline priority into NodePriorities, and it flows to VRRP
// (uint8-truncated on the wire) and the private control-link election (raw
// int), so an out-of-range value both truncates and diverges the two election
// views. A post-compile range gate (validateChassisClusterStrict) now rejects
// it at commit, matching the flat-set / expanded shape which the schema leaf
// already gates. This was previously a contract-pin ACCEPTANCE test; it is now
// a rejection test at the compile layer.
func TestCompile_ChassisCluster_PackedOneLinerPriorityRejected(t *testing.T) {
	packed := `chassis {
    cluster {
        authentication-key test-cluster-psk-6611;
        redundancy-group 1 {
            node 0 priority 999;
        }
    }
}`
	// The walker still does not catch the packed shape — SchemaValidate passes.
	if err := schemaCheck(t, packed); err != nil {
		t.Fatalf("SchemaValidate is expected to still pass the packed shape "+
			"(unchanged walker limitation); got: %v", err)
	}
	// The post-compile gate rejects it.
	tree, errs := config.NewParser(packed).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	if _, err := config.CompileConfig(tree); err == nil {
		t.Fatal("packed one-liner priority 999 must be rejected at compile")
	} else if !strings.Contains(err.Error(), "priority") || !strings.Contains(err.Error(), "999") {
		t.Fatalf("compile error should name the out-of-range priority: %v", err)
	}

	// A valid packed priority compiles clean (no over-eager rejection).
	okTree, errs := config.NewParser(`chassis {
    cluster {
        authentication-key test-cluster-psk-6611;
        redundancy-group 1 {
            node 0 priority 200;
        }
    }
}`).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	if _, err := config.CompileConfig(okTree); err != nil {
		t.Fatalf("valid packed priority 200 must compile: %v", err)
	}
}

// TestCompile_ChassisCluster_PriorityGateClosesBothShapes asserts the #4880
// post-compile priority gate is SHAPE-AGNOSTIC: it catches the flat-set /
// expanded shape (priority in its own child node, built via ParseSetCommand +
// SetPath) at the same compile layer, so the packed and expanded shapes can no
// longer disagree. (The schema leaf also rejects the expanded shape earlier at
// SchemaValidate; this pins the compile backstop directly.)
func TestCompile_ChassisCluster_PriorityGateClosesBothShapes(t *testing.T) {
	badTree := &config.ConfigTree{}
	path, err := config.ParseSetCommand("set chassis cluster redundancy-group 1 node 0 priority 999")
	if err != nil {
		t.Fatalf("ParseSetCommand: %v", err)
	}
	if err := badTree.SetPath(path); err != nil {
		t.Fatalf("SetPath: %v", err)
	}
	if _, err := config.CompileConfig(badTree); err == nil {
		t.Fatal("flat-set expanded priority 999 must be rejected at the compile gate")
	} else if !strings.Contains(err.Error(), "priority") || !strings.Contains(err.Error(), "999") {
		t.Fatalf("compile error should name the out-of-range priority: %v", err)
	}

	okTree := &config.ConfigTree{}
	for _, cmd := range []string{
		"set chassis cluster authentication-key test-cluster-psk-6611",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
	} {
		okPath, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := okTree.SetPath(okPath); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	if _, err := config.CompileConfig(okTree); err != nil {
		t.Fatalf("valid flat-set priority 200 must compile: %v", err)
	}
}

// In-range chassis values must round-trip through the real compiler with
// the values the operator wrote (no silent coercion).
func TestSchemaValidate_ChassisCluster_AcceptedValuesCompileAsWritten(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, cmd := range []string{
		"set chassis cluster cluster-id 22",
		"set chassis cluster authentication-key test-cluster-psk-6611",
		"set chassis cluster heartbeat-interval 200",
		"set chassis cluster heartbeat-threshold 5",
		"set chassis cluster reth-advertise-interval 30",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
	} {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	if err := config.SchemaValidate(tree); err != nil {
		t.Fatalf("SchemaValidate: %v", err)
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	cc := cfg.Chassis.Cluster
	if cc == nil {
		t.Fatal("Chassis.Cluster is nil")
	}
	if cc.ClusterID != 22 || cc.HeartbeatInterval != 200 ||
		cc.HeartbeatThreshold != 5 || cc.RethAdvertiseInterval != 30 {
		t.Fatalf("compiled values diverge from validated input: %+v", cc)
	}
	if len(cc.RedundancyGroups) != 1 || cc.RedundancyGroups[0].NodePriorities[0] != 200 {
		t.Fatalf("compiled RG priorities diverge: %+v", cc.RedundancyGroups)
	}
}

// Unit coverage for the min-only validator introduced for the
// no-upper-bound leaves (Codex review, PR #1845).
func TestValidateIntegerMin(t *testing.T) {
	v := config.ValidateIntegerMin(1)
	for _, ok := range []string{"1", "17", "1000", "9223372036854775807"} {
		if err := v(ok); err != nil {
			t.Errorf("ValidateIntegerMin(1)(%q): unexpected error: %v", ok, err)
		}
	}
	for _, bad := range []string{"0", "-1", "asd", "", "9223372036854775808"} {
		if err := v(bad); err == nil {
			t.Errorf("ValidateIntegerMin(1)(%q): expected error, got nil", bad)
		}
	}
}
