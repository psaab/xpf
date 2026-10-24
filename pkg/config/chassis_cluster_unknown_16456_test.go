package config

import (
	"os"
	"strings"
	"testing"
)

// #16456: unknown statements at the `chassis cluster` level and in a
// `redundancy-group` body strict-reject and lenient-warn. Each typo row
// pairs the misspelt statement with correctly spelt siblings that build
// the same RG/cluster without it — on the pre-fix tree the strict
// compile succeeded with byte-identical warnings and the compiled RG
// carried no monitor / no ip-monitoring / no preempt for the typo'd
// line, so the group never failed over on it.
//
// Base lines use a >=16-char PSK so the #6611 auth-length gate does not
// fire and mask the #16456 verdict.

const clusterPSK16456 = "test-cluster-psk-16456-long"

func clusterBase16456(extra ...string) []string {
	lines := []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key " + clusterPSK16456,
		"set chassis cluster node 0",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set chassis cluster redundancy-group 1 node 1 priority 100",
		"set chassis cluster redundancy-group 1 interface-monitor ge-0/0/1 weight 255",
		"set chassis cluster redundancy-group 1 interface-monitor ge-7/0/1 weight 255",
	}
	return append(lines, extra...)
}

func assertReject16456(t *testing.T, tree *ConfigTree, wantTok string) {
	t.Helper()
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("strict compile accepted unknown statement %q (#16456)", wantTok)
	}
	if !strings.Contains(err.Error(), "#16456") || !strings.Contains(err.Error(), wantTok) {
		t.Fatalf("strict error = %q, want #16456 naming %q", err, wantTok)
	}
}

func assertLenientWarns16456(t *testing.T, tree *ConfigTree, wantTok string) *Config {
	t.Helper()
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must boot (#1960): %v", err)
	}
	warnings := strings.Join(cfg.Warnings, "\n")
	if !strings.Contains(warnings, "#16456") || !strings.Contains(warnings, wantTok) {
		t.Fatalf("lenient warnings = %q, want #16456 naming %q", warnings, wantTok)
	}
	return cfg
}

func flat16456(lines ...string) func(*testing.T) *ConfigTree {
	return func(t *testing.T) *ConfigTree { return buildTree(t, lines) }
}

func hier16456(src string) func(*testing.T) *ConfigTree {
	return func(t *testing.T) *ConfigTree { return hierTree(t, src) }
}

const hierBase16456 = `chassis {
    cluster {
        cluster-id 1;
        authentication-key test-cluster-psk-16456-long;
        node 0;
        redundancy-group 1 {
            node 0 priority 200;
            node 1 priority 100;
            interface-monitor {
                ge-0/0/1 weight 255;
                ge-7/0/1 weight 255;
            }
        }
    }
}`

func TestChassisClusterUnknownStatements16456(t *testing.T) {
	rows := []struct {
		name  string
		build func(*testing.T) *ConfigTree
		tok   string
	}{
		// RG level: the acceptance spellings (flat-set shape).
		{"flat interface-monitr", flat16456(clusterBase16456(
			"set chassis cluster redundancy-group 1 interface-monitr ge-0/0/2 weight 255")...), "interface-monitr"},
		{"flat interface-monitors", flat16456(clusterBase16456(
			"set chassis cluster redundancy-group 1 interface-monitors ge-0/0/2 weight 255")...), "interface-monitors"},
		{"flat interface-montior", flat16456(clusterBase16456(
			"set chassis cluster redundancy-group 1 interface-montior ge-0/0/2 weight 255")...), "interface-montior"},
		{"flat preemt", flat16456(clusterBase16456(
			"set chassis cluster redundancy-group 1 preemt")...), "preemt"},
		{"flat ip-monitorng", flat16456(clusterBase16456(
			"set chassis cluster redundancy-group 1 ip-monitorng family inet 10.0.0.1 weight 100")...), "ip-monitorng"},
		{"flat xpfbogus in RG", flat16456(clusterBase16456(
			"set chassis cluster redundancy-group 1 xpfbogus 5")...), "xpfbogus"},
		// RG level: hierarchical shapes (container + packed instance line).
		{"hier interface-monitr", hier16456(`chassis { cluster { cluster-id 1; authentication-key test-cluster-psk-16456-long; node 0; redundancy-group 1 { node 0 priority 200; interface-monitr ge-0/0/2 weight 255; } } }`), "interface-monitr"},
		{"hier preemt", hier16456(`chassis { cluster { cluster-id 1; authentication-key test-cluster-psk-16456-long; node 0; redundancy-group 1 { node 0 priority 200; preemt; } } }`), "preemt"},
		{"hier ip-monitorng", hier16456(`chassis { cluster { cluster-id 1; authentication-key test-cluster-psk-16456-long; node 0; redundancy-group 1 { node 0 priority 200; ip-monitorng { family inet 10.0.0.1 weight 100; } } } }`), "ip-monitorng"},
		// Cluster level: misspelt cluster statements and the RG keyword itself.
		{"flat redundancy-grup", flat16456(
			"set chassis cluster cluster-id 1",
			"set chassis cluster authentication-key "+clusterPSK16456,
			"set chassis cluster redundancy-grup 1 node 0 priority 200"), "redundancy-grup"},
		{"flat heartbeat-intervalzq", flat16456(clusterBase16456(
			"set chassis cluster heartbeat-intervalzq 200")...), "heartbeat-intervalzq"},
		{"flat peer-addresszq", flat16456(clusterBase16456(
			"set chassis cluster peer-addresszq 10.99.0.2")...), "peer-addresszq"},
		{"flat xpfbogus in cluster", flat16456(clusterBase16456(
			"set chassis cluster xpfbogus 5")...), "xpfbogus"},
		{"hier heartbeat-intervalzq", hier16456(`chassis { cluster { cluster-id 1; authentication-key test-cluster-psk-16456-long; node 0; heartbeat-intervalzq 200; redundancy-group 1 { node 0 priority 200; } } }`), "heartbeat-intervalzq"},
		{"hier packed cluster typo", hier16456(`chassis { cluster cluster-id 1 authentication-key test-cluster-psk-16456-long heartbeat-intervalzq 200; }`), "heartbeat-intervalzq"},
	}
	for _, tc := range rows {
		t.Run(tc.name+"/strict", func(t *testing.T) { assertReject16456(t, tc.build(t), tc.tok) })
		t.Run(tc.name+"/lenient", func(t *testing.T) { assertLenientWarns16456(t, tc.build(t), tc.tok) })
	}
}

// The acceptance headline: the correctly spelt control compiles with
// its monitors / preempt / ip-monitoring intact and no #16456 warning,
// in every spelling.
func TestChassisClusterControlCompiles16456(t *testing.T) {
	controls := []struct {
		name  string
		build func(*testing.T) *ConfigTree
	}{
		{"flat control", flat16456(clusterBase16456(
			"set chassis cluster redundancy-group 1 preempt",
			"set chassis cluster redundancy-group 1 ip-monitoring global-weight 255",
			"set chassis cluster redundancy-group 1 ip-monitoring family inet 10.0.0.1 weight 100")...)},
		{"hier control", hier16456(hierBase16456)},
		{"hier packed control", hier16456(`chassis { cluster { cluster-id 1; authentication-key test-cluster-psk-16456-long; node 0; redundancy-group 1 node 0 priority 200 preempt; } }`)},
		{"hier packed cluster control", hier16456(`chassis { cluster cluster-id 1 authentication-key test-cluster-psk-16456-long node 0 heartbeat-interval 200; }`)},
	}
	for _, tc := range controls {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(tc.build(t))
			if err != nil {
				t.Fatalf("control strict compile: %v", err)
			}
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "#16456") {
					t.Fatalf("control produced #16456 warning: %q", w)
				}
			}
		})
	}
	// The flat control's compiled shape: both monitors, preempt, and
	// the ip-monitoring target all present.
	cfg, err := CompileConfig(buildTree(t, clusterBase16456(
		"set chassis cluster redundancy-group 1 preempt",
		"set chassis cluster redundancy-group 1 ip-monitoring global-weight 255",
		"set chassis cluster redundancy-group 1 ip-monitoring family inet 10.0.0.1 weight 100")))
	if err != nil {
		t.Fatalf("flat control compile: %v", err)
	}
	rg := onlyRG6588(t, cfg)
	if len(rg.InterfaceMonitors) != 2 {
		t.Fatalf("control monitors = %v, want 2", describeMonitors(rg.InterfaceMonitors))
	}
	if !rg.Preempt {
		t.Fatal("control preempt = false, want true")
	}
	if rg.IPMonitoring == nil || rg.IPMonitoring.GlobalWeight != 255 || len(rg.IPMonitoring.Targets) != 1 {
		t.Fatalf("control ip-monitoring = %+v, want global-weight 255 with 1 target", rg.IPMonitoring)
	}
}

// Lenient compilation keeps the pre-fix compiled shape (the dropped
// line stays dropped) — only the warning is new (#1960).
func TestChassisClusterLenientKeepsShape16456(t *testing.T) {
	cfg := assertLenientWarns16456(t, buildTree(t, clusterBase16456(
		"set chassis cluster redundancy-group 1 interface-monitr ge-0/0/2 weight 255")), "interface-monitr")
	rg := onlyRG6588(t, cfg)
	if len(rg.InterfaceMonitors) != 2 {
		t.Fatalf("lenient monitors = %v, want the 2 correctly spelt ones (typo'd line stays dropped, warning only)", describeMonitors(rg.InterfaceMonitors))
	}
	cfg = assertLenientWarns16456(t, buildTree(t, clusterBase16456(
		"set chassis cluster redundancy-group 1 preemt")), "preemt")
	if onlyRG6588(t, cfg).Preempt {
		t.Fatal("lenient preemt compiled Preempt=true, want false (dropped line stays dropped, warning only)")
	}
}

// Declared statements at the judged levels must not be flagged:
// every RG statement and every cluster statement in its valid form,
// apply statements, group-inherited typos judged like inline ones, and
// the shipped cluster config.
func TestChassisClusterDeclaredAndMetaStayClean16456(t *testing.T) {
	clean := []struct {
		name  string
		build func(*testing.T) *ConfigTree
	}{
		{"all RG statements", flat16456(clusterBase16456(
			"set chassis cluster redundancy-group 1 gratuitous-arp-count 8",
			"set chassis cluster redundancy-group 1 preempt",
			"set chassis cluster redundancy-group 1 strict-vip-ownership",
			"set chassis cluster redundancy-group 1 allow-degraded-routing-takeover",
			"set chassis cluster redundancy-group 1 ip-monitoring global-threshold 100")...)},
		{"apply-macro in RG", hier16456(`chassis { cluster { cluster-id 1; authentication-key test-cluster-psk-16456-long; node 0; redundancy-group 1 { node 0 priority 200; apply-macro M { k v; } } } }`)},
		{"apply-macro in cluster", hier16456(`chassis { cluster { cluster-id 1; authentication-key test-cluster-psk-16456-long; node 0; apply-macro M { k v; } redundancy-group 1 { node 0 priority 200; } } }`)},
		{"hier control", hier16456(hierBase16456)},
	}
	for _, tc := range clean {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(tc.build(t))
			if err != nil {
				t.Fatalf("declared shape rejected: %v", err)
			}
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "#16456") {
					t.Fatalf("declared shape produced #16456 warning: %q", w)
				}
			}
		})
	}
	// Group-inherited typo: judged post-expansion, same as inline.
	assertReject16456(t, buildTree(t, []string{
		"set groups G chassis cluster redundancy-group 1 preemt",
		"set apply-groups G",
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key " + clusterPSK16456,
		"set chassis cluster redundancy-group 1 node 0 priority 200",
	}), "preemt")
	// The lenient flag must be registered or the tolerant path bricks.
	if !lenientCompileOpts().lenientChassisClusterUnknown16456 {
		t.Fatal("lenientChassisClusterUnknown16456 is NOT registered in lenientCompileOpts() — a persisted or peer-synced config carrying an unknown cluster/RG statement would fail to boot (#1960)")
	}
}

// The shipped cluster configs still commit strict.
func TestChassisClusterShippedConfigsCommit16456(t *testing.T) {
	for _, path := range []string{
		"../../test/incus/xpf-cluster-fw0.conf",
		"../../docs/ha-cluster-userspace.conf",
		"../../docs/ha-cluster.conf",
	} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Skipf("shipped config %s not readable: %v", path, err)
		}
		tree, perrs := NewParser(string(data)).Parse()
		if len(perrs) > 0 {
			t.Fatalf("%s parse: %v", path, perrs)
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("shipped config %s strict compile: %v", path, err)
		}
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "#16456") {
				t.Fatalf("shipped config %s produced #16456 warning: %q", path, w)
			}
		}
	}
}
