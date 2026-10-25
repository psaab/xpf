package config

import (
	"strings"
	"testing"
)

func compile8357(t *testing.T, cmds []string, compile func(*ConfigTree) (*Config, error)) *Config {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := compile(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return cfg
}

func hasNTPAdvisory8357(cfg *Config) bool {
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "system ntp server") && strings.Contains(w, "fabric RPC") {
			return true
		}
	}
	return false
}

var clusterCmds8357 = []string{
	// The strict path hard-rejects a cluster with no PSK (the control channel
	// fails OPEN without one), so the fixture must carry a key or it never
	// reaches the advisory at all — it would fail for an unrelated reason and
	// look like the advisory was absent.
	"set chassis cluster authentication-key aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	"set chassis cluster cluster-id 1",
	"set chassis cluster node 0",
	"set chassis cluster no-private-rg-election",
	"set chassis cluster redundancy-group 1 node 0 priority 200",
	"set chassis cluster redundancy-group 1 node 1 priority 100",
}

// #8357: a chassis cluster with no `system ntp server` warns at COMMIT.
//
// The fault is #6708's: both nodes ran with NTPSynchronized=no, every
// cross-node fabric RPC died, and the symptom the operator saw named SESSIONS.
// Nothing told them the cluster had no time source until the control plane was
// already down.
func TestClusterWithoutNTPWarnsOnTheStrictPath8357(t *testing.T) {
	cfg := compile8357(t, clusterCmds8357, CompileConfig)
	if !hasNTPAdvisory8357(cfg) {
		t.Fatalf("a chassis cluster with no `system ntp server` must warn at commit; "+
			"warnings were %q (#8357)", cfg.Warnings)
	}
}

// #8357 THE DISCRIMINATING CONTROL, and the cell a strict-only fixture cannot
// see: the tolerant paths must stay SILENT.
//
// CompileConfigLenient backs Store.Load (persisted-config boot) and
// CompileConfigForNodeLenient backs Store.SyncApply (HA peer sync). Without the
// suppression this advisory fires on every boot and every peer sync of a config
// committed long ago — and a warning an operator sees on every boot for a
// decision they already made is one they learn to skip. That costs more than
// the advisory buys, so it is tested, not assumed.
func TestClusterWithoutNTPIsSilentOnTheTolerantPaths8357(t *testing.T) {
	for _, tc := range []struct {
		name    string
		compile func(*ConfigTree) (*Config, error)
	}{
		{"CompileConfigLenient (Store.Load)", CompileConfigLenient},
		{"CompileConfigForNodeLenient (Store.SyncApply)", func(tr *ConfigTree) (*Config, error) {
			return CompileConfigForNodeLenient(tr, 0)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := compile8357(t, clusterCmds8357, tc.compile)
			if hasNTPAdvisory8357(cfg) {
				t.Fatalf("the NTP advisory must NOT fire on a tolerant path — it would "+
					"repeat on every boot / peer sync of an already-committed config, "+
					"which trains operators to ignore warnings (#8357). warnings=%q",
					cfg.Warnings)
			}
		})
	}
}

// #8357: a cluster that HAS an NTP server must not warn — the over-correction
// case. Without it the advisory could fire unconditionally on every cluster and
// the strict cell above would not notice.
func TestClusterWithNTPDoesNotWarn8357(t *testing.T) {
	cfg := compile8357(t, append(append([]string{}, clusterCmds8357...),
		"set system ntp server 192.0.2.1"), CompileConfig)
	if hasNTPAdvisory8357(cfg) {
		t.Fatalf("a cluster WITH an ntp server must not warn; warnings=%q", cfg.Warnings)
	}
	if len(cfg.System.NTPServers) == 0 {
		t.Fatalf("fixture precondition: the ntp server must have compiled, or this " +
			"cell passes for the wrong reason")
	}
}

// #8357: a NON-cluster config with no NTP must not warn. The advisory is
// cluster-specific because cross-node fabric RPC is what breaks; a standalone
// node has none to lose, and warning there would be noise on the majority of
// deployments.
func TestStandaloneWithoutNTPDoesNotWarn8357(t *testing.T) {
	cfg := compile8357(t, []string{"set system host-name fw0"}, CompileConfig)
	if hasNTPAdvisory8357(cfg) {
		t.Fatalf("a standalone config must not carry the cluster NTP advisory; warnings=%q",
			cfg.Warnings)
	}
}

// #8357: it is a WARNING, not an error — the commit still succeeds. An operator
// legitimately configures a cluster before NTP is reachable, and hard-rejecting
// that would be worse than the fault it prevents.
func TestClusterWithoutNTPStillCompiles8357(t *testing.T) {
	tree := &ConfigTree{}
	for _, cmd := range clusterCmds8357 {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("the advisory must not reject the commit: %v (#8357)", err)
	}
}
