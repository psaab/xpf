package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

// #15269 cohort: B18-01 screen detail, B18-05 terse disabled, C09-01 DNAT source.

func screen15269CLI(t *testing.T, synExtra, flow string) *CLI {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	body := `
security {
    zones { security-zone untrust { screen p; } }
    screen { ids-option p {
            tcp { syn-flood { attack-threshold 200; ` + synExtra + ` } }
    } }
` + flow + `
}
`
	if err := store.LoadOverride(body); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return &CLI{store: store}
}

func TestCLIScreenSynFloodUnset15269(t *testing.T) {
	c := screen15269CLI(t, "", "")
	out := captureStdout(t, func() {
		if err := c.showScreenIdsOptionDetail("p"); err != nil {
			t.Fatalf("detail: %v", err)
		}
	})
	if strings.Contains(out, "(default)") {
		t.Errorf("unset must not render (default):\n%s", out)
	}
	for _, want := range []string{"disabled", "512 (not applied)", "4000 (not applied)", "20"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	// Configured control stays numeric.
	c2 := screen15269CLI(t, "alarm-threshold 512; source-threshold 4000; destination-threshold 4000; timeout 45;", "")
	out2 := captureStdout(t, func() { _ = c2.showScreenIdsOptionDetail("p") })
	if strings.Contains(out2, "(not applied)") || !strings.Contains(out2, "45") {
		t.Errorf("configured arm wrong:\n%s", out2)
	}
	// Global flow initial-timeout is effective opening window when unset.
	c3 := screen15269CLI(t, "", "    flow { tcp-session { initial-timeout 30; } }")
	out3 := captureStdout(t, func() { _ = c3.showScreenIdsOptionDetail("p") })
	// Timeout row should show 30 (effective), not claim 20 default applied.
	found30 := false
	for _, line := range strings.Split(out3, "\n") {
		if strings.Contains(line, "Timeout (seconds)") && strings.Contains(line, "30") {
			found30 = true
		}
	}
	if !found30 {
		t.Errorf("timeout must show effective 30:\n%s", out3)
	}
}

func reth15269CLI(t *testing.T) *CLI {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride(`
interfaces {
    ge-0/0/2 { gigether-options { redundant-parent reth0; } }
    reth0 {
        vlan-tagging;
        unit 50 { disable; vlan-id 50; family inet { address 172.16.50.8/24; } }
        unit 51 { vlan-id 51; family inet { address 172.16.51.8/24; } }
    }
    ge-0/0/5 { unit 0 { disable; family inet { address 10.0.5.8/24; } } }
}
security { zones { security-zone wan { interfaces { reth0.50; reth0.51; ge-0/0/5.0; } } } }
`); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	cfg := store.ActiveConfig()
	if cfg == nil || cfg.Interfaces.Interfaces["reth0"] == nil || !cfg.Interfaces.Interfaces["reth0"].Units[50].Disable {
		t.Fatalf("fixture reth0.50 not disabled: %+v", cfg)
	}
	return &CLI{store: store}
}

func TestCLITerseDisabled15269(t *testing.T) {
	c := reth15269CLI(t)
	out := captureStdout(t, func() {
		if err := c.showInterfacesTerse(); err != nil {
			t.Fatalf("terse: %v", err)
		}
	})
	lines := strings.Split(out, "\n")
	find := func(prefix string) string {
		for _, l := range lines {
			if strings.HasPrefix(l, prefix) {
				return l
			}
		}
		return ""
	}
	if l := find("reth0.50"); !strings.Contains(l, "down") || strings.Contains(l, "172.16.50.8") {
		t.Errorf("reth0.50 must be down without address, got %q\n%s", l, out)
	}
	if l := find("reth0.51"); strings.Contains(l, "down") && strings.Contains(l, "down") && !strings.Contains(l, "172.16.51.8") {
		t.Errorf("reth0.51 control wrong: %q", l)
	}
	if l := find("reth0.51"); !strings.Contains(l, "172.16.51.8") {
		t.Errorf("reth0.51 must keep address: %q\n%s", l, out)
	}
	if l := find("ge-0/0/5.0"); !strings.Contains(l, "down") {
		t.Errorf("ge-0/0/5.0 must be down: %q\n%s", l, out)
	}
}

func dnat15269CLI(t *testing.T) *CLI {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	lines := []string{
		"set security zones security-zone untrust",
		"set security nat destination pool dp1 address 10.0.0.5",
		"set security nat destination rule-set drs from zone untrust",
		"set security nat destination rule-set drs rule scoped match source-address 198.51.100.0/24",
		"set security nat destination rule-set drs rule scoped match destination-address 203.0.113.10/32",
		"set security nat destination rule-set drs rule scoped then destination-nat pool dp1",
		"set security nat destination rule-set drs rule open match destination-address 203.0.113.11/32",
		"set security nat destination rule-set drs rule open then destination-nat pool dp1",
	}
	if _, err := store.LoadSet(strings.Join(lines, "\n")); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return &CLI{store: store}
}

func TestCLIDNATSourceMatch15269(t *testing.T) {
	c := dnat15269CLI(t)
	cfg := c.store.ActiveConfig()
	views := map[string]func() error{
		"detail":   func() error { return c.showNATDestinationRuleDetail(cfg) },
		"rule-set": func() error { return c.showNATDestinationRuleSet(cfg, "drs") },
		"rule all": func() error { return c.showNATDestinationRuleAll(cfg) },
		"default": func() error {
			// default view (no subcommand)
			return c.showNATDestination(cfg, nil)
		},
	}
	for name, run := range views {
		out := captureStdout(t, func() {
			if err := run(); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		})
		if !strings.Contains(out, "198.51.100.0/24") {
			t.Errorf("%s missing scoped source 198.51.100.0/24:\n%s", name, out)
		}
		if !strings.Contains(out, "0.0.0.0/0") {
			t.Errorf("%s missing unscoped 0.0.0.0/0:\n%s", name, out)
		}
	}
}
