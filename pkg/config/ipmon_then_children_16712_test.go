package config

import (
	"strings"
	"testing"
)

// #16712: `services ip-monitoring policy <p> then interface <if>
// enable|disable` committed clean with no warning and was silently
// ignored — compileIPMonitoring reads only `preferred-route` under
// `then`, IPMonitoringPolicy has no interface action, and the runtime
// never touches the interface. The scoped gate
// validateIPMonThenChildrenAST16712 strict-rejects (naming the
// policy and the unsupported action) and lenient-warns (#1960).
//
// RED-on-revert: removing the gate from runPreWalkGates (or its
// lenient flag) makes every Reject/Warn cell below accept silently.

func ipMon16712Lines(extra ...string) []string {
	lines := append(rpmProbeLines(),
		"set services ip-monitoring policy p match rpm-probe WAN",
		"set services ip-monitoring policy p then preferred-route route 0.0.0.0/0 next-hop 10.0.0.1",
	)
	return append(lines, extra...)
}

func assertIPMonReject16712(t *testing.T, tree *ConfigTree, want ...string) {
	t.Helper()
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("strict compile accepted undeclared then child, want reject naming %v (#16712)", want)
	}
	for _, s := range want {
		if !strings.Contains(err.Error(), s) {
			t.Fatalf("strict error = %q, want substring %q", err, s)
		}
	}
}

func assertIPMonLenientWarns16712(t *testing.T, tree *ConfigTree, want ...string) *Config {
	t.Helper()
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must boot (#1960): %v", err)
	}
	joined := strings.Join(cfg.Warnings, "\n")
	for _, s := range want {
		if !strings.Contains(joined, s) {
			t.Fatalf("lenient warnings = %q, want substring %q", joined, s)
		}
	}
	return cfg
}

func hierIPMon16712(thenBody string) string {
	return `services {
  rpm { probe WAN { test t { target address 1.1.1.1; } } }
  ip-monitoring { policy p {
    match { rpm-probe WAN; }
    then {
      preferred-route { route 0.0.0.0/0 { next-hop 10.0.0.1; } }
      ` + thenBody + `
    }
  } }
}`
}

func TestIPMonThenInterfaceAction16712(t *testing.T) {
	rows := []struct {
		name  string
		build func(*testing.T) *ConfigTree
		want  []string
	}{
		{"flat enable", func(t *testing.T) *ConfigTree {
			return buildTree(t, ipMon16712Lines("set services ip-monitoring policy p then interface ge-0/0/1 enable"))
		}, []string{`"p"`, "interface", "enable|disable", "#16712"}},
		{"flat disable", func(t *testing.T) *ConfigTree {
			return buildTree(t, ipMon16712Lines("set services ip-monitoring policy p then interface ge-0/0/1 disable"))
		}, []string{`"p"`, "interface", "#16712"}},
		{"hier braced enable", func(t *testing.T) *ConfigTree {
			return hierTree(t, hierIPMon16712("interface ge-0/0/1 enable;"))
		}, []string{`"p"`, "interface", "#16712"}},
		{"hier braced disable block", func(t *testing.T) *ConfigTree {
			return hierTree(t, hierIPMon16712("interface ge-0/0/1 { disable; }"))
		}, []string{`"p"`, "interface", "#16712"}},
		{"hier packed then", func(t *testing.T) *ConfigTree {
			return hierTree(t, `services {
  rpm { probe WAN { test t { target address 1.1.1.1; } } }
  ip-monitoring { policy p {
    match { rpm-probe WAN; }
    then { preferred-route { route 0.0.0.0/0 { next-hop 10.0.0.1; } } }
    then interface ge-0/0/1 enable;
  } }
}`)
		}, []string{`"p"`, "interface", "#16712"}},
		{"hier packed policy then", func(t *testing.T) *ConfigTree {
			return hierTree(t, `services {
  rpm { probe WAN { test t { target address 1.1.1.1; } } }
  ip-monitoring { policy p {
    match { rpm-probe WAN; }
    then { preferred-route { route 0.0.0.0/0 { next-hop 10.0.0.1; } } }
  } }
  ip-monitoring { policy p then interface ge-0/0/1 enable; }
}`)
		}, []string{`"p"`, "interface", "#16712"}},
		{"flat typo preffered-route", func(t *testing.T) *ConfigTree {
			return buildTree(t, ipMon16712Lines("set services ip-monitoring policy p then preffered-route route 0.0.0.0/0 next-hop 10.0.0.2"))
		}, []string{`"p"`, "preffered-route", "preferred-route", "#16712"}},
		{"hier bogus child", func(t *testing.T) *ConfigTree {
			return hierTree(t, hierIPMon16712("zzbogus 5;"))
		}, []string{`"p"`, "zzbogus", "#16712"}},
		{"group inherited", func(t *testing.T) *ConfigTree {
			lines := []string{"set groups G services ip-monitoring policy p then interface ge-0/0/1 enable", "set apply-groups G"}
			lines = append(lines, ipMon16712Lines()...)
			return buildTree(t, lines)
		}, []string{`"p"`, "interface", "#16712"}},
	}
	for _, tc := range rows {
		t.Run(tc.name+"/strict", func(t *testing.T) { assertIPMonReject16712(t, tc.build(t), tc.want...) })
		t.Run(tc.name+"/lenient", func(t *testing.T) { assertIPMonLenientWarns16712(t, tc.build(t), tc.want...) })
	}
}

// The preferred-route-only control stays accepted on both paths,
// with the route compiled and no #16712 warning.
func TestIPMonThenPreferredRouteOnlyControl16712(t *testing.T) {
	for _, tc := range []struct {
		name  string
		build func(*testing.T) *ConfigTree
	}{
		{"flat", func(t *testing.T) *ConfigTree { return buildTree(t, ipMon16712Lines()) }},
		{"hier", func(t *testing.T) *ConfigTree { return hierTree(t, hierIPMon16712("")) }},
		{"hier routing-instance", func(t *testing.T) *ConfigTree {
			return hierTree(t, `services {
  rpm { probe WAN { test t { target address 1.1.1.1; } } }
  ip-monitoring { policy p {
    match { rpm-probe WAN; }
    then { preferred-route { routing-instance vr1 { route 0.0.0.0/0 { next-hop 10.0.0.1; } } } }
  } }
}
routing-instances { vr1 { instance-type virtual-router; } }`)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(tc.build(t))
			if err != nil {
				t.Fatalf("control strict compile: %v", err)
			}
			pol := cfg.Services.IPMonitoring.Policies["p"]
			if pol == nil || len(pol.PreferredRoutes) != 1 {
				t.Fatalf("control policy = %+v, want 1 preferred route", pol)
			}
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "#16712") {
					t.Fatalf("control produced #16712 warning: %q", w)
				}
			}
			cfgL, err := CompileConfigLenient(tc.build(t))
			if err != nil {
				t.Fatalf("control lenient compile: %v", err)
			}
			for _, w := range cfgL.Warnings {
				if strings.Contains(w, "#16712") {
					t.Fatalf("control lenient produced #16712 warning: %q", w)
				}
			}
		})
	}
}

// Lenient compilation keeps the pre-fix compiled shape: the
// preferred route still compiles, the interface action stays
// inert — only the warning is new (#1960).
func TestIPMonThenLenientKeepsShape16712(t *testing.T) {
	cfg := assertIPMonLenientWarns16712(t, buildTree(t, ipMon16712Lines(
		"set services ip-monitoring policy p then interface ge-0/0/1 enable")), `"p"`, "interface", "#16712")
	pol := cfg.Services.IPMonitoring.Policies["p"]
	if pol == nil || len(pol.PreferredRoutes) != 1 || pol.PreferredRoutes[0].NextHop != "10.0.0.1" {
		t.Fatalf("lenient policy = %+v, want preferred route preserved", pol)
	}
}

// Interface-only policy: still rejected (now by the #16712 gate on
// strict, and by the pre-existing preferred-route requirement where
// the gate only warns) — never silently accepted strict.
func TestIPMonThenInterfaceOnlyStillRejected16712(t *testing.T) {
	lines := append(rpmProbeLines(),
		"set services ip-monitoring policy p match rpm-probe WAN",
		"set services ip-monitoring policy p then interface ge-0/0/1 enable",
	)
	assertIPMonReject16712(t, buildTree(t, lines), `"p"`, "interface", "#16712")
}

// The gate is scoped, not closedWorld: arming closedWorld on the
// `then` schema node would inherit into preferred-route/route and
// fire only on SchemaValidate. Assert it stays off, mirroring the
// #9017/#16459 pins.
func TestIPMonThenNotClosedWorld16712(t *testing.T) {
	thenNode := setSchema.children["services"].children["ip-monitoring"].children["policy"].children["then"]
	if thenNode == nil {
		t.Fatal("schema has no services ip-monitoring policy then — this cell would prove nothing")
	}
	if thenNode.closedWorld {
		t.Error("`services ip-monitoring policy then` is closedWorld. That flag INHERITS into " +
			"preferred-route/route and fires only on SchemaValidate; the ip-monitoring `then` gate is " +
			"validateIPMonThenChildrenAST16712 (#16712), which covers both compile paths.")
	}
	declared := ipMonThenChildTokens16712()
	if len(declared) != 1 || declared[0] != "preferred-route" {
		t.Fatalf("declared then children = %v, want [preferred-route] (positive control)", declared)
	}
}

// Direct gate calls: valid then children pass in both modes, and a
// schema-declared child is never judged.
func TestIPMonThenDirectGate16712(t *testing.T) {
	good := hierTree(t, hierIPMon16712(""))
	if w, err := validateIPMonThenChildrenAST16712(good.Children, false); err != nil || len(w) != 0 {
		t.Fatalf("strict direct valid = warnings %v err %v", w, err)
	}
	if w, err := validateIPMonThenChildrenAST16712(good.Children, true); err != nil || len(w) != 0 {
		t.Fatalf("lenient direct valid = warnings %v err %v", w, err)
	}
	bad := hierTree(t, hierIPMon16712("interface ge-0/0/1 enable;"))
	if _, err := validateIPMonThenChildrenAST16712(bad.Children, false); err == nil ||
		!strings.Contains(err.Error(), "interface") {
		t.Fatalf("strict direct gate = %v, want interface reject", err)
	}
	warnings, err := validateIPMonThenChildrenAST16712(bad.Children, true)
	if err != nil || len(warnings) != 1 || !strings.Contains(warnings[0], "#16712") {
		t.Fatalf("lenient direct gate = warnings %v err %v, want 1 #16712 warning", warnings, err)
	}
}
