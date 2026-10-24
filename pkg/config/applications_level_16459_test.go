package config

import (
	"strings"
	"testing"
)

// #16459: unknown children at the `applications` level strict-reject and
// lenient-warn. Each typo row pairs a misspelt line carrying a
// destination-port constraint with correctly spelt sibling lines that
// build the same application without it — on the pre-fix tree the
// strict compile succeeded and the compiled application had an empty
// DestinationPort (permits every TCP port).

func assertReject16459(t *testing.T, tree *ConfigTree, wantTok string) {
	t.Helper()
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("strict compile accepted unknown child %q (#16459)", wantTok)
	}
	if !strings.Contains(err.Error(), "#16459") || !strings.Contains(err.Error(), wantTok) {
		t.Fatalf("strict error = %q, want #16459 naming %q", err, wantTok)
	}
}

func assertLenientWarns16459(t *testing.T, tree *ConfigTree, wantTok string) *Config {
	t.Helper()
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must boot (#1960): %v", err)
	}
	warnings := strings.Join(cfg.Warnings, "\n")
	if !strings.Contains(warnings, "#16459") || !strings.Contains(warnings, wantTok) {
		t.Fatalf("lenient warnings = %q, want #16459 naming %q", warnings, wantTok)
	}
	return cfg
}

func flat16459(lines ...string) func(*testing.T) *ConfigTree {
	return func(t *testing.T) *ConfigTree { return flatTreeFromSets(t, lines...) }
}

func hier16459(src string) func(*testing.T) *ConfigTree {
	return func(t *testing.T) *ConfigTree { return hierTree(t, src) }
}

func TestApplicationsLevelUnknownChildren16459(t *testing.T) {
	rows := []struct {
		name  string
		build func(*testing.T) *ConfigTree
		tok   string
	}{
		{"flat applicaiton", flat16459(
			"set applications application app-x protocol tcp",
			"set applications applicaiton app-x destination-port 8443"), "applicaiton"},
		{"flat aplication", flat16459(
			"set applications aplication app-x protocol tcp",
			"set applications application app-x destination-port 8443"), "aplication"},
		{"flat applicaton", flat16459(
			"set applications applicaton app-x protocol tcp",
			"set applications application app-x destination-port 8443"), "applicaton"},
		{"flat application-setzq", flat16459(
			"set applications application app-x protocol tcp",
			"set applications application app-x destination-port 8443",
			"set applications application-setzq s1 application app-x"), "application-setzq"},
		{"flat application-set typo only", flat16459(
			"set applications application app-x protocol tcp destination-port 8443",
			"set applications applicaiton-set s1 application app-x"), "applicaiton-set"},
		{"flat root bogus", flat16459(
			"set applications xpfbogus 5",
			"set applications application app-x protocol tcp"), "xpfbogus"},
		{"flat packed typo", flat16459(
			"set applications applicaiton app-x destination-port 8443 protocol tcp"), "applicaiton"},
		{"hier applicaiton", hier16459(`applications { application app-x { protocol tcp; } applicaiton app-x { destination-port 8443; } }`), "applicaiton"},
		{"hier application-setzq", hier16459(`applications { application app-x { protocol tcp; destination-port 8443; } application-setzq s1 { application app-x; } }`), "application-setzq"},
		{"hier elided typo", hier16459(`applications { applicaiton app-x destination-port 8443; application app-x { protocol tcp; } }`), "applicaiton"},
	}
	for _, tc := range rows {
		t.Run(tc.name+"/strict", func(t *testing.T) { assertReject16459(t, tc.build(t), tc.tok) })
		t.Run(tc.name+"/lenient", func(t *testing.T) { assertLenientWarns16459(t, tc.build(t), tc.tok) })
	}
}

// The acceptance headline: the widened application must not
// strict-commit, and the correctly spelt control compiles with its
// port constraint intact.
func TestApplicationsLevelControlCompiles16459(t *testing.T) {
	cfg, err := CompileConfig(flatTreeFromSets(t,
		"set applications application app-x protocol tcp",
		"set applications application app-x destination-port 8443",
		"set applications application-set s1 application app-x",
	))
	if err != nil {
		t.Fatalf("control strict compile: %v", err)
	}
	app := cfg.Applications.Applications["app-x"]
	if app == nil || app.DestinationPort != "8443" || app.Protocol != "tcp" {
		t.Fatalf("control app = %+v, want tcp/8443", app)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#16459") {
			t.Fatalf("control produced #16459 warning: %q", w)
		}
	}
	// Hierarchical control, including a term body (opaque to the schema).
	cfg, err = CompileConfig(hierTree(t, `applications { application app-x { term t1 { protocol tcp; destination-port 8443; } } application-set s1 { application app-x; description "web"; } }`))
	if err != nil {
		t.Fatalf("hier control strict compile: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#16459") {
			t.Fatalf("hier control produced #16459 warning: %q", w)
		}
	}
}

// Lenient compilation keeps the pre-fix compiled shape (the dropped
// line stays dropped) — only the warning is new (#1960).
func TestApplicationsLevelLenientKeepsShape16459(t *testing.T) {
	cfg := assertLenientWarns16459(t, flatTreeFromSets(t,
		"set applications application app-x protocol tcp",
		"set applications applicaiton app-x destination-port 8443",
	), "applicaiton")
	app := cfg.Applications.Applications["app-x"]
	if app == nil || app.DestinationPort != "" {
		t.Fatalf("lenient app = %+v, want port-less (dropped line stays dropped, warning only)", app)
	}
}

// Declared statements at the judged level must not be flagged:
// application / application-set bodies (including term bodies and
// packed flat-set chains), apply statements at the applications level
// and inside an application, and a group-inherited typo must be judged
// exactly like an inline one (the gate runs post-expansion).
func TestApplicationsLevelDeclaredAndMetaStayClean16459(t *testing.T) {
	clean := []struct {
		name  string
		build func(*testing.T) *ConfigTree
	}{
		{"flat packed chain", flat16459(
			"set applications application app-x protocol tcp destination-port 8443")},
		{"hier elided", hier16459(`applications { application app-x protocol tcp destination-port 8443; }`)},
		{"apply-macro at level", hier16459(`applications { apply-macro M { k v; } application APP { protocol tcp; destination-port 80; } }`)},
		{"apply-groups in application", flat16459(
			"set groups G applications application app-x protocol tcp",
			"set groups G applications application app-x destination-port 8443",
			"set applications application app-x apply-groups G")},
		{"app-set description", hier16459(`applications { application app-x { protocol tcp; destination-port 8443; } application-set s1 { description "x"; application app-x; } }`)},
	}
	for _, tc := range clean {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(tc.build(t))
			if err != nil {
				t.Fatalf("declared shape rejected: %v", err)
			}
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "#16459") {
					t.Fatalf("declared shape produced #16459 warning: %q", w)
				}
			}
		})
	}
	// Group-inherited typo: judged post-expansion, same as inline.
	assertReject16459(t, flatTreeFromSets(t,
		"set groups G applications applicaiton app-x destination-port 8443",
		"set apply-groups G",
		"set applications application app-x protocol tcp",
	), "applicaiton")
}

// The gate is scoped, not closedWorld: arming closedWorld on
// schemaApplications would inherit into term bodies and flat-set
// chains and reject shipped spellings (measured). Assert it stays off,
// mirroring the #9017 pin on `firewall family`.
func TestApplicationsLevelNotClosedWorld16459(t *testing.T) {
	if schemaApplications.closedWorld {
		t.Error("`applications` is closedWorld again. That flag INHERITS: it closes " +
			"the term grammar and flat-set chains beneath it and rejects valid config " +
			"such as `term t1 { protocol tcp; }`. The applications-level gate is " +
			"validateApplicationsLevelChildrenAST16459 (#16459).")
	}
}
