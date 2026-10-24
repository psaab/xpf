package config

import (
	"fmt"
	"strings"
	"testing"
)

// #16079 UTM-01 (+SEC2-01): services security-intelligence /
// advanced-anti-malware (+ETI ssl initiation/termination rider) and
// services application-identification children committed silently inert —
// only a generic "no L7 engine" warning fired, no child was named, unlike
// the SSL-proxy sibling (#10984). Each family must now produce a
// child-named accepted-only warning on BOTH strict and lenient paths,
// while remaining loadable (the fix warns; it must not reject or drop the
// authored stanza). RED on revert: delete servicesNamedAcceptedOnlyWarnings
// and every named-warning assertion below fails, leaving only the generic
// application-identification line.

func utm16079Compilers() []struct {
	name    string
	compile func(*ConfigTree) (*Config, error)
} {
	return []struct {
		name    string
		compile func(*ConfigTree) (*Config, error)
	}{
		{name: "strict commit", compile: CompileConfig},
		{name: "lenient load", compile: CompileConfigLenient},
	}
}

// countWarningsContaining counts warnings containing every substring.
func countWarningsContaining(warnings []string, wants ...string) int {
	n := 0
	for _, w := range warnings {
		ok := true
		for _, want := range wants {
			if !strings.Contains(w, want) {
				ok = false
				break
			}
		}
		if ok {
			n++
		}
	}
	return n
}

func TestServicesUTMNamedWarnings16079(t *testing.T) {
	setTree := buildTree(t, []string{
		"set services security-intelligence profile secprof category Enhanced_Inspection feed-name feed1",
		"set services security-intelligence authentication token tok",
		"set services advanced-anti-malware profile aamprof http inspection-profile default-profile",
		"set services advanced-anti-malware connection url https://example.com",
		"set services application-identification no-application-system-cache",
		"set services application-identification application-system-cache timeout 100",
		"set services application-identification download url https://example.com/pkg",
		"set services ssl initiation profile initprof server-certificate cert1",
		"set services ssl termination profile termprof server-certificate cert2",
		// Sibling that already warned before this fix: must stay exactly once.
		"set services ssl proxy profile proxyprof root-ca enterprise-ca",
	})
	hierarchicalTree, parseErrors := NewParser(`services {
    security-intelligence {
        profile hsec {
            category { Enhanced_Inspection { feed-name f2; } }
        }
    }
    advanced-anti-malware {
        profile haam { traceoptions { file aam.log; } }
    }
    application-identification {
        no-application-system-cache;
        download { url https://example.com/pkg; }
    }
    ssl {
        initiation { profile hinit { server-certificate c1; } }
        termination { profile hterm { server-certificate c2; } }
        proxy { profile hproxy { root-ca ca; } }
    }
}`).Parse()
	if len(parseErrors) != 0 {
		t.Fatalf("hierarchical fixture must parse: %v", parseErrors)
	}

	// Each entry is the exact child-named phrase the warning must carry.
	shapes := []struct {
		name string
		tree *ConfigTree
		want []string
	}{
		{name: "flat set", tree: setTree, want: []string{
			`services security-intelligence profile "secprof"`,
			"services security-intelligence authentication",
			`services advanced-anti-malware profile "aamprof"`,
			"services advanced-anti-malware connection",
			"services application-identification no-application-system-cache",
			"services application-identification application-system-cache",
			"services application-identification download",
			`services ssl initiation profile "initprof"`,
			`services ssl termination profile "termprof"`,
			`services ssl proxy profile "proxyprof"`,
		}},
		{name: "hierarchical", tree: hierarchicalTree, want: []string{
			`services security-intelligence profile "hsec"`,
			`services advanced-anti-malware profile "haam"`,
			"services application-identification no-application-system-cache",
			"services application-identification download",
			`services ssl initiation profile "hinit"`,
			`services ssl termination profile "hterm"`,
			`services ssl proxy profile "hproxy"`,
		}},
	}
	for _, shape := range shapes {
		t.Run(shape.name, func(t *testing.T) {
			for _, tc := range utm16079Compilers() {
				t.Run(tc.name, func(t *testing.T) {
					cfg, err := tc.compile(shape.tree)
					if err != nil {
						t.Fatalf("UTM/AppID stanzas must remain loadable (warn, not reject): %v", err)
					}
					joined := strings.Join(cfg.Warnings, "\n")
					for _, want := range shape.want {
						if !strings.Contains(joined, want) {
							t.Errorf("missing child-named warning %q; warnings=%v", want, cfg.Warnings)
						}
						if !strings.Contains(joined, "accepted-only") ||
							!strings.Contains(joined, "no runtime effect") ||
							!strings.Contains(joined, "#16079") {
							t.Errorf("warnings must state accepted-only / no runtime effect / #16079; warnings=%v", cfg.Warnings)
							break
						}
					}
					// The pre-existing generic AppID line still fires (it
					// describes the base knob), exactly once.
					if n := countWarningsContaining(cfg.Warnings,
						"services application-identification is enabled"); n != 1 {
						t.Errorf("generic AppID warning count=%d want 1; warnings=%v", n, cfg.Warnings)
					}
					// The #10984 SSL-proxy sibling stays single, not doubled
					// by the new pass.
					if n := countWarningsContaining(cfg.Warnings, "ssl proxy profile"); n != 1 {
						t.Errorf("ssl proxy warnings=%d want 1; warnings=%v", n, cfg.Warnings)
					}
					// ApplicationIdentification presence semantics unchanged:
					// the knob is still live as a boolean.
					if !cfg.Services.ApplicationIdentification {
						t.Errorf("application-identification presence must still compile on; warnings=%v", cfg.Warnings)
					}
				})
			}
			// Authored stanzas survive for display/persistence.
			rendered := shape.tree.Format()
			for _, frag := range []string{"security-intelligence", "advanced-anti-malware"} {
				if !strings.Contains(rendered, frag) {
					t.Errorf("source tree lost %q:\n%s", frag, rendered)
				}
			}
		})
	}
}

// Repeated flat lines for one profile collapse to a single named warning
// (dedup), and a bare stanza still warns naming the family.
func TestServicesUTMDedupAndBare16079(t *testing.T) {
	tree := buildTree(t, []string{
		"set services security-intelligence profile dup category A feed-name f",
		"set services security-intelligence profile dup category B feed-name g",
		"set services advanced-anti-malware",
		"set services application-identification statistics interval 60",
		"set services application-identification statistics interval 120",
	})
	for _, tc := range utm16079Compilers() {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := tc.compile(tree)
			if err != nil {
				t.Fatalf("must remain loadable: %v", err)
			}
			if n := countWarningsContaining(cfg.Warnings, `security-intelligence profile "dup"`); n != 1 {
				t.Errorf("duplicate profile warnings=%d want 1; warnings=%v", n, cfg.Warnings)
			}
			if n := countWarningsContaining(cfg.Warnings,
				"services advanced-anti-malware configured but accepted-only"); n != 1 {
				t.Errorf("bare advanced-anti-malware warnings=%d want 1; warnings=%v", n, cfg.Warnings)
			}
			if n := countWarningsContaining(cfg.Warnings,
				"services application-identification statistics"); n != 1 {
				t.Errorf("duplicate statistics child warnings=%d want 1; warnings=%v", n, cfg.Warnings)
			}
		})
	}
}

// Controls: configs without these families, the bare AppID knob, and ssl
// stanzas without initiation/termination profiles must not gain warnings.
func TestServicesUTMNegativeControls16079(t *testing.T) {
	cases := []struct {
		name  string
		lines []string
	}{
		{name: "no services utm", lines: []string{
			"set system host-name r1",
		}},
		{name: "bare appid knob only", lines: []string{
			"set services application-identification",
		}},
		{name: "ssl proxy only", lines: []string{
			"set services ssl proxy profile p root-ca ca",
		}},
		{name: "ssl without profile", lines: []string{
			"set services ssl initiation actions log all",
		}},
		{name: "other services", lines: []string{
			"set services rpm probe p1 test t1 probe-type icmp-ping",
			"set services rpm probe p1 test t1 target address 192.0.2.1",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTree(t, tc.lines)
			for _, mode := range utm16079Compilers() {
				cfg, err := mode.compile(tree)
				if err != nil {
					t.Fatalf("%s compile: %v", mode.name, err)
				}
				if n := countWarningsContaining(cfg.Warnings, "#16079"); n != 0 {
					t.Errorf("%s: unexpected #16079 warnings=%v", mode.name, cfg.Warnings)
				}
			}
		})
	}
}

// Guard against helper drift: the warning for a family must name that
// family, not a sibling (a swapped family string would pass a loose
// "accepted-only" check).
func TestServicesUTMFamilyNotSwapped16079(t *testing.T) {
	tree := buildTree(t, []string{
		"set services security-intelligence profile onlysec category A feed-name f",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, fmt.Sprintf("%s", "advanced-anti-malware")) {
			t.Fatalf("security-intelligence-only config warned about advanced-anti-malware: %v", cfg.Warnings)
		}
	}
	if countWarningsContaining(cfg.Warnings, `security-intelligence profile "onlysec"`, "#16079") != 1 {
		t.Fatalf("expected one named security-intelligence warning; warnings=%v", cfg.Warnings)
	}
}
