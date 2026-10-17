package config

import "testing"

// #14419 (DR15-H4): same-name as-path definition across shapes adopted
// beside instead of inline-wins, so compiler map last-wins stored the
// GROUP regex (".*") over the inline narrow regex ("^65001$").
//
// RED on origin/master: packed/container, container/packed and
// container/container cells compiled AP1=".*"; packed/packed passed.
// Different-name definitions must still adopt in all shape pairs, and
// container/container with different first tokens is included per spec
// (a).3 — this fix covers it via the same same-name drop.

func compileASPaths14419(t *testing.T, src string) *Config {
	t.Helper()
	tree, errs := NewParser(src).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs[0])
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return cfg
}

func aspathConfig14419(groupBody, inline string) string {
	return "groups {\n  g1 {\n    policy-options {\n      " + groupBody + "\n    }\n  }\n}\n" +
		"policy-options {\n  " + inline + "\n  policy-statement P {\n    term t1 {\n      from {\n        as-path AP1;\n      }\n      then accept;\n    }\n    term t2 {\n      then reject;\n    }\n  }\n}\napply-groups g1;\n"
}

func TestDR15H4AsPathSameNameAcrossShapes(t *testing.T) {
	packedInline := `as-path AP1 "^65001$";`
	packedGroup := `as-path AP1 ".*";`
	containerInline := "as-path AP1 {\n        \"^65001$\";\n      }"
	containerGroup := "as-path AP1 {\n        \".*\";\n      }"
	// Note: container children are bare leaves; first token is regex token quoted.
	cases := []struct {
		name string
		src  string
	}{
		{"packed/packed", aspathConfig14419(packedGroup, packedInline)},
		{"packed/container", aspathConfig14419(packedGroup, containerInline)},
		{"container/packed", aspathConfig14419(containerGroup, packedInline)},
		{"container/container same first token", aspathConfig14419(containerGroup, containerInline)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := compileASPaths14419(t, tc.src)
			ap := cfg.PolicyOptions.ASPaths["AP1"]
			if ap == nil {
				t.Fatalf("no AP1 compiled")
			}
			if ap.Regex != "^65001$" {
				t.Fatalf("AP1 Regex = %q, want inline %q", ap.Regex, "^65001$")
			}
		})
	}
}
func TestDR15H4AsPathDifferentNameAdopts(t *testing.T) {
	for _, tc := range []struct {
		name       string
		groupBody  string
		inlineBody string
	}{
		{"packed/packed", `as-path AP2 ".*";`, `as-path AP1 "^65001$";`},
		{"container/packed", "as-path AP2 {\n        \".*\";\n      }", `as-path AP1 "^65001$";`},
		{"packed/container", `as-path AP2 ".*";`, "as-path AP1 {\n        \"^65001$\";\n      }"},
		{"container/container", "as-path AP2 {\n        \".*\";\n      }", "as-path AP1 {\n        \"^65001$\";\n      }"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := compileASPaths14419(t, aspathConfig14419(tc.groupBody, tc.inlineBody))
			if ap := cfg.PolicyOptions.ASPaths["AP1"]; ap == nil || ap.Regex != "^65001$" {
				t.Fatalf("AP1 = %+v want ^65001$", ap)
			}
			if ap := cfg.PolicyOptions.ASPaths["AP2"]; ap == nil || ap.Regex != ".*" {
				t.Fatalf("AP2 = %+v want .* (different-name must adopt)", ap)
			}
		})
	}
}

func TestDR15H4AsPathContainerDifferentFirstToken(t *testing.T) {
	group := "as-path AP1 {\n        \"65002 .*\";\n      }"
	inline := "as-path AP1 {\n        \"^65001$\";\n      }"
	cfg := compileASPaths14419(t, aspathConfig14419(group, inline))
	ap := cfg.PolicyOptions.ASPaths["AP1"]
	if ap == nil || ap.Regex != "^65001$" {
		t.Fatalf("AP1 = %+v want inline ^65001$", ap)
	}
}

func TestDR15H4AsPathSingleAndGroupOnlyControls(t *testing.T) {
	inlineOnly := "policy-options {\n  as-path AP1 \"^65001$\";\n  policy-statement P {\n    term t1 { from { as-path AP1; } then accept; }\n  }\n}\n"
	if ap := compileASPaths14419(t, inlineOnly).PolicyOptions.ASPaths["AP1"]; ap == nil || ap.Regex != "^65001$" {
		t.Fatalf("inline-only AP1 = %+v", ap)
	}
	groupOnly := aspathConfig14419(`as-path AP1 ".*";`, `as-path AP9 "^65009$";`)
	cfg := compileASPaths14419(t, groupOnly)
	if ap := cfg.PolicyOptions.ASPaths["AP1"]; ap == nil || ap.Regex != ".*" {
		t.Fatalf("group-only AP1 = %+v want .*", ap)
	}
}
