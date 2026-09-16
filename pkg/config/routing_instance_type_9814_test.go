package config

import (
	"strings"
	"testing"
)

// #9814 STEP-0: routing-instance `instance-type` is a free string and the three
// L3VPN statements are inert without warning.
//
// Member 1 (DUP-CMP08, MATERIAL): the schema leaf has no validator and the
// compiler stores the raw token, while every consumer tests the literal
// "forwarding". A typo (`forwardng`), an unimplemented Junos type
// (`no-forwarding`, `l2vpn`, `vpls`), or garbage (`bogus`) commits clean and
// is silently treated as a VRF — the harmful direction per
// schema_routing.go:938-941 (forwarding is what makes the daemon SKIP VRF
// creation, so losing the value creates a VRF the operator asked NOT to have).
//
// Member 2 (SYN-CMP-04, COHORT): `vrf-target`, `vrf-table-label` and
// `route-distinguisher` are deliberately accepted and inert (#9323) but draw
// no warning, unlike inert per-instance protocols (#9374).
//
// RED on base: every reject/warn assertion below fails; the controls pass.

func tree9814(t *testing.T, lines ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	return tree
}

func braced9814(t *testing.T, body string) *ConfigTree {
	t.Helper()
	tree, perrs := NewParser("routing-instances { V9814 { " + body + " } }").Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture must parse: %v", perrs)
	}
	return tree
}

// Member 1, strict half: an unknown non-empty type is REFUSED — by the schema
// gate (Store.Commit rejects before compiling) and by direct CompileConfig.
func TestRoutingInstanceTypeStrictRejectsUnknown9814(t *testing.T) {
	for _, tc := range []struct{ name, typ string }{
		{"typo", "forwardng"},
		{"garbage", "bogus"},
		{"junos-unimplemented", "no-forwarding"},
		{"junos-l2vpn", "l2vpn"},
		{"junos-vpls", "vpls"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setTree := tree9814(t, "set routing-instances V9814 instance-type "+tc.typ)
			if err := SchemaValidate(setTree, nil); err == nil || !strings.Contains(err.Error(), tc.typ) {
				t.Errorf("SchemaValidate(set) accepted instance-type %q; want rejection naming the value, got: %v", tc.typ, err)
			}
			if _, err := CompileConfig(setTree); err == nil || !strings.Contains(err.Error(), tc.typ) {
				t.Errorf("CompileConfig(set) accepted instance-type %q; want rejection naming the value, got: %v", tc.typ, err)
			}
			bracedTree := braced9814(t, "instance-type "+tc.typ+";")
			if err := SchemaValidate(bracedTree, nil); err == nil || !strings.Contains(err.Error(), tc.typ) {
				t.Errorf("SchemaValidate(braced) accepted instance-type %q; want rejection naming the value, got: %v", tc.typ, err)
			}
			if _, err := CompileConfig(bracedTree); err == nil || !strings.Contains(err.Error(), tc.typ) {
				t.Errorf("CompileConfig(braced) accepted instance-type %q; want rejection naming the value, got: %v", tc.typ, err)
			}
		})
	}
}

// Member 1, controls: the three supported values and an omitted type keep
// committing on both spellings and both strict legs. Omitted stays accepted —
// existing tests (e.g. ri_member_collision_9821) compile typeless instances,
// and every consumer already treats non-"forwarding" as a VRF.
func TestRoutingInstanceTypeSupportedAndOmittedAccepted9814(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"forwarding", "instance-type forwarding;"},
		{"virtual-router", "instance-type virtual-router;"},
		{"vrf", "instance-type vrf;"},
		{"omitted", "interface ge-0/0/0.0;"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := braced9814(t, tc.body)
			if err := SchemaValidate(tree, nil); err != nil {
				t.Errorf("SchemaValidate rejected %s instance: %v", tc.name, err)
			}
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("CompileConfig rejected %s instance: %v", tc.name, err)
			}
			if len(cfg.RoutingInstances) != 1 {
				t.Fatalf("want 1 instance, got %d", len(cfg.RoutingInstances))
			}
			if tc.name == "omitted" && cfg.RoutingInstances[0].InstanceType != "" {
				t.Errorf("omitted instance-type compiled to %q, want \"\"", cfg.RoutingInstances[0].InstanceType)
			}
		})
	}
	for _, typ := range []string{"forwarding", "virtual-router", "vrf"} {
		tree := tree9814(t, "set routing-instances V9814 instance-type "+typ)
		if err := SchemaValidate(tree, nil); err != nil {
			t.Errorf("SchemaValidate(set) rejected instance-type %q: %v", typ, err)
		}
		if _, err := CompileConfig(tree); err != nil {
			t.Errorf("CompileConfig(set) rejected instance-type %q: %v", typ, err)
		}
	}
}

// Member 1, tolerant half: the lenient load / peer-sync path cannot reject
// (#1960) but must warn in cfg.Warnings — and must stay silent for the
// supported values and an omitted type.
func TestRoutingInstanceTypeLenientWarns9814(t *testing.T) {
	for _, typ := range []string{"forwardng", "bogus", "no-forwarding", "l2vpn", "vpls"} {
		tree := tree9814(t, "set routing-instances V9814 instance-type "+typ)
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("lenient compile of instance-type %q rejected (#1960 no-brick): %v", typ, err)
		}
		joined := strings.Join(cfg.Warnings, "\n")
		if !strings.Contains(joined, typ) || !strings.Contains(joined, "#9814") {
			t.Errorf("lenient compile of instance-type %q warned nothing naming the value (#9814); warnings=%v", typ, cfg.Warnings)
		}
		// Lenient posture pin: the raw value stays live as a VRF (#1319 —
		// already-running state keeps compiling "the same way today"; no
		// inert posture exists since "" IS a VRF). A later change that
		// quarantines or clamps here breaks running VRFs on upgrade.
		if len(cfg.RoutingInstances) != 1 || cfg.RoutingInstances[0].InstanceType != typ {
			t.Errorf("lenient compile of instance-type %q: want 1 instance keeping raw value, got %+v", typ, cfg.RoutingInstances)
		}
	}
	for _, tc := range []struct {
		name  string
		lines []string
	}{
		{"forwarding", []string{"set routing-instances V9814 instance-type forwarding"}},
		{"virtual-router", []string{"set routing-instances V9814 instance-type virtual-router"}},
		{"vrf", []string{"set routing-instances V9814 instance-type vrf"}},
		{"omitted", []string{"set routing-instances V9814 interface ge-0/0/0.0"}},
	} {
		tree := tree9814(t, tc.lines...)
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("lenient compile of %s instance: %v", tc.name, err)
		}
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "#9814") {
				t.Errorf("lenient compile of %s instance carries a #9814 warning: %q", tc.name, w)
			}
		}
	}
}

// Member 2: the three L3VPN statements stay accepted (never rejected — #9323)
// but warn #9374-style on BOTH paths, since xpf compiles no BGP/MPLS VPN
// state from them.
func TestRoutingInstanceVpnStatementsWarn9814(t *testing.T) {
	cases := []struct {
		kw   string
		set  string
		body string
	}{
		{"vrf-target", "set routing-instances V9814 vrf-target target:65001:100", "vrf-target target:65001:100;"},
		{"vrf-table-label", "set routing-instances V9814 vrf-table-label", "vrf-table-label;"},
		{"route-distinguisher", "set routing-instances V9814 route-distinguisher 65001:100", "route-distinguisher 65001:100;"},
	}
	check := func(t *testing.T, path string, cfg *Config, kw string) {
		t.Helper()
		joined := strings.Join(cfg.Warnings, "\n")
		if !strings.Contains(joined, kw) || !strings.Contains(joined, "ACCEPTED but NOT APPLIED") || !strings.Contains(joined, "#9814") {
			t.Errorf("%s: want a #9374-style ACCEPTED-but-NOT-APPLIED warning naming %q; warnings=%v", path, kw, cfg.Warnings)
		}
	}
	for _, tc := range cases {
		t.Run(tc.kw+"/set", func(t *testing.T) {
			tree := tree9814(t,
				"set routing-instances V9814 instance-type vrf",
				tc.set,
			)
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("strict compile rejected %s (must stay accepted per #9323): %v", tc.kw, err)
			}
			check(t, "strict", cfg, tc.kw)
			lcfg, err := CompileConfigLenient(tree9814(t,
				"set routing-instances V9814 instance-type vrf",
				tc.set,
			))
			if err != nil {
				t.Fatalf("lenient compile rejected %s: %v", tc.kw, err)
			}
			check(t, "lenient", lcfg, tc.kw)
		})
		t.Run(tc.kw+"/braced", func(t *testing.T) {
			cfg, err := CompileConfig(braced9814(t, "instance-type vrf; "+tc.body))
			if err != nil {
				t.Fatalf("strict compile rejected %s (must stay accepted per #9323): %v", tc.kw, err)
			}
			check(t, "strict", cfg, tc.kw)
			lcfg, err := CompileConfigLenient(braced9814(t, "instance-type vrf; "+tc.body))
			if err != nil {
				t.Fatalf("lenient compile rejected %s: %v", tc.kw, err)
			}
			check(t, "lenient", lcfg, tc.kw)
		})
	}
}

// Round 2 (review item 1): explicitly-EMPTY is malformed, genuinely-OMITTED
// is the silent VRF default. The old `== ""` skip conflated them: a stray
// `instance-type ""` nested under untyped `description` is hoisted by #9792
// and OVERWRITES a valid value (the `compileRoutingInstances` switch is
// last-wins), then skipped the gate on both paths — silently creating a VRF
// instead of forwarding. The `instanceTypeExplicit9814` flag preserves the
// distinction through compilation.
func TestRoutingInstanceTypeExplicitEmptyRejected9814(t *testing.T) {
	parse := func(t *testing.T, text string) *ConfigTree {
		t.Helper()
		tree, perrs := NewParser(text).Parse()
		if len(perrs) > 0 {
			t.Fatalf("fixture must parse: %v", perrs)
		}
		return tree
	}
	t.Run("nested-empty-overwrites-forwarding", func(t *testing.T) {
		text := `routing-instances { V9814 { instance-type forwarding; description x { instance-type ""; } } }`
		if _, err := CompileConfig(parse(t, text)); err == nil {
			t.Errorf("CompileConfig accepted nested instance-type \"\" overwriting forwarding; want rejection")
		} else if !strings.Contains(err.Error(), "#9814") {
			t.Errorf("nested-empty rejection lacks #9814 marker (wrong gate?): %v", err)
		}
		lcfg, err := CompileConfigLenient(parse(t, text))
		if err != nil {
			t.Fatalf("lenient compile rejected nested empty (#1960 no-brick): %v", err)
		}
		if joined := strings.Join(lcfg.Warnings, "\n"); !strings.Contains(joined, "#9814") {
			t.Errorf("lenient compile of nested empty warned nothing (#9814); warnings=%v", lcfg.Warnings)
		}
	})
	t.Run("direct-empty", func(t *testing.T) {
		text := `routing-instances { V9814 { instance-type ""; } }`
		if err := SchemaValidate(parse(t, text), nil); err == nil {
			t.Errorf("SchemaValidate accepted direct instance-type \"\"; want rejection")
		}
		if _, err := CompileConfig(parse(t, text)); err == nil {
			t.Errorf("CompileConfig accepted direct instance-type \"\"; want rejection")
		}
		lcfg, err := CompileConfigLenient(parse(t, text))
		if err != nil {
			t.Fatalf("lenient compile rejected direct empty: %v", err)
		}
		if joined := strings.Join(lcfg.Warnings, "\n"); !strings.Contains(joined, "#9814") {
			t.Errorf("lenient compile of direct empty warned nothing (#9814); warnings=%v", lcfg.Warnings)
		}
	})
	t.Run("valueless", func(t *testing.T) {
		text := `routing-instances { V9814 { instance-type; } }`
		if err := SchemaValidate(parse(t, text), nil); err == nil {
			t.Errorf("SchemaValidate accepted valueless instance-type; want rejection")
		}
		if _, err := CompileConfig(parse(t, text)); err == nil {
			t.Errorf("CompileConfig accepted valueless instance-type; want rejection")
		}
		lcfg, err := CompileConfigLenient(parse(t, text))
		if err != nil {
			t.Fatalf("lenient compile rejected valueless instance-type: %v", err)
		}
		if joined := strings.Join(lcfg.Warnings, "\n"); !strings.Contains(joined, "#9814") {
			t.Errorf("lenient compile of valueless instance-type warned nothing (#9814); warnings=%v", lcfg.Warnings)
		}
	})
}

// Round 2 (review item 3): the type gate reads post-expansion effective
// values, so every authoring shape reaches it. Elided shapes ARE asserted
// through direct `SchemaValidate`: it normalizes via
// normalizeCompactForValidation → normalizeElidedRoutingInstance9620
// (schema_walk.go, compact_normalize_8662.go) before walking, so the enum
// fires there too. Groups-inherited bogus stays `CompileConfig`-only:
// merging group bodies requires group expansion, which direct
// `SchemaValidate` does not perform. The operator commit path is pinned
// separately via `CheckText` legs in pkg/configstore (elided included).
func TestRoutingInstanceTypeShapes9814(t *testing.T) {
	t.Run("elided-bogus-rejects", func(t *testing.T) {
		tree, perrs := NewParser("routing-instances { V9814 instance-type bogus; }").Parse()
		if len(perrs) > 0 {
			t.Fatalf("fixture must parse: %v", perrs)
		}
		if err := SchemaValidate(tree, nil); err == nil {
			t.Errorf("SchemaValidate accepted elided instance-type bogus; want rejection")
		} else if !strings.Contains(err.Error(), "bogus") || !strings.Contains(err.Error(), "#9814") {
			t.Errorf("elided SchemaValidate rejection lacks the value, the #9814 marker, or both: %v", err)
		}
		if _, err := CompileConfig(tree); err == nil {
			t.Errorf("CompileConfig accepted elided instance-type bogus; want rejection")
		} else if !strings.Contains(err.Error(), "#9814") {
			t.Errorf("elided-bogus rejection lacks #9814 marker: %v", err)
		}
	})
	t.Run("groups-inherited-bogus-rejects", func(t *testing.T) {
		tree := tree9814(t,
			"set groups G routing-instances V9814 instance-type bogus",
			"set routing-instances V9814 interface ge-0/0/0.0",
			"set routing-instances apply-groups G",
		)
		if _, err := CompileConfig(tree); err == nil {
			t.Errorf("CompileConfig accepted groups-inherited instance-type bogus; want rejection")
		} else if !strings.Contains(err.Error(), "#9814") {
			t.Errorf("groups-inherited rejection lacks #9814 marker: %v", err)
		}
	})
	t.Run("elided-lenient-warns", func(t *testing.T) {
		tree, perrs := NewParser("routing-instances { V9814 instance-type bogus; }").Parse()
		if len(perrs) > 0 {
			t.Fatalf("fixture must parse: %v", perrs)
		}
		lcfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("lenient compile rejected elided bogus (#1960 no-brick): %v", err)
		}
		if joined := strings.Join(lcfg.Warnings, "\n"); !strings.Contains(joined, "bogus") || !strings.Contains(joined, "#9814") {
			t.Errorf("lenient compile of elided bogus warned nothing naming the value; warnings=%v", lcfg.Warnings)
		}
	})
}

// Round 2 (review item 6): valid configurations are silent on the STRICT
// path too (the lenient silence loop lives in `TestRoutingInstanceTypeLenientWarns9814`).
func TestRoutingInstanceTypeStrictSilentOnValid9814(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"forwarding", "instance-type forwarding;"},
		{"virtual-router", "instance-type virtual-router;"},
		{"vrf", "instance-type vrf;"},
		{"omitted", "interface ge-0/0/0.0;"},
	} {
		cfg, err := CompileConfig(braced9814(t, tc.body))
		if err != nil {
			t.Fatalf("strict compile rejected %s instance: %v", tc.name, err)
		}
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "#9814") {
				t.Errorf("strict compile of %s instance carries a #9814 warning: %q", tc.name, w)
			}
		}
	}
}

// Round 2 (review item 5): per-occurrence pin. Repeats with distinct values
// are legitimate Junos, so each occurrence warns (keyword-only: values are
// shape-complex — bracket lists, block forms, multi-token — and the inert
// STATEMENT is the actionable signal).
func TestRoutingInstanceVpnRepeatWarnsPerOccurrence9814(t *testing.T) {
	cfg, err := CompileConfig(braced9814(t, "instance-type vrf; vrf-target target:A; vrf-target target:B;"))
	if err != nil {
		t.Fatalf("strict compile rejected repeated vrf-target (must stay accepted per #9323): %v", err)
	}
	n := 0
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "vrf-target") && strings.Contains(w, "#9814") {
			n++
		}
	}
	if n != 2 {
		t.Errorf("want exactly 2 per-occurrence vrf-target warnings, got %d: %v", n, cfg.Warnings)
	}
}

// Round 3 (review item 1): a TRUE #9792 packed sibling-leaf run — one braced
// child node whose Keys carry several statements (`instance-type bogus` +
// `interface ...` on a single packed line), split by expandFlatRun. This is
// NEITHER the #9620 brace-elided shape (normalized before compile — see
// TestRoutingInstanceTypeShapes9814) NOR the nested-hoist branch (children
// under another leaf — see the nested-empty subtest): packedOrNestedLeafRun9792
// takes the packed Keys>2 arm here and declines it there.
func TestRoutingInstanceTypePackedWarns9814(t *testing.T) {
	text := `routing-instances { V9814 { instance-type bogus interface ge-0/0/0.0; } }`
	parse := func(t *testing.T) *ConfigTree {
		t.Helper()
		tree, perrs := NewParser(text).Parse()
		if len(perrs) > 0 {
			t.Fatalf("fixture must parse: %v", perrs)
		}
		return tree
	}
	if _, err := CompileConfig(parse(t)); err == nil {
		t.Errorf("CompileConfig accepted packed instance-type bogus; want rejection")
	} else if !strings.Contains(err.Error(), "#9814") {
		t.Errorf("packed rejection lacks #9814 marker (wrong gate?): %v", err)
	}
	lcfg, err := CompileConfigLenient(parse(t))
	if err != nil {
		t.Fatalf("lenient compile rejected packed bogus (#1960 no-brick): %v", err)
	}
	if joined := strings.Join(lcfg.Warnings, "\n"); !strings.Contains(joined, "bogus") || !strings.Contains(joined, "#9814") {
		t.Errorf("lenient compile of packed bogus warned nothing naming the value; warnings=%v", lcfg.Warnings)
	}
	if len(lcfg.RoutingInstances) != 1 {
		t.Fatalf("lenient compile of packed bogus: want 1 instance, got %+v", lcfg.RoutingInstances)
	}
	if lcfg.RoutingInstances[0].InstanceType != "bogus" {
		t.Errorf("lenient compile of packed bogus: want raw value kept, got %+v", lcfg.RoutingInstances)
	}
	if got := lcfg.RoutingInstances[0].Interfaces; len(got) != 1 || got[0] != "ge-0/0/0.0" {
		t.Errorf("packed run split lost the sibling leaf: interfaces=%v", got)
	}
}

// Round 3 (review item 8/advisory): defense-in-depth for externally or
// manually assembled configs. The compiler always sets
// `instanceTypeExplicit9814` when authoring a type, so a hand-built
// `RoutingInstanceConfig` carrying a non-empty invalid type must still be
// rejected (skip applies ONLY to genuine omission: !Explicit AND empty).
func TestRoutingInstanceTypeHandAssembledBogusRejected9814(t *testing.T) {
	bogus := &Config{RoutingInstances: []*RoutingInstanceConfig{{Name: "V9814", InstanceType: "bogus"}}}
	if err := validateRoutingInstanceTypeStrict9814(bogus); err == nil {
		t.Errorf("gate accepted hand-assembled InstanceType bogus; want rejection")
	} else if !strings.Contains(err.Error(), "bogus") || !strings.Contains(err.Error(), "#9814") {
		t.Errorf("hand-assembled rejection lacks the value, the #9814 marker, or both: %v", err)
	}
	omitted := &Config{RoutingInstances: []*RoutingInstanceConfig{{Name: "V9814"}}}
	if err := validateRoutingInstanceTypeStrict9814(omitted); err != nil {
		t.Errorf("gate rejected hand-assembled omitted type (must stay silent): %v", err)
	}
	for _, typ := range []string{"forwarding", "virtual-router", "vrf"} {
		valid := &Config{RoutingInstances: []*RoutingInstanceConfig{{Name: "V9814", InstanceType: typ}}}
		if err := validateRoutingInstanceTypeStrict9814(valid); err != nil {
			t.Errorf("gate rejected hand-assembled valid type %q: %v", typ, err)
		}
	}
}
