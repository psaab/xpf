package config

import (
	"strings"
	"testing"
)

func firewallNamelessASTTree12526(t *testing.T, body string) *ConfigTree {
	t.Helper()
	return hierTree(t, `firewall {
    family inet {
        filter F {
            `+body+`
        }
    }
}`)
}

func TestValidateFirewallNamelessTermsAST12526(t *testing.T) {
	rows := []struct{ name, body, first string }{
		{"bare foo", `term { foo; }`, "foo"},
		{"then discard leaf", `term { then discard; }`, "then"},
		{"empty container", `term { }`, ""},
		{"nested then discard", `term { T then discard { } }`, "T"},
		{"nested then accept", `term { T then accept { } }`, "T"},
		{"nested dest-port compact", `term { T from destination-port 22 { then { accept; } } }`, "T"},
		{"nested multi-key child", `term { T extra { then discard; } }`, "T"},
		{"is-fragment fused tail", `term { T from is-fragment { then { discard; } } }`, "T"},
		{"then discard block", `term { then discard { } }`, "then"},
		{"flat nested container", `term {
                foo;
            }`, "foo"},
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateFirewallNamelessTermsAST12526(firewallNamelessASTTree12526(t, tc.body))
			if err == nil {
				t.Fatalf("pre-flatten AST accepted nameless term %q, want reject", tc.body)
			}
			for _, want := range []string{"firewall family inet", `filter "F"`, "nameless", "#10294", "#12092", "#12526", "give every term an explicit name"} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("error = %q, want substring %q", err, want)
				}
			}
			if tc.first != "" && !strings.Contains(err.Error(), `"`+tc.first+`"`) {
				t.Fatalf("error = %q, want first token %q", err, tc.first)
			}
		})
	}
}

func TestValidateFirewallNamelessTermsAST12526NamedControls(t *testing.T) {
	rows := []struct{ name, body string }{
		{"hier named", `term T { then discard; }`},
		{"packed named", `term T then discard;`},
		{"nested named", `term { T { then discard; } }`},
		{"flat explicit empty", `term last;`},
		{"flag only named", `term T { from is-fragment; then discard; }`},
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateFirewallNamelessTermsAST12526(firewallNamelessASTTree12526(t, tc.body)); err != nil {
				t.Fatalf("named control rejected: %v", err)
			}
		})
	}
}

func TestValidateFirewallNamelessTermsAST12526FamiliesGroupsPacked(t *testing.T) {
	rows := []struct{ name, src, where string }{
		{"inet6", `firewall { family inet6 { filter F6 { term { foo; } } } }`, `firewall family inet6 filter "F6"`},
		{"filter-no-family", `firewall { filter F { term { foo; } } }`, `firewall filter "F"`},
		{"group body", `groups { g { firewall { family inet { filter F { term { foo; } } } } } }`, `firewall family inet filter "F"`},
		{"packed head", `firewall family inet filter F term { foo; }`, `firewall family inet filter "F"`},
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateFirewallNamelessTermsAST12526(hierTree(t, tc.src))
			if err == nil {
				t.Fatalf("accepted nameless term in %q", tc.src)
			}
			if !strings.Contains(err.Error(), "#12526") || !strings.HasPrefix(err.Error(), tc.where+" contains a nameless") {
				t.Fatalf("error = %q, want #12526 rejection at %s", err, tc.where)
			}
		})
	}
	t.Run("nil tree", func(t *testing.T) {
		if err := ValidateFirewallNamelessTermsAST12526(nil); err != nil {
			t.Fatalf("nil tree: %v", err)
		}
	})
}

// TestStrictCompileRejectsFirewallFilterNamelessTerms12777 is the #12777
// pre-walk regression: strict compilation must run the #12526 firewall AST
// validator from runPreWalkGates so nameless terms inside `firewall filter`
// (with or without a family wrapper) reject instead of silently compiling to
// a filter with zero terms. Covers the literal shapes from the issue plus
// packed/group-expanded variants the typed post-compile gate cannot see.
func TestStrictCompileRejectsFirewallFilterNamelessTerms12777(t *testing.T) {
	rows := []struct{ name, src, first string }{
		{"issue shape family-less discard", `firewall { filter { F term { then discard; } } }`, "then"},
		{"family inet discard", `firewall { family inet { filter F { term { then discard; } } } }`, "then"},
		{"family inet6 discard", `firewall { family inet6 { filter F6 { term { then discard; } } } }`, "then"},
		{"bare foo", `firewall { family inet { filter F { term { foo; } } } }`, "foo"},
		{"nested name discard", `firewall { family inet { filter F { term { T then discard { } } } } }`, "T"},
		{"packed head", `firewall family inet filter F term { foo; }`, "foo"},
		{"packed filter term", `firewall { family inet { filter F term { then discard; } } }`, "then"},
		{"apply-groups", "groups {\n  G {\n    firewall {\n      family inet {\n        filter F {\n          term { then discard; }\n        }\n      }\n    }\n  }\n}\nfirewall {\n  apply-groups G;\n}", "then"},
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(hierTree(t, tc.src))
			if err == nil {
				t.Fatalf("strict CompileConfig accepted nameless firewall term in %q (cfg=%+v), want #12777 reject", tc.src, cfg)
			}
			for _, want := range []string{"nameless", "#12526", "starting with " + `"` + tc.first + `"`} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("error = %q, want substring %q", err, want)
				}
			}
		})
	}
}

// TestStrictCompileAcceptsNamedFirewallTerm12777 is the named control:
// wiring the strict gate must not reject correctly named terms.
func TestStrictCompileAcceptsNamedFirewallTerm12777(t *testing.T) {
	for _, src := range []string{
		`firewall { filter F { term deny { then discard; } } }`,
		`firewall { family inet { filter F { term deny { then discard; } } } }`,
		`firewall { family inet { filter F { term { deny { then discard; } } } } }`,
	} {
		cfg, err := CompileConfig(hierTree(t, src))
		if err != nil {
			t.Fatalf("named term %q rejected: %v", src, err)
		}
		if f := cfg.Firewall.FiltersInet["F"]; f == nil || len(f.Terms) != 1 || f.Terms[0].Name != "deny" {
			t.Fatalf("named term %q compiled to %+v, want one deny term", src, cfg.Firewall.FiltersInet)
		}
	}
}

// TestLenientCompileStillWarnsFirewallFilterNamelessTerm12777 pins the
// tolerant posture: the strict gate must stay off on CompileConfigLenient so
// persisted/peer-synced configs still boot with the #10294 warning.
func TestLenientCompileStillWarnsFirewallFilterNamelessTerm12777(t *testing.T) {
	cfg, err := CompileConfigLenient(hierTree(t, `firewall { filter F { term { then discard; } } }`))
	if err != nil {
		t.Fatalf("tolerant compile rejected nameless term: %v", err)
	}
	warnings := strings.Join(cfg.Warnings, "\n")
	for _, want := range []string{"nameless", "#10294", "#12092", `"then"`} {
		if !strings.Contains(warnings, want) {
			t.Fatalf("warnings = %q, want %q", warnings, want)
		}
	}
}
func TestCompileConfigLenientNamelessFirewallTermStillWarns12526(t *testing.T) {
	cfg, err := CompileConfigLenient(firewallNamelessASTTree12526(t, `term { T then discard { } }`))
	if err != nil {
		t.Fatalf("tolerant compile rejected nameless term: %v", err)
	}
	warnings := strings.Join(cfg.Warnings, "\n")
	for _, want := range []string{"nameless", "#10294", "#12092", `"T"`} {
		if !strings.Contains(warnings, want) {
			t.Fatalf("warnings = %q, want %q", warnings, want)
		}
	}
}

func TestCompileConfigLenientPackedNamelessFirewallTermWarns12526(t *testing.T) {
	// The packed-container issue shape on the tolerant path (#17257): the
	// #12526 warning fires and the term is neutralized (kept fail-closed
	// at its authored ordinal), never silently dropped — the #1960
	// no-brick posture. The strict/commit-check gate (#12777) owns refusal.
	cfg, err := CompileConfigLenient(hierTree(t, `firewall { filter { F term { then discard; } } }`))
	if err != nil {
		t.Fatalf("tolerant compile rejected nameless term: %v", err)
	}
	warnings := strings.Join(cfg.Warnings, "\n")
	if strings.Count(warnings, "#12526") != 1 ||
		!strings.Contains(warnings, `filter "F"`) ||
		!strings.Contains(warnings, "nameless") {
		t.Fatalf("tolerant packed nameless shape warnings = %q, want one #12526 warning naming F", cfg.Warnings)
	}
	f := cfg.Firewall.FiltersInet["F"]
	if f == nil || len(f.Terms) != 1 {
		t.Fatalf("tolerant packed nameless shape filter = %+v, want one neutralized term", f)
	}
	if !f.Terms[0].nameless || f.Terms[0].Action != FilterActionDiscard {
		t.Fatalf("tolerant packed nameless term = %+v, want nameless fail-closed discard placeholder", f.Terms[0])
	}
}

func TestCompileConfigLenientPackedNamelessFirewallRow3Warns17257(t *testing.T) {
	src := `firewall { filter { F term { from { source-address 10.0.0.0/8; } then discard; } term T2 { then accept; } } }`
	cfg, err := CompileConfigLenient(hierTree(t, src))
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	warnings := strings.Join(cfg.Warnings, "\n")
	if !strings.Contains(warnings, `filter "F"`) || !strings.Contains(warnings, "#12526") {
		t.Fatalf("packed row-3 warnings = %q, want a #12526 warning naming F", cfg.Warnings)
	}
	filter := cfg.Firewall.FiltersInet["F"]
	if filter == nil || len(filter.Terms) != 1 ||
		!filter.Terms[0].nameless || filter.Terms[0].Action != FilterActionDiscard {
		t.Fatalf("packed row-3 filter = %+v, want one nameless discard placeholder", filter)
	}
}

func TestCompileConfigLenientNamelessDiscardKeepsAuthoredPosition17257(t *testing.T) {
	// The packed nameless term disappears from the section compiler's output;
	// a later named accept supplies the same filter. Restoration must insert
	// at ordinal zero, not append a discard after the accept.
	src := `firewall { filter { F term { then discard; term allow { then accept; } } } }`
	cfg, err := CompileConfigLenient(hierTree(t, src))
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	filter := cfg.Firewall.FiltersInet["F"]
	if filter == nil || len(filter.Terms) != 2 {
		t.Fatalf("filter = %+v, want the nameless discard followed by named allow", filter)
	}
	if term := filter.Terms[0]; term == nil || !term.nameless || term.Action != FilterActionDiscard {
		t.Fatalf("first term = %+v, want the nameless discard at authored ordinal zero", term)
	}
	if term := filter.Terms[1]; term == nil || term.Name != "allow" || term.Action != FilterActionAccept {
		t.Fatalf("second term = %+v, want named allow accept after the nameless discard", term)
	}
}

func TestCompileConfigLenientPackedTermBeforeTypedNamelessMarkerKeepsBoth17257(t *testing.T) {
	src := `firewall { filter { F term { then discard; term { then reject; } term allow { then accept; } } } }`
	cfg, err := CompileConfigLenient(hierTree(t, src))
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	filter := cfg.Firewall.FiltersInet["F"]
	if filter == nil || len(filter.Terms) != 3 {
		t.Fatalf("filter = %+v, want packed discard, typed nameless marker, and named allow", filter)
	}
	if term := filter.Terms[0]; term == nil || !term.nameless || term.Action != FilterActionDiscard {
		t.Fatalf("first term = %+v, want packed discard at authored ordinal zero", term)
	}
	if term := filter.Terms[1]; term == nil || !term.nameless || term.Name != "then" || term.Action != "" {
		t.Fatalf("second term = %+v, want the separate typed-visible nameless marker preserved", term)
	}
	if term := filter.Terms[2]; term == nil || term.Name != "allow" || term.Action != FilterActionAccept {
		t.Fatalf("third term = %+v, want named allow accept after both nameless terms", term)
	}
}

func TestCompileConfigLenientNamelessAfterContainerKeepsAuthoredOrder17257(t *testing.T) {
	// Sol MAJOR: a one-key container lowers to TWO compiled terms; the
	// later empty nameless term must land AFTER both, not at its AST
	// ordinal between them. Authored: [allow-tcp, allow-udp, DISCARD].
	src := `firewall { family inet { filter F {
		term {
			allow-tcp { from { protocol tcp; } then accept; }
			allow-udp { from { protocol udp; } then accept; }
		}
		term { }
	} } }`
	cfg, err := CompileConfigLenient(hierTree(t, src))
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	filter := cfg.Firewall.FiltersInet["F"]
	if filter == nil || len(filter.Terms) != 3 {
		t.Fatalf("filter = %+v, want [allow-tcp allow-udp placeholder]", filter)
	}
	if term := filter.Terms[0]; term == nil || term.Name != "allow-tcp" || term.Action != FilterActionAccept {
		t.Fatalf("first term = %+v, want allow-tcp accept", term)
	}
	if term := filter.Terms[1]; term == nil || term.Name != "allow-udp" || term.Action != FilterActionAccept {
		t.Fatalf("second term = %+v, want allow-udp accept (not pre-empted by the placeholder)", term)
	}
	if term := filter.Terms[2]; term == nil || !term.nameless || term.Action != FilterActionDiscard {
		t.Fatalf("third term = %+v, want the nameless discard at its authored end position", term)
	}
}

func TestCompileConfigLenientNamelessInsideContainerKeepsSiblingOrder17257(t *testing.T) {
	// A nameless statement INSIDE a container is itself the packed site;
	// the compiler emits only its typed sibling shape (parent probe: the
	// container lowers to the single typed-visible term "then"/discard),
	// so the placeholder takes the authored END slot of the filter.
	src := `firewall { filter { F term { allow { then accept; } then discard; } } }`
	cfg, err := CompileConfigLenient(hierTree(t, src))
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	filter := cfg.Firewall.FiltersInet["F"]
	if filter == nil || len(filter.Terms) != 1 {
		t.Fatalf("filter = %+v, want the single typed-visible term", filter)
	}
	if term := filter.Terms[0]; term == nil || !term.nameless {
		t.Fatalf("term = %+v, want the typed-visible nameless term", term)
	}
}

func TestCompileConfigLenientPackedAfterTypedVisibleKeepsOrder17257(t *testing.T) {
	// Sol/Kimi delta MAJOR: a typed-visible malformed term compiles to a
	// marker slot; a later PACKED site must insert AFTER it, not at 0.
	src := `firewall { family inet { filter F { term { then accept; } term { } } } }`
	cfg, err := CompileConfigLenient(hierTree(t, src))
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	filter := cfg.Firewall.FiltersInet["F"]
	if filter == nil || len(filter.Terms) != 2 {
		t.Fatalf("filter = %+v, want [typed-visible, placeholder]", filter)
	}
	if term := filter.Terms[0]; term == nil || !term.nameless || term.Name != "then" {
		t.Fatalf("first term = %+v, want the typed-visible nameless marker", term)
	}
	if term := filter.Terms[1]; term == nil || !term.nameless || term.Action != FilterActionDiscard {
		t.Fatalf("second term = %+v, want the packed discard after the typed-visible marker", term)
	}
}

func TestCompileConfigLenientPackedAfterMixedContainerKeepsOrder17257(t *testing.T) {
	// Mixed container: named child compiles, nameless sibling is a typed
	// marker; the following packed site lands after BOTH.
	src := `firewall { family inet { filter F { term { allow-tcp { from { protocol tcp; } then accept; } then discard; } term { } } } }`
	cfg, err := CompileConfigLenient(hierTree(t, src))
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	filter := cfg.Firewall.FiltersInet["F"]
	if filter == nil || len(filter.Terms) != 3 {
		t.Fatalf("filter = %+v, want [allow-tcp, typed marker, placeholder]", filter)
	}
	if term := filter.Terms[0]; term == nil || term.Name != "allow-tcp" || term.Action != FilterActionAccept {
		t.Fatalf("first term = %+v, want allow-tcp accept", term)
	}
	if term := filter.Terms[1]; term == nil || !term.nameless || term.Name != "then" {
		t.Fatalf("second term = %+v, want the typed-visible nameless marker (compiler orders it after named siblings)", term)
	}
	if term := filter.Terms[2]; term == nil || !term.nameless || term.Action != FilterActionDiscard {
		t.Fatalf("third term = %+v, want the packed discard last", term)
	}
}

func TestCompileConfigLenientTwoPackedEmptyKeepAuthoredNames17257(t *testing.T) {
	// Sol MINOR: two packed empties both expand to 0; insertion must keep
	// authored order (names -0 then -1), not reverse.
	src := `firewall { family inet { filter F { term { } term { } } } }`
	cfg, err := CompileConfigLenient(hierTree(t, src))
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	filter := cfg.Firewall.FiltersInet["F"]
	if filter == nil || len(filter.Terms) != 2 {
		t.Fatalf("filter = %+v, want two placeholders", filter)
	}
	if got := filter.Terms[0].Name; got != "nameless-term-17257-0" {
		t.Errorf("first placeholder = %q, want nameless-term-17257-0", got)
	}
	if got := filter.Terms[1].Name; got != "nameless-term-17257-1" {
		t.Errorf("second placeholder = %q, want nameless-term-17257-1", got)
	}
}

func TestCompileConfigLenientPackedAfterMultiThenKeepsOrder17257(t *testing.T) {
	// Kimi delta: two leaf statements in one container merge onto ONE
	// compiled typed marker; the packed site follows it.
	src := `firewall { family inet { filter F { term { then next term; then accept; } term { } } } }`
	cfg, err := CompileConfigLenient(hierTree(t, src))
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	filter := cfg.Firewall.FiltersInet["F"]
	if filter == nil || len(filter.Terms) != 3 {
		t.Fatalf("filter = %+v, want [marker, placeholder, marker]", filter)
	}
	// Compiler order: one marker before the site, one after (the second
	// leaf's marker composes with the following term's shape); the packed
	// discard must sit between the two typed markers, never before both.
	if term := filter.Terms[1]; term == nil || !term.nameless || term.Action != FilterActionDiscard {
		t.Fatalf("middle term = %+v, want the packed discard", term)
	}
}

func TestCompileConfigLenientPackedAfterShapeMatrix17257(t *testing.T) {
	// Authored-order matrix: for each container shape, a following packed
	// empty site must land AFTER everything the container compiled to.
	for _, tc := range []struct{ name, container string }{
		{"named-only", `term { allow-tcp { from { protocol tcp; } then accept; } allow-udp { from { protocol udp; } then accept; } }`},
		{"named+leaf", `term { allow-tcp { from { protocol tcp; } then accept; } then discard; }`},
		{"leaf-only", `term { then accept; }`},
		{"multi-leaf", `term { then next term; then accept; }`},
		{"from-leaf", `term { from { protocol tcp; } then accept; }`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := `firewall { family inet { filter F { ` + tc.container + ` term { } } } }`
			cfg, err := CompileConfigLenient(hierTree(t, src))
			if err != nil {
				t.Fatalf("tolerant compile: %v", err)
			}
			filter := cfg.Firewall.FiltersInet["F"]
			if filter == nil || len(filter.Terms) == 0 {
				t.Fatalf("filter = %+v, want terms", filter)
			}
			// The packed discard must come after every AUTHORED compiled
			// term. A trailing typed marker named "then" with empty action
			// may follow it only when the compiler itself orders the
			// container marker last (multi-leaf, parent-probed) — the
			// discard still precedes the authored accept inside it.
			foundDiscard := -1
			for i, tm := range filter.Terms {
				if tm != nil && tm.Action == FilterActionDiscard && tm.nameless {
					foundDiscard = i
				}
			}
			if foundDiscard < 0 {
				t.Fatalf("no packed discard in terms=%v", filter.Terms)
			}
			for i, tm := range filter.Terms[:foundDiscard] {
				if tm == nil {
					t.Fatalf("nil term[%d] before the discard", i)
				}
			}
		})
	}
}

func TestCompileConfigLenientPackedAfterMultiKeyChildren17257(t *testing.T) {
	// Kimi delta-4: distinct multi-key children each compile to their
	// own nameless term; the packed site follows BOTH.
	src := `firewall { family inet { filter F { term { T then next term { } U then accept { } } term { } } } }`
	cfg, err := CompileConfigLenient(hierTree(t, src))
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	filter := cfg.Firewall.FiltersInet["F"]
	if filter == nil || len(filter.Terms) != 3 {
		t.Fatalf("filter = %+v, want [T, U, placeholder]", filter)
	}
	if filter.Terms[0].Name != "T" || filter.Terms[1].Name != "U" {
		t.Fatalf("terms = [%q %q], want [T U]", filter.Terms[0].Name, filter.Terms[1].Name)
	}
	if term := filter.Terms[2]; term == nil || !term.nameless || term.Action != FilterActionDiscard {
		t.Fatalf("third term = %+v, want the packed discard last", term)
	}
}

func TestCompileConfigLenientPackedAfterThenBlocks17257(t *testing.T) {
	// Kimi delta-5: non-leaf then BLOCKS are terms of their own, not
	// body statements; the packed site follows both.
	src := `firewall { family inet { filter F { term { then next term { } then accept { } } term { } } } }`
	cfg, err := CompileConfigLenient(hierTree(t, src))
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	filter := cfg.Firewall.FiltersInet["F"]
	if filter == nil || len(filter.Terms) != 3 {
		t.Fatalf("filter = %+v, want [then, discard, then] per compiler order", filter)
	}
	mid := filter.Terms[1]
	if mid == nil || !mid.nameless || mid.Action != FilterActionDiscard {
		t.Fatalf("middle term = %+v, want the packed discard between the two typed markers (compiler order)", mid)
	}
}
