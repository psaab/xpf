package config

import (
	"strings"
	"testing"
)

// #9875: the tolerant-path record half of the FromUnrepresentable channel.
//
// A `from` match leaf the dataplane cannot enforce must not widen the term.
// Whole-leaf drops hit compileFilterFrom's default arm (term.UnknownFrom,
// #3307); valueless value-bearing leaves (`from protocol;`, #8480) compile
// to the byte-identical empty match set the omitted form produces. The
// strict gates reject both; on the tolerant load / peer-sync path they
// downgrade to warnings — and, as of this change, the compiled term carries
// the record (UnknownFrom / ValuelessFrom) the snapshot builder, the lo0
// mirror and the PBR classifier fail closed on.

func fwTree9875(t *testing.T, filterBody string) *ConfigTree {
	t.Helper()
	src := `firewall { family inet { filter F { ` + filterBody + ` } } }`
	tree, perrs := NewParser(src).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture did not parse: %v", perrs)
	}
	return tree
}

// fwSplitTree9875 wraps a filter body in the set-command family shape
// (`family { inet { ... } }`) the compiler descends into (GPT-1). The
// strict gate must walk it too — skipping the family-name child lets a
// valueless leaf commit while compilation records the marker.
func fwSplitTree9875(t *testing.T, filterBody string) *ConfigTree {
	t.Helper()
	src := `firewall { family { inet { filter F { ` + filterBody + ` } } } }`
	tree, perrs := NewParser(src).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture did not parse: %v", perrs)
	}
	return tree
}

// fwRawTree9875 parses a complete config source (for shapes the filter-body
// wrappers cannot express: nested instance names, policy-options siblings,
// non-inet families).
func fwRawTree9875(t *testing.T, src string) *ConfigTree {
	t.Helper()
	tree, perrs := NewParser(src).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture did not parse: %v", perrs)
	}
	return tree
}

// TestFilterValuelessFromRecordedLenient9875 pins the ValuelessFrom record:
// every valueless spelling the #8480 strict gate rejects must leave the
// leaf name on the leniently-compiled term (the marker the dataplane fails
// closed on), with the match set empty exactly as before.
func TestFilterValuelessFromRecordedLenient9875(t *testing.T) {
	rows := []struct {
		name string
		mk   func(*testing.T) *ConfigTree
		leaf string
	}{
		{"braced", func(t *testing.T) *ConfigTree {
			return fwTree9875(t, `term T { from { protocol; } then { discard; } }`)
		}, "protocol"},
		{"from-packed", func(t *testing.T) *ConfigTree {
			return fwTree9875(t, `term T { from protocol; then discard; }`)
		}, "protocol"},
		{"flat-set", func(t *testing.T) *ConfigTree {
			return buildFilterTree(t,
				"set firewall family inet filter F term T from protocol",
				"set firewall family inet filter F term T then discard")
		}, "protocol"},
		{"second leaf", func(t *testing.T) *ConfigTree {
			return fwTree9875(t, `term T { from { destination-port; } then { accept; } }`)
		}, "destination-port"},
		{"two valueless leaves both recorded", func(t *testing.T) *ConfigTree {
			return fwTree9875(t, `term T { from { protocol; icmp-type; } then { discard; } }`)
		}, "protocol, icmp-type"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			tree := row.mk(t)
			// Strict still rejects (message unchanged, #8480 owns it).
			if _, err := CompileConfig(tree); err == nil {
				t.Fatalf("strict must reject valueless `from %s`", row.leaf)
			} else if !strings.Contains(err.Error(), "#8480") {
				t.Fatalf("strict error must stay the #8480 gate, got: %v", err)
			}
			// Lenient records the leaf on the term.
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient must warn, not fail: %v", err)
			}
			term := firstInetTerm(t, cfg, "F")
			got := strings.Join(term.ValuelessFrom, ", ")
			if got != row.leaf {
				t.Fatalf("ValuelessFrom = %q, want %q", got, row.leaf)
			}
		})
	}
}

// TestFilterValuelessFromControls9875 pins what must NOT record: every shape
// the #8480 gate lets commit must compile with ValuelessFrom empty —
// otherwise the marker would refuse snapshots for good configs on the
// tolerant path (a boot/sync brick).
func TestFilterValuelessFromControls9875(t *testing.T) {
	rows := []struct {
		name string
		body string
	}{
		{"valued leaf", `term T { from { protocol tcp; } then { discard; } }`},
		{"bracketed list", `term T { from { protocol [ tcp udp ]; } then { discard; } }`},
		{"omitted leaf", `term T { from { source-address 10.0.0.0/8; } then { discard; } }`},
		{"empty from block", `term T { from { } then { discard; } }`},
		{"is-fragment flag", `term T { from { is-fragment; } then { discard; } }`},
		{"flexible-match-range with children", `term T { from { flexible-match-range { match-start layer-3; byte-offset 4; } } then { discard; } }`},
		{"duplicated leaf valueless-then-valued", `term T { from { protocol; protocol tcp; } then { discard; } }`},
		{"duplicated leaf valued-then-valueless", `term T { from { protocol tcp; protocol; } then { discard; } }`},
		{"valued prefix-list ref", `term T { from { source-prefix-list PL; } then { discard; } }`},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			src := fwTree9875(t, row.body)
			// The valued-ref row needs the list defined (else the
			// dangling-ref gate, not #8480, owns the verdict).
			if strings.Contains(row.body, "source-prefix-list PL") {
				pl, perrs := NewParser(`policy-options { prefix-list PL { 10.0.0.0/8; } }`).Parse()
				if len(perrs) > 0 {
					t.Fatalf("prefix-list fixture did not parse: %v", perrs)
				}
				src.Children = append(pl.Children, src.Children...)
			}
			if _, err := CompileConfig(src); err != nil {
				t.Fatalf("control must commit, got: %v", err)
			}
			cfg, err := CompileConfigLenient(src)
			if err != nil {
				t.Fatalf("lenient must succeed: %v", err)
			}
			if got := firstInetTerm(t, cfg, "F").ValuelessFrom; len(got) > 0 {
				t.Fatalf("control must not record ValuelessFrom, got %v", got)
			}
		})
	}
}

// TestFilterSelfNamedPrefixListCommits9875 is the falsifier for the #8480
// helper's "the two readers never disagree on emptiness" claim: a defined
// prefix-list legitimately named like the leaf (quoted keyword-shaped names
// are legitimate per #9029) compiles a REAL resolving ref, so the gate must
// not call it valueless — and the #9875 marker (which shares the helper)
// must not flag it, or good configs would refuse their snapshots on the
// tolerant path.
func TestFilterSelfNamedPrefixListCommits9875(t *testing.T) {
	mk := func(t *testing.T, ref string) *ConfigTree {
		t.Helper()
		src := `policy-options { prefix-list "source-prefix-list" { 10.0.0.0/8; } }
			firewall { family inet { filter F { term T { from { source-prefix-list ` + ref + `; } then { accept; } } } } }`
		tree, perrs := NewParser(src).Parse()
		if len(perrs) > 0 {
			t.Fatalf("fixture did not parse: %v", perrs)
		}
		return tree
	}
	for _, tc := range []struct{ name, ref string }{
		{"quoted self-name", `"source-prefix-list"`},
		{"bare self-name", `source-prefix-list`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(mk(t, tc.ref))
			if err != nil {
				t.Fatalf("a resolving self-named ref must commit, got: %v", err)
			}
			term := firstInetTerm(t, cfg, "F")
			if len(term.ValuelessFrom) > 0 {
				t.Fatalf("ValuelessFrom = %v for a resolving ref", term.ValuelessFrom)
			}
			if len(term.SourcePrefixLists) != 1 || term.SourcePrefixLists[0].Name != "source-prefix-list" {
				t.Fatalf("the ref must survive compilation, got %+v", term.SourcePrefixLists)
			}
		})
	}
	// A DANGLING self-named ref is still rejected — by the reference gate,
	// not #8480 — so the fix cannot smuggle an unresolvable scope through.
	t.Run("dangling self-name still rejected", func(t *testing.T) {
		src := `firewall { family inet { filter F { term T { from { source-prefix-list "source-prefix-list"; } then { accept; } } } } }`
		tree, perrs := NewParser(src).Parse()
		if len(perrs) > 0 {
			t.Fatalf("fixture did not parse: %v", perrs)
		}
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatal("a dangling self-named ref must be rejected")
		}
		if strings.Contains(err.Error(), "#8480") {
			t.Fatalf("dangling ref must be owned by the reference gate, got: %v", err)
		}
	})
}

// TestFilterFromMarkerGateEquivalence9875 pins gate-verdict == marker-verdict
// per spelling (Codex B4): a marked lenient term must be strict-rejected (a
// committed config never carries the marker), and a strict-rejected shape
// must leave its record. #10071 closes the packed unknown rows; #10072 keeps
// its term-packed valueless exclusion until its own gate fix lands.
func TestFilterFromMarkerGateEquivalence9875(t *testing.T) {
	rows := []struct {
		name         string
		mk           func(*testing.T) *ConfigTree
		strictReject bool
		marker       string // "" = none; else the recorded leaf
		markerField  string // "UnknownFrom" or "ValuelessFrom" ("" when marker == "")
	}{
		{"flat valueless", func(t *testing.T) *ConfigTree {
			return buildFilterTree(t, "set firewall family inet filter F term T from protocol",
				"set firewall family inet filter F term T then discard")
		}, true, "protocol", "ValuelessFrom"},
		{"braced valueless", func(t *testing.T) *ConfigTree {
			return fwTree9875(t, `term T { from { protocol; } then { discard; } }`)
		}, true, "protocol", "ValuelessFrom"},
		{"from-packed valueless", func(t *testing.T) *ConfigTree {
			return fwTree9875(t, `term T { from protocol; then discard; }`)
		}, true, "protocol", "ValuelessFrom"},
		{"term-packed valueless escapes both (#10072)", func(t *testing.T) *ConfigTree {
			return fwTree9875(t, `term T from protocol;`)
		}, false, "", ""},
		{"flat unknown leaf", func(t *testing.T) *ConfigTree {
			return buildFilterTree(t, "set firewall family inet filter F term T from protocol tcp",
				"set firewall family inet filter F term T from ttl 64",
				"set firewall family inet filter F term T then accept")
		}, true, "ttl", "UnknownFrom"},
		{"braced unknown leaf", func(t *testing.T) *ConfigTree {
			return fwTree9875(t, `term T { from { protocol tcp; ttl 64; } then { accept; } }`)
		}, true, "ttl", "UnknownFrom"},
		{"from-packed unknown leaf (#10071)", func(t *testing.T) *ConfigTree {
			return fwTree9875(t, `term T { from ttl 64; then accept; }`)
		}, true, "ttl", "UnknownFrom"},
		{"term-packed unknown leaf (#10071)", func(t *testing.T) *ConfigTree {
			return fwTree9875(t, `term T from ttl 64;`)
		}, true, "ttl", "UnknownFrom"},
		{"flat valued control", func(t *testing.T) *ConfigTree {
			return buildFilterTree(t, "set firewall family inet filter F term T from protocol tcp",
				"set firewall family inet filter F term T then accept")
		}, false, "", ""},
		{"braced valued control", func(t *testing.T) *ConfigTree {
			return fwTree9875(t, `term T { from { protocol tcp; } then { accept; } }`)
		}, false, "", ""},
		{"from-packed valued control", func(t *testing.T) *ConfigTree {
			return fwTree9875(t, `term T { from protocol tcp; then accept; }`)
		}, false, "", ""},
		{"term-packed valued control", func(t *testing.T) *ConfigTree {
			return fwTree9875(t, `term T from protocol tcp;`)
		}, false, "", ""},
		{"split-family valueless prefix-list (GPT-1)", func(t *testing.T) *ConfigTree {
			return fwSplitTree9875(t, `term T { from { source-prefix-list; } then { discard; } }`)
		}, true, "source-prefix-list", "ValuelessFrom"},
		{"split-family valued control (GPT-1)", func(t *testing.T) *ConfigTree {
			return fwSplitTree9875(t, `term T { from { protocol tcp; } then { accept; } }`)
		}, false, "", ""},
		{"from-packed valueless prefix-list (GLM-F1)", func(t *testing.T) *ConfigTree {
			return fwTree9875(t, `term T { from source-prefix-list; then { discard; } }`)
		}, true, "source-prefix-list", "ValuelessFrom"},
		{"from-packed valued prefix-list control = 2419 boundary (GLM-F1)", func(t *testing.T) *ConfigTree {
			// Valued-but-packed: the leaf has a value, so #8480 must NOT
			// fire — but compilation drops the ref (the normalizer
			// declines the pair and no reader consumes the packed tail).
			// That silent drop is #2419-CLASS but uninventoried (the
			// census probes only the valueless shape for these flag-modelled
			// leaves) — flagged to parent as a found gap.
			// Strict passes AND unmarked = gate/mark equivalent; the
			// drop itself is not this lane's to fix.
			return fwTree9875(t, `term T { from source-prefix-list AAA; then { discard; } }`)
		}, false, "", ""},
		{"nested filter-name valueless (GPT-F1)", func(t *testing.T) *ConfigTree {
			return fwRawTree9875(t, `firewall { family inet { filter { F { term T { from { source-prefix-list; } then { discard; } } } } } }`)
		}, true, "source-prefix-list", "ValuelessFrom"},
		{"nested term-name valueless (GPT-F1)", func(t *testing.T) *ConfigTree {
			return fwRawTree9875(t, `firewall { family inet { filter F { term { T { from { source-prefix-list; } then { discard; } } } } } }`)
		}, true, "source-prefix-list", "ValuelessFrom"},
		{"nested filter+term-name valueless (GPT-F1)", func(t *testing.T) *ConfigTree {
			return fwRawTree9875(t, `firewall { family inet { filter { F { term { T { from { source-prefix-list; } then { discard; } } } } } } }`)
		}, true, "source-prefix-list", "ValuelessFrom"},
		{"nested filter+term-name valued control (GPT-F1)", func(t *testing.T) *ConfigTree {
			return fwRawTree9875(t, `firewall { family inet { filter { F { term { T { from { protocol tcp; } then { accept; } } } } } } }`)
		}, false, "", ""},
		{"packed self-named valued commits (GPT-F2)", func(t *testing.T) *ConfigTree {
			// A resolving list legitimately named like the leaf (quoted
			// keyword-shaped name, #9029), referenced from-packed. The
			// operand after the leaf keyword is a value — quoted or
			// not, keyword-shaped or not — so #8480 must NOT fire:
			// packedBody's reinterpretation of it as another statement
			// (#10081) must not leak into the gate/mark pair.
			return fwRawTree9875(t, `policy-options { prefix-list "source-prefix-list" { 10.0.0.0/8; } }
				firewall { family inet { filter F { term T { from source-prefix-list "source-prefix-list"; then { accept; } } } } }`)
		}, false, "", ""},
		{"packed unquoted self-named rejects (GPT-F2)", func(t *testing.T) *ConfigTree {
			// Unquoted, the keyword operand is indistinguishable from a
			// new statement head — the grammar genuinely cannot tell
			// them apart — so it reads as two valueless statements and
			// #8480 fires. Asymmetric with the braced reader (which
			// quote-blindly keeps it as a ref), but #9029 legitimizes
			// the quoted spelling and an unquoted keyword-named list
			// is dangling-gated on the braced side too.
			return fwTree9875(t, `term T { from source-prefix-list source-prefix-list; then { discard; } }`)
		}, true, "source-prefix-list", "ValuelessFrom"},
		{"any packed valueless (Spark-F2)", func(t *testing.T) *ConfigTree {
			return fwRawTree9875(t, `firewall { family any { filter F { term T { from protocol; then { discard; } } } } }`)
		}, true, "protocol", "ValuelessFrom"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			_, serr := CompileConfig(row.mk(t))
			if row.strictReject && serr == nil {
				t.Fatalf("strict must reject (else the marker has no gate)")
			}
			if !row.strictReject && serr != nil {
				t.Fatalf("strict must pass, got: %v", serr)
			}
			cfg, err := CompileConfigLenient(row.mk(t))
			if err != nil {
				t.Fatalf("lenient must warn, not fail: %v", err)
			}
			term := firstInetTerm(t, cfg, "F")
			var got, field string
			switch {
			case len(term.UnknownFrom) > 0:
				got, field = term.UnknownFrom[0], "UnknownFrom"
			case len(term.ValuelessFrom) > 0:
				got, field = term.ValuelessFrom[0], "ValuelessFrom"
			}
			if got != row.marker || (row.marker != "" && field != row.markerField) {
				t.Fatalf("marker = %s:%q, want %s:%q", field, got, row.markerField, row.marker)
			}
			// The equivalence itself: rejected ⟺ marked.
			if row.strictReject != (row.marker != "") {
				t.Fatalf("gate/mark divergence: strictReject=%t marker=%q (a committed config must never carry the marker)",
					row.strictReject, row.marker)
			}
		})
	}
}

// TestFilterUnknownFromLenientRecord9875 pins the F-004 record the wire marker
// derives from: a leniently-loaded term keeps its representable matches AND
// the dropped leaf name (the strict #3307 rejection is pinned by
// firewall_from_unenforced_3307_test.go and firewall_filter_regressions_4422_test.go,
// not duplicated here).
func TestFilterUnknownFromLenientRecord9875(t *testing.T) {
	tree := buildFilterTree(t,
		"set firewall family inet filter f term t from protocol tcp",
		"set firewall family inet filter f term t from ttl 64",
		"set firewall family inet filter f term t then accept",
	)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient must warn, not fail: %v", err)
	}
	term := firstInetTerm(t, cfg, "f")
	if len(term.Protocols) != 1 || term.Protocols[0] != "tcp" {
		t.Fatalf("representable match must survive, got %v", term.Protocols)
	}
	if len(term.UnknownFrom) != 1 || term.UnknownFrom[0] != "ttl" {
		t.Fatalf("UnknownFrom = %v, want [ttl]", term.UnknownFrom)
	}
	if len(term.ValuelessFrom) != 0 {
		t.Fatalf("a valued term must not record ValuelessFrom, got %v", term.ValuelessFrom)
	}
}

// TestFilterFromPackedSeenWithoutNormalizer9875 proves the gate/mark pair
// sees packed tails STRUCTURALLY (GLM-F1), not by normalizer scope-accident.
// From-packed `protocol` passed the matrix above even pre-fix — but only
// because the compact normalizer happens to admit (from,protocol) and
// expands it before gates run. With normalization skipped entirely the
// pre-fix helper saw no children and missed it; the packedBody read sees
// it regardless of scope.
func TestFilterFromPackedSeenWithoutNormalizer9875(t *testing.T) {
	mk := func(t *testing.T) *ConfigTree {
		t.Helper()
		return fwTree9875(t, `term T { from protocol; then { discard; } }`)
	}
	if _, err := compileConfigWithOpts(mk(t), compileOpts{skipCompactNormalize: true}); err == nil {
		t.Fatal("strict must reject from-packed valueless `protocol` even with the normalizer skipped")
	} else if !strings.Contains(err.Error(), "#8480") {
		t.Fatalf("strict error must stay the #8480 gate, got: %v", err)
	}
	lo := lenientCompileOpts()
	lo.skipCompactNormalize = true
	cfg, err := compileConfigWithOpts(mk(t), lo)
	if err != nil {
		t.Fatalf("lenient must warn, not fail: %v", err)
	}
	if got := firstInetTerm(t, cfg, "F").ValuelessFrom; len(got) != 1 || got[0] != "protocol" {
		t.Fatalf("ValuelessFrom = %q without the normalizer, want [protocol]", got)
	}
}

// TestFilterNoFamilyPackedValuelessRejected9875 originally exercised the
// helper's nil-schema fallback for a family-less filter. Since #9899 this
// valid Junos spelling is normalized to inet before gates and compilation;
// it must still reject a packed valueless match, not become a match-all term.
func TestFilterNoFamilyPackedValuelessRejected9875(t *testing.T) {
	mk := func(t *testing.T) *ConfigTree {
		t.Helper()
		return fwRawTree9875(t, `firewall { filter F { term T { from protocol; then { discard; } } } }`)
	}
	if _, err := CompileConfig(mk(t)); err == nil {
		t.Fatal("strict must reject implicit-inet from-packed valueless `protocol`")
	} else if !strings.Contains(err.Error(), "#8480") {
		t.Fatalf("strict error must stay the #8480 gate, got: %v", err)
	}
}
