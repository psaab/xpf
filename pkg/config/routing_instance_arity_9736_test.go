package config

import (
	"strings"
	"testing"
)

// CompileConfig historically accepted these packed tails because the compiler
// reads only the declared value slot and drops the rest. SchemaValidate must
// reject them, and the AST gate must keep direct CompileConfig callers from
// observing a different silent-drop contract (#9736).
func TestRoutingInstanceFixedArityRejectsPackedTails9736(t *testing.T) {
	cases := []struct {
		name, statement, want string
	}{
		{
			name:      "description",
			statement: `description tenant-a firewall family inet filter f1 term t then discard;`,
			want:      "description",
		},
		{
			name:      "route-distinguisher",
			statement: `route-distinguisher 65000:1 firewall family inet filter f1 term t then discard;`,
			want:      "route-distinguisher",
		},
		{
			name:      "vrf-target",
			statement: `vrf-target export target:65000:1 junk-token foo;`,
			want:      "vrf-target",
		},
		{
			name:      "vrf-table-label",
			statement: `vrf-table-label junk-token foo;`,
			want:      "vrf-table-label",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spellings := []string{
				`routing-instances { ri1 ` + tc.statement + ` }`,
				`routing-instances { ri1 { ` + tc.statement + ` } }`,
			}
			for _, text := range spellings {
				tree := parse9323(t, text)
				if err := SchemaValidate(tree, nil); err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Errorf("SchemaValidate accepted %q or named the wrong leaf: %v", text, err)
				}
				if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Errorf("CompileConfig accepted %q or named the wrong leaf: %v", text, err)
				}
			}
		})
	}
}

// A block header can carry packed tokens too. Validate the header before
// walking its children so `vrf-target junk { target:...; }` cannot bypass the
// fixed grammar (#9736).
func TestRoutingInstanceVRFTargetBlockHeaderRejectsPackedPrefix9736(t *testing.T) {
	for _, text := range []string{
		`routing-instances { ri1 vrf-target junk { target:65000:1; } }`,
		`routing-instances { ri1 { vrf-target junk { target:65000:1; } } }`,
	} {
		tree := parse9323(t, text)
		if err := SchemaValidate(tree, nil); err == nil || !strings.Contains(err.Error(), "vrf-target") {
			t.Errorf("SchemaValidate accepted malformed block header %q: %v", text, err)
		}
		if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), "vrf-target") {
			t.Errorf("CompileConfig accepted malformed block header %q: %v", text, err)
		}
	}
}

// Flat-set syntax stores trailing garbage as a child node rather than packing
// it into Keys. The scalar validator must reject that child, while the one
// compiler-owned nested shape needed by #9814 remains deferred.
func TestRoutingInstanceSetFixedArityRejectsChildren9736(t *testing.T) {
	for _, command := range []string{
		`set routing-instances ri1 description tenant-a firewall x`,
		`set routing-instances ri1 route-distinguisher 65000:1 firewall x`,
	} {
		tree := buildSetTree3332(t, command)
		if err := SchemaValidate(tree, nil); err == nil {
			t.Errorf("SchemaValidate accepted fixed-arity child from %q", command)
		}
		if _, err := CompileConfig(tree); err == nil {
			t.Errorf("CompileConfig accepted fixed-arity child from %q", command)
		}
	}
}

// Keep the fixed-arity gate scoped to leaf statements. A body-bearing child
// remains open-world under routing-options, including an unknown keyword that
// the compiler intentionally ignores.
func TestRoutingInstanceBodyBoundaryRemainsOpenWorld9736(t *testing.T) {
	for _, text := range []string{
		`routing-instances { ri1 routing-options bogus-kw foo; }`,
		`routing-instances { ri1 { routing-options bogus-kw foo; } }`,
	} {
		if _, err := CompileConfig(parse9323(t, text)); err != nil {
			t.Errorf("routing-options body was incorrectly closed: %q: %v", text, err)
		}
	}
}

// The accepted target grammar is not a one-keyword walk: export/import are
// modifiers and block/list/repeated spellings are valid representations.
func TestRoutingInstanceVRFTargetFormsRemainValid9736(t *testing.T) {
	for _, text := range []string{
		`routing-instances { ri1 vrf-target export target:65000:1; }`,
		`routing-instances { ri1 { vrf-target export target:65000:1; } }`,
		`routing-instances { ri1 { vrf-target { export target:65000:1; import target:65000:2; } } }`,
		`routing-instances { ri1 { vrf-target [ target:65000:1 target:65000:2 ]; } }`,
		`routing-instances { ri1 { vrf-target target:65000:1; vrf-target target:65000:2; } }`,
	} {
		tree := parse9323(t, text)
		if err := SchemaValidate(tree, nil); err != nil {
			t.Errorf("valid vrf-target form rejected by schema: %q: %v", text, err)
		}
		if _, err := CompileConfig(tree); err != nil {
			t.Errorf("valid vrf-target form rejected by compiler: %q: %v", text, err)
		}
	}
}

func TestRoutingInstanceVRFTargetSetPathExportRemainsValid9736(t *testing.T) {
	tree := buildSetTree3332(t,
		`set routing-instances ri1 vrf-target export target:65000:1`,
		`set routing-instances ri1 vrf-target export target:65000:2`,
	)
	if err := SchemaValidate(tree, nil); err != nil {
		t.Fatalf("valid SetPath vrf-target export was rejected by schema: %v", err)
	}
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("valid SetPath vrf-target export was rejected by compiler: %v", err)
	}
}

func TestRoutingInstanceVRFTargetBracketMissingTarget9736(t *testing.T) {
	for _, text := range []string{
		`routing-instances { ri1 { vrf-target [ export ]; } }`,
		`routing-instances { ri1 { vrf-target [ import export ]; } }`,
	} {
		if err := SchemaValidate(parse9323(t, text), nil); err == nil {
			t.Errorf("SchemaValidate accepted bracketed VRF target without target: %q", text)
		}
	}
}
