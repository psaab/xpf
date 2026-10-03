package config

// #4406 golden-output behavior-preservation harness.
//
// compileExpanded is being decomposed into named phase helpers (P1 AST
// pre-walk, P2 base skeleton, P3 warning append, P4 section dispatch, P5
// cross-section derivations, P6a early-strict folds, P6b uniform gates, P7
// tail). Each step is a behavior-preserving extract-function refactor gated
// by an OUTPUT-level golden proof: compile a representative corpus through
// the full strict/lenient x node0/node1 matrix, deterministically serialize
// the returned *Config (INCLUDING the order-sensitive cfg.Warnings slice)
// plus the error string, and assert the whole blob is byte-identical to a
// committed baseline captured on origin/master before the first extraction.
//
// This is the reusable merge gate for EVERY subsequent extraction step in
// the #4406 landing order (P1 -> P4 -> P7 -> P6b -> P5 -> P6a). A pure
// code-motion of orchestration glue over the already-extracted section
// compilers / validators must not change any observable output; any diff
// here fails the step.
//
// Regenerate the baseline (only when a legitimate behavior change lands, or
// to capture the origin/master baseline the first time) with:
//
//	GOLDEN_4406_UPDATE=1 go test ./pkg/config/ -run TestCompileGolden4406
//
// The corpus deliberately exercises the order-dependent surfaces the
// decomposition plan calls out: the flat vSRX chassis-cluster config is
// compiled for node0 AND node1 (invariant #2, the #4329 NodeID stamp before
// fabric derivation), CoS compile output and lenient downgrade warnings are
// byte-pinned (including cfg.Warnings order), a multi-strict-violation config
// proves the same FIRST error is returned (invariant #6), and a many-lenient-
// downgrade config proves the same warning ORDER on the tolerant path
// (invariant #7).

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// goldenCase is one (config, matrix-cell) compile result. Config is the raw
// JSON of the returned *Config (nil -> "null"); Error is err.Error() or "".
type goldenCase struct {
	Key    string          `json:"key"`
	Config json.RawMessage `json:"config"`
	Error  string          `json:"error"`
}

// goldenPkgDir returns the directory of this test file so the corpus and
// baseline are located independent of the test's working directory.
func goldenPkgDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	return filepath.Dir(file)
}

// goldenParseHier parses a hierarchical (curly-brace) config into a fresh
// tree — the LoadOverride / persisted-config builder (NewParser), the
// correct shape for the groups{node0/node1} cluster fixtures.
func goldenParseHier(t *testing.T, content string) *ConfigTree {
	t.Helper()
	p := NewParser(content)
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		t.Fatalf("golden: parse hierarchical fixture: %v", perrs)
	}
	return tree
}

// goldenBuildSet builds a fresh tree from embedded flat `set` lines using the
// ParseSetVerb + SetPath loop the CLI uses (never NewParser for set syntax,
// per CLAUDE.md — the parser merges newline-separated set lines).
func goldenBuildSet(t *testing.T, lines string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, ln := range strings.Split(lines, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		verb, path, err := ParseSetVerb(ln)
		if err != nil {
			t.Fatalf("golden: ParseSetVerb(%q): %v", ln, err)
		}
		if verb != verbSet {
			t.Fatalf("golden: embedded fixture must be set-only, got verb %q in %q", verb, ln)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("golden: SetPath(%q): %v", ln, err)
		}
	}
	return tree
}

// goldenMatrixCells is the strict/lenient x generic/node0/node1 matrix. Each
// cell re-builds a fresh tree so no compile can observe another's mutation.
var goldenMatrixCells = []struct {
	cell string
	run  func(*ConfigTree) (*Config, error)
}{
	{"strict/generic", func(tr *ConfigTree) (*Config, error) { return CompileConfig(tr) }},
	{"lenient/generic", func(tr *ConfigTree) (*Config, error) { return CompileConfigLenient(tr) }},
	{"strict/node0", func(tr *ConfigTree) (*Config, error) { return CompileConfigForNode(tr, 0) }},
	{"strict/node1", func(tr *ConfigTree) (*Config, error) { return CompileConfigForNode(tr, 1) }},
	{"lenient/node0", func(tr *ConfigTree) (*Config, error) { return CompileConfigForNodeLenient(tr, 0) }},
	{"lenient/node1", func(tr *ConfigTree) (*Config, error) { return CompileConfigForNodeLenient(tr, 1) }},
}

func goldenAppendMatrix(t *testing.T, name string, build func() *ConfigTree, out *[]goldenCase) {
	t.Helper()
	for _, c := range goldenMatrixCells {
		tr := build()
		cfg, err := c.run(tr)
		j, merr := json.Marshal(cfg)
		if merr != nil {
			t.Fatalf("golden: marshal %s/%s: %v", name, c.cell, merr)
		}
		es := ""
		if err != nil {
			es = err.Error()
		}
		*out = append(*out, goldenCase{Key: name + "/" + c.cell, Config: j, Error: es})
	}
}

func TestCompileGolden4406(t *testing.T) {
	dir := goldenPkgDir(t)
	readFile := func(rel string) string {
		b, err := os.ReadFile(filepath.Join(dir, rel))
		if err != nil {
			t.Fatalf("golden: read corpus %s: %v", rel, err)
		}
		return string(b)
	}

	var cases []goldenCase

	// (a)+(b) broad multi-section + flat vSRX chassis-cluster (compiled for
	// generic + node0 + node1 -> invariant #2, the #4329 NodeID stamp before
	// the fabric-member / FabricInterface derivation).
	goldenAppendMatrix(t, "ha-cluster-userspace", func() *ConfigTree {
		return goldenParseHier(t, readFile("../../docs/ha-cluster-userspace.conf"))
	}, &cases)
	goldenAppendMatrix(t, "ha-cluster", func() *ConfigTree {
		return goldenParseHier(t, readFile("../../docs/ha-cluster.conf"))
	}, &cases)

	// (c) broad class-of-service compile output with populated classifiers,
	// schedulers, scheduler-map, profile, rewrite-rule, and interface bindings.
	goldenAppendMatrix(t, "cos-compile", func() *ConfigTree {
		return goldenBuildSet(t, readFile("testdata/golden_4406_cos.set"))
	}, &cases)

	// (d) lenient CoS code-point downgrades across all classifier/rewrite
	// families. Fixture lines reverse the compile-family order so cfg.Warnings
	// pins deterministic warning ordering, not source-line order.
	goldenAppendMatrix(t, "cos-warning-order", func() *ConfigTree {
		return goldenBuildSet(t, readFile("testdata/golden_4406_cos_warnings.set"))
	}, &cases)

	// (e) multi-strict-violation -> proves the same FIRST error is returned on
	// the strict cells and the same warning ORDER on the lenient cells
	// (invariants #6/#7). Triggers several P1 pre-walk gates: VRRP
	// authentication (#4288, an early gate that wins the strict first-error
	// slot), policy required-match (#3044), and DNAT `to` scope (#3444).
	goldenAppendMatrix(t, "strict-violations", func() *ConfigTree {
		return goldenBuildSet(t, goldenStrictViolationsSet)
	}, &cases)

	// (f) many-lenient-downgrade -> exercises the tolerant-path warning
	// accumulation (invariant #7) across several P1 gates plus the
	// expandInterfaceRanges (#4027) tree mutation.
	goldenAppendMatrix(t, "lenient-downgrades", func() *ConfigTree {
		return goldenBuildSet(t, goldenLenientDowngradeSet)
	}, &cases)

	sort.Slice(cases, func(i, j int) bool { return cases[i].Key < cases[j].Key })
	got, err := json.MarshalIndent(cases, "", "  ")
	if err != nil {
		t.Fatalf("golden: marshal blob: %v", err)
	}
	got = append(got, '\n')

	goldenPath := filepath.Join(dir, "testdata", "golden_4406.json")
	if os.Getenv("GOLDEN_4406_UPDATE") == "1" {
		if err := os.MkdirAll(filepath.Dir(goldenPath), 0o755); err != nil {
			t.Fatalf("golden: mkdir testdata: %v", err)
		}
		if err := os.WriteFile(goldenPath, got, 0o644); err != nil {
			t.Fatalf("golden: write baseline: %v", err)
		}
		t.Logf("golden: updated baseline %s (%d bytes, %d cases)", goldenPath, len(got), len(cases))
		return
	}

	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("golden: read baseline (create it once with GOLDEN_4406_UPDATE=1): %v", err)
	}
	if bytes.Equal(got, want) {
		return
	}

	// Mismatch: write the actual output next to the baseline for inspection
	// and report the first differing case key for a readable failure.
	actualPath := filepath.Join(dir, "testdata", "golden_4406.actual.json")
	_ = os.WriteFile(actualPath, got, 0o644)

	var wantCases []goldenCase
	if uerr := json.Unmarshal(want, &wantCases); uerr != nil {
		t.Fatalf("golden mismatch AND baseline unparseable (%v); actual written to %s", uerr, actualPath)
	}
	wantByKey := make(map[string]goldenCase, len(wantCases))
	for _, c := range wantCases {
		wantByKey[c.Key] = c
	}
	for _, gc := range cases {
		wc, ok := wantByKey[gc.Key]
		if !ok {
			t.Errorf("golden: new case %q not in baseline", gc.Key)
			continue
		}
		if gc.Error != wc.Error {
			t.Errorf("golden: case %q ERROR changed:\n  baseline: %q\n  current:  %q", gc.Key, wc.Error, gc.Error)
		}
		if !bytes.Equal(gc.Config, wc.Config) {
			t.Errorf("golden: case %q CONFIG changed (see %s vs baseline)", gc.Key, actualPath)
		}
	}
	t.Fatalf("golden: compileExpanded output changed vs baseline (behavior NOT preserved); actual written to %s", actualPath)
}

// goldenStrictViolationsSet is a set-syntax config carrying several P1
// pre-walk strict-reject violations. On the strict cells the FIRST gate in
// execution order (VRRP authentication, #4288) wins the error slot; on the
// lenient cells all three downgrade to warnings in source order.
const goldenStrictViolationsSet = `
set interfaces ge-0-0-1 unit 0 family inet address 10.0.61.1/24
set interfaces ge-0-0-1 unit 0 family inet vrrp-group 5 virtual-address 10.0.61.254
set interfaces ge-0-0-1 unit 0 family inet vrrp-group 5 authentication-type md5
set interfaces ge-0-0-1 unit 0 family inet vrrp-group 5 authentication-key mysecret
set security policies from-zone trust to-zone untrust policy p1 match source-address any
set security policies from-zone trust to-zone untrust policy p1 then permit
set security nat destination rule-set rs1 to zone untrust
set security nat destination rule-set rs1 rule r1 match destination-address 10.0.0.1/32
set security nat destination rule-set rs1 rule r1 then destination-nat off
`

// goldenLenientDowngradeSet exercises the tolerant-path warning accumulation
// across several P1 gates plus the #4027 interface-range expansion (a P1 tree
// mutation) and a #3339 application name collision.
const goldenLenientDowngradeSet = `
set security flow traceoptions file /etc/passwd
set security flow tcp-mss all-tcp mss 70000
set interfaces interface-range RANGE member ge-0-0-5
set interfaces interface-range RANGE member ge-0-0-6
set interfaces interface-range RANGE mtu 9000
set applications application appA protocol tcp destination-port 80
set applications application appA protocol udp destination-port 80
`
