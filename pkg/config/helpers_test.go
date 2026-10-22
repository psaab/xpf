package config

// In-package per-channel test kit (#16139, W2.11 part C).
//
// Each helper is exactly ONE compile channel — there is deliberately no
// bool lenient flag and no combined MustCompile(opts...): a lenient flag
// would let a test silently exercise the tolerant channel while claiming
// the strict operator channel (docs/engineering-style.md:50, the
// CompileConfig-vs-CheckText disaster). External `configtest` packages
// are rejected for in-package tests: they cannot be imported without a
// cycle (95%+ of this package's tests are internal).
//
// Channels provided, and what each one is:
//
//	parseHierText           hierarchical text -> *ConfigTree (NewParser.Parse, fatal on []ParseError)
//	parseSetCommands        flat `set` commands -> *ConfigTree (ParseSetCommand + SetPath, never NewParser)
//	compileHierStrict       hierarchical text -> *Config via CompileConfig (strict operator compile)
//	compileHierLenient      hierarchical text -> *Config via CompileConfigLenient (tolerant load only)
//	compileTreeStrictKit    *ConfigTree -> *Config via CompileConfig
//	compileTreeLenientKit   *ConfigTree -> *Config via CompileConfigLenient
//	compileTreeForNodeKit   *ConfigTree -> *Config via CompileConfigForNode (strict, node-aware)
//
// configstore.CheckText is NOT wrapped here: it lives in pkg/configstore
// (the real commit gate: SchemaValidate on the expanded view, then
// compileTreeStrict). In-package tests cannot import configstore without
// a cycle, so tests that need the operator commit gate belong in
// pkg/configstore or in package config_test where that import is legal.
// Naming a CompileConfig helper "check" would flatten that distinction.
//
// Decl census at introduction (origin/master 0ffdc6f35b, pkg/config,
// package config test files only): 73 pure parse clones of the
// parseHierText shape (single string arg, *ConfigTree return, only
// NewParser(param).Parse() + len(errs) guard + return) were found by
// scripted census; this PR migrates that one clone family and deletes
// every clone. Helpers that wrap text, inject fixtures, expand groups,
// or assert extra premises are NOT clones and are left untouched.
// Permanent clone-equivalence is pinned by helpers_equivalence_test.go
// against independent expected fixtures (a comparison against the
// deleted functions cannot compile, so none is attempted).

import "testing"

// parseHierText parses hierarchical Junos text and fails the test on
// any parse error. This is the parse-only channel: it does not compile.
func parseHierText(t *testing.T, src string) *ConfigTree {
	t.Helper()
	tree, errs := NewParser(src).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors for %q: %v", src, errs)
	}
	return tree
}

// parseSetCommands builds a tree from flat `set` commands via
// ParseSetCommand + SetPath. It never goes through NewParser, so it
// exercises the flat-run channel, not the hierarchical one.
func parseSetCommands(t *testing.T, cmds ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

// compileTreeStrictKit compiles an already-parsed tree on the strict
// channel (CompileConfig). Use on candidate/commit-shaped fixtures.
func compileTreeStrictKit(t *testing.T, tree *ConfigTree) *Config {
	t.Helper()
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

// compileTreeLenientKit compiles an already-parsed tree on the tolerant
// channel (CompileConfigLenient). Use only for already-persisted /
// already-active fixtures; never as a substitute for the strict gate.
func compileTreeLenientKit(t *testing.T, tree *ConfigTree) *Config {
	t.Helper()
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	return cfg
}

// compileTreeForNodeKit compiles an already-parsed tree on the strict
// node-aware channel (CompileConfigForNode) for the given node ID.
func compileTreeForNodeKit(t *testing.T, tree *ConfigTree, nodeID int) *Config {
	t.Helper()
	cfg, err := CompileConfigForNode(tree, nodeID)
	if err != nil {
		t.Fatalf("CompileConfigForNode(%d): %v", nodeID, err)
	}
	return cfg
}

// compileHierStrict parses hierarchical text and compiles it on the
// strict channel. Equivalent to compileTreeStrictKit(parseHierText).
func compileHierStrict(t *testing.T, src string) *Config {
	t.Helper()
	return compileTreeStrictKit(t, parseHierText(t, src))
}

// compileHierLenient parses hierarchical text and compiles it on the
// tolerant channel. Equivalent to compileTreeLenientKit(parseHierText).
func compileHierLenient(t *testing.T, src string) *Config {
	t.Helper()
	return compileTreeLenientKit(t, parseHierText(t, src))
}

// compileSetStrict builds a tree from flat `set` commands and compiles
// it on the strict channel.
func compileSetStrict(t *testing.T, cmds ...string) *Config {
	t.Helper()
	return compileTreeStrictKit(t, parseSetCommands(t, cmds...))
}

// compileSetLenient builds a tree from flat `set` commands and compiles
// it on the tolerant channel.
func compileSetLenient(t *testing.T, cmds ...string) *Config {
	t.Helper()
	return compileTreeLenientKit(t, parseSetCommands(t, cmds...))
}
