package config

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

// #14577 (Y03-02): #10078's closed-world `security` schema rejects three
// compiler-read, documented leaves. compileFlow reads
// `syn-flood-protection-mode` (compiler_security_flow.go), compileLog reads
// `report` (compiler_security_log.go), and compileFlow +
// validateFlowTraceSizeFilesAST read `traceoptions file <name> size <s>
// files <n>` across flat, packed and braced shapes (#3424). None was
// modelled, so strict commit refused them and a leniently-carried config
// commit-locked the node on the next unrelated commit.
//
// These cells are RED on origin/master: each valid line returns
// "unknown configuration keyword ... under closed-world subtree" from
// SchemaValidate, and CheckText-equivalent CompileConfig fails the same
// way. The typo control and out-of-range controls must stay RED.

// TestClosedWorldSecurity14577_AcceptsCompilerReadLeaves pins that every
// compiler-read leaf named by #14577 validates and compiles to its value.
func TestClosedWorldSecurity14577_AcceptsCompilerReadLeaves(t *testing.T) {
	cases := []struct {
		name  string
		lines []string
		check func(t *testing.T, cfg *Config)
	}{
		{
			name:  "syn-flood-protection-mode syn-cookie",
			lines: []string{"set security flow syn-flood-protection-mode syn-cookie"},
			check: func(t *testing.T, cfg *Config) {
				if cfg.Security.Flow.SynFloodProtectionMode != "syn-cookie" {
					t.Fatalf("SynFloodProtectionMode = %q, want syn-cookie", cfg.Security.Flow.SynFloodProtectionMode)
				}
			},
		},
		{
			name:  "security log report",
			lines: []string{"set security log report"},
			check: func(t *testing.T, cfg *Config) {
				if !cfg.Security.Log.Report {
					t.Fatalf("Log.Report = false, want true")
				}
			},
		},
		{
			name:  "traceoptions file flat size/files",
			lines: []string{"set security flow traceoptions file f1 size 100000 files 3"},
			check: func(t *testing.T, cfg *Config) {
				to := cfg.Security.Flow.Traceoptions
				if to == nil || to.File != "f1" || to.FileSize != 100000 || to.FileCount != 3 {
					t.Fatalf("Traceoptions = %+v, want file=f1 size=100000 files=3", to)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTree(t, tc.lines)
			if err := SchemaValidate(tree, nil); err != nil {
				t.Fatalf("SchemaValidate(%q) = %v, want nil (compiler-read leaf must be schema-reachable)", tc.lines, err)
			}
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("CompileConfig(%q) = %v, want nil", tc.lines, err)
			}
			tc.check(t, cfg)
		})
	}
}

// TestClosedWorldSecurity14577_HierarchicalShapes pins the braced and
// single-line hierarchical spellings the issue lists.
func TestClosedWorldSecurity14577_HierarchicalShapes(t *testing.T) {
	cases := []struct {
		name string
		text string
	}{
		{"syn-cookie braced", "security {\n flow {\n syn-flood-protection-mode syn-cookie;\n }\n}\n"},
		{"log report braced", "security {\n log {\n report;\n }\n}\n"},
		{"traceoptions file single-line hierarchical", "security {\n flow {\n traceoptions {\n file f1 size 100000 files 3;\n }\n }\n}\n"},
		{"traceoptions file braced size/files", "security {\n flow {\n traceoptions {\n file f1 {\n size 100000;\n files 3;\n }\n }\n }\n}\n"},
		{"traceoptions file packed", "security {\n flow {\n traceoptions {\n file f1 size 100000 files 3;\n }\n }\n}\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree, perrs := NewParser(tc.text).Parse()
			if len(perrs) > 0 {
				t.Fatalf("parse: %v", perrs)
			}
			if err := SchemaValidate(tree, nil); err != nil {
				t.Fatalf("SchemaValidate hierarchical = %v, want nil", err)
			}
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("CompileConfig hierarchical = %v, want nil", err)
			}
			_ = cfg
		})
	}
	// Compiled values for the braced traceoptions shape.
	tree, perrs := NewParser("security {\n flow {\n traceoptions {\n file f1 {\n size 100000;\n files 3;\n }\n }\n }\n}\n").Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse braced: %v", perrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig braced: %v", err)
	}
	to := cfg.Security.Flow.Traceoptions
	if to == nil || to.File != "f1" || to.FileSize != 100000 || to.FileCount != 3 {
		t.Fatalf("braced Traceoptions = %+v, want file=f1 size=100000 files=3", to)
	}
}

// TestClosedWorldSecurity14577_RejectsInvalidValues keeps the closed-world
// arm honest: typos, the unimplemented Junos syn-proxy mode, and
// out-of-range trace rotation values must still fail strict commit.
func TestClosedWorldSecurity14577_RejectsInvalidValues(t *testing.T) {
	cases := []struct {
		name string
		line string
		want string
	}{
		{"typo syn-flood-protection-mod", "set security flow syn-flood-protection-mod syn-cookie", "syn-flood-protection-mod"},
		{"syn-proxy explicit reject", "set security flow syn-flood-protection-mode syn-proxy", "syn-proxy"},
		{"syn-cookie typo value", "set security flow syn-flood-protection-mode syn-cokie", "syn-cokie"},
		{"trace size below min", "set security flow traceoptions file f1 size 1 files 3", "size"},
		{"trace files above max", "set security flow traceoptions file f1 size 100000 files 1000000000", "files"},
		{"trace size non-integer", "set security flow traceoptions file f1 size abc files 3", "size"},
		{"trace bogus modifier", "set security flow traceoptions file f1 bogus 3", "bogus"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTree(t, []string{tc.line})
			// Strict commit = SchemaValidate then CompileConfig (the
			// compileTreeStrict composition). Either stage rejecting
			// naming the token is a pass; both accepting is the defect.
			if err := SchemaValidate(tree, nil); err != nil {
				if !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("SchemaValidate error %q does not name %q", err.Error(), tc.want)
				}
				return
			}
			if _, cerr := CompileConfig(tree); cerr == nil {
				t.Fatalf("strict gate accepted %q, want reject naming %q", tc.line, tc.want)
			} else if !strings.Contains(cerr.Error(), tc.want) {
				t.Fatalf("CompileConfig error %q does not name %q", cerr.Error(), tc.want)
			}
		})
	}
}

// TestClosedWorldSecurity14577_CompilerReadCensus is the acceptance census:
// every keyword compileFlow / compileLog reads at the flow/log level must
// be schema-reachable. It enumerates the compiler-read sets explicitly
// (mirroring the #3377 policy-then canary) and asserts the schema child
// sets contain them, so a future compiler leaf cannot drift out again.
func TestClosedWorldSecurity14577_CompilerReadCensus(t *testing.T) {
	// Keywords compileFlow reads via FindChild/FindChildren on the flow
	// node (compiler_security_flow.go). Presence flags and valued leaves
	// alike must be modelled.
	flowCompilerRead := []string{
		"aging", "tcp-session", "udp-session", "icmp-session", "tcp-mss",
		"allow-dns-reply", "allow-embedded-icmp", "allow-unstamped-fabric-ingress",
		"gre-performance-acceleration", "power-mode-disable",
		"route-change-timeout", "sync-icmp-session", "force-ip-reassembly",
		"multicast-session-lifetime", "preserve-incoming-fragment-size",
		"syn-flood-protection-mode", "traceoptions",
	}
	// Keywords compileLog reads on the log node (compiler_security_log.go).
	logCompilerRead := []string{"mode", "format", "source-interface", "report", "stream", "profile"}

	sec := setSchema.children["security"]
	if sec == nil {
		t.Fatal("security schema missing")
	}
	flow := sec.children["flow"]
	if flow == nil {
		t.Fatal("security flow schema missing")
	}
	for _, kw := range flowCompilerRead {
		if flow.children[kw] == nil {
			t.Errorf("compileFlow reads %q but schema flow has no such child (compiler-read leaf not schema-reachable)", kw)
		}
	}
	logNode := sec.children["log"]
	if logNode == nil {
		t.Fatal("security log schema missing")
	}
	for _, kw := range logCompilerRead {
		if logNode.children[kw] == nil {
			t.Errorf("compileLog reads %q but schema log has no such child (compiler-read leaf not schema-reachable)", kw)
		}
	}
	// traceoptions file must model size/files as typed modifiers with the
	// #3424 bounds.
	to := flow.children["traceoptions"]
	if to == nil || to.children["file"] == nil {
		t.Fatal("traceoptions file schema missing")
	}
	file := to.children["file"]
	for _, mod := range []string{"size", "files"} {
		m := file.children[mod]
		if m == nil {
			t.Errorf("traceoptions file has no %q modifier child", mod)
			continue
		}
		if m.validator == nil {
			t.Errorf("traceoptions file %q has no validator (must carry #3424 bounds)", mod)
		}
	}
	// syn-flood-protection-mode must be a typed enum leaf.
	sf := flow.children["syn-flood-protection-mode"]
	if sf == nil {
		t.Fatal("syn-flood-protection-mode schema missing")
	}
	if sf.valueType != ValueEnumOf || sf.validator == nil {
		t.Errorf("syn-flood-protection-mode must be typed enum with validator, got valueType=%v validator=%v", sf.valueType, sf.validator != nil)
	}
	// Completion must offer the new leaves.
	for _, tc := range []struct {
		path []string
		want string
	}{
		{[]string{"security", "flow"}, "syn-flood-protection-mode"},
		{[]string{"security", "log"}, "report"},
		{[]string{"security", "flow", "traceoptions", "file", "f1"}, "size"},
		{[]string{"security", "flow", "traceoptions", "file", "f1"}, "files"},
	} {
		got := CompleteSetPath(tc.path)
		found := false
		for _, g := range got {
			if g == tc.want {
				found = true
			}
		}
		if !found {
			sort.Strings(got)
			t.Errorf("CompleteSetPath(%v) = %v, want to contain %q", tc.path, got, tc.want)
		}
	}
	_ = reflect.DeepEqual
}

// TestClosedWorldSecurity14577_ControlsStillPass pins the issue controls.
func TestClosedWorldSecurity14577_ControlsStillPass(t *testing.T) {
	for _, line := range []string{
		"set security flow allow-dns-reply",
		"set security log mode stream",
	} {
		tree := buildTree(t, []string{line})
		if err := SchemaValidate(tree, nil); err != nil {
			t.Fatalf("control %q SchemaValidate = %v, want nil", line, err)
		}
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("control %q CompileConfig = %v, want nil", line, err)
		}
	}
}
