package config

import (
	"strings"
	"testing"
)

// #15198 (A04-01): application `icmp-type` rejected Junos symbolic names
// (echo-request, ...) although the firewall-filter path resolves them via
// icmpTypeNames/icmp6TypeNames (#3205). The application schema carried
// ValidateInteger(0,255) and the compiler used Atoi only, so a valid Junos
// name failed closed at commit — a migration blocker. The fix resolves
// symbolic icmp-type names in the application path, chosen by protocol,
// and keeps icmp-code numeric-only (Junos application icmp-code is
// numeric; the filter path likewise fails closed on symbolic codes).
//
// RED on origin/master: every symbolic cell below is rejected with
// `invalid icmp-type/icmp-code "echo-request"; must be an integer in
// 0..255` (direct) or the SchemaValidate integer error. GREEN after the
// fix: symbolic cells compile to the same ICMPType as numeric ones.

func symbolicApp(t *testing.T, name string, props ...string) *Application {
	t.Helper()
	tree := flatTreeFromSets(t, refApp(name, props...)...)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("expected commit to accept %v: %v", props, err)
	}
	app := cfg.Applications.Applications[name]
	if app == nil {
		t.Fatalf("application %q missing; got %v", name, appNames(cfg))
	}
	return app
}

func TestApplicationSymbolicICMPTypeDirect_15198(t *testing.T) {
	cases := []struct {
		name  string
		props []string
		want  uint8
	}{
		{"v4 echo-request", []string{"protocol icmp", "icmp-type echo-request"}, 8},
		{"v4 echo alias", []string{"protocol icmp", "icmp-type echo"}, 8},
		{"v4 echo-reply", []string{"protocol icmp", "icmp-type echo-reply"}, 0},
		{"v4 destination-unreachable", []string{"protocol icmp", "icmp-type destination-unreachable"}, 3},
		{"v4 case-insensitive", []string{"protocol icmp", "icmp-type Echo-Request"}, 8},
		{"v4 numeric still works", []string{"protocol icmp", "icmp-type 8"}, 8},
		{"v6 echo-request", []string{"protocol icmpv6", "icmp-type echo-request"}, 128},
		{"v6 echo-reply", []string{"protocol icmpv6", "icmp-type echo-reply"}, 129},
		{"v6 neighbor-solicit", []string{"protocol icmpv6", "icmp-type neighbor-solicit"}, 135},
		{"v6 numeric still works", []string{"protocol icmpv6", "icmp-type 128"}, 128},
		{"proto 1 echo-request", []string{"protocol 1", "icmp-type echo-request"}, 8},
		{"proto 58 echo-request", []string{"protocol 58", "icmp-type echo-request"}, 128},
		{"junos-pingv6 neighbor-solicit", []string{"protocol junos-pingv6", "icmp-type neighbor-solicit"}, 135},
		{"icmp before protocol v6", []string{"icmp-type echo-request", "protocol icmpv6"}, 128},
		{"icmp before protocol v4", []string{"icmp-type echo-request", "protocol icmp"}, 8},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			app := symbolicApp(t, "symapp", c.props...)
			if app.ICMPType == nil || *app.ICMPType != c.want {
				t.Fatalf("props %v: ICMPType=%v, want %d (symbolic must compile to same value as numeric)", c.props, app.ICMPType, c.want)
			}
			if len(app.UnknownICMP) != 0 {
				t.Fatalf("props %v: UnknownICMP=%v, want empty", c.props, app.UnknownICMP)
			}
		})
	}
}

// Symbolic and numeric spellings of the same constraint compile identically.
func TestApplicationSymbolicEqualsNumeric_15198(t *testing.T) {
	sym := symbolicApp(t, "symapp", "protocol icmp", "icmp-type echo-request", "icmp-code 0")
	num := symbolicApp(t, "symapp", "protocol icmp", "icmp-type 8", "icmp-code 0")
	if sym.ICMPType == nil || num.ICMPType == nil || *sym.ICMPType != *num.ICMPType {
		t.Fatalf("symbolic ICMPType=%v, numeric=%v, want equal", sym.ICMPType, num.ICMPType)
	}
	if sym.ICMPCode == nil || num.ICMPCode == nil || *sym.ICMPCode != *num.ICMPCode {
		t.Fatalf("symbolic ICMPCode=%v, numeric=%v, want equal", sym.ICMPCode, num.ICMPCode)
	}
}

// A duplicate restated in the other spelling is idempotent, not a conflict.
func TestApplicationSymbolicNumericDuplicateIdempotent_15198(t *testing.T) {
	app := symbolicApp(t, "symapp", "protocol icmp", "icmp-type echo-request", "icmp-type 8")
	if app.ICMPType == nil || *app.ICMPType != 8 {
		t.Fatalf("ICMPType=%v, want 8", app.ICMPType)
	}
	if len(app.DuplicateDirectLeaves) != 0 {
		t.Fatalf("DuplicateDirectLeaves=%v, want empty for alias restate", app.DuplicateDirectLeaves)
	}
}

// Conflicting symbolic vs numeric values are still a duplicate conflict
// (hierarchical shape — flat-set collapses a single-value leaf, #5574).
func TestApplicationSymbolicConflictingDuplicateRejected_15198(t *testing.T) {
	tree := hierTree(t, "applications {\n    application symapp {\n        protocol icmp; icmp-type echo-request; icmp-type 0;\n    }\n}\n")
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("expected commit to REJECT conflicting icmp-type echo-request vs 0")
	} else if !strings.Contains(err.Error(), "icmp-type") {
		t.Fatalf("error should name icmp-type, got: %v", err)
	}
	tree2 := hierTree(t, "applications {\n    application symapp {\n        protocol icmp; icmp-type echo-request; icmp-type 8;\n    }\n}\n")
	cfg, err := CompileConfig(tree2)
	if err != nil {
		t.Fatalf("alias restate echo-request/8 must commit: %v", err)
	}
	if app := cfg.Applications.Applications["symapp"]; app == nil || app.ICMPType == nil || *app.ICMPType != 8 {
		t.Fatalf("alias restate ICMPType=%v, want 8", app)
	}
}

func TestApplicationSymbolicICMPTypeTerm_15198(t *testing.T) {
	cases := []struct {
		name string
		term string
		want uint8
	}{
		{"v4 term echo-request", "term t1 protocol icmp icmp-type echo-request", 8},
		{"v6 term echo-request", "term t1 protocol icmpv6 icmp-type echo-request", 128},
		{"v6 term neighbor-solicit", "term t1 protocol icmpv6 icmp-type neighbor-solicit", 135},
		{"term icmp before protocol", "term t1 icmp-type echo-request protocol icmpv6", 128},
		{"term numeric still works", "term t1 protocol icmp icmp-type 8", 8},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tree := flatTreeFromSets(t, refApp("symterm", c.term)...)
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("expected commit to accept %q: %v", c.term, err)
			}
			var found *Application
			for _, app := range cfg.Applications.Applications {
				if app != nil && app.ICMPType != nil && *app.ICMPType == c.want {
					found = app
				}
				if app != nil && len(app.UnknownICMP) != 0 {
					t.Fatalf("term %q: UnknownICMP=%v, want empty", c.term, app.UnknownICMP)
				}
			}
			if found == nil {
				t.Fatalf("term %q: no application with ICMPType=%d; got %v", c.term, c.want, appNames(cfg))
			}
		})
	}
}

// Multi-protocol term: the same name resolves per generated application.
func TestApplicationSymbolicICMPTypeMultiProtoTerm_15198(t *testing.T) {
	tree := flatTreeFromSets(t, refApp("multi", "term t1 protocol icmp protocol icmpv6 icmp-type echo-request")...)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("expected multi-protocol symbolic term to commit: %v", err)
	}
	byProto := map[string]uint8{}
	for name, app := range cfg.Applications.Applications {
		if app == nil || app.ICMPType == nil {
			continue
		}
		byProto[app.Protocol] = *app.ICMPType
		_ = name
	}
	if byProto["icmp"] != 8 || byProto["icmpv6"] != 128 {
		t.Fatalf("multi-proto echo-request: got %v, want icmp=8 icmpv6=128", byProto)
	}
}

// Hierarchical (braced) spelling resolves too.
func TestApplicationSymbolicICMPTypeHier_15198(t *testing.T) {
	tree := hierTree(t, "applications {\n    application hierping {\n        protocol icmpv6;\n        icmp-type echo-request;\n    }\n}\n"+
		"security {\n    zones {\n        security-zone trust;\n        security-zone untrust;\n    }\n"+
		"    policies {\n        from-zone trust to-zone untrust {\n            policy p {\n"+
		"                match { source-address any; destination-address any; application hierping; }\n"+
		"                then { permit; }\n            }\n        }\n    }\n}\n")
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("expected hierarchical symbolic icmp-type to commit: %v", err)
	}
	app := cfg.Applications.Applications["hierping"]
	if app == nil || app.ICMPType == nil || *app.ICMPType != 128 {
		t.Fatalf("hierping ICMPType=%v, want 128", app)
	}
}

// Fail-closed controls: unknown names, wrong-family names, symbolic codes,
// and out-of-range numerics are still rejected.
func TestApplicationSymbolicICMPRejectedControls_15198(t *testing.T) {
	cases := []struct {
		name  string
		props []string
	}{
		{"unknown name", []string{"protocol icmp", "icmp-type frobnicate"}},
		{"v6-only name on v4", []string{"protocol icmp", "icmp-type neighbor-solicit"}},
		{"v4-only name on v6", []string{"protocol icmpv6", "icmp-type source-quench"}},
		{"symbolic icmp-code", []string{"protocol icmp", "icmp-type echo-request", "icmp-code network-unreachable"}},
		{"out of range", []string{"protocol icmp", "icmp-type 999"}},
		{"symbolic on tcp still rejected", []string{"protocol tcp", "icmp-type echo-request"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tree := flatTreeFromSets(t, refApp("badapp", c.props...)...)
			if _, err := CompileConfig(tree); err == nil {
				t.Fatalf("expected commit to REJECT %v", c.props)
			}
		})
	}
	// Term spelling of the unknown-name control.
	tree := flatTreeFromSets(t, refApp("badterm", "term t1 protocol icmp icmp-type frobnicate")...)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("expected commit to REJECT term icmp-type frobnicate")
	}
}

// SchemaValidate (strict commit-check) accepts symbolic icmp-type and
// numeric icmp-code, and still rejects garbage. Hierarchical shape is
// used because the typed-leaf walk reaches sibling leaves there.
func TestApplicationSymbolicICMPSchema_15198(t *testing.T) {
	good := hierTree(t, "applications {\n    application a {\n        protocol icmp; icmp-type echo-request; icmp-code 0;\n    }\n}\n")
	if err := SchemaValidate(good, nil); err != nil {
		t.Fatalf("SchemaValidate must accept symbolic icmp-type: %v", err)
	}
	badType := hierTree(t, "applications {\n    application a {\n        protocol icmp; icmp-type frobnicate;\n    }\n}\n")
	if err := SchemaValidate(badType, nil); err == nil {
		t.Fatal("SchemaValidate must reject unknown icmp-type frobnicate")
	}
	badCode := hierTree(t, "applications {\n    application a {\n        protocol icmp; icmp-type 8; icmp-code frobnicate;\n    }\n}\n")
	if err := SchemaValidate(badCode, nil); err == nil {
		t.Fatal("SchemaValidate must reject symbolic icmp-code frobnicate")
	}
}
