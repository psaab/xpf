package config

import (
	"strings"
	"testing"
)

// #15681 (V14-04 residual): the 3-bit rewrite parser special-cased binary
// only for ieee-802.1, so valid inet-precedence/exp binary tokens (110) and
// inet-precedence symbolic aliases (net-control) were rejected at strict
// commit, and INetPrecedenceClassifierDefs was populated only for classifiers
// with entries, so an entryless-but-defined binding was absent from Defs.

func mustCompile15681(t *testing.T, lines ...string) *Config {
	t.Helper()
	tree := &ConfigTree{}
	for _, ln := range lines {
		path, err := ParseSetCommand(ln)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", ln, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", ln, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict CompileConfig: %v", err)
	}
	return cfg
}

func compileStrictErr15681(t *testing.T, lines ...string) error {
	t.Helper()
	tree := &ConfigTree{}
	for _, ln := range lines {
		path, err := ParseSetCommand(ln)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", ln, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", ln, err)
		}
	}
	_, err := CompileConfig(tree)
	return err
}

// FAIL-ON-REVERT: restoring the ieee-802.1-only binary special-case makes
// the inet-precedence/exp `110` rows fail with "out of range (must be 0..7)";
// dropping alias resolution makes net-control/internet-control fail.
func TestCoS3BitRewriteBinaryAndAliases15681(t *testing.T) {
	cfg := mustCompile15681(t,
		"set class-of-service forwarding-classes queue 0 BE",
		"set class-of-service rewrite-rules inet-precedence IP forwarding-class BE loss-priority low code-point 110",
		"set class-of-service rewrite-rules exp EXP forwarding-class BE loss-priority low code-point 110",
		"set class-of-service rewrite-rules ieee-802.1 PCP forwarding-class BE loss-priority low code-point 110",
		"set class-of-service rewrite-rules inet-precedence IPA forwarding-class BE loss-priority low code-point net-control",
		"set class-of-service rewrite-rules inet-precedence IPB forwarding-class BE loss-priority low code-point internet-control",
		"set class-of-service rewrite-rules inet-precedence IPC forwarding-class BE loss-priority low code-point 001",
		"set class-of-service rewrite-rules exp EXPD forwarding-class BE loss-priority low code-point 7",
	)
	if r := cfg.ClassOfService.INetPrecedenceRewriteRuleDefs["IP"]; r == nil || len(r.Entries) != 1 || r.Entries[0].CodePoint != 6 {
		t.Fatalf("inet-precedence rewrite 110 => %+v, want code-point 6", r)
	}
	if r := cfg.ClassOfService.EXPRewriteRuleDefs["EXP"]; r == nil || len(r.Entries) != 1 || r.Entries[0].CodePoint != 6 {
		t.Fatalf("exp rewrite 110 => %+v, want code-point 6", r)
	}
	if r := cfg.ClassOfService.IEEE8021RewriteRules["PCP"]; r == nil || len(r.Entries) != 1 || r.Entries[0].PCPValue != 6 {
		t.Fatalf("ieee-802.1 rewrite 110 (control) => %+v, want 6", r)
	}
	if r := cfg.ClassOfService.INetPrecedenceRewriteRuleDefs["IPA"]; r == nil || len(r.Entries) != 1 || r.Entries[0].CodePoint != 7 {
		t.Fatalf("inet-precedence rewrite net-control => %+v, want 7", r)
	}
	if r := cfg.ClassOfService.INetPrecedenceRewriteRuleDefs["IPB"]; r == nil || len(r.Entries) != 1 || r.Entries[0].CodePoint != 6 {
		t.Fatalf("inet-precedence rewrite internet-control => %+v, want 6", r)
	}
	if r := cfg.ClassOfService.INetPrecedenceRewriteRuleDefs["IPC"]; r == nil || len(r.Entries) != 1 || r.Entries[0].CodePoint != 1 {
		t.Fatalf("inet-precedence rewrite 001 (control) => %+v, want 1", r)
	}
	if r := cfg.ClassOfService.EXPRewriteRuleDefs["EXPD"]; r == nil || len(r.Entries) != 1 || r.Entries[0].CodePoint != 7 {
		t.Fatalf("exp rewrite decimal 7 (control) => %+v, want 7", r)
	}
}

// The widening must not accept nonsense: bogus and 4-bit tokens stay loud
// strict rejects (never silently widened to binary).
func TestCoS3BitRewriteRejectsNonsense15681(t *testing.T) {
	for _, tc := range []struct{ family, token string }{
		{"exp", "bogus"}, {"exp", "1111"}, {"exp", "8"},
		{"inet-precedence", "bogus"}, {"inet-precedence", "1111"}, {"inet-precedence", "cs6"},
	} {
		err := compileStrictErr15681(t,
			"set class-of-service forwarding-classes queue 0 BE",
			"set class-of-service rewrite-rules "+tc.family+" R forwarding-class BE loss-priority low code-point "+tc.token,
		)
		if err == nil {
			t.Errorf("%s rewrite code-point %q accepted, want strict reject", tc.family, tc.token)
		}
	}
}

// FAIL-ON-REVERT: restoring `if len(classifier.Entries) > 0` around the Defs
// assignment makes EMPTY absent from Defs again.
func TestCoSEntrylessINetPrecedenceInDefs15681(t *testing.T) {
	cfg := mustCompile15681(t,
		"set class-of-service classifiers inet-precedence EMPTY",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set class-of-service interfaces ge-0/0/0 unit 0 classifiers inet-precedence EMPTY",
	)
	def := cfg.ClassOfService.INetPrecedenceClassifierDefs["EMPTY"]
	if def == nil {
		t.Fatal("entryless inet-precedence classifier absent from Defs (#15681)")
	}
	if len(def.Entries) != 0 {
		t.Fatalf("entryless classifier has %d entries, want 0", len(def.Entries))
	}
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "undefined inet-precedence") {
			t.Fatalf("defined entryless classifier warned undefined: %v", ValidateConfig(cfg))
		}
	}
}

// Queue-mapping warnings must still fire for an inet-precedence classifier
// whose entries map to an unmaterialized queue (regression guard for the
// Defs-population change — entries are still consulted, not just presence).
func TestCoSINetPrecedenceQueueWarningStillFires15681(t *testing.T) {
	cfg := mustCompile15681(t,
		"set class-of-service forwarding-classes queue 0 BE",
		"set class-of-service forwarding-classes queue 5 VOICE",
		"set class-of-service schedulers S transmit-rate percent 10",
		"set class-of-service scheduler-maps M forwarding-class BE scheduler S",
		"set class-of-service classifiers inet-precedence PREC forwarding-class VOICE loss-priority low code-points 110",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set class-of-service interfaces ge-0/0/0 unit 0 scheduler-map M",
		"set class-of-service interfaces ge-0/0/0 unit 0 classifiers inet-precedence PREC",
	)
	// Binary 110 in the classifier also compiles to precedence 6.
	def := cfg.ClassOfService.INetPrecedenceClassifierDefs["PREC"]
	if def == nil || len(def.Entries) != 1 || len(def.Entries[0].Precedences) != 1 || def.Entries[0].Precedences[0] != 6 {
		t.Fatalf("classifier binary 110 => %+v, want [6]", def)
	}
	found := false
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, `forwarding-class "VOICE"`) {
			found = true
		}
	}
	if !found {
		t.Fatalf("queue-mapping warning for VOICE missing; warnings=%v", ValidateConfig(cfg))
	}
}
