package config

import (
	"strings"
	"testing"
)

// #15124 (A85-05): an unknown child of `snmp community <c>` — `client
// 10.0.0.0/8`, `clinets …`, `client-list-nam L`, or any other undeclared
// keyword — was skipped by both community walks (the statement collection
// in compileSNMP and the Keys-packed scan) with no error or warning, so a
// one-letter typo in the operator-authored source ACL left the community
// answering EVERY source on a green commit (AllowsSource reads an empty
// allowlist as allow-all). Prior fixes (#4289, #4834, #5472, #5833,
// #5898, #8778, #9416, #10687) each fixed a NAMED spelling; none added a
// default arm.
//
// FAIL-ON-REVERT: removing the gate in compileSNMP makes every strict cell
// below compile clean (err == nil) and every lenient cell allow-all with
// no warning, so the assertions fire RED.

// TestSNMPCommunityUnknownChildStrictRejects15124 pins the strict arm:
// every unknown-child spelling is REJECTED at commit, naming the token.
func TestSNMPCommunityUnknownChildStrictRejects15124(t *testing.T) {
	for _, tc := range []struct {
		name string
		line string
		tok  string
	}{
		{"client singular typo", "set snmp community mon client 10.0.0.0/8", "client"},
		{"clinets transposed", "set snmp community mon clinets 10.0.0.0/8", "clinets"},
		{"client-list-nam truncated", "set snmp community mon client-list-nam trusted", "client-list-nam"},
		{"arbitrary garbage", "set snmp community mon zzbogus 5", "zzbogus"},
		{"unknown nested under authorization chain", "set snmp community mon authorization read-only client 10.0.0.0/8", "client"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := compileSNMPLines(t, []string{tc.line})
			if err == nil {
				t.Fatalf("unknown community child %q compiled without error (#15124 fail-open regression)\nline: %s", tc.tok, tc.line)
			}
			if !strings.Contains(err.Error(), tc.tok) {
				t.Fatalf("error %q does not name the offending token %q", err, tc.tok)
			}
			// The community NAME is a secret and must never be echoed.
			if strings.Contains(err.Error(), "mon") && !strings.Contains(tc.tok, "mon") {
				t.Fatalf("error %q echoes the community name (a secret)", err)
			}
		})
	}
}

// TestSNMPCommunityUnknownChildBracedStrictRejects15124 drives the same
// defect through the hierarchical spellings CheckText accepts: braced
// children and the brace-elided Keys-packed run on the community line.
func TestSNMPCommunityUnknownChildBracedStrictRejects15124(t *testing.T) {
	for _, tc := range []struct {
		name string
		text string
		tok  string
	}{
		{"braced client", "snmp {\n community mon {\n  authorization read-only;\n  client 10.0.0.0/8;\n }\n}\n", "client"},
		{"braced clinets", "snmp {\n community mon {\n  clinets 10.0.0.0/8;\n }\n}\n", "clinets"},
		{"packed client", "snmp { community mon client 10.0.0.0/8; }\n", "client"},
		{"packed client-list-nam", "snmp { community mon client-list-nam trusted; }\n", "client-list-nam"},
		{"packed garbage after valid", "snmp { community mon authorization read-only zzbogus 5; }\n", "zzbogus"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := NewParser(tc.text)
			tree, perrs := p.Parse()
			if len(perrs) > 0 {
				t.Fatalf("parse errors: %v", perrs)
			}
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("unknown community child %q compiled without error (#15124)\ntext:\n%s", tc.tok, tc.text)
			}
			if !strings.Contains(err.Error(), tc.tok) {
				t.Fatalf("error %q does not name the offending token %q", err, tc.tok)
			}
		})
	}
}

// TestSNMPCommunityUnknownChildLenientQuarantines15124 pins the tolerant
// arm: the config BOOTS (#1960), a warning names the token, and the
// affected community is quarantined to deny-all — while a well-formed
// sibling community keeps its intended policy.
func TestSNMPCommunityUnknownChildLenientQuarantines15124(t *testing.T) {
	tree := &ConfigTree{}
	lines := []string{
		"set snmp community mon authorization read-only",
		"set snmp community mon client 10.0.0.0/8", // typo: client, not clients
		"set snmp community pub authorization read-only",
		"set snmp community pub clients 192.168.0.0/16",
	}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient must not fail on an unknown community child (brick-on-restart): %v", err)
	}
	if !hasWarningSubstr(cfg.Warnings, `"client"`) {
		t.Fatalf("expected a lenient warning naming the unknown token 'client', warnings=%v", cfg.Warnings)
	}
	mon := cfg.System.SNMP.Communities["mon"]
	if mon == nil {
		t.Fatal("community 'mon' missing from compiled config")
	}
	for _, src := range []string{"8.8.8.8", "10.1.2.3", "192.168.1.1", "2001:db8::1"} {
		if mon.AllowsSource(snmpClientTestSource10687(src)) {
			t.Errorf("quarantined community must DENY %s, but it was allowed "+
				"(fail-open: the typo'd restriction was silently dropped, #15124)", src)
		}
	}
	pub := cfg.System.SNMP.Communities["pub"]
	if pub == nil {
		t.Fatal("well-formed community 'pub' missing — the rest of the config failed to load")
	}
	if !pub.AllowsSource(snmpClientTestSource10687("192.168.1.1")) {
		t.Error("well-formed community 'pub' must ALLOW its listed source 192.168.1.1")
	}
	if pub.AllowsSource(snmpClientTestSource10687("8.8.8.8")) {
		t.Error("well-formed community 'pub' must DENY an unlisted source 8.8.8.8")
	}
}

// TestSNMPCommunityKnownChildrenControl15124 is the named control adjacent
// to the mechanism: every legitimate community spelling through the same
// code path stays green — strict compiles clean, the `clients` control is
// unchanged, and the inert knobs keep their accept-with-advisory posture
// instead of becoming hard rejects.
func TestSNMPCommunityKnownChildrenControl15124(t *testing.T) {
	// Inline clients control: unchanged enforcement.
	cfg, err := compileSNMPLines(t, []string{
		"set snmp community mon authorization read-only",
		"set snmp community mon clients 10.0.0.0/8",
	})
	if err != nil {
		t.Fatalf("well-formed clients control must compile clean: %v", err)
	}
	mon := cfg.System.SNMP.Communities["mon"]
	if mon == nil {
		t.Fatal("community 'mon' missing")
	}
	if !mon.AllowsSource(snmpClientTestSource10687("10.1.2.3")) {
		t.Error("clients control: listed source 10.1.2.3 must be allowed")
	}
	if mon.AllowsSource(snmpClientTestSource10687("8.8.8.8")) {
		t.Error("clients control: unlisted source 8.8.8.8 must be denied (the control is unchanged)")
	}

	// Flat-set chain that nests a legal keyword under a terminal leaf —
	// the spelling a closedWorld flip would false-reject (#9265).
	if _, err := compileSNMPLines(t, []string{
		"set snmp client-list trusted 10.0.0.0/8",
		"set snmp community public client-list-name trusted authorization read-only",
	}); err != nil {
		t.Fatalf("legal flat-set chain must compile clean: %v", err)
	}

	// Braced spelling with every declared child.
	text := "snmp {\n client-list trusted { 10.0.0.0/8; }\n community public {\n  authorization read-only;\n  clients 192.168.0.0/16;\n  client-list-name trusted;\n }\n}\n"
	p := NewParser(text)
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse errors: %v", perrs)
	}
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("braced community with all declared children must compile clean: %v", err)
	}

	// Inert knobs stay accept-with-advisory (#4306), not hard rejects.
	cfgView, err := compileSNMPLines(t, []string{
		"set snmp community public authorization read-only view myview",
	})
	if err != nil {
		t.Fatalf("inert `view` knob must stay accept-with-advisory, got reject: %v", err)
	}
	if !hasWarningSubstr(cfgView.Warnings, "snmp community view") {
		t.Fatalf("inert `view` knob must keep its advisory, warnings=%v", cfgView.Warnings)
	}
	// A `view` VALUE that happens to spell a restriction keyword is a
	// value, not a statement: it must not trip the unknown-child gate.
	if _, err := compileSNMPLines(t, []string{
		"set snmp community public view clients",
	}); err != nil {
		t.Fatalf("a view named 'clients' is a value and must compile clean: %v", err)
	}
}

// TestSNMPClientListUnreferencedWarns15124 pins the companion signal: a
// defined-but-unreferenced `snmp client-list` is named on both paths,
// because it is the usual residue of a `client-list-nam` typo.
func TestSNMPClientListUnreferencedWarns15124(t *testing.T) {
	cfg, err := compileSNMPLines(t, []string{
		"set snmp client-list trusted 10.0.0.0/8",
		"set snmp community public authorization read-only",
	})
	if err != nil {
		t.Fatalf("unreferenced client-list must not hard-reject: %v", err)
	}
	if !hasWarningSubstr(cfg.Warnings, "not referenced") {
		t.Fatalf("expected an unreferenced client-list warning, warnings=%v", cfg.Warnings)
	}
	// Referenced: no warning.
	cfg2, err := compileSNMPLines(t, []string{
		"set snmp client-list trusted 10.0.0.0/8",
		"set snmp community public client-list-name trusted",
	})
	if err != nil {
		t.Fatalf("referenced client-list must compile clean: %v", err)
	}
	if hasWarningSubstr(cfg2.Warnings, "not referenced") {
		t.Fatalf("referenced client-list must not warn as unreferenced, warnings=%v", cfg2.Warnings)
	}
}
