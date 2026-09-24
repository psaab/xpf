package config

import (
	"strings"
	"testing"
)

// #5898: a leading/orphan `restrict` — a `restrict` token with NO preceding
// prefix to modify (`clients restrict 0.0.0.0/0`, invalid-Junos ordering) — was
// SILENTLY DROPPED by parseSNMPClients (the `len(out)==0` guard), leaving the
// following `0.0.0.0/0` a plain ALLOW: the SNMP community answerable from every
// source, with NO malformed token recorded, so #5833's quarantine never engaged.
// This is identical on the STRICT and LENIENT paths (so NOT the lenient-only
// class #5833 fixed). The fix records the orphan `restrict` as a client entry —
// "restrict" is not a valid IP/CIDR, so validateSNMPClients flags it MALFORMED —
// hooking into #5833's existing quarantine: strict hard-rejects, lenient
// quarantines to deny-all. A well-formed `<prefix> restrict` is unaffected.

// TestSNMPOrphanRestrictStrictRejected_5898: strict commit hard-rejects a
// leading/orphan `restrict`, naming the offending token.
//
// FAIL-ON-REVERT: restoring the silent drop (len(out)==0 -> skip) makes the
// orphan restrict vanish and `0.0.0.0/0` compile as a plain allow with no error.
func TestSNMPOrphanRestrictStrictRejected_5898(t *testing.T) {
	_, err := compileSNMPLines(t, []string{
		"set snmp community mon authorization read-only",
		"set snmp community mon clients restrict 0.0.0.0/0", // restrict BEFORE the prefix
	})
	if err == nil {
		t.Fatal("a leading/orphan 'restrict' (clients restrict 0.0.0.0/0) compiled without error " +
			"— it was silently dropped, leaving 0.0.0.0/0 a plain allow-all (#5898 fail-open)")
	}
	if !strings.Contains(err.Error(), "restrict") {
		t.Fatalf("error %q must name the offending 'restrict' token", err)
	}
}

// TestSNMPOrphanRestrictLenientQuarantines_5898: the tolerant load / peer-sync
// path must NOT brick (#1960) but must fail CLOSED — the affected community is
// quarantined to DENY-ALL, never left as the fail-open 0.0.0.0/0 allow.
//
// FAIL-ON-REVERT: reverting to the silent drop keeps 0.0.0.0/0 a plain allow, so
// AllowsSource returns TRUE for arbitrary sources -> the deny assertions fire RED.
func TestSNMPOrphanRestrictLenientQuarantines_5898(t *testing.T) {
	tree := &ConfigTree{}
	lines := []string{
		"set snmp community mon authorization read-only",
		"set snmp community mon clients restrict 0.0.0.0/0", // orphan restrict -> quarantine
		// A second, WELL-FORMED community proves the quarantine is scoped and the
		// rest of the config still loads.
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
		t.Fatalf("CompileConfigLenient must not brick on an orphan-restrict typo (#1960): %v", err)
	}
	if !hasWarningSubstr(cfg.Warnings, "restrict") {
		t.Fatalf("expected a downgraded clients-token warning naming 'restrict', warnings=%v", cfg.Warnings)
	}

	mon := cfg.System.SNMP.Communities["mon"]
	if mon == nil {
		t.Fatal("community 'mon' missing from compiled config")
	}
	// Quarantined = DENY-ALL: the surviving broad 0.0.0.0/0 allow must NOT be
	// honored (fail-open), and IPv6 is denied too.
	for _, src := range []string{"8.8.8.8", "10.1.2.3", "192.168.1.1", "2001:db8::1"} {
		if mon.AllowsSource(snmpClientTestSource10687(src)) {
			t.Errorf("quarantined community must DENY %s, but it was allowed — the orphan 'restrict' was "+
				"dropped and the broad 0.0.0.0/0 allow survived (fail-open, #5898)", src)
		}
	}

	// The rest of the config loaded: the well-formed community keeps its policy.
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

// TestSNMPValidRestrictOrderingUnaffected_5898: the fix does not over-reject or
// over-quarantine. The VALID ordering `<prefix> restrict` still applies the
// modifier to its prefix, and a plain allow still allows — no warning, no
// quarantine — on both the strict and lenient paths.
func TestSNMPValidRestrictOrderingUnaffected_5898(t *testing.T) {
	lines := []string{
		"set snmp community mon authorization read-only",
		"set snmp community mon clients 10.0.0.0/8 restrict", // deny 10/8 (valid ordering)...
		"set snmp community mon clients 10.1.0.0/16",         // ...except the more-specific /16
		"set snmp community mon clients 192.168.1.5",         // a bare-IP allow
	}

	// Strict: compiles clean (no over-reject).
	cfg, err := compileSNMPLines(t, lines)
	if err != nil {
		t.Fatalf("valid `<prefix> restrict` ordering must compile clean (strict): %v", err)
	}
	mon := cfg.System.SNMP.Communities["mon"]
	if mon == nil {
		t.Fatal("community 'mon' missing")
	}
	// Longest-prefix restrict/allow semantics intact:
	if mon.AllowsSource(snmpClientTestSource10687("10.2.3.4")) {
		t.Error("10.0.0.0/8 restrict must DENY 10.2.3.4")
	}
	if !mon.AllowsSource(snmpClientTestSource10687("10.1.2.3")) {
		t.Error("more-specific 10.1.0.0/16 allow must PERMIT 10.1.2.3")
	}
	if !mon.AllowsSource(snmpClientTestSource10687("192.168.1.5")) {
		t.Error("bare-IP allow 192.168.1.5 must be PERMITTED")
	}

	// Lenient: no false quarantine (no warning, valid restrict is the modifier).
	tree := &ConfigTree{}
	for _, line := range lines {
		path, perr := ParseSetCommand(line)
		if perr != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, perr)
		}
		if serr := tree.SetPath(path); serr != nil {
			t.Fatalf("SetPath(%q): %v", line, serr)
		}
	}
	lcfg, lerr := CompileConfigLenient(tree)
	if lerr != nil {
		t.Fatalf("valid `<prefix> restrict` must not fail lenient compile: %v", lerr)
	}
	if hasWarningSubstr(lcfg.Warnings, "restrict") {
		t.Fatalf("valid `<prefix> restrict` must NOT produce a token warning (no false quarantine), warnings=%v", lcfg.Warnings)
	}
	lmon := lcfg.System.SNMP.Communities["mon"]
	if lmon == nil || lmon.AllowsSource(snmpClientTestSource10687("10.2.3.4")) || !lmon.AllowsSource(snmpClientTestSource10687("10.1.2.3")) {
		t.Fatal("valid restrict semantics must survive the lenient path unchanged (no false quarantine)")
	}
}
