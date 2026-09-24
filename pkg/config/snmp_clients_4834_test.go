package config

import (
	"strings"
	"testing"
)

// TestSNMPClients_RestrictTypoRejected is the RED-on-revert guard for #4834.
//
// A mistyped "restrict" keyword (here "restric") detaches from the
// preceding broad prefix, so `0.0.0.0/0 restric` produces TWO client
// entries: an unrestricted `0.0.0.0/0` allow and an unparseable
// `restric` entry. Before the fix, compileClientNets silently dropped the
// unparseable "restric" entry and left `0.0.0.0/0` as a plain allow — a
// silent fail-open (the community becomes answerable from ANY source
// with no commit warning). The fix rejects the commit outright, naming
// the bad token, so the operator catches the typo before it can produce
// an unrestricted community.
func TestSNMPClients_RestrictTypoRejected(t *testing.T) {
	_, err := compileSNMPLines(t, []string{
		"set snmp community mon authorization read-only",
		"set snmp community mon clients 0.0.0.0/0 restric",
		"set snmp community mon clients 10.0.0.0/8",
	})
	if err == nil {
		t.Fatal("typoed 'restrict' keyword ('restric') compiled without error (#4834 fail-open regression)")
	}
	if !strings.Contains(err.Error(), "restric") {
		t.Fatalf("error %q does not name the offending token 'restric'", err)
	}
}

// TestSNMPClients_MalformedPrefixRejected pins the companion case: a plain
// prefix typo (not a "restrict" near-miss) is also rejected at commit,
// rather than being silently dropped from the allowlist.
func TestSNMPClients_MalformedPrefixRejected(t *testing.T) {
	_, err := compileSNMPLines(t, []string{
		"set snmp community mon authorization read-only",
		"set snmp community mon clients 10.0.0.0/99",
	})
	if err == nil {
		t.Fatal("malformed clients prefix '10.0.0.0/99' compiled without error")
	}
	if !strings.Contains(err.Error(), "10.0.0.0/99") {
		t.Fatalf("error %q does not name the offending prefix", err)
	}
}

// TestSNMPClients_RestrictTypoLenientQuarantines pins the #5833 fail-CLOSED
// contract on the tolerant load / peer-sync path. The malformed token the
// STRICT path rejects must NOT brick the node (#1960), but it must also NOT
// leave the surviving broad allow live: `0.0.0.0/0 restric` + `10.0.0.0/8`
// used to drop the bad token and keep `0.0.0.0/0` as a plain allow, so on
// restart/upgrade/peer-sync the community answered from EVERY source (fail
// open). The community is now QUARANTINED to deny-all instead, while the rest
// of the config (a second, well-formed community) still loads, and the warning
// is preserved.
//
// FAIL-ON-REVERT: reverting the quarantine (dropping the malformed token and
// keeping the surviving 0.0.0.0/0 allow) makes AllowsSource("8.8.8.8") return
// true, so the deny assertions below fire RED.
func TestSNMPClients_RestrictTypoLenientQuarantines(t *testing.T) {
	tree := &ConfigTree{}
	lines := []string{
		"set snmp community mon authorization read-only",
		"set snmp community mon clients 0.0.0.0/0 restric",
		"set snmp community mon clients 10.0.0.0/8",
		// A second, WELL-FORMED community: the quarantine is scoped to the
		// affected community, and the REST of the config must still load.
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
		t.Fatalf("CompileConfigLenient must not fail on a typoed clients token (brick-on-restart): %v", err)
	}
	if !hasWarningSubstr(cfg.Warnings, "restric") {
		t.Fatalf("expected a downgraded clients-token warning naming 'restric', warnings=%v", cfg.Warnings)
	}

	mon := cfg.System.SNMP.Communities["mon"]
	if mon == nil {
		t.Fatal("community 'mon' missing from compiled config")
	}
	// Quarantined = DENY-ALL. Every source is denied — the surviving broad
	// 0.0.0.0/0 allow (and the 10.0.0.0/8 allow) must NOT be honored, and IPv6
	// is denied too.
	for _, src := range []string{"8.8.8.8", "10.1.2.3", "192.168.1.1", "2001:db8::1"} {
		if mon.AllowsSource(snmpClientTestSource10687(src)) {
			t.Errorf("quarantined community must DENY %s, but it was allowed "+
				"(fail-open: the broad allow survived the malformed \"restrict\" token, #5833)", src)
		}
	}

	// The rest of the config loaded: the well-formed community keeps its
	// intended allowlist policy (no false quarantine of a sibling community).
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

// TestSNMPClients_WellFormedLenientNoQuarantine confirms the #5833 quarantine
// does not over-fire: a well-formed clients allowlist on the LENIENT path keeps
// its intended longest-prefix restrict/allow semantics (a correctly-spelled
// `restrict` is the modifier, never a malformed prefix entry), with no warning
// and no deny-all quarantine.
func TestSNMPClients_WellFormedLenientNoQuarantine(t *testing.T) {
	tree := &ConfigTree{}
	lines := []string{
		"set snmp community mon authorization read-only",
		"set snmp community mon clients 10.0.0.0/8 restrict", // deny the /8...
		"set snmp community mon clients 10.1.0.0/16",         // ...except this more-specific /16
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
		t.Fatalf("CompileConfigLenient failed on a well-formed allowlist: %v", err)
	}
	if hasWarningSubstr(cfg.Warnings, "restric") {
		t.Fatalf("well-formed clients must not produce a token warning, warnings=%v", cfg.Warnings)
	}
	mon := cfg.System.SNMP.Communities["mon"]
	if mon == nil {
		t.Fatal("community 'mon' missing from compiled config")
	}
	// Longest-prefix restrict semantics intact (no false quarantine):
	//   10.2.3.4 -> matched only by 10.0.0.0/8 restrict -> DENY
	//   10.1.2.3 -> matched by more-specific 10.1.0.0/16 allow           -> ALLOW
	if mon.AllowsSource(snmpClientTestSource10687("10.2.3.4")) {
		t.Error("10.0.0.0/8 restrict must DENY 10.2.3.4")
	}
	if !mon.AllowsSource(snmpClientTestSource10687("10.1.2.3")) {
		t.Error("more-specific 10.1.0.0/16 allow must PERMIT 10.1.2.3 (false quarantine?)")
	}
}

// TestSNMPClients_ValidAccepted confirms the fix does not over-reject: a
// well-formed clients allowlist (CIDR, bare IP, correctly-spelled
// restrict) still compiles clean.
func TestSNMPClients_ValidAccepted(t *testing.T) {
	cfg, err := compileSNMPLines(t, []string{
		"set snmp community mon authorization read-only",
		"set snmp community mon clients 0.0.0.0/0 restrict",
		"set snmp community mon clients 10.0.0.0/8",
		"set snmp community mon clients 192.168.1.5",
	})
	if err != nil {
		t.Fatalf("valid clients allowlist failed to compile: %v", err)
	}
	comm := cfg.System.SNMP.Communities["mon"]
	if comm == nil {
		t.Fatal("community 'mon' missing from compiled config")
	}
	if len(comm.Clients) != 3 {
		t.Fatalf("expected 3 client entries, got %+v", comm.Clients)
	}
}
