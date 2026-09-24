package config

import (
	"strings"
	"testing"
)

// Tests for #4098: `security ipsec vpn <name> traffic-selector <ts>
// local-ip / remote-ip` had no commit validation, and pkg/ipsec/policy.go
// rendered the value raw into the swanctl.conf children{} block as
// `local_ts = <value>`. The Junos lexer materializes a `\n` escape inside a
// quoted value, so a selector value could inject an arbitrary swanctl line
// (`updown = <script>`, run as root by charon -> RCE, or an esp_proposals
// override). validateIPsecTrafficSelectorsStrict rejects such a value at
// commit; the render belt (sanitizeSwanctlValue) neutralizes it on the lenient
// load / peer-sync path.

// buildTree4098 compiles a flat set-command list into a ConfigTree via the
// ParseSetCommand + SetPath loop (NewParser merges newline-separated set lines
// into one node and must not be used for set syntax — see CLAUDE.md "Testing
// flat set syntax"). A quoted value carrying a `\n` is materialized into a real
// newline by the lexer, exactly as the exploit input would be.
func buildTree4098(t *testing.T, cmds []string) *ConfigTree {
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

// TestTrafficSelectorNewlineRejectedStrict guards the injection vector end to
// end: a local-ip value with an embedded newline must be rejected at strict
// commit. At HEAD the general free-text control-char gate
// (validateNodesControlChars, freetext.go) fires FIRST and already rejects any
// newline in any value — so this asserts rejection, not a specific gate. The
// #4098-specific RED-on-revert lives in TestTrafficSelectorWhitespaceRejectedStrict
// / TestTrafficSelectorNonCIDRRejectedStrict, which exercise cases the general
// control-char gate does NOT catch (whitespace, malformed shape).
func TestTrafficSelectorNewlineRejectedStrict(t *testing.T) {
	tree := buildTree4098(t, []string{
		`set security ipsec vpn v1 bind-interface st0`,
		`set security ipsec vpn v1 traffic-selector ts1 local-ip "10.0.0.0/24\n        updown = /tmp/pwn.sh"`,
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted a traffic-selector local-ip with an embedded newline; want a strict reject (#4098)")
	}
	if !strings.Contains(err.Error(), "control character") {
		t.Fatalf("reject error %q should reference the control character", err.Error())
	}
}

// TestTrafficSelectorWhitespaceRejectedStrict is the primary #4098 RED-on-revert
// guard. A value carrying only whitespace (no control character) clears the
// general control-char gate, so ONLY validateIPsecTrafficSelectorsStrict rejects
// it. Reverting the validator call in compiler.go makes CompileConfig accept the
// value and this test goes RED. A space in local_ts still yields a malformed /
// mis-scoped swanctl selector, so rejecting it is correct.
func TestTrafficSelectorWhitespaceRejectedStrict(t *testing.T) {
	tree := buildTree4098(t, []string{
		`set security ipsec vpn v1 bind-interface st0`,
		`set security ipsec vpn v1 traffic-selector ts1 local-ip "10.0.0.0/24 updown=/tmp/pwn.sh"`,
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted a traffic-selector local-ip with embedded whitespace; want a strict reject (#4098)")
	}
	if !strings.Contains(err.Error(), "#4098") ||
		!strings.Contains(err.Error(), "traffic-selector") ||
		!strings.Contains(err.Error(), "whitespace") {
		t.Fatalf("reject error %q does not identify the #4098 traffic-selector gate", err.Error())
	}
}

// TestTrafficSelectorNonCIDRRejectedStrict is a second #4098 RED-on-revert case:
// a value that clears the control-char gate but is not a CIDR / host / range.
func TestTrafficSelectorNonCIDRRejectedStrict(t *testing.T) {
	tree := buildTree4098(t, []string{
		`set security ipsec vpn v1 bind-interface st0`,
		`set security ipsec vpn v1 traffic-selector ts1 local-ip not.an.address`,
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted a non-CIDR traffic-selector local-ip; want a strict reject (#4098)")
	}
	if !strings.Contains(err.Error(), "#4098") || !strings.Contains(err.Error(), "CIDR") {
		t.Fatalf("reject error %q should identify the #4098 gate and the required CIDR/host/range shape", err.Error())
	}
}

// TestTrafficSelectorLenientWarns proves the #1960 downgrade for MY gate: a
// value STRICT rejects (whitespace, clean of control chars so the general gate
// ignores it) must NOT fail the lenient load / peer-sync compile — an
// already-persisted or peer-synced config still boots — but must surface as a
// #4098 warning. The render belt keeps the value inert.
func TestTrafficSelectorLenientWarns(t *testing.T) {
	tree := buildTree4098(t, []string{
		`set security ipsec vpn v1 bind-interface st0`,
		`set security ipsec vpn v1 traffic-selector ts1 local-ip "10.0.0.0/24 updown=/tmp/pwn.sh"`,
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient must not fail on a persisted config (#1960): %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#4098") && strings.Contains(w, "traffic-selector") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("lenient compile did not warn about the injected traffic-selector; warnings=%v", cfg.Warnings)
	}
}

// TestTrafficSelectorValidCIDRAccepted is the over-reject negative control: a
// well-formed selector (CIDR both sides) commits cleanly and warns on neither
// path.
func TestTrafficSelectorValidCIDRAccepted(t *testing.T) {
	tree := buildTree4098(t, []string{
		`set security ipsec vpn v1 bind-interface st0`,
		`set security ipsec vpn v1 traffic-selector ts1 local-ip 10.0.0.0/24`,
		`set security ipsec vpn v1 traffic-selector ts1 remote-ip 2001:db8::/48`,
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig rejected a valid CIDR traffic selector: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#4098") {
			t.Fatalf("clean selector produced a #4098 warning: %q", w)
		}
	}
}

// TestTrafficSelectorRangeAndHostAccepted guards the host-address and range
// shapes the validator must also accept (a false reject would break legitimate
// configs).
func TestTrafficSelectorRangeAndHostAccepted(t *testing.T) {
	tree := buildTree4098(t, []string{
		`set security ipsec vpn v1 bind-interface st0`,
		`set security ipsec vpn v1 traffic-selector ts1 local-ip 10.0.0.5`,
		`set security ipsec vpn v1 traffic-selector ts1 remote-ip 10.0.1.10-10.0.1.20`,
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig rejected a host / range traffic selector: %v", err)
	}
}
