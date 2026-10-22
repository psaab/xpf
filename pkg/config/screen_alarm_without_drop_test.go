package config

import (
	"strings"
	"testing"
)

// fable-review-164 L-10: the Junos profile-wide `alarm-without-drop` screen
// ids-option (audit/log-only mode) was hard-rejected at commit — the
// compileScreen top-level family switch accepted only icmp/ip/tcp/udp/
// limit-session, so `alarm-without-drop` landed in UnknownLeaves and
// validateScreenUnknownStrict (#3318) failed the commit. These tests pin the
// fix: the leaf compiles, threads onto ScreenProfile.AlarmWithoutDrop, and is
// known to the config-mode schema; garbage after it is still rejected.
//
// FAIL-ON-REVERT: drop the `case "alarm-without-drop"` arm in compileScreen and
// the accept subtest goes RED (commit rejects a valid audit-mode profile);
// remove the AlarmWithoutDrop assignment and the field stays false.
func TestScreenAlarmWithoutDropCompiles(t *testing.T) {
	tree := buildTree(t, []string{
		// A profile with a real check PLUS the profile-wide audit modifier.
		"set security screen ids-option audit tcp land",
		"set security screen ids-option audit alarm-without-drop",
		"set interfaces ge-0-0-1 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone untrust screen audit",
		"set security zones security-zone untrust interfaces ge-0-0-1",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig rejected a valid alarm-without-drop profile: %v", err)
	}
	sp := cfg.Security.Screen["audit"]
	if sp == nil {
		t.Fatalf("screen profile audit not compiled")
	}
	if !sp.AlarmWithoutDrop {
		t.Fatalf("AlarmWithoutDrop not set on the compiled profile (leaf dropped)")
	}
	if !sp.TCP.Land {
		t.Fatalf("the sibling land check must still compile alongside alarm-without-drop")
	}
	// The config-mode schema must recognize the leaf (commit-check + completion).
	if err := SchemaValidate(tree); err != nil {
		t.Fatalf("SchemaValidate rejected a valid alarm-without-drop leaf: %v", err)
	}
}

// A profile WITHOUT the modifier must leave AlarmWithoutDrop false (default
// drop-on-trip behavior is unchanged).
func TestScreenAlarmWithoutDropDefaultFalse(t *testing.T) {
	tree := buildTree(t, []string{
		"set security screen ids-option plain tcp land",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if sp := cfg.Security.Screen["plain"]; sp == nil || sp.AlarmWithoutDrop {
		t.Fatalf("AlarmWithoutDrop must default to false when the leaf is absent")
	}
}

// A trailing garbage token after the boolean flag is still rejected at commit
// (recordKeyExtras -> UnknownLeaves -> validateScreenUnknownStrict), so a typo
// like `alarm-without-drop enable` is not silently accepted.
func TestScreenAlarmWithoutDropTrailingTokenRejected(t *testing.T) {
	tree := buildTree(t, []string{
		"set security screen ids-option bad-screen alarm-without-drop bogus",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("expected commit to reject a trailing token after alarm-without-drop")
	}
	if !strings.Contains(err.Error(), "alarm-without-drop bogus") {
		t.Fatalf("error %q does not name the offending trailing token", err.Error())
	}
}
