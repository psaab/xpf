package config

// #5299: fail-closed validation for the legacy firewall policer
// `if-exceeding bandwidth-limit` / `burst-size-limit` leaves.
//
// Before the fix both leaves were untyped (ValueAny), so the compiler's
// silent-zero parsers (parseBandwidthLimit / parseBurstSizeLimit) coerced
// malformed / zero / overflowing input to 0 bps/bytes. A typo like
// `bandwidth-limit 10mm` committed CLEAN and then fail-closed the meter to
// a drop-all (default `then discard`) — a total outage for matching
// traffic. parseBurstSizeLimit additionally WRAPPED an overflowing uint64
// multiply to a small nonzero value (a silently-wrong meter).
//
// FAIL-ON-REVERT: dropping the validator/valueType wiring from
// schema_cos.go (or ValidatePolicerBurstSize) makes every "rejects"
// assertion below go RED — the malformed/zero/overflow values commit
// clean again and coerce to 0. Reverting the parseBurstSizeLimit
// delegation to the old inline `v * multiplier` makes
// TestPolicer5299_ParseBurstSizeLimit_OverflowReturnsZero go RED (the old
// code returns a wrapped nonzero instead of 0).

import (
	"strings"
	"testing"
)

// policer5299SchemaCheck builds a candidate tree from flat-set lines
// (ParseSetCommand + SetPath — never NewParser, per CLAUDE.md) and runs
// the strict typed-leaf commit gate.
func policer5299SchemaCheck(t *testing.T, cmds ...string) error {
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
	return SchemaValidate(tree, nil)
}

func policer5299Tree(t *testing.T, cmds ...string) *ConfigTree {
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

// --- valid values: strict commit succeeds + compiles to the expected units ---

func TestPolicer5299_Valid_CommitsAndCompiles(t *testing.T) {
	cmds := []string{
		"set firewall policer p-ok if-exceeding bandwidth-limit 10m",
		"set firewall policer p-ok if-exceeding burst-size-limit 15k",
		"set firewall policer p-ok then discard",
	}
	if err := policer5299SchemaCheck(t, cmds...); err != nil {
		t.Fatalf("valid policer should pass strict commit gate, got: %v", err)
	}
	cfg, err := CompileConfig(policer5299Tree(t, cmds...))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	pol := cfg.Firewall.Policers["p-ok"]
	if pol == nil {
		t.Fatalf("policer p-ok not compiled")
	}
	// bandwidth-limit 10m = 10,000,000 bits/sec / 8 = 1,250,000 bytes/sec.
	if pol.BandwidthLimit != 1_250_000 {
		t.Fatalf("BandwidthLimit = %d, want 1250000 bytes/sec", pol.BandwidthLimit)
	}
	// burst-size-limit 15k = 15,000 bytes.
	if pol.BurstSizeLimit != 15_000 {
		t.Fatalf("BurstSizeLimit = %d, want 15000 bytes", pol.BurstSizeLimit)
	}
}

// A bare-integer burst size (unambiguous bytes for a policer) stays valid.
func TestPolicer5299_BareIntegerBurst_Valid(t *testing.T) {
	cmds := []string{
		"set firewall policer p-bare if-exceeding bandwidth-limit 100000",
		"set firewall policer p-bare if-exceeding burst-size-limit 100000",
	}
	if err := policer5299SchemaCheck(t, cmds...); err != nil {
		t.Fatalf("bare-integer policer values should pass strict commit gate, got: %v", err)
	}
	cfg, err := CompileConfig(policer5299Tree(t, cmds...))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	pol := cfg.Firewall.Policers["p-bare"]
	if pol == nil {
		t.Fatalf("policer p-bare not compiled")
	}
	if pol.BurstSizeLimit != 100_000 {
		t.Fatalf("BurstSizeLimit = %d, want 100000 bytes", pol.BurstSizeLimit)
	}
	if pol.BandwidthLimit != 12_500 { // 100000 bps / 8
		t.Fatalf("BandwidthLimit = %d, want 12500 bytes/sec", pol.BandwidthLimit)
	}
}

// --- malformed / zero / negative / overflow: strict commit REJECTS ---

func TestPolicer5299_Reject_BandwidthLimit(t *testing.T) {
	cases := []struct {
		name string
		val  string
	}{
		{"malformed-double-suffix", "10mm"},
		{"zero", "0"},
		{"negative", "-5"},
		{"garbage", "asd"},
		{"nan", "NaN"},
		{"inf", "Inf"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := policer5299SchemaCheck(t,
				"set firewall policer p-bad if-exceeding bandwidth-limit "+tc.val)
			if err == nil {
				t.Fatalf("bandwidth-limit %q: expected strict rejection, got nil "+
					"(pre-#5299 this committed clean and coerced to 0 bps -> drop-all)", tc.val)
			}
			if !strings.Contains(err.Error(), "bandwidth-limit") {
				t.Fatalf("bandwidth-limit %q: error should reference the leaf: %v", tc.val, err)
			}
		})
	}
}

func TestPolicer5299_Reject_BurstSizeLimit(t *testing.T) {
	cases := []struct {
		name string
		val  string
	}{
		{"malformed-double-suffix", "15kk"},
		{"zero", "0"},
		{"negative", "-5"},
		{"garbage", "asd"},
		// ParseUint succeeds (2e13 fits uint64) but *1e9 overflows uint64.
		{"overflow", "20000000000000g"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := policer5299SchemaCheck(t,
				"set firewall policer p-bad if-exceeding burst-size-limit "+tc.val)
			if err == nil {
				t.Fatalf("burst-size-limit %q: expected strict rejection, got nil "+
					"(pre-#5299 this committed clean and coerced/wrapped)", tc.val)
			}
			if !strings.Contains(err.Error(), "burst-size-limit") {
				t.Fatalf("burst-size-limit %q: error should reference the leaf: %v", tc.val, err)
			}
		})
	}
}

// #10310: a policer burst smaller than one maximum-sized packet cannot admit
// any ordinary MTU frame. The strict commit gate must reject it rather than
// installing a bucket that silently marks every packet yellow/red.
func TestPolicer10310_RejectsSubPacketBurst(t *testing.T) {
	for _, value := range []string{"1", "100", "1499"} {
		t.Run(value, func(t *testing.T) {
			err := policer5299SchemaCheck(t,
				"set firewall policer p-subpacket if-exceeding burst-size-limit "+value)
			if err == nil {
				t.Fatalf(
					"burst-size-limit %q: expected rejection below one 1500-byte packet",
					value,
				)
			}
			if !strings.Contains(err.Error(), "burst-size-limit") {
				t.Fatalf("burst-size-limit %q: error should name the leaf: %v", value, err)
			}
		})
	}
	if err := policer5299SchemaCheck(
		t,
		"set firewall policer p-one-packet if-exceeding burst-size-limit 1500",
	); err != nil {
		t.Fatalf("exactly one 1500-byte packet must remain valid: %v", err)
	}
}

// --- tolerant-load path: WARN, not hard-fail ---
//
// The configstore tolerant ingress (Store.Load / SyncApply -> compileTreeLenient)
// runs the SAME SchemaValidate gate but DOWNGRADES a violation to a warning,
// then compiles leniently. We assert that two-tier behavior at the pkg/config
// layer: the strict gate errors (the value that would be downgraded), while the
// lenient compiler does NOT hard-fail (it coerces the bad value to 0, so a
// peer-synced / older-binary config cannot blackout-boot the node).
func TestPolicer5299_TolerantLoad_WarnsNotHardFail(t *testing.T) {
	tree := policer5299Tree(t,
		"set firewall policer p-legacy if-exceeding bandwidth-limit 10mm",
		"set firewall policer p-legacy if-exceeding burst-size-limit 15kk",
	)
	if err := SchemaValidate(tree, nil); err == nil {
		t.Fatalf("strict gate should reject the malformed values (this is the error configstore downgrades to a warning)")
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must NOT hard-fail on the tolerant path, got: %v", err)
	}
	pol := cfg.Firewall.Policers["p-legacy"]
	if pol == nil {
		t.Fatalf("policer p-legacy not compiled on lenient path")
	}
	// The malformed values coerce to 0 on the lenient path (unset), which the
	// strict commit gate is exactly there to reject before it ships.
	if pol.BandwidthLimit != 0 || pol.BurstSizeLimit != 0 {
		t.Fatalf("lenient compile should coerce malformed values to 0, got bw=%d burst=%d",
			pol.BandwidthLimit, pol.BurstSizeLimit)
	}
}

// --- parseBurstSizeLimit overflow: returns 0, never a wrapped nonzero ---

func TestPolicer5299_ParseBurstSizeLimit_OverflowReturnsZero(t *testing.T) {
	// 2e13 fits in uint64; 2e13 * 1e9 = 2e22 overflows uint64 (max ~1.8e19).
	// The pre-#5299 inline `v * multiplier` wrapped this to a small NONZERO
	// value (a silently-wrong meter). The fix returns 0 (the unambiguous
	// "unset" sentinel already rejected loud at commit).
	if got := parseBurstSizeLimit("20000000000000g"); got != 0 {
		t.Fatalf("parseBurstSizeLimit overflow = %d, want 0 (old inline multiply wrapped to a nonzero value)", got)
	}
	// Valid values are unchanged.
	if got := parseBurstSizeLimit("15k"); got != 15_000 {
		t.Fatalf("parseBurstSizeLimit(15k) = %d, want 15000", got)
	}
	if got := parseBurstSizeLimit("1m"); got != 1_000_000 {
		t.Fatalf("parseBurstSizeLimit(1m) = %d, want 1000000", got)
	}
	if got := parseBurstSizeLimit("100000"); got != 100_000 {
		t.Fatalf("parseBurstSizeLimit(100000) = %d, want 100000", got)
	}
}
