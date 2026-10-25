package config_test

// #1979 Layer B — commit-time NUM_WIDTH range validation for the
// flow/flow-export fields that Layer A (#1977,
// pkg/dataplane/userspace/flow.go) coerces to Rust u16/u32/u64.
//
// Tier 1 (version9 / version-ipfix flow-active/inactive-timeout) and Tier 2
// (tcp-session / udp-session / icmp-session timeouts, sampling input rate,
// flow-server port) are TYPED setSchema leaves, so accept/reject is asserted
// here through SchemaValidate. Tier 3 (tcp-mss) stays opaque in setSchema and
// is validated by the compiler AST pre-walk — its accept/reject is in
// compiler_tcp_mss_range_test.go via CompileConfig, NOT SchemaValidate.
//
// Per the dual-AST testing rule (CLAUDE.md) flat set-syntax is driven via
// ParseSetCommand + tree.SetPath (flatSchemaCheck), hierarchical via
// NewParser().Parse() (schemaCheck) — NEVER NewParser for set-syntax.

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// rangeAccept asserts SchemaValidate accepts a set-syntax config.
func rangeAccept(t *testing.T, cmds ...string) {
	t.Helper()
	if err := flatSchemaCheck(t, cmds...); err != nil {
		t.Fatalf("expected ACCEPT for %v, got: %v", cmds, err)
	}
}

// rangeReject asserts SchemaValidate rejects a set-syntax config with a
// range/out-of-range error that quotes the leaf keyword.
func rangeReject(t *testing.T, leaf string, cmds ...string) {
	t.Helper()
	err := flatSchemaCheck(t, cmds...)
	if err == nil {
		t.Fatalf("expected REJECT for %v, got nil", cmds)
	}
	if !strings.Contains(err.Error(), "out of range") && !strings.Contains(err.Error(), "not an integer") {
		t.Fatalf("error should be a range/integer error for %v: %v", cmds, err)
	}
	if leaf != "" && !strings.Contains(err.Error(), leaf) {
		t.Fatalf("error should reference leaf %q for %v: %v", leaf, cmds, err)
	}
}

// --- Tier 1: version9 / version-ipfix flow-active/inactive-timeout (u32) ---

func TestNumWidth_Tier1_Version9Timeouts(t *testing.T) {
	base := "set services flow-monitoring version9 template t1 "
	rangeAccept(t, base+"flow-active-timeout 60")
	rangeAccept(t, base+"flow-inactive-timeout 15")
	rangeAccept(t, base+"flow-active-timeout 0")          // lower bound
	rangeAccept(t, base+"flow-active-timeout 4294967295") // u32 max
	rangeReject(t, "flow-active-timeout", base+"flow-active-timeout -1")
	rangeReject(t, "flow-active-timeout", base+"flow-active-timeout 4294967296") // u32 max+1
	rangeReject(t, "flow-inactive-timeout", base+"flow-inactive-timeout 5000000000")

	// Hierarchical shape must accept/reject identically.
	if err := schemaCheck(t, `services {
    flow-monitoring {
        version9 { template t1 { flow-active-timeout 60; } }
    }
}`); err != nil {
		t.Fatalf("hierarchical valid: %v", err)
	}
	if err := schemaCheck(t, `services {
    flow-monitoring {
        version9 { template t1 { flow-active-timeout 5000000000; } }
    }
}`); err == nil {
		t.Fatal("hierarchical out-of-range version9 flow-active-timeout should reject")
	}
}

func TestNumWidth_Tier1_VersionIPFIXTimeouts(t *testing.T) {
	// UX parity only (these do NOT reach the wire — buildFlowExportSnapshot
	// reads fm.Version9 only). Plain accept/reject still applies.
	base := "set services flow-monitoring version-ipfix template t1 "
	rangeAccept(t, base+"flow-active-timeout 60")
	rangeAccept(t, base+"flow-inactive-timeout 4294967295")
	rangeReject(t, "flow-active-timeout", base+"flow-active-timeout 4294967296")
}

// --- Tier 2: session timeouts (u64, cap MaxDurationSeconds) ---

func TestNumWidth_Tier2_SessionTimeouts(t *testing.T) {
	max := config.MaxDurationSeconds // 9223372036

	// tcp-session: all four typed timeouts (only established reaches wire,
	// the rest share the Duration-overflow ceiling).
	for _, kind := range []string{"established-timeout", "initial-timeout", "tcp-initial-timeout", "closing-timeout", "time-wait-timeout"} {
		rangeAccept(t, "set security flow tcp-session "+kind+" 1800")
		rangeAccept(t, "set security flow tcp-session "+kind+" 0")
		rangeReject(t, kind, "set security flow tcp-session "+kind+" -1")
		// MaxDurationSeconds+1 overflows the secs*1e9 product.
		rangeReject(t, kind, "set security flow tcp-session "+kind+" 9223372037")
	}
	// Exactly MaxDurationSeconds is accepted (Layer A leaves it unchanged).
	rangeAccept(t, "set security flow tcp-session established-timeout 9223372036")
	if max != 9223372036 {
		t.Fatalf("MaxDurationSeconds drifted from 9223372036: %d", max)
	}

	// tcp-session presence flags still accepted (declared presence-only).
	rangeAccept(t, "set security flow tcp-session no-syn-check")
	rangeAccept(t, "set security flow tcp-session rst-invalidate-session")
	rangeAccept(t, "set security flow tcp-session fin-invalidate-session")
	rangeAccept(t, "set security flow tcp-session no-sequence-check") // #2008 M9

	// udp-session / icmp-session timeout.
	rangeAccept(t, "set security flow udp-session timeout 60")
	rangeReject(t, "timeout", "set security flow udp-session timeout 9223372037")
	rangeAccept(t, "set security flow icmp-session timeout 60")
	rangeReject(t, "timeout", "set security flow icmp-session timeout -1")

	// Hierarchical shape parity.
	if err := schemaCheck(t, `security {
    flow {
        tcp-session { established-timeout 1800; no-syn-check; }
        udp-session { timeout 60; }
        icmp-session { timeout 60; }
    }
}`); err != nil {
		t.Fatalf("hierarchical valid session timeouts: %v", err)
	}
	if err := schemaCheck(t, `security {
    flow { udp-session { timeout 9223372037; } }
}`); err == nil {
		t.Fatal("hierarchical out-of-range udp-session timeout should reject")
	}
}

// TestSessionTimeout_2441_CommitGate is the #2441 operator-facing reject pin.
// The Rust SessionTimeouts::from_seconds saturates seconds→ns at
// MAX_SESSION_TIMEOUT_SECS (== config.MaxDurationSeconds) as the runtime
// backstop; this Go gate is the load-bearing in-band reject so an absurd
// configured timeout is refused at commit with a clear error rather than
// silently saturated at runtime. fail-on-revert: drop the
// ValidateInteger(0, MaxDurationSeconds) bound from any of these leaves (set
// it to ValidateIntegerMin(0) / no upper bound) and the matching reject
// assertion below goes red.
func TestSessionTimeout_2441_CommitGate(t *testing.T) {
	over := "9223372037" // config.MaxDurationSeconds + 1 — the first seconds
	// value whose secs*1e9 product overflows i64/u64.
	atMax := "9223372036" // exactly config.MaxDurationSeconds — accepted.

	// All three timeouts that reach Rust from_seconds: established (TCP), udp,
	// icmp. Each rejects over-max at commit and accepts the exact max.
	rangeReject(t, "established-timeout",
		"set security flow tcp-session established-timeout "+over)
	rangeAccept(t, "set security flow tcp-session established-timeout "+atMax)

	rangeReject(t, "timeout", "set security flow udp-session timeout "+over)
	rangeAccept(t, "set security flow udp-session timeout "+atMax)

	rangeReject(t, "timeout", "set security flow icmp-session timeout "+over)
	rangeAccept(t, "set security flow icmp-session timeout "+atMax)

	// The gate's max MUST equal the documented Rust MAX_SESSION_TIMEOUT_SECS
	// contract; if MaxDurationSeconds ever drifts the two layers diverge.
	if config.MaxDurationSeconds != 9223372036 {
		t.Fatalf("MaxDurationSeconds drifted from the #2441 contract value "+
			"(must equal Rust MAX_SESSION_TIMEOUT_SECS = i64::MAX/1e9 = "+
			"9223372036): got %d", config.MaxDurationSeconds)
	}
}

// --- Tier 2: sampling input rate (u32) — Q3 = [0, u32max], accept 0 ---

func TestNumWidth_Tier2_SamplingRate(t *testing.T) {
	base := "set forwarding-options sampling instance i1 input rate "
	// Q3 DECISION: accept 0 (the documented `0 = sample all` sentinel;
	// Layer A normalizes rate<=0 -> 1). This is the EXACT Layer-A mirror.
	rangeAccept(t, base+"0")
	rangeAccept(t, base+"1")
	rangeAccept(t, base+"1000")
	rangeAccept(t, base+"4294967295") // u32 max
	rangeReject(t, "rate", base+"-1")
	rangeReject(t, "rate", base+"4294967296") // u32 max+1

	if err := schemaCheck(t, `forwarding-options {
    sampling { instance i1 { input { rate 1000; } } }
}`); err != nil {
		t.Fatalf("hierarchical valid sampling rate: %v", err)
	}
	if err := schemaCheck(t, `forwarding-options {
    sampling { instance i1 { input { rate 4294967296; } } }
}`); err == nil {
		t.Fatal("hierarchical out-of-range sampling rate should reject")
	}
}

// --- Tier 2: flow-server port (u16, [1,65535]) ---

func TestNumWidth_Tier2_FlowServerPort(t *testing.T) {
	for _, fam := range []string{"inet", "inet6"} {
		base := "set forwarding-options sampling instance i1 family " + fam + " output flow-server 10.0.0.1 "
		if fam == "inet6" {
			base = "set forwarding-options sampling instance i1 family " + fam + " output flow-server 2001:db8::1 "
		}
		rangeAccept(t, base+"port 2055")
		rangeAccept(t, base+"port 65535")
		rangeReject(t, "port", base+"port 0")     // [1,65535]: Layer A skips port 0 / <1
		rangeReject(t, "port", base+"port 65536") // >u16
		rangeReject(t, "port", base+"port -1")
	}

	// Bare flow-server (no port) still accepted; the other declared
	// children (version9-template, source-address) still accepted.
	rangeAccept(t, "set forwarding-options sampling instance i1 family inet output flow-server 10.0.0.1")
	rangeAccept(t, "set forwarding-options sampling instance i1 family inet output flow-server 10.0.0.1 version9-template t1")
	rangeAccept(t, "set forwarding-options sampling instance i1 family inet output flow-server 10.0.0.1 source-address 10.0.0.9")

	if err := schemaCheck(t, `forwarding-options {
    sampling { instance i1 { family inet { output { flow-server 10.0.0.1 { port 2055; } } } } }
}`); err != nil {
		t.Fatalf("hierarchical valid flow-server port: %v", err)
	}
	if err := schemaCheck(t, `forwarding-options {
    sampling { instance i1 { family inet { output { flow-server 10.0.0.1 { port 65536; } } } } }
}`); err == nil {
		t.Fatal("hierarchical out-of-range flow-server port should reject")
	}
}

// --- Round-trip stability: an expanded container must not corrupt grouping ---

func TestNumWidth_RoundTripStable(t *testing.T) {
	tree := &config.ConfigTree{}
	cmds := []string{
		"set services flow-monitoring version9 template t1 flow-active-timeout 60",
		"set services flow-monitoring version9 template t1 flow-inactive-timeout 15",
		"set security flow tcp-session established-timeout 1800",
		"set security flow tcp-session no-syn-check",
		"set security flow udp-session timeout 60",
		"set security flow icmp-session timeout 60",
		"set forwarding-options sampling instance i1 input rate 1000",
		"set forwarding-options sampling instance i1 family inet output flow-server 10.0.0.1 port 2055",
	}
	for _, cmd := range cmds {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	const golden = `set services flow-monitoring version9 template t1 flow-active-timeout 60
set services flow-monitoring version9 template t1 flow-inactive-timeout 15
set security flow tcp-session established-timeout 1800
set security flow tcp-session no-syn-check
set security flow udp-session timeout 60
set security flow icmp-session timeout 60
set forwarding-options sampling instance i1 input rate 1000
set forwarding-options sampling instance i1 family inet output flow-server 10.0.0.1 port 2055
`
	if got := tree.FormatSet(); got != golden {
		t.Fatalf("flow numwidth grouping changed:\n--- got ---\n%s\n--- want ---\n%s", got, golden)
	}

	// Two flow-servers must APPEND (multiple collectors valid), not replace.
	for _, cmd := range []string{
		"set forwarding-options sampling instance i1 family inet output flow-server 10.0.0.2 port 2056",
	} {
		path, _ := config.ParseSetCommand(cmd)
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	out := tree.FormatSet()
	if strings.Count(out, "flow-server 10.0.0.1") == 0 || strings.Count(out, "flow-server 10.0.0.2") == 0 {
		t.Fatalf("expected both flow-servers to survive (APPEND, not replace):\n%s", out)
	}
}

// --- Completion parity: every compiler-read child of an expanded container
// must still be offered (no silent drop after the container expansion). ---

func TestNumWidth_CompletionParity(t *testing.T) {
	want := func(t *testing.T, tokens []string, expected ...string) {
		t.Helper()
		got := config.CompleteSetPath(tokens)
		set := map[string]bool{}
		for _, g := range got {
			set[g] = true
		}
		for _, e := range expected {
			if !set[e] {
				t.Fatalf("completion at %v missing %q (got %v)", tokens, e, got)
			}
		}
	}
	want(t, []string{"security", "flow", "tcp-session"},
		"established-timeout", "initial-timeout", "tcp-initial-timeout", "closing-timeout", "time-wait-timeout",
		"no-syn-check", "no-syn-check-in-tunnel", "rst-invalidate-session", "fin-invalidate-session", "no-sequence-check")
	want(t, []string{"security", "flow", "udp-session"}, "timeout")
	want(t, []string{"security", "flow", "icmp-session"}, "timeout")
	want(t, []string{"forwarding-options", "sampling", "instance", "i1", "input"}, "rate")
	want(t, []string{"forwarding-options", "sampling", "instance", "i1", "family", "inet", "output", "flow-server", "10.0.0.1"},
		"port", "version9-template", "version9", "source-address")
}
