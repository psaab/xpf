package config_test

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15171 (B19-01): the tcp-mss commit gate checked only the Layer-A wire
// bound [0,65535], not the Junos range 64..65535. `mss 0` committed clean
// as unset (compileFlow stores nothing for v <= 0, so the configured clamp
// silently did not happen — PMTU black-holing on the path it was meant
// for) and 1..63 were written into SYN MSS options (userspace
// clamp_tcp_mss has no floor), collapsing throughput.
//
// Strict (CompileConfig) must reject 0 and 63 naming the range and accept
// 64 and 1350; lenient (CompileConfigLenient) must warn naming the range
// and warn-load. Dual-AST per CLAUDE.md: flat via ParseSetCommand/SetPath
// (mssFlatTree), hierarchical via NewParser().Parse() (mssHierTree).
//
// FAIL-ON-REVERT: ValidateInteger(0, maxWireU16) in checkTCPMSSKind and
// every strict cell below accepts again.
func TestTCPMSSFloor15171_StrictRejectsBelow64(t *testing.T) {
	for _, kind := range []string{"gre-in", "gre-out", "all-tcp"} {
		for _, val := range []string{"0", "1", "63"} {
			tree := mssFlatTree(t, "set security flow tcp-mss "+kind+" "+val)
			_, err := config.CompileConfig(tree)
			if err == nil {
				t.Fatalf("strict must REJECT tcp-mss %s %s (Junos floor is 64)", kind, val)
			}
			if !strings.Contains(err.Error(), "tcp-mss") ||
				!strings.Contains(err.Error(), "out of range [64..65535]") {
				t.Fatalf("reject for %s %s should name tcp-mss and range [64..65535]: %v", kind, val, err)
			}
		}
	}
	// Hierarchical shapes reject identically.
	for _, input := range []string{
		"security { flow { tcp-mss { gre-in { mss 0; } } } }",
		"security { flow { tcp-mss { all-tcp { mss 63; } } } }",
		"security { flow { tcp-mss { gre-out mss 1; } } }",
		"security { flow { tcp-mss all-tcp 0; } }",
	} {
		if _, err := config.CompileConfig(mssHierTree(t, input)); err == nil {
			t.Fatalf("strict must REJECT hierarchical %q", input)
		}
	}
	// Packed flat-set spelling of the hierarchical child.
	if _, err := config.CompileConfig(mssFlatTree(t,
		"set security flow tcp-mss all-tcp mss 0")); err == nil {
		t.Fatal("strict must REJECT `all-tcp mss 0`")
	}
}

func TestTCPMSSFloor15171_StrictAcceptsInRange(t *testing.T) {
	// Junos floor and a typical tunnel value, flat + hierarchical.
	for _, tc := range []struct {
		val  string
		want int
	}{{"64", 64}, {"1350", 1350}, {"65535", 65535}} {
		cfg, err := config.CompileConfig(mssFlatTree(t,
			"set security flow tcp-mss gre-in "+tc.val))
		if err != nil {
			t.Fatalf("strict must ACCEPT tcp-mss gre-in %s: %v", tc.val, err)
		}
		if cfg.Security.Flow.TCPMSSGreIn != tc.want {
			t.Fatalf("gre-in %s compiled to %d, want %d", tc.val, cfg.Security.Flow.TCPMSSGreIn, tc.want)
		}
	}
	mssAcceptStrict(t, mssHierTree(t, `security {
    flow { tcp-mss { gre-in { mss 64; } all-tcp { mss 1350; } } }
}`))
	cfg, err := config.CompileConfig(mssHierTree(t, `security {
    flow { tcp-mss { gre-in { mss 64; } } }
}`))
	if err != nil {
		t.Fatalf("hierarchical mss 64 must compile: %v", err)
	}
	if cfg.Security.Flow.TCPMSSGreIn != 64 {
		t.Fatalf("hierarchical mss 64 compiled to %d", cfg.Security.Flow.TCPMSSGreIn)
	}
	// Mixed shape: child 64 selected, discarded flat token irrelevant.
	mssAcceptStrict(t, mssHierTree(t, `security {
    flow { tcp-mss { gre-in 0 { mss 1360; } } }
}`))
}

func TestTCPMSSFloor15171_LenientWarns(t *testing.T) {
	cases := []struct {
		cmd        string
		wantField  func(*config.Config) int
		wantSubstr string
	}{
		// 0 is treated as unset by the compiler; it must still warn.
		{"set security flow tcp-mss gre-in 0", func(c *config.Config) int { return c.Security.Flow.TCPMSSGreIn }, "unset"},
		// 1..63 reaches the dataplane unchanged; warn it stays in effect.
		{"set security flow tcp-mss gre-in 63", func(c *config.Config) int { return c.Security.Flow.TCPMSSGreIn }, "below 64"},
		{"set security flow tcp-mss all-tcp 1", func(c *config.Config) int { return c.Security.Flow.TCPMSSAllTCP }, "below 64"},
	}
	for _, tc := range cases {
		cfg, err := config.CompileConfigLenient(mssFlatTree(t, tc.cmd))
		if err != nil {
			t.Fatalf("lenient must WARN-LOAD %q, got error: %v", tc.cmd, err)
		}
		found := false
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "tcp-mss") && strings.Contains(w, "[64..65535]") &&
				strings.Contains(w, tc.wantSubstr) {
				found = true
			}
		}
		if !found {
			t.Fatalf("lenient %q should warn naming tcp-mss [64..65535] + %q, got: %v",
				tc.cmd, tc.wantSubstr, cfg.Warnings)
		}
	}
	// The lenient 0 stays unset (no clamp reaches the dataplane).
	cfg, err := config.CompileConfigLenient(mssFlatTree(t, "set security flow tcp-mss gre-in 0"))
	if err != nil {
		t.Fatalf("lenient 0: %v", err)
	}
	if cfg.Security.Flow.TCPMSSGreIn != 0 {
		t.Fatalf("lenient mss 0 must stay unset, got %d", cfg.Security.Flow.TCPMSSGreIn)
	}
	// Node-aware lenient sibling warn-loads too.
	if _, err := config.CompileConfigForNodeLenient(
		mssFlatTree(t, "set security flow tcp-mss gre-in 63"), 0); err != nil {
		t.Fatalf("CompileConfigForNodeLenient must WARN-LOAD mss 63: %v", err)
	}
}
