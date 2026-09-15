package natshow

import (
	"context"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// Unknown NAT `match` leaves — #9877 show cells.
//
// A rule the snapshot builder skips must render NOT INSTALLED with the dropped
// leaf named — on every mode, including interface-mode source NAT (which has
// no pool verdict to hang the annotation on). Fixtures compile through the
// REAL tolerant path so the marker the renderer reads is the one production
// sets. The CLI/REST/gRPC surfaces share config.SourceNATRuleNotInstalledReason
// (pinned in pkg/config); these cells pin the natshow detail renderers.

// lenientNATCfg9877 compiles set-lines on the tolerant load / peer-sync path.
func lenientNATCfg9877(t *testing.T, cmds []string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, cmd := range cmds {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	return cfg
}

func TestSourceSkippedRuleAnnotatesNotInstalled9877(t *testing.T) {
	t.Run("interface mode", func(t *testing.T) {
		cfg := lenientNATCfg9877(t, []string{
			"set security nat source rule-set rs1 from zone trust",
			"set security nat source rule-set rs1 to zone untrust",
			"set security nat source rule-set rs1 rule r1 match source-address 10.0.0.0/8",
			"set security nat source rule-set rs1 rule r1 match soruce-address 192.168.0.0/16",
			"set security nat source rule-set rs1 rule r1 then source-nat interface",
		})
		var b strings.Builder
		RenderSourceRuleDetail(context.Background(), &b, cfg, nil, nil)
		got := b.String()
		if !strings.Contains(got, "NOT INSTALLED") {
			t.Fatalf("skipped interface-mode rule renders armed (no NOT INSTALLED):\n%s", got)
		}
		if !strings.Contains(got, "soruce-address") {
			t.Fatalf("annotation does not name the dropped leaf:\n%s", got)
		}
	})
	t.Run("pool mode", func(t *testing.T) {
		cfg := lenientNATCfg9877(t, []string{
			"set security nat source pool p1 address 198.51.100.1/32",
			"set security nat source rule-set rs1 from zone trust",
			"set security nat source rule-set rs1 to zone untrust",
			"set security nat source rule-set rs1 rule r1 match source-address 10.0.0.0/8",
			"set security nat source rule-set rs1 rule r1 match soruce-address 192.168.0.0/16",
			"set security nat source rule-set rs1 rule r1 then source-nat pool p1",
		})
		var b strings.Builder
		RenderSourceRuleDetail(context.Background(), &b, cfg, nil, nil)
		got := b.String()
		if !strings.Contains(got, "NOT INSTALLED") || !strings.Contains(got, "soruce-address") {
			t.Fatalf("skipped pool-mode rule misrenders:\n%s", got)
		}
	})
	t.Run("clean control stays armed", func(t *testing.T) {
		cfg := lenientNATCfg9877(t, []string{
			"set security nat source rule-set rs1 from zone trust",
			"set security nat source rule-set rs1 to zone untrust",
			"set security nat source rule-set rs1 rule r1 match source-address 10.0.0.0/8",
			"set security nat source rule-set rs1 rule r1 then source-nat interface",
		})
		var b strings.Builder
		RenderSourceRuleDetail(context.Background(), &b, cfg, nil, nil)
		if got := b.String(); strings.Contains(got, "NOT INSTALLED") {
			t.Fatalf("clean rule renders NOT INSTALLED:\n%s", got)
		}
	})
	t.Run("skipped rule renders no hits line", func(t *testing.T) {
		cfg := lenientNATCfg9877(t, []string{
			"set security nat source pool p1 address 198.51.100.1/32",
			"set security nat source rule-set rs1 from zone trust",
			"set security nat source rule-set rs1 to zone untrust",
			"set security nat source rule-set rs1 rule r1 match source-address 10.0.0.0/8",
			"set security nat source rule-set rs1 rule r1 match soruce-address 192.168.0.0/16",
			"set security nat source rule-set rs1 rule r1 then source-nat pool p1",
		})
		// Armed dataplane with a nonzero counter behind the rule's key: if
		// the hits read is not gated on the exclusion verdict, it leaks
		// into the output as an armed-but-idle (or busy) counter.
		dp := &fakeReader{counters: map[uint32]dataplane.CounterValue{7: {Packets: 41, Bytes: 4200}}}
		key := dataplane.NATCounterKey(dataplane.NATCounterTypeSource, "rs1", "r1")
		cr := &dataplane.ApplyResult{NATCounterIDs: map[string]uint32{key: 7}}
		var b strings.Builder
		RenderSourceRuleDetail(context.Background(), &b, cfg, dp, func() *dataplane.ApplyResult { return cr })
		got := b.String()
		if !strings.Contains(got, "NOT INSTALLED") {
			t.Fatalf("precondition: skipped rule renders armed:\n%s", got)
		}
		if strings.Contains(got, "Translation hits") {
			t.Fatalf("skipped rule renders a Translation hits line — it owns no counter:\n%s", got)
		}
	})
}

func TestDestSkippedRuleAnnotatesNotInstalled9877(t *testing.T) {
	cfg := lenientNATCfg9877(t, []string{
		"set security nat destination pool p1 address 192.0.2.5",
		"set security nat destination rule-set rs1 from zone trust",
		"set security nat destination rule-set rs1 rule r1 match destination-address 203.0.113.0/24",
		"set security nat destination rule-set rs1 rule r1 match soruce-address 10.0.0.0/8",
		"set security nat destination rule-set rs1 rule r1 then destination-nat pool p1",
	})
	var b strings.Builder
	RenderDestRuleDetail(context.Background(), &b, cfg, nil, nil)
	got := b.String()
	if !strings.Contains(got, "NOT INSTALLED") || !strings.Contains(got, "soruce-address") {
		t.Fatalf("skipped destination rule misrenders:\n%s", got)
	}
}

func TestStaticSkippedRuleAnnotatesNotInstalled9877(t *testing.T) {
	t.Run("plain", func(t *testing.T) {
		cfg := lenientNATCfg9877(t, []string{
			"set security nat static rule-set rs1 from zone untrust",
			"set security nat static rule-set rs1 rule r1 match destination-address 198.51.100.10/32",
			"set security nat static rule-set rs1 rule r1 match soruce-address 10.0.0.0/8",
			"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.5/32",
		})
		var b strings.Builder
		RenderStatic(&b, cfg)
		got := b.String()
		if !strings.Contains(got, "NOT INSTALLED") || !strings.Contains(got, "soruce-address") {
			t.Fatalf("skipped static rule misrenders:\n%s", got)
		}
	})
	t.Run("nptv6", func(t *testing.T) {
		cfg := lenientNATCfg9877(t, []string{
			"set security nat static rule-set rs1 from zone trust",
			"set security nat static rule-set rs1 rule r1 match destination-address 2001:db8:1::/48",
			"set security nat static rule-set rs1 rule r1 match soruce-address 2001:db8:9::/48",
			"set security nat static rule-set rs1 rule r1 then static-nat nptv6-prefix fd00:1::/48",
		})
		var b strings.Builder
		RenderStatic(&b, cfg)
		got := b.String()
		if !strings.Contains(got, "NOT INSTALLED") || !strings.Contains(got, "soruce-address") {
			t.Fatalf("skipped NPTv6 rule misrenders:\n%s", got)
		}
	})
}

// TestSourceBothMarkersAnnotatesAdmitted9874_9877 pins the note-site
// precedence (second-lander cell, parent ruling: DISARM-WINS): the #9874
// ADMITTED note wins over NOT INSTALLED — the rule ships as the fail-closed
// drop tombstone (deny: drop + stop), so claiming not-installed would be the
// #6534 lie in the other direction.
func TestSourceBothMarkersAnnotatesAdmitted9874_9877(t *testing.T) {
	cfg := lenientNATCfg9877(t, []string{
		"set security nat source pool p1 address 198.51.100.1/32",
		"set security nat source rule-set rs1 from zone trust",
		"set security nat source rule-set rs1 to zone untrust",
		"set security nat source rule-set rs1 rule r1 match soruce-address 192.168.0.0/16",
		"set security nat source rule-set rs1 rule r1 then source-nat pool p1",
	})
	var b strings.Builder
	RenderSourceRuleDetail(context.Background(), &b, cfg, nil, nil)
	got := b.String()
	if !strings.Contains(got, "ADMITTED BY TOLERANT LOAD") || !strings.Contains(got, "#9874") {
		t.Fatalf("both-markers rule misrenders:\n%s", got)
	}
	if strings.Contains(got, "NOT INSTALLED") {
		t.Fatalf("both-markers rule claims NOT INSTALLED for a shipped tombstone:\n%s", got)
	}
}

// TestDestBothMarkersAnnotatesFirstCause9874_9877 pins the destination
// first-cause order (second-lander cell): the #9874 unconstrained verdict
// precedes the #9877 clause in both the predicate and the builder, so the
// annotation reads #9874. The typo is named by the compile warning, not here.
func TestDestBothMarkersAnnotatesFirstCause9874_9877(t *testing.T) {
	cfg := lenientNATCfg9877(t, []string{
		"set security nat destination pool p1 address 192.0.2.5",
		"set security nat destination rule-set rs1 from zone trust",
		"set security nat destination rule-set rs1 rule r1 match soruce-address 10.0.0.0/8",
		"set security nat destination rule-set rs1 rule r1 then destination-nat pool p1",
	})
	var b strings.Builder
	RenderDestRuleDetail(context.Background(), &b, cfg, nil, nil)
	got := b.String()
	if !strings.Contains(got, "NOT INSTALLED") || !strings.Contains(got, "#9874") {
		t.Fatalf("both-markers destination rule misrenders:\n%s", got)
	}
	if strings.Contains(got, "soruce-address") {
		t.Fatalf("both-markers destination annotation names the typo — first-cause order broken:\n%s", got)
	}
}

// TestDestSkippedRuleRendersNoHitsLine9877: a skipped destination rule owns no
// counter, so no Translation hits line may print (the source renderer's #8185
// shape). Armed dataplane with a nonzero counter behind the rule's key: if the
// hits read is not gated on the exclusion verdict, it leaks into the output.
func TestDestSkippedRuleRendersNoHitsLine9877(t *testing.T) {
	cfg := lenientNATCfg9877(t, []string{
		"set security nat destination pool p1 address 192.0.2.5",
		"set security nat destination rule-set rs1 from zone trust",
		"set security nat destination rule-set rs1 rule r1 match destination-address 203.0.113.0/24",
		"set security nat destination rule-set rs1 rule r1 match soruce-address 10.0.0.0/8",
		"set security nat destination rule-set rs1 rule r1 then destination-nat pool p1",
	})
	dp := &fakeReader{counters: map[uint32]dataplane.CounterValue{9: {Packets: 41, Bytes: 4200}}}
	key := dataplane.NATCounterKey(dataplane.NATCounterTypeDest, "rs1", "r1")
	cr := &dataplane.ApplyResult{NATCounterIDs: map[string]uint32{key: 9}}
	var b strings.Builder
	RenderDestRuleDetail(context.Background(), &b, cfg, dp, func() *dataplane.ApplyResult { return cr })
	got := b.String()
	if !strings.Contains(got, "NOT INSTALLED") {
		t.Fatalf("precondition: skipped rule renders armed:\n%s", got)
	}
	if strings.Contains(got, "Translation hits") {
		t.Fatalf("skipped rule renders a Translation hits line — it owns no counter:\n%s", got)
	}
}
