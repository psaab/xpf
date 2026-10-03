package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #6848 (#4228 Gap 7 residual): `show class-of-service rewrite-rule` over gRPC.
//
// This is the PRODUCIBILITY half of the coverage. The format-level tests in
// pkg/dataplane/userspace/format hand-build a ClassOfServiceConfig; that proves
// the renderer works but not that the config compiler ever emits the shape it
// renders. Here every rule is authored as real `set` syntax, committed through
// the real store, and read back through the real ShowText dispatch — so the
// external four-family split is covered: two entry lists and two name-only
// surfaces. The compiler's validation-only inert entries are not exposed here.
//
// It also covers the remote surface specifically: the local CLI and the gRPC
// server are separate dispatchers, and a command wired into only one of them
// works interactively while silently falling through to help text on the `cli`
// binary most operators use.
func newCoSRewriteRuleServer(t *testing.T) *Server {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	for _, cmd := range []string{
		"class-of-service forwarding-classes queue 0 best-effort",
		"class-of-service forwarding-classes queue 1 premium",
		// dscp: the one family the dataplane actually applies on egress.
		"class-of-service rewrite-rules dscp rw-dscp forwarding-class premium loss-priority low code-point ef",
		"class-of-service rewrite-rules dscp rw-dscp forwarding-class best-effort loss-priority low code-point be",
		// The three accepted-but-inert families.
		"class-of-service rewrite-rules ieee-802.1 rw-pcp forwarding-class premium loss-priority high code-point 5",
		"class-of-service rewrite-rules inet-precedence rw-prec forwarding-class premium loss-priority low code-point 5",
		"class-of-service rewrite-rules exp rw-exp forwarding-class premium loss-priority low code-point 5",
		// #6858 fold: BIND rw-dscp to a unit. Runtime DSCP rewriting happens
		// only for the rule an interface references, so without this line the
		// rule is configured-but-unbound and must not report as enforced. The
		// original fixture omitted the binding and still asserted
		// "Enforced: yes" -- it pinned the defect, not the contract.
		// #6858 round 3: the binding must land on a logical unit that EXISTS.
		// buildInterfaceSnapshots walks cfg.Interfaces.Interfaces and reads the
		// CoS unit off each real unit, so a class-of-service stanza naming an
		// interface with no `interfaces` counterpart is never read and the rule
		// is not enforced. Binding without this line asserted "Enforced: yes"
		// for a rewrite the dataplane could never apply.
		"interfaces ge-0-0-1 unit 0 family inet address 10.9.0.1/24",
		"class-of-service interfaces ge-0-0-1 unit 0 rewrite-rules dscp rw-dscp",
	} {
		if err := store.SetFromInput(cmd); err != nil {
			t.Fatalf("SetFromInput(%q) error = %v", cmd, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return &Server{store: store, dp: dataplane.New()}
}

func showRewriteRuleText(t *testing.T, s *Server, topic string) string {
	t.Helper()
	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: topic})
	if err != nil {
		t.Fatalf("ShowText(%q) error = %v", topic, err)
	}
	return resp.Output
}

// TestShowTextCoSRewriteRuleAllFamilies6848 proves the four families survive
// the real commit path and reach the renderer.
//
// FAIL-ON-REVERT: remove the "cos-rewrite-rule" dispatch arm in server_show.go
// and ShowText falls through to a different topic, so the rule-name assertions
// go RED.
func TestShowTextCoSRewriteRuleAllFamilies6848(t *testing.T) {
	out := showRewriteRuleText(t, newCoSRewriteRuleServer(t), "cos-rewrite-rule")
	for _, want := range []string{
		"Rewrite rule: rw-dscp, Code point type: dscp",
		"Rewrite rule: rw-pcp, Code point type: ieee-802.1",
		"Rewrite rule: rw-prec, Code point type: inet-precedence",
		"Rewrite rule: rw-exp, Code point type: exp",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in output:\n%s", want, out)
		}
	}
}

// TestShowTextCoSRewriteRuleMarksInert6848 is the operational point, asserted
// against config authored in real Junos syntax: an operator who configured four
// rewrite rules must be able to see that three of them do nothing.
func TestShowTextCoSRewriteRuleMarksInert6848(t *testing.T) {
	out := showRewriteRuleText(t, newCoSRewriteRuleServer(t), "cos-rewrite-rule")

	var dscpHeader string
	inertMarked := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		switch {
		case strings.HasPrefix(line, "Rewrite rule: rw-dscp,"):
			dscpHeader = line
		case strings.HasPrefix(line, "Rewrite rule: rw-pcp,"),
			strings.HasPrefix(line, "Rewrite rule: rw-prec,"),
			strings.HasPrefix(line, "Rewrite rule: rw-exp,"):
			name := strings.TrimSuffix(strings.Fields(line)[2], ",")
			inertMarked[name] = strings.Contains(line, "Enforced: no")
		}
	}
	if !strings.Contains(dscpHeader, "Enforced: yes") {
		t.Errorf("dscp rewrite rule must report as enforced; header: %q", dscpHeader)
	}
	for _, name := range []string{"rw-pcp", "rw-prec", "rw-exp"} {
		if !inertMarked[name] {
			t.Errorf("accepted-but-inert rule %q was not marked NOT enforced:\n%s", name, out)
		}
	}
}

// TestShowTextCoSRewriteRuleNameOnlyFamiliesAreProducible6848 is the fixture
// honesty check.
//
// The renderer treats inet-precedence and exp as NAME-ONLY families — it prints
// "Code points not modeled" instead of a code-point table. The compiler now
// validates their inner entries in Go-only definitions (#11811), but no wire or
// runtime consumer exists and show intentionally does not expose those values.
// This authors a rule WITH a code-point (5) in real set syntax and asserts the
// value does not appear under that rule, binding the external rendering contract.
func TestShowTextCoSRewriteRuleNameOnlyFamiliesAreProducible6848(t *testing.T) {
	s := newCoSRewriteRuleServer(t)
	for _, topic := range []string{
		"cos-rewrite-rule:type=inet-precedence",
		"cos-rewrite-rule:type=exp",
	} {
		out := showRewriteRuleText(t, s, topic)
		if !strings.Contains(out, "Code points not modeled") {
			t.Errorf("%s: expected the name-only explanation:\n%s", topic, out)
		}
		if strings.Contains(out, "Forwarding class") {
			t.Errorf("%s: rendered a code-point table for a family whose entries the "+
				"compiler discards — either the compiler now models them (render "+
				"them) or the table is fabricated:\n%s", topic, out)
		}
	}
}

// TestShowTextCoSRewriteRuleUnboundDSCPNotEnforced6858 drives the gate MAJOR
// through the REAL commit path: a dscp rewrite rule with no interface binding.
//
// This is the producible half of the unbound pin. The format-level test builds
// the config struct directly; here the rule is authored in real `set` syntax
// with no `interfaces ... rewrite-rules dscp` line, so the state is
// demonstrably reachable from an operator config rather than only from a
// hand-built fixture.
func TestShowTextCoSRewriteRuleUnboundDSCPNotEnforced6858(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	for _, cmd := range []string{
		"class-of-service forwarding-classes queue 0 best-effort",
		// Defined, never bound to any interface unit.
		"class-of-service rewrite-rules dscp unused forwarding-class best-effort loss-priority low code-point be",
	} {
		if err := store.SetFromInput(cmd); err != nil {
			t.Fatalf("SetFromInput(%q) error = %v", cmd, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	s := &Server{store: store, dp: dataplane.New()}

	out := showRewriteRuleText(t, s, "cos-rewrite-rule:name=unused")
	if !strings.Contains(out, "Rewrite rule: unused") {
		t.Fatalf("rule not rendered:\n%s", out)
	}
	if strings.Contains(out, "Enforced: yes") {
		t.Errorf("an unbound dscp rewrite rule reported as enforced. No interface "+
			"unit references it, so the dataplane builds no rewrite table for it "+
			"and it rewrites nothing:\n%s", out)
	}
	if !strings.Contains(out, "not bound") {
		t.Errorf("output must say the rule is not bound to any unit:\n%s", out)
	}
}

// TestShowTextCoSRewriteRuleFilters6848 covers the topic-param decoding on the
// remote path, including the no-match message.
func TestShowTextCoSRewriteRuleFilters6848(t *testing.T) {
	s := newCoSRewriteRuleServer(t)

	out := showRewriteRuleText(t, s, "cos-rewrite-rule:type=dscp")
	if !strings.Contains(out, "rw-dscp") || strings.Contains(out, "rw-pcp") {
		t.Errorf("type=dscp filter wrong:\n%s", out)
	}

	out = showRewriteRuleText(t, s, "cos-rewrite-rule:name=rw-pcp")
	if !strings.Contains(out, "rw-pcp") || strings.Contains(out, "rw-dscp") {
		t.Errorf("name=rw-pcp filter wrong:\n%s", out)
	}

	out = showRewriteRuleText(t, s, "cos-rewrite-rule:name=nope")
	if !strings.Contains(out, "No class-of-service rewrite-rule matches") {
		t.Errorf("expected no-match message:\n%s", out)
	}
}
