package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

// #6848/#6858: the LOCAL `show class-of-service classifier|rewrite-rule` filter
// surface.
//
// The GRAMMAR itself is tested once, in pkg/cmdtree
// (TestParseCoSNameTypeArgs6848), because pkg/cli, cmd/cli and pkg/grpcapi all
// call cmdtree.ParseCoSNameTypeArgs. This file asserts the WIRING instead: that
// the local dispatcher really routes through the shared parser, on inputs a
// re-introduced local parser would get wrong. A mirrored copy of the grammar
// table here would test cmdtree twice and this dispatcher not at all — which is
// how the old pair drifted (pkg/cli covered `keyword overrides bare`, cmd/cli
// did not) without either test noticing.

func newCoSRewriteRuleCLI(t *testing.T) *CLI {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	for _, cmd := range []string{
		"class-of-service forwarding-classes queue 0 best-effort",
		"class-of-service rewrite-rules dscp rw-dscp forwarding-class best-effort loss-priority low code-point be",
		"class-of-service rewrite-rules dscp rw-other forwarding-class best-effort loss-priority low code-point ef",
		// A name containing the byte the remote topic encoding uses as its own
		// param separator. This commits — verified against the real store — so
		// it is an operator-reachable name, not a synthetic one.
		`class-of-service rewrite-rules dscp "rw,x" forwarding-class best-effort loss-priority low code-point af11`,
	} {
		if err := store.SetFromInput(cmd); err != nil {
			t.Fatalf("SetFromInput(%q) error = %v", cmd, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return &CLI{store: store}
}

// TestLocalCoSRewriteRuleFilterWiring6858 drives the real local dispatcher.
//
// FAIL-ON-REVERT: reintroduce a keyword-only parser in handleShowClassOfService
// and the bare-name cases dump every rule, so the "other rule absent"
// assertions go RED.
func TestLocalCoSRewriteRuleFilterWiring6858(t *testing.T) {
	c := newCoSRewriteRuleCLI(t)
	for _, tc := range []struct {
		desc    string
		args    []string
		want    string
		notWant []string
	}{
		// Bare positional — what an operator submits after tab-completing a
		// name under the command.
		{"bare name", []string{"rewrite-rule", "rw-dscp"}, "Rewrite rule: rw-dscp,", []string{"rw-other"}},
		{"keyword name", []string{"rewrite-rule", "name", "rw-other"}, "Rewrite rule: rw-other,", []string{"rw-dscp"}},
		// A later explicit keyword beats the bare positional.
		{"keyword overrides bare", []string{"rewrite-rule", "rw-dscp", "name", "rw-other"},
			"Rewrite rule: rw-other,", []string{"Rewrite rule: rw-dscp,"}},
		// The comma-bearing name, which is the case the remote surface got
		// wrong before #6858. Locally it always worked; it is asserted here so
		// the two surfaces are compared on the SAME input
		// (TestCoSRewriteRuleLocalRemoteParity6858 in pkg/grpcapi).
		{"comma in name", []string{"rewrite-rule", "rw,x"}, "Rewrite rule: rw,x,", []string{"rw-other"}},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			out := captureStdout(t, func() {
				if err := c.handleShowClassOfService(tc.args); err != nil {
					t.Fatalf("handleShowClassOfService(%q) error = %v", tc.args, err)
				}
			})
			if !strings.Contains(out, tc.want) {
				t.Errorf("missing %q in output:\n%s", tc.want, out)
			}
			for _, no := range tc.notWant {
				if strings.Contains(out, no) {
					t.Errorf("filter leaked %q into output:\n%s", no, out)
				}
			}
		})
	}
}

func TestLocalCoSFiltersRejectUnknownAndDangling11834(t *testing.T) {
	c := newCoSRewriteRuleCLI(t)
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"rewrite-rule unknown", []string{"rewrite-rule", "name", "rw-dscp", "naem"}, `unknown argument "naem"`},
		{"rewrite-rule dangling", []string{"rewrite-rule", "name"}, `missing value for "name"`},
		{"classifier unknown", []string{"classifier", "name", "wan-classifier", "naem"}, `unknown argument "naem"`},
		{"classifier dangling", []string{"classifier", "name"}, `missing value for "name"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := captureStdout(t, func() {
				err := c.handleShowClassOfService(tc.args)
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("handleShowClassOfService(%q) error = %v, want containing %q",
						tc.args, err, tc.want)
				}
			})
			if out != "" {
				t.Fatalf("invalid filter emitted unfiltered output:\n%s", out)
			}
		})
	}
}
