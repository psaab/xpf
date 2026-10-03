package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cmdtree"
	"github.com/psaab/xpf/pkg/dataplane"
	dpformat "github.com/psaab/xpf/pkg/dataplane/userspace/format"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #6858: local and remote must render the SAME rule for the same keystrokes.
//
// Both surfaces derive their filters from cmdtree.ParseCoSNameTypeArgs. The
// remote path then carries them through a ShowText topic and back, so the whole
// parity question is whether that carriage is lossless. The topic joined params
// with `,` and split on `,`, and a rewrite-rule / classifier NAME containing a
// comma commits — so `show class-of-service rewrite-rule "rw,x"` rendered a
// different rule remotely than locally, or reported that no rule matched.
//
// The topics here are BUILT by calling the encoder rather than typed as
// literals, so a change to the encoding flows into the decoder side of this
// test instead of silently making it assert a form nothing produces.

func newCoSCommaNameServer(t *testing.T) *Server {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	for _, cmd := range []string{
		"class-of-service forwarding-classes queue 0 best-effort",
		// Comma-bearing names for BOTH commands that share the encoding.
		`class-of-service rewrite-rules dscp "rw,x" forwarding-class best-effort loss-priority low code-point ef`,
		`class-of-service classifiers dscp "cl,x" forwarding-class best-effort loss-priority low code-points 0`,
		// The prefix the comma truncates to. Its presence is what makes the bug
		// render a DIFFERENT rule rather than an empty result: without it the
		// operator merely sees "no match", which is wrong but not misleading.
		"class-of-service rewrite-rules dscp rw forwarding-class best-effort loss-priority low code-point be",
		"class-of-service classifiers dscp cl forwarding-class best-effort loss-priority low code-points 8",
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

// TestCoSRewriteRuleLocalRemoteParity6858 compares, for one set of operator
// tokens, what the local dispatcher renders against what ShowText returns.
//
// FAIL-ON-REVERT: drop the escaping in cmdtree.CoSNameTypeTopic (emit the raw
// value) and the comma cases diverge — remote renders the rule named "rw" while
// local renders "rw,x" — so the equality assertion goes RED for both commands.
func TestCoSRewriteRuleLocalRemoteParity6858(t *testing.T) {
	s := newCoSCommaNameServer(t)
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		t.Fatal("no active config")
	}

	for _, tc := range []struct {
		desc   string
		prefix string
		args   []string
		// local renders straight from the filters, exactly as
		// pkg/cli.handleShowClassOfService does.
		local func(name, typ string) string
		// A substring the CORRECT answer contains, so an equality that holds
		// because both sides are equally broken still fails.
		wantContains string
	}{
		{
			desc: "rewrite-rule comma name", prefix: "cos-rewrite-rule", args: []string{"rw,x"},
			local: func(n, ty string) string { return dpformat.FormatCoSRewriteRules(cfg, n, ty) },
			// The trailing comma is the renderer's own field separator, so this
			// pins the FULL name rather than a prefix of it.
			wantContains: "Rewrite rule: rw,x, Code point type: dscp",
		},
		{
			desc: "rewrite-rule comma name with type", prefix: "cos-rewrite-rule",
			args:  []string{"name", "rw,x", "type", "dscp"},
			local: func(n, ty string) string { return dpformat.FormatCoSRewriteRules(cfg, n, ty) },
			// wantContains is unchanged: filtering to the family the rule is in
			// must not change which rule is shown.
			wantContains: "Rewrite rule: rw,x, Code point type: dscp",
		},
		{
			desc: "classifier comma name", prefix: "cos-classifier", args: []string{"cl,x"},
			local:        func(n, ty string) string { return dpformat.FormatCoSClassifiers(cfg, n, ty) },
			wantContains: "Classifier: cl,x, Code point type: dscp",
		},
		{
			desc: "rewrite-rule plain name", prefix: "cos-rewrite-rule", args: []string{"rw"},
			local:        func(n, ty string) string { return dpformat.FormatCoSRewriteRules(cfg, n, ty) },
			wantContains: "Rewrite rule: rw, Code point type: dscp",
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			name, typ, err := cmdtree.ParseCoSNameTypeArgs(tc.args)
			if err != nil {
				t.Fatalf("ParseCoSNameTypeArgs(%q) error = %v", tc.args, err)
			}
			localOut := tc.local(name, typ)

			topic := cmdtree.CoSNameTypeTopic(tc.prefix, name, typ)
			resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: topic})
			if err != nil {
				t.Fatalf("ShowText(%q) error = %v", topic, err)
			}
			remoteOut := resp.Output

			if !strings.Contains(localOut, tc.wantContains) {
				t.Fatalf("the LOCAL render is already wrong for %q — expected %q:\n%s",
					tc.args, tc.wantContains, localOut)
			}
			if localOut != remoteOut {
				t.Errorf("local and remote disagree for %q (topic %q).\nlocal:\n%s\nremote:\n%s",
					tc.args, topic, localOut, remoteOut)
			}
		})
	}
}

// TestCoSCommaNameRemoteIsNotThePrefixRule6858 states the failure in the terms
// the operator experiences it, independently of the parity equality above: the
// remote surface must not answer a query for "rw,x" with the rule named "rw".
//
// An equality assertion alone would pass if both surfaces regressed together;
// this one fails if the remote surface renders the wrong rule for any reason.
func TestCoSCommaNameRemoteIsNotThePrefixRule6858(t *testing.T) {
	s := newCoSCommaNameServer(t)
	topic := cmdtree.CoSNameTypeTopic("cos-rewrite-rule", "rw,x", "")
	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: topic})
	if err != nil {
		t.Fatalf("ShowText(%q) error = %v", topic, err)
	}
	out := resp.Output
	if !strings.Contains(out, "Rewrite rule: rw,x,") {
		t.Errorf("remote did not render the requested rule (topic %q):\n%s", topic, out)
	}
	if strings.Contains(out, "Rewrite rule: rw,\n") || strings.Contains(out, "Rewrite rule: rw, Code") {
		t.Errorf("remote rendered the comma-truncated prefix rule instead (topic %q):\n%s", topic, out)
	}
	if strings.Contains(out, "No class-of-service rewrite-rule matches") {
		t.Errorf("remote reported the operator's committed rule does not exist (topic %q):\n%s", topic, out)
	}
}
