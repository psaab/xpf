package api

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6539: the REST show-text `flow-timeouts` topic must not render the three
// tcp-session timeouts that have NO dataplane wire carrier in the same shape as
// established-timeout, which does. Driven through the live showTextHandler on a
// real committed config, so the commit path and the render path are both
// exercised.
//
// The expected annotation is read from config.TCPSessionTimeoutNote rather than
// spelled here: this binds the REST surface to the same authority the CLI and
// gRPC surfaces render through, so a surface that invents its own wording reds
// even if the wording reads correctly.
func TestShowTextFlowTimeoutsAnnotateUnenforced_6539(t *testing.T) {
	s := stageShowTextConfig(t, []string{
		"set security flow tcp-session established-timeout 600",
		"set security flow tcp-session initial-timeout 45",
		"set security flow tcp-session closing-timeout 15",
		"set security flow tcp-session time-wait-timeout 90",
	})
	out := renderShowTextBody(t, s, "flow-timeouts")

	lineWith := func(sub string) string {
		for _, l := range strings.Split(out, "\n") {
			if strings.Contains(l, sub) {
				return l
			}
		}
		return ""
	}

	for _, tc := range []struct {
		label string
		leaf  string
		value string
	}{
		{"TCP initial timeout", config.TCPSessionInitialTimeoutLeaf, "45s"},
		{"TCP closing timeout", config.TCPSessionClosingTimeoutLeaf, "15s"},
		{"TCP time-wait timeout", config.TCPSessionTimeWaitTimeoutLeaf, "90s"},
	} {
		line := lineWith(tc.label + ":")
		if line == "" {
			t.Errorf("no %q row in flow-timeouts; the operator surface vanished.\n%s", tc.label, out)
			continue
		}
		if !strings.Contains(line, tc.value) {
			t.Errorf("%s row lost the configured value %s: %q", tc.label, tc.value, line)
		}
		// #7342: every tcp-session timeout is enforced now, so the shared
		// table hands back no annotation and the row must render the bare
		// value. Reading the note from the table rather than hard-coding "no
		// annotation" is what keeps this surface tied to the single authority:
		// if a future leaf becomes unenforced, this asserts the annotation
		// appears instead.
		note := config.TCPSessionTimeoutNote(tc.leaf)
		if note == "" {
			if strings.Contains(line, "not enforced") {
				t.Errorf("%s row still carries a not-enforced annotation for an ENFORCED leaf, "+
					"so REST reports a configured value as inert: %q", tc.label, line)
			}
			continue
		}
		if !strings.Contains(line, note) {
			t.Errorf("%s row does not carry the shared not-enforced annotation, so REST reports a "+
				"value in force.\n got: %q\nwant substring: %q", tc.label, line, note)
		}
	}

	est := lineWith("TCP established timeout:")
	if est == "" {
		t.Fatalf("no TCP established row in flow-timeouts.\n%s", out)
	}
	if !strings.Contains(est, "600s") {
		t.Errorf("TCP established row lost its value: %q", est)
	}
	if strings.Contains(est, "not enforced") {
		t.Errorf("established-timeout is wire-carried and must render unannotated: %q", est)
	}
}
