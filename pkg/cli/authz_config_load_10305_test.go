package cli

import (
	"io"
	"strings"
	"testing"
)

// #10305 through the local CLI: the gate and the store must agree on the
// trigger-led body's route. A gate that still calls the body flat only checks
// the annotate trigger and lets the hierarchical denied subtree reach
// LoadMerge; a gate that classifies it like the store refuses before mutation.
func TestCLILoadDivergentTriggerIsRefused10305(t *testing.T) {
	body := "annotate system host-name \"trigger10305\";\n" +
		"system { root-authentication { plain-text-password hunter2; } }\n"
	for _, mode := range []string{"merge", "override"} {
		t.Run(mode, func(t *testing.T) {
			c, st := cliWithRestrictedClass9892(t, "limited")
			before := st.ShowCandidate()
			path := writeConf9892(t, body)
			if err := c.handleLoad([]string{mode, path}); err == nil {
				t.Fatalf("load %s of a body carrying a denied hierarchical subtree was allowed (#10305)", mode)
			} else if strings.Contains(err.Error(), "hunter2") {
				t.Errorf("the refusal echoed the denied secret: %v", err)
			}
			if after := st.ShowCandidate(); after != before {
				t.Fatalf("load %s changed the candidate despite refusal:\nbefore:\n%s\nafter:\n%s", mode, before, after)
			}
		})
	}
}

// Narrowness/control: load set still accepts a flat, unrelated path after the
// shared predicate change. This catches a repair that simply refuses every
// nontrivial load body.
func TestCLILoadSetAllowedControl10305(t *testing.T) {
	c, st := cliWithRestrictedClass9892(t, "limited")
	r := &scriptedReader{
		lines:  []string{"set system host-name allowed10305"},
		endErr: io.EOF,
	}
	c.readLineFn = r.read
	if err := c.handleLoad([]string{"set", "terminal"}); err != nil {
		t.Fatalf("load set of an allowed flat path was refused: %v", err)
	}
	if got := st.ShowCandidate(); !strings.Contains(got, "allowed10305") {
		t.Fatalf("load set control did not mutate candidate:\n%s", got)
	}
}
