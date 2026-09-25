package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenWorldRoutingUnknownLeafWarnsAtStrictCommitOutput10707(t *testing.T) {
	for _, tc := range []struct {
		name       string
		args       []string
		completion string
	}{
		{name: "commit check", args: []string{"check"}, completion: "configuration check succeeds"},
		{name: "commit", completion: "commit complete"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
			if err := store.EnterConfigure(); err != nil {
				t.Fatalf("EnterConfigure() error = %v", err)
			}
			for _, line := range []string{
				"set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24",
				"set protocols ospf area 0.0.0.0 interface ge-0/0/0.0 cost 10",
				"set protocols ospf area 0.0.0.0 interface ge-0/0/0.0 cosst 11",
			} {
				if _, err := store.LoadSet(line); err != nil {
					t.Fatalf("LoadSet(%q) error = %v", line, err)
				}
			}

			var callErr error
			out := captureStdout(t, func() {
				callErr = (&CLI{store: store}).handleCommit(tc.args)
			})
			if callErr != nil {
				t.Fatalf("strict commit failed instead of warning: %v; output=%q", callErr, out)
			}
			if !strings.Contains(out, tc.completion) {
				t.Fatalf("strict commit did not complete; output=%q", out)
			}
			for _, want := range []string{"warning: protocols ospf", `"cosst"`, "#10707"} {
				if !strings.Contains(out, want) {
					t.Errorf("operator-visible warning output missing %q; output=%q", want, out)
				}
			}
		})
	}
}
