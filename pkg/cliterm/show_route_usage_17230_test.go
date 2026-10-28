package cliterm

import (
	"os"
	"strings"
	"testing"
)

// #17230: ShowRouteUsage is single-sourced here. Prior to the fix each
// dispatcher carried its own literal, justified in cmd/cli by a false
// "import cycle" comment (nothing imports package main, and cmd/cli
// already imports this package), and both CLI READMEs claimed
// cmd/cli runs on the pkg/cli engine it has never imported. These
// cells pin the single definition and the corrected docs. RED on
// base: ShowRouteUsage undefined here; the literal appeared in both
// cmd/cli/show.go and pkg/cli/cli_show_routing.go; both READMEs
// stated the false sharing model.

func TestShowRouteUsageGrammar17230(t *testing.T) {
	// Positive/control: the shared grammar keeps the exact #15723
	// spellings both dispatchers rejected against before the move.
	want := "usage: show route [<destination> [exact|longer|orlonger]] | show route [terse|detail|summary|fib] | show route table <name> | show route instance <name> | show route protocol <name>"
	if ShowRouteUsage != want {
		t.Fatalf("ShowRouteUsage = %q, want %q", ShowRouteUsage, want)
	}
}

func TestShowRouteUsageSingleDefinition17230(t *testing.T) {
	for _, f := range []string{"../cli/cli_show_routing.go", "../../cmd/cli/show.go"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		if strings.Contains(string(b), "usage: show route [<destination>") {
			t.Errorf("%s still defines its own show-route usage literal", f)
		}
		if !strings.Contains(string(b), "ShowRouteUsage") {
			t.Errorf("%s does not reference the shared ShowRouteUsage", f)
		}
	}
	b, err := os.ReadFile("../../cmd/cli/show.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "import cycle"+" through the CLI package") {
		t.Error("cmd/cli/show.go still claims an impossible import cycle")
	}
}

func TestCLIReadmesDescribeTwins17230(t *testing.T) {
	for _, tc := range []struct {
		file     string
		banned   []string
		mustHave string
	}{
		{"../../cmd/cli/README.md", []string{"shared `pkg/cli` engine"}, "does NOT import `pkg/cli`"},
		{"../cli/README.md", []string{"and the remote CLI\n(`cmd/cli`)", "`cmd/cli` (remote client), `cmd/xpfd`"}, "never imports this package"},
	} {
		b, err := os.ReadFile(tc.file)
		if err != nil {
			t.Fatalf("read %s: %v", tc.file, err)
		}
		s := string(b)
		for _, banned := range tc.banned {
			if strings.Contains(s, banned) {
				t.Errorf("%s still states the false sharing model: %q", tc.file, banned)
			}
		}
		if !strings.Contains(s, tc.mustHave) {
			t.Errorf("%s must state the twins model (%q)", tc.file, tc.mustHave)
		}
	}
}
