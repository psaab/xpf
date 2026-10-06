package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func parseRoutingPolicy11779(t *testing.T, src string) *config.ConfigTree {
	t.Helper()
	tree, errs := config.NewParser(src).Parse()
	if len(errs) != 0 {
		t.Fatalf("parse routing policy: %v", errs)
	}
	return tree
}

func replayRoutingPolicySet11779(t *testing.T, text string) *config.ConfigTree {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, line := range strings.Split(strings.TrimSpace(text), "\n") {
		path, quoted, grouped, err := config.ParseSetCommandGrouped(line)
		if err != nil {
			t.Fatalf("ParseSetCommandGrouped(%q): %v", line, err)
		}
		if err := tree.SetPathQuotedGrouped(path, quoted, grouped); err != nil {
			t.Fatalf("SetPathQuotedGrouped(%q): %v", line, err)
		}
	}
	return tree
}

func TestGeneratePolicyOptionsFinalQuotedThenSurvivesReplay11779(t *testing.T) {
	tree := parseRoutingPolicy11779(t, `policy-options {
 prefix-list then 10.0.0.0/8;
 prefix-list PL2 172.16.0.0/12;
 policy-statement P {
  term T {
   from prefix-list [ PL2 "then" ];
   then reject;
  }
 }
}`)
	for _, replay := range []struct {
		name string
		text string
	}{
		{"Format", tree.Format()},
		{"FormatSet", tree.FormatSet()},
	} {
		t.Run(replay.name, func(t *testing.T) {
			var replayed *config.ConfigTree
			if replay.name == "FormatSet" {
				replayed = replayRoutingPolicySet11779(t, replay.text)
			} else {
				replayed = parseRoutingPolicy11779(t, replay.text)
			}
			cfg, err := config.CompileConfig(replayed)
			if err != nil {
				t.Fatalf("compile replay: %v", err)
			}
			term := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
			if len(term.PrefixList) != 2 || term.PrefixList[0] != "PL2" ||
				term.PrefixList[1] != "then" || len(term.UnknownFrom) != 0 ||
				term.Action != "reject" {
				t.Fatalf("replay changed the final list member: %+v", term)
			}
			got := (&Manager{frrConf: "/dev/null"}).generatePolicyOptions(
				&cfg.PolicyOptions, map[string]bool{"P": true})
			if !strings.Contains(got, "route-map P deny 20\n match ip address prefix-list then\n") {
				t.Fatalf("replayed `then` has no FRR deny sequence:\n%s", got)
			}
			if !strings.Contains(got, "route-map P permit 30\n") {
				t.Fatalf("BGP default permit sequence missing after both list members:\n%s", got)
			}
		})
	}
}

func TestGeneratePolicyOptionsFromThenDoesNotRenderPermit11779(t *testing.T) {
	tree := parseRoutingPolicy11779(t, `policy-options {
 policy-statement P { term T { from { then accept; } } }
}`)
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	term := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
	if len(term.UnknownFrom) != 1 || term.UnknownFrom[0] != "then" || term.Action != "reject" {
		t.Fatalf("unsupported from-then was not quarantined: %+v", term)
	}
	got := (&Manager{frrConf: "/dev/null"}).generatePolicyOptions(&cfg.PolicyOptions)
	if strings.Contains(got, "route-map P permit 10\n") {
		t.Fatalf("unsupported from-then rendered a match-less permit:\n%s", got)
	}
	if !strings.Contains(got, "route-map P deny 10\n") {
		t.Fatalf("quarantined from-then did not render fail-closed deny:\n%s", got)
	}
}

func TestGeneratePolicyOptionsNestedProtocolDirectNeighborFailsClosed11779(t *testing.T) {
	tree := parseRoutingPolicy11779(t, `policy-options {
 policy-statement P {
  term T { from { protocol direct { neighbor 192.0.2.1; } } then accept; }
 }
}`)
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile hard-error: %v", err)
	}
	term := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
	if len(term.UnknownFrom) != 1 || term.UnknownFrom[0] != "neighbor" || term.Action != "reject" {
		t.Fatalf("nested protocol neighbor did not force reject: %+v", term)
	}
	got := (&Manager{frrConf: "/dev/null"}).generatePolicyOptions(&cfg.PolicyOptions)
	if strings.Contains(got, "match source-protocol neighbor") {
		t.Fatalf("unsupported nested neighbor rendered as a source protocol:\n%s", got)
	}
	if !strings.Contains(got, "route-map P deny 10\n") {
		t.Fatalf("nested protocol neighbor did not render fail-closed:\n%s", got)
	}
}
