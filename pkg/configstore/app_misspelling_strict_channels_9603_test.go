package configstore

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9603: the coordinator decision keeps a MISSPELLED constraint beside a
// retained one (rows 1, 2 and 4 of the issue) as the documented residual, on
// the condition that no strict commit channel admits it. This pins that
// condition. If a later change lets one of these commit, the residual is no
// longer "text only a looser build could have committed", and #9603 reopens.
//
// Each row must be rejected, with the misspelled token named, by strict
// CompileConfig and by compileTreeStrict. compileTreeStrict is what both
// Store.compileTree (every commit and commit check) and CheckText run. For the
// hierarchical rows CheckText is also checked; it parses hierarchical text
// only. SchemaValidate is not asserted: applications are opaque to it by
// design, and compileTreeStrict composes it with the strict compile. Each
// application kind has a correctly spelled control that must pass every
// channel, so a rejection cannot come from the fixture.

const policy9603 = "security { zones { security-zone lan; security-zone wan; } policies { default-policy { deny-all; } " +
	"from-zone lan to-zone wan { policy p1 { match { source-address any; destination-address any; application a; } then { permit; } } } } }"

var policySets9603 = []string{
	"set security zones security-zone lan",
	"set security zones security-zone wan",
	"set security policies default-policy deny-all",
	"set security policies from-zone lan to-zone wan policy p1 match source-address any",
	"set security policies from-zone lan to-zone wan policy p1 match destination-address any",
	"set security policies from-zone lan to-zone wan policy p1 match application a",
	"set security policies from-zone lan to-zone wan policy p1 then permit",
}

type channelRow9603 struct {
	name, hier string
	sets       []string
	token      string // "" for a control that must commit
}

func checkChannels9603(t *testing.T, r channelRow9603) {
	t.Helper()
	var tree *config.ConfigTree
	text := ""
	if len(r.sets) == 0 {
		text = "applications { " + r.hier + " } " + policy9603
		tr, errs := config.NewParser(text).Parse()
		if len(errs) > 0 {
			t.Fatalf("parse: %v", errs)
		}
		tree = tr
	} else {
		tree = &config.ConfigTree{}
		for _, line := range append(append([]string(nil), r.sets...), policySets9603...) {
			p, err := config.ParseSetCommand(line)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", line, err)
			}
			if err := tree.SetPath(p); err != nil {
				t.Fatalf("SetPath(%q): %v", line, err)
			}
		}
	}
	judge := func(channel string, err error) {
		t.Helper()
		switch {
		case r.token == "" && err != nil:
			t.Errorf("%s: control refused: %v", channel, err)
		case r.token != "" && err == nil:
			t.Errorf("%s ADMITTED a misspelling beside a retained constraint; #9603's residual assumption is broken", channel)
		case r.token != "" && !strings.Contains(err.Error(), r.token):
			t.Errorf("%s rejected, but not for %q: %v", channel, r.token, err)
		}
	}
	_, err := config.CompileConfig(tree)
	judge("CompileConfig", err)
	_, err = compileTreeStrict(tree, -1)
	judge("compileTreeStrict", err)
	if text != "" {
		_, err = CheckText(text, -1)
		judge("CheckText", err)
	}
}

func TestMisspellingBesideARetainedConstraintNeverCommits9603(t *testing.T) {
	for _, r := range []channelRow9603{
		{"control tcp dport 80 sport 1024", `application a { protocol tcp; destination-port 80; source-port 1024; }`, nil, ""},
		{"row 1 hier source-poort", `application a { protocol tcp; destination-port 80; source-poort 1024; }`, nil, "source-poort"},
		{"row 1 term source-poort", `application a { term t1 { protocol tcp; destination-port 80; source-poort 1024; } }`, nil, "source-poort"},
		{"control flat tcp dport 80 sport 1024", "", []string{
			"set applications application a protocol tcp",
			"set applications application a destination-port 80",
			"set applications application a source-port 1024"}, ""},
		{"row 1 flat lines source-poort", "", []string{
			"set applications application a protocol tcp",
			"set applications application a destination-port 80",
			"set applications application a source-poort 1024"}, "source-poort"},
		{"row 1 flat chain source-poort", "", []string{"set applications application a protocol tcp destination-port 80 source-poort 1024"}, "source-poort"},
		{"control icmp type 8 code 0", `application a { protocol icmp; icmp-type 8; icmp-code 0; }`, nil, ""},
		{"row 2 hier icmp-cod", `application a { protocol icmp; icmp-type 8; icmp-cod 0; }`, nil, "icmp-cod"},
		{"row 2 term icmp-cod", `application a { term t1 { protocol icmp; icmp-type 8; icmp-cod 0; } }`, nil, "icmp-cod"},
		{"row 2 flat lines icmp-cod", "", []string{
			"set applications application a protocol icmp",
			"set applications application a icmp-type 8",
			"set applications application a icmp-cod 0"}, "icmp-cod"},
		{"control set application junos-ssh", `application-set a { application junos-ssh; }`, nil, ""},
		{"row 4 hier applicaton (sole member)", `application-set a { applicaton nosuchapp; }`, nil, "applicaton"},
		{"row 4 hier applicaton beside junos-ssh", `application-set a { application junos-ssh; applicaton nosuchapp; }`, nil, "applicaton"},
		{"row 4 flat applicaton beside junos-ssh", "", []string{
			"set applications application-set a application junos-ssh",
			"set applications application-set a applicaton nosuchapp"}, "applicaton"},
	} {
		t.Run(r.name, func(t *testing.T) { checkChannels9603(t, r) })
	}
}
