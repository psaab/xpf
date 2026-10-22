package config

import (
	"fmt"
	"testing"
)

// issue 8939: a firewall filter term's `then` clause loses every action after
// the first, in TWO spellings and by TWO different mechanisms.
//
//	braced-hier   then { count c1; dscp af11; }    count=c1  dscp=af11   worked
//	packed-hier   then count c1 dscp af11;         count=c1  dscp=""     LOST
//	packed CLI    set … then count c1 dscp af11    count=c1  dscp=""     LOST
//
// THE DROPPED VALUE PRODUCES A WRONG MARKING, NOT AN ABSENT ONE, and that is
// what sets the severity. pkg/dataplane/compiler_filter.go branches on the
// dropped field and the branch below it is a FALLBACK:
//
//	if term.DSCPRewrite != ""   { base.DSCPRewrite = <explicit> }
//	if term.ForwardingClass != "" && base.DSCPRewrite == 0xFF {
//	                              base.DSCPRewrite = <derived from fc> }
//
// so dropping `then dscp` hands the decision to the forwarding-class
// derivation and the packet goes out remarked with a DSCP the operator never
// configured. A missing value is eventually noticeable because something is
// unconfigured; a WRONG one is not, because nothing is.
//
// IT IS ORDER-DEPENDENT. The run keeps the FIRST action, so which one survives
// depends on the order typed. `then dscp af11 forwarding-class ef` keeps the
// explicit DSCP; `then forwarding-class ef dscp af11` keeps the forwarding
// class and derives a different DSCP from it. Same statements, two orders, two
// behaviours, both accepted silently.
//
// ALL THREE SPELLINGS ARE ASSERTED IN ONE TABLE, DELIBERATELY. The two
// mechanisms have separate fixes -- `packedStatements` for the packed tail, a
// chain flatten for the SetPath nesting -- and either alone leaves the config
// broken. A cell per mechanism could go green on half the defect, and a landed
// partial fix removes the reason anyone looks again. This one passes only when
// both hold.
func TestFirewallThenAgreesAcrossSpellings8939(t *testing.T) {
	type want struct{ count, dscp, fc string }

	compileSet := func(t *testing.T, cmd string) *Config {
		t.Helper()
		tree := &ConfigTree{}
		p, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
		cfg, err := CompileConfigLenient(tree)
		if err != nil || cfg == nil {
			t.Fatalf("compile: %v", err)
		}
		return cfg
	}
	got := func(t *testing.T, c *Config) want {
		t.Helper()
		for _, f := range c.Firewall.FiltersInet {
			for _, tm := range f.Terms {
				return want{tm.Count, tm.DSCPRewrite, tm.ForwardingClass}
			}
		}
		t.Fatal("no filter term compiled")
		return want{}
	}

	for _, tc := range []struct {
		name     string
		braced   string
		packed   string
		set      string
		expected want
	}{
		{
			name:     "count+dscp",
			braced:   `firewall { family inet { filter f1 { term t1 { then { count c1; dscp af11; } } } } }`,
			packed:   `firewall { family inet { filter f1 { term t1 { then count c1 dscp af11; } } } }`,
			set:      "set firewall family inet filter f1 term t1 then count c1 dscp af11",
			expected: want{"c1", "af11", ""},
		},
		{
			// THE ORDER THAT FLIPS THE DATAPLANE BRANCH. With `dscp` second it
			// is the one dropped, and the forwarding-class fallback then chooses
			// the marking instead of the operator.
			name:     "forwarding-class+dscp (fc first)",
			braced:   `firewall { family inet { filter f1 { term t1 { then { forwarding-class ef; dscp af11; } } } } }`,
			packed:   `firewall { family inet { filter f1 { term t1 { then forwarding-class ef dscp af11; } } } }`,
			set:      "set firewall family inet filter f1 term t1 then forwarding-class ef dscp af11",
			expected: want{"", "af11", "ef"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := got(t, compileText(t, tc.braced))
			// POSITIVE CONTROL: the braced arm is the reference. If it stops
			// delivering, every comparison below would pass against a term that
			// carries nothing.
			if b != tc.expected {
				t.Fatalf("the BRACED arm delivered %+v, want %+v -- the reference "+
					"arm is wrong, so this cell cannot tell a fixed spelling from "+
					"a broken fixture (#8939)", b, tc.expected)
			}
			for _, arm := range []struct {
				name, mechanism string
				got             want
			}{
				{"packed-hier", "packed tail on one node's Keys, split by packedStatements",
					got(t, compileText(t, tc.packed))},
				{"packed CLI", "SetPath nests the actions; the reader flattens the chain",
					got(t, compileSet(t, tc.set))},
			} {
				if arm.got != b {
					t.Errorf("%s spelling delivers %+v, braced delivers %+v.\n"+
						"  mechanism: %s\n"+
						"  A dropped `then dscp` does not disable the rewrite -- the "+
						"forwarding-class fallback in dataplane/compiler_filter.go "+
						"fires instead, so the packet is remarked with a DSCP the "+
						"operator never configured (#8939).",
						arm.name, arm.got, b, arm.mechanism)
				}
			}
		})
	}
}

// `then reject <message-type>` legitimately carries a body -- `reject` declares
// fourteen message-type children -- so the chain flatten must NOT hoist it.
// Without the schema gate the message type becomes a sibling action.
func TestFirewallThenRejectBodyIsNotHoisted8939(t *testing.T) {
	tree := &ConfigTree{}
	p, err := ParseSetCommand("set firewall family inet filter f1 term t1 then reject administratively-prohibited")
	if err != nil {
		t.Fatalf("ParseSetCommand: %v", err)
	}
	if err := tree.SetPath(p); err != nil {
		t.Fatalf("SetPath: %v", err)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil || cfg == nil {
		t.Fatalf("compile: %v", err)
	}
	for _, f := range cfg.Firewall.FiltersInet {
		for _, tm := range f.Terms {
			if tm.Action != FilterActionReject || tm.RejectMessageType != "administratively-prohibited" {
				t.Errorf("action=%q messageType=%q, want reject/administratively-prohibited "+
					"-- the chain flatten hoisted a body the schema says `reject` owns (#8939)",
					tm.Action, tm.RejectMessageType)
			}
			return
		}
	}
	t.Fatal("no filter term compiled")
	_ = fmt.Sprint()
}
