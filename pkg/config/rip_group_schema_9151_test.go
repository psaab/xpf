package config

import "testing"

// #9151: `protocols rip group` was declared `children: nil` while
// compiler_protocols.go's `case "group"` iterates child.Children and reads
// `neighbor` (-> RIP.Interfaces) and `export` (-> Redistribute).
//
// This cell pins the AGREEMENT between the two, which is what the declaration
// buys. IT DOES NOT CLOSE #9151, and saying so here is the point: a landed
// partial fix removes the reason anyone looks again, so the gap is asserted
// rather than left for someone to rediscover.
func TestRipGroupSchemaMatchesCompiler9151(t *testing.T) {
	rip := setSchema.children["protocols"].children["rip"]
	if rip == nil {
		t.Fatal("protocols rip missing from setSchema")
	}
	grp := rip.children["group"]
	if grp == nil {
		t.Fatal("protocols rip group missing from setSchema")
	}
	// The compiler reads exactly these two under a group. If it grows a third
	// `case`, this cell must grow with it or the schema falls behind again --
	// which is the #9151 defect returning by the same route.
	for _, want := range []string{"neighbor", "export"} {
		c := grp.children[want]
		if c == nil {
			t.Errorf("#9151: compiler_protocols.go's `case \"group\"` reads %q, and the "+
				"schema does not declare it. A schema that declares less than the "+
				"compiler reads leaves the closed-world walk nothing to descend into, "+
				"which is what made the packed spelling admissible.", want)
			continue
		}
		if !c.multi {
			t.Errorf("#9151: %q is read through firewallMatchValues (Keys[1:] AND child "+
				"nodes, #3904), so it must be declared multi or a bracket list is "+
				"truncated to its first entry", want)
		}
	}
	if grp.children == nil {
		t.Error("#9151: group declares no children at all -- the original defect")
	}
}

// TestRipGroupPackedRunStillAdmitted9151 records what the declaration does NOT
// fix, as a live assertion rather than a comment.
//
// `set protocols rip group g1 authentication-key secret1` still commits and
// loses both the group content and the sibling key. Declaring the children
// makes the schema HONEST about what the compiler reads; it does not refuse an
// UNDECLARED trailing statement, because `protocols rip` is open-world. By the
// #9148 conjunction a flat run is accepted iff the container is open-world AND
// the starting leaf is untyped, and this declaration changes neither.
//
// When someone closes #9151 -- by flipping the container closed-world, or by
// teaching the compiler to walk the run -- THIS CELL WILL FAIL, and that
// failure is the signal to delete it rather than a regression.
// TestRipGroupRefusesUndeclaredStatements9151 replaces
// TestRipGroupPackedRunStillAdmitted9151, which existed only to keep the open
// gap visible and carried an instruction to delete itself once the gate began
// refusing. It does now.
//
// Declaring the two children was NECESSARY AND NOT SUFFICIENT: the container
// stayed OPEN-WORLD, so an undeclared trailing statement was accepted and
// silently discarded --
//
//	set protocols rip group g1 authentication-key secret1
//	  gate=ACCEPT  compile=nil  ifaces=[] redist=[] authKey=""
//
// -- which is the #9148 conjunction (a flat run is accepted iff the container
// is open-world AND the leaf it starts at is untyped). Closing the container
// breaks it here.
//
// THE MATRIX IS THE POINT, not the single fixed row. `closedWorld` INHERITS, so
// arming it is only safe where the subtree is shallow; the ACCEPT rows below are
// what say it did not close more than intended. On #9017 the same flag armed one
// level up began rejecting `from source-prefix-list trusted`, valid shipped
// configuration, and only a full-package gate caught it.
func TestRipGroupRefusesUndeclaredStatements9151(t *testing.T) {
	const G = "set protocols rip group g1 "
	for _, tc := range []struct {
		name   string
		lines  []string
		accept bool
		ifaces []string
		redist []string
	}{
		// MUST STILL WORK. Over-denying here breaks RIP groups outright, and
		// every one of these is a spelling an operator legitimately writes.
		{"neighbor", []string{G + "neighbor ge-0/0/0"}, true, []string{"ge-0/0/0"}, nil},
		{"neighbor bracketed list", []string{G + "neighbor [ ge-0/0/0 ge-0/0/1 ]"}, true,
			[]string{"ge-0/0/0", "ge-0/0/1"}, nil},
		{"export", []string{G + "export static"}, true, nil, []string{"static"}},
		{"export bracketed list", []string{G + "export [ static direct ]"}, true, nil,
			[]string{"static", "direct"}},
		{"both on separate lines", []string{G + "neighbor ge-0/0/0", G + "export static"}, true,
			[]string{"ge-0/0/0"}, []string{"static"}},
		{"packed run of the two DECLARED children", []string{G + "neighbor ge-0/0/0 export static"},
			true, []string{"ge-0/0/0"}, []string{"static"}},

		// MUST NOW REFUSE — the reported defect.
		{"undeclared trailing statement", []string{G + "authentication-key secret1"}, false, nil, nil},
		{"typo'd child", []string{G + "neighbour ge-0/0/0"}, false, nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := &ConfigTree{}
			for _, l := range tc.lines {
				toks, err := ParseSetCommand(l)
				if err != nil {
					t.Fatalf("ParseSetCommand(%q): %v", l, err)
				}
				if err := tr.SetPath(toks); err != nil {
					t.Fatalf("SetPath: %v", err)
				}
			}
			err := SchemaValidateWithDefinitions(tr, tr)
			if (err == nil) != tc.accept {
				t.Fatalf("commit gate accepted=%v, want %v (err=%v)", err == nil, tc.accept, err)
			}
			if !tc.accept {
				return
			}
			cfg, cerr := CompileConfig(tr)
			if cerr != nil {
				t.Fatalf("compile: %v", cerr)
			}
			r := cfg.Protocols.RIP
			if r == nil {
				t.Fatal("no RIP config compiled")
			}
			if !equalStrs9151(r.Interfaces, tc.ifaces) {
				t.Errorf("Interfaces = %v, want %v", r.Interfaces, tc.ifaces)
			}
			if !equalStrs9151(r.Redistribute, tc.redist) {
				t.Errorf("Redistribute = %v, want %v", r.Redistribute, tc.redist)
			}
		})
	}
}

// TestRipGroupMultiLeafStillAbsorbs9151 PINS A RESIDUAL THAT THIS FIX DOES NOT
// CLOSE, so the gap stays visible rather than being implied away by the issue
// closing.
//
// `neighbor` is a multi leaf, so it absorbs every trailing token as a VALUE
// (the #2419 contract) BEFORE the closed-world walk could see any of them as
// keywords. The undeclared statement is therefore not refused here — it is
// injected as bogus interface names:
//
//	set protocols rip group g1 neighbor ge-0/0/0 authentication-key secret1
//	  -> ifaces=[ge-0/0/0 authentication-key secret1]
//
// MEASURED PRE-EXISTING, not introduced by the #9183 declaration: the same
// input produces the same interface list on a tree where `rip group` still had
// `children: nil`. Closing it needs a value validator strict enough to reject
// `authentication-key` as an interface name, which is a different change with
// its own risk of rejecting legitimate names.
//
// This cell asserts the CURRENT behaviour so a future fix reds it deliberately.
func TestRipGroupMultiLeafStillAbsorbs9151(t *testing.T) {
	tr := &ConfigTree{}
	toks, err := ParseSetCommand("set protocols rip group g1 neighbor ge-0/0/0 authentication-key secret1")
	if err != nil {
		t.Fatal(err)
	}
	if err := tr.SetPath(toks); err != nil {
		t.Fatal(err)
	}
	if err := SchemaValidateWithDefinitions(tr, tr); err != nil {
		t.Skipf("the multi-leaf absorption residual is now REFUSED (%v) — good news. "+
			"Delete this cell and the note on the issue it pins.", err)
	}
	cfg, cerr := CompileConfig(tr)
	if cerr != nil {
		t.Fatalf("compile: %v", cerr)
	}
	got := cfg.Protocols.RIP.Interfaces
	want := []string{"ge-0/0/0", "authentication-key", "secret1"}
	if !equalStrs9151(got, want) {
		t.Errorf("the pinned residual changed shape: Interfaces = %v, want %v. "+
			"If this is a FIX, delete this cell; if it is a new drift, adjudicate it.", got, want)
	}
}

func equalStrs9151(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
