package config

import "testing"

// #14418 (DR15-H3): a group term CONTAINER adopted beside an inline PACKED
// term leaf. sameKeyedContainers9802 matches containers only, so the inline
// packed leaf `term t1 from ... then reject;` is invisible; the #4325 C-guard
// needs len(Keys)==1 and `term t1` has two keys, so the group container was
// appended beside it (two `term t1` nodes). Routing then composed same-name
// terms last-wins (group accept overwrote inline reject); firewall appended
// both terms first-match (Y-only traffic accepted by the spurious twin).
//
// Fix: in mergeNodes' container !found arm, promote the inline packed leaf
// peer (same full instance identity) and merge the group container's children
// into it with inline precedence, mirroring #9855.

func compile14418(t *testing.T, src string) *Config {
	t.Helper()
	tree, perrs := NewParser(src).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

const routingCrossShape14418 = `
groups {
  g1 {
    policy-options {
      policy-statement P {
        term t1 {
          then accept;
        }
      }
    }
  }
}
policy-options {
  policy-statement P {
    term t1 from route-filter 10.0.0.0/8 orlonger then reject;
    term t2 {
      then accept;
    }
  }
}
apply-groups g1;
`

func TestDR15H3RoutingCrossShapeInlineRejectWins14418(t *testing.T) {
	cfg := compile14418(t, routingCrossShape14418)
	ps := cfg.PolicyOptions.PolicyStatements["P"]
	if ps == nil {
		t.Fatalf("policy-statement P missing")
	}
	var t1s []*PolicyTerm
	for _, tm := range ps.Terms {
		if tm.Name == "t1" {
			t1s = append(t1s, tm)
		}
	}
	if len(t1s) != 1 {
		t.Fatalf("compiled %d t1 terms, want exactly 1: %+v", len(t1s), ps.Terms)
	}
	if t1s[0].Action != "reject" {
		t.Errorf("t1 Action = %q, want inline reject to win over group accept", t1s[0].Action)
	}
	if len(t1s[0].RouteFilters) == 0 {
		t.Errorf("t1 RouteFilters empty, want inline route-filter preserved (union of conditions)")
	}
}

const firewallCrossShape14418 = `
groups {
  g1 {
    firewall {
      family inet {
        filter F {
          term t1 {
            from {
              destination-address 203.0.113.0/24;
            }
            then accept;
          }
        }
      }
    }
  }
}
firewall {
  family inet {
    filter F {
      term t1 from source-address 192.0.2.0/24 then discard;
      term t2 {
        then discard;
      }
    }
  }
}
apply-groups g1;
`

func firewallFilter14418(t *testing.T, cfg *Config) *FirewallFilter {
	t.Helper()
	f := cfg.Firewall.FiltersInet["F"]
	if f == nil {
		t.Fatalf("filter F missing: %+v", cfg.Firewall.FiltersInet)
	}
	return f
}

func TestDR15H3FirewallCrossShapeOneTermDiscard14418(t *testing.T) {
	cfg := compile14418(t, firewallCrossShape14418)
	f := firewallFilter14418(t, cfg)
	var t1s []*FirewallFilterTerm
	var names []string
	for _, tm := range f.Terms {
		names = append(names, tm.Name)
		if tm.Name == "t1" {
			t1s = append(t1s, tm)
		}
	}
	if len(t1s) != 1 {
		t.Fatalf("compiled %d t1 terms %v, want exactly 1 (Y-only must reach t2)", len(t1s), names)
	}
	tm := t1s[0]
	if tm.Action != "discard" {
		t.Errorf("t1 Action = %q, want inline discard", tm.Action)
	}
	// X AND Y: both conditions must be present on the single term.
	foundSrc, foundDst := false, false
	for _, a := range tm.SourceAddresses {
		if a == "192.0.2.0/24" {
			foundSrc = true
		}
	}
	for _, a := range tm.DestAddresses {
		if a == "203.0.113.0/24" {
			foundDst = true
		}
	}
	if !foundSrc || !foundDst {
		t.Errorf("t1 must match X AND Y: src=%v dst=%v", tm.SourceAddresses, tm.DestAddresses)
	}
	// t2 still present after t1.
	if len(f.Terms) != 2 || f.Terms[1].Name != "t2" {
		t.Errorf("terms = %v, want [t1 t2]", names)
	}
}

// Controls: both-packed and both-braced spellings must agree with cross-shape.

func TestDR15H3ControlsAgree14418(t *testing.T) {
	// Both-packed routing control: leaf-branch already merges into ONE t1
	// (measured on master: group protocol bgp unions, group accept survives
	// on that path). Pin only the merged-single-term invariant so this control
	// does not encode a precedence the leaf path never had; the cross-shape
	// fix must not disturb it.
	bothPackedRouting := `
groups { g1 { policy-options { policy-statement P { term t1 from protocol bgp then accept; } } } }
policy-options { policy-statement P { term t1 from route-filter 10.0.0.0/8 orlonger then reject; term t2 { then accept; } } }
apply-groups g1;
`
	cfg := compile14418(t, bothPackedRouting)
	ps := cfg.PolicyOptions.PolicyStatements["P"]
	var t1 *PolicyTerm
	n := 0
	for _, tm := range ps.Terms {
		if tm.Name == "t1" {
			t1, n = tm, n+1
		}
	}
	if n != 1 || t1 == nil {
		t.Fatalf("both-packed routing: n=%d, want 1 merged t1", n)
	}
	if len(t1.FromProtocols) == 0 || len(t1.RouteFilters) == 0 {
		t.Errorf("both-packed routing: merged t1 lost a match side: proto=%v rf=%v", t1.FromProtocols, t1.RouteFilters)
	}

	// Both-braced routing.
	bothBracedRouting := `
groups { g1 { policy-options { policy-statement P { term t1 { then accept; } } } } }
policy-options { policy-statement P { term t1 { from { route-filter 10.0.0.0/8 orlonger; } then reject; } term t2 { then accept; } } }
apply-groups g1;
`
	cfg = compile14418(t, bothBracedRouting)
	ps = cfg.PolicyOptions.PolicyStatements["P"]
	t1, n = nil, 0
	for _, tm := range ps.Terms {
		if tm.Name == "t1" {
			t1, n = tm, n+1
		}
	}
	if n != 1 || t1 == nil || t1.Action != "reject" {
		t.Errorf("both-braced routing: n=%d t1=%v, want 1/reject", n, t1)
	}

	// Both-packed firewall: the leaf-merge produces ONE term whose `then`
	// carries both discard and accept, so strict commit rejects it via
	// FilterHasConflictingTerminalActions (measured on master). That gate
	// outcome is the control: the cross-shape fix must instead yield ONE
	// clean discard term (inline wins), which is stricter-correct.
	bothPackedFW := `
groups { g1 { firewall { family inet { filter F { term t1 from destination-address 203.0.113.0/24 then accept; } } } } }
firewall { family inet { filter F { term t1 from source-address 192.0.2.0/24 then discard; term t2 { then discard; } } } }
apply-groups g1;
`
	func() {
		tree, perrs := NewParser(bothPackedFW).Parse()
		if len(perrs) > 0 {
			t.Fatalf("parse: %v", perrs)
		}
		if _, err := CompileConfig(tree); err == nil {
			t.Errorf("both-packed firewall control: expected conflicting-terminal rejection on the pre-existing leaf path")
		}
	}()

	// Both-braced firewall: container-container merge already yields ONE t1
	// but strict commit may see both actions; assert at the AST level via a
	// non-conflicting braced pair instead (group supplies only a condition).
	bothBracedFW := `
groups { g1 { firewall { family inet { filter F { term t1 { from { destination-address 203.0.113.0/24; } } } } } } }
firewall { family inet { filter F { term t1 { from { source-address 192.0.2.0/24; } then discard; } term t2 { then discard; } } } }
apply-groups g1;
`
	cfg = compile14418(t, bothBracedFW)
	f := firewallFilter14418(t, cfg)
	cnt := 0
	var ftm *FirewallFilterTerm
	for _, tm := range f.Terms {
		if tm.Name == "t1" {
			cnt, ftm = cnt+1, tm
		}
	}
	if cnt != 1 || ftm == nil || ftm.Action != "discard" {
		t.Errorf("both-braced firewall: cnt=%d ftm=%v, want 1/discard", cnt, ftm)
	}
	if ftm != nil && (len(ftm.SourceAddresses) == 0 || len(ftm.DestAddresses) == 0) {
		t.Errorf("both-braced firewall t1 must match X AND Y: src=%v dst=%v", ftm.SourceAddresses, ftm.DestAddresses)
	}

	// Different-name terms: both survive.
	diffName := `
groups { g1 { firewall { family inet { filter F { term t9 { from { destination-address 203.0.113.0/24; } then accept; } } } } } }
firewall { family inet { filter F { term t1 from source-address 192.0.2.0/24 then discard; term t2 { then discard; } } } }
apply-groups g1;
`
	cfg = compile14418(t, diffName)
	f = firewallFilter14418(t, cfg)
	if len(f.Terms) != 3 {
		t.Errorf("different-name: got %d terms, want 3 (t1,t2,t9 all survive)", len(f.Terms))
	}
}
