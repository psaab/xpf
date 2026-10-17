package config

import (
	"sort"
	"testing"
)

// #14417 (DR15-H2): a group packed prefix-list definition beside an inline
// packed prefix-list definition with a DIFFERENT name was dropped by the
// apply-groups leaf merge: namedLeafPeer9859 declines the children==nil
// prefix-list schema, the legacy keyword peer selects the inline list by
// Keys[0] alone, and the leaf branch overrides (drops) the group leaf.
// The dropped list is then referenced by a routing-policy `then reject`
// term that never matches, so the routes it was written to reject fall
// through to accept. Both definitions must compile; same-name definitions
// must still union.

func prefixListPrefixes14417(t *testing.T, cfg *Config, name string) []string {
	t.Helper()
	pl := cfg.PolicyOptions.PrefixLists[name]
	if pl == nil {
		return nil
	}
	out := append([]string(nil), pl.Prefixes...)
	sort.Strings(out)
	return out
}

func equalStrings14417(a, b []string) bool {
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

const dr15H2Fixture14417 = `
groups {
  g1 {
    policy-options {
      prefix-list PL2 192.168.0.0/16;
    }
  }
}
policy-options {
  prefix-list PL1 10.0.0.0/8;
  policy-statement P {
    term t1 {
      from {
        prefix-list PL2;
      }
      then reject;
    }
    term t2 {
      then accept;
    }
  }
}
apply-groups g1;
`

func TestDR15H2GroupPackedPrefixListBesideInlinePacked(t *testing.T) {
	cfg := mustCompile(t, dr15H2Fixture14417)
	if got := prefixListPrefixes14417(t, cfg, "PL1"); !equalStrings14417(got, []string{"10.0.0.0/8"}) {
		t.Fatalf("PL1 = %v, want [10.0.0.0/8]", got)
	}
	if got := prefixListPrefixes14417(t, cfg, "PL2"); !equalStrings14417(got, []string{"192.168.0.0/16"}) {
		t.Fatalf("#14417: PL2 = %v, want [192.168.0.0/16] — group packed prefix-list definition dropped beside inline packed PL1", got)
	}
	ps := cfg.PolicyOptions.PolicyStatements["P"]
	if ps == nil || len(ps.Terms) != 2 {
		t.Fatalf("policy-statement P = %+v, want 2 terms", ps)
	}
	if len(ps.Terms[0].PrefixList) != 1 || ps.Terms[0].PrefixList[0] != "PL2" {
		t.Fatalf("t1 PrefixList = %v, want [PL2]", ps.Terms[0].PrefixList)
	}
}

func TestDR15H2GroupPackedPrefixListBesideInlinePackedSwapped(t *testing.T) {
	cfg := mustCompile(t, `
groups {
  g1 {
    policy-options {
      prefix-list PL1 10.0.0.0/8;
    }
  }
}
policy-options {
  prefix-list PL2 192.168.0.0/16;
  policy-statement P {
    term t1 {
      from {
        prefix-list PL2;
      }
      then reject;
    }
    term t2 {
      then accept;
    }
  }
}
apply-groups g1;
`)
	if got := prefixListPrefixes14417(t, cfg, "PL1"); !equalStrings14417(got, []string{"10.0.0.0/8"}) {
		t.Fatalf("PL1 = %v, want [10.0.0.0/8]", got)
	}
	if got := prefixListPrefixes14417(t, cfg, "PL2"); !equalStrings14417(got, []string{"192.168.0.0/16"}) {
		t.Fatalf("#14417 swapped: PL2 = %v, want [192.168.0.0/16]", got)
	}
}

func TestDR15H2SameNameGroupInlinePrefixListsStillUnion(t *testing.T) {
	cfg := mustCompile(t, `
groups {
  g1 {
    policy-options {
      prefix-list PL1 192.168.0.0/16;
    }
  }
}
policy-options {
  prefix-list PL1 10.0.0.0/8;
}
apply-groups g1;
`)
	if got := prefixListPrefixes14417(t, cfg, "PL1"); !equalStrings14417(got, []string{"10.0.0.0/8"}) {
		t.Fatalf("same-name PL1 = %v, want inline-wins [10.0.0.0/8] (compiler #2641 union preserved via adopt/merge path, not leaf drop)", got)
	}
	if len(cfg.PolicyOptions.PrefixLists) != 1 {
		t.Fatalf("PrefixLists = %v, want exactly one PL1 entry", cfg.PolicyOptions.PrefixLists)
	}
}

func TestDR15H2InlineOnlyBothPrefixLists(t *testing.T) {
	cfg := mustCompile(t, `
policy-options {
  prefix-list PL1 10.0.0.0/8;
  prefix-list PL2 192.168.0.0/16;
}
`)
	if got := prefixListPrefixes14417(t, cfg, "PL1"); !equalStrings14417(got, []string{"10.0.0.0/8"}) {
		t.Fatalf("PL1 = %v, want [10.0.0.0/8]", got)
	}
	if got := prefixListPrefixes14417(t, cfg, "PL2"); !equalStrings14417(got, []string{"192.168.0.0/16"}) {
		t.Fatalf("PL2 = %v, want [192.168.0.0/16]", got)
	}
}

func TestDR15H2GroupOnlyPrefixListAdopted(t *testing.T) {
	cfg := mustCompile(t, `
groups {
  g1 {
    policy-options {
      prefix-list PL2 192.168.0.0/16;
    }
  }
}
policy-options {
  policy-statement P {
    term t1 {
      from {
        prefix-list PL2;
      }
      then reject;
    }
  }
}
apply-groups g1;
`)
	if got := prefixListPrefixes14417(t, cfg, "PL2"); !equalStrings14417(got, []string{"192.168.0.0/16"}) {
		t.Fatalf("group-only PL2 = %v, want [192.168.0.0/16]", got)
	}
}
