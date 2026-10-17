package config_test

// #14416 (DR15-H1): a group `route-filter` leaf beside an inline
// `route-filter` leaf in the same policy-statement term `from` was
// dropped by the apply-groups leaf merge. `route-filter` is
// schema `args:2, multi:true` (schema_routing.go): repeated members
// are Junos OR-members, and the compiler appends EVERY sibling
// route-filter into term.RouteFilters. But `leafListUnionEligible`
// requires `args <= 1`, promote/same-instance fail because the leaf
// schema has no children, so the leaf branch fell through to the
// inline-wins `continue` and the group member vanished. A reject
// term written in two halves therefore matched only the inline half;
// the group half's prefixes fell through to the next term's accept.
//
// FAIL-ON-REVERT: removing the route-filter OR-member adoption arm
// in mergeNodes (ast_groups.go) drops the group member again and
// every group+inline cell below goes RED; the duplicate-member and
// inline-only controls pin that adoption is deduped, not duplicated.

import (
	"fmt"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func routeFilterKeys14416(cfg *config.Config) []string {
	ps := cfg.PolicyOptions.PolicyStatements["P"]
	if ps == nil {
		return nil
	}
	for _, term := range ps.Terms {
		if term.Name != "t1" {
			continue
		}
		var out []string
		for _, rf := range term.RouteFilters {
			key := fmt.Sprintf("%s %s", rf.Prefix, rf.MatchType)
			if rf.MatchType == "upto" && rf.UptoLen != 0 {
				key += fmt.Sprintf(" /%d", rf.UptoLen)
			}
			if rf.MatchType == "prefix-length-range" && (rf.RangeLow != 0 || rf.RangeHigh != 0) {
				key += fmt.Sprintf(" /%d-/%d", rf.RangeLow, rf.RangeHigh)
			}
			if rf.MatchType == "through" && rf.ThroughPrefix != "" {
				key += " " + rf.ThroughPrefix
			}
			out = append(out, key)
		}
		if term.Action != "reject" {
			out = append(out, "ACTION="+term.Action)
		}
		return out
	}
	return nil
}

func assertRouteFilters14416(t *testing.T, cfg *config.Config, want ...string) {
	t.Helper()
	got := routeFilterKeys14416(cfg)
	seen := map[string]int{}
	for _, g := range got {
		seen[g]++
	}
	for _, w := range want {
		if seen[w] == 0 {
			t.Fatalf("route-filters = %v, missing %q (want %v)", got, w, want)
		}
		if seen[w] > 1 {
			t.Fatalf("route-filters = %v, member %q duplicated", got, w)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("route-filters = %v, want exactly %v", got, want)
	}
	// t2 must still be the fall-through accept term.
	ps := cfg.PolicyOptions.PolicyStatements["P"]
	if len(ps.Terms) != 2 || ps.Terms[1].Name != "t2" || ps.Terms[1].Action != "accept" {
		t.Fatalf("policy terms changed: %+v", ps.Terms)
	}
}

func TestGroupRouteFilterORBesideInline14416(t *testing.T) {
	t.Run("braced group beside braced inline", func(t *testing.T) {
		cfg := compileHier(t, `
groups {
  g1 {
    policy-options {
      policy-statement P {
        term t1 {
          from {
            route-filter 192.168.0.0/16 exact;
          }
        }
      }
    }
  }
}
policy-options {
  policy-statement P {
    term t1 {
      from {
        route-filter 10.0.0.0/8 orlonger;
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
		assertRouteFilters14416(t, cfg, "10.0.0.0/8 orlonger", "192.168.0.0/16 exact")
	})

	t.Run("swapped group and inline prefixes", func(t *testing.T) {
		cfg := compileHier(t, `
groups {
  g1 {
    policy-options {
      policy-statement P {
        term t1 {
          from {
            route-filter 10.0.0.0/8 orlonger;
          }
        }
      }
    }
  }
}
policy-options {
  policy-statement P {
    term t1 {
      from {
        route-filter 192.168.0.0/16 exact;
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
		assertRouteFilters14416(t, cfg, "10.0.0.0/8 orlonger", "192.168.0.0/16 exact")
	})

	t.Run("packed group route-filter leaf", func(t *testing.T) {
		cfg := compileHier(t, `
groups {
  g1 {
    policy-options {
      policy-statement P {
        term t1 {
          from route-filter 192.168.0.0/16 exact;
        }
      }
    }
  }
}
policy-options {
  policy-statement P {
    term t1 {
      from {
        route-filter 10.0.0.0/8 orlonger;
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
		assertRouteFilters14416(t, cfg, "10.0.0.0/8 orlonger", "192.168.0.0/16 exact")
	})

	t.Run("split inline from blocks", func(t *testing.T) {
		cfg := compileHier(t, `
groups {
  g1 {
    policy-options {
      policy-statement P {
        term t1 {
          from {
            route-filter 192.168.0.0/16 exact;
          }
        }
      }
    }
  }
}
policy-options {
  policy-statement P {
    term t1 {
      from {
        protocol bgp;
      }
      from {
        route-filter 10.0.0.0/8 orlonger;
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
		assertRouteFilters14416(t, cfg, "10.0.0.0/8 orlonger", "192.168.0.0/16 exact")
	})

	t.Run("flat-set group beside flat-set inline", func(t *testing.T) {
		cfg := compileFlat(t,
			"set groups g1 policy-options policy-statement P term t1 from route-filter 192.168.0.0/16 exact",
			"set policy-options policy-statement P apply-groups g1",
			"set policy-options policy-statement P term t1 from route-filter 10.0.0.0/8 orlonger",
			"set policy-options policy-statement P term t1 then reject",
			"set policy-options policy-statement P term t2 then accept",
		)
		assertRouteFilters14416(t, cfg, "10.0.0.0/8 orlonger", "192.168.0.0/16 exact")
	})

	t.Run("distinct trailing upto members both kept", func(t *testing.T) {
		cfg := compileHier(t, `
groups {
  g1 {
    policy-options {
      policy-statement P {
        term t1 {
          from {
            route-filter 10.0.0.0/8 upto /16;
          }
        }
      }
    }
  }
}
policy-options {
  policy-statement P {
    term t1 {
      from {
        route-filter 10.0.0.0/8 upto /24;
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
		assertRouteFilters14416(t, cfg, "10.0.0.0/8 upto /16", "10.0.0.0/8 upto /24")
	})

	t.Run("duplicate member is not duplicated", func(t *testing.T) {
		cfg := compileHier(t, `
groups {
  g1 {
    policy-options {
      policy-statement P {
        term t1 {
          from {
            route-filter 10.0.0.0/8 orlonger;
          }
        }
      }
    }
  }
}
policy-options {
  policy-statement P {
    term t1 {
      from {
        route-filter 10.0.0.0/8 orlonger;
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
		assertRouteFilters14416(t, cfg, "10.0.0.0/8 orlonger")
	})

	t.Run("inline-only control unchanged", func(t *testing.T) {
		cfg := compileHier(t, `
policy-options {
  policy-statement P {
    term t1 {
      from {
        route-filter 10.0.0.0/8 orlonger;
      }
      then reject;
    }
    term t2 {
      then accept;
    }
  }
}
`)
		assertRouteFilters14416(t, cfg, "10.0.0.0/8 orlonger")
	})
}
