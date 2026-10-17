package config_test

// #14741: cross-term control for the per-expansion route-filter dedup.
// The same group member adopted beside DIFFERENT inline members in
// DIFFERENT terms must adopt in both terms — the dedup record is keyed
// on the destination level (ancestor path + inline peer identity), so
// suppressing across terms would silently drop a reject half again.

import "testing"

func TestGroupRouteFilterSameMemberTwoTerms14741(t *testing.T) {
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
        term t2 {
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
      from {
        route-filter 172.16.0.0/12 orlonger;
      }
      then reject;
    }
    term t3 {
      then accept;
    }
  }
}
apply-groups g1;
`)
	ps := cfg.PolicyOptions.PolicyStatements["P"]
	if ps == nil || len(ps.Terms) != 3 {
		t.Fatalf("policy-statement P = %+v, want 3 terms", ps)
	}
	for i, want := range []int{2, 2, 0} {
		if got := len(ps.Terms[i].RouteFilters); got != want {
			t.Fatalf("term %s route-filters = %d, want %d (%v)", ps.Terms[i].Name, got, want, ps.Terms[i].RouteFilters)
		}
	}
}
