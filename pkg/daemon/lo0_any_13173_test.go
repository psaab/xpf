package daemon

import "testing"

func TestNftAddrPredicateAnyUniverse13173(t *testing.T) {
	for _, tc := range []struct {
		name, family string
		addrs        []string
	}{
		{"v4 any", "ip", []string{"any"}},
		{"v6 any", "ip6", []string{"any"}},
		{"v4 slash0", "ip", []string{"0.0.0.0/0"}},
		{"v6 slash0", "ip6", []string{"::/0"}},
	} {
		t.Run(tc.name+"/positive", func(t *testing.T) {
			pred, nothing := nftAddrPredicate("saddr", tc.family, tc.addrs, false, true)
			if pred != "" || nothing {
				t.Fatalf("predicate=%q matchesNothing=%v, want empty,false", pred, nothing)
			}
		})
		t.Run(tc.name+"/except", func(t *testing.T) {
			pred, nothing := nftAddrPredicate("saddr", tc.family, tc.addrs, true, true)
			if pred != "" || !nothing {
				t.Fatalf("predicate=%q matchesNothing=%v, want empty,true", pred, nothing)
			}
		})
	}
	if got, nothing := nftAddrPredicate("saddr", "ip", []string{"any", "10.0.0.0/8"}, false, true); got != "" || nothing {
		t.Fatalf("any plus v4 prefix = %q,%v, want empty,false", got, nothing)
	}
	if got, nothing := nftAddrPredicate("saddr", "ip", []string{"::/0"}, false, true); got != "" || !nothing {
		t.Fatalf("wrong-family /0 = %q,%v, want empty,true", got, nothing)
	}
	// A malformed entry must not be hidden by a match-any token: retain the
	// invalid token so nft rejects the atomic ruleset, matching #6512.
	if got, nothing := nftAddrPredicate("saddr", "ip", []string{"any", "not-an-address"}, false, true); got == "" || nothing {
		t.Fatalf("malformed alongside any = %q,%v, want invalid predicate for fail-closed load", got, nothing)
	}
}
