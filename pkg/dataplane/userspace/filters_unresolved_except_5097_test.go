package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #5097, #11451: the tolerant/peer-sync path records unresolved prefix-list
// polarity, but an unresolved `except` is NOT a defined-empty except. Match-all
// could admit or PBR-steer traffic the absent list intended to exclude, so every
// non-deny action must match nothing. Deny actions are checked in the companion
// mixed-ref tests and match all to prevent fall-through to a later permit.
//
// Fail-on-revert: restoring match-all for an unresolved except makes the
// non-deny assertions below fail.
func TestResolvePrefixListAddrsUnresolvedSoleExceptFailsClosedByAction_5097(t *testing.T) {
	// An empty config: the referenced prefix-list is undefined (unresolved on
	// the tolerant path).
	cfg := &config.Config{}

	cases := []struct {
		name      string
		literal   []string
		refName   string
		direction string
	}{
		{"source-inet", nil, "undefined4", "source"},
		{"dest-inet", nil, "undefined4", "destination"},
		{"source-inet6", nil, "undefined6", "source"},
		{"dest-inet6", nil, "undefined6", "destination"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addrs, except, constrained := resolvePrefixListAddrs(
				tc.literal,
				[]config.PrefixListRef{{Name: tc.refName, Except: true}},
				cfg, "f", "t", tc.direction, "accept",
			)
			if !constrained {
				t.Fatalf("an unresolved except reference must stay constrained "+
					"(fail closed), got constrained=false addrs=%v", addrs)
			}
			if except {
				t.Fatalf("a non-deny term with an unresolved sole except must match nothing, "+
					"not match-all; got except=true addrs=%v", addrs)
			}
			if len(addrs) != 0 {
				t.Fatalf("an unresolved except contributes NO prefixes, got addrs=%v", addrs)
			}
		})
	}
}

// A match-any positive literal (`0.0.0.0/0`) alongside an UNRESOLVED except
// reference is still fail-closed for a non-deny action: it must match nothing,
// not compose to match-all with the unknown exclusion list.
func TestResolvePrefixListAddrsMatchAnyPlusUnresolvedExceptFailsClosed_5097(t *testing.T) {
	cfg := &config.Config{}
	addrs, except, constrained := resolvePrefixListAddrs(
		[]string{"0.0.0.0/0"},
		[]config.PrefixListRef{{Name: "undefined", Except: true}},
		cfg, "f", "t", "source", "accept",
	)
	if except || !constrained || len(addrs) != 0 {
		t.Fatalf("match-any + unresolved except must fail closed to match-nothing; got except=%v constrained=%v addrs=%v",
			except, constrained, addrs)
	}
}

// A specific positive scope alongside an UNRESOLVED except still fails closed
// for a non-deny action: an unknown excluded set must not preserve a potentially
// over-broad admit/steer scope.
func TestResolvePrefixListAddrsSpecificPlusUnresolvedExceptFailsClosed_5097(t *testing.T) {
	cfg := &config.Config{}
	addrs, except, constrained := resolvePrefixListAddrs(
		[]string{"10.0.0.0/8"},
		[]config.PrefixListRef{{Name: "undefined", Except: true}},
		cfg, "f", "t", "source", "accept",
	)
	if except || !constrained || len(addrs) != 0 {
		t.Fatalf("specific positive + unresolved except must fail closed to match-nothing; got except=%v constrained=%v addrs=%v",
			except, constrained, addrs)
	}
}
