package config

import (
	"sort"
	"strings"
	"testing"
)

// #6854: `then reject <message-type>` was validated and stored and then read by
// nothing — the dataplane hardcoded ICMPv4 code 13 / ICMPv6 code 1 for every
// reject. These cells cover the config half: the token must survive compilation
// from every spelling, because the value is now consumed downstream.
//
// compileFilterThen assigns RejectMessageType at THREE sites, and the spellings
// do not map onto them the way the names suggest — the same trap #6853 hit in
// this file. Measured, not assumed, so each cell states which site it drives.
func TestRejectMessageTypeSurvivesEverySpelling_6854(t *testing.T) {
	for _, c := range []struct {
		name string
		tree func(*testing.T) *ConfigTree
	}{
		{
			"compact leaf `then reject host-unreachable;`",
			func(t *testing.T) *ConfigTree {
				return parseHierText(t, `
firewall { family inet { filter f { term t { then reject host-unreachable; } } } }
`)
			},
		},
		{
			"block `then { reject host-unreachable; }`",
			func(t *testing.T) *ConfigTree {
				return parseHierText(t, `
firewall { family inet { filter f { term t { then { reject host-unreachable; } } } } }
`)
			},
		},
		{
			"flat set",
			func(t *testing.T) *ConfigTree {
				return flatTreeFromSets(t,
					"set firewall family inet filter f term t then reject host-unreachable")
			},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			cfg, err := CompileConfig(c.tree(t))
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			filter := cfg.Firewall.FiltersInet["f"]
			if filter == nil || len(filter.Terms) != 1 {
				t.Fatalf("filter f did not compile one term: %+v", cfg.Firewall.FiltersInet)
			}
			term := filter.Terms[0]
			if term.Action != FilterActionReject {
				t.Errorf("Action = %q, want reject", term.Action)
			}
			if term.RejectMessageType != "host-unreachable" {
				t.Errorf("RejectMessageType = %q, want host-unreachable — the token is now "+
					"CONSUMED by the dataplane to pick the ICMP code, so losing it silently "+
					"reverts #6854 to administratively-prohibited",
					term.RejectMessageType)
			}
		})
	}
}

// A bare `then reject` must leave the message-type EMPTY, which is what the
// dataplane resolves to administratively-prohibited — the behaviour every
// reject had before #6854. Without this cell, a change that defaulted the field
// to a concrete token would pass every cell above while altering the wire for
// configs that never asked for a message-type.
func TestBareRejectCarriesNoMessageType_6854(t *testing.T) {
	cfg, err := CompileConfig(parseHierText(t, `
firewall { family inet { filter f { term t { then reject; } } } }
`))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	term := cfg.Firewall.FiltersInet["f"].Terms[0]
	if term.Action != FilterActionReject {
		t.Fatalf("Action = %q, want reject", term.Action)
	}
	if term.RejectMessageType != "" {
		t.Errorf("RejectMessageType = %q, want empty — a bare `then reject` must keep the "+
			"pre-#6854 administratively-prohibited codes", term.RejectMessageType)
	}
}

// CROSS-LANGUAGE TRIPWIRE.
//
// The Rust resolver (`crate::filter::resolve_reject_message`) has one match arm
// per token in `rejectMessageTypes`, and Go cannot call it. The two must agree:
// a token accepted here that the resolver does not know silently degrades to
// administratively-prohibited, which is the exact defect #6854 fixed.
//
// This pins the accepted SET so adding a token reds here and points at the Rust
// table that must gain a row. It deliberately pins the set rather than the
// count — a count alone passes when one token is swapped for another.
func TestRejectMessageTypeSetIsPinnedToTheRustTable_6854(t *testing.T) {
	got := make([]string, 0, len(rejectMessageTypes))
	for k := range rejectMessageTypes {
		got = append(got, k)
	}
	sort.Strings(got)

	// Keep in step with the table in
	// userspace-dp/src/filter/tests.rs :: reject_message_type_maps_every_accepted_token_6854
	want := []string{
		"administratively-prohibited",
		"bad-host-tos",
		"bad-network-tos",
		"host-prohibited",
		"host-unreachable",
		"network-prohibited",
		"network-unreachable",
		"port-unreachable",
		"precedence-cutoff",
		"precedence-violation",
		"protocol-unreachable",
		"source-host-isolated",
		"source-route-failed",
		"tcp-reset",
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("the accepted `then reject` message-type set changed.\n got: %v\nwant: %v\n\n"+
			"If a token was ADDED, add a row to the Rust mapping table in\n"+
			"userspace-dp/src/filter/tests.rs (reject_message_type_maps_every_accepted_token_6854)\n"+
			"AND a match arm in crate::filter::resolve_reject_message, or the new token silently\n"+
			"degrades to administratively-prohibited on the wire (#6854).", got, want)
	}
}
