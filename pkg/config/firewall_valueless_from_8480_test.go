package config

import (
	"strings"
	"testing"
)

func fwTree8480(t *testing.T, fromBody string) *ConfigTree {
	t.Helper()
	src := `firewall { family inet { filter F { term T { from { ` + fromBody +
		` } then { discard; } } } } }`
	tree, perrs := NewParser(src).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture did not parse: %v", perrs)
	}
	return tree
}

// TestValuelessFirewallFromIsRejected8480 is the #8480 gate.
//
// A value-bearing `from` leaf written with no operand compiles to the
// byte-identical empty match set the OMITTED form produces, and the matcher
// reads empty as match-ANY. So `from protocol;` beside `then discard` discards
// every protocol, and beside `then accept` opens every protocol — the term
// widens in whichever direction the action points.
//
// Security policies have rejected this since #6526 and NAT since #8430; this is
// #8430's unshipped remainder, so the value of the cells is as much about the
// CONSISTENCY as about the defect.
func TestValuelessFirewallFromIsRejected8480(t *testing.T) {
	rows := []struct {
		name    string
		from    string
		wantErr string // "" = must COMMIT
	}{
		{"protocol with no value", `protocol;`, "protocol"},
		{"source-address with no value", `source-address;`, "source-address"},
		{"destination-port with no value", `destination-port;`, "destination-port"},
		{"tcp-flags with no value", `tcp-flags;`, "tcp-flags"},
		{"source-prefix-list with no value", `source-prefix-list;`, "source-prefix-list"},
		{
			// Two at once: the message must name BOTH, or an operator fixes one
			// and re-commits into the same error.
			name:    "two valueless leaves are both named",
			from:    `protocol; icmp-type;`,
			wantErr: "protocol, icmp-type",
		},

		// ── CONTROLS. Each is a shape the gate must NOT touch, and together
		// they are what distinguishes this from a gate that refuses every
		// `from` block.
		{"protocol WITH a value commits", `protocol tcp;`, ""},
		{"a bracketed list commits", `protocol [ tcp udp ];`, ""},
		{
			// is-fragment is a presence-only FLAG — compileFirewall sets
			// term.IsFragment = true and reads no values. Rejecting it would
			// refuse a correct configuration, and it is the single most likely
			// over-reach here because it LOOKS valueless.
			name: "the is-fragment FLAG is not a valueless value-leaf",
			from: `is-fragment;`,
		},
		{
			// #14347: direct field leaves under flexible-match-range (no
			// named range) are outside the schema grammar and are now
			// recorded on UnknownFlexMatch, so strict rejects. (Was a
			// commits control before #14347.)
			name:    "flexible-match-range direct leaves rejected (#14347)",
			from:    `flexible-match-range { match-start layer-3; byte-offset 4; }`,
			wantErr: "flexible-match-range",
		},
		{
			// Junos merges duplicate blocks, so a leaf written twice is
			// constrained if ANY occurrence carries a value. Flagging this
			// would refuse a correct config, and it is the case a naive
			// last-one-wins read gets wrong.
			name: "a duplicated leaf is constrained if either occurrence has a value",
			from: `protocol; protocol tcp;`,
		},
		{
			// BOTH orders. The first version tested only valueless-then-valued,
			// and a mutation replacing the seen/valued split with a
			// last-occurrence-wins assignment ESCAPED — that order happens to
			// end on the valued occurrence, so it passes either way. This is
			// the order that discriminates, and its absence made the case above
			// a fixture that varies the right axis and samples only the passing
			// point.
			name: "...in EITHER order",
			from: `protocol tcp; protocol;`,
		},
		{"an empty from block commits (nothing written, nothing widened)", ``, ""},
	}

	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			_, err := CompileConfig(fwTree8480(t, row.from))
			if row.wantErr == "" {
				if err != nil {
					t.Fatalf("must commit, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("a valueless `from %s` was accepted — the term matches "+
					"EVERY packet on that criterion", row.from)
			}
			if !strings.Contains(err.Error(), row.wantErr) {
				t.Fatalf("rejected for the wrong reason\n  want substring: %q\n  got: %v",
					row.wantErr, err)
			}
		})
	}
}

// TestValuelessFirewallFromIsLenientOnLoad8480 pins the #1960 no-brick side.
// A config an older binary accepted and PERSISTED must still boot, so the
// tolerant path warns instead of failing. Without this the gate turns every
// already-committed valueless term into an unbootable node — strictly worse
// than the defect it fixes.
func TestValuelessFirewallFromIsLenientOnLoad8480(t *testing.T) {
	tree := fwTree8480(t, `protocol;`)

	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("control failed: the strict path must reject this, or the " +
			"lenient assertion below proves nothing")
	}

	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("the tolerant path must not brick the node: %v", err)
	}
	var found bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "protocol") && strings.Contains(w, "8480") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the tolerant path must WARN, not swallow; warnings: %v", cfg.Warnings)
	}
}
