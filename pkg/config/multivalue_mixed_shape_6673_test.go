package config

import (
	"strings"
	"testing"
)

// Round-9 guards for the two remaining classes the widened multi-value readers
// introduced: an INVENTED REJECTION on a mixed AST shape (a config that
// committed before #6659 must still commit), and a VALIDATION ESCAPE where a
// widened value reaches no gate at all.

// masterAMExprs6673 is origin/master's `attributes-match` reader verbatim (the
// pre-#6659 body of compileEventOptions):
//
//	for _, amChild := range child.Children {
//	    append(ep.AttributesMatch, strings.Join(amChild.Keys, " "))
//	}
//
// The node's own Keys were never read, which is exactly why a mixed
// `attributes-match <tail> { <expr>; }` compiled cleanly on master.
func masterAMExprs6673(n *Node) []string {
	var out []string
	for _, c := range n.Children {
		out = append(out, strings.Join(c.Keys, " "))
	}
	return out
}

func amNode6673(t *testing.T, tree *ConfigTree) *Node {
	t.Helper()
	for _, root := range tree.Children {
		if root.Name() != "event-options" {
			continue
		}
		pol := root.FindChild("policy")
		if pol == nil {
			t.Fatal("no policy node")
		}
		am := pol.FindChild("attributes-match")
		if am == nil {
			t.Fatal("no attributes-match node")
		}
		return am
	}
	t.Fatal("no event-options root")
	return nil
}

// TestEventAttributesMatch6673MixedShapeStillCommits is the R4 differential.
//
// `attributes-match bogus { "ping_test_failed.test-owner matches ^alice$"; }` parses as
// Keys=["attributes-match","bogus"] with one child. Master read Children only,
// so `bogus` was discarded and the config committed. Materialising it hands
// ValidateEventAttributesMatchStrict a token with no " matches " separator,
// which is rejected as a malformed match expression — a configuration that
// committed before this PR stops committing.
//
// The expected constraint list is origin/master's own reader output, not a
// literal: a hardcoded expectation is how the earlier round's vacuous
// assertions got written.
func TestEventAttributesMatch6673MixedShapeStillCommits(t *testing.T) {
	const cfgText = `event-options {
  policy p {
    events ping_test_failed;
    attributes-match bogus { "ping_test_failed.test-owner matches ^alice$"; }
  }
}`
	tree := hierTree6659(t, cfgText)
	want := masterAMExprs6673(amNode6673(t, tree))
	if len(want) != 1 {
		t.Fatalf("oracle premise broken: origin/master's reader produced %q, "+
			"want the one child expression", want)
	}

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict commit REJECTED a configuration origin/master "+
			"accepts: %v\n"+
			"The `bogus` token is the identifier slot of a mixed "+
			"`attributes-match <tail> { <expr>; }` node. Master's reader never "+
			"looked at the node's own Keys, so it discarded the token and "+
			"compiled %q. Promoting it turns a committed config into an "+
			"uncommittable one on upgrade — widening a read must not invent a "+
			"rejection out of a token the previous reader discarded.", err, want)
	}
	got := cfg.EventOptions[0].AttributesMatch
	if len(got) != len(want) {
		t.Fatalf("compiled constraints %q, want origin/master's %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("compiled constraint[%d] = %q, want origin/master's %q "+
				"(full: got %q want %q)", i, got[i], want[i], got, want)
		}
	}
}

// TestEventChangeConfigCommands6673MixedShapeStillCommits is the config-side
// half of R2: the same mixed shape on the `commands` leaf must keep compiling to
// exactly the child command. (pkg/eventengine carries the runtime half, which
// asserts the batch still classifies into an executable plan.)
func TestEventChangeConfigCommands6673MixedShapeStillCommits(t *testing.T) {
	tree := hierTree6659(t, `event-options {
  policy p {
    events ping_test_failed;
    then { change-configuration { commands bogus { "set system host-name fired"; } } }
  }
}`)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict commit rejected a configuration origin/master accepts: %v", err)
	}
	got := cfg.EventOptions[0].ThenCommands
	if len(got) != 1 || got[0] != "set system host-name fired" {
		t.Fatalf("ThenCommands = %q, want exactly the child command; the "+
			"node's own `bogus` tail is the identifier slot master discarded, "+
			"and promoting it makes eventengine.classifyPlan reject the whole "+
			"remediation batch", got)
	}
}

// TestEventAttributesMatch6673PackedMalformedStillRejected is the CONTROL that
// keeps the R4 fix from becoming "stop validating tails". A packed tail with NO
// children is the shape master compiled NOTHING from, so #6659's fail-closed
// conversion applies there and a malformed packed expression must still be
// rejected at strict commit.
func TestEventAttributesMatch6673PackedMalformedStillRejected(t *testing.T) {
	tree := hierTree6659(t, `event-options {
  policy p {
    events ping_test_failed;
    attributes-match bogus;
  }
}`)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("strict commit accepted a malformed PACKED attributes-match " +
			"expression; master compiled nothing from a packed tail (the #6659 " +
			"fail-open), so this must reject")
	}
}

// TestMixedShape6673IsOnlyAnIssueForChildrenOnlyReaders pins the SCOPE claim
// the two fixes above rest on, so the next auditor does not have to re-derive
// it: the promote-a-discarded-token regression is possible only where the
// pre-#6659 reader read Children EXCLUSIVELY.
//
// `nodeVal` reads Keys[1] and falls back to Children[0].Name(), so on every
// other widened leaf the tail was ALREADY the selected value — there is no
// discarded token to promote. Feeding those leaves the same mixed shape either
// still commits (proxy-ARP, whose leaf takes a list) or fails for the
// CARDINALITY reason that applies to the bracket spelling too — the reviewed
// core of #6659, not a shape-specific invention.
func TestMixedShape6673IsOnlyAnIssueForChildrenOnlyReaders(t *testing.T) {
	t.Run("proxy-arp address a { b; } still commits", func(t *testing.T) {
		if _, err := CompileConfig(hierTree6659(t, `
security { nat { proxy-arp { interface ge-0-0-0 { address 192.0.2.1 { 192.0.2.2; } } } } }`)); err != nil {
			t.Fatalf("a mixed-shape proxy-ARP address list must still commit: %v", err)
		}
	})
	for _, tc := range []struct{ name, mixed, bracket, wantSub string }{
		{
			name: "static-NAT match destination-address",
			mixed: `
security { nat { static { rule-set rs1 { from zone untrust;
    rule r1 { match { destination-address 192.0.2.1/32 { 198.51.100.1/32; } }
              then { static-nat prefix 10.0.0.1/32; } } } } } }`,
			bracket: `
security { nat { static { rule-set rs1 { from zone untrust;
    rule r1 { match { destination-address [ 192.0.2.1/32 198.51.100.1/32 ]; }
              then { static-nat prefix 10.0.0.1/32; } } } } } }`,
			wantSub: "declares 2 `match destination-address` prefixes",
		},
		{
			name: "forwarding-table export",
			mixed: `
policy-options { policy-statement p1 { then accept; } policy-statement p2 { then accept; } }
routing-options { forwarding-table { export p1 { p2; } } }`,
			bracket: `
policy-options { policy-statement p1 { then accept; } policy-statement p2 { then accept; } }
routing-options { forwarding-table { export [ p1 p2 ]; } }`,
			wantSub: "declares 2 policies",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, mixedErr := CompileConfig(hierTree6659(t, tc.mixed))
			_, bracketErr := CompileConfig(hierTree6659(t, tc.bracket))
			if mixedErr == nil || bracketErr == nil {
				t.Fatalf("both spellings authored TWO values and must be "+
					"rejected: mixed=%v bracket=%v", mixedErr, bracketErr)
			}
			for _, e := range []error{mixedErr, bracketErr} {
				if !strings.Contains(e.Error(), tc.wantSub) {
					t.Fatalf("rejection is not the cardinality gate: %v", e)
				}
			}
			if mixedErr.Error() != bracketErr.Error() {
				t.Fatalf("the mixed shape must fail for the SAME reason as the "+
					"bracket spelling — a shape-specific rejection would be the "+
					"promote-a-discarded-token defect:\n  mixed:   %v\n  bracket: %v",
					mixedErr, bracketErr)
			}
		})
	}
}

// TestEventOptions6673IdentifierSlotValueIsDropped pins the stated RESIDUAL of
// the children-win rule: a value authored in the identifier slot BESIDE a block
// is dropped, exactly as origin/master dropped it. Nothing regresses, but the
// loss is silent, so it is written down here and in docs/config-schema.md rather
// than left for someone to discover.
func TestEventOptions6673IdentifierSlotValueIsDropped(t *testing.T) {
	tree := hierTree6659(t, `event-options {
  policy p {
    events ping_test_failed;
    attributes-match "ping_test_failed.test-owner matches ^alice$" { "ping_test_failed.test-name matches ^wan$"; }
    then { change-configuration { commands "set system host-name a" { "set system host-name b"; } } }
  }
}`)
	want := masterAMExprs6673(amNode6673(t, tree))
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict compile: %v", err)
	}
	pol := cfg.EventOptions[0]
	if len(pol.AttributesMatch) != 1 || pol.AttributesMatch[0] != want[0] {
		t.Fatalf("AttributesMatch = %q, want origin/master's %q — the "+
			"identifier-slot value is dropped on both trees", pol.AttributesMatch, want)
	}
	if len(pol.ThenCommands) != 1 || pol.ThenCommands[0] != "set system host-name b" {
		t.Fatalf("ThenCommands = %q, want the block member alone", pol.ThenCommands)
	}
}

// TestNPTv6MatchAddr6673HostBitsTailIsNotCollapsed is the G1 differential.
//
// `destination-address [ 2001:db8:1::/48 2001:db8:1:2::/48 ]` widens to a
// two-value MatchAddresses. The second has host bits set, which the NPTv6
// consumer REJECTS (parse_prefix in userspace-dp/src/nptv6.rs: "OR host bits
// are set beyond the prefix length (#4519 — fail closed, do NOT mask)").
// Keying both on their MASKED form collapsed them to one, so:
//
//   - the cardinality gate saw a single prefix and passed;
//   - the generic per-address validator skips NPTv6 rules;
//   - validateNPTv6PrefixesStrict reads only the scalar rule.Match, which is
//     the FIRST (valid) value.
//
// Nothing rejected the invalid tail and nothing installed it — the widened
// value reached no gate at all, falsifying the PR's "every widened value is
// validated". The dedupe key is the defect: masking is the right identity for
// plain static NAT (whose Rust consumer masks too) and the WRONG one for NPTv6.
func TestNPTv6MatchAddr6673HostBitsTailIsNotCollapsed(t *testing.T) {
	tree := hierTree6659(t, `
security { nat { static { rule-set rs1 { from zone untrust;
    rule r1 { match { destination-address [ 2001:db8:1::/48 2001:db8:1:2::/48 ]; }
              then { static-nat { nptv6-prefix 2001:db8:2::/48; } } } } } } }`)

	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("strict commit ACCEPTED an NPTv6 rule whose second `match " +
			"destination-address` has host bits set. The value is neither " +
			"installed nor rejected: staticNATMatchAddrKey masks both prefixes " +
			"to 2001:db8:1::/48 so the cardinality gate counts one, the " +
			"per-address validator skips NPTv6 rules, and the NPTv6 validator " +
			"reads only the scalar rule.Match. NPTv6's consumer fails closed on " +
			"host bits instead of masking, so the two prefixes do NOT install " +
			"alike and must not share a dedupe key")
	}
	if !strings.Contains(err.Error(), "2001:db8:1:2::/48") {
		t.Fatalf("the rejection must name the value that escaped, got: %v", err)
	}

	// The tolerant path must still boot on the same config (#1960 no-brick),
	// and must install the SELECTED prefix exactly as origin/master did.
	cfg, lerr := CompileConfigLenient(tree)
	if lerr != nil {
		t.Fatalf("tolerant compile must not brick on a config an older binary "+
			"persisted: %v", lerr)
	}
	if got := cfg.Security.NAT.Static[0].Rules[0].Match; got != "2001:db8:1::/48" {
		t.Fatalf("tolerant Match = %q, want the selected first value "+
			"2001:db8:1::/48 (origin/master's installed prefix)", got)
	}
}

// TestNPTv6MatchAddr6673IdenticalRepeatStillCollapses is the CONTROL for G1: the
// invented-rejection fix dedupeValuesBy exists for must survive. A prefix
// REPEATED identically is one prefix under any consumer, including NPTv6, and a
// canonical-but-differently-spelled repeat is too.
func TestNPTv6MatchAddr6673IdenticalRepeatStillCollapses(t *testing.T) {
	for _, tc := range []struct{ name, list string }{
		{"identical repeat", `[ 2001:db8:1::/48 2001:db8:1::/48 ]`},
		{"same prefix, leading-zero spelling", `[ 2001:db8:1::/48 2001:0db8:0001::/48 ]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := hierTree6659(t, `
security { nat { static { rule-set rs1 { from zone untrust;
    rule r1 { match { destination-address `+tc.list+`; }
              then { static-nat { nptv6-prefix 2001:db8:2::/48; } } } } } } }`)
			if _, err := CompileConfig(tree); err != nil {
				t.Fatalf("strict commit rejected a REPEATED identical NPTv6 "+
					"prefix, which origin/master accepted and compiled "+
					"byte-identically: %v", err)
			}
		})
	}
}

// TestNPTv6MatchAddr6673HostBitsAloneStillRejected pins the pre-existing scalar
// gate the G1 reasoning leans on: when the host-bits value IS the selected one,
// validateNPTv6PrefixesStrict already rejects it. Together with the cardinality
// gate above, every widened NPTv6 value is covered — a value distinct from the
// selected one by cardinality, a value identical to it by this gate.
func TestNPTv6MatchAddr6673HostBitsAloneStillRejected(t *testing.T) {
	tree := hierTree6659(t, `
security { nat { static { rule-set rs1 { from zone untrust;
    rule r1 { match { destination-address 2001:db8:1:2::/48; }
              then { static-nat { nptv6-prefix 2001:db8:2::/48; } } } } } } }`)
	err := CompileConfig6673MustFail(t, tree)
	if !strings.Contains(err.Error(), "host bits set") {
		t.Fatalf("want the NPTv6 host-bits rejection, got: %v", err)
	}
}

// CompileConfig6673MustFail asserts strict compilation rejects tree.
func CompileConfig6673MustFail(t *testing.T, tree *ConfigTree) error {
	t.Helper()
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("strict compile accepted a configuration that must be rejected")
	}
	return err
}

// TestStaticNATMatchAddr6673PlainRuleStillMasks is the CONTROL that keeps the
// G1 key fix scoped to NPTv6. Plain static NAT's Rust consumer MASKS
// (`base = addr & !host_mask(len)` in parse_nat_prefix), so two spellings of the
// same host route still lower to one row and must still count once.
func TestStaticNATMatchAddr6673PlainRuleStillMasks(t *testing.T) {
	tree := hierTree6659(t, `
security { nat { static { rule-set rs1 { from zone untrust;
    rule r1 { match { destination-address [ 192.0.2.1/32 192.0.2.1 ]; }
              then { static-nat prefix 10.0.0.1/32; } } } } } }`)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("strict commit rejected two spellings of ONE host route on a "+
			"plain static-NAT rule; the masked dedupe key must stay in force "+
			"for the non-NPTv6 consumer: %v", err)
	}
}
