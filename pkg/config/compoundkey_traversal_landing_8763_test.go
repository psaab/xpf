package config

import (
	"encoding/json"
	"sort"
	"testing"
)

// #8763: what the compoundKey traversal fix actually activates.
//
// 30 admitted (container, head) pairs are reachable ONLY below a `family`.
// Before the fix they folded nothing; after it they fold for the first time.
// "The suite stays green" is not a measurement of them -- a pair whose value is
// silently dropped produces a clean commit either way, which is the whole
// defect class this normalizer exists for.
//
// THE INSTRUMENT IS THREE-WAY, AND THAT IS THE POINT. Comparing packed against
// braced establishes AGREEMENT, and two spellings agree whenever BOTH are
// wrong: a leaf whose reader ignores the value compiles identically in either
// spelling, so an agreement check reports success on a leaf that does nothing.
// Every case therefore also compiles a BASELINE with the statement REMOVED:
//
//	braced == baseline   the braced spelling delivers NOTHING. Pre-existing
//	                     reader defect, and no verdict about the fold at all.
//	braced != baseline   braced delivers. Only then is the packed form judged.
//
// The baseline leg caught `inet6 mode` (nothing reads it in any spelling) and
// it is what distinguishes a real recovery from two spellings agreeing on a
// dropped value.
type famOnlyCase8763 struct {
	pair     string
	preamble string
	braced   string
	packed   string
	baseline string
	want     string
}

const (
	inert8763    = "reads-but-inert"    // the packed tail is already read; the fold changes nothing
	recover8763  = "recovery"           // dropped today, fold delivers exactly the braced result
	chainCut8763 = "chain-incomplete"   // fold fires and STILL delivers nothing: the next link is unadmitted
	readerBug    = "reader-defect"      // braced compiles the same as absent; pre-existing
	gated8763    = "refused-either-way" // a commit gate rejects the value in both spellings
)

func compileFor8763(t *testing.T, text string, skipNormalize bool) (js, verdict string) {
	t.Helper()
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		return "", "PARSE-ERR"
	}
	cfg, err := compileConfigWithOpts(tree, compileOpts{skipCompactNormalize: skipNormalize})
	if err != nil {
		return "", "REJECTED"
	}
	if cfg == nil {
		return "", "nil-cfg"
	}
	cfg.Warnings = nil
	b, _ := json.Marshal(cfg)
	return string(b), "accepted"
}

func foldCount8763(t *testing.T, text string) int {
	t.Helper()
	tree, _ := NewParser(text).Parse()
	if tree == nil {
		return -1
	}
	return normalizeCompactStanzas(tree)
}

func TestTheThirtyFamilyOnlyPairsDeliverOrAreInert8763(t *testing.T) {
	for _, c := range famOnlyCases8763() {
		c := c
		t.Run(c.pair, func(t *testing.T) {
			base, baseV := compileFor8763(t, c.preamble+c.baseline, true)
			br, brV := compileFor8763(t, c.preamble+c.braced, true)
			brOn, _ := compileFor8763(t, c.preamble+c.braced, false)
			pOff, _ := compileFor8763(t, c.preamble+c.packed, true)
			pOn, pOnV := compileFor8763(t, c.preamble+c.packed, false)
			folds := foldCount8763(t, c.preamble+c.packed)

			got := ""
			switch {
			case brV == "REJECTED" && pOnV == "REJECTED":
				got = gated8763
			case brV != "accepted" || baseV != "accepted":
				got = "FIXTURE-BROKEN(" + brV + "/" + baseV + ")"
			case br == base:
				got = readerBug
			case br != brOn:
				got = "PASS-DISTURBS-BRACED"
			case pOnV != "accepted":
				got = "INTRODUCES-REJECTION"
			case pOff == br:
				got = inert8763
			case pOn == br:
				got = recover8763
			case pOn == base:
				got = chainCut8763
			default:
				got = "DIVERGENT"
			}
			if got != c.want {
				t.Errorf("#8763 pair %q: measured %q, expected %q (folds=%d).\n"+
					"This pair is admitted and reachable only below a `family`, so the compoundKey "+
					"traversal is what makes it fold at all. A change here means the fold now does "+
					"something different to a live configuration -- re-measure it against the BRACED "+
					"reference AND the baseline before adjusting this expectation.",
					c.pair, got, c.want, folds)
			}
			// A fold count of zero would make every comparison above a
			// statement about an UNCHANGED tree rather than about the fold --
			// the touched=0 trap. It is only a defect for a pair that is still
			// admitted: this change deliberately un-admits the two `vrrp-group`
			// pairs, and for those the correct expectation is that nothing folds
			// AND the value is refused either way, which is asserted instead.
			kw, head, _ := splitPair8763(c.pair)
			if admitted := compactNormalizeInScope(kw, head); admitted && folds == 0 {
				t.Errorf("#8763 pair %q is ADMITTED but folded NOTHING, so every comparison above is "+
					"a statement about an unchanged tree rather than about the fold", c.pair)
			} else if !admitted {
				if c.want != gated8763 {
					t.Errorf("#8763 pair %q is not admitted but is recorded as %q; only a pair whose "+
						"value a gate refuses in BOTH spellings may be carried here unadmitted, "+
						"because a measurement of an excluded pair otherwise just restates the "+
						"exclusion", c.pair, c.want)
				}
				if folds != 0 {
					t.Errorf("#8763 pair %q is not admitted yet folded %d time(s)", c.pair, folds)
				}
			}
		})
	}
}

// TestTheThirtyAreTheWholeFamilyOnlyPopulation8763 ties the table to the
// enumeration, so a pair admitted later cannot slip past the measurement by
// simply not being listed. The failure this prevents is the one that made the
// dual-path list wrong: a hand-kept population is wrong in the direction nobody
// checks, which is the members that are absent.
func TestTheThirtyAreTheWholeFamilyOnlyPopulation8763(t *testing.T) {
	underFam, noFam, _ := walkPairsByFamilyReach8763(setSchema)
	var live []string
	for pair := range underFam {
		kw, head, ok := splitPair8763(pair)
		if !ok || noFam[pair] || !compactNormalizeInScope(kw, head) {
			continue
		}
		live = append(live, pair)
	}
	measured := map[string]bool{}
	for _, c := range famOnlyCases8763() {
		measured[c.pair] = true
	}
	var missing []string
	for _, p := range live {
		if !measured[p] {
			missing = append(missing, p)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("%d admitted family-only pair(s) have no measurement: %v\n"+
			"Each folds nothing today and starts folding the moment the traversal reaches it. "+
			"Add a case to famOnlyCases8763 -- braced, packed AND baseline -- rather than "+
			"removing it from the walk (#8763).", len(missing), missing)
	}
	if len(live) == 0 {
		t.Error("the walk found no admitted family-only pairs at all, so this cell is vacuous (#8763)")
	}
	// The reverse direction is allowed for exactly one reason: a pair this
	// change UN-ADMITTED is still measured, because "removing it changed
	// nothing" is the claim that justified removing it.
	liveSet := map[string]bool{}
	for _, p := range live {
		liveSet[p] = true
	}
	for _, c := range famOnlyCases8763() {
		if liveSet[c.pair] || c.want == gated8763 {
			continue
		}
		t.Errorf("pair %q is measured but no longer admitted, and is not recorded as %q. "+
			"Either it was removed from scope without saying so here, or the case is stale (#8763).",
			c.pair, gated8763)
	}
	t.Logf("#8763: %d admitted family-only pairs, %d measured", len(live), len(measured))
}

func famOnlyCases8763() []famOnlyCase8763 {
	fwTerm := func(body string) string {
		return "firewall {\n family inet {\n  filter f1 {\n   term t1 {\n" + body + "\n   }\n  }\n }\n}\n"
	}
	fwFilters := "firewall {\n family inet {\n  filter f4probe {\n   term t1 { from { protocol tcp; } then { accept; } }\n  }\n }\n family inet6 {\n  filter f6probe {\n   term t1 { from { next-header tcp; } then { accept; } }\n  }\n }\n}\n"
	ifUnit := func(inner string) string {
		return fwFilters + "interfaces {\n ge-0-0-0 {\n  unit 0 {\n" + inner + "\n  }\n }\n}\n"
	}
	fs := func(inner string) string {
		return "forwarding-options {\n sampling {\n  instance i1 {\n   family inet {\n    output {\n     flow-server 203.0.113.78 {\n" + inner + "\n     }\n    }\n   }\n  }\n }\n}\n"
	}
	fsPacked := func(stmt string) string {
		return "forwarding-options {\n sampling {\n  instance i1 {\n   family inet {\n    output {\n     flow-server 203.0.113.78 " + stmt + ";\n    }\n   }\n  }\n }\n}\n"
	}
	out := func(inner string) string {
		return "forwarding-options {\n sampling {\n  instance i1 {\n   family inet {\n" + inner + "\n   }\n  }\n }\n}\n"
	}
	bgp := func(inner string) string {
		return "protocols {\n bgp {\n  group g1 {\n   type external;\n   peer-as 65001;\n   neighbor 198.51.100.90 {\n    family inet {\n     unicast {\n" + inner + "\n     }\n    }\n   }\n  }\n }\n}\n"
	}
	vrrp := func(inner string) string {
		return ifUnit("   family inet {\n    address 10.9.9.1/24 {\n     vrrp-group 1 " + inner + "\n    }\n   }")
	}
	// A from/then case: `extra` is the rest of the term, held identical across
	// all three legs so the only variable is the statement under measurement.
	fw := func(pair, extra, braced, packed, want string) famOnlyCase8763 {
		return famOnlyCase8763{pair, "", fwTerm(extra + braced), fwTerm(extra + packed), fwTerm(extra), want}
	}
	acc := "    then { accept; }"
	tcp := "    from { protocol tcp; }\n    then { accept; }"
	icmp := "    from { protocol icmp; icmp-type 3; }\n    then { accept; }"
	tcpOnly := "    from { protocol tcp; }"

	return []famOnlyCase8763{
		// The firewall filter MATCH surface. Every one of these is already read
		// out of the packed tail today, so the traversal activates nothing here
		// -- which is the opposite of what "30 pairs go live" suggests, and the
		// reason it had to be measured rather than reasoned about.
		fw("from source-address", acc, "\n    from { source-address 198.51.100.77/32; }", "\n    from source-address 198.51.100.77/32;", inert8763),
		fw("from destination-address", acc, "\n    from { destination-address 203.0.113.77/32; }", "\n    from destination-address 203.0.113.77/32;", inert8763),
		fw("from source-port", tcp, "\n    from { source-port 51479; }", "\n    from source-port 51479;", inert8763),
		fw("from destination-port", tcp, "\n    from { destination-port 51477; }", "\n    from destination-port 51477;", inert8763),
		fw("from source-port-except", tcp, "\n    from { source-port-except 51480; }", "\n    from source-port-except 51480;", inert8763),
		fw("from destination-port-except", tcp, "\n    from { destination-port-except 51478; }", "\n    from destination-port-except 51478;", inert8763),
		fw("from dscp", acc, "\n    from { dscp 37; }", "\n    from dscp 37;", inert8763),
		fw("from icmp-type", icmp, "\n    from { icmp-type 13; }", "\n    from icmp-type 13;", inert8763),
		fw("from icmp-code", icmp, "\n    from { icmp-code 7; }", "\n    from icmp-code 7;", inert8763),
		fw("from tcp-flags", tcp, "\n    from { tcp-flags syn; }", "\n    from tcp-flags syn;", inert8763),
		fw("from traffic-class", acc, "\n    from { traffic-class 5; }", "\n    from traffic-class 5;", inert8763),
		// ...except this one, which IS dropped today. Same container, same
		// `from`, opposite answer -- a container-level verdict would have been
		// wrong for it.
		fw("flexible-match-range range", tcp, "\n    from { flexible-match-range { range 100-200; } }", "\n    from { flexible-match-range range 100-200; }", recover8763),
		// The firewall filter ACTION surface.
		{"then policer", "firewall {\n policer polprobe77 {\n  if-exceeding { bandwidth-limit 10m; burst-size-limit 1500; }\n  then { discard; }\n }\n}\n",
			fwTerm(tcpOnly + "\n    then { policer polprobe77; }"), fwTerm(tcpOnly + "\n    then policer polprobe77;"), fwTerm(tcpOnly + "\n    then { }"), inert8763},
		{"then forwarding-class", "class-of-service {\n forwarding-classes {\n  class fcprobe77 queue-num 3;\n }\n}\n",
			fwTerm(tcp + "\n    then { forwarding-class fcprobe77; }"), fwTerm(tcp + "\n    then forwarding-class fcprobe77;"), fwTerm(tcp), inert8763},
		{"then routing-instance", "routing-instances {\n riprobe77 {\n  instance-type virtual-router;\n }\n}\n",
			fwTerm(tcpOnly + "\n    then { routing-instance riprobe77; }"), fwTerm(tcpOnly + "\n    then routing-instance riprobe77;"), fwTerm(tcpOnly + "\n    then { }"), inert8763},
		{"then dscp", "", fwTerm(tcp + "\n    then { dscp 41; }"), fwTerm(tcp + "\n    then dscp 41;"), fwTerm(tcp), inert8763},
		{"then traffic-class", "", fwTerm(tcp + "\n    then { traffic-class 6; }"), fwTerm(tcp + "\n    then traffic-class 6;"), fwTerm(tcp), inert8763},
		// The filter's own body.
		{"filter term", "", "firewall {\n family inet {\n  filter fprobe77 {\n   term tprobe77 { }\n  }\n }\n}\n",
			"firewall {\n family inet {\n  filter fprobe77 term tprobe77;\n }\n}\n",
			"firewall {\n family inet {\n  filter fprobe77 { }\n }\n}\n", recover8763},
		// Sampling / flow export: six real silent drops.
		{"flow-server port", "", fs("      port 51481;"), fsPacked("port 51481"), fs(""), recover8763},
		{"flow-server source-address", "", fs("      source-address 198.51.100.78;"), fsPacked("source-address 198.51.100.78"), fs(""), recover8763},
		{"flow-server version-ipfix-template", "services {\n flow-monitoring {\n  version-ipfix { template tmplprobe77; }\n }\n}\n",
			fs("      version-ipfix-template tmplprobe77;"), fsPacked("version-ipfix-template tmplprobe77"), fs(""), recover8763},
		{"flow-server version9-template", "services {\n flow-monitoring {\n  version9 { template tmpl9probe77; }\n }\n}\n",
			fs("      version9-template tmpl9probe77;"), fsPacked("version9-template tmpl9probe77"), fs(""), recover8763},
		// `output source-address` is measured ALONE. A packed
		// `output source-address x;` is necessarily its own node, so pairing it
		// against a braced block that ALSO contains a flow-server compares it to
		// a reference the spelling cannot reach -- and two sibling BRACED
		// `output` blocks do not compile the same as one either, which is the
		// control that establishes it is the shape and not the fold.
		{"output source-address", "", out("    output { source-address 198.51.100.79; }"), out("    output source-address 198.51.100.79;"), out("    "), recover8763},
		{"output flow-server", "", out("    output {\n     flow-server 203.0.113.79 { }\n    }"), out("    output flow-server 203.0.113.79;"), out("    output { }"), recover8763},
		{"prefix-limit maximum", "", bgp("      prefix-limit { maximum 51482; }"), bgp("      prefix-limit maximum 51482;"), bgp("      "), recover8763},
		// FORMERLY `chain-incomplete`, NOW A RECOVERY -- and the history is the
		// point rather than the current value. When this traversal landed,
		// (inet, filter) was admitted, the fold FIRED, and the interface still
		// committed with no filter bound, because (filter, input) -- the second
		// link -- was not admitted. A scope entry that fires and delivers
		// nothing reads as coverage, which is why it was recorded here instead
		// of being left to be rediscovered.
		//
		// #8755 admitted the missing links, so the chain completes and these are
		// ordinary recoveries now. If either ever returns to `chain-incomplete`,
		// a link was removed from the chain and the interface is silently
		// running with no filter again.
		{"inet filter", "", ifUnit("   family inet {\n    filter { input f4probe; }\n   }"), ifUnit("   family inet filter input f4probe;"), ifUnit("   family inet {\n   }"), recover8763},
		{"inet6 filter", "", ifUnit("   family inet6 {\n    filter { input f6probe; }\n   }"), ifUnit("   family inet6 filter input f6probe;"), ifUnit("   family inet6 {\n   }"), recover8763},
		// #8755: the four links that complete the interface-unit chains. Each is
		// measured HERE at the compoundKey shape as well as in
		// interface_unit_chain_8755_test.go, which measures the whole statement;
		// these rows measure the pair in the same table as its siblings so the
		// population cell below stays exhaustive.
		{"filter input", "", ifUnit("   family inet {\n    filter { input f4probe; }\n   }"), ifUnit("   family inet {\n    filter input f4probe;\n   }"), ifUnit("   family inet {\n    filter { }\n   }"), recover8763},
		{"filter output", "", ifUnit("   family inet {\n    filter { output f4probe; }\n   }"), ifUnit("   family inet {\n    filter output f4probe;\n   }"), ifUnit("   family inet {\n    filter { }\n   }"), recover8763},
		{"inet address", "", ifUnit("   family inet {\n    address 10.9.9.1/24;\n   }"), ifUnit("   family inet address 10.9.9.1/24;"), ifUnit("   family inet {\n   }"), recover8763},
		{"inet6 address", "", ifUnit("   family inet6 {\n    address 2001:db8::1/64;\n   }"), ifUnit("   family inet6 address 2001:db8::1/64;"), ifUnit("   family inet6 {\n   }"), recover8763},
		// Refused in both spellings by a live gate, so nothing the fold does can
		// change the outcome. These two are also REMOVED from the scope list by
		// this change -- see the note in compact_normalize_8662.go.
		{"vrrp-group authentication-key", "", vrrp("{ authentication-key \"s3cr3t\"; }"), vrrp("authentication-key \"s3cr3t\";"), vrrp("{ }"), gated8763},
		{"vrrp-group authentication-type", "", vrrp("{ authentication-type md5; }"), vrrp("authentication-type md5;"), vrrp("{ }"), gated8763},
		// Nothing reads it in ANY spelling: braced compiles the same as absent,
		// and `packet-based` compiles the same as `flow-based`. Pre-existing and
		// untouched by the traversal; recorded so it is not mistaken for one.
		{"inet6 mode", "", "forwarding-options {\n family inet6 {\n  mode packet-based;\n }\n}\n", "forwarding-options {\n family inet6 mode packet-based;\n}\n", "forwarding-options {\n family inet6 {\n }\n}\n", readerBug},
	}
}

// The compoundKey descent hands the DEEPER schema to the statement splitter as
// well as to the recursion, and that argument is currently unobservable in
// production: `packedStatements` is opt-in and no container reachable below a
// `family` sets it, so passing the shallow schema instead changes nothing and
// the mutation survives. A surviving mutation means an untested line, and the
// answer is not to delete a correct line -- it is to build the input that
// distinguishes them.
//
// This calls the pass directly against a synthetic schema where the compound
// SUB-key opts in and the compound keyword does not. With the deeper schema the
// packed run splits into one child per statement; with the shallow one it stays
// a single child. Nothing here touches setSchema.
func TestCompoundDescentGivesTheSplitterTheDeeperSchema8763(t *testing.T) {
	leafArg := func() *schemaNode { return &schemaNode{args: 1} }
	inet := &schemaNode{
		packedStatements: true,
		children: map[string]*schemaNode{
			"alpha": leafArg(),
			"beta":  leafArg(),
		},
	}
	schema := &schemaNode{children: map[string]*schemaNode{
		"family": {compoundKey: true, children: map[string]*schemaNode{"inet": inet}},
	}}
	node := &Node{Keys: []string{"family", "inet", "alpha", "1", "beta", "2"}, IsLeaf: true}
	folds := normalizeCompactNodes([]*Node{node}, schema, func(kw, head string) bool {
		return kw == "inet" && head == "alpha"
	})
	if folds != 1 {
		t.Fatalf("expected exactly one fold, got %d -- the compound descent did not reach the sub-key", folds)
	}
	if got, want := node.Keys, []string{"family", "inet"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("node identity = %v, want %v", got, want)
	}
	if len(node.Children) != 2 {
		var spelled [][]string
		for _, ch := range node.Children {
			spelled = append(spelled, ch.Keys)
		}
		t.Fatalf("the packed run became %d child(ren) %v, want 2 -- the splitter was given the "+
			"schema for the COMPOUND KEYWORD (which does not opt into packedStatements) rather "+
			"than for the SUB-KEY (which does), so the whole tail collapsed into one statement "+
			"(#8763/#8768)", len(node.Children), spelled)
	}
	if node.Children[0].Keys[0] != "alpha" || node.Children[1].Keys[0] != "beta" {
		t.Fatalf("split produced %v / %v, want alpha… / beta…", node.Children[0].Keys, node.Children[1].Keys)
	}
}
