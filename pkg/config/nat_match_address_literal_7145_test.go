package config

import (
	"reflect"
	"strings"
	"testing"
)

// #7145: a malformed CIDR in a NAT rule's `match source-address` committed
// clean on ALL THREE NAT kinds — and on the source rule-set's `match
// destination-address` too — while `match destination-address` on the
// destination and static rule-sets REJECTED the identical value.
//
// MEASURED AT bf10c6b7c, over the base config below, with `999.1.1.1/24` (and
// `zznotanaddr`, so this is not a near-miss in the CIDR grammar):
//
//	kind         leaf                  master     here
//	source       source-address        ACCEPTED   rejected   <- #7145
//	source       destination-address   ACCEPTED   rejected   <- #7145
//	destination  source-address        ACCEPTED   rejected   <- #7145
//	destination  destination-address   rejected   rejected   (#3228, untouched)
//	static       source-address        ACCEPTED   rejected   <- #7145
//	static       destination-address   rejected   rejected   (#3206, untouched)
//
// The four ACCEPTED slots are what validateNATMatchAddressLiteralsStrict
// closes. The two already-rejecting slots keep their own gates and are asserted
// here as CONTROLS — they are in the table so a regression that silently
// removed one of the OLD gates fails here too, and so the table is a complete
// (kind x leaf) census rather than a list of the ones this change touched.
//
// The accept was not inert. These values reach the wire VERBATIM (the Go
// snapshot builders copy the list unfiltered) and each Rust consumer drops an
// entry it cannot parse while keeping the rule CONSTRAINED — so a malformed
// entry silently NARROWS the rule and an all-malformed list makes it match
// NOTHING, recorded only as a bounded NAT parse-error counter (#4718).
//
// Per CLAUDE.md every flat-set case is built with ParseSetCommand + SetPath,
// never NewParser (which merges all set lines into one node).

// nat7145Base is the two-interface / two-zone config the issue reproduces over;
// it commits clean on its own.
var nat7145Base = []string{
	"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
	"set interfaces ge-0/0/1 unit 0 family inet address 10.0.2.1/24",
	"set security zones security-zone trust interfaces ge-0/0/0.0",
	"set security zones security-zone untrust interfaces ge-0/0/1.0",
}

// nat7145Kind describes one NAT kind's complete rule-set scaffolding plus the
// `set ... match ` prefix that addresses its single rule.
type nat7145Kind struct {
	name     string // "source" | "destination" | "static"
	ruleSet  string
	scaffold []string
	// sibling is the OTHER match leaf's valid value, needed because a static /
	// destination rule with no destination-address at all is out of scope for
	// the gates that already exist (they skip a rule with no match) — without
	// it the source-address cases would not be comparable to the base config.
	sibling map[string][]string
}

func nat7145Kinds() []nat7145Kind {
	return []nat7145Kind{
		{
			name:    "source",
			ruleSet: "RS",
			scaffold: []string{
				"set security nat source rule-set RS from zone trust",
				"set security nat source rule-set RS to zone untrust",
				"set security nat source rule-set RS rule R1 then source-nat interface",
			},
		},
		{
			name:    "destination",
			ruleSet: "RD",
			scaffold: []string{
				"set security nat destination pool P1 address 10.0.2.5/32",
				"set security nat destination rule-set RD from zone trust",
				"set security nat destination rule-set RD rule R1 then destination-nat pool P1",
			},
			sibling: map[string][]string{
				"source-address": {"set security nat destination rule-set RD rule R1 match destination-address 203.0.113.1/32"},
			},
		},
		{
			name:    "static",
			ruleSet: "RT",
			scaffold: []string{
				"set security nat static rule-set RT from zone trust",
				"set security nat static rule-set RT rule R1 then static-nat prefix 10.0.1.5/32",
			},
			sibling: map[string][]string{
				"source-address": {"set security nat static rule-set RT rule R1 match destination-address 203.0.113.1/32"},
			},
		},
	}
}

// nat7145Cmds builds the full flat-set corpus for one (kind, leaf, values) cell.
func nat7145Cmds(k nat7145Kind, leaf string, values ...string) []string {
	cmds := append([]string{}, nat7145Base...)
	cmds = append(cmds, k.scaffold...)
	cmds = append(cmds, k.sibling[leaf]...)
	set := "set security nat " + k.name + " rule-set " + k.ruleSet + " rule R1 match " + leaf
	for _, v := range values {
		cmds = append(cmds, set+" "+v)
	}
	return cmds
}

func nat7145Tree(t *testing.T, cmds []string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		p, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

// nat7145MatchList returns the compiled match list for one (kind, leaf) cell,
// so a test can assert what the tolerant path actually LOWERED rather than
// asserting only that it did not error.
func nat7145MatchList(t *testing.T, cfg *Config, kind, leaf string) []string {
	t.Helper()
	switch kind {
	case "source":
		if len(cfg.Security.NAT.Source) == 0 || len(cfg.Security.NAT.Source[0].Rules) == 0 {
			t.Fatalf("source-NAT rule missing from the compiled config: %+v", cfg.Security.NAT.Source)
		}
		m := cfg.Security.NAT.Source[0].Rules[0].Match
		if leaf == "destination-address" {
			return m.DestinationAddresses
		}
		return m.SourceAddresses
	case "destination":
		if cfg.Security.NAT.Destination == nil || len(cfg.Security.NAT.Destination.RuleSets) == 0 ||
			len(cfg.Security.NAT.Destination.RuleSets[0].Rules) == 0 {
			t.Fatalf("destination-NAT rule missing from the compiled config: %+v", cfg.Security.NAT.Destination)
		}
		m := cfg.Security.NAT.Destination.RuleSets[0].Rules[0].Match
		if leaf == "destination-address" {
			return m.DestinationAddresses
		}
		return m.SourceAddresses
	case "static":
		if len(cfg.Security.NAT.Static) == 0 || len(cfg.Security.NAT.Static[0].Rules) == 0 {
			t.Fatalf("static-NAT rule missing from the compiled config: %+v", cfg.Security.NAT.Static)
		}
		r := cfg.Security.NAT.Static[0].Rules[0]
		if leaf == "destination-address" {
			return r.MatchAddresses
		}
		return r.SourceAddresses
	}
	t.Fatalf("unknown NAT kind %q", kind)
	return nil
}

// TestNATMatchAddressLiteral7145StrictRejectsEverySlot is the ASYMMETRY guard:
// the same malformed value must be refused in every (NAT kind x match leaf)
// slot, and the rejection must NAME the offending value, the rule-set, and the
// rule so the operator can find it.
//
// It is a full 3x2 census on purpose. Two of the six cells are the pre-existing
// #3228 / #3206 gates; the other four are #7145. Reading the table is how you
// see that the six now agree — a test that only covered the four would leave
// "they agree" unbound.
//
// RED-on-revert (the four #7145 cells): drop the
// validateNATMatchAddressLiteralsStrict call from runUniformGatesNAT, or make
// natMatchPrefixParses return true unconditionally, and this fails at
// "committed CLEAN".
func TestNATMatchAddressLiteral7145StrictRejectsEverySlot(t *testing.T) {
	for _, bad := range []string{"999.1.1.1/24", "zznotanaddr"} {
		for _, k := range nat7145Kinds() {
			for _, leaf := range []string{"source-address", "destination-address"} {
				t.Run(bad+"/"+k.name+"/"+leaf, func(t *testing.T) {
					tree := nat7145Tree(t, nat7145Cmds(k, leaf, bad))
					_, err := CompileConfig(tree)
					if err == nil {
						t.Fatalf("`security nat %s rule-set %s rule R1 match %s %s` committed CLEAN. "+
							"The value reaches the dataplane verbatim, which cannot parse it and drops "+
							"it from the match set while leaving the rule CONSTRAINED — so the rule "+
							"silently narrows, and with this as its only value it matches NOTHING and "+
							"stops translating, visible only as a NAT parse-error counter (#7145)",
							k.name, k.ruleSet, leaf, bad)
					}
					msg := err.Error()
					if !strings.Contains(msg, bad) {
						t.Errorf("the rejection must NAME the offending value %q so the operator can "+
							"find it in a long rule-set; got: %v", bad, msg)
					}
					if !strings.Contains(msg, k.ruleSet) || !strings.Contains(msg, "R1") {
						t.Errorf("the rejection must name the rule-set (%q) and rule (\"R1\"); got: %v",
							k.ruleSet, msg)
					}
					if !strings.Contains(msg, leaf) {
						t.Errorf("the rejection must name the match leaf (%q) — the whole point of "+
							"#7145 is that the two leaves of one rule disagreed, so a message that "+
							"does not say WHICH leaf leaves the operator where they started; got: %v",
							leaf, msg)
					}
				})
			}
		}
	}
}

// TestNATMatchAddressLiteral7145LenientWarnsAndKeeps is the #1960 no-brick half
// at the compiler: the tolerant path must WARN, not fail — and it must KEEP the
// malformed value in the lowered list.
//
// KEEPING IT IS LOAD-BEARING, not laziness. The Rust `*_constrained` flag is
// keyed on the snapshot list being NON-EMPTY, not on how many entries parsed
// (source.rs `source_constrained = !snap.source_addresses.is_empty()`,
// destination.rs, static_nat.rs `SourceConstraint::from_list`). Dropping an
// all-malformed list Go-side would clear that flag and collapse the rule to
// MATCH-ANY — converting a fail-CLOSED silent break into a fail-OPEN one, which
// is strictly worse than the bug this change fixes. So the tolerant path warns,
// keeps the value, and lets the dataplane drop it.
//
// The good value is asserted intact ALONGSIDE the malformed one, and the
// malformed value is authored SECOND, so the test also pins that the gate walks
// the whole bracket list rather than only slot 0.
//
// RED-on-revert: remove lenientNATMatchAddressLiterals from
// lenientCompileOpts() and this fails at "the tolerant path REJECTED".
func TestNATMatchAddressLiteral7145LenientWarnsAndKeeps(t *testing.T) {
	const bad = "999.1.1.1/24"
	// The four slots #7145 closes. The other two are covered by their own
	// gates' tolerant paths (#3228 / #3206) and word their warnings
	// differently, so asserting this warning text on them would bind the wrong
	// gate.
	for _, tc := range []struct{ kind, leaf, good string }{
		{"source", "source-address", "10.0.0.0/8"},
		{"source", "destination-address", "198.51.100.0/24"},
		{"destination", "source-address", "10.0.0.0/8"},
		{"static", "source-address", "10.0.0.0/8"},
	} {
		t.Run(tc.kind+"/"+tc.leaf, func(t *testing.T) {
			var k nat7145Kind
			for _, cand := range nat7145Kinds() {
				if cand.name == tc.kind {
					k = cand
				}
			}
			tree := nat7145Tree(t, nat7145Cmds(k, tc.leaf, tc.good, bad))

			// Precondition: the SAME corpus is refused by the strict path.
			// Without this the tolerant assertion below could pass simply
			// because the corpus never tripped the gate at all.
			if _, err := CompileConfig(tree); err == nil {
				t.Fatalf("precondition: the strict path must REJECT this corpus, else the "+
					"tolerant assertion is vacuous (kind=%s leaf=%s)", tc.kind, tc.leaf)
			}

			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("the tolerant path REJECTED a config carrying a malformed NAT match "+
					"prefix. A config an older binary committed must still BOOT and still "+
					"FORWARD (#1960): a compile failure on Store.Load leaves ActiveConfig() nil, "+
					"which forces the daemon into the bootstrap/lifeline state — a worse outage "+
					"than the narrowed NAT rule it complains about: %v", err)
			}
			if cfg == nil {
				t.Fatal("the tolerant path returned a nil config; a silent nil is the same brick " +
					"as an error")
			}

			var warn string
			for _, w := range cfg.Warnings {
				if strings.Contains(w, bad) && strings.Contains(w, tc.leaf) {
					warn = w
					break
				}
			}
			if warn == "" {
				t.Fatalf("the tolerant path must WARN, naming the value and the leaf — a silent "+
					"tolerate is the pre-#7145 behaviour, which is exactly the defect. warnings: %v",
					cfg.Warnings)
			}
			if !strings.Contains(warn, k.ruleSet) || !strings.Contains(warn, "R1") {
				t.Errorf("the warning must name the rule-set (%q) and rule (\"R1\"); got: %s",
					k.ruleSet, warn)
			}

			got := nat7145MatchList(t, cfg, tc.kind, tc.leaf)
			want := []string{tc.good, bad}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("tolerant-path match list = %q, want %q. The GOOD value must survive "+
					"(a tolerant load that lost it would silently widen or break the rule), and "+
					"the MALFORMED value must survive too: the Rust *_constrained flag is keyed "+
					"on this list being non-empty, so dropping it here would collapse an "+
					"all-malformed rule to MATCH-ANY — a fail-OPEN regression worse than #7145",
					got, want)
			}
		})
	}
}

// TestNATMatchAddressLiteral7145AcceptsValidPrefixes is the OVER-REJECTION
// guard, and it is the half that makes the widening safe to ship: a widened
// validator that rejects a value the dataplane happily installs bricks the next
// commit on a working box (#1960).
//
// Every value here is one the Rust parsers accept, so every one must still
// commit on every slot:
//
//   - `0.0.0.0/0` / `::/0` — the match-any spelling that ships in
//     docs/ha-cluster-userspace.conf and test/incus/xpf-cluster-fw0.conf today.
//   - a bare host IP — `IpAddr::from_str` promotes it to /32 / /128.
//   - a CIDR with host bits set — `IpNet::from_str` permits them.
//   - `1.2.3.4/024` — a ZERO-PADDED prefix length. Rust's `u8::from_str`
//     reads "024" as 24 and installs the prefix, and Go's net.ParseCIDR agrees;
//     netip.ParsePrefix does NOT (it rejects the padding), which is precisely
//     why natMatchPrefixParses is built on net.ParseCIDR. Swap it to the netip
//     form and this cell goes RED — that is the point of the cell.
//
// The static `match destination-address` slot is excluded per value, not
// wholesale: static NAT requires a HOST route there (#3206 / #3031), so `/0`,
// `/24` and `/024` are legitimately rejected by that older gate for a reason
// that has nothing to do with #7145.
func TestNATMatchAddressLiteral7145AcceptsValidPrefixes(t *testing.T) {
	for _, good := range []string{"0.0.0.0/0", "10.0.0.0/8", "192.0.2.5", "192.0.2.5/32", "1.2.3.4/024", "2001:db8::/32", "2001:db8::1"} {
		for _, k := range nat7145Kinds() {
			for _, leaf := range []string{"source-address", "destination-address"} {
				if k.name == "static" && leaf == "destination-address" {
					// Host-route-only slot; governed by #3206 / #3031, not #7145.
					continue
				}
				if k.name == "static" && strings.HasPrefix(good, "2001:db8:") {
					// A v6 source-address against a v4 `then static-nat prefix`
					// is a family mismatch the static gates reject for their
					// own reasons.
					continue
				}
				t.Run(good+"/"+k.name+"/"+leaf, func(t *testing.T) {
					tree := nat7145Tree(t, nat7145Cmds(k, leaf, good))
					if _, err := CompileConfig(tree); err != nil {
						t.Fatalf("`match %s %s` on %s NAT was REJECTED, but the dataplane parses "+
							"and installs it. A widened validator that refuses a working value "+
							"bricks the operator's next commit on a box that was forwarding "+
							"correctly (#1960): %v", leaf, good, k.name, err)
					}
				})
			}
		}
	}
}
