package config

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

// #9235 — the #8939 residue: 18 flat-run losses on the LENIENT path only.
//
// NAMING THE CHANNEL IS THE FINDING HERE, NOT A CAVEAT ON IT. At these twelve
// containers the typed schema walk REFUSES the packed spelling, so an operator
// cannot type it into a running box and `configstore.CheckText` rejects it. The
// loss is reachable only through `config.CompileConfigLenient` — `Store.Load`
// (boot from the persisted DB) and `Store.SyncApply` (HA config sync), which
// downgrade the same gate to a `slog.Warn` for the #1960 no-brick doctrine.
//
// `config.CompileConfig` does not lose these values either, because the strict
// pipeline never receives the tree: the schema gate ran first and refused it. A
// claim about this fix that does not name `CompileConfigLenient` is not a
// measurement of it.

func tree9235(t *testing.T, lines ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, l := range lines {
		p, err := ParseSetCommand(l)
		if err != nil {
			t.Fatalf("parse %q: %v", l, err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("setpath %q: %v", l, err)
		}
	}
	return tree
}

func compileLenient9235(t *testing.T, lines ...string) *Config {
	t.Helper()
	c, err := CompileConfigLenient(tree9235(t, lines...))
	if err != nil {
		t.Fatalf("CompileConfigLenient(%v): %v", lines, err)
	}
	if c == nil {
		t.Fatalf("CompileConfigLenient(%v): nil config", lines)
	}
	c.Warnings = nil
	return c
}

// flatRunResidueRow9235 is one census row: the container, the packed one-line
// spelling, and the per-leaf spelling it must compile identically to.
type flatRunResidueRow9235 struct {
	name   string
	packed string
	split  []string
	// operatorReachable is MEASURED, not assumed, and two rows falsify the
	// issue's premise. See TestFlatRunResidueChannelIsMeasuredPerRow9235.
	operatorReachable bool
}

func flatRunResidueRows9235() []flatRunResidueRow9235 {
	return []flatRunResidueRow9235{
		{
			name:   "firewall policer if-exceeding",
			packed: "set firewall policer p1 if-exceeding bandwidth-limit 1m burst-size-limit 15k",
			split: []string{
				"set firewall policer p1 if-exceeding bandwidth-limit 1m",
				"set firewall policer p1 if-exceeding burst-size-limit 15k",
			},
		},
		{
			name:   "router-advertisement prefix flags",
			packed: "set protocols router-advertisement interface ge-0/0/0.0 prefix 2001:db8::/64 no-autonomous no-onlink",
			split: []string{
				"set protocols router-advertisement interface ge-0/0/0.0 prefix 2001:db8::/64 no-autonomous",
				"set protocols router-advertisement interface ge-0/0/0.0 prefix 2001:db8::/64 no-onlink",
			},
			// MEASURED operator-reachable; the #8939 census scored it
			// lenient-only because its synthetic `prefix arg1` fails the typed
			// key validator.
			operatorReachable: true,
		},
		{
			name:   "static route qualified-next-hop",
			packed: "set routing-options static route 10.9.0.0/16 qualified-next-hop 10.0.0.2 interface ge-0/0/1.0 metric 7",
			split: []string{
				"set routing-options static route 10.9.0.0/16 qualified-next-hop 10.0.0.2 interface ge-0/0/1.0",
				"set routing-options static route 10.9.0.0/16 qualified-next-hop 10.0.0.2 metric 7",
			},
			// MEASURED operator-reachable, same census artefact as the row above
			// (`route arg1` is not a valid prefix).
			operatorReachable: true,
		},
		{
			name:   "schedulers scheduler window",
			packed: "set schedulers scheduler s1 start-date 2026-01-01 start-time 08:00:00 stop-date 2026-12-31",
			split: []string{
				"set schedulers scheduler s1 start-date 2026-01-01",
				"set schedulers scheduler s1 start-time 08:00:00",
				"set schedulers scheduler s1 stop-date 2026-12-31",
			},
		},
		{
			name:   "security flow aging",
			packed: "set security flow aging early-ageout 10 high-watermark 80 low-watermark 60",
			split: []string{
				"set security flow aging early-ageout 10",
				"set security flow aging high-watermark 80",
				"set security flow aging low-watermark 60",
			},
		},
		{
			name:   "security log top-level",
			packed: "set security log format sd-syslog mode event source-interface fxp0",
			split: []string{
				"set security log format sd-syslog",
				"set security log mode event",
				"set security log source-interface fxp0",
			},
		},
		{
			name:   "nat source pool persistent-nat",
			packed: "set security nat source pool pl1 persistent-nat inactivity-timeout 600 permit any-remote-host",
			split: []string{
				"set security nat source pool pl1 persistent-nat inactivity-timeout 600",
				"set security nat source pool pl1 persistent-nat permit any-remote-host",
			},
		},
		{
			name:   "flow-monitoring version-ipfix template",
			packed: "set services flow-monitoring version-ipfix template t1 flow-active-timeout 60 flow-inactive-timeout 15",
			split: []string{
				"set services flow-monitoring version-ipfix template t1 flow-active-timeout 60",
				"set services flow-monitoring version-ipfix template t1 flow-inactive-timeout 15",
			},
		},
		{
			name:   "flow-monitoring version9 template",
			packed: "set services flow-monitoring version9 template t1 flow-active-timeout 60 flow-inactive-timeout 15",
			split: []string{
				"set services flow-monitoring version9 template t1 flow-active-timeout 60",
				"set services flow-monitoring version9 template t1 flow-inactive-timeout 15",
			},
		},
		{
			name:   "system dataplane coalescence",
			packed: "set system dataplane coalescence adaptive disable rx-usecs 8 tx-usecs 8",
			split: []string{
				"set system dataplane coalescence adaptive disable",
				"set system dataplane coalescence rx-usecs 8",
				"set system dataplane coalescence tx-usecs 8",
			},
		},
		{
			name:   "dhcp-local-server static-binding",
			packed: "set system services dhcp-local-server group g1 pool p1 static-binding 00:11:22:33:44:55 fixed-address 10.0.0.50 host-name host50",
			split: []string{
				"set system services dhcp-local-server group g1 pool p1 static-binding 00:11:22:33:44:55 fixed-address 10.0.0.50",
				"set system services dhcp-local-server group g1 pool p1 static-binding 00:11:22:33:44:55 host-name host50",
			},
		},
		{
			name:   "system services ssh",
			packed: "set system services ssh client-alive-count-max 3 client-alive-interval 30 connection-limit 10",
			split: []string{
				"set system services ssh client-alive-count-max 3",
				"set system services ssh client-alive-interval 30",
				"set system services ssh connection-limit 10",
			},
		},
	}
}

// TestFlatRunResidueCompilesIdentically9235 is the fix.
//
// CHANNEL: config.CompileConfigLenient, the only channel on which these rows
// lose anything.
//
// THE VACUITY CONTROL IS THE ROW THAT MAKES THE EQUALITY MEAN SOMETHING. "packed
// == split" is satisfied by two compiles that both produced nothing, which is
// exactly the shape the #8939 census had to add two controls for. So each row
// also asserts the SPLIT compile differs from the EMPTY compile: if it does not,
// the leaves are unobservable in the typed config and the equality is about the
// fixture, not about walking the chain.
func TestFlatRunResidueCompilesIdentically9235(t *testing.T) {
	empty := compileLenient9235(t)
	for _, row := range flatRunResidueRows9235() {
		t.Run(row.name, func(t *testing.T) {
			split := compileLenient9235(t, row.split...)
			// VACUITY CONTROL: the per-leaf spelling must actually land in the
			// typed config, or "identical" proves nothing.
			if reflect.DeepEqual(split, empty) {
				t.Fatalf("VACUOUS: the per-leaf spelling compiles to the EMPTY config, so "+
					"comparing it against the packed spelling measures nothing.\nlines: %v",
					row.split)
			}
			packed := compileLenient9235(t, row.packed)
			if !reflect.DeepEqual(packed, split) {
				t.Errorf("#9235: the PACKED spelling does not compile to the same config as "+
					"the per-leaf spelling, so a value the operator wrote was dropped.\n"+
					"packed: %s\nsplit : %v\n\nThis is the lenient channel "+
					"(CompileConfigLenient = Store.Load / Store.SyncApply). The schema gate "+
					"refuses the packed spelling at commit, so no operator can type it — "+
					"which is why the loss is silent: a slog.Warn on a booting firewall.",
					row.packed, row.split)
			}
		})
	}
}

// TestFlatRunResidueSharpestLossesAreNamed9235 spells out three of the losses as
// FIELD assertions rather than a config-equality check.
//
// The equality test above is the complete instrument; this one exists because an
// equality failure does not tell a reader WHAT was lost, and for these three the
// answer is the reason the issue is not cosmetic: a session-aging control that
// reverts to disabled, a scheduler window that falls OPEN when empty, and a
// floating backup whose metric orders failover.
func TestFlatRunResidueSharpestLossesAreNamed9235(t *testing.T) {
	t.Run("flow aging keeps BOTH watermarks", func(t *testing.T) {
		c := compileLenient9235(t,
			"set security flow aging early-ageout 10 high-watermark 80 low-watermark 60")
		got := [3]int{c.Security.Flow.AgingEarlyAgeout, c.Security.Flow.AgingHighWatermark,
			c.Security.Flow.AgingLowWatermark}
		if got != [3]int{10, 80, 60} {
			t.Errorf("#9235: aging = early=%d high=%d low=%d, want 10/80/60. A zero watermark "+
				"is DISABLED, so aggressive aging the operator configured never ran.",
				got[0], got[1], got[2])
		}
	})
	t.Run("scheduler keeps its whole window", func(t *testing.T) {
		c := compileLenient9235(t,
			"set schedulers scheduler s1 start-date 2026-01-01 start-time 08:00:00 stop-date 2026-12-31")
		s := c.Schedulers["s1"]
		if s == nil {
			t.Fatal("no scheduler s1")
		}
		if s.StartDate == "" || s.StartTime == "" || s.StopDate == "" {
			t.Errorf("#9235: scheduler s1 = start-date %q start-time %q stop-date %q; an "+
				"EMPTY window makes isWithinWindow fall OPEN (#3849), so a scheduled policy "+
				"that should have been inactive enforces around the clock.",
				s.StartDate, s.StartTime, s.StopDate)
		}
	})
	t.Run("qualified-next-hop keeps its metric", func(t *testing.T) {
		c := compileLenient9235(t,
			"set routing-options static route 10.9.0.0/16 qualified-next-hop 10.0.0.2 interface ge-0/0/1.0 metric 7")
		var found bool
		for _, r := range c.RoutingOptions.StaticRoutes {
			for _, nh := range r.NextHops {
				if nh.Address == "10.0.0.2" {
					found = true
					if !nh.HasMetric || nh.Metric != 7 || nh.Interface != "ge-0/0/1.0" {
						t.Errorf("#9235: qualified-next-hop = interface %q metric %d (set %v), "+
							"want ge-0/0/1.0 / 7. The per-next-hop METRIC is what orders two "+
							"equal-preference floating backups, so losing it silently reorders "+
							"failover.", nh.Interface, nh.Metric, nh.HasMetric)
					}
				}
			}
		}
		if !found {
			t.Fatal("POSITIVE CONTROL: the qualified-next-hop was not compiled at all")
		}
	})
}

// TestFlatRunResidueChannelIsMeasuredPerRow9235 pins the CHANNEL per row, and
// its load-bearing row is the one that must still be ACCEPTED.
//
// THE ISSUE'S PREMISE IS PARTLY FALSE, AND MEASURING IT IS WHY. #9235 says all
// eighteen rows are `lenient-only` — "a fidelity question, not a security one".
// Measured here with REAL instance names, ten are; TWO ARE OPERATOR-REACHABLE:
//
//	protocols router-advertisement interface <if> prefix <p>  no-autonomous no-onlink
//	routing-options static route <r> qualified-next-hop <gw>  interface <if> metric <m>
//
// Both commit CLEAN through `configstore.CheckText` and then enforce less than
// they say, which is the more severe #9088 class, not a fidelity question.
//
// THE CENSUS MISLABELLED THEM, AND THE MECHANISM IS THE ONE #9265 NAMES. The
// #8939 census synthesises the instance name as the literal token `arg1`, so the
// fixture it hands the gate is
// `… interface arg1 prefix arg1 autonomous no-autonomous`. `arg1` is not a valid
// IPv6 prefix, so the typed KEY validator rejects the fixture — and
// `flatSetAdmittedAnyOrder` reads any rejection as "the packed spelling is
// refused", i.e. lenient-only. The row scored rejected because its NAME was
// invalid, not because its BODY was checked. That is exactly the `xpfarg` hazard
// #9265 warns a census owes a control for, observed here on a shipped column
// rather than predicted.
//
// So the channel is recorded PER ROW and asserted in BOTH directions: a row that
// silently became operator-reachable is a severity increase nobody would see, and
// a row that silently became unreachable would mean a gate tightened and this
// fix's justification moved.
//
// AND THE ROW THAT MATTERS MOST IS NEITHER OF THOSE. "The packed spelling is
// refused" is satisfiable by refusing EVERYTHING, which would make these twelve
// containers unconfigurable — a worse defect than the truncation being fixed, and
// the #4191 over-rejection class. So every row first asserts the PER-LEAF
// spelling is ACCEPTED.
func TestFlatRunResidueChannelIsMeasuredPerRow9235(t *testing.T) {
	for _, row := range flatRunResidueRows9235() {
		t.Run(row.name, func(t *testing.T) {
			// THE LOAD-BEARING ROW: the supported spelling must still commit.
			ok := tree9235(t, row.split...)
			if err := SchemaValidateWithDefinitions(ok, ok, nil); err != nil {
				t.Fatalf("#9235 OVER-REJECTION: the per-leaf spelling — the one the operator "+
					"is supposed to type — is REFUSED by the schema gate: %v\nlines: %v\n"+
					"\"The packed spelling is rejected\" is satisfiable by rejecting "+
					"everything, which is the #4191 class and worse than the loss being "+
					"fixed.", err, row.split)
			}
			packed := tree9235(t, row.packed)
			accepted := SchemaValidateWithDefinitions(packed, packed, nil) == nil
			if accepted == row.operatorReachable {
				return
			}
			if accepted {
				t.Errorf("#9235 CHANNEL CHANGED: the schema gate now ACCEPTS %q, so this row "+
					"is OPERATOR-REACHABLE and is no longer lenient-only. That is a SEVERITY "+
					"INCREASE — it commits clean through configstore.CheckText and enforces "+
					"less than it says (#9088) — and it must be recorded as such, not "+
					"absorbed.", row.packed)
				return
			}
			t.Errorf("#9235 CHANNEL CHANGED: the schema gate now REJECTS %q, which this table "+
				"recorded as OPERATOR-REACHABLE. A gate tightened, so this row's severity "+
				"dropped and the justification for it moved — re-measure before editing the "+
				"expectation.", row.packed)
		})
	}
}

// TestFlatRunResidueSchemasResolve9235 is the instrument control.
//
// Every fix in this change is gated on a resolver returning non-nil: a nil
// container makes expandRun9235 a no-op, which turns the whole fix off
// SILENTLY. A schema rename would do it, and the behavioural tests above would
// be the only thing to notice — so the resolvers are asserted directly, with the
// children each one must declare, which is what distinguishes "resolved" from
// "resolved to the wrong node".
func TestFlatRunResidueSchemasResolve9235(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  *schemaNode
		want []string
	}{
		{"policer if-exceeding", policerIfExceedingSchema9235(), []string{"bandwidth-limit", "burst-size-limit"}},
		// M3 (#9882): the policer `then` resolvers drive hoistAndSplitRun8939
		// at both then-readers — without these rows a nil resolver would
		// silently disable the one-line-run expansion.
		{"policer then", policerThenSchema9882(), []string{"discard", "forwarding-class", "loss-priority"}},
		{"three-color-policer then", threeColorPolicerThenSchema9882(), []string{"discard", "forwarding-class", "loss-priority"}},
		{"ra prefix", raPrefixSchema9235(), []string{"autonomous", "no-autonomous", "no-onlink", "on-link"}},
		{"static qualified-next-hop", staticQualifiedNextHopSchema9235(), []string{"interface", "metric", "preference"}},
		{"scheduler", schedulerSchema9235(), []string{"start-date", "start-time", "stop-date"}},
		{"flow aging", flowAgingSchema9235(), []string{"early-ageout", "high-watermark", "low-watermark"}},
		{"security log", securityLogSchema9235(), []string{"format", "mode", "source-interface"}},
		{"persistent-nat", persistentNATSchema9235(), []string{"inactivity-timeout", "permit"}},
		{"ipfix template", ipfixTemplateSchema9235(), []string{"flow-active-timeout", "flow-inactive-timeout"}},
		{"version9 template", version9TemplateSchema9235(), []string{"flow-active-timeout", "flow-inactive-timeout"}},
		{"dataplane coalescence", dataplaneCoalescenceSchema9235(), []string{"adaptive", "rx-usecs", "tx-usecs"}},
		{"dhcp static-binding", dhcpStaticBindingSchema9235(), []string{"fixed-address", "host-name"}},
		{"system services ssh", systemServicesSSHSchema9235(), []string{"client-alive-count-max", "client-alive-interval", "connection-limit"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got == nil {
				t.Fatalf("#9235: the resolver returned nil, which makes expandRun9235 a no-op "+
					"and turns the %s fix off silently", tc.name)
			}
			var missing []string
			for _, w := range tc.want {
				if resolveSchemaChild(tc.got, w) == nil {
					missing = append(missing, w)
				}
			}
			if len(missing) > 0 {
				var have []string
				for k := range tc.got.children {
					have = append(have, k)
				}
				sort.Strings(have)
				t.Errorf("#9235: the resolver landed on a node that does not declare %v "+
					"(it declares %v) — it resolved to the WRONG container, which is not the "+
					"same failure as resolving to none", missing, have)
			}
		})
	}
}

// TestFlatRunResidueCompileDoesNotTouchTheAuthoredTree9235 pins the property, and
// its honest statement is about a CONJUNCTION of two guards rather than either
// one.
//
// `show configuration` and `show | display set` read the same `*ConfigTree` the
// compiler is handed, so a compiler that rewrote nodes in place would change what
// the operator sees as a side effect of compiling. Nothing else in this file would
// notice: every other assertion here reads the COMPILED config and is blind to
// what the compile did to the tree.
//
// TWO INDEPENDENT MECHANISMS PROVIDE IT, AND THAT TOOK THREE MEASUREMENTS TO
// STATE CORRECTLY — the first two accounts in this comment's history were both
// wrong, in opposite directions:
//
//	mutation                                              verdict
//	expandRun9235 writes in place (clone removed)         SURVIVED
//	compileConfigWithOpts discards cloneForExpansion      SURVIVED
//	BOTH of the above                                     KILLED — the two
//	                                                      expandRun9235 subtests
//
// So `compileConfigWithOpts`'s opening `tree = tree.cloneForExpansion()` (a deep
// copy, before any reader runs) and the clone inside `expandRun9235` cover each
// other exactly, and no single-clause mutation can expose either. That is the
// #8690 mutation-insensitivity shape: a property reached by two paths is
// individually unkillable by construction. It is recorded rather than resolved by
// deleting one of them, because `cloneForExpansion` is the TOTAL guarantee — it
// covers every compiler reader, not only the three that call `expandRun9235` —
// and the local clone is what keeps a future caller outside the compile path
// honest. Neither is redundant to the OTHER's scope; they are redundant only on
// these three fixtures.
//
// The third subtest (`security flow aging`) does not red even under the double
// mutation, and that is correct: it reaches `expandRunChildren9235`, which returns
// a fresh slice and never writes through to the parent node, so it has no
// in-place variant to mutate. It is carried because it is covered by
// `cloneForExpansion` alone, which is the arm a future compiler reader would
// depend on.
//
// The claim this cell originally made — that `expandRun9235`'s clone is what
// protects the authored tree — was false, and it was stated in the helper's doc
// comment too. Both now say what was measured.
func TestFlatRunResidueCompileDoesNotTouchTheAuthoredTree9235(t *testing.T) {
	for _, tc := range []struct {
		name, packed, marker string
	}{
		{
			name:   "security log (expandRun9235 site)",
			packed: "set security log format sd-syslog mode event source-interface fxp0",
			marker: "format sd-syslog mode event source-interface fxp0",
		},
		{
			name:   "system services ssh (expandRun9235 site)",
			packed: "set system services ssh client-alive-count-max 3 client-alive-interval 30 connection-limit 10",
			marker: "client-alive-count-max 3 client-alive-interval 30 connection-limit 10",
		},
		{
			name:   "security flow aging (expandRunChildren9235 site)",
			packed: "set security flow aging early-ageout 10 high-watermark 80 low-watermark 60",
			marker: "early-ageout 10 high-watermark 80 low-watermark 60",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := tree9235(t, tc.packed)
			before := tree.FormatSet()
			// POSITIVE CONTROL: the fixture must actually be the PACKED spelling,
			// or "unchanged" is trivially true of a tree with nothing to expand.
			if !strings.Contains(before, tc.marker) {
				t.Fatalf("POSITIVE CONTROL: the fixture is not the PACKED spelling (%q not in "+
					"the set view):\n%s", tc.marker, before)
			}
			if _, err := CompileConfigLenient(tree); err != nil {
				t.Fatalf("compile: %v", err)
			}
			if after := tree.FormatSet(); after != before {
				t.Errorf("#9235: compiling REWROTE the authored tree:\nbefore %q\nafter  %q\n"+
					"`compileConfigWithOpts` must keep its `tree = tree.cloneForExpansion()` "+
					"deep copy. `show configuration` is the operator's record of what they "+
					"typed, and the renderers read the same object the compiler was handed.",
					before, after)
			}
		})
	}
}
