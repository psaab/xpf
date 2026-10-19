package config

import (
	"reflect"
	"strings"
	"testing"
)

// #15064 (A01-03): packed CoS instance lines inside braced containers
// compile to nothing. `namedInstances` returns the instance sub-node with
// its packed tail still on Keys (`[be priority high]`), while every CoS
// loop in compileClassOfService reads only `inst.node.Children` — so
// scheduler priority/transmit-rate, TCP shaping-rate, scheduler-map
// entries, classifier/rewrite entries, and interface bindings are
// silently dropped on a clean commit while `show configuration` displays
// the line. The braced twin compiles normally.
//
// Each cell compares the braced spelling against the packed spelling
// through the strict compile path and requires identical typed CoS
// state; the braced arm is asserted non-vacuous first so an empty==empty
// comparison cannot pass.

func compileBracedPacked15064(t *testing.T, braced, packed string) (*Config, *Config) {
	t.Helper()
	b := mustCompile8436(t, braced)
	p := mustCompile8436(t, packed)
	return b, p
}

func TestCoSPackedSchedulerPriority15064(t *testing.T) {
	braced := `class-of-service { schedulers { be { priority high; transmit-rate 10m; } } }`
	packed := `class-of-service { schedulers { be priority high transmit-rate 10m; } }`
	b, p := compileBracedPacked15064(t, braced, packed)
	bs := b.ClassOfService.Schedulers["be"]
	if bs == nil || bs.Priority != "high" || bs.TransmitRateBytes == 0 {
		t.Fatalf("braced control did not compile priority/transmit-rate: %+v", bs)
	}
	if !reflect.DeepEqual(b.ClassOfService.Schedulers, p.ClassOfService.Schedulers) {
		t.Errorf("packed scheduler compiles differently than braced:\n braced=%+v\n packed=%+v",
			bs, p.ClassOfService.Schedulers["be"])
	}
}

func TestCoSPackedSchedulerFlags15064(t *testing.T) {
	braced := `class-of-service { schedulers { be { surplus-sharing; } } }`
	packed := `class-of-service { schedulers { be surplus-sharing; } }`
	b, p := compileBracedPacked15064(t, braced, packed)
	if bs := b.ClassOfService.Schedulers["be"]; bs == nil || !bs.SurplusSharing {
		t.Fatalf("braced control did not compile surplus-sharing: %+v", bs)
	}
	if !reflect.DeepEqual(b.ClassOfService.Schedulers, p.ClassOfService.Schedulers) {
		t.Errorf("packed surplus-sharing compiles differently than braced:\n braced=%+v\n packed=%+v",
			b.ClassOfService.Schedulers["be"], p.ClassOfService.Schedulers["be"])
	}
}

func TestCoSPackedTrafficControlProfile15064(t *testing.T) {
	braced := `class-of-service { traffic-control-profiles { TCP { shaping-rate 10m; scheduler-map M; } } }`
	packed := `class-of-service { traffic-control-profiles { TCP shaping-rate 10m scheduler-map M; } }`
	b, p := compileBracedPacked15064(t, braced, packed)
	bt := b.ClassOfService.TrafficControlProfiles["TCP"]
	if bt == nil || bt.ShapingRateBytes == 0 || bt.SchedulerMap != "M" {
		t.Fatalf("braced control did not compile shaping-rate/scheduler-map: %+v", bt)
	}
	if !reflect.DeepEqual(b.ClassOfService.TrafficControlProfiles, p.ClassOfService.TrafficControlProfiles) {
		t.Errorf("packed TCP compiles differently than braced:\n braced=%+v\n packed=%+v",
			bt, p.ClassOfService.TrafficControlProfiles["TCP"])
	}
}

func TestCoSPackedSchedulerMap15064(t *testing.T) {
	braced := `class-of-service { schedulers { S { transmit-rate 10m; } } scheduler-maps { M { forwarding-class best-effort { scheduler S; } } } }`
	packed := `class-of-service { schedulers { S { transmit-rate 10m; } } scheduler-maps { M forwarding-class best-effort scheduler S; } }`
	b, p := compileBracedPacked15064(t, braced, packed)
	bm := b.ClassOfService.SchedulerMaps["M"]
	if bm == nil || bm.Entries["best-effort"] == nil || bm.Entries["best-effort"].Scheduler != "S" {
		t.Fatalf("braced control did not compile scheduler-map entry: %+v", bm)
	}
	if !reflect.DeepEqual(b.ClassOfService.SchedulerMaps, p.ClassOfService.SchedulerMaps) {
		t.Errorf("packed scheduler-map compiles differently than braced:\n braced=%+v\n packed=%+v",
			bm, p.ClassOfService.SchedulerMaps["M"])
	}
}

func TestCoSPackedDSCPClassifier15064(t *testing.T) {
	braced := `class-of-service { classifiers { dscp { C { forwarding-class best-effort { loss-priority low { code-points ef; } } } } } }`
	packed := `class-of-service { classifiers { dscp { C forwarding-class best-effort loss-priority low code-points ef; } } }`
	b, p := compileBracedPacked15064(t, braced, packed)
	bc := b.ClassOfService.DSCPClassifiers["C"]
	if bc == nil || len(bc.Entries) != 1 {
		t.Fatalf("braced control did not compile DSCP classifier entry: %+v", bc)
	}
	if !reflect.DeepEqual(b.ClassOfService.DSCPClassifiers, p.ClassOfService.DSCPClassifiers) {
		t.Errorf("packed DSCP classifier compiles differently than braced:\n braced=%+v\n packed=%+v",
			bc, p.ClassOfService.DSCPClassifiers["C"])
	}
}

func TestCoSPackedIEEE8021Classifier15064(t *testing.T) {
	braced := `class-of-service { classifiers { ieee-802.1 { C { forwarding-class best-effort { loss-priority low { code-points 5; } } } } } }`
	packed := `class-of-service { classifiers { ieee-802.1 { C forwarding-class best-effort loss-priority low code-points 5; } } }`
	b, p := compileBracedPacked15064(t, braced, packed)
	bc := b.ClassOfService.IEEE8021Classifiers["C"]
	if bc == nil || len(bc.Entries) != 1 {
		t.Fatalf("braced control did not compile 802.1 classifier entry: %+v", bc)
	}
	if !reflect.DeepEqual(b.ClassOfService.IEEE8021Classifiers, p.ClassOfService.IEEE8021Classifiers) {
		t.Errorf("packed 802.1 classifier compiles differently than braced:\n braced=%+v\n packed=%+v",
			bc, p.ClassOfService.IEEE8021Classifiers["C"])
	}
}

func TestCoSPackedInetPrecedenceClassifier15064(t *testing.T) {
	braced := `class-of-service { classifiers { inet-precedence { C { forwarding-class best-effort { loss-priority low { code-points 5; } } } } } }`
	packed := `class-of-service { classifiers { inet-precedence { C forwarding-class best-effort loss-priority low code-points 5; } } }`
	b, p := compileBracedPacked15064(t, braced, packed)
	bc := b.ClassOfService.INetPrecedenceClassifierDefs["C"]
	if bc == nil || len(bc.Entries) != 1 {
		t.Fatalf("braced control did not compile inet-precedence classifier entry: %+v", bc)
	}
	if !reflect.DeepEqual(b.ClassOfService.INetPrecedenceClassifierDefs, p.ClassOfService.INetPrecedenceClassifierDefs) {
		t.Errorf("packed inet-precedence classifier compiles differently than braced:\n braced=%+v\n packed=%+v",
			bc, p.ClassOfService.INetPrecedenceClassifierDefs["C"])
	}
}

func TestCoSPackedDSCPRewrite15064(t *testing.T) {
	braced := `class-of-service { rewrite-rules { dscp { R { forwarding-class best-effort { loss-priority low { code-point ef; } } } } } }`
	packed := `class-of-service { rewrite-rules { dscp { R forwarding-class best-effort loss-priority low code-point ef; } } }`
	b, p := compileBracedPacked15064(t, braced, packed)
	br := b.ClassOfService.DSCPRewriteRules["R"]
	if br == nil || len(br.Entries) != 1 {
		t.Fatalf("braced control did not compile DSCP rewrite entry: %+v", br)
	}
	if !reflect.DeepEqual(b.ClassOfService.DSCPRewriteRules, p.ClassOfService.DSCPRewriteRules) {
		t.Errorf("packed DSCP rewrite compiles differently than braced:\n braced=%+v\n packed=%+v",
			br, p.ClassOfService.DSCPRewriteRules["R"])
	}
}

func TestCoSPackedIEEE8021Rewrite15064(t *testing.T) {
	braced := `class-of-service { rewrite-rules { ieee-802.1 { R { forwarding-class best-effort { loss-priority low { code-point 5; } } } } } }`
	packed := `class-of-service { rewrite-rules { ieee-802.1 { R forwarding-class best-effort loss-priority low code-point 5; } } }`
	b, p := compileBracedPacked15064(t, braced, packed)
	br := b.ClassOfService.IEEE8021RewriteRules["R"]
	if br == nil || len(br.Entries) != 1 {
		t.Fatalf("braced control did not compile 802.1 rewrite entry: %+v", br)
	}
	if !reflect.DeepEqual(b.ClassOfService.IEEE8021RewriteRules, p.ClassOfService.IEEE8021RewriteRules) {
		t.Errorf("packed 802.1 rewrite compiles differently than braced:\n braced=%+v\n packed=%+v",
			br, p.ClassOfService.IEEE8021RewriteRules["R"])
	}
}

func TestCoSPackedInetPrecedenceRewrite15064(t *testing.T) {
	braced := `class-of-service { rewrite-rules { inet-precedence { R { forwarding-class best-effort { loss-priority low { code-point 5; } } } } } }`
	packed := `class-of-service { rewrite-rules { inet-precedence { R forwarding-class best-effort loss-priority low code-point 5; } } }`
	b, p := compileBracedPacked15064(t, braced, packed)
	br := b.ClassOfService.INetPrecedenceRewriteRuleDefs["R"]
	if br == nil || len(br.Entries) != 1 {
		t.Fatalf("braced control did not compile inet-precedence rewrite entry: %+v", br)
	}
	if !reflect.DeepEqual(b.ClassOfService.INetPrecedenceRewriteRuleDefs, p.ClassOfService.INetPrecedenceRewriteRuleDefs) {
		t.Errorf("packed inet-precedence rewrite compiles differently than braced:\n braced=%+v\n packed=%+v",
			br, p.ClassOfService.INetPrecedenceRewriteRuleDefs["R"])
	}
}

func TestCoSPackedEXPRewrite15064(t *testing.T) {
	braced := `class-of-service { rewrite-rules { exp { R { forwarding-class best-effort { loss-priority low { code-point 5; } } } } } }`
	packed := `class-of-service { rewrite-rules { exp { R forwarding-class best-effort loss-priority low code-point 5; } } }`
	b, p := compileBracedPacked15064(t, braced, packed)
	br := b.ClassOfService.EXPRewriteRuleDefs["R"]
	if br == nil || len(br.Entries) != 1 {
		t.Fatalf("braced control did not compile EXP rewrite entry: %+v", br)
	}
	if !reflect.DeepEqual(b.ClassOfService.EXPRewriteRuleDefs, p.ClassOfService.EXPRewriteRuleDefs) {
		t.Errorf("packed EXP rewrite compiles differently than braced:\n braced=%+v\n packed=%+v",
			br, p.ClassOfService.EXPRewriteRuleDefs["R"])
	}
}

func TestCoSPackedInterfaceBinding15064(t *testing.T) {
	pre := `schedulers { S { transmit-rate 10m; } } scheduler-maps { M { forwarding-class best-effort { scheduler S; } } } `
	braced := `class-of-service { ` + pre + `interfaces { ge-0/0/0 { scheduler-map M; } } }`
	packed := `class-of-service { ` + pre + `interfaces { ge-0/0/0 scheduler-map M; } }`
	b, p := compileBracedPacked15064(t, braced, packed)
	bi := b.ClassOfService.Interfaces["ge-0/0/0"]
	if bi == nil || bi.Level == nil || bi.Level.SchedulerMap != "M" {
		t.Fatalf("braced control did not compile interface scheduler-map: %+v", bi)
	}
	if !reflect.DeepEqual(b.ClassOfService.Interfaces, p.ClassOfService.Interfaces) {
		t.Errorf("packed interface binding compiles differently than braced:\n braced=%+v\n packed=%+v",
			bi, p.ClassOfService.Interfaces["ge-0/0/0"])
	}
}

// Sub-instance depth: the unit packed at its own level inside a braced
// interface (`ge { 0 scheduler-map M; }`) and a forwarding-class packed
// inside a braced scheduler-map are the same drop one level down.
func TestCoSPackedSubUnitBinding15064(t *testing.T) {
	pre := `schedulers { S { transmit-rate 10m; } } scheduler-maps { M { forwarding-class best-effort { scheduler S; } } } `
	braced := `class-of-service { ` + pre + `interfaces { ge-0/0/0 { unit 0 { scheduler-map M; } } } }`
	packed := `class-of-service { ` + pre + `interfaces { ge-0/0/0 { 0 scheduler-map M; } } }`
	b, p := compileBracedPacked15064(t, braced, packed)
	bi := b.ClassOfService.Interfaces["ge-0/0/0"]
	if bi == nil || bi.Units[0] == nil || bi.Units[0].SchedulerMap != "M" {
		t.Fatalf("braced control did not compile unit scheduler-map: %+v", bi)
	}
	if !reflect.DeepEqual(b.ClassOfService.Interfaces, p.ClassOfService.Interfaces) {
		t.Errorf("packed sub-unit binding compiles differently than braced:\n braced=%+v\n packed=%+v",
			bi, p.ClassOfService.Interfaces["ge-0/0/0"])
	}
}

func TestCoSPackedSubForwardingClass15064(t *testing.T) {
	braced := `class-of-service { schedulers { S { transmit-rate 10m; } } scheduler-maps { M { forwarding-class best-effort { scheduler S; } } } }`
	packed := `class-of-service { schedulers { S { transmit-rate 10m; } } scheduler-maps { M { best-effort scheduler S; } } }`
	b, p := compileBracedPacked15064(t, braced, packed)
	bm := b.ClassOfService.SchedulerMaps["M"]
	if bm == nil || bm.Entries["best-effort"] == nil || bm.Entries["best-effort"].Scheduler != "S" {
		t.Fatalf("braced control did not compile scheduler-map entry: %+v", bm)
	}
	if !reflect.DeepEqual(b.ClassOfService.SchedulerMaps, p.ClassOfService.SchedulerMaps) {
		t.Errorf("packed sub-forwarding-class compiles differently than braced:\n braced=%+v\n packed=%+v",
			bm, p.ClassOfService.SchedulerMaps["M"])
	}
}

func TestCoSPackedInterfaceUnitBinding15064(t *testing.T) {
	pre := `schedulers { S { transmit-rate 10m; } } scheduler-maps { M { forwarding-class best-effort { scheduler S; } } } `
	braced := `class-of-service { ` + pre + `interfaces { ge-0/0/0 { unit 0 { scheduler-map M; } } } }`
	packed := `class-of-service { ` + pre + `interfaces { ge-0/0/0 { unit 0 scheduler-map M; } } }`
	b, p := compileBracedPacked15064(t, braced, packed)
	bi := b.ClassOfService.Interfaces["ge-0/0/0"]
	if bi == nil || bi.Units[0] == nil || bi.Units[0].SchedulerMap != "M" {
		t.Fatalf("braced control did not compile unit scheduler-map: %+v", bi)
	}
	if !reflect.DeepEqual(b.ClassOfService.Interfaces, p.ClassOfService.Interfaces) {
		t.Errorf("packed unit binding compiles differently than braced:\n braced=%+v\n packed=%+v",
			bi, p.ClassOfService.Interfaces["ge-0/0/0"])
	}
}

// Narrowness control: a packed instance naming only one leaf must not
// invent the others. Guards against a fix that fills defaults.
func TestCoSPackedSchedulerSingleLeafNarrow15064(t *testing.T) {
	p := mustCompile8436(t, `class-of-service { schedulers { be priority high; } }`)
	s := p.ClassOfService.Schedulers["be"]
	if s == nil || s.Priority != "high" {
		t.Fatalf("packed single-leaf scheduler lost its own leaf: %+v", s)
	}
	if s.TransmitRateBytes != 0 || s.SurplusSharing {
		t.Errorf("packed `priority high` alone also set transmit-rate=%d surplus=%v",
			s.TransmitRateBytes, s.SurplusSharing)
	}
}

// Gate pairing: once the compiler reads the packed tail, the schema
// gate must validate it. A bogus packed value must reject exactly as
// the braced spelling does (#6821 bidirectional contract).
func TestCoSPackedInvalidValueRejected15064(t *testing.T) {
	for _, tc := range []struct{ name, braced, packed string }{
		{"scheduler priority",
			`class-of-service { schedulers { be { priority bogus; } } }`,
			`class-of-service { schedulers { be priority bogus; } }`},
		{"scheduler transmit-rate",
			`class-of-service { schedulers { be { transmit-rate bogus; } } }`,
			`class-of-service { schedulers { be transmit-rate bogus; } }`},
		{"tcp shaping-rate",
			`class-of-service { traffic-control-profiles { TCP { shaping-rate bogus; } } }`,
			`class-of-service { traffic-control-profiles { TCP shaping-rate bogus; } }`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bTree, bErrs := NewParser(tc.braced).Parse()
			if len(bErrs) != 0 {
				t.Fatalf("braced parse: %v", bErrs)
			}
			pTree, pErrs := NewParser(tc.packed).Parse()
			if len(pErrs) != 0 {
				t.Fatalf("packed parse: %v", pErrs)
			}
			bErr := SchemaValidate(bTree, nil)
			pErr := SchemaValidate(pTree, nil)
			if bErr == nil {
				t.Fatalf("braced control %q was supposed to be REJECTED, got nil — cell would be vacuous", tc.braced)
			}
			if pErr == nil {
				t.Errorf("packed %q ACCEPTED at the gate while braced %q REJECTS (%v) — compiled-unvalidated hole (#15064/#6821)",
					tc.packed, tc.braced, bErr)
			} else if !strings.Contains(pErr.Error(), "bogus") && !strings.Contains(bErr.Error(), "bogus") {
				t.Errorf("packed rejection does not name the bad value: packed=%v braced=%v", pErr, bErr)
			}
		})
	}
}
