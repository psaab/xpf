package config

import (
	"strings"
	"testing"
)

func TestCompileClassOfServiceHierarchical(t *testing.T) {
	input := `class-of-service {
    forwarding-classes {
        queue 0 best-effort;
        queue 1 expedited-forwarding;
    }
    schedulers {
        be-sched {
            transmit-rate 7g;
            priority low;
            buffer-size 16m;
        }
        ef-sched {
            transmit-rate 3g;
            priority strict-high;
            buffer-size 4m;
        }
    }
    scheduler-maps {
        edge-map {
            forwarding-class best-effort {
                scheduler be-sched;
            }
            forwarding-class expedited-forwarding {
                scheduler ef-sched;
            }
        }
    }
    interfaces {
        ge-0/0/1 {
            unit 0 {
                shaping-rate 10g {
                    burst-size 125m;
                }
                scheduler-map edge-map;
            }
        }
    }
}
system {
    dataplane-type userspace;
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	if cfg.ClassOfService == nil {
		t.Fatal("expected class-of-service config")
	}
	if got := cfg.ClassOfService.ForwardingClasses["best-effort"].Queue; got != 0 {
		t.Fatalf("best-effort queue = %d, want 0", got)
	}
	if got := cfg.ClassOfService.Schedulers["ef-sched"].TransmitRateBytes; got != parseBandwidthLimit("3g") {
		t.Fatalf("ef-sched transmit-rate = %d, want %d", got, parseBandwidthLimit("3g"))
	}
	if got := cfg.ClassOfService.Schedulers["ef-sched"].Priority; got != "strict-high" {
		t.Fatalf("ef-sched priority = %q, want strict-high", got)
	}
	unit := cfg.ClassOfService.Interfaces["ge-0/0/1"].Units[0]
	if unit == nil {
		t.Fatal("expected ge-0/0/1 unit 0 CoS config")
	}
	if got := unit.ShapingRateBytes; got != parseBandwidthLimit("10g") {
		t.Fatalf("shaping-rate = %d, want %d", got, parseBandwidthLimit("10g"))
	}
	if got := unit.BurstSizeBytes; got != parseBurstSizeLimit("125m") {
		t.Fatalf("burst-size = %d, want %d", got, parseBurstSizeLimit("125m"))
	}
	if got := unit.SchedulerMap; got != "edge-map" {
		t.Fatalf("scheduler-map = %q, want edge-map", got)
	}
}

func TestCompileClassOfServiceSetSyntax(t *testing.T) {
	lines := []string{
		"set class-of-service forwarding-classes queue 0 best-effort",
		"set class-of-service classifiers dscp wan-classifier forwarding-class best-effort loss-priority low code-points be",
		"set class-of-service classifiers ieee-802.1 wan-pcp forwarding-class best-effort loss-priority low code-points 0",
		"set class-of-service schedulers be-sched transmit-rate 5g",
		"set class-of-service schedulers be-sched transmit-rate exact",
		"set class-of-service schedulers be-sched priority low",
		"set class-of-service schedulers be-sched buffer-size 8m",
		"set class-of-service scheduler-maps edge-map forwarding-class best-effort scheduler be-sched",
		"set class-of-service interfaces ge-0/0/2 unit 80 shaping-rate 9g",
		"set class-of-service interfaces ge-0/0/2 unit 80 shaping-rate burst-size 64m",
		"set class-of-service interfaces ge-0/0/2 unit 80 scheduler-map edge-map",
		"set class-of-service interfaces ge-0/0/2 unit 80 classifiers dscp wan-classifier",
		"set class-of-service interfaces ge-0/0/2 unit 80 classifiers ieee-802.1 wan-pcp",
		"set class-of-service rewrite-rules dscp wan-rewrite forwarding-class best-effort loss-priority low code-point ef",
		"set class-of-service interfaces ge-0/0/2 unit 80 rewrite-rules dscp wan-rewrite",
		"set system dataplane-type userspace",
	}
	tree := &ConfigTree{}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	unit := cfg.ClassOfService.Interfaces["ge-0/0/2"].Units[80]
	if unit == nil {
		t.Fatal("expected ge-0/0/2 unit 80 CoS config")
	}
	if got := unit.ShapingRateBytes; got != parseBandwidthLimit("9g") {
		t.Fatalf("shaping-rate = %d, want %d", got, parseBandwidthLimit("9g"))
	}
	if got := unit.SchedulerMap; got != "edge-map" {
		t.Fatalf("scheduler-map = %q, want edge-map", got)
	}
	if got := unit.DSCPClassifier; got != "wan-classifier" {
		t.Fatalf("dscp-classifier = %q, want wan-classifier", got)
	}
	if got := unit.IEEE8021Classifier; got != "wan-pcp" {
		t.Fatalf("ieee-802.1 classifier = %q, want wan-pcp", got)
	}
	if got := unit.DSCPRewriteRule; got != "wan-rewrite" {
		t.Fatalf("dscp rewrite-rule = %q, want wan-rewrite", got)
	}
	if !cfg.ClassOfService.Schedulers["be-sched"].TransmitRateExact {
		t.Fatal("expected be-sched transmit-rate exact")
	}
	classifier := cfg.ClassOfService.DSCPClassifiers["wan-classifier"]
	if classifier == nil || len(classifier.Entries) != 1 {
		t.Fatalf("expected wan-classifier entry, got %#v", classifier)
	}
	if got := classifier.Entries[0].DSCPValues; len(got) != 1 || got[0] != 0 {
		t.Fatalf("wan-classifier dscp values = %v, want [0]", got)
	}
	pcpClassifier := cfg.ClassOfService.IEEE8021Classifiers["wan-pcp"]
	if pcpClassifier == nil || len(pcpClassifier.Entries) != 1 {
		t.Fatalf("expected wan-pcp entry, got %#v", pcpClassifier)
	}
	if got := pcpClassifier.Entries[0].CodePoints; len(got) != 1 || got[0] != 0 {
		t.Fatalf("wan-pcp code-points = %v, want [0]", got)
	}
	rewriteRule := cfg.ClassOfService.DSCPRewriteRules["wan-rewrite"]
	if rewriteRule == nil || len(rewriteRule.Entries) != 1 {
		t.Fatalf("expected wan-rewrite entry, got %#v", rewriteRule)
	}
	if got := rewriteRule.Entries[0].DSCPValue; got != 46 {
		t.Fatalf("wan-rewrite code-point = %d, want 46", got)
	}
}

func TestCompileClassOfServiceInlineTransmitRateExactSyntax(t *testing.T) {
	lines := []string{
		"set class-of-service forwarding-classes queue 0 best-effort",
		"set class-of-service schedulers be-sched transmit-rate 5g exact",
		"set system dataplane-type userspace",
	}
	tree := &ConfigTree{}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	sched := cfg.ClassOfService.Schedulers["be-sched"]
	if sched == nil {
		t.Fatal("expected be-sched scheduler")
	}
	if got := sched.TransmitRateBytes; got != parseBandwidthLimit("5g") {
		t.Fatalf("transmit-rate = %d, want %d", got, parseBandwidthLimit("5g"))
	}
	if !sched.TransmitRateExact {
		t.Fatal("expected inline transmit-rate exact")
	}
}

func TestCompileClassOfServiceDecimalTransmitRateExactSyntax(t *testing.T) {
	lines := []string{
		"set class-of-service forwarding-classes queue 4 iperf-a",
		"set class-of-service schedulers iperf-a transmit-rate 10.0g",
		"set class-of-service schedulers iperf-a transmit-rate exact",
		"set class-of-service scheduler-maps edge-map forwarding-class iperf-a scheduler iperf-a",
		"set class-of-service interfaces ge-0/0/2 unit 80 shaping-rate 20g",
		"set class-of-service interfaces ge-0/0/2 unit 80 scheduler-map edge-map",
		"set system dataplane-type userspace",
	}
	tree := &ConfigTree{}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	sched := cfg.ClassOfService.Schedulers["iperf-a"]
	if sched == nil {
		t.Fatal("expected iperf-a scheduler")
	}
	if got := sched.TransmitRateBytes; got != parseBandwidthLimit("10.0g") {
		t.Fatalf("transmit-rate = %d, want %d", got, parseBandwidthLimit("10.0g"))
	}
	if !sched.TransmitRateExact {
		t.Fatal("expected transmit-rate exact")
	}
}

// #915: surplus-sharing flag set via flat-set syntax.
func TestSchedulerSurplusSharingFlatSet(t *testing.T) {
	lines := []string{
		"set class-of-service forwarding-classes queue 4 iperf-a",
		"set class-of-service schedulers iperf-a transmit-rate 1g exact",
		"set class-of-service schedulers iperf-a surplus-sharing",
		"set class-of-service scheduler-maps edge-map forwarding-class iperf-a scheduler iperf-a",
		"set class-of-service interfaces ge-0/0/2 unit 80 shaping-rate 10g",
		"set class-of-service interfaces ge-0/0/2 unit 80 scheduler-map edge-map",
		"set system dataplane-type userspace",
	}
	tree := &ConfigTree{}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	sched := cfg.ClassOfService.Schedulers["iperf-a"]
	if sched == nil {
		t.Fatal("expected iperf-a scheduler")
	}
	if !sched.TransmitRateExact {
		t.Fatal("expected transmit-rate exact")
	}
	if !sched.SurplusSharing {
		t.Fatal("expected surplus-sharing = true")
	}
}

// #915: surplus-sharing flag set via hierarchical syntax.
func TestSchedulerSurplusSharingHierarchical(t *testing.T) {
	input := `class-of-service {
    forwarding-classes {
        queue 4 iperf-a;
    }
    schedulers {
        iperf-a {
            transmit-rate 1g exact;
            surplus-sharing;
        }
    }
    scheduler-maps {
        edge-map {
            forwarding-class iperf-a {
                scheduler iperf-a;
            }
        }
    }
    interfaces {
        ge-0/0/2 {
            unit 80 {
                shaping-rate 10g;
                scheduler-map edge-map;
            }
        }
    }
}
system {
    dataplane-type userspace;
}
`
	parser := NewParser(input)
	tree, parseErrs := parser.Parse()
	if len(parseErrs) > 0 {
		t.Fatalf("parse: %v", parseErrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	sched := cfg.ClassOfService.Schedulers["iperf-a"]
	if sched == nil {
		t.Fatal("expected iperf-a scheduler")
	}
	if !sched.TransmitRateExact || !sched.SurplusSharing {
		t.Fatalf("expected exact + surplus-sharing; got exact=%v surplus_sharing=%v",
			sched.TransmitRateExact, sched.SurplusSharing)
	}
}

// #915: ValidateConfig warn-and-strips surplus-sharing when set
// without transmit-rate exact (#1183 lesson — runtime never sees
// the no-op flag).
func TestSchedulerSurplusSharingWithoutExactWarnsAndStrips(t *testing.T) {
	lines := []string{
		"set class-of-service forwarding-classes queue 4 iperf-a",
		"set class-of-service schedulers iperf-a transmit-rate 1g",
		"set class-of-service schedulers iperf-a surplus-sharing",
		"set class-of-service scheduler-maps edge-map forwarding-class iperf-a scheduler iperf-a",
		"set class-of-service interfaces ge-0/0/2 unit 80 shaping-rate 10g",
		"set class-of-service interfaces ge-0/0/2 unit 80 scheduler-map edge-map",
		"set system dataplane-type userspace",
	}
	tree := &ConfigTree{}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	// CompileConfig calls ValidateConfig internally and stores
	// warnings on cfg.Warnings; calling ValidateConfig again is a
	// no-op because the strip already cleared SurplusSharing.
	gotWarn := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "surplus-sharing") &&
			strings.Contains(w, "iperf-a") {
			gotWarn = true
			break
		}
	}
	if !gotWarn {
		t.Fatalf("expected warn-and-strip warning on cfg.Warnings; got: %v",
			cfg.Warnings)
	}
	sched := cfg.ClassOfService.Schedulers["iperf-a"]
	if sched == nil {
		t.Fatal("scheduler missing")
	}
	if sched.SurplusSharing {
		t.Fatal("expected SurplusSharing=false after warn-and-strip")
	}
}

func TestValidateClassOfServiceWarnings(t *testing.T) {
	input := `class-of-service {
    forwarding-classes {
        queue 0 best-effort;
    }
    classifiers {
        dscp edge-classifier {
            forwarding-class missing-class {
                loss-priority low {
                    code-points [ ef ];
                }
            }
        }
        ieee-802.1 pcp-classifier {
            forwarding-class missing-class {
                loss-priority low {
                    code-points [ 5 ];
                }
            }
        }
    }
    scheduler-maps {
        edge-map {
            forwarding-class best-effort {
                scheduler missing-sched;
            }
        }
    }
    interfaces {
        ge-0/0/1 {
            unit 0 {
                shaping-rate 10g;
                scheduler-map edge-map;
                classifiers {
                    dscp missing-classifier;
                    ieee-802.1 missing-pcp-classifier;
                }
                rewrite-rules {
                    dscp missing-rewrite;
                }
            }
        }
    }
    rewrite-rules {
        dscp edge-rewrite {
            forwarding-class missing-class {
                loss-priority low {
                    code-point ef;
                }
            }
        }
    }
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	warnings := strings.Join(cfg.Warnings, "\n")
	if !strings.Contains(warnings, `scheduler-map "edge-map" references undefined scheduler "missing-sched"`) {
		t.Fatalf("expected undefined scheduler warning, got: %s", warnings)
	}
	if !strings.Contains(warnings, `dscp classifier "edge-classifier" references undefined forwarding-class "missing-class"`) {
		t.Fatalf("expected undefined forwarding-class warning, got: %s", warnings)
	}
	if !strings.Contains(warnings, `ieee-802.1 classifier "pcp-classifier" references undefined forwarding-class "missing-class"`) {
		t.Fatalf("expected undefined 802.1p forwarding-class warning, got: %s", warnings)
	}
	if !strings.Contains(warnings, `references undefined dscp classifier "missing-classifier"`) {
		t.Fatalf("expected undefined dscp classifier warning, got: %s", warnings)
	}
	if !strings.Contains(warnings, `references undefined ieee-802.1 classifier "missing-pcp-classifier"`) {
		t.Fatalf("expected undefined 802.1p classifier warning, got: %s", warnings)
	}
	if !strings.Contains(warnings, `references undefined dscp rewrite-rule "missing-rewrite"`) {
		t.Fatalf("expected undefined dscp rewrite-rule warning, got: %s", warnings)
	}
	if !strings.Contains(warnings, `dscp rewrite-rule "edge-rewrite" references undefined forwarding-class "missing-class"`) {
		t.Fatalf("expected undefined dscp rewrite-rule forwarding-class warning, got: %s", warnings)
	}
	if !strings.Contains(warnings, "dscp/802.1p classifier loss-priority is accepted for compatibility but not yet enforced") {
		t.Fatalf("expected classifier loss-priority warning, got: %s", warnings)
	}
	if !strings.Contains(warnings, "dscp rewrite-rule loss-priority is accepted for compatibility but not yet enforced") {
		t.Fatalf("expected rewrite-rule loss-priority warning, got: %s", warnings)
	}
	if !strings.Contains(warnings, "class-of-service shaping, classifier attachment, and dscp rewrite-rule attachment are only implemented in the userspace dataplane") {
		t.Fatalf("expected dataplane warning, got: %s", warnings)
	}
}

func TestCompileClassOfServiceHierarchicalDSCPClassifier(t *testing.T) {
	input := `class-of-service {
    forwarding-classes {
        queue 0 best-effort;
        queue 5 voice;
    }
    classifiers {
        dscp edge-classifier {
            forwarding-class voice {
                loss-priority low {
                    code-points [ ef 46 ];
                }
            }
            forwarding-class best-effort {
                loss-priority low {
                    code-points [ default cs0 ];
                }
            }
        }
    }
    interfaces {
        ge-0/0/1 {
            unit 0 {
                classifiers {
                    dscp edge-classifier;
                }
            }
        }
    }
}
system {
    dataplane-type userspace;
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	classifier := cfg.ClassOfService.DSCPClassifiers["edge-classifier"]
	if classifier == nil {
		t.Fatal("expected edge-classifier")
	}
	if got := cfg.ClassOfService.Interfaces["ge-0/0/1"].Units[0].DSCPClassifier; got != "edge-classifier" {
		t.Fatalf("unit classifier = %q, want edge-classifier", got)
	}
	if len(classifier.Entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(classifier.Entries))
	}
	if got := classifier.Entries[0].DSCPValues; len(got) != 1 || got[0] != 46 {
		t.Fatalf("voice code-points = %v, want [46]", got)
	}
	if got := classifier.Entries[1].DSCPValues; len(got) != 1 || got[0] != 0 {
		t.Fatalf("best-effort code-points = %v, want [0]", got)
	}
}

func TestCompileClassOfServiceHierarchicalIEEE8021Classifier(t *testing.T) {
	input := `class-of-service {
    forwarding-classes {
        queue 0 best-effort;
        queue 5 voice;
    }
    classifiers {
        ieee-802.1 edge-pcp {
            forwarding-class voice {
                loss-priority low {
                    code-points [ 5 5 ];
                }
            }
            forwarding-class best-effort {
                loss-priority low {
                    code-points [ 0 ];
                }
            }
        }
    }
	    interfaces {
	        ge-0/0/1 {
	            unit 0 {
	                classifiers {
	                    ieee-802.1 edge-pcp;
	                }
	            }
	        }
	    }
	}
	system {
	    dataplane-type userspace;
	}
	`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	classifier := cfg.ClassOfService.IEEE8021Classifiers["edge-pcp"]
	if classifier == nil {
		t.Fatal("expected edge-pcp classifier")
	}
	if got := cfg.ClassOfService.Interfaces["ge-0/0/1"].Units[0].IEEE8021Classifier; got != "edge-pcp" {
		t.Fatalf("unit classifier = %q, want edge-pcp", got)
	}
	if len(classifier.Entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(classifier.Entries))
	}
	if got := classifier.Entries[0].CodePoints; len(got) != 1 || got[0] != 5 {
		t.Fatalf("voice code-points = %v, want [5]", got)
	}
	if got := classifier.Entries[1].CodePoints; len(got) != 1 || got[0] != 0 {
		t.Fatalf("best-effort code-points = %v, want [0]", got)
	}
}

func TestCompileClassOfServiceHierarchicalDSCPRewriteRule(t *testing.T) {
	input := `class-of-service {
    forwarding-classes {
        queue 0 best-effort;
        queue 5 voice;
    }
    rewrite-rules {
        dscp edge-rewrite {
            forwarding-class voice {
                loss-priority low {
                    code-point ef;
                }
            }
            forwarding-class best-effort {
                loss-priority low {
                    code-point default;
                }
            }
        }
    }
    interfaces {
        ge-0/0/1 {
            unit 0 {
                rewrite-rules {
                    dscp edge-rewrite;
                }
            }
        }
    }
}
system {
    dataplane-type userspace;
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	rewriteRule := cfg.ClassOfService.DSCPRewriteRules["edge-rewrite"]
	if rewriteRule == nil {
		t.Fatal("expected edge-rewrite")
	}
	if got := cfg.ClassOfService.Interfaces["ge-0/0/1"].Units[0].DSCPRewriteRule; got != "edge-rewrite" {
		t.Fatalf("unit rewrite-rule = %q, want edge-rewrite", got)
	}
	if len(rewriteRule.Entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(rewriteRule.Entries))
	}
	if got := rewriteRule.Entries[0].DSCPValue; got != 46 {
		t.Fatalf("voice code-point = %d, want 46", got)
	}
	if got := rewriteRule.Entries[1].DSCPValue; got != 0 {
		t.Fatalf("best-effort code-point = %d, want 0", got)
	}
}

func TestValidateClassOfServiceQueueRangeWarning(t *testing.T) {
	input := `class-of-service {
    forwarding-classes {
        queue 300 invalid-class;
    }
}
system {
    dataplane-type userspace;
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	warnings := strings.Join(cfg.Warnings, "\n")
	if !strings.Contains(warnings, `forwarding-class "invalid-class" uses out-of-range queue 300`) {
		t.Fatalf("expected queue range warning, got: %s", warnings)
	}
}

// TestCompileClassOfServiceRejectsDuplicateFCPerQueue pins the validation
// added for the #785 follow-up: two forwarding classes assigned to the
// same queue ID must cause `CompileConfig` to return an error, not a
// silent warning.
//
// Before the fix, a config like the one below silently compiled into two
// CoSQueueConfig entries sharing `queue_id=5` with different transmit
// rates, which the userspace dataplane then resolved inconsistently
// across three code paths (runtime queue transmit_rate, shared-lease
// rate, and display) — the discovery that pre-empted the #785 cross-
// worker investigation's throughput-vs-fairness analysis. Rejection at
// compile time prevents the inconsistency from ever reaching the
// dataplane.
func TestCompileClassOfServiceRejectsDuplicateFCPerQueue(t *testing.T) {
	lines := []string{
		"set class-of-service forwarding-classes queue 0 best-effort",
		"set class-of-service forwarding-classes queue 5 iperf-b",
		"set class-of-service forwarding-classes queue 5 iperf-c", // conflict
		"set class-of-service schedulers scheduler-iperf-b transmit-rate 10g",
		"set class-of-service schedulers scheduler-iperf-b transmit-rate exact",
		"set class-of-service schedulers scheduler-iperf-c transmit-rate 25g",
		"set class-of-service schedulers scheduler-iperf-c transmit-rate exact",
		"set class-of-service scheduler-maps bandwidth-limit forwarding-class iperf-b scheduler scheduler-iperf-b",
		"set class-of-service scheduler-maps bandwidth-limit forwarding-class iperf-c scheduler scheduler-iperf-c",
		"set class-of-service interfaces reth0 unit 80 shaping-rate 25g",
		"set class-of-service interfaces reth0 unit 80 scheduler-map bandwidth-limit",
		"set system dataplane-type userspace",
	}
	tree := &ConfigTree{}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal(
			"expected CompileConfig to REJECT a config with two " +
				"forwarding-classes on the same queue; got no error. " +
				"Regression re-introduces the three-way runtime " +
				"inconsistency that bit the #785 investigation.",
		)
	}
	msg := err.Error()
	// The error must name the offending queue and BOTH FCs so the
	// operator can fix the config without having to diff the whole
	// forwarding-classes block.
	if !strings.Contains(msg, "queue 5") {
		t.Errorf("error message must identify the conflicting queue ID 5, got: %s", msg)
	}
	if !strings.Contains(msg, "iperf-b") {
		t.Errorf("error message must identify first FC iperf-b, got: %s", msg)
	}
	if !strings.Contains(msg, "iperf-c") {
		t.Errorf("error message must identify second FC iperf-c, got: %s", msg)
	}
}

// TestCompileClassOfServiceAllowsIdempotentReassignment pins that
// setting the SAME FC-to-queue mapping twice does NOT produce an
// error — reconciliation paths (e.g. `load merge`, `load override`,
// or applying a set script that re-runs the same assignment) must
// remain idempotent.
func TestCompileClassOfServiceAllowsIdempotentReassignment(t *testing.T) {
	lines := []string{
		"set class-of-service forwarding-classes queue 0 best-effort",
		"set class-of-service forwarding-classes queue 5 iperf-c",
		"set class-of-service forwarding-classes queue 5 iperf-c", // same, not duplicate
		"set system dataplane-type userspace",
	}
	tree := &ConfigTree{}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("idempotent reassignment must compile cleanly: %v", err)
	}
	fc := cfg.ClassOfService.ForwardingClasses["iperf-c"]
	if fc == nil {
		t.Fatal("expected iperf-c forwarding class")
	}
	if fc.Queue != 5 {
		t.Fatalf("iperf-c queue = %d, want 5", fc.Queue)
	}
}

// TestCompileClassOfServiceRejectsSameFCOnDifferentQueues pins the
// second direction of the FC ↔ queue bijection: one forwarding class
// cannot be assigned to two different queue numbers.
//
// This path can arise organically from `apply-groups` / `${node}`
// expansion producing duplicate entries in an operator's config.
// Pre-fix the second assignment silently overwrote
// `ForwardingClasses[name].Queue`, so classifier + scheduler-map
// references to that FC would resolve to the wrong queue depending
// on the compile-time iteration order — a silent runtime-routing
// bug with no warning surface. (Flagged by Codex review of the
// initial PR #787 revision; that revision guarded only the
// queue-ID → FC-name direction.)
func TestCompileClassOfServiceRejectsSameFCOnDifferentQueues(t *testing.T) {
	lines := []string{
		"set class-of-service forwarding-classes queue 0 best-effort",
		"set class-of-service forwarding-classes queue 4 iperf-a",
		"set class-of-service forwarding-classes queue 5 iperf-a", // conflict
		"set class-of-service schedulers scheduler-iperf-a transmit-rate 1g",
		"set class-of-service schedulers scheduler-iperf-a transmit-rate exact",
		"set class-of-service scheduler-maps bandwidth-limit forwarding-class iperf-a scheduler scheduler-iperf-a",
		"set system dataplane-type userspace",
	}
	tree := &ConfigTree{}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal(
			"expected CompileConfig to REJECT a config that assigns " +
				"the same forwarding-class to two different queues; got " +
				"no error. Regression silently overwrites the FC→queue " +
				"map and mis-routes classifier / scheduler-map references.",
		)
	}
	msg := err.Error()
	// Error must name the FC and BOTH conflicting queue numbers.
	if !strings.Contains(msg, "iperf-a") {
		t.Errorf("error message must name the conflicting FC iperf-a, got: %s", msg)
	}
	if !strings.Contains(msg, "queue 4") {
		t.Errorf("error message must name first queue 4, got: %s", msg)
	}
	if !strings.Contains(msg, "queue 5") {
		t.Errorf("error message must name second queue 5, got: %s", msg)
	}
}

// TestCompileClassOfServiceRejectsThreeFCsOnOneQueue pins that the
// duplicate detection fires on the SECOND collision regardless of
// how many FCs pile up on one queue — the error catches the
// earliest conflict in iteration order, not the last.
func TestCompileClassOfServiceRejectsThreeFCsOnOneQueue(t *testing.T) {
	lines := []string{
		"set class-of-service forwarding-classes queue 5 iperf-a",
		"set class-of-service forwarding-classes queue 5 iperf-b",
		"set class-of-service forwarding-classes queue 5 iperf-c",
		"set system dataplane-type userspace",
	}
	tree := &ConfigTree{}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected three FCs on one queue to be rejected at compile time")
	}
	if !strings.Contains(err.Error(), "queue 5") {
		t.Errorf("error must reference queue 5, got: %s", err.Error())
	}
}
