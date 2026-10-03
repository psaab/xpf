package config

import (
	"fmt"
	"os"
	"path/filepath"
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
		"set class-of-service schedulers be-sched equal-flow-enforcement",
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
	if !cfg.ClassOfService.Schedulers["be-sched"].EqualFlowEnforcement {
		t.Fatal("expected be-sched equal-flow-enforcement")
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

func TestCompileClassOfServicePercentBufferSize(t *testing.T) {
	lines := []string{
		"set class-of-service schedulers be-sched transmit-rate 5g",
		"set class-of-service schedulers be-sched buffer-size 10%",
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
		t.Fatal("expected be-sched")
	}
	if got := sched.BufferSizePercent; got != 10 {
		t.Fatalf("buffer percent = %v, want 10", got)
	}
	if got := sched.BufferSizeBytes; got != 0 {
		t.Fatalf("buffer bytes = %d, want 0 for percent form", got)
	}
}

func TestCompileClassOfServiceRejectsAggregatePercentBuffersOver100PerInterface(t *testing.T) {
	tree := &ConfigTree{}
	lines := []string{
		"set class-of-service forwarding-classes queue 0 best-effort",
		"set class-of-service forwarding-classes queue 1 expedited-forwarding",
		"set class-of-service schedulers be-sched buffer-size 75%",
		"set class-of-service schedulers ef-sched buffer-size 75%",
		"set class-of-service scheduler-maps edge-map forwarding-class best-effort scheduler be-sched",
		"set class-of-service scheduler-maps edge-map forwarding-class expedited-forwarding scheduler ef-sched",
		"set class-of-service interfaces ge-0/0/2 unit 0 scheduler-map edge-map",
	}
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
		t.Fatal("expected aggregate percent buffer-size error, got nil")
	}
	for _, want := range []string{"sum of buffer-size percent", "150", "100"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q missing %q", err, want)
		}
	}
}

func TestCompileClassOfServiceAllowsAggregatePercentBuffersAt100PerInterface(t *testing.T) {
	tree := &ConfigTree{}
	lines := []string{
		"set class-of-service forwarding-classes queue 0 best-effort",
		"set class-of-service forwarding-classes queue 1 expedited-forwarding",
		"set class-of-service schedulers be-sched buffer-size 25%",
		"set class-of-service schedulers ef-sched buffer-size 75%",
		"set class-of-service scheduler-maps edge-map forwarding-class best-effort scheduler be-sched",
		"set class-of-service scheduler-maps edge-map forwarding-class expedited-forwarding scheduler ef-sched",
		"set class-of-service interfaces ge-0/0/2 unit 0 scheduler-map edge-map",
	}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig at 100%% aggregate: %v", err)
	}
}

func TestCompileClassOfServiceEqualFlowEnforcementRequiresPositiveExactRate(t *testing.T) {
	tests := []struct {
		name  string
		lines []string
	}{
		{
			name: "no transmit rate",
			lines: []string{
				"set class-of-service schedulers ef-sched equal-flow-enforcement",
			},
		},
		{
			name: "non exact transmit rate",
			lines: []string{
				"set class-of-service schedulers ef-sched transmit-rate 10m",
				"set class-of-service schedulers ef-sched equal-flow-enforcement",
			},
		},
		{
			name: "exact without positive rate",
			lines: []string{
				"set class-of-service schedulers ef-sched transmit-rate exact",
				"set class-of-service schedulers ef-sched equal-flow-enforcement",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tree := &ConfigTree{}
			for _, line := range tc.lines {
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
				t.Fatal("CompileConfig succeeded, want equal-flow-enforcement validation error")
			}
			// #9366: the message widened to name the three first-class rate
			// forms. All three rows above still REJECT — the behaviour this
			// cell exists to pin is unchanged; only the wording moved. The
			// message is still asserted rather than dropped, because a
			// rejection reached through the WRONG branch reads as a working
			// guard when only the failure is checked.
			if !strings.Contains(err.Error(), "equal-flow-enforcement requires a positive transmit-rate") {
				t.Fatalf("CompileConfig error = %v, want equal-flow-enforcement validation", err)
			}
		})
	}
}

func TestCompileClassOfServiceEqualFlowEnforcementRejectsSurplusSharing(t *testing.T) {
	lines := []string{
		"set class-of-service schedulers ef-sched transmit-rate 10m exact",
		"set class-of-service schedulers ef-sched surplus-sharing",
		"set class-of-service schedulers ef-sched equal-flow-enforcement",
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
		t.Fatal("CompileConfig succeeded, want equal-flow/surplus-sharing validation error")
	}
	if !strings.Contains(err.Error(), "equal-flow-enforcement cannot be combined with surplus-sharing") {
		t.Fatalf("CompileConfig error = %v, want equal-flow/surplus-sharing validation", err)
	}
}

// TestCompileClassOfServicePercentBufferAggregateOvercommitRejected verifies
// that a scheduler-map whose schedulers' buffer-size percentages sum to more
// than 100% is rejected at compile time. Junos does not allow a port's queue
// buffer allocations to exceed the total interface buffer pool.
func TestCompileClassOfServicePercentBufferAggregateOvercommitRejected(t *testing.T) {
	lines := []string{
		// Two schedulers each claiming 75% → 150% overcommit.
		"set class-of-service schedulers voice buffer-size 75%",
		"set class-of-service schedulers data buffer-size 75%",
		"set class-of-service scheduler-maps edge forwarding-class ef scheduler voice",
		"set class-of-service scheduler-maps edge forwarding-class be scheduler data",
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
		t.Fatal("CompileConfig succeeded, want percent overcommit validation error")
	}
	if !strings.Contains(err.Error(), "sum of buffer-size percent") {
		t.Fatalf("CompileConfig error = %v, want aggregate percent overcommit error", err)
	}
}

// TestCompileClassOfServicePercentBuffer100PercentAllowed verifies that a
// scheduler-map whose schedulers' buffer-size percentages sum to exactly 100%
// is accepted (full pool allocation is valid).
func TestCompileClassOfServicePercentBuffer100PercentAllowed(t *testing.T) {
	lines := []string{
		"set class-of-service schedulers voice buffer-size 40%",
		"set class-of-service schedulers data buffer-size 60%",
		"set class-of-service scheduler-maps edge forwarding-class ef scheduler voice",
		"set class-of-service scheduler-maps edge forwarding-class be scheduler data",
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
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig: unexpected error for 40%%+60%% = 100%%: %v", err)
	}
}

func TestCompileClassOfServicePercentBufferLiteral100PercentAllowed(t *testing.T) {
	lines := []string{
		"set class-of-service forwarding-classes queue 1 expedited-forwarding",
		"set class-of-service schedulers voice buffer-size 100%",
		"set class-of-service scheduler-maps edge forwarding-class ef scheduler voice",
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
		t.Fatalf("CompileConfig: unexpected error for literal 100%%: %v", err)
	}
	if got := cfg.ClassOfService.Schedulers["voice"].BufferSizePercent; got != 100 {
		t.Fatalf("BufferSizePercent = %v, want 100", got)
	}
}

// TestCompileClassOfServiceBothBufferFieldsRejected verifies that a scheduler
// with both BufferSizeBytes and BufferSizePercent set simultaneously is
// rejected rather than silently applying the byte-wins runtime preference.
// The compiler always clears the unused field, so this state can only arise
// in constructed configs.
func TestCompileClassOfServiceBothBufferFieldsRejected(t *testing.T) {
	// Directly construct a CoSScheduler with both fields non-zero to exercise
	// the type-level guard in validateClassOfServiceStrict.
	cos := &ClassOfServiceConfig{
		Schedulers: map[string]*CoSScheduler{
			"voice": {
				Name:              "voice",
				BufferSizeBytes:   16_000_000,
				BufferSizePercent: 10,
			},
		},
		SchedulerMaps:       make(map[string]*CoSSchedulerMap),
		ForwardingClasses:   make(map[string]*CoSForwardingClass),
		DSCPClassifiers:     make(map[string]*CoSDSCPClassifier),
		IEEE8021Classifiers: make(map[string]*CoSIEEE8021Classifier),
		DSCPRewriteRules:    make(map[string]*CoSDSCPRewriteRule),
		Interfaces:          make(map[string]*CoSInterface),
	}
	err := validateClassOfServiceStrict(cos)
	if err == nil {
		t.Fatal("validateClassOfServiceStrict succeeded, want both-fields-set validation error")
	}
	if !strings.Contains(err.Error(), "both buffer-size bytes") {
		t.Fatalf("validateClassOfServiceStrict error = %v, want both-buffer-size error", err)
	}
}

func TestCompileClassOfServiceBufferTemporalMixedFormsRejected11789(t *testing.T) {
	tests := []struct {
		name     string
		bytes    uint64
		percent  float64
		temporal uint64
	}{
		{name: "bytes and temporal", bytes: 16_000_000, temporal: 50_000},
		{name: "percent and temporal", percent: 10, temporal: 50_000},
		{name: "all three forms", bytes: 16_000_000, percent: 10, temporal: 50_000},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cos := &ClassOfServiceConfig{
				Schedulers: map[string]*CoSScheduler{
					"voice": {
						Name:                 "voice",
						BufferSizeBytes:      tc.bytes,
						BufferSizePercent:    tc.percent,
						BufferSizeTemporalUS: tc.temporal,
					},
				},
				SchedulerMaps:       make(map[string]*CoSSchedulerMap),
				ForwardingClasses:   make(map[string]*CoSForwardingClass),
				DSCPClassifiers:     make(map[string]*CoSDSCPClassifier),
				IEEE8021Classifiers: make(map[string]*CoSIEEE8021Classifier),
				DSCPRewriteRules:    make(map[string]*CoSDSCPRewriteRule),
				Interfaces:          make(map[string]*CoSInterface),
			}
			err := validateClassOfServiceStrict(cos)
			if err == nil {
				t.Fatal("validateClassOfServiceStrict accepted multiple buffer-size forms")
			}
			for _, want := range []string{"buffer-size", "voice", "temporal", "one form"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("validation error %q does not name %q", err, want)
				}
			}
		})
	}
}

func TestCompileClassOfServiceFairnessRSSExpectations(t *testing.T) {
	lines := []string{
		"set class-of-service fairness rss-expectation interface ge-0/0/2 queue 4 balanced",
		"set class-of-service fairness rss-expectation interface ge-0/0/2 queue 5 max-worker-flow-share 0.5",
		"set class-of-service fairness rss-expectation interface ge-0/0/3 queue 7 cstruct-max 0.25",
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
	got := cfg.ClassOfService.FairnessExpectations
	if len(got) != 3 {
		t.Fatalf("FairnessExpectations len = %d, want 3: %#v", len(got), got)
	}
	tests := []struct {
		idx     int
		iface   string
		queueID uint8
		expect  string
	}{
		{idx: 0, iface: "ge-0/0/2", queueID: 4, expect: "balanced"},
		{idx: 1, iface: "ge-0/0/2", queueID: 5, expect: "max-worker-flow-share:0.5"},
		{idx: 2, iface: "ge-0/0/3", queueID: 7, expect: "cstruct-max:0.25"},
	}
	for _, tt := range tests {
		row := got[tt.idx]
		if row.Interface != tt.iface || row.QueueID != tt.queueID || row.RSSExpectation != tt.expect {
			t.Fatalf("expectation[%d] = interface=%s queue=%d expectation=%q, want interface=%s queue=%d expectation=%q",
				tt.idx, row.Interface, row.QueueID, row.RSSExpectation, tt.iface, tt.queueID, tt.expect)
		}
	}
}

func TestCompileClassOfServiceFairnessRSSExpectationRejectsDuplicateConflict(t *testing.T) {
	tree := &ConfigTree{}
	for _, line := range []string{
		"set class-of-service fairness rss-expectation interface ge-0/0/2 queue 4 balanced",
		"set class-of-service fairness rss-expectation interface ge-0/0/2 queue 4 cstruct-max 0.25",
	} {
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
		t.Fatal("CompileConfig succeeded, want duplicate fairness expectation error")
	}
	if !strings.Contains(err.Error(), "multiple expectations configured") {
		t.Fatalf("CompileConfig error = %v, want multiple expectations configured", err)
	}
}

func TestCompileClassOfServiceFairnessRSSExpectationSetDuplicateSameValueDedupes(t *testing.T) {
	tree := &ConfigTree{}
	for _, line := range []string{
		"set class-of-service fairness rss-expectation interface ge-0/0/2 queue 4 balanced",
		"set class-of-service fairness rss-expectation interface ge-0/0/2 queue 4 balanced",
	} {
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
		t.Fatalf("CompileConfig error = %v", err)
	}
	if got := cfg.ClassOfService.FairnessExpectations; len(got) != 1 || got[0].RSSExpectation != "balanced" {
		t.Fatalf("FairnessExpectations = %#v, want one balanced row", got)
	}
}

func TestCompileClassOfServiceFairnessRSSExpectationRejectsHierarchicalDuplicateLeaf(t *testing.T) {
	raw := `
class-of-service {
    fairness {
        rss-expectation {
            interface ge-0/0/2 {
                queue 4 {
                    balanced;
                    balanced;
                }
            }
        }
    }
}
system {
    dataplane-type userspace;
}
`
	parser := NewParser(raw)
	tree, errs := parser.Parse()
	if len(errs) != 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig succeeded, want duplicate hierarchical fairness expectation error")
	}
	if !strings.Contains(err.Error(), "duplicate balanced expectation leaf") {
		t.Fatalf("CompileConfig error = %v, want duplicate balanced expectation leaf", err)
	}
}

func TestCoSIperfSymmetricFixtureCompilesReverseSourcePortOutputFilter(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "test", "incus", "cos-iperf-symmetric.set"))
	if err != nil {
		t.Fatalf("read symmetric fixture: %v", err)
	}
	tree := &ConfigTree{}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if !strings.HasPrefix(line, "set ") {
			continue
		}
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
		t.Fatalf("compile symmetric fixture: %v", err)
	}

	reth0Cos := cfg.ClassOfService.Interfaces["reth0"].Units[80]
	if reth0Cos == nil {
		t.Fatal("expected forward CoS shaper on reth0 unit 80")
	}
	if got := reth0Cos.SchedulerMap; got != "bandwidth-limit" {
		t.Fatalf("reth0.80 scheduler-map = %q, want bandwidth-limit", got)
	}

	geCos := cfg.ClassOfService.Interfaces["ge-0-0-1"].Units[0]
	if geCos == nil {
		t.Fatal("expected reverse CoS shaper on ge-0-0-1 unit 0")
	}
	if got := geCos.ShapingRateBytes; got != parseBandwidthLimit("25g") {
		t.Fatalf("ge-0-0-1.0 shaping-rate = %d, want %d", got, parseBandwidthLimit("25g"))
	}
	if got := geCos.SchedulerMap; got != "bandwidth-limit" {
		t.Fatalf("ge-0-0-1.0 scheduler-map = %q, want bandwidth-limit", got)
	}

	fwdUnit := cfg.Interfaces.Interfaces["reth0"].Units[80]
	if fwdUnit == nil {
		t.Fatal("expected reth0 unit 80 interface config")
	}
	if got := fwdUnit.FilterOutputV4; got != "bandwidth-output" {
		t.Fatalf("reth0.80 inet output filter = %q, want bandwidth-output", got)
	}
	if got := fwdUnit.FilterOutputV6; got != "bandwidth-output" {
		t.Fatalf("reth0.80 inet6 output filter = %q, want bandwidth-output", got)
	}

	revUnit := cfg.Interfaces.Interfaces["ge-0-0-1"].Units[0]
	if revUnit == nil {
		t.Fatal("expected ge-0-0-1 unit 0 interface config")
	}
	if got := revUnit.FilterOutputV4; got != "bandwidth-output-reverse" {
		t.Fatalf("ge-0-0-1.0 inet output filter = %q, want bandwidth-output-reverse", got)
	}
	if got := revUnit.FilterOutputV6; got != "bandwidth-output-reverse" {
		t.Fatalf("ge-0-0-1.0 inet6 output filter = %q, want bandwidth-output-reverse", got)
	}

	revFilter := cfg.Firewall.FiltersInet["bandwidth-output-reverse"]
	if revFilter == nil {
		t.Fatal("expected inet bandwidth-output-reverse filter")
	}
	if len(revFilter.Terms) == 0 {
		t.Fatal("expected reverse filter terms")
	}
	term := revFilter.Terms[0]
	if got := strings.Join(term.SourcePorts, ","); got != "5200,6200" {
		t.Fatalf("reverse term 0 source ports = %q, want 5200,6200", got)
	}
	if len(term.DestinationPorts) != 0 {
		t.Fatalf("reverse term 0 must not match destination-port; got %v", term.DestinationPorts)
	}
	if got := term.ForwardingClass; got != "best-effort" {
		t.Fatalf("reverse term 0 forwarding-class = %q, want best-effort", got)
	}

	rev6Filter := cfg.Firewall.FiltersInet6["bandwidth-output-reverse"]
	if rev6Filter == nil || len(rev6Filter.Terms) < 4 {
		t.Fatal("expected inet6 bandwidth-output-reverse filter with at least 4 terms")
	}
	term = rev6Filter.Terms[3]
	if got := strings.Join(term.SourcePorts, ","); got != "5203,6203" {
		t.Fatalf("reverse inet6 term 3 source ports = %q, want 5203,6203", got)
	}
	if got := term.ForwardingClass; got != "iperf-3g" {
		t.Fatalf("reverse inet6 term 3 forwarding-class = %q, want iperf-3g", got)
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

// #915/#4966: ValidateConfig WARNS about surplus-sharing set without
// transmit-rate exact, but must NOT strip it — validation is a
// read-only pass and stripping made it non-idempotent (#4966). The
// configured intent stays on the active config; the runtime never sees
// the inert flag because buildClassOfServiceSnapshot gates it on
// TransmitRateExact (asserted in the userspace snapshot tests).
func TestSchedulerSurplusSharingWithoutExactWarnsButPreservesIntent(t *testing.T) {
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
	hasSurplusWarn := func(warns []string) bool {
		for _, w := range warns {
			if strings.Contains(w, "surplus-sharing") &&
				strings.Contains(w, "iperf-a") {
				return true
			}
		}
		return false
	}
	if !hasSurplusWarn(cfg.Warnings) {
		t.Fatalf("expected surplus-sharing warning on cfg.Warnings; got: %v",
			cfg.Warnings)
	}
	sched := cfg.ClassOfService.Schedulers["iperf-a"]
	if sched == nil {
		t.Fatal("scheduler missing")
	}
	// Intent preserved: ValidateConfig no longer strips the flag.
	if !sched.SurplusSharing {
		t.Fatal("expected SurplusSharing preserved (not stripped) after compile")
	}
	// Idempotent: a re-run of ValidateConfig on the active config must
	// re-emit the same warning (the recompute surfaces depend on this)
	// and must NOT mutate SurplusSharing.
	if warns := ValidateConfig(cfg); !hasSurplusWarn(warns) {
		t.Fatalf("second ValidateConfig dropped the surplus-sharing warning; got: %v", warns)
	}
	if !sched.SurplusSharing {
		t.Fatal("ValidateConfig mutated SurplusSharing (must be read-only)")
	}
}

// #4966: ValidateConfig is a read-only pass and MUST be idempotent —
// calling it twice yields an identical warning slice and leaves the
// config it was given unchanged. Before the fix, the surplus-sharing
// warn-and-strip mutated the config, so the second call saw a
// different state and produced a different result.
func TestValidateConfigIdempotentAndNonMutating(t *testing.T) {
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
	sched := cfg.ClassOfService.Schedulers["iperf-a"]
	if sched == nil {
		t.Fatal("scheduler missing")
	}
	before := sched.SurplusSharing

	first := ValidateConfig(cfg)
	if sched.SurplusSharing != before {
		t.Fatalf("ValidateConfig mutated SurplusSharing: before=%v after=%v", before, sched.SurplusSharing)
	}
	second := ValidateConfig(cfg)
	if sched.SurplusSharing != before {
		t.Fatalf("second ValidateConfig mutated SurplusSharing: before=%v after=%v", before, sched.SurplusSharing)
	}
	if len(first) != len(second) {
		t.Fatalf("ValidateConfig not idempotent: len(first)=%d len(second)=%d\nfirst=%v\nsecond=%v",
			len(first), len(second), first, second)
	}
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("ValidateConfig warning %d differs across calls:\n first=%q\nsecond=%q", i, first[i], second[i])
		}
	}
}

// #1614 A4 / #11810: ValidateConfig warns when configured transmit-rate
// claims exceed the interface unit's shaping-rate. The warning includes
// absolute, resolved-percent, and resolved-remainder claims, and surfaces the
// policy so operators see which exact-class distribution applies.
func TestValidateCoSOversubscriptionWarning(t *testing.T) {
	lines := []string{
		"set class-of-service forwarding-classes queue 0 best-effort",
		"set class-of-service forwarding-classes queue 1 iperf-a",
		"set class-of-service forwarding-classes queue 2 iperf-b",
		"set class-of-service schedulers iperf-a transmit-rate 12g",
		"set class-of-service schedulers iperf-a transmit-rate exact",
		"set class-of-service schedulers iperf-b transmit-rate 9g",
		"set class-of-service schedulers iperf-b transmit-rate exact",
		"set class-of-service scheduler-maps edge-map forwarding-class iperf-a scheduler iperf-a",
		"set class-of-service scheduler-maps edge-map forwarding-class iperf-b scheduler iperf-b",
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
	// Sum of exact rates is 21g, shaping is 10g — warning must fire.
	gotWarn := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "sum of configured transmit-rate claims") &&
			strings.Contains(w, "ge-0/0/2") &&
			strings.Contains(w, "proportional") {
			gotWarn = true
			break
		}
	}
	if !gotWarn {
		t.Fatalf("expected oversubscription warning on cfg.Warnings; got: %v",
			cfg.Warnings)
	}
}

// #1614 A4: oversubscription warning surfaces the active policy name
// when the operator has opted into guarantee-rate mode.
func TestValidateCoSOversubscriptionWarningGuaranteeRate(t *testing.T) {
	lines := []string{
		"set class-of-service forwarding-classes queue 1 iperf-a",
		"set class-of-service forwarding-classes queue 2 iperf-b",
		"set class-of-service schedulers iperf-a transmit-rate 12g",
		"set class-of-service schedulers iperf-a transmit-rate exact",
		"set class-of-service schedulers iperf-b transmit-rate 9g",
		"set class-of-service schedulers iperf-b transmit-rate exact",
		"set class-of-service scheduler-maps edge-map forwarding-class iperf-a scheduler iperf-a",
		"set class-of-service scheduler-maps edge-map forwarding-class iperf-b scheduler iperf-b",
		"set class-of-service interfaces ge-0/0/2 unit 80 shaping-rate 10g",
		"set class-of-service interfaces ge-0/0/2 unit 80 scheduler-map edge-map",
		"set class-of-service interfaces ge-0/0/2 unit 80 oversubscription-policy guarantee-rate 0.7",
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
	gotWarn := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "sum of configured transmit-rate claims") &&
			strings.Contains(w, "guarantee-rate 0.7") {
			gotWarn = true
			break
		}
	}
	if !gotWarn {
		t.Fatalf("expected guarantee-rate warning on cfg.Warnings; got: %v",
			cfg.Warnings)
	}
	// Verify the parsed policy threaded through to the typed config.
	iface := cfg.ClassOfService.Interfaces["ge-0/0/2"]
	if iface == nil {
		t.Fatal("interface ge-0/0/2 missing")
	}
	unit := iface.Units[80]
	if unit == nil {
		t.Fatal("unit 80 missing")
	}
	if unit.OversubscriptionPolicy != "guarantee-rate" {
		t.Fatalf("expected OversubscriptionPolicy=guarantee-rate; got %q",
			unit.OversubscriptionPolicy)
	}
	if unit.OversubscriptionGuaranteeFraction != 0.7 {
		t.Fatalf("expected OversubscriptionGuaranteeFraction=0.7; got %f",
			unit.OversubscriptionGuaranteeFraction)
	}
}

// TestValidateCoSOversubscriptionWarningResolvesTransmitRateForms11810 pins
// the warning's claim calculation to the dataplane's byte-rate resolution.
// The percent-only cases omit `exact` deliberately: exact is not an
// eligibility gate for the aggregate demand warning.
func TestValidateCoSOversubscriptionWarningResolvesTransmitRateForms11810(t *testing.T) {
	rows := []struct {
		name        string
		rates       [][]string
		wantBPS     uint64
		wantWarning bool
	}{
		{
			name: "percent oversubscription",
			rates: [][]string{
				{"percent", "60"},
				{"percent", "60"},
			},
			wantBPS:     1_500_000_000,
			wantWarning: true,
		},
		{
			name: "mixed absolute and percent oversubscription",
			rates: [][]string{
				{"8g"},
				{"percent", "30"},
			},
			wantBPS:     1_375_000_000,
			wantWarning: true,
		},
		{
			name: "overcommitted percent leaves zero remainder",
			rates: [][]string{
				{"percent", "60"},
				{"percent", "60"},
				{"remainder"},
			},
			wantBPS:     1_500_000_000,
			wantWarning: true,
		},
		{
			name: "remainder fills unused shaping capacity",
			rates: [][]string{
				{"percent", "40"},
				{"remainder"},
			},
		},
		{
			name: "under-capacity percent",
			rates: [][]string{
				{"percent", "40"},
			},
		},
	}

	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			lines := []string{
				"set class-of-service interfaces ge-0/0/2 unit 80 shaping-rate 10g",
				"set class-of-service interfaces ge-0/0/2 unit 80 scheduler-map edge-map",
				"set system dataplane-type userspace",
			}
			for i, rate := range row.rates {
				scheduler := fmt.Sprintf("sched-%d", i)
				forwardingClass := fmt.Sprintf("class-%d", i)
				lines = append(lines,
					fmt.Sprintf("set class-of-service forwarding-classes queue %d %s", i+1, forwardingClass),
					fmt.Sprintf("set class-of-service schedulers %s transmit-rate %s", scheduler, strings.Join(rate, " ")),
					fmt.Sprintf("set class-of-service scheduler-maps edge-map forwarding-class %s scheduler %s", forwardingClass, scheduler),
				)
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
			if err := SchemaValidate(tree, nil); err != nil {
				t.Fatalf("SchemaValidate: %v", err)
			}
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}

			var gotWarning string
			for _, warning := range cfg.Warnings {
				if strings.Contains(warning, "sum of configured transmit-rate claims") {
					gotWarning = warning
					break
				}
			}
			if !row.wantWarning {
				if gotWarning != "" {
					t.Fatalf("unexpected oversubscription warning: %s", gotWarning)
				}
				return
			}
			if gotWarning == "" {
				t.Fatalf("expected oversubscription warning; got: %v", cfg.Warnings)
			}
			if want := fmt.Sprintf("(%d B/s) exceeds shaping-rate (1250000000 B/s)", row.wantBPS); !strings.Contains(gotWarning, want) {
				t.Fatalf("warning %q does not report the resolved sum and shaping-rate %q", gotWarning, want)
			}
		})
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
    schedulers {
        be-sched {
            transmit-rate percent 10;
        }
    }
    scheduler-maps {
        edge-map {
            forwarding-class best-effort {
                scheduler be-sched;
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
	// #7337: this fixture deliberately carries a dangling class-of-service
	// INTERFACE reference (`dscp missing-classifier`), now hard-rejected at
	// strict commit by validateClassOfServiceInterfaceRefsStrict — the same
	// treatment the scheduler-map reference already gets, per the note below.
	// Compile on the TOLERANT path so the warnings under test are still
	// produced; the strict rejection has its own coverage.
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("compile error (lenient): %v", err)
	}
	warnings := strings.Join(cfg.Warnings, "\n")
	// A dangling scheduler reference in a scheduler-map is no longer
	// warn-only: it is hard-rejected at strict commit
	// (validateClassOfServiceSchedulerMapRefsStrict), covered by
	// TestSchedulerMapDanglingSchedulerRejectedStrict. The scheduler-map
	// above references the DEFINED scheduler "be-sched" so this
	// warn-collection test still exercises the surviving warn-only refs
	// (undefined forwarding-class + undefined classifier / rewrite refs).
	if strings.Contains(warnings, `references undefined scheduler`) {
		t.Fatalf("did not expect an undefined-scheduler warning for a defined scheduler, got: %s", warnings)
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
	// #3995: classifier loss-priority now drives egress rewrite selection but
	// still warns about the remaining drop-precedence / WRED gap.
	if !strings.Contains(warnings, "classifier loss-priority now drives egress dscp rewrite-rule selection") {
		t.Fatalf("expected classifier loss-priority warning, got: %s", warnings)
	}
	// #3995: rewrite-rule loss-priority is now ENFORCED, so its old
	// accepted-but-inert warning must NOT appear.
	if strings.Contains(warnings, "dscp rewrite-rule loss-priority is accepted for compatibility but not yet enforced") {
		t.Fatalf("did not expect the stale rewrite-rule loss-priority warning, got: %s", warnings)
	}
	if strings.Contains(warnings, "class-of-service shaping, classifier attachment, and dscp rewrite-rule attachment are only implemented in the userspace dataplane") {
		t.Fatalf("unexpected dataplane warning for default userspace path: %s", warnings)
	}
}

// TestSchedulerMapDanglingSchedulerRejectedStrict pins the #1960
// strict-on-commit / lenient-on-load contract for a scheduler-map entry
// that references an undefined scheduler. Before the gate the reference
// was warn-only at commit and then fail-open in the dataplane (the class
// silently lost its guarantee and won the maximum best-effort surplus
// share). The strict commit path must now REJECT it; the tolerant load /
// peer-sync path must DOWNGRADE it to a warning so an already-persisted
// or peer-synced config still boots.
func TestSchedulerMapDanglingSchedulerRejectedStrict(t *testing.T) {
	const danglingRef = `class-of-service {
    forwarding-classes {
        queue 0 best-effort;
        queue 1 ef;
    }
    schedulers {
        ef-sched {
            transmit-rate percent 30;
            priority strict-high;
        }
    }
    scheduler-maps {
        edge-map {
            forwarding-class ef {
                scheduler ef-typo;
            }
        }
    }
    interfaces {
        ge-0/0/1 {
            unit 0 {
                shaping-rate 10g;
                scheduler-map edge-map;
            }
        }
    }
}
`
	compile := func(t *testing.T, input string) *ConfigTree {
		t.Helper()
		tree, errs := NewParser(input).Parse()
		if len(errs) > 0 {
			t.Fatalf("parse errors: %v", errs)
		}
		return tree
	}

	// Strict commit path rejects the dangling reference.
	strictTree := compile(t, danglingRef)
	_, err := CompileConfig(strictTree)
	if err == nil {
		t.Fatal("CompileConfig accepted a scheduler-map with a dangling scheduler reference; want rejection")
	}
	if !strings.Contains(err.Error(), `references undefined scheduler "ef-typo"`) {
		t.Fatalf("strict error missing the dangling-scheduler substring: %q", err.Error())
	}

	// Tolerant load path downgrades to a warning and still compiles.
	lenientTree := compile(t, danglingRef)
	cfg, err := CompileConfigLenient(lenientTree)
	if err != nil {
		t.Fatalf("CompileConfigLenient rejected a persistable config with a dangling scheduler reference (#1960 brick): %v", err)
	}
	warnings := strings.Join(cfg.Warnings, "\n")
	if !strings.Contains(warnings, "scheduler-map reference (downgraded to warning on tolerant path)") ||
		!strings.Contains(warnings, `references undefined scheduler "ef-typo"`) {
		t.Fatalf("lenient path missing the downgraded scheduler-map warning, got: %s", warnings)
	}

	// A valid scheduler reference is unchanged on BOTH paths.
	validInput := strings.Replace(danglingRef, "scheduler ef-typo;", "scheduler ef-sched;", 1)
	if _, err := CompileConfig(compile(t, validInput)); err != nil {
		t.Fatalf("CompileConfig rejected a scheduler-map with a DEFINED scheduler: %v", err)
	}
	validCfg, err := CompileConfigLenient(compile(t, validInput))
	if err != nil {
		t.Fatalf("CompileConfigLenient rejected a valid scheduler-map: %v", err)
	}
	if strings.Contains(strings.Join(validCfg.Warnings, "\n"), "references undefined scheduler") {
		t.Fatalf("unexpected undefined-scheduler warning for a defined scheduler: %v", validCfg.Warnings)
	}
}

// #3995: an operator typo in a class-of-service loss-priority value (e.g.
// `medum-low` for `medium-low`) must be REJECTED at commit / commit-check, not
// silently threaded to the dataplane and applied as the SAFE default LOW /
// wildcard (wrong QoS, silently). The tolerant load / peer-sync path downgrades
// it to a warning so an already-persisted config still boots (#1960 no-brick).
//
// FAIL-ON-REVERT: without validateClassOfServiceLossPriorityStrict the strict
// CompileConfig would ACCEPT `medum-low` (it was never validated), and the
// dataplane's cos_loss_priority_index would silently map it to LOW.
func TestCoSLossPriorityTypoRejectedStrict(t *testing.T) {
	compile := func(t *testing.T, input string) *ConfigTree {
		t.Helper()
		tree, errs := NewParser(input).Parse()
		if len(errs) > 0 {
			t.Fatalf("parse errors: %v", errs)
		}
		return tree
	}

	cases := []struct {
		name    string
		block   string
		errFrag string
	}{
		{
			name: "rewrite-rule",
			block: `    rewrite-rules {
        dscp rw {
            forwarding-class voice {
                loss-priority medum-low {
                    code-point ef;
                }
            }
        }
    }`,
			errFrag: `rewrite-rules dscp "rw" forwarding-class "voice" has unrecognized loss-priority "medum-low"`,
		},
		{
			name: "dscp-classifier",
			block: `    classifiers {
        dscp ba {
            forwarding-class voice {
                loss-priority medum-low code-points ef;
            }
        }
    }`,
			errFrag: `classifiers dscp "ba" forwarding-class "voice" has unrecognized loss-priority "medum-low"`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := "class-of-service {\n" +
				"    forwarding-classes {\n" +
				"        queue 0 best-effort;\n" +
				"        queue 5 voice;\n" +
				"    }\n" +
				tc.block + "\n}\n"

			// Strict commit path rejects the typo, naming the bad value and the
			// valid set.
			_, err := CompileConfig(compile(t, input))
			if err == nil {
				t.Fatal("CompileConfig accepted an unrecognized loss-priority; want rejection")
			}
			if !strings.Contains(err.Error(), tc.errFrag) {
				t.Fatalf("strict error missing the typo substring: %q", err.Error())
			}
			if !strings.Contains(err.Error(), "must be one of: low, medium-low, medium-high, high") {
				t.Fatalf("strict error missing the valid-value set: %q", err.Error())
			}

			// Tolerant load path downgrades to a warning and still compiles
			// (#1960 no-brick).
			cfg, err := CompileConfigLenient(compile(t, input))
			if err != nil {
				t.Fatalf("CompileConfigLenient rejected a persistable config with a bad loss-priority (#1960 brick): %v", err)
			}
			warnings := strings.Join(cfg.Warnings, "\n")
			if !strings.Contains(warnings, "loss-priority (downgraded to warning on tolerant path)") ||
				!strings.Contains(warnings, "unrecognized loss-priority") {
				t.Fatalf("lenient path missing the downgraded loss-priority warning, got: %s", warnings)
			}

			// A valid loss-priority is unchanged on BOTH paths.
			validInput := strings.Replace(input, "medum-low", "medium-low", 1)
			if _, err := CompileConfig(compile(t, validInput)); err != nil {
				t.Fatalf("CompileConfig rejected a VALID loss-priority medium-low: %v", err)
			}
			validCfg, err := CompileConfigLenient(compile(t, validInput))
			if err != nil {
				t.Fatalf("CompileConfigLenient rejected a valid loss-priority: %v", err)
			}
			if strings.Contains(strings.Join(validCfg.Warnings, "\n"), "unrecognized loss-priority") {
				t.Fatalf("unexpected unrecognized-loss-priority warning for a valid value: %v", validCfg.Warnings)
			}
		})
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

// TestValidateClassOfServiceQueueRange pins the #4594 behavior split: an
// out-of-range forwarding-class queue is HARD-REJECTED on the strict commit /
// commit-check path (it used to only warn + commit, while the userspace helper
// fail-closed the whole CoS snapshot on CosQueueIdOutOfRange and kept stale
// state), but DOWNGRADED to a warning on the tolerant load / peer-sync path so
// an already-persisted config still boots (#1960 no-brick).
func TestValidateClassOfServiceQueueRange(t *testing.T) {
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
	// Strict commit path: hard-reject.
	if _, err := CompileConfig(tree); err == nil ||
		!strings.Contains(err.Error(), `forwarding-class "invalid-class" uses out-of-range queue 300`) {
		t.Fatalf("strict commit must reject out-of-range queue 300, got: %v", err)
	}
	// Tolerant load / peer-sync path: warn, do not brick.
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient load must not brick on out-of-range queue: %v", err)
	}
	warnings := strings.Join(cfg.Warnings, "\n")
	if !strings.Contains(warnings, `forwarding-class "invalid-class" uses out-of-range queue 300`) {
		t.Fatalf("expected queue range warning on tolerant path, got: %s", warnings)
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

// TestCompileClassOfServiceRejectsOutOfRangeDSCPCodePoint proves the #2447
// fix: a DSCP code-point outside the 6-bit domain (0..63) is REJECTED at
// commit with a clear operator error, rather than being silently dropped at
// the Go parse layer (pre-fix) or masked `dscp & 0x3f` into a different
// traffic class by the dataplane builder (110 → 46).
//
// Fail-on-revert: restore the pre-fix `v >= 0 && v <= 63` silent-skip in
// expandCoSCodePointToken (returning nil instead of an error) and this test
// goes RED — the bad config compiles and the classifier installs with the
// out-of-range entry dropped (no commit error).
func TestCompileClassOfServiceRejectsOutOfRangeDSCPCodePoint(t *testing.T) {
	tree := &ConfigTree{}
	lines := []string{
		"set class-of-service forwarding-classes queue 0 best-effort",
		"set class-of-service classifiers dscp wan-classifier forwarding-class best-effort loss-priority low code-points 110",
		"set system dataplane-type userspace",
	}
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
		t.Fatal("expected compile to reject DSCP code-point 110, got nil error")
	}
	if !strings.Contains(err.Error(), "110") || !strings.Contains(err.Error(), "0..63") {
		t.Errorf("error must name the out-of-range value 110 and the 0..63 range, got: %s", err.Error())
	}
}

// TestCompileClassOfServiceRejectsOutOfRangePCPCodePoint proves the #2447
// fix for the 802.1p path: a code-point outside the 3-bit PCP domain (0..7)
// is REJECTED at commit rather than silently dropped (pre-fix) or clamped
// `pcp.min(7)` into a different traffic class by the dataplane builder (9 → 7).
func TestCompileClassOfServiceRejectsOutOfRangePCPCodePoint(t *testing.T) {
	tree := &ConfigTree{}
	lines := []string{
		"set class-of-service forwarding-classes queue 0 best-effort",
		"set class-of-service classifiers ieee-802.1 wan-pcp forwarding-class best-effort loss-priority low code-points 9",
		"set system dataplane-type userspace",
	}
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
		t.Fatal("expected compile to reject 802.1p code-point 9, got nil error")
	}
	if !strings.Contains(err.Error(), "9") || !strings.Contains(err.Error(), "0..7") {
		t.Errorf("error must name the out-of-range value 9 and the 0..7 range, got: %s", err.Error())
	}
}

// TestCompileClassOfServiceRejectsOutOfRangeRewriteCodePoint proves a DSCP
// rewrite-rule code-point > 63 is rejected (same domain, same builder hazard).
func TestCompileClassOfServiceRejectsOutOfRangeRewriteCodePoint(t *testing.T) {
	tree := &ConfigTree{}
	lines := []string{
		"set class-of-service forwarding-classes queue 0 best-effort",
		"set class-of-service rewrite-rules dscp wan-rewrite forwarding-class best-effort loss-priority low code-point 200",
		"set system dataplane-type userspace",
	}
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
		t.Fatal("expected compile to reject rewrite code-point 200, got nil error")
	}
	if !strings.Contains(err.Error(), "200") || !strings.Contains(err.Error(), "0..63") {
		t.Errorf("error must name the out-of-range value 200 and the 0..63 range, got: %s", err.Error())
	}
}

// TestCompileClassOfServiceAcceptsBoundaryCodePoints confirms the valid
// domain still compiles unchanged: DSCP 63 (max) and PCP 7 (max), plus the
// `ef` alias (46), all build a classifier entry with the expected value.
func TestCompileClassOfServiceAcceptsBoundaryCodePoints(t *testing.T) {
	tree := &ConfigTree{}
	lines := []string{
		"set class-of-service forwarding-classes queue 0 best-effort",
		"set class-of-service classifiers dscp wan-classifier forwarding-class best-effort loss-priority low code-points 63",
		"set class-of-service classifiers dscp wan-classifier forwarding-class best-effort loss-priority high code-points ef",
		"set class-of-service classifiers ieee-802.1 wan-pcp forwarding-class best-effort loss-priority low code-points 7",
		"set system dataplane-type userspace",
	}
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
		t.Fatalf("compile of in-range boundary code-points: %v", err)
	}
	dscp := cfg.ClassOfService.DSCPClassifiers["wan-classifier"]
	if dscp == nil {
		t.Fatal("expected wan-classifier")
	}
	var sawDSCP63, sawDSCP46 bool
	for _, e := range dscp.Entries {
		for _, v := range e.DSCPValues {
			if v == 63 {
				sawDSCP63 = true
			}
			if v == 46 {
				sawDSCP46 = true
			}
		}
	}
	if !sawDSCP63 || !sawDSCP46 {
		t.Fatalf("expected DSCP 63 and 46 (ef) entries, got %#v", dscp.Entries)
	}
	pcp := cfg.ClassOfService.IEEE8021Classifiers["wan-pcp"]
	if pcp == nil || len(pcp.Entries) != 1 || len(pcp.Entries[0].CodePoints) != 1 || pcp.Entries[0].CodePoints[0] != 7 {
		t.Fatalf("expected wan-pcp code-point 7, got %#v", pcp)
	}
}

// buildCoSTree4021 applies flat-set lines via ParseSetCommand + SetPath (the
// only correct way to test set syntax; NewParser merges newline-separated set
// lines into one node).
func buildCoSTree4021(t *testing.T, lines []string) *ConfigTree {
	t.Helper()
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
	return tree
}

// #4021: an interface-level CoS binding (`class-of-service interfaces geX
// scheduler-map M` with no `unit`) must produce a LIVE per-unit binding. On
// revert (compiler reads only per-unit `unit` children) cos.Interfaces[geX]
// is nil and this test goes RED.
func TestCompileClassOfServiceInterfaceLevelBinding4021(t *testing.T) {
	lines := []string{
		"set class-of-service forwarding-classes queue 0 best-effort",
		"set class-of-service schedulers be-sched transmit-rate 5g",
		"set class-of-service scheduler-maps edge-map forwarding-class best-effort scheduler be-sched",
		"set class-of-service classifiers dscp wan-classifier forwarding-class best-effort loss-priority low code-points be",
		"set class-of-service rewrite-rules dscp wan-rewrite forwarding-class best-effort loss-priority low code-point ef",
		// Physical interface carries logical units 0 and 80.
		"set interfaces ge-0/0/2 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/2 unit 80 vlan-id 80",
		// Interface-level (no unit) CoS binding.
		"set class-of-service interfaces ge-0/0/2 scheduler-map edge-map",
		"set class-of-service interfaces ge-0/0/2 shaping-rate 9g",
		"set class-of-service interfaces ge-0/0/2 classifiers dscp wan-classifier",
		"set class-of-service interfaces ge-0/0/2 rewrite-rules dscp wan-rewrite",
		"set system dataplane-type userspace",
	}
	tree := buildCoSTree4021(t, lines)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	if serr := SchemaValidate(tree, cfg); serr != nil {
		t.Fatalf("SchemaValidate error: %v", serr)
	}
	ci := cfg.ClassOfService.Interfaces["ge-0/0/2"]
	if ci == nil {
		t.Fatal("interface-level CoS binding DROPPED: cos.Interfaces[ge-0/0/2] == nil")
	}
	if ci.Level == nil || ci.Level.SchedulerMap != "edge-map" {
		t.Fatalf("expected Level.SchedulerMap=edge-map, got %#v", ci.Level)
	}
	// Interface-level applies to EVERY configured logical unit (0 and 80).
	for _, unitNum := range []int{0, 80} {
		u := ci.Units[unitNum]
		if u == nil {
			t.Fatalf("unit %d: interface-level binding did not fold in", unitNum)
		}
		if u.SchedulerMap != "edge-map" {
			t.Fatalf("unit %d scheduler-map = %q, want edge-map", unitNum, u.SchedulerMap)
		}
		if u.ShapingRateBytes != parseBandwidthLimit("9g") {
			t.Fatalf("unit %d shaping-rate = %d, want %d", unitNum, u.ShapingRateBytes, parseBandwidthLimit("9g"))
		}
		if u.DSCPClassifier != "wan-classifier" {
			t.Fatalf("unit %d dscp classifier = %q, want wan-classifier", unitNum, u.DSCPClassifier)
		}
		if u.DSCPRewriteRule != "wan-rewrite" {
			t.Fatalf("unit %d dscp rewrite = %q, want wan-rewrite", unitNum, u.DSCPRewriteRule)
		}
	}
}

// #4021: a unit-level binding overrides the interface-level one PER KNOB,
// while knobs the unit does not set still inherit the interface-level value.
func TestCompileClassOfServiceUnitOverridesInterfaceLevel4021(t *testing.T) {
	lines := []string{
		"set class-of-service forwarding-classes queue 0 best-effort",
		"set class-of-service schedulers be-sched transmit-rate 5g",
		"set class-of-service scheduler-maps edge-map forwarding-class best-effort scheduler be-sched",
		"set class-of-service scheduler-maps unit-map forwarding-class best-effort scheduler be-sched",
		"set interfaces ge-0/0/2 unit 0 family inet address 10.0.0.1/24",
		// Interface-level defaults.
		"set class-of-service interfaces ge-0/0/2 scheduler-map edge-map",
		"set class-of-service interfaces ge-0/0/2 shaping-rate 9g",
		// Unit-level overrides scheduler-map only; shaping-rate inherits.
		"set class-of-service interfaces ge-0/0/2 unit 0 scheduler-map unit-map",
		"set system dataplane-type userspace",
	}
	tree := buildCoSTree4021(t, lines)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	u := cfg.ClassOfService.Interfaces["ge-0/0/2"].Units[0]
	if u == nil {
		t.Fatal("expected ge-0/0/2 unit 0")
	}
	if u.SchedulerMap != "unit-map" {
		t.Fatalf("unit-level override lost: scheduler-map = %q, want unit-map", u.SchedulerMap)
	}
	if u.ShapingRateBytes != parseBandwidthLimit("9g") {
		t.Fatalf("interface-level shaping-rate not inherited: got %d, want %d", u.ShapingRateBytes, parseBandwidthLimit("9g"))
	}
}

// #4021: the per-unit-only form is unchanged by the fix — no interface-level
// Level, binding lands on the named unit only.
func TestCompileClassOfServicePerUnitStillWorks4021(t *testing.T) {
	lines := []string{
		"set class-of-service forwarding-classes queue 0 best-effort",
		"set class-of-service schedulers be-sched transmit-rate 5g",
		"set class-of-service scheduler-maps edge-map forwarding-class best-effort scheduler be-sched",
		"set interfaces ge-0/0/2 unit 0 family inet address 10.0.0.1/24",
		"set class-of-service interfaces ge-0/0/2 unit 0 scheduler-map edge-map",
		"set system dataplane-type userspace",
	}
	tree := buildCoSTree4021(t, lines)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	ci := cfg.ClassOfService.Interfaces["ge-0/0/2"]
	if ci == nil {
		t.Fatal("expected ge-0/0/2 CoS")
	}
	if ci.Level != nil {
		t.Fatalf("per-unit-only config must not synthesize an interface-level binding, got %#v", ci.Level)
	}
	if ci.Units[0] == nil || ci.Units[0].SchedulerMap != "edge-map" {
		t.Fatalf("per-unit scheduler-map = %#v, want edge-map", ci.Units[0])
	}
}

// cosWarnings returns the compile warnings that mention class-of-service.
func cosWarnings(cfg *Config) []string {
	var out []string
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "class-of-service") {
			out = append(out, w)
		}
	}
	return out
}

// #hb166 G-6: a CoS binding on an interface that is NOT configured under
// [interfaces] is a silent no-op (the dataplane applier only visits CoS
// bindings that resolve against cfg.Interfaces). Commit must warn.
// RED on revert: the warn validator never checks interface existence, so
// no warning is emitted and the operator believes CoS is applied.
func TestCompileClassOfServiceBindingNonexistentInterfaceWarnsHB166G6(t *testing.T) {
	lines := []string{
		// reth0 is shaped but never configured under [interfaces].
		"set class-of-service interfaces reth0 unit 80 shaping-rate 3g",
		"set system dataplane-type userspace",
	}
	tree := buildCoSTree4021(t, lines)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	var found bool
	for _, w := range cosWarnings(cfg) {
		if strings.Contains(w, "interface reth0 is bound but not configured under [interfaces]") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an inert-CoS-binding warning for reth0; got %v", cosWarnings(cfg))
	}
}

// #hb166 G-6: the interface exists but the bound logical unit does not.
func TestCompileClassOfServiceBindingUnconfiguredUnitWarnsHB166G6(t *testing.T) {
	lines := []string{
		// ge-0/0/2 is configured with unit 0 only; the CoS binding targets
		// unit 5 which is never configured.
		"set interfaces ge-0/0/2 unit 0 family inet address 10.0.0.1/24",
		"set class-of-service interfaces ge-0/0/2 unit 5 shaping-rate 3g",
		"set system dataplane-type userspace",
	}
	tree := buildCoSTree4021(t, lines)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	var found bool
	for _, w := range cosWarnings(cfg) {
		if strings.Contains(w, "unit 5 is bound but unit 5 is not configured") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an inert-CoS-unit warning for ge-0/0/2 unit 5; got %v", cosWarnings(cfg))
	}
}

// #hb166 G-6: a fully-configured interface + unit must NOT warn.
func TestCompileClassOfServiceBindingConfiguredInterfaceNoWarnHB166G6(t *testing.T) {
	lines := []string{
		"set interfaces ge-0/0/2 unit 0 family inet address 10.0.0.1/24",
		"set class-of-service interfaces ge-0/0/2 unit 0 shaping-rate 3g",
		"set system dataplane-type userspace",
	}
	tree := buildCoSTree4021(t, lines)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	for _, w := range cosWarnings(cfg) {
		if strings.Contains(w, "bound but not configured") || strings.Contains(w, "is bound but unit") {
			t.Fatalf("configured interface/unit must not warn inert; got %q", w)
		}
	}
}

func TestCompileClassOfServiceBindOnlyTunnelWarningIsNarrow11788(t *testing.T) {
	tests := []struct {
		name                        string
		zoneAuthoredTunnelUnit      bool
		wantMissingInterfaceWarning bool
	}{
		{
			name:                        "zone-authored bound tunnel unit",
			zoneAuthoredTunnelUnit:      true,
			wantMissingInterfaceWarning: false,
		},
		{
			name:                        "bound tunnel unit without zone reference",
			zoneAuthoredTunnelUnit:      false,
			wantMissingInterfaceWarning: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lines := []string{
				"set security ipsec vpn vpn1 bind-interface st0.1",
				"set class-of-service interfaces st0 unit 1 shaping-rate 3g",
				"set system dataplane-type userspace",
			}
			if tc.zoneAuthoredTunnelUnit {
				lines = append(lines,
					"set security zones security-zone vpn interfaces st0.1",
					"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
					"set security zones security-zone trust interfaces ge-0/0/0.0")
			}
			cfg, err := CompileConfig(buildCoSTree4021(t, lines))
			if err != nil {
				t.Fatalf("compile error: %v", err)
			}
			if cfg.Interfaces.Interfaces["st0"] != nil {
				t.Fatal("premise broken: st0 unexpectedly has an [interfaces] stanza")
			}
			if _, ok := cfg.SecureTunnelNetdevForRef("st0.1"); !ok {
				t.Fatal("premise broken: st0.1 is not a bound secure-tunnel unit")
			}
			unit := cfg.ClassOfService.Interfaces["st0"].Units[1]
			if unit == nil {
				t.Fatal("premise broken: CoS unit st0.1 was not compiled")
			}
			var found bool
			for _, warning := range cosWarnings(cfg) {
				if strings.Contains(warning, "class-of-service interface st0 is bound but not configured under [interfaces]") {
					found = true
				}
			}
			if found != tc.wantMissingInterfaceWarning {
				t.Fatalf("missing-interface warning found = %t, want %t; warnings: %v",
					found, tc.wantMissingInterfaceWarning, cosWarnings(cfg))
			}
		})
	}
}

// #hb166 G-10: a unit that overrides shaping-rate but sets no burst-size
// must NOT inherit the interface-level burst-size (a shaper is a coupled
// (rate, burst) pair). RED on revert: mergeCoSInterfaceLevelInto inherits
// level.BurstSizeBytes unconditionally, pairing a level burst with a unit
// rate.
func TestCompileClassOfServiceUnitRateOverrideDropsLevelBurstHB166G10(t *testing.T) {
	lines := []string{
		"set interfaces ge-0/0/2 unit 0 family inet address 10.0.0.1/24",
		// Interface-level shaper: 100m with an explicit 200000-byte burst.
		"set class-of-service interfaces ge-0/0/2 shaping-rate 100m burst-size 200000",
		// Unit overrides the rate to 1g and sets NO burst.
		"set class-of-service interfaces ge-0/0/2 unit 0 shaping-rate 1g",
		"set system dataplane-type userspace",
	}
	tree := buildCoSTree4021(t, lines)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	u := cfg.ClassOfService.Interfaces["ge-0/0/2"].Units[0]
	if u == nil {
		t.Fatal("expected ge-0/0/2 unit 0")
	}
	if u.ShapingRateBytes != parseBandwidthLimit("1g") {
		t.Fatalf("unit shaping-rate override lost: got %d, want %d", u.ShapingRateBytes, parseBandwidthLimit("1g"))
	}
	if u.BurstSizeBytes != 0 {
		t.Fatalf("unit rate override must not inherit the level burst-size: got %d, want 0 (dataplane applies its rate-independent floor)", u.BurstSizeBytes)
	}
}

// #hb166 G-10: a unit that inherits the rate (sets no shaping-rate) still
// inherits BOTH the level rate and the level burst-size as a pair.
func TestCompileClassOfServiceUnitInheritsLevelRateAndBurstHB166G10(t *testing.T) {
	lines := []string{
		"set interfaces ge-0/0/2 unit 0 family inet address 10.0.0.1/24",
		"set class-of-service interfaces ge-0/0/2 shaping-rate 100m burst-size 200000",
		// Unit overrides only the scheduler-map; shaper inherits fully.
		"set class-of-service forwarding-classes queue 0 best-effort",
		"set class-of-service schedulers be-sched transmit-rate 5g",
		"set class-of-service scheduler-maps m forwarding-class best-effort scheduler be-sched",
		"set class-of-service interfaces ge-0/0/2 unit 0 scheduler-map m",
		"set system dataplane-type userspace",
	}
	tree := buildCoSTree4021(t, lines)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	u := cfg.ClassOfService.Interfaces["ge-0/0/2"].Units[0]
	if u == nil {
		t.Fatal("expected ge-0/0/2 unit 0")
	}
	if u.ShapingRateBytes != parseBandwidthLimit("100m") {
		t.Fatalf("unit must inherit level rate: got %d, want %d", u.ShapingRateBytes, parseBandwidthLimit("100m"))
	}
	if u.BurstSizeBytes != parseBurstSizeLimit("200000") {
		t.Fatalf("unit inheriting the rate must also inherit the level burst: got %d, want %d", u.BurstSizeBytes, parseBurstSizeLimit("200000"))
	}
}

// #9366: `transmit-rate percent <n> exact` and `transmit-rate remainder exact`
// were REJECTED AT COMMIT. Both set `TransmitRateExact = true` and leave
// `TransmitRateBytes` at 0 — their value lives in `TransmitRatePercent` /
// `TransmitRateRemainder` — so a gate reading only the absolute byte field
// fired, and told the operator to supply the exact rate they had just written
// as a percentage or a remainder.
//
// The gate predates #4228 Gap 2 (percent) and #6846 (remainder), which made
// both forms first-class, and was not revisited. The DATAPLANE already resolves
// both: `forwarding_build/cos.rs` derives `guarantee_enabled` from
// `cos_effective_transmit_rate_bytes(...).or_else(remainder)`. This Go gate was
// the sole blocker on a shipped, documented fairness feature.
//
// Fail-on-revert: restore `sched.TransmitRateBytes == 0` and both accept rows
// go red with the commit refusal.
func TestEqualFlowEnforcementAcceptsEveryRateForm9366(t *testing.T) {
	base := []string{
		"set class-of-service interfaces ge-0/0/2 unit 0 shaping-rate 1g",
		"set class-of-service interfaces ge-0/0/2 unit 0 scheduler-map sm",
		"set class-of-service scheduler-maps sm forwarding-class ef scheduler ef-sched",
		"set class-of-service forwarding-classes queue 5 ef",
	}
	for _, tc := range []struct {
		name       string
		rate       []string
		wantReject bool
	}{
		{
			name: "absolute exact — accepted before and after",
			rate: []string{"set class-of-service schedulers ef-sched transmit-rate 500m exact"},
		},
		{
			name: "percent exact — THE DEFECT",
			rate: []string{"set class-of-service schedulers ef-sched transmit-rate percent 50 exact"},
		},
		{
			name: "remainder exact — THE DEFECT",
			rate: []string{"set class-of-service schedulers ef-sched transmit-rate remainder exact"},
		},
		{
			// NARROWNESS: still refused. The feature needs a guarantee to
			// enforce against, and a percent rate WITHOUT `exact` does not
			// express one. Without this row the change is satisfied by a gate
			// that accepts everything.
			name:       "percent without exact — must still be refused",
			rate:       []string{"set class-of-service schedulers ef-sched transmit-rate percent 50"},
			wantReject: true,
		},
		{
			name:       "no transmit rate at all — must still be refused",
			rate:       nil,
			wantReject: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := &ConfigTree{}
			lines := append(append([]string{}, base...), tc.rate...)
			lines = append(lines, "set class-of-service schedulers ef-sched equal-flow-enforcement")
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
			if tc.wantReject {
				if err == nil {
					t.Fatal("committed clean; equal-flow-enforcement with no exact " +
						"guarantee has nothing to enforce against")
				}
				return
			}
			if err != nil {
				t.Fatalf("REJECTED a legitimate config: %v\n\nThe operator wrote the "+
					"rate this error says is missing, in a form the schema admits and "+
					"the dataplane resolves.", err)
			}
		})
	}
}

// #11785: an interface-level binding has no runtime target when its configured
// interface stanza has no logical units. Keep the warning scoped to that shape:
// a folded Level binding with units remains valid, while deleting the last unit
// must surface the now-inert binding.
func TestCompileClassOfServiceLevelBindingWithoutUnitsWarns11785(t *testing.T) {
	hasNoUnitWarning := func(cfg *Config) bool {
		for _, warning := range cosWarnings(cfg) {
			if strings.Contains(warning, "no configured logical units") {
				return true
			}
		}
		return false
	}

	t.Run("zero units", func(t *testing.T) {
		cfg, err := CompileConfig(buildCoSTree4021(t, []string{
			"set interfaces ge-0/0/2 mtu 1500",
			"set class-of-service interfaces ge-0/0/2 shaping-rate 3g",
		}))
		if err != nil {
			t.Fatalf("compile error: %v", err)
		}
		if ifCfg := cfg.Interfaces.Interfaces["ge-0/0/2"]; ifCfg == nil || len(ifCfg.Units) != 0 {
			t.Fatalf("fixture must configure ge-0/0/2 with zero units, got %#v", ifCfg)
		}
		if !hasNoUnitWarning(cfg) {
			t.Fatalf("interface-level CoS binding with zero units must warn; warnings=%v", cosWarnings(cfg))
		}
	})
	t.Run("Level nil", func(t *testing.T) {
		cfg, err := CompileConfig(buildCoSTree4021(t, []string{
			"set interfaces ge-0/0/2 mtu 1500",
			"set class-of-service interfaces ge-0/0/2 unit 0 shaping-rate 3g",
		}))
		if err != nil {
			t.Fatalf("compile error: %v", err)
		}
		cosIface := cfg.ClassOfService.Interfaces["ge-0/0/2"]
		if cosIface == nil || cosIface.Level != nil {
			t.Fatalf("fixture must compile a CoS interface without a Level binding, got %#v", cosIface)
		}
		if ifCfg := cfg.Interfaces.Interfaces["ge-0/0/2"]; ifCfg == nil || len(ifCfg.Units) != 0 {
			t.Fatalf("fixture must configure ge-0/0/2 with zero units, got %#v", ifCfg)
		}
		if hasNoUnitWarning(cfg) {
			t.Fatalf("unit-only CoS binding must not trigger the Level-only warning; warnings=%v", cosWarnings(cfg))
		}
	})

	t.Run("configured unit", func(t *testing.T) {
		cfg, err := CompileConfig(buildCoSTree4021(t, []string{
			"set interfaces ge-0/0/2 unit 0 family inet address 10.0.0.1/24",
			"set class-of-service interfaces ge-0/0/2 shaping-rate 3g",
		}))
		if err != nil {
			t.Fatalf("compile error: %v", err)
		}
		if hasNoUnitWarning(cfg) {
			t.Fatalf("Level binding folded onto a configured unit must not warn; warnings=%v", cosWarnings(cfg))
		}
	})
	t.Run("missing interfaces stanza", func(t *testing.T) {
		cfg, err := CompileConfig(buildCoSTree4021(t, []string{
			"set class-of-service interfaces ge-0/0/2 shaping-rate 3g",
		}))
		if err != nil {
			t.Fatalf("compile error: %v", err)
		}
		cosIface := cfg.ClassOfService.Interfaces["ge-0/0/2"]
		if cosIface == nil || cosIface.Level == nil {
			t.Fatalf("fixture must retain the interface-level binding, got %#v", cosIface)
		}
		if ifCfg := cfg.Interfaces.Interfaces["ge-0/0/2"]; ifCfg != nil {
			t.Fatalf("fixture must omit the [interfaces] stanza, got %#v", ifCfg)
		}
		if hasNoUnitWarning(cfg) {
			t.Fatalf("missing [interfaces] stanza must not trigger the zero-unit warning; warnings=%v", cosWarnings(cfg))
		}
	})

	t.Run("delete last unit", func(t *testing.T) {
		tree := buildCoSTree4021(t, []string{
			"set interfaces ge-0/0/2 unit 0 family inet address 10.0.0.1/24",
			"set interfaces ge-0/0/2 description keep-ifcfg",
			"set class-of-service interfaces ge-0/0/2 shaping-rate 3g",
		})
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("initial compile error: %v", err)
		}
		if hasNoUnitWarning(cfg) {
			t.Fatalf("Level binding with unit 0 must not warn before deletion; warnings=%v", cosWarnings(cfg))
		}
		path, err := ParseSetCommand("delete interfaces ge-0/0/2 unit 0")
		if err != nil {
			t.Fatalf("ParseSetCommand delete: %v", err)
		}
		if err := tree.DeletePath(path); err != nil {
			t.Fatalf("DeletePath last unit: %v", err)
		}
		cfg, err = CompileConfig(tree)
		if err != nil {
			t.Fatalf("compile after deleting last unit: %v", err)
		}
		if !hasNoUnitWarning(cfg) {
			t.Fatalf("deleting the last unit must expose the inert Level binding; warnings=%v", cosWarnings(cfg))
		}
	})
}

// The same zero-unit warning must identify both names when the Level binding
// carries the incompatible dscp + inet-precedence pair (#6847).
func TestCompileClassOfServiceZeroUnitLevelClassifierConflictWarningNames11785(t *testing.T) {
	lines := append(cosINetPrecedenceBase(),
		"set class-of-service classifiers dscp dscp-cl forwarding-class voice loss-priority low code-points 46",
		"set interfaces ge-0/0/2 mtu 1500",
		"set class-of-service interfaces ge-0/0/2 classifiers dscp dscp-cl",
		"set class-of-service interfaces ge-0/0/2 classifiers inet-precedence prec-cl",
	)
	cfg, err := CompileConfig(buildCoSTree4021(t, lines))
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	var zeroUnitWarning string
	for _, warning := range cosWarnings(cfg) {
		if strings.Contains(warning, "no configured logical units") {
			zeroUnitWarning = warning
			break
		}
	}
	if zeroUnitWarning == "" {
		t.Fatalf("zero-unit classifier warning was not emitted; warnings=%v", cosWarnings(cfg))
	}
	for _, want := range []string{
		"dscp classifier", "dscp-cl",
		"inet-precedence classifier", "prec-cl", "bind at most one",
	} {
		if !strings.Contains(zeroUnitWarning, want) {
			t.Errorf("zero-unit warning %q does not contain %q", zeroUnitWarning, want)
		}
	}
}
