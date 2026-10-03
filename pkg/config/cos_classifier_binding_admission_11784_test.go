package config

import (
	"strings"
	"testing"
)

func TestCoSClassifierOnlyAllNonBestEffortWarns11784(t *testing.T) {
	cfg := cosINetTree7080(t,
		"set class-of-service forwarding-classes queue 0 best-effort",
		"set class-of-service forwarding-classes queue 5 ef",
		"set class-of-service classifiers dscp cls forwarding-class ef loss-priority low code-points 46",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set class-of-service interfaces ge-0/0/0 unit 0 classifiers dscp cls",
	)
	warnings := ValidateConfig(cfg)
	if !cosHasWarning7080(warnings, "classifier binding(s)") ||
		!cosHasWarning7080(warnings, `forwarding-class "ef"`) ||
		!cosHasWarning7080(warnings, "no CoS knob admits") {
		t.Fatalf("classifier-only binding to a non-best-effort class must warn as inert; warnings=%v", warnings)
	}
}

func TestCoSRewriteOnlyAllNonBestEffortWarns11784(t *testing.T) {
	cfg := cosINetTree7080(t,
		"set class-of-service forwarding-classes queue 0 best-effort",
		"set class-of-service forwarding-classes queue 5 ef",
		"set class-of-service rewrite-rules dscp rw forwarding-class ef loss-priority low code-point 46",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set class-of-service interfaces ge-0/0/0 unit 0 rewrite-rules dscp rw",
	)
	warnings := ValidateConfig(cfg)
	if !cosHasWarning7080(warnings, `dscp rewrite-rule "rw"`) ||
		!cosHasWarning7080(warnings, `forwarding-class "ef"`) ||
		!cosHasWarning7080(warnings, "no CoS knob admits") {
		t.Fatalf("rewrite-only binding to a non-best-effort class must warn as inert; warnings=%v", warnings)
	}
}

func TestCoSRewriteOnlyWithShapingAdmissionDoesNotWarn11784(t *testing.T) {
	cfg := cosINetTree7080(t,
		"set class-of-service forwarding-classes queue 0 best-effort",
		"set class-of-service forwarding-classes queue 5 ef",
		"set class-of-service rewrite-rules dscp rw forwarding-class ef loss-priority low code-point 46",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set class-of-service interfaces ge-0/0/0 unit 0 shaping-rate 1g",
		"set class-of-service interfaces ge-0/0/0 unit 0 rewrite-rules dscp rw",
	)
	for _, warning := range ValidateConfig(cfg) {
		if strings.Contains(warning, "no CoS knob admits") {
			t.Fatalf("shaping-rate admits the unit; inert-binding warning should be silent: %q", warning)
		}
	}
}

func TestCoSClassifierWithShapingAdmissionKeepsBlackholeWarning11784(t *testing.T) {
	cfg := cosINetTree7080(t,
		"set class-of-service forwarding-classes queue 0 best-effort",
		"set class-of-service forwarding-classes queue 5 ef",
		"set class-of-service classifiers dscp cls forwarding-class ef loss-priority low code-points 46",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set class-of-service interfaces ge-0/0/0 unit 0 shaping-rate 1g",
		"set class-of-service interfaces ge-0/0/0 unit 0 classifiers dscp cls",
	)
	warnings := ValidateConfig(cfg)
	if cosHasWarning7080(warnings, "no CoS knob admits") {
		t.Fatalf("shaping-rate admits the unit; inert-binding warning should be silent: %v", warnings)
	}
	if !cosHasWarning7080(warnings, "no scheduler-map entry on this interface") {
		t.Fatalf("the existing admitted blackhole warning must remain visible: %v", warnings)
	}
}
