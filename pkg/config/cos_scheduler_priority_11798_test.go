package config

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func schedulerPriorityTree11798(t *testing.T) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, line := range []string{
		"set class-of-service schedulers broken priority ultra-high",
		"set class-of-service schedulers good priority high",
		"set class-of-service forwarding-classes queue 0 best-effort",
		"set class-of-service forwarding-classes queue 5 voice",
		"set class-of-service scheduler-maps edge-map forwarding-class voice scheduler broken",
		"set class-of-service scheduler-maps edge-map forwarding-class best-effort scheduler good",
		"set class-of-service interfaces ge-0/0/1 scheduler-map edge-map",
	} {
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

// TestCoSSchedulerPriorityStrictVsLenient11798 pins the priority wire contract:
// strict compilation rejects an unknown token, while tolerant compilation
// clears it to the Rust builder's empty/unset legacy-low default and names both
// the scheduler and original value in its warning.
func TestCoSSchedulerPriorityStrictVsLenient11798(t *testing.T) {
	if _, err := CompileConfig(schedulerPriorityTree11798(t)); err == nil ||
		!strings.Contains(err.Error(), "priority") || !strings.Contains(err.Error(), "ultra-high") {
		t.Fatalf("strict compile must reject the unknown scheduler priority, got %v", err)
	}

	cfg, err := CompileConfigLenient(schedulerPriorityTree11798(t))
	if err != nil {
		t.Fatalf("lenient compile must keep the persisted config bootable: %v", err)
	}
	broken := cfg.ClassOfService.Schedulers["broken"]
	if broken == nil || broken.Priority != "" {
		t.Fatalf("lenient compile priority = %+v, want unknown token cleared to empty", broken)
	}
	if good := cfg.ClassOfService.Schedulers["good"]; good == nil || good.Priority != "high" {
		t.Fatalf("lenient compile changed a valid scheduler priority: %+v", good)
	}
	warnings := strings.Join(cfg.Warnings, "\n")
	for _, want := range []string{"scheduler \"broken\"", "priority \"ultra-high\"", "#11798"} {
		if !strings.Contains(warnings, want) {
			t.Fatalf("lenient warnings missing %q: %v", want, cfg.Warnings)
		}
	}
}

func TestCoSSchedulerPriorityStrictGate11798(t *testing.T) {
	cos := &ClassOfServiceConfig{Schedulers: map[string]*CoSScheduler{
		"z-bad": {Name: "z-bad", Priority: "unknown-z"},
		"a-bad": {Name: "a-bad", Priority: "unknown-a"},
		"unset": {Name: "unset"},
	}}
	err := validateClassOfServiceSchedulerPriorityStrict(cos)
	if err == nil || !strings.Contains(err.Error(), `scheduler "a-bad"`) ||
		!strings.Contains(err.Error(), `"unknown-a"`) {
		t.Fatalf("strict gate must reject the first unknown priority in stable scheduler order, got %v", err)
	}
	for _, priority := range []string{"", "low", "medium-low", "medium-high", "high", "strict-high"} {
		if !CoSSchedulerPriorityValid(priority) {
			t.Errorf("CoSSchedulerPriorityValid(%q) = false", priority)
		}
	}
	for _, priority := range []string{"medium", "ultra-high"} {
		if CoSSchedulerPriorityValid(priority) {
			t.Errorf("CoSSchedulerPriorityValid(%q) = true", priority)
		}
	}
}

func readCoSParitySource11799(t *testing.T, parts ...string) string {
	t.Helper()
	path := filepath.Join(append([]string{"..", "..", "userspace-dp", "src"}, parts...)...)
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read CoS parity source %s: %v", path, err)
	}
	return string(body)
}

func readConfigParitySource11799(t *testing.T, name string) string {
	t.Helper()
	body, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read Go parity source %s: %v", name, err)
	}
	return string(body)
}

// TestCoSRustFailClosedInputVariantsHaveGoGates11799 is the input-value
// parity census for the Rust CoS snapshot errors. The two additional Cos*
// errors are explicitly runtime-derived structural checks (queue exhaustion
// after interface resolution and duplicate resolved ifindexes); the seven
// token/range errors must each stay paired with a Go strict gate and a Go
// fail-on-revert test.
func TestCoSRustFailClosedInputVariantsHaveGoGates11799(t *testing.T) {
	errorSource := readCoSParitySource11799(t, "policy_snapshot_error.rs")
	rustBuild := readCoSParitySource11799(t, "afxdp", "forwarding_build", "cos.rs")
	rustValidated := readCoSParitySource11799(t, "afxdp", "forwarding_build", "validated.rs")
	strictGo := readConfigParitySource11799(t, "compiler_validate_strict_cos.go")
	compilerGo := readConfigParitySource11799(t, "compiler_class_of_service.go")

	variantRE := regexp.MustCompile(`(?m)^    (Cos[A-Za-z0-9_]+)\s*\{`)
	var gotVariants []string
	for _, match := range variantRE.FindAllStringSubmatch(errorSource, -1) {
		gotVariants = append(gotVariants, match[1])
	}
	sort.Strings(gotVariants)
	wantVariants := []string{
		"CosDscpCodePointOutOfRange",
		"CosDscpRewriteCodePointOutOfRange",
		"CosDuplicateUnitIfindex",
		"CosIeee8021CodePointOutOfRange",
		"CosInetPrecedenceCodePointOutOfRange",
		"CosNoLowPriorityDefaultQueue",
		"CosQueueIdOutOfRange",
		"CosUnknownEqualFlowTargetPolicy",
		"CosUnknownSchedulerPriority",
	}
	if strings.Join(gotVariants, ",") != strings.Join(wantVariants, ",") {
		t.Fatalf("Rust CoS integrity-error census changed: got %v, want %v; adjudicate every new/removed variant", gotVariants, wantVariants)
	}

	bindings := []struct {
		variant, rustConsumer, goSource, goGate, goTestFile, goTest string
	}{
		{"CosQueueIdOutOfRange", rustValidated, strictGo, "validateClassOfServiceForwardingClassQueueStrict", "compiler_cos_fc_queue_4594_test.go", "TestCoSForwardingClassQueueOutOfRange_StrictReject_4594"},
		{"CosDscpCodePointOutOfRange", rustBuild, compilerGo, "collectCoSDSCPCodePoints", "lenient_fw_cos_4953_test.go", "TestCoSNumericCodePointStrictVsLenient_4953"},
		{"CosIeee8021CodePointOutOfRange", rustBuild, compilerGo, "collectCoS8021CodePoints", "lenient_fw_cos_4953_test.go", "TestCoSNumericCodePointStrictVsLenient_4953"},
		{"CosInetPrecedenceCodePointOutOfRange", rustBuild, compilerGo, "collectCoSINetPrecedenceCodePoints", "cos_inet_precedence_classifier_6847_test.go", "TestCoSINetPrecedenceCodePointOutOfRangeFailsCommit"},
		{"CosDscpRewriteCodePointOutOfRange", rustBuild, compilerGo, "collectCoSDSCPRewriteCodePoint", "lenient_fw_cos_4953_test.go", "TestCoSNumericCodePointStrictVsLenient_4953"},
		{"CosUnknownEqualFlowTargetPolicy", rustBuild, strictGo, "validateClassOfServiceStrict", "compiler_equal_flow_target_policy_test.go", "TestEqualFlowTargetPolicyStrictRejectsUnknownValue"},
		{"CosUnknownSchedulerPriority", rustBuild, strictGo, "validateClassOfServiceSchedulerPriorityStrict", "cos_scheduler_priority_11798_test.go", "TestCoSSchedulerPriorityStrictGate11798"},
	}
	for _, binding := range bindings {
		binding := binding
		t.Run(binding.variant, func(t *testing.T) {
			if !strings.Contains(errorSource, "    "+binding.variant+" {") {
				t.Fatalf("Rust error enum no longer declares %s", binding.variant)
			}
			if !strings.Contains(binding.rustConsumer, "SnapshotIntegrityError::"+binding.variant) {
				t.Fatalf("Rust consumer no longer emits %s", binding.variant)
			}
			if !strings.Contains(binding.goSource, binding.goGate) {
				t.Fatalf("Rust %s has no mapped Go gate %s", binding.variant, binding.goGate)
			}
			path := filepath.Join(".", binding.goTestFile)
			body, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read fail-on-revert test %s for %s: %v", path, binding.variant, err)
			}
			if !strings.Contains(string(body), "func "+binding.goTest+"(") {
				t.Fatalf("Rust %s Go gate %s has no mapped fail-on-revert test %s", binding.variant, binding.goGate, binding.goTest)
			}
		})
	}

	// These are not omitted gates: they depend on post-resolution runtime
	// topology rather than an authored scalar value and therefore remain Rust
	// structural backstops, outside the seven-value Go strict-gate census.
	for _, variant := range []string{"CosNoLowPriorityDefaultQueue", "CosDuplicateUnitIfindex"} {
		if !strings.Contains(rustBuild, "SnapshotIntegrityError::"+variant) {
			t.Errorf("Rust structural CoS error %s disappeared without updating this census", variant)
		}
	}
}

func TestCoSSchedulerPriorityRanksMatchSchemaAndRust11799(t *testing.T) {
	schema := readConfigParitySource11799(t, "schema_cos.go")
	rust := readCoSParitySource11799(t, "afxdp", "forwarding_build", "cos.rs")
	const rankSignature = "fn cos_priority_rank(priority: &str) -> Option<u8> {"
	start := strings.Index(rust, rankSignature)
	if start < 0 {
		t.Fatal("Rust cos_priority_rank function disappeared; update this parity census")
	}
	bodyStart := start + len(rankSignature)
	end := strings.Index(rust[bodyStart:], "\n}")
	if end < 0 {
		t.Fatal("could not delimit Rust cos_priority_rank body")
	}
	rankBody := rust[bodyStart : bodyStart+end]
	rankRE := regexp.MustCompile(`"([^"]+)"\s*=>\s*Some\(\d+\)`)
	var rustPriorities []string
	for _, match := range rankRE.FindAllStringSubmatch(rankBody, -1) {
		rustPriorities = append(rustPriorities, match[1])
	}
	sort.Strings(rustPriorities)
	goPriorities := make([]string, 0, len(cosSchedulerPriorityValues))
	for priority := range cosSchedulerPriorityValues {
		goPriorities = append(goPriorities, priority)
	}
	sort.Strings(goPriorities)
	if strings.Join(rustPriorities, ",") != strings.Join(goPriorities, ",") {
		t.Fatalf("Go scheduler priority set %v differs from Rust rank set %v", goPriorities, rustPriorities)
	}
	priorityNode := strings.Index(schema, `"priority": {`)
	if priorityNode < 0 {
		t.Fatal("CoS scheduler priority schema node disappeared")
	}
	priorityEnd := strings.Index(schema[priorityNode:], "\n\t\t},")
	if priorityEnd < 0 {
		t.Fatal("could not delimit CoS scheduler priority schema node")
	}
	prioritySchema := schema[priorityNode : priorityNode+priorityEnd]
	for _, priority := range rustPriorities {
		if !strings.Contains(prioritySchema, `"`+priority+`"`) {
			t.Errorf("schema priority enum no longer accepts Rust scheduler priority %q", priority)
		}
	}
}
