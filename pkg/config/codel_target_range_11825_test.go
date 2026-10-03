package config

import (
	"fmt"
	"strings"
	"testing"
)

const maxCodelTargetMillis11825 = int64(18_446_744_073_709)

func codelTargetTree11825(t *testing.T, value string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	path, err := ParseSetCommand("set class-of-service schedulers sched1 codel-target " + value)
	if err != nil {
		t.Fatalf("ParseSetCommand: %v", err)
	}
	if err := tree.SetPath(path); err != nil {
		t.Fatalf("SetPath: %v", err)
	}
	return tree
}

func TestCodelTargetMillisRangeSchema11825(t *testing.T) {
	max := fmt.Sprint(maxCodelTargetMillis11825)
	if err := SchemaValidate(codelTargetTree11825(t, max), nil); err != nil {
		t.Fatalf("maximum CoDel target %s ms should pass schema: %v", max, err)
	}
	for _, value := range []string{fmt.Sprint(maxCodelTargetMillis11825 + 1), "banana"} {
		err := SchemaValidate(codelTargetTree11825(t, value), nil)
		if err == nil || !strings.Contains(err.Error(), "codel-target") {
			t.Errorf("CoDel target %q: want codel-target schema rejection, got %v", value, err)
		}
	}
}

func TestCodelTargetMillisStrictAndLenientBounds11825(t *testing.T) {
	max := fmt.Sprint(maxCodelTargetMillis11825)
	wantNS := uint64(maxCodelTargetMillis11825) * 1_000_000
	cfg, err := CompileConfig(codelTargetTree11825(t, max))
	if err != nil {
		t.Fatalf("maximum CoDel target %s ms should compile: %v", max, err)
	}
	if got := cfg.ClassOfService.Schedulers["sched1"].CodelTargetNS; got != wantNS {
		t.Fatalf("maximum CoDel target converted to %d ns, want %d", got, wantNS)
	}

	for _, value := range []string{fmt.Sprint(maxCodelTargetMillis11825 + 1), "banana", "18446744073709551616"} {
		if _, err := CompileConfig(codelTargetTree11825(t, value)); err == nil {
			t.Errorf("strict compile accepted invalid CoDel target %q", value)
		}
	}

	cfg, err = CompileConfigLenient(codelTargetTree11825(t, fmt.Sprint(maxCodelTargetMillis11825+1)))
	if err != nil {
		t.Fatalf("lenient compile of over-ceiling CoDel target: %v", err)
	}
	if got := cfg.ClassOfService.Schedulers["sched1"].CodelTargetNS; got != wantNS {
		t.Errorf("lenient over-ceiling target converted to %d ns, want clamped %d", got, wantNS)
	}
	if !codelTargetHasWarning11825(cfg, "clamped on tolerant load") {
		t.Fatalf("lenient over-ceiling target must report its clamp; got %v", cfg.Warnings)
	}

	for _, value := range []string{"banana", "18446744073709551616"} {
		cfg, err = CompileConfigLenient(codelTargetTree11825(t, value))
		if err != nil {
			t.Fatalf("lenient compile of unparseable CoDel target %q: %v", value, err)
		}
		if got := cfg.ClassOfService.Schedulers["sched1"].CodelTargetNS; got != 0 {
			t.Errorf("lenient unparseable target %q produced %d ns, want unset 0", value, got)
		}
		if !codelTargetHasWarning11825(cfg, "ignored on tolerant load") {
			t.Errorf("lenient unparseable target %q must warn rather than silently become zero; warnings=%v", value, cfg.Warnings)
		}
	}
}

func codelTargetHasWarning11825(cfg *Config, fragment string) bool {
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, fragment) {
			return true
		}
	}
	return false
}
