package dataplane

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestGlobalCountersMapEntryUpgradeFromOldPin10498(t *testing.T) {
	base := validABIBaseSpec()
	const target = "global_counters"
	ref := sharedShimMapSpecByName(target)
	if ref == nil {
		t.Fatalf("Go SSOT missing %s", target)
	}
	correct := mapABIFromSpec(ref)
	if correct.MaxEntries != GlobalCtrMax {
		t.Fatalf("%s expected max_entries=%d, got %d", target, GlobalCtrMax, correct.MaxEntries)
	}

	if err := validateUserspaceShimSpecWith(base, sharedMapLivePinReader(base, target, correct)); err != nil {
		t.Fatalf("matching %s pin rejected: %v", target, err)
	}

	old := correct
	old.MaxEntries = 41
	if err := legacyPresenceMaxEntriesValidate(base); err != nil {
		t.Fatalf("legacy validator rejected synthetic base: %v", err)
	}
	err := validateUserspaceShimSpecWith(base, sharedMapLivePinReader(base, target, old))
	if err == nil {
		t.Fatalf("old 41-entry %s pin must fail before stop", target)
	}
	for _, want := range []string{target, "MaxEntries", "ABI-incompatible", userspaceShimStalePinRemediation} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %v, want substring %q", err, want)
		}
	}
}

func TestGlobalCountersCAndGoMaxEntriesParity10498(t *testing.T) {
	if GlobalCtrMax != 43 {
		t.Fatalf("Go GlobalCtrMax = %d, want exact ABI size 43", GlobalCtrMax)
	}
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	headerPath := filepath.Join(filepath.Dir(file), "..", "..", "bpf", "headers", "xpf_common.h")
	header, err := os.ReadFile(headerPath)
	if err != nil {
		t.Fatalf("read C counter header: %v", err)
	}
	match := regexp.MustCompile(`(?m)^#define\s+GLOBAL_CTR_MAX\s+(\d+)\s*$`).FindSubmatch(header)
	if len(match) != 2 {
		t.Fatalf("GLOBAL_CTR_MAX definition missing from %s", headerPath)
	}
	cMax, err := strconv.ParseUint(string(match[1]), 10, 32)
	if err != nil {
		t.Fatalf("parse C GLOBAL_CTR_MAX: %v", err)
	}
	if uint32(cMax) != GlobalCtrMax {
		t.Fatalf("C GLOBAL_CTR_MAX=%d, Go GlobalCtrMax=%d", cMax, GlobalCtrMax)
	}
	if spec := sharedShimMapSpecByName("global_counters"); spec == nil || spec.MaxEntries != GlobalCtrMax {
		t.Fatalf("Go global_counters map spec must use max_entries=%d", GlobalCtrMax)
	}
}
