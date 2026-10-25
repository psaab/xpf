package config

import (
	"strings"
	"testing"
)

// #16866 gate5 R1: operator prefix-lists in the generated RIP
// gate namespace (`xpf-rip-…`) merge with generated
// distribute-list gates in FRR's flat prefix-list object.
// validatePrefixListReservedRIPGateStrict reserves the prefix:
// hard-reject at commit, lenient-warn on load (#1960); pkg/frr's
// ApplyFull guard fails the apply closed on the tolerant path.

func TestPrefixListReservedRIPGateRejected16866(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set policy-options prefix-list xpf-rip-0-grp-0 203.0.113.0/24",
		"set protocols rip neighbor ge-0/0/1.0",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted a prefix-list in the reserved xpf-rip- namespace (#16866)")
	}
	for _, want := range []string{"xpf-rip-0-grp-0", "xpf-rip-", "reserved"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err.Error(), want)
		}
	}
}

func TestPrefixListNormalNameAccepted16866(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set policy-options prefix-list OPERATOR-LIST 203.0.113.0/24",
		"set protocols rip neighbor ge-0/0/1.0",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig rejected a normal prefix-list name: %v", err)
	}
}

func TestPrefixListReservedRIPGateLenientWarns16866(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set policy-options prefix-list xpf-rip-0-grp-0 203.0.113.0/24",
		"set protocols rip neighbor ge-0/0/1.0",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient must downgrade to warning, got: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "xpf-rip-0-grp-0") && strings.Contains(w, "reserved") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected downgraded reserved-namespace warning; warnings=%v", cfg.Warnings)
	}
}
