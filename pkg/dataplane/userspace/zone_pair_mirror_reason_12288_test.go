package userspace

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func malformedZonePairMirrorConfig12288(t *testing.T, fromZone, toZone string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	commands := []string{
		"set security zones security-zone A",
		"set security zones security-zone B",
		"set security zones security-zone C",
		"set security policies from-zone " + fromZone + " to-zone " + toZone + " policy p1 match source-address any",
		"set security policies from-zone " + fromZone + " to-zone " + toZone + " policy p1 match destination-address any",
		"set security policies from-zone " + fromZone + " to-zone " + toZone + " policy p1 match application any",
		"set security policies from-zone " + fromZone + " to-zone " + toZone + " policy p1 then deny",
		"set security policies default-policy permit-all",
	}
	for _, command := range commands {
		path, quoted, grouped, err := config.ParseSetCommandGrouped(command)
		if err != nil {
			t.Fatalf("ParseSetCommandGrouped(%q): %v", command, err)
		}
		if err := tree.SetPathQuotedGrouped(path, quoted, grouped); err != nil {
			t.Fatalf("SetPathQuotedGrouped(%q): %v", command, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	if len(cfg.Security.MalformedZonePairs) != 1 {
		t.Fatalf("fixture recorded malformed zone-pair diagnostics %q, want exactly one", cfg.Security.MalformedZonePairs)
	}
	return cfg
}

func TestMalformedZonePairMirrorReasonNamesShape12288(t *testing.T) {
	cases := []struct {
		name     string
		fromZone string
		toZone   string
	}{
		{name: "to-zone list", fromZone: "A", toZone: "[ B C ]"},
		{name: "from-zone list", fromZone: "[ A C ]", toZone: "B"},
	}
	seenReasons := make(map[string]bool, len(cases))
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := malformedZonePairMirrorConfig12288(t, tc.fromZone, tc.toZone)
			reasons := PolicyContentRejectionReasons(cfg, nil)
			if len(reasons) != 1 {
				t.Fatalf("want one mirror reason for the poisoned snapshot, got %q", reasons)
			}
			reason := reasons[0]
			shape := cfg.Security.MalformedZonePairs[0]
			if !strings.Contains(reason, shape) {
				t.Errorf("mirror reason does not identify recorded malformed shape %q: %s", shape, reason)
			}
			if strings.Contains(reason, "lenient-dropped-policy-enforcement-constraint") {
				t.Errorf("mirror reason exposes only the generic poison carrier instead of its malformed shape: %s", reason)
			}
			if !strings.Contains(reason, "names content the userspace matcher cannot represent") {
				t.Errorf("mirror reason lost the policy-content rejection prefix: %s", reason)
			}
			if !strings.Contains(reason, "the userspace helper rejects the whole policy snapshot") {
				t.Errorf("mirror reason does not explain that the whole snapshot is rejected: %s", reason)
			}
			if !strings.Contains(reason, "synthetic carrier global/xpf-malformed-zone-pair-poison") {
				t.Errorf("mirror reason misidentifies the synthetic carrier as an authored policy: %s", reason)
			}
			snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)
			if err != nil {
				t.Fatalf("buildSnapshot: %v", err)
			}
			sawSentinel := false
			for _, rule := range snap.Policies {
				for _, term := range rule.ApplicationTerms {
					if term.Name == unsupportedApplicationSentinel || term.Protocol == unsupportedApplicationSentinel {
						sawSentinel = true
					}
				}
			}
			if !sawSentinel {
				t.Fatal("snapshot reports a malformed-shape rejection without the __unsupported__ wire sentinel")
			}
			if got := snap.Capabilities.PolicyContentRejected; len(got) != 1 || !strings.Contains(got[0], shape) {
				t.Errorf("snapshot rejection mirror does not identify malformed shape %q: %v", shape, got)
			}
			if seenReasons[reason] {
				t.Errorf("different malformed shapes produced the same mirror reason: %s", reason)
			}
			seenReasons[reason] = true
		})
	}
}
