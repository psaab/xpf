package userspace

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9571 — the wire half. A widened fold is poisoned with LenientContentDropped in
// pkg/config; this asserts the helper actually receives the refusal, on the
// marshalled bytes, and that the content-rejection mirror reports it. Channel:
// config.CompileConfigLenient.

func lenientHier9571(t *testing.T, text string) *config.Config {
	t.Helper()
	tree, errs := config.NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile refused the fixture: %v", err)
	}
	return cfg
}

func TestFoldWidenedDuplicatePoisonsTheWire9571(t *testing.T) {
	const anyM = `match { source-address any; destination-address any; application any; }`
	text := func(second string) string {
		return `security { zones { security-zone trust; security-zone untrust; } policies { from-zone trust to-zone untrust { ` +
			second + ` } } }`
	}
	for _, tc := range []struct {
		name     string
		text     string
		poisoned bool
	}{
		{"deny then permit", text(`policy p1 { ` + anyM + ` then { deny; } } policy p1 { ` + anyM + ` then { permit; } }`), true},
		{"#8752 control: permit then a deny fragment", text(`policy p1 { ` + anyM + ` then { permit; } } policy p1 { then { deny; } }`), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := lenientHier9571(t, tc.text)
			rules, err := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, nil)
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			if len(rules) != 1 {
				t.Fatalf("want 1 folded rule, got %d", len(rules))
			}
			wire, err := json.Marshal(rules[0])
			if err != nil {
				t.Fatal(err)
			}
			onWire := strings.Contains(string(wire), `"`+unsupportedApplicationSentinel+`"`)
			reasons := PolicyContentRejectionReasons(cfg, nil)
			if tc.poisoned {
				if !onWire {
					t.Errorf("#9571: the widened rule reaches the helper without the %q poison: %s", unsupportedApplicationSentinel, wire)
				}
				if len(reasons) == 0 {
					t.Error("#9571: the content-rejection mirror does not report the refusal, so `show security match-policies` disagrees with the helper")
				}
				return
			}
			if onWire || len(reasons) != 0 {
				t.Errorf("#9571 OVER-REJECTION on the #8752 fixture: sentinel on wire=%v reasons=%v", onWire, reasons)
			}
		})
	}
}
