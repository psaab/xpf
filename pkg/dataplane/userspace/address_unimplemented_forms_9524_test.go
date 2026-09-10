package userspace

import (
	"strings"
	"testing"
)

// #9524 — the tolerant wire. Channel: config.CompileConfigLenient. A policy that
// references a mixed address must fail closed like the sole-value case (the
// #3261 sentinel, whole snapshot refused), not enforce the prefix alone.

func TestMixedAddressFailsClosedOnTheTolerantPath9524(t *testing.T) {
	pol := func(src string) string {
		return `zones { security-zone trust { address-book { address zmixed { 10.20.0.0/24; dns-name evil.example; } } } security-zone untrust; } policies { from-zone trust to-zone untrust { policy d1 { match { source-address ` + src + `; destination-address any; application any; } then { deny; } } } }`
	}
	for _, tc := range []struct {
		name     string
		text     string
		poisoned bool
	}{
		{"global mixed, referenced", `security { address-book { global { address mixed { 10.10.0.0/24; dns-name evil.example; } } } ` + pol("mixed") + ` }`, true},
		{"zone-local mixed, referenced", `security { ` + pol("zmixed") + ` }`, true},
		{"control: sole prefix", `security { address-book { global { address mixed 10.10.0.0/24; } } ` + pol("mixed") + ` }`, false},
		{"control: mixed but unreferenced", `security { address-book { global { address mixed { 10.10.0.0/24; dns-name evil.example; } address web 10.30.0.0/24; } } ` + pol("web") + ` }`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := lenientHier9571(t, tc.text)
			rules, err := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, nil)
			if err != nil || len(rules) != 1 {
				t.Fatalf("build: rules=%d err=%v", len(rules), err)
			}
			sentinel := addressListHasSentinel(rules[0].SourceLiterals) || addressListHasSentinel(rules[0].SourceAddresses)
			reasons := PolicyContentRejectionReasons(cfg, nil)
			if tc.poisoned {
				if !sentinel {
					t.Errorf("#9524: the referencing rule enforced the prefix alone: ids=%v literals=%v", rules[0].SourceBookIDs, rules[0].SourceLiterals)
				}
				if len(reasons) == 0 || !strings.Contains(reasons[0], "source-address") {
					t.Errorf("#9524: the mirror does not report the refusal: %v", reasons)
				}
				return
			}
			if sentinel || len(reasons) != 0 {
				t.Errorf("#9524 OVER-REJECTION: sentinel=%v reasons=%v", sentinel, reasons)
			}
		})
	}
}
