package configstore

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// Tests for #14660 on the operator surface: CheckText is the strict
// commit-check pipeline (xpfd check-config / every commit). Inert
// event-options shapes must fail there with the offending token named,
// and the fully working shape (RPM events + change-configuration) must
// pass. The config-level gate is in pkg/config
// (TestEventOptionsInert14660*); these cells bind the wiring so a gate
// that is correct but unreached cannot pass.

func TestCheckTextEventOptionsInert14660(t *testing.T) {
	cases := []struct {
		name string
		text string
		want string
	}{
		{
			name: "unknown event",
			text: "event-options {\n policy p {\n  events snmp_trap_link_down;\n  then { change-configuration { commands \"set system host-name x\"; } }\n }\n}\n",
			want: "snmp_trap_link_down",
		},
		{
			name: "uppercase event",
			text: "event-options {\n policy p {\n  events PING_TEST_FAILED;\n }\n}\n",
			want: "PING_TEST_FAILED",
		},
		{
			name: "then execute-commands",
			text: "event-options {\n policy p {\n  events ping_test_failed;\n  then { execute-commands { commands \"show version\"; } }\n }\n}\n",
			want: "execute-commands",
		},
		{
			name: "then raise-trap",
			text: "event-options {\n policy p {\n  events ping_test_failed;\n  then { raise-trap; }\n }\n}\n",
			want: "raise-trap",
		},
		{
			name: "event-options generate-event child",
			text: "event-options {\n generate-event FOO { time-of-day \"2020-01-01\"; }\n policy p { events ping_test_failed; }\n}\n",
			want: "generate-event",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CheckText(tc.text, -1)
			if err == nil {
				t.Fatalf("CheckText accepted inert shape (cfg=%+v); want reject naming %q", cfg, tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("CheckText error %q does not name %q", err.Error(), tc.want)
			}
			if !strings.Contains(err.Error(), "#14660") {
				t.Fatalf("CheckText error %q does not cite #14660", err.Error())
			}
		})
	}
}

// TestCheckTextEventOptionsInert15134 covers #15134 (A91-02) on the
// operator surface: unknown change-configuration children (above all
// the verify-only `commit-options { check; }`) must fail CheckText
// naming the token, while plain `commands` still passes.
func TestCheckTextEventOptionsInert15134(t *testing.T) {
	cases := []struct {
		name string
		text string
		want string
	}{
		{
			name: "commit-options check hier",
			text: "event-options {\n policy p {\n  events ping_test_failed;\n  then { change-configuration { commit-options { check; } commands \"set system host-name x\"; } }\n }\n}\n",
			want: "commit-options",
		},
		{
			name: "user-name hier",
			text: "event-options {\n policy p {\n  events ping_test_failed;\n  then { change-configuration { user-name bob; commands \"set system host-name x\"; } }\n }\n}\n",
			want: "user-name",
		},
		{
			name: "retry hier",
			text: "event-options {\n policy p {\n  events ping_test_failed;\n  then { change-configuration { retry 3; commands \"set system host-name x\"; } }\n }\n}\n",
			want: "retry",
		},
		{
			name: "junk hier",
			text: "event-options {\n policy p {\n  events ping_test_failed;\n  then { change-configuration { junk-thing foo; commands \"set system host-name x\"; } }\n }\n}\n",
			want: "junk-thing",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CheckText(tc.text, -1)
			if err == nil {
				t.Fatalf("CheckText accepted inert change-configuration child (cfg=%+v); want reject naming %q", cfg, tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("CheckText error %q does not name %q", err.Error(), tc.want)
			}
			if !strings.Contains(err.Error(), "#15134") {
				t.Fatalf("CheckText error %q does not cite #15134", err.Error())
			}
		})
	}
	// Flat-set rows return an error through the same strict pipeline.
	flat := "set event-options policy p events ping_test_failed\nset event-options policy p then change-configuration commit-options check\nset event-options policy p then change-configuration commands \"set system host-name x\"\n"
	if _, err := CheckText(flat, -1); err == nil || !strings.Contains(err.Error(), "commit-options") {
		t.Fatalf("CheckText flat commit-options = %v, want reject naming commit-options", err)
	}
}

// TestCheckTextEventOptionsValid14660 is the positive control: the one
// fully working shape stays accepted with no #14660 warning.
func TestCheckTextEventOptionsValid14660(t *testing.T) {
	text := "event-options {\n policy p {\n  events [ ping_probe_failed ping_test_failed ping_test_completed ];\n  within 60 { trigger on 1; }\n  then { change-configuration { commands \"set system host-name recovered\"; } }\n }\n}\n"
	cfg, err := CheckText(text, -1)
	if err != nil {
		t.Fatalf("CheckText rejected valid RPM event policy: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#14660") {
			t.Fatalf("valid control carried #14660 warning: %q", w)
		}
	}
	if len(cfg.EventOptions) != 1 || len(cfg.EventOptions[0].Events) != 3 {
		t.Fatalf("compiled EventOptions = %+v, want 1 policy with 3 events", cfg.EventOptions)
	}
}

// TestCheckTextEventOptionsWithin16654 covers #16654 on the operator
// surface: Junos correlation children under `within` (events / not
// events / bogus token) must fail CheckText naming the policy and the
// token, in hierarchical and flat-set spellings, while the
// `within 60 { trigger on 3; }` control stays accepted. Store-level
// CommitCheck is exercised via CheckText here; the dedicated
// candidate CommitCheck path shares the same strict CompileConfig
// pipeline (CheckText is its text form), and CompileConfig strict
// cells live in pkg/config TestEventWithinCorrelationChildren16654*.
func TestCheckTextEventOptionsWithin16654(t *testing.T) {
	cases := []struct {
		name string
		text string
		want string
	}{
		{
			name: "hier braced not events",
			text: "event-options {\n policy p {\n  events ping_test_failed;\n  within 60 { not events ping_test_completed; trigger on 1; }\n  then { change-configuration { commands \"set system host-name x\"; } }\n }\n}\n",
			want: "not",
		},
		{
			name: "hier braced events",
			text: "event-options {\n policy p {\n  events ping_test_failed;\n  within 60 { events ping_test_completed; trigger on 1; }\n }\n}\n",
			want: "events",
		},
		{
			name: "hier braced bogus token",
			text: "event-options {\n policy p {\n  events ping_test_failed;\n  within 60 { bogus-token foo; trigger on 1; }\n }\n}\n",
			want: "bogus-token",
		},
		{
			name: "hier packed not events tail (fused sibling)",
			text: "event-options {\n policy p {\n  events ping_test_failed;\n  within 60 not events ping_test_completed;\n }\n}\n",
			want: "events",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CheckText(tc.text, -1)
			if err == nil {
				t.Fatalf("CheckText accepted inert within correlation child (cfg=%+v); want reject naming %q", cfg, tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("CheckText error %q does not name %q", err.Error(), tc.want)
			}
			// Fused packed tails are rejected earlier by the #8437
			// sibling gate (also naming the token); braced rows carry
			// the #16654 tag from validateEventWithinClause.
			if tc.name == "hier packed not events tail (fused sibling)" {
				if !strings.Contains(err.Error(), "#8437") {
					t.Fatalf("CheckText fused error %q does not cite #8437", err.Error())
				}
			} else if !strings.Contains(err.Error(), "#16654") {
				t.Fatalf("CheckText error %q does not name #16654", err.Error())
			}
		})
	}
	// Flat-set rows (the issue's SetPath example) reject through the
	// same strict pipeline.
	flat := "set event-options policy p events ping_test_failed\nset event-options policy p within 60 not events ping_test_completed\nset event-options policy p within 60 trigger on 1\nset event-options policy p then change-configuration commands \"set system host-name x\"\n"
	if _, err := CheckText(flat, -1); err == nil || !strings.Contains(err.Error(), "not") || !strings.Contains(err.Error(), "#16654") {
		t.Fatalf("CheckText flat not-events = %v, want reject naming not + #16654", err)
	}
	// Control: plain within/trigger stays accepted with no #16654 warning.
	control := "event-options {\n policy p {\n  events ping_test_failed;\n  within 60 { trigger on 3; }\n  then { change-configuration { commands \"set system host-name x\"; } }\n }\n}\n"
	cfg, err := CheckText(control, -1)
	if err != nil {
		t.Fatalf("CheckText rejected within trigger control: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#16654") {
			t.Fatalf("valid within control carried #16654 warning: %q", w)
		}
	}
}

// TestStoreCommitCheckWithin16654 binds the candidate-commit surface:
// acceptance requires rejection by Store.CommitCheck (not only
// CheckText/CompileConfig) naming the policy and token, with the
// trigger control passing CommitCheck clean.
func TestStoreCommitCheckWithin16654(t *testing.T) {
	bad := "event-options {\n policy p {\n  events ping_test_failed;\n  within 60 { not events ping_test_completed; trigger on 1; }\n  then { change-configuration { commands \"set system host-name x\"; } }\n }\n}\n"
	store := newTestStore(t)
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := store.LoadOverride(bad); err != nil {
		t.Fatalf("LoadOverride(bad within) = %v, want staged candidate", err)
	}
	if _, err := store.CommitCheck(); err == nil || !strings.Contains(err.Error(), "not") || !strings.Contains(err.Error(), "#16654") {
		t.Fatalf("CommitCheck bad within = %v, want reject naming not + #16654", err)
	}
	store.ExitConfigure()

	good := "event-options {\n policy p {\n  events ping_test_failed;\n  within 60 { trigger on 3; }\n  then { change-configuration { commands \"set system host-name x\"; } }\n }\n}\n"
	store2 := newTestStore(t)
	if err := store2.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := store2.LoadOverride(good); err != nil {
		t.Fatalf("LoadOverride(good within) = %v", err)
	}
	cfg, err := store2.CommitCheck()
	if err != nil {
		t.Fatalf("CommitCheck good within = %v, want clean", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#16654") {
			t.Fatalf("CommitCheck control carried #16654 warning: %q", w)
		}
	}
}

// TestKnownEventNamesMatchesRPMProducers14660 guards drift between
// config.KnownEventNames (the commit gate's SSOT) and the actual
// fireEvent call sites in pkg/rpm — a new producer event added without
// updating the gate would otherwise be rejected at commit, and a gate
// name with no producer would silently re-admit an inert policy.
func TestKnownEventNamesMatchesRPMProducers14660(t *testing.T) {
	data, err := os.ReadFile("../../pkg/rpm/rpm.go")
	if err != nil {
		t.Fatalf("read pkg/rpm/rpm.go: %v", err)
	}
	re := regexp.MustCompile(`fireEvent\("([^"]+)"`)
	found := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(string(data), -1) {
		found[m[1]] = true
	}
	if len(found) == 0 {
		t.Fatal("no fireEvent producers found in pkg/rpm/rpm.go — fixture drift?")
	}
	for name := range found {
		if !config.EventNameKnown(name) {
			t.Errorf("rpm fires %q but config.KnownEventNames does not know it", name)
		}
	}
	// Reverse direction is asserted via the exported sorted list.
	for _, name := range config.KnownEventNamesSorted() {
		if !found[name] {
			t.Errorf("config.KnownEventNames knows %q but no rpm fireEvent site fires it", name)
		}
	}
}
