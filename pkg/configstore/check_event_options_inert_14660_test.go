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
