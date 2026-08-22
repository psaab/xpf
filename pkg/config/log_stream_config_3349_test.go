package config_test

// #3349: security log stream / top-level log field validation. Before this
// change each of these sub-fields committed cleanly with a typo and then
// silently widened, remapped, or fell back at runtime (audit fail-open):
//   - category typo  -> 0 = no filter = send ALL categories
//   - severity typo  -> 0 = no floor  = send ALL severities
//   - facility typo  -> silently remapped to local0
//   - port typo      -> strconv.Atoi error ignored -> stays 514
//   - source-address invalid -> stream silently dropped at apply
//   - source-interface non-numeric unit -> wrong source IP (unit 0)
//   - mode/format typo -> silent fallback
//
// The enum/value fields are now typed schema leaves (validated by
// SchemaValidate, the commit-check gate) and port is validated by the
// validateSecurityLogStreamPortsAST compiler pass. Each test below is
// RED-on-revert: removing the validator makes the bad value pass.

import (
	"fmt"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func buildTree3349(t *testing.T, cmds ...string) *config.ConfigTree {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, cmd := range cmds {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

// schemaCheck3349 runs the commit-check typed-leaf gate over a flat-set config.
func schemaCheck3349(t *testing.T, cmds ...string) error {
	t.Helper()
	return config.SchemaValidate(buildTree3349(t, cmds...), nil)
}

// TestLogStream3349_SchemaFields_RejectTypos asserts every typed log field
// rejects a bad value at commit (was silently accepted before #3349).
func TestLogStream3349_SchemaFields_RejectTypos(t *testing.T) {
	bad := map[string][]string{
		"category":         {"set security log stream s host 192.0.2.1", "set security log stream s category sesion"},
		"severity":         {"set security log stream s host 192.0.2.1", "set security log stream s severity wraning"},
		"facility":         {"set security log stream s host 192.0.2.1", "set security log stream s facility locl0"},
		"stream-format":    {"set security log stream s host 192.0.2.1", "set security log stream s format sdsyslog"},
		"source-address":   {"set security log stream s host 192.0.2.1", "set security log stream s source-address not-an-ip"},
		"mode":             {"set security log mode steam"},
		"format":           {"set security log format sdsyslog"},
		"source-interface": {"set security log source-interface reth1.abc"},
		// #6218 item 7: MaxLogicalUnit+1 can never name a real interface unit
		// (compiler_interfaces.go caps `unit <n>` at MaxLogicalUnit), so this
		// source-interface could never resolve — the same silent audit-source
		// loss #3349 closed for a non-numeric unit.
		"source-interface-unit-range": {fmt.Sprintf(
			"set security log source-interface ge-0-0-0.%d", config.MaxLogicalUnit+1)},
	}
	for name, cmds := range bad {
		t.Run(name, func(t *testing.T) {
			if err := schemaCheck3349(t, cmds...); err == nil {
				t.Fatalf("expected commit rejection for %v, got nil (field silently accepted)", cmds)
			}
		})
	}
}

// TestLogStream3349_SchemaFields_AcceptValid asserts a fully-valid stanza
// commits cleanly — the validators must not reject legitimate config.
func TestLogStream3349_SchemaFields_AcceptValid(t *testing.T) {
	good := []string{
		"set security log mode stream",
		"set security log format sd-syslog",
		"set security log source-interface ge-0-0-0",
		"set security log stream s host 192.0.2.1",
		"set security log stream s category session",
		"set security log stream s severity warning",
		"set security log stream s facility local7",
		"set security log stream s format structured",
		"set security log stream s source-address 2001:db8::1",
		"set security log stream s2 host 10.0.0.2",
		"set security log stream s2 source-interface reth1.100",
		// At the exact MaxLogicalUnit boundary: the #6218 item 7 upper bound
		// must not over-reject a legitimate, if extreme, unit number.
		"set security log stream s3 host 10.0.0.3",
		fmt.Sprintf("set security log stream s3 source-interface ge-0-0-0.%d", config.MaxLogicalUnit),
	}
	if err := schemaCheck3349(t, good...); err != nil {
		t.Fatalf("valid log config rejected: %v", err)
	}
	// And it must actually compile (strict).
	if _, err := config.CompileConfig(buildTree3349(t, good...)); err != nil {
		t.Fatalf("valid log config failed strict compile: %v", err)
	}
}

// TestLogStream3349_Port_StrictReject covers the port range gate
// (validateSecurityLogStreamPortsAST) for both the direct `stream port` and
// the nested `host { port }` spellings. A non-numeric or out-of-range port
// previously committed and silently stayed 514.
func TestLogStream3349_Port_StrictReject(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
	}{
		{"direct-nonnumeric", []string{"set security log stream s host 192.0.2.1", "set security log stream s port 6514x"}},
		{"direct-zero", []string{"set security log stream s host 192.0.2.1", "set security log stream s port 0"}},
		{"direct-overrange", []string{"set security log stream s host 192.0.2.1", "set security log stream s port 70000"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := config.CompileConfig(buildTree3349(t, tc.cmds...))
			if err == nil {
				t.Fatalf("expected strict compile rejection for %v, got nil", tc.cmds)
			}
			if !strings.Contains(err.Error(), "port") {
				t.Fatalf("error should mention port, got %v", err)
			}
		})
	}
}

// TestLogStream3349_Port_NestedHostReject covers the Junos-canonical nested
// host{port} location parsed hierarchically.
func TestLogStream3349_Port_NestedHostReject(t *testing.T) {
	const cfg = `security {
		log {
			stream s {
				host {
					192.0.2.1;
					port 6514x;
				}
			}
		}
	}`
	p := config.NewParser(cfg)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	if _, err := config.CompileConfig(tree); err == nil {
		t.Fatalf("expected strict compile rejection for nested host{port 6514x}, got nil")
	}
}

// TestLogStream3349_EventModeFormat covers the cross-field event-mode format
// compatibility gate (validateLogEventModeFormatStrict). #3409 implemented
// structured (Junos RT_FLOW) and sd-syslog (RFC 5424) output in the event-mode
// LocalLogWriter fanout, so all four schema formats are now honored in event
// mode and must compile clean — no value silently falls back (the #3349
// contract holds without a hard reject because nothing no-ops any more).
func TestLogStream3349_EventModeFormat(t *testing.T) {
	accept := map[string][]string{
		"event-binary":       {"set security log mode event", "set security log format binary"},
		"event-syslog":       {"set security log mode event", "set security log format syslog"},
		"event-no-format":    {"set security log mode event"},
		"event-structured":   {"set security log mode event", "set security log format structured"},
		"event-sd-syslog":    {"set security log mode event", "set security log format sd-syslog"},
		"stream-structured":  {"set security log mode stream", "set security log format structured"},
		"stream-sd-syslog":   {"set security log mode stream", "set security log format sd-syslog"},
		"default-structured": {"set security log format structured"}, // no mode => stream default
	}
	for name, cmds := range accept {
		t.Run("accept/"+name, func(t *testing.T) {
			if _, err := config.CompileConfig(buildTree3349(t, cmds...)); err != nil {
				t.Fatalf("expected %v to compile, got %v", cmds, err)
			}
		})
	}
}

// TestLogStream3349_Port_LenientWarns proves the #1960/#3261 doctrine: an
// already-persisted/peer-synced config carrying a bad port must NOT brick the
// load — it is downgraded to a warning and still compiles.
func TestLogStream3349_Port_LenientWarns(t *testing.T) {
	tree := buildTree3349(t,
		"set security log stream s host 192.0.2.1",
		"set security log stream s port 6514x",
	)
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must not fail on a bad port, got %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "port") && strings.Contains(w, "6514x") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected a lenient warning about the bad port, warnings=%v", cfg.Warnings)
	}
}
