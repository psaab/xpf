package config_test

// #15703: `security log stream <name> facility` rejected the documented
// Junos facility names at strict commit even though
// pkg/logging.ParseFacilityChecked (#6830) maps every one of them to a
// wire facility. syslogFacilities (pkg/config/schema_security.go) listed
// only the BSD spellings, so a valid Junos stanza such as
// `facility authorization` failed SchemaValidate with
// "invalid value ... (expected one of: auth, change-log, daemon, kern,
// local0...)" while the runtime would have emitted it correctly.
//
// The fix adds exactly the eight Junos names ParseFacilityChecked knows
// that were missing — authorization, kernel, firewall, dfc, pfe,
// conflict-log, interactive-commands, ftp — to syslogFacilities. It does
// NOT add `any` (a wildcard on the system-syslog surface, meaningless for
// a stream's numeric facility) or `ntp` (#6830: Junos documents no
// configurable `ntp` facility, so it stays rejected rather than silently
// remapping to local0).
//
// RED-on-revert: dropping any of the eight names from syslogFacilities
// makes the corresponding accept subtest fail at SchemaValidate; adding
// `any`/`ntp`/a typo makes the reject subtests fail.

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/logging"
)

// junosFacilities15703 is the eight-name set #15703 adds, transcribed
// independently from pkg/logging's documented Junos table (#6830) rather
// than read from the schema list, so a name dropped from either side
// reds here.
var junosFacilities15703 = []string{
	"authorization", "kernel", "firewall", "dfc",
	"pfe", "conflict-log", "interactive-commands", "ftp",
}

func facilityTree15703(t *testing.T, facility string) *config.ConfigTree {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, cmd := range []string{
		"set security log stream s host 192.0.2.1",
		"set security log stream s facility " + facility,
	} {
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

func facilityHierTree15703(t *testing.T, facility string) *config.ConfigTree {
	t.Helper()
	text := "security { log { stream s { host 192.0.2.1; facility " + facility + "; } } }"
	tree, errs := config.NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse %q: %v", text, errs)
	}
	return tree
}

// TestSecurityLogFacilityJunosNamesCommit15703 is the strict-commit gate:
// every Junos name the runtime maps must commit as authored (flat and
// hierarchical spellings) and survive compilation verbatim, so the daemon
// path (ParseFacilityChecked) emits the Junos wire facility instead of
// the authored name being rejected or silently rewritten.
func TestSecurityLogFacilityJunosNamesCommit15703(t *testing.T) {
	for _, facility := range junosFacilities15703 {
		t.Run("flat/"+facility, func(t *testing.T) {
			tree := facilityTree15703(t, facility)
			if err := config.SchemaValidate(tree, nil); err != nil {
				t.Fatalf("SchemaValidate rejected Junos facility %q: %v (#15703)", facility, err)
			}
			if _, known := logging.ParseFacilityChecked(facility); !known {
				t.Fatalf("ParseFacilityChecked(%q) reports unknown; the schema must not "+
					"accept a name the runtime cannot map", facility)
			}
			cfg, err := config.CompileConfig(tree)
			if err != nil {
				t.Fatalf("CompileConfig rejected Junos facility %q: %v", facility, err)
			}
			stream := cfg.Security.Log.Streams["s"]
			if stream == nil {
				t.Fatalf("facility %q: stream s did not compile; streams=%v", facility, cfg.Security.Log.Streams)
			}
			if stream.Facility != facility {
				t.Errorf("compiled Facility = %q, want authored %q — the name must reach "+
					"the daemon verbatim so ParseFacilityChecked maps it", stream.Facility, facility)
			}
		})
		t.Run("hier/"+facility, func(t *testing.T) {
			tree := facilityHierTree15703(t, facility)
			if err := config.SchemaValidate(tree, nil); err != nil {
				t.Fatalf("hierarchical SchemaValidate rejected Junos facility %q: %v (#15703)", facility, err)
			}
			cfg, err := config.CompileConfig(tree)
			if err != nil {
				t.Fatalf("hierarchical CompileConfig rejected Junos facility %q: %v", facility, err)
			}
			if stream := cfg.Security.Log.Streams["s"]; stream == nil || stream.Facility != facility {
				t.Fatalf("hierarchical compiled stream = %+v, want Facility %q", stream, facility)
			}
		})
	}
}

// TestSecurityLogFacilityExistingNamesStillCommit15703 pins the pre-#15703
// vocabulary: widening the enum must not drop or rename any name that
// already committed.
func TestSecurityLogFacilityExistingNamesStillCommit15703(t *testing.T) {
	for _, facility := range []string{
		"auth", "change-log", "daemon", "kern",
		"local0", "local1", "local2", "local3",
		"local4", "local5", "local6", "local7",
		"syslog", "user",
	} {
		t.Run(facility, func(t *testing.T) {
			if err := config.SchemaValidate(facilityTree15703(t, facility), nil); err != nil {
				t.Fatalf("SchemaValidate rejected previously-valid facility %q: %v", facility, err)
			}
		})
	}
}

// TestSecurityLogFacilityStillRejectsUnknown15703 is the fail-closed
// guard: the widening is exactly the documented Junos set, not an open
// vocabulary. `any` (wildcard, no numeric facility), `ntp` (#6830: not
// configurable Junos) and plain typos must still fail strict commit,
// naming the offending value.
func TestSecurityLogFacilityStillRejectsUnknown15703(t *testing.T) {
	for _, facility := range []string{"any", "ntp", "locl0", "authh", "kernelx"} {
		t.Run(facility, func(t *testing.T) {
			err := config.SchemaValidate(facilityTree15703(t, facility), nil)
			if err == nil {
				t.Fatalf("SchemaValidate accepted facility %q; want strict rejection (#15703)", facility)
			}
			if !strings.Contains(err.Error(), facility) {
				t.Errorf("rejection for %q must name the value, got %v", facility, err)
			}
		})
	}
}

// TestSecurityLogFacilityJunosNamesLenient15703 covers the tolerant
// load / peer-sync path (#1960): a persisted config carrying a Junos
// facility must compile leniently with the authored name intact (no
// downgrade-to-warning rewrite, no silent local0 substitution at the
// config layer).
func TestSecurityLogFacilityJunosNamesLenient15703(t *testing.T) {
	for _, facility := range junosFacilities15703 {
		t.Run(facility, func(t *testing.T) {
			cfg, err := config.CompileConfigLenient(facilityTree15703(t, facility))
			if err != nil {
				t.Fatalf("CompileConfigLenient rejected Junos facility %q: %v", facility, err)
			}
			stream := cfg.Security.Log.Streams["s"]
			if stream == nil || stream.Facility != facility {
				t.Fatalf("lenient compiled stream = %+v, want Facility %q", stream, facility)
			}
		})
	}
}
