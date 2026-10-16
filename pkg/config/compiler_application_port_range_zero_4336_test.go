package config

import "testing"

// #4336 / #13920: Junos accepts 0 as the FLOOR of an application source-port /
// destination-port range. The zero floor must remain in the compiled range:
// port 0 is a real TCP/UDP tuple value, so narrowing 0-N to 1-N caused a deny
// to miss port-0 traffic. These tests use a REFERENCED application so the
// reference-scoped validateApplicationSpecsStrict port gate runs.
//

// Core fail-on-revert: `source-port 0-41640` on a referenced app commits, and
// the stored spec preserves `0-41640`. A regression that clamps the floor to 1
// or rejects it makes this assertion RED.
func TestApplicationPortRange_ZeroFloor_SourcePort_Accepted(t *testing.T) {
	tree := flatTreeFromSets(t, refApp("facetime",
		"protocol udp", "source-port 0-41640", "destination-port 3478-3497")...)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("expected commit to ACCEPT source-port 0-41640 (#4336), got: %v", err)
	}
	app := cfg.Applications.Applications["facetime"]
	if app == nil {
		t.Fatalf("application facetime missing; have %v", appNames(cfg))
	}
	if app.SourcePort != "0-41640" {
		t.Fatalf("source-port 0-41640 must preserve zero, got %q", app.SourcePort)
	}
}

// destination-port 0-N is preserved identically.
func TestApplicationPortRange_ZeroFloor_DestinationPort_Accepted(t *testing.T) {
	tree := flatTreeFromSets(t, refApp("app0", "protocol tcp", "destination-port 0-1024")...)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("expected commit to ACCEPT destination-port 0-1024 (#4336), got: %v", err)
	}
	app := cfg.Applications.Applications["app0"]
	if app == nil || app.DestinationPort != "0-1024" {
		t.Fatalf("destination-port 0-1024 must preserve zero, got %+v", app)
	}
}

// The zero floor also works inside an inline term (the generated term app
// carries the preserved port).
func TestApplicationPortRange_ZeroFloor_InlineTerm_Accepted(t *testing.T) {
	tree := flatTreeFromSets(t, refApp("ft",
		"term t0 protocol udp source-port 0-41640 destination-port 3478-3497")...)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("expected commit to ACCEPT inline-term source-port 0-41640 (#4336), got: %v", err)
	}
	app := cfg.Applications.Applications["ft-t0"]
	if app == nil || app.SourcePort != "0-41640" {
		t.Fatalf("inline-term source-port 0-41640 must preserve zero, got %+v", app)
	}
}

// Guard against over-acceptance: a normal 1-N range is byte-identical (no
// clamp), and genuine garbage is still hard-rejected on the referenced (strict)
// path — a bare single port 0 stays invalid (matching Junos), and an
// out-of-range / non-numeric endpoint still fails.
func TestApplicationPortRange_ZeroFloor_GuardsIntact(t *testing.T) {
	cfg, err := CompileConfig(flatTreeFromSets(t,
		refApp("ok", "protocol tcp", "source-port 1024-2048")...))
	if err != nil {
		t.Fatalf("normal range 1024-2048 must still commit: %v", err)
	}
	if app := cfg.Applications.Applications["ok"]; app == nil || app.SourcePort != "1024-2048" {
		t.Fatalf("normal range must be unchanged, got %+v", app)
	}
	for _, bad := range []string{"70000", "0-70000", "abc", "0"} {
		t.Run("reject_"+bad, func(t *testing.T) {
			_, err := CompileConfig(flatTreeFromSets(t,
				refApp("bad", "protocol tcp", "source-port "+bad)...))
			if err == nil {
				t.Fatalf("expected commit to REJECT garbage source-port %q", bad)
			}
		})
	}
}
