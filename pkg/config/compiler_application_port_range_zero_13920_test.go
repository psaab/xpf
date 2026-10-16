package config

import "testing"

// #13920 (H02-01): a 0-N source/destination port range must keep its literal
// port-0 coverage end to end. The pre-fix chain silently rewrote it to 1-N at
// resolveAppPort (and rejected a raw 0 floor at validatePortSpec), so a deny
// whose application carried `0-N` never matched a real TCP/UDP packet whose
// port is 0. These tests pin the post-fix contract.
//
// FAIL-ON-REVERT: reverting the resolveAppPort zero-floor preservation (or
// the validatePortSpec floor acceptance) makes the stored spec come back as
// "1-N" (or the compile fail) and these tests go RED.

func TestApplicationPortRange_PortZeroFloor_Preserved_13920(t *testing.T) {
	// Source-port twin.
	tree := flatTreeFromSets(t, refApp("facetime",
		"protocol udp", "source-port 0-41640", "destination-port 3478-3497")...)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("expected commit to ACCEPT source-port 0-41640 (#13920), got: %v", err)
	}
	app := cfg.Applications.Applications["facetime"]
	if app == nil {
		t.Fatalf("application facetime missing; have %v", appNames(cfg))
	}
	if app.SourcePort != "0-41640" {
		t.Fatalf("source-port 0-41640 must be preserved verbatim, got %q (silently rewritten to 1-N?)", app.SourcePort)
	}

	// Destination-port twin.
	tree = flatTreeFromSets(t, refApp("app0", "protocol tcp", "destination-port 0-1024")...)
	cfg, err = CompileConfig(tree)
	if err != nil {
		t.Fatalf("expected commit to ACCEPT destination-port 0-1024 (#13920), got: %v", err)
	}
	app = cfg.Applications.Applications["app0"]
	if app == nil || app.DestinationPort != "0-1024" {
		t.Fatalf("destination-port 0-1024 must be preserved verbatim, got %+v", app)
	}

	// Inline-term twin: the generated term app carries the preserved spec.
	tree = flatTreeFromSets(t, refApp("ft",
		"term t0 protocol udp source-port 0-41640 destination-port 3478-3497")...)
	cfg, err = CompileConfig(tree)
	if err != nil {
		t.Fatalf("expected commit to ACCEPT inline-term source-port 0-41640 (#13920), got: %v", err)
	}
	app = cfg.Applications.Applications["ft-t0"]
	if app == nil || app.SourcePort != "0-41640" {
		t.Fatalf("inline-term source-port 0-41640 must be preserved verbatim, got %+v", app)
	}
	// A fully degenerate explicit range is still distinguishable from an
	// omitted field in the policy-term wire representation.
	tree = flatTreeFromSets(t, refApp("zero-only", "protocol tcp", "destination-port 0-0")...)
	cfg, err = CompileConfig(tree)
	if err != nil {
		t.Fatalf("expected commit to ACCEPT destination-port 0-0 (#13920), got: %v", err)
	}
	app = cfg.Applications.Applications["zero-only"]
	if app == nil || app.DestinationPort != "0-0" {
		t.Fatalf("destination-port 0-0 must be preserved verbatim, got %+v", app)
	}
}

func TestApplicationPortRange_PortZeroFloor_GuardsIntact_13920(t *testing.T) {
	// A normal 1-N range is byte-identical (no clamp in either direction).
	cfg, err := CompileConfig(flatTreeFromSets(t,
		refApp("ok", "protocol tcp", "source-port 1024-2048")...))
	if err != nil {
		t.Fatalf("normal range 1024-2048 must still commit: %v", err)
	}
	if app := cfg.Applications.Applications["ok"]; app == nil || app.SourcePort != "1024-2048" {
		t.Fatalf("normal range must be unchanged, got %+v", app)
	}
	// Genuine garbage is still hard-rejected on the referenced (strict) path:
	// out-of-range / non-numeric endpoints and a reversed range still fail.
	// A bare single port 0 also stays invalid (it has no range and no wire
	// representation distinct from "no constraint" in Junos).
	for _, bad := range []string{"70000", "0-70000", "abc", "0", "9000-8000"} {
		t.Run("reject_"+bad, func(t *testing.T) {
			_, err := CompileConfig(flatTreeFromSets(t,
				refApp("bad", "protocol tcp", "source-port "+bad)...))
			if err == nil {
				t.Fatalf("expected commit to REJECT garbage source-port %q", bad)
			}
		})
	}
}
