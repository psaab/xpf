package policymatch

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #4422 (audit test-coverage follow-up: "ICMP AppID type/code attribution").
//
// VERIFY-FIRST outcome: the ICMP application type/code attribution is CORRECT
// end-to-end. The compiler maps `icmp-type` -> Application.ICMPType and
// `icmp-code` -> Application.ICMPCode with no swap (compiler_applications.go),
// carries both through the wire snapshot (capabilities.go / protocol.go), and
// the matcher checks the query TYPE against ICMPType and the query CODE against
// ICMPCode, with the code only required when the app constrains it (Go
// simulator matchSingleApp; Rust policy.rs icmp_constraints.find, type == ptype
// && code.map_or(true, |c| c == pcode)). So this is a COVERAGE test, not a fix.
//
// The gap it closes: the existing match-level tests (icmp_test.go,
// app_junos_ping_3348_test.go) exercise type-constrained `junos-icmp-ping` and
// XPF's custom alias compatibility path; `junos-ping` is protocol-only (#11340).
// None pins the icmp-CODE dimension through the end-to-end compile -> Match
// path, and none uses a distinctive type!=code pair, so a type<->code SWAP (or
// a silently-dropped / ignored code) in either the compiler or matcher would
// pass the current suite. These cases pin it: a wrong attribution (swap, drop,
// or mis-range) flips an assertion.

// TestICMPAppTypeCodeAttribution_CustomApp is the end-to-end fail-on-swap pin.
// A custom application `icmp-guard` constrains BOTH type 3 (destination
// unreachable) AND code 1 (host unreachable) — a deliberately asymmetric pair
// so a type<->code swap anywhere in the pipeline changes the match set.
func TestICMPAppTypeCodeAttribution_CustomApp(t *testing.T) {
	cfg := compileFromSet(t, []string{
		"set applications application icmp-guard protocol icmp",
		"set applications application icmp-guard icmp-type 3",
		"set applications application icmp-guard icmp-code 1",
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy allow match source-address any",
		"set security policies from-zone trust to-zone untrust policy allow match destination-address any",
		"set security policies from-zone trust to-zone untrust policy allow match application icmp-guard",
		"set security policies from-zone trust to-zone untrust policy allow then permit",
		"set security policies default-policy deny-all",
	})

	// Belt-and-suspenders: the compiled app must carry type 3 / code 1 in the
	// RIGHT fields. A compiler swap (icmp-type -> ICMPCode) is caught here even
	// before the matcher, because 3 != 1.
	app := cfg.Applications.Applications["icmp-guard"]
	if app == nil {
		t.Fatalf("application icmp-guard missing from compiled config")
	}
	if app.ICMPType == nil || *app.ICMPType != 3 {
		t.Fatalf("icmp-guard ICMPType = %v, want 3 (a swap with icmp-code would show 1)", app.ICMPType)
	}
	if app.ICMPCode == nil || *app.ICMPCode != 1 {
		t.Fatalf("icmp-guard ICMPCode = %v, want 1 (a swap with icmp-type would show 3)", app.ICMPCode)
	}

	tests := []struct {
		name        string
		icmpType    *uint8
		icmpCode    *uint8
		wantMatched bool
		wantAction  config.PolicyAction
	}{
		{
			// Exact attribution: type 3 AND code 1 -> permit.
			name: "type 3 code 1 permitted", icmpType: u8(3), icmpCode: u8(1),
			wantMatched: true, wantAction: config.PolicyPermit,
		},
		{
			// SWAP CATCH: type 1 code 3 is the transposed pair. If the compiler
			// or matcher confused type<->code, this would falsely permit. It must
			// fall through to default deny.
			name: "swapped type 1 code 3 denied", icmpType: u8(1), icmpCode: u8(3),
			wantMatched: false, wantAction: config.PolicyDeny,
		},
		{
			// Right type, WRONG code: the code constraint must fail closed.
			name: "type 3 code 0 denied (wrong code)", icmpType: u8(3), icmpCode: u8(0),
			wantMatched: false, wantAction: config.PolicyDeny,
		},
		{
			// Right type, code OMITTED: a code-constrained app must not match a
			// query with an unknown code (mirrors the dataplane pcode == None
			// path — the code cannot be confirmed, so fail closed).
			name: "type 3 code omitted denied", icmpType: u8(3), icmpCode: nil,
			wantMatched: false, wantAction: config.PolicyDeny,
		},
		{
			// Type OMITTED: a type-constrained app fails closed when the query
			// carries no type.
			name: "type omitted denied", icmpType: nil, icmpCode: u8(1),
			wantMatched: false, wantAction: config.PolicyDeny,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := Query{FromZone: "trust", ToZone: "untrust", Protocol: "icmp", ICMPType: tt.icmpType, ICMPCode: tt.icmpCode}
			res := Match(cfg, q)
			if res.Matched != tt.wantMatched || res.Action != tt.wantAction {
				t.Fatalf("icmp-guard (type 3 code 1) vs %s: got matched=%v action=%v, want matched=%v action=%v",
					tt.name, res.Matched, res.Action, tt.wantMatched, tt.wantAction)
			}
		})
	}
}

// TestICMPAppTypeOnly_MatchesAnyCode pins the complementary contract: a custom
// app that constrains ONLY the type (no icmp-code) must match that type
// regardless of the packet's code — the code must NOT be spuriously required.
// A regression that treated a nil ICMPCode as "code must be 0" would flip the
// nonzero-code case to deny.
func TestICMPAppTypeOnly_MatchesAnyCode(t *testing.T) {
	cfg := compileFromSet(t, []string{
		"set applications application type-guard protocol icmp",
		"set applications application type-guard icmp-type 3",
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy allow match source-address any",
		"set security policies from-zone trust to-zone untrust policy allow match destination-address any",
		"set security policies from-zone trust to-zone untrust policy allow match application type-guard",
		"set security policies from-zone trust to-zone untrust policy allow then permit",
		"set security policies default-policy deny-all",
	})

	app := cfg.Applications.Applications["type-guard"]
	if app == nil || app.ICMPType == nil || *app.ICMPType != 3 {
		t.Fatalf("type-guard ICMPType = %v, want 3", app)
	}
	if app.ICMPCode != nil {
		t.Fatalf("type-guard ICMPCode = %v, want nil (type-only app must not pin a code)", *app.ICMPCode)
	}

	tests := []struct {
		name        string
		icmpType    *uint8
		icmpCode    *uint8
		wantMatched bool
		wantAction  config.PolicyAction
	}{
		{"type 3 code 0 permitted", u8(3), u8(0), true, config.PolicyPermit},
		{"type 3 code 1 permitted", u8(3), u8(1), true, config.PolicyPermit},
		{"type 3 code 99 permitted", u8(3), u8(99), true, config.PolicyPermit},
		{"type 3 code omitted permitted", u8(3), nil, true, config.PolicyPermit},
		{"wrong type 5 code 1 denied", u8(5), u8(1), false, config.PolicyDeny},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := Query{FromZone: "trust", ToZone: "untrust", Protocol: "icmp", ICMPType: tt.icmpType, ICMPCode: tt.icmpCode}
			res := Match(cfg, q)
			if res.Matched != tt.wantMatched || res.Action != tt.wantAction {
				t.Fatalf("type-guard (type 3, any code) vs %s: got matched=%v action=%v, want matched=%v action=%v",
					tt.name, res.Matched, res.Action, tt.wantMatched, tt.wantAction)
			}
		})
	}
}

// TestICMPBuiltinAppsCarryCorrectTypeCode is the match-level cross-check for the
// junos-icmp-* builtins named in the #4422 slice. Their compiled type/code
// values are pinned structurally in pkg/config/predefined_icmp_3020_test.go;
// here we pin the OPERATOR-VISIBLE effect (the Match verdict) so a regression in
// the builtin definitions or the matcher flips a permit/deny:
//   - junos-icmp-ping is echo-request only (type 8), and its lack of a code
//     constraint means any code of type 8 matches (the code-agnostic contrast to
//     the code-constrained custom app above);
//   - junos-ping is protocol-only and permits all ICMP types.
func TestICMPBuiltinAppsCarryCorrectTypeCode(t *testing.T) {
	pingCfg := compileFromSet(t, []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy p match source-address any",
		"set security policies from-zone trust to-zone untrust policy p match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p match application junos-icmp-ping",
		"set security policies from-zone trust to-zone untrust policy p then permit",
		"set security policies default-policy deny-all",
	})
	allCfg := compileFromSet(t, []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy p match source-address any",
		"set security policies from-zone trust to-zone untrust policy p match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p match application junos-ping",
		"set security policies from-zone trust to-zone untrust policy p then permit",
		"set security policies default-policy deny-all",
	})

	tests := []struct {
		name        string
		cfg         *config.Config
		icmpType    *uint8
		icmpCode    *uint8
		wantMatched bool
		wantAction  config.PolicyAction
	}{
		// junos-icmp-ping is code-agnostic: any code of type 8 matches.
		{"junos-icmp-ping type 8 code 0 permitted", pingCfg, u8(8), u8(0), true, config.PolicyPermit},
		{"junos-icmp-ping type 8 code 5 permitted", pingCfg, u8(8), u8(5), true, config.PolicyPermit},
		{"junos-icmp-ping type 0 (echo-reply) denied", pingCfg, u8(0), u8(0), false, config.PolicyDeny},
		// junos-ping is protocol-only and permits any ICMP type/code.
		{"junos-ping type 3 code 1 permitted", allCfg, u8(3), u8(1), true, config.PolicyPermit},
		{"junos-ping type 8 code 9 permitted", allCfg, u8(8), u8(9), true, config.PolicyPermit},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := Query{FromZone: "trust", ToZone: "untrust", Protocol: "icmp", ICMPType: tt.icmpType, ICMPCode: tt.icmpCode}
			res := Match(tt.cfg, q)
			if res.Matched != tt.wantMatched || res.Action != tt.wantAction {
				t.Fatalf("%s: got matched=%v action=%v, want matched=%v action=%v",
					tt.name, res.Matched, res.Action, tt.wantMatched, tt.wantAction)
			}
		})
	}
}
