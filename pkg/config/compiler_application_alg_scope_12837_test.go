package config

import (
	"testing"
)

// #12837: the inert-ALG advisory's tag-eligibility helper disagreed with the
// userspace tagger (publish_conntrack.rs alg_type_for_session) in two ways.
//
//   - Protocol spelling: the helper compared the application protocol to the
//     literal "tcp"/"udp"/"6"/"17" only, while the SSOT (appid.ProtocolNumber)
//     also resolves the Junos predefined aliases `junos-tcp-any`/`junos-udp-any`
//     to 6/17 — a pin like `protocol junos-tcp-any destination-port 21 alg ftp`
//     matched tagged sessions yet drew a FALSE "no dataplane effect" warning.
//   - Global disable: the helper ignored `security alg <proto> disable`, but the
//     tagger honours the bitfield (ALG_DISABLE_*) and stamps ALG_TYPE_NONE for
//     every tuple of a disabled ALG, so a well-known-port pin was INERT yet
//     stayed SILENT — the operator never learned the knob nullified the ALG.
//
// Empty and range port specs that CONTAIN the service port remain taggable
// (tuple contract: "any tuple the tagger recognizes") — those must NOT warn
// merely because a disable or alias is present; see the guard tests below.
//
// Trees are built from flat `set` commands via flatTreeFromSets + refApp —
// the same AST shape the #11673 tests use.

// Core fail-on-revert (alias leg): a pin whose protocol is spelled with a
// Junos predefined alias resolves to the tagged protocol and must stay
// silent. Revert the alias folding and every subtest goes RED.
func TestApplicationALG_CanonicalAliasProtocol_TaggedPin_StaysSilent_12837(t *testing.T) {
	cases := []struct {
		name  string
		props []string
	}{
		{"ftp-tcp-any-port-21", []string{"protocol junos-tcp-any", "destination-port 21", "alg ftp"}},
		{"dns-udp-any-port-53", []string{"protocol junos-udp-any", "destination-port 53", "alg dns"}},
		{"sip-tcp-any-port-5060", []string{"protocol junos-tcp-any", "destination-port 5060", "alg sip"}},
		{"sip-udp-any-port-5060", []string{"protocol junos-udp-any", "destination-port 5060", "alg sip"}},
		{"ftp-tcp-any-no-port", []string{"protocol junos-tcp-any", "alg ftp"}},
		{"ftp-tcp-any-range-spanning-21", []string{"protocol junos-tcp-any", "destination-port 20-25", "alg ftp"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tree := flatTreeFromSets(t, refApp("aliasedalg", c.props...)...)
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("expected commit to accept %s: %v", c.name, err)
			}
			if hasWarningContaining(cfg.Warnings, "has no dataplane effect") {
				t.Fatalf("expected NO inert-pin warning for %s (junos-*-any resolves to the tagged protocol per appid.ProtocolNumber), got warnings: %v", c.name, cfg.Warnings)
			}
		})
	}
}

// Guard against over-widening: an alias pin whose protocol is NOT the ALG's
// protocol, or whose port is not the service port, still warns.
func TestApplicationALG_CanonicalAliasProtocol_WrongProtoOrPort_StillWarns_12837(t *testing.T) {
	cases := []struct {
		name  string
		props []string
	}{
		{"ftp-on-udp-any", []string{"protocol junos-udp-any", "destination-port 21", "alg ftp"}},
		{"ftp-on-tcp-any-custom-port", []string{"protocol junos-tcp-any", "destination-port 2121", "alg ftp"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tree := flatTreeFromSets(t, refApp("mismatchedalg", c.props...)...)
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("expected commit to accept %s (warn, not reject): %v", c.name, err)
			}
			if !hasWarningContaining(cfg.Warnings, `application mismatchedalg: alg "ftp"`) {
				t.Fatalf("expected an inert-pin warning naming mismatchedalg for %s, got warnings: %v", c.name, cfg.Warnings)
			}
		})
	}
}

// Core fail-on-revert (disable leg): `security alg <proto> disable` makes the
// tagger stamp ALG_TYPE_NONE for every tuple of that ALG, so even the
// well-known service-port pin is inert and MUST warn — naming the knob so the
// operator sees which config nullified the ALG. Revert the disable check and
// every subtest goes RED (master stays silent here).
func TestApplicationALG_GlobalDisable_WarnsNamingKnob_12837(t *testing.T) {
	cases := []struct {
		name  string
		knob  string
		props []string
	}{
		{"ftp-disabled-port-21", "ftp", []string{"protocol tcp", "destination-port 21", "alg ftp"}},
		{"dns-disabled-port-53", "dns", []string{"protocol udp", "destination-port 53", "alg dns"}},
		{"sip-disabled-port-5060", "sip", []string{"protocol udp", "destination-port 5060", "alg sip"}},
		{"ftp-disabled-no-port", "ftp", []string{"protocol tcp", "alg ftp"}},
		{"ftp-disabled-range-spanning-21", "ftp", []string{"protocol tcp", "destination-port 20-25", "alg ftp"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sets := append(refApp("disabledalg", c.props...),
				"set security alg "+c.knob+" disable")
			tree := flatTreeFromSets(t, sets...)
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("expected commit to ACCEPT %s (warn, not reject): %v", c.name, err)
			}
			if !hasWarningContaining(cfg.Warnings, `application disabledalg: alg "`+c.knob+`"`) {
				t.Fatalf("expected an inert-pin warning naming disabledalg for %s, got warnings: %v", c.name, cfg.Warnings)
			}
			if !hasWarningContaining(cfg.Warnings, "has no dataplane effect") {
				t.Fatalf("expected the warning to state the no-dataplane-effect contract for %s, got warnings: %v", c.name, cfg.Warnings)
			}
			if !hasWarningContaining(cfg.Warnings, "security alg "+c.knob+" disable") {
				t.Fatalf("expected the warning to name the `security alg %s disable` knob for %s, got warnings: %v", c.knob, c.name, cfg.Warnings)
			}
		})
	}
}

// Guard: a disable knob for a DIFFERENT ALG must not suppress or create a
// warning for a taggable pin — only the pin's own ALG's knob matters.
func TestApplicationALG_UnrelatedGlobalDisable_StaysSilent_12837(t *testing.T) {
	sets := append(refApp("okalg", "protocol tcp", "destination-port 21", "alg ftp"),
		"set security alg sip disable")
	tree := flatTreeFromSets(t, sets...)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("expected commit to accept the unrelated-disable config: %v", err)
	}
	if hasWarningContaining(cfg.Warnings, "has no dataplane effect") {
		t.Fatalf("expected NO inert-pin warning (sip disable does not affect FTP tagging), got warnings: %v", cfg.Warnings)
	}
}
