package config

import (
	"testing"
)

// #11673: a custom-port application with a KNOWN ALG name committed silently
// with zero dataplane effect — not even session tagging. The userspace
// dataplane derives conntrack alg_type from the well-known service port alone
// (FTP TCP/21, SIP TCP/5060 and UDP/5060, DNS UDP/53;
// publish_conntrack.rs alg_type_for_session) and the snapshot carries no
// per-application ALG field (only the global alg_disable_flags bitfield), so
// e.g. `alg ftp destination-port 2121` tags nothing: the control session is
// untagged and ungated on the live path. The commit must warn NAMING the
// inert pin (application + alg + port); enforcement of the pin itself stays
// deferred to the per-application ALG slice of #2008 (no dataplane change
// here).
//
// Trees are built from flat `set` commands via flatTreeFromSets + refApp /
// unrefAppOnly — the only correct way to exercise the flat-set AST shape.

// Core fail-on-revert: a known ALG pinned to a custom port commits (warn, not
// reject) AND warns naming the inert pin. Revert the warn pass and the commit
// goes silent — every warning assertion below goes RED.
func TestApplicationALG_KnownName_CustomPort_WarnsNamingPin_11673(t *testing.T) {
	cases := []struct{ alg, port string }{
		{"ftp", "2121"}, // the issue's example
		{"dns", "5353"},
		{"sip", "5070"},
		{"FTP", "2121"}, // case-insensitive, like validApplicationALG
		{"ftp", "2120-2122"},
	}
	for _, c := range cases {
		t.Run(c.alg+"/"+c.port, func(t *testing.T) {
			tree := flatTreeFromSets(t, refApp("customalg",
				"protocol tcp", "destination-port "+c.port, "alg "+c.alg)...)
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("expected commit to ACCEPT known alg %q on custom port %s (warn, not reject, #11673), got: %v", c.alg, c.port, err)
			}
			if !hasWarningContaining(cfg.Warnings, `application customalg: alg "`+c.alg+`" on destination-port "`+c.port+`"`) {
				t.Fatalf("expected an inert-pin warning naming application customalg + alg %q + port %s, got warnings: %v", c.alg, c.port, cfg.Warnings)
			}
			if !hasWarningContaining(cfg.Warnings, "has no dataplane effect") {
				t.Fatalf("expected the inert-pin warning to state the no-dataplane-effect contract, got warnings: %v", cfg.Warnings)
			}
		})
	}
}

// Guard against over-warning: a known ALG on its well-known port (or on an
// omitted / match-any port, or a range spanning the well-known port) stays
// silent — those sessions ARE tagged by port on the live path.
func TestApplicationALG_KnownName_WellKnownPort_StaysSilent_11673(t *testing.T) {
	cases := []struct {
		name  string
		props []string
	}{
		{"ftp-wellknown", []string{"protocol tcp", "destination-port 21", "alg ftp"}},
		{"dns-wellknown", []string{"protocol udp", "destination-port 53", "alg dns"}},
		{"sip-wellknown", []string{"protocol tcp", "destination-port 5060", "alg sip"}},
		{"ftp-range-spanning-21", []string{"protocol tcp", "destination-port 20-25", "alg ftp"}},
		{"ftp-no-port", []string{"protocol tcp", "alg ftp"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tree := flatTreeFromSets(t, refApp("okalgsilent", c.props...)...)
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("expected commit to accept %s: %v", c.name, err)
			}
			if hasWarningContaining(cfg.Warnings, "has no dataplane effect") {
				t.Fatalf("expected NO inert-pin warning for %s (well-known/match-any port is tagged by port), got warnings: %v", c.name, cfg.Warnings)
			}
		})
	}
}

// TFTP has no session tagging at ANY port (alg_type is none/FTP/SIP/DNS
// only), so a TFTP pin is inert even on UDP/69 — it always warns.
func TestApplicationALG_TFTP_AlwaysWarnsInert_11673(t *testing.T) {
	for _, props := range [][]string{
		{"protocol udp", "destination-port 69", "alg tftp"},
		{"protocol udp", "alg tftp"},
	} {
		tree := flatTreeFromSets(t, refApp("tftpapp", props...)...)
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("expected commit to ACCEPT tftp pin (warn, not reject, #11673), got: %v", err)
		}
		if !hasWarningContaining(cfg.Warnings, `application tftpapp: alg "tftp"`) {
			t.Fatalf("expected an inert-pin warning naming the tftp pin (%v), got warnings: %v", props, cfg.Warnings)
		}
		if !hasWarningContaining(cfg.Warnings, "no TFTP session tagging") {
			t.Fatalf("expected the tftp warning to state no tagging exists at any port (%v), got warnings: %v", props, cfg.Warnings)
		}
	}
}

// Scope: an UNREFERENCED user application with a custom-port ALG pin warns
// too — the advisory iterates every user app, referenced or not (mirrors the
// #4337 unreferenced scope).
func TestApplicationALG_CustomPort_Unreferenced_Warns_11673(t *testing.T) {
	tree := flatTreeFromSets(t, unrefAppOnly("lonelyalg", "protocol tcp", "destination-port 2121", "alg ftp")...)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("expected commit to ACCEPT custom-port alg on an UNREFERENCED app (warn, not reject, #11673), got: %v", err)
	}
	if !hasWarningContaining(cfg.Warnings, `application lonelyalg: alg "ftp" on destination-port "2121"`) {
		t.Fatalf("expected an inert-pin warning naming lonelyalg, got warnings: %v", cfg.Warnings)
	}
}
