package policymatch

import (
	"net"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #4394 — the `request security match-policies` simulator only detected
// content-rejection for an UNEXPANDABLE application-set (#3727). The DATAPLANE
// (userspace-dp/src/policy.rs) ALSO fails the WHOLE snapshot CLOSED on:
//
//   (1) a protocol-less application (proto=="" -> expandUserspacePolicyApplications
//       ok=false -> __unsupported__ sentinel -> Rust
//       SnapshotIntegrityError::UnrepresentableApplicationProtocol);
//   (2) an unrepresentable protocol or port (appid.ProtocolNumber /
//       userspacePortSpecRepresentable rejects it -> same sentinel/reject);
//   (3) an undefined application reference (resolveUserspaceApplicationNames
//       ok=false -> same sentinel/reject);
//   (4) an unresolvable address — an undefined address-book / prefix-list name,
//       or a defined book whose value is a non-literal (dns-name / wildcard /
//       range) -> __unsupported_address__ sentinel -> Rust
//       SnapshotIntegrityError::UnrepresentableAddress.
//
// In each case the helper retains its previous-good snapshot (or fresh-boots
// default-deny) and enforces NONE of the config. The pre-#4394 simulator SKIPPED
// the unrepresentable term (a per-term no-match) and fell through to a later rule
// / the configured default-policy, FABRICATING a permit/deny/default verdict.
// Under a default-PERMIT it reported PERMIT for a config the dataplane
// fail-closes (a dangerous operator lie). These tests pin the fail-closed-parity
// fix: any of the four conditions makes Match report the first-class
// ContentRejected verdict for EVERY query, matching the dataplane.
//
// RED-ON-REVERT: dropping the config-wide ContentRejected gate (or the
// dpuserspace.PolicyContentRejectionReasons detection) makes each config fall
// through to the default-PERMIT (Matched=false, DefaultUsed=true, Action=permit,
// ContentRejected=false), failing the want-ContentRejected assertions below.

// assertContentRejected checks the ContentRejected verdict invariants shared by
// all four #4394 conditions: the whole config is content-rejected, no rule
// matched, no default verdict was fabricated, and the reason names the offending
// policy scope.
func assertContentRejected(t *testing.T, res Result, wantScope string) {
	t.Helper()
	if !res.ContentRejected {
		t.Fatalf("ContentRejected = false, want true: the dataplane fails this config closed; the simulator must not fabricate a verdict (res = %+v)", res)
	}
	if res.Matched || res.DefaultUsed || res.HostInboundUnmatched {
		t.Fatalf("Matched=%v DefaultUsed=%v HostInboundUnmatched=%v, want all false for a ContentRejected verdict (res = %+v)",
			res.Matched, res.DefaultUsed, res.HostInboundUnmatched, res)
	}
	if res.DisplayAction() != ContentRejectedActionString {
		t.Fatalf("DisplayAction() = %q, want ContentRejectedActionString", res.DisplayAction())
	}
	reason := strings.Join(res.ContentRejectionReasons, " | ")
	if !strings.Contains(reason, wantScope) {
		t.Fatalf("reason %q does not name the offending policy scope %q", reason, wantScope)
	}
}

// TestContentRejectProtocolLessApp4394 — condition (1): a named application with
// no protocol. The default-PERMIT would fabricate a PERMIT verdict pre-fix.
func TestContentRejectProtocolLessApp4394(t *testing.T) {
	cfg := cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyPermit,
		Policies: []*config.ZonePairPolicies{
			zonePair("trust", "untrust", permit("permit-noproto",
				config.PolicyMatch{Applications: []string{"noproto"}})),
		},
	}, config.ApplicationsConfig{
		Applications: map[string]*config.Application{
			"noproto": {Name: "noproto"}, // no protocol -> unrepresentable
		},
	})

	res := Match(cfg, Query{FromZone: "trust", ToZone: "untrust", Protocol: "tcp", DstPort: PortPtr(80)})
	assertContentRejected(t, res, "trust->untrust/permit-noproto")
}

// TestContentRejectUnrepresentablePort4394 — condition (2): a named application
// whose destination-port exceeds the u16 wire space (userspacePortSpecRepresentable
// rejects "70000"). Mirrors the #2124/#4345 dataplane reject.
func TestContentRejectUnrepresentablePort4394(t *testing.T) {
	cfg := cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyPermit,
		Policies: []*config.ZonePairPolicies{
			zonePair("trust", "untrust", permit("permit-badport",
				config.PolicyMatch{Applications: []string{"badport"}})),
		},
	}, config.ApplicationsConfig{
		Applications: map[string]*config.Application{
			// Valid protocol, but a destination-port the u16 wire cannot carry.
			"badport": {Name: "badport", Protocol: "tcp", DestinationPort: "70000"},
		},
	})

	res := Match(cfg, Query{FromZone: "trust", ToZone: "untrust", Protocol: "tcp", DstPort: PortPtr(80)})
	assertContentRejected(t, res, "trust->untrust/permit-badport")
}

// TestContentRejectUnrepresentableProtocol4394 — condition (2) protocol variant:
// a named application whose protocol appid.ProtocolNumber cannot resolve.
func TestContentRejectUnrepresentableProtocol4394(t *testing.T) {
	cfg := cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyPermit,
		Policies: []*config.ZonePairPolicies{
			zonePair("trust", "untrust", permit("permit-badproto",
				config.PolicyMatch{Applications: []string{"badproto"}})),
		},
	}, config.ApplicationsConfig{
		Applications: map[string]*config.Application{
			"badproto": {Name: "badproto", Protocol: "not-a-protocol"},
		},
	})

	res := Match(cfg, Query{FromZone: "trust", ToZone: "untrust", Protocol: "tcp", DstPort: PortPtr(80)})
	assertContentRejected(t, res, "trust->untrust/permit-badproto")
}

// TestContentRejectUndefinedApp4394 — condition (3): `match application X` where
// X is neither a defined application nor an application-set. The pre-fix
// matchSingleApp returned false (no-match) and the query fell through to
// default-permit; the dataplane instead poisons the rule with the
// __unsupported__ sentinel and fails the whole snapshot closed.
func TestContentRejectUndefinedApp4394(t *testing.T) {
	cfg := cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyPermit,
		Policies: []*config.ZonePairPolicies{
			zonePair("trust", "untrust", permit("permit-undef-app",
				config.PolicyMatch{Applications: []string{"no-such-app"}})),
		},
	}, config.ApplicationsConfig{})

	res := Match(cfg, Query{FromZone: "trust", ToZone: "untrust", Protocol: "tcp", DstPort: PortPtr(80)})
	assertContentRejected(t, res, "trust->untrust/permit-undef-app")
}

// TestContentRejectUnresolvableAddress4394 — condition (4): `match source-address
// missing-book` where missing-book is not in the address book. The pre-fix
// matchAddr resolved it to no prefix (MatchNone) and the query fell through to
// default-permit; the dataplane instead emits the __unsupported_address__
// sentinel and fails the whole snapshot closed.
func TestContentRejectUnresolvableAddress4394(t *testing.T) {
	cfg := cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyPermit,
		Policies: []*config.ZonePairPolicies{
			zonePair("trust", "untrust", permit("permit-missing-book",
				config.PolicyMatch{SourceAddresses: []string{"missing-book"}})),
		},
	}, config.ApplicationsConfig{})

	res := Match(cfg, Query{
		FromZone: "trust", ToZone: "untrust", Protocol: "tcp",
		SrcIP: net.ParseIP("10.0.1.5"), DstIP: net.ParseIP("10.0.2.5"), DstPort: PortPtr(80),
	})
	assertContentRejected(t, res, "trust->untrust/permit-missing-book")
}

// TestContentRejectNonLiteralAddressBook4394 — condition (4) variant: a DEFINED
// address-book entry whose value is empty (the compiler stores "" for a Junos
// dns-name / wildcard-address / range-address that the userspace matcher cannot
// represent). nameRepresentable rejects it, so the dataplane emits the
// __unsupported_address__ sentinel and fails closed — the simulator must not
// widen the empty value to match-any / fall through.
func TestContentRejectNonLiteralAddressBook4394(t *testing.T) {
	cfg := cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyPermit,
		AddressBook: &config.AddressBook{
			Addresses: map[string]*config.Address{
				// Empty Value models a dns-name/wildcard/range that compiled to
				// no concrete prefix (compiler_validate_warn.go).
				"dns-book": {Name: "dns-book"},
			},
		},
		Policies: []*config.ZonePairPolicies{
			zonePair("trust", "untrust", permit("permit-dns-book",
				config.PolicyMatch{DestinationAddresses: []string{"dns-book"}})),
		},
	}, config.ApplicationsConfig{})

	res := Match(cfg, Query{
		FromZone: "trust", ToZone: "untrust", Protocol: "tcp",
		SrcIP: net.ParseIP("10.0.1.5"), DstIP: net.ParseIP("10.0.2.5"), DstPort: PortPtr(80),
	})
	assertContentRejected(t, res, "trust->untrust/permit-dns-book")
}

// TestContentRejectPoisonsWholeConfig4394 — the fail-close is CONFIG-WIDE: a
// single unrepresentable rule (here an undefined app in dmz->wan) content-rejects
// EVERY query, including one whose own zone pair has a perfectly clean rule the
// query would otherwise match. Mirrors the whole-snapshot dataplane reject.
func TestContentRejectPoisonsWholeConfig4394(t *testing.T) {
	cfg := cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		Policies: []*config.ZonePairPolicies{
			zonePair("trust", "untrust", permit("clean-http",
				config.PolicyMatch{Applications: []string{"junos-http"}})),
			zonePair("dmz", "wan", permit("permit-undef-app",
				config.PolicyMatch{Applications: []string{"no-such-app"}})),
		},
	}, config.ApplicationsConfig{})

	// This query matches the clean trust->untrust permit pre-fix, but the config
	// is poisoned by the dmz->wan undefined-app rule.
	res := Match(cfg, Query{FromZone: "trust", ToZone: "untrust", Protocol: "tcp", DstPort: PortPtr(80)})
	assertContentRejected(t, res, "dmz->wan/permit-undef-app")
}

// TestContentRejectNoOverReport4394 is the non-regression control: a config whose
// every rule is representable (defined resolvable book, representable app with a
// valid port) must NOT be content-rejected and must report its REAL permit/deny
// verdict. This is the no-over-report proof — the gate flags ONLY the conditions
// the dataplane actually fails closed on, never a healthy config.
func TestContentRejectNoOverReport4394(t *testing.T) {
	cfg := cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		AddressBook: &config.AddressBook{
			Addresses: map[string]*config.Address{
				"trust-net": {Name: "trust-net", Value: "10.0.1.0/24"},
			},
		},
		Policies: []*config.ZonePairPolicies{
			zonePair("trust", "untrust", permit("allow-web",
				config.PolicyMatch{
					SourceAddresses: []string{"trust-net"},
					Applications:    []string{"junos-http", "web-8080"},
				})),
		},
	}, config.ApplicationsConfig{
		Applications: map[string]*config.Application{
			// Representable custom app: valid protocol + valid u16 port.
			"web-8080": {Name: "web-8080", Protocol: "tcp", DestinationPort: "8080"},
		},
	})

	// Matches junos-http (tcp/80) from the trust-net source.
	res := Match(cfg, Query{
		FromZone: "trust", ToZone: "untrust", Protocol: "tcp",
		SrcIP: net.ParseIP("10.0.1.5"), DstPort: PortPtr(80),
	})
	if res.ContentRejected {
		t.Fatalf("ContentRejected = true for a fully-representable config (over-report); reasons=%v", res.ContentRejectionReasons)
	}
	if !res.Matched || res.Action != config.PolicyPermit || res.PolicyName != "allow-web" {
		t.Fatalf("healthy config did not report its real permit verdict: Matched=%v Action=%v Name=%q", res.Matched, res.Action, res.PolicyName)
	}

	// The representable custom app also matches on tcp/8080 (no over-narrowing).
	res = Match(cfg, Query{
		FromZone: "trust", ToZone: "untrust", Protocol: "tcp",
		SrcIP: net.ParseIP("10.0.1.5"), DstPort: PortPtr(8080),
	})
	if res.ContentRejected {
		t.Fatalf("ContentRejected = true for a representable custom-port app (over-report); reasons=%v", res.ContentRejectionReasons)
	}
	if !res.Matched || res.Action != config.PolicyPermit {
		t.Fatalf("representable custom app tcp/8080 did not match: res = %+v", res)
	}
}
