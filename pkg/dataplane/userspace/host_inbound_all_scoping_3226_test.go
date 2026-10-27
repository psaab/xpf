package userspace

import "testing"

// host_inbound_all_scoping_3226_test.go is the VERDICT guard for #3226: the
// scoping of `host-inbound-traffic system-services all` from a packet-wide
// admit to the union of the named system-services.
//
// Junos scopes `all` to "traffic from the defined system services available on
// the Routing Engine" (Juniper, `system-services (Security Zones Host Inbound
// Traffic)`), and its documented service list carries no raw IP protocol —
// GRE/ESP/OSPF/PIM/VRRP arrive through `protocols`, never through
// `system-services`. Before #3226 xpf short-circuited `all` to a full admit on
// both enforcement layers, so an `all` zone accepted EVERY IP protocol and port
// to its local addresses with no catch-all deny at all: a fail-OPEN relative to
// the Junos meaning that could mask a missing explicit `protocols` entry.
//
// These tests assert the ADMIT/DENY VERDICT for concrete packet tuples, not the
// shape of any intermediate structure — a structure-only assertion would pass
// straight through a policy widening.

// TestClassifyHostInboundSystemServicesAllScopedToNamedServices is the #3226
// RED-on-revert core: `system-services all` alone must ADMIT the named
// system-services and DENY every raw IP protocol the pre-#3226 blanket admit
// let through.
//
// FAIL-ON-REVERT: restore the full-admit short-circuit (teach
// config.HostInboundFullAdmitService to return true for "all", or drop the
// `case "all"` expansion from config.HostInboundServiceMatch) and every DENIED
// row below flips to admitted.
func TestClassifyHostInboundSystemServicesAllScopedToNamedServices(t *testing.T) {
	const (
		TCP = uint8(6)
		UDP = uint8(17)
	)
	cfg := cfgWithHostInbound("edge", []string{"all"}, nil)

	// --- ADMITTED: the named system-service union `all` now stands for. ------
	admitted := []struct {
		name  string
		proto uint8
		port  int
	}{
		{"ssh tcp/22", TCP, 22},
		{"https tcp/443", TCP, 443},
		{"telnet tcp/23", TCP, 23},
		{"snmp udp/161", UDP, 161},
		{"ntp udp/123", UDP, 123},
		{"dns udp/53", UDP, 53},
		{"ike udp/500", UDP, 500},
		{"netconf tcp/830", TCP, 830},
	}
	for _, tc := range admitted {
		got := ClassifyHostInbound(cfg, "edge", tc.proto, true, tc.port, tc.port != 0, nil, "ip")
		if got.Status != HostInboundTokenAdmit {
			t.Errorf("%s with system-services all: got %+v, want token-admit (`all` expands to the named service union)", tc.name, got)
		}
	}

	// --- DENIED: raw IP protocols Junos `all` never opens. -------------------
	// These are exactly the protocols the issue names. ESP (50) / AH (51) are
	// deliberately absent: they carry an unconditional global accept for
	// host-terminated IPsec (#3171) that is orthogonal to the host-inbound
	// token set, so they would be admitted regardless of this change and prove
	// nothing about the scoping.
	deniedProtos := []struct {
		name  string
		proto uint8
	}{
		{"ospf proto 89", 89},
		{"gre proto 47", 47},
		{"vrrp proto 112", 112},
		{"pim proto 103", 103},
		{"nhrp proto 54", 54},
		{"an unassigned future protocol 253", 253},
	}
	for _, tc := range deniedProtos {
		got := ClassifyHostInbound(cfg, "edge", tc.proto, true, 0, false, nil, "ip")
		if got.Status != HostInboundDenied {
			t.Errorf("%s with system-services all: got %+v, want DENIED — `all` is the union of named system-services, not a packet-wide admit (#3226)", tc.name, got)
		}
	}

	// --- DENIED: an unlisted TCP/UDP port. -----------------------------------
	// The catch-all deny is re-armed for the zone, so a port outside the named
	// service union is denied just as it is for any explicit service list.
	if got := ClassifyHostInbound(cfg, "edge", TCP, true, 9999, true, nil, "ip"); got.Status != HostInboundDenied {
		t.Errorf("tcp/9999 with system-services all: got %+v, want DENIED (unlisted port, #3226)", got)
	}
}

// TestClassifyHostInboundSystemServicesAllExcludesGRE pins the xpf-extension
// carve-out. `gre` is NOT a Junos system-service (Junos has no raw-IP-protocol
// service token); xpf accepts it because operator configs list it there. It is
// therefore excluded from the `all` expansion — otherwise `all` would silently
// open a protocol Junos's `all` never opens, which is the very over-admit
// #3226 closes. The token stays fully usable when listed EXPLICITLY.
//
// FAIL-ON-REVERT: drop "gre" from config.HostInboundNonJunosSystemServices and
// the first row (deny) flips to admitted.
func TestClassifyHostInboundSystemServicesAllExcludesGRE(t *testing.T) {
	const gre = uint8(47)

	if got := ClassifyHostInbound(cfgWithHostInbound("edge", []string{"all"}, nil),
		"edge", gre, true, 0, false, nil, "ip"); got.Status != HostInboundDenied {
		t.Errorf("gre proto 47 with system-services all: got %+v, want DENIED (gre is an xpf extension, excluded from the Junos `all` union)", got)
	}

	// Explicitly listed, it is admitted — the carve-out narrows `all`, it does
	// not remove the token.
	if got := ClassifyHostInbound(cfgWithHostInbound("edge", []string{"gre"}, nil),
		"edge", gre, true, 0, false, nil, "ip"); got.Status != HostInboundTokenAdmit || got.Token != "gre" {
		t.Errorf("gre proto 47 with an explicit system-services gre: got %+v, want token-admit gre", got)
	}
}

// TestClassifyHostInboundAllAdmitsDocumentedJunosServices is the fail-CLOSED
// half of the #3226 contract. Scoping `all` to the recognized-token union only
// preserves Junos semantics if that union actually CONTAINS every service
// Juniper defines. Several did not exist in xpf at all, so before this fold an
// authored `all` stopped admitting them AND the operator could not restore them
// by naming the service, because strict validation rejects any token outside
// the same allowlist (validateHostInboundStanzaStrict). That is a hard
// regression for a real service, not an over-admit closed.
//
// The union is derived from Juniper's published YANG schema, vendored at
// pkg/config/testdata/junos-es-conf-security@2024-01-01.yang.gz. The prose
// reference pages are individually incomplete and had this set wrong three
// times.
//
// This test covers the services with a port Juniper actually FIXES:
// reverse-telnet tcp/2900 and reverse-ssh tcp/2901 (explicit YANG `default`
// statements on `[edit system services reverse telnet|ssh] port`), and
// lsselfping udp/8503 (RFC 7746 §3/§6 — NOT 3503, which is `lsping`). The Junos
// services xpf has no authoritative port for are covered by
// TestClassifyHostInboundUnportedServicesAdmitNothing below.
//
// FAIL-ON-REVERT: drop any of these from config.KnownHostInboundSystemServices
// (or from config.HostInboundServiceMatch) and its rows flip to denied.
func TestClassifyHostInboundAllAdmitsDocumentedJunosServices(t *testing.T) {
	const (
		TCP = uint8(6)
		UDP = uint8(17)
	)
	all := cfgWithHostInbound("edge", []string{"all"}, nil)

	for _, tc := range []struct {
		name  string
		token string
		proto uint8
		port  int
	}{
		{"reverse-telnet tcp/2900", "reverse-telnet", TCP, 2900},
		{"reverse-ssh tcp/2901", "reverse-ssh", TCP, 2901},
		{"lsselfping udp/8503", "lsselfping", UDP, 8503},
	} {
		// Reached through the `all` union.
		if got := ClassifyHostInbound(all, "edge", tc.proto, true, tc.port, tc.port != 0, nil, "ip"); got.Status != HostInboundTokenAdmit {
			t.Errorf("%s with system-services all: got %+v, want token-admit — %q is a documented Junos system-service and `all` is the union of them", tc.name, got, tc.token)
		}
		// And reachable by NAMING the service, which is what makes the union
		// restorable rather than a dead end.
		named := cfgWithHostInbound("edge", []string{tc.token}, nil)
		if got := ClassifyHostInbound(named, "edge", tc.proto, true, tc.port, tc.port != 0, nil, "ip"); got.Status != HostInboundTokenAdmit || got.Token != tc.token {
			t.Errorf("%s with an explicit system-services %s: got %+v, want token-admit %s", tc.name, tc.token, got, tc.token)
		}
	}
}

// TestClassifyHostInboundUnportedServicesAdmitNothing is the unverified-port
// half of the #3226 fold, stated as a VERDICT: a Junos service xpf has no
// authoritative listening port to admit for must admit NOTHING — whether
// reached through `all` or named explicitly. Two of them (rpm, r2cp) have a
// port Junos documents as operator-chosen; for the other three xpf simply could
// not find it. Those are different statements — see
// config.HostInboundNoAdmitReason — and neither licenses inventing a port.
//
// An earlier revision of this fold synthesized ports for two of them:
//
//	r2cp udp/28762 — draft-dubois-r2cp-00 calls 28762 a value prototypes
//	  "suggested"; Juniper adopts it in neither schema nor documentation.
//	  `[edit protocols r2cp] server-port` is range 1..65535 with NO YANG default.
//	rpm tcp+udp/7  — 7 is the FLOOR of the `[edit services rpm probe-server]
//	  port` range ("Port number 7 through 65535"), not a default; the
//	  probe-server container is presence-gated, so nothing listens at all
//	  without explicit configuration.
//
// An unverified port does not fail safe in one direction — it opens a port with
// no listener on every `all` zone AND still denies the port actually in use.
// The basis is a deliberate CHOICE under uncertainty, NOT an inference from the
// schema: no authoritative host-inbound tuple was found for these tokens, and
// under that gap opening nothing fails in one direction and visibly, whereas a
// guessed port fails in both directions and silently. (An earlier revision
// argued the absence of a YANG `default` proved no fixed port existed; that is
// false — `[edit system services telnet]` has no port leaf either, yet telnet is
// TCP/23 — and has been withdrawn.)
//
// FAIL-ON-REVERT: restore a synthesized port (add a case arm in
// config.HostInboundServiceMatch, or drop the token from
// config.HostInboundUnportedSystemServices) and the matching row flips to
// admitted.
func TestClassifyHostInboundUnportedServicesAdmitNothing(t *testing.T) {
	const (
		TCP = uint8(6)
		UDP = uint8(17)
	)
	all := cfgWithHostInbound("edge", []string{"all"}, nil)

	// The two historical guesses, plus ports these services plausibly reach.
	probes := []struct {
		name  string
		proto uint8
		port  int
	}{
		{"the r2cp draft-suggested udp/28762", UDP, 28762},
		{"the rpm range-floor tcp/7", TCP, 7},
		{"the rpm range-floor udp/7", UDP, 7},
		{"the appqoe PASSIVE-probe udp/36000 (transit; Juniper says DISCARD it inbound)", UDP, 36000},
	}
	for _, tc := range probes {
		for _, family := range []string{"ip", "ip6"} {
			if got := ClassifyHostInbound(all, "edge", tc.proto, true, tc.port, tc.port != 0, nil, family); got.Status != HostInboundDenied {
				t.Errorf("%s with system-services all (%s): got %+v, want DENIED — no service in "+
					"Juniper's enumeration fixes this port (#3226)", tc.name, family, got)
			}
		}
	}

	// Naming an unported service explicitly admits nothing either: xpf has no
	// port it can justify admitting, so the stanza is a documented no-op rather
	// than a guess.
	for _, token := range []string{"r2cp", "rpm", "tcp-encap", "appqoe", "high-availability"} {
		named := cfgWithHostInbound("edge", []string{token}, nil)
		for _, tc := range probes {
			if got := ClassifyHostInbound(named, "edge", tc.proto, true, tc.port, tc.port != 0, nil, "ip"); got.Status != HostInboundDenied {
				t.Errorf("explicit `system-services %s`: %s got %+v, want DENIED — xpf has no "+
					"authoritative listening port for this service. For rpm/r2cp the port is "+
					"operator-configured, so none exists to restore; for tcp-encap/appqoe/"+
					"high-availability it is UNSOURCED — a port may well exist, we could not "+
					"source it, and inventing one would open the firewall to itself (#3226)",
					token, tc.name, got)
			}
		}
	}

	// Anti-vacuity: `all` must still admit the services that DO carry a fixed
	// port, or every deny above would prove nothing.
	for _, tc := range []struct {
		name  string
		proto uint8
		port  int
	}{
		{"reverse-telnet tcp/2900", TCP, 2900},
		{"reverse-ssh tcp/2901", TCP, 2901},
		{"lsselfping udp/8503", UDP, 8503},
		{"ssh tcp/22", TCP, 22},
	} {
		if got := ClassifyHostInbound(all, "edge", tc.proto, true, tc.port, tc.port != 0, nil, "ip"); got.Status != HostInboundTokenAdmit {
			t.Errorf("%s with system-services all: got %+v, want token-admit — otherwise the deny "+
				"assertions above are vacuous", tc.name, got)
		}
	}
}

// TestClassifyHostInboundSystemServicesAllExcludesRexec pins the second
// xpf-extension carve-out. Juniper's host-inbound service list — zone-level and
// interface-level — documents `rlogin` and `rsh` but NOT rexec, so a
// Junos-correct `all` never opens TCP/512. Unlike the other xpf-only spellings
// (`webapi-clear-text`/`webapi-ssl` → the http/https ports,
// `ssh-netconf`/`netconf-ssh` → ssh ∪ netconf) `r-exec` is not a port-neutral
// alias: 512 is opened by no other token, so including it in the expansion
// widened `all` past the Junos meaning #3226 exists to restore.
//
// FAIL-ON-REVERT: drop "r-exec"/"rexec" from
// config.HostInboundNonJunosSystemServices and the first row flips to admitted.
func TestClassifyHostInboundSystemServicesAllExcludesRexec(t *testing.T) {
	const TCP = uint8(6)

	if got := ClassifyHostInbound(cfgWithHostInbound("edge", []string{"all"}, nil),
		"edge", TCP, true, 512, true, nil, "ip"); got.Status != HostInboundDenied {
		t.Errorf("rexec tcp/512 with system-services all: got %+v, want DENIED (rexec is an xpf extension, absent from Juniper's documented service list)", got)
	}

	// Both spellings stay fully usable when listed EXPLICITLY — the carve-out
	// narrows `all`, it does not remove the token.
	for _, tok := range []string{"r-exec", "rexec"} {
		if got := ClassifyHostInbound(cfgWithHostInbound("edge", []string{tok}, nil),
			"edge", TCP, true, 512, true, nil, "ip"); got.Status != HostInboundTokenAdmit || got.Token != tok {
			t.Errorf("rexec tcp/512 with an explicit system-services %s: got %+v, want token-admit %s", tok, got, tok)
		}
	}
}

// TestClassifyHostInboundAnyServiceStillFullAdmit pins the other half of the
// #3226 contract: `any-service` REMAINS the packet-wide escape hatch. Junos
// defines it as "all system services on an entire port range including the
// system services that are not defined", so it is the documented way to admit
// what the named set does not cover — and the one-token migration for a config
// that relied on the pre-#3226 breadth of `all`.
//
// OVER-REACH GUARD: if the #3226 narrowing were applied to `any-service` too,
// every row here flips to denied.
func TestClassifyHostInboundAnyServiceStillFullAdmit(t *testing.T) {
	cfg := cfgWithHostInbound("edge", []string{"any-service"}, nil)

	for _, tc := range []struct {
		name  string
		proto uint8
		port  int
	}{
		{"ospf proto 89", 89, 0},
		{"gre proto 47", 47, 0},
		{"vrrp proto 112", 112, 0},
		{"an unlisted tcp/9999", 6, 9999},
	} {
		got := ClassifyHostInbound(cfg, "edge", tc.proto, true, tc.port, tc.port != 0, nil, "ip")
		if got.Status != HostInboundTokenAdmit || got.Token != "any-service" {
			t.Errorf("%s with system-services any-service: got %+v, want token-admit any-service (full-admit escape hatch retained)", tc.name, got)
		}
	}
}

// TestClassifyHostInboundSystemServicesAllPlusProtocols proves the two `all`
// tokens compose the way Junos means them to: `system-services all` supplies
// the service union and `protocols all` supplies the routing set, and a
// protocol reached ONLY through `protocols` (ospf) needs that explicit entry.
//
// This is the acceptance criterion stated in the issue: "`system-services all`
// admits SSH/HTTPS/SNMP but denies OSPF/GRE/VRRP unless a matching `protocols`
// entry exists".
func TestClassifyHostInboundSystemServicesAllPlusProtocols(t *testing.T) {
	const (
		TCP  = uint8(6)
		ospf = uint8(89)
	)

	// system-services all ALONE: ssh admitted, ospf denied.
	svcOnly := cfgWithHostInbound("edge", []string{"all"}, nil)
	if got := ClassifyHostInbound(svcOnly, "edge", TCP, true, 22, true, nil, "ip"); got.Status != HostInboundTokenAdmit {
		t.Fatalf("ssh tcp/22 with system-services all: got %+v, want token-admit", got)
	}
	if got := ClassifyHostInbound(svcOnly, "edge", ospf, true, 0, false, nil, "ip"); got.Status != HostInboundDenied {
		t.Fatalf("ospf proto 89 with system-services all only: got %+v, want DENIED", got)
	}

	// Add the matching `protocols ospf` entry and ospf is admitted — the
	// operator now says what they mean, which is the point of the narrowing.
	withProto := cfgWithHostInbound("edge", []string{"all"}, []string{"ospf"})
	if got := ClassifyHostInbound(withProto, "edge", ospf, true, 0, false, nil, "ip"); got.Status != HostInboundTokenAdmit || got.Kind != "protocols" {
		t.Fatalf("ospf proto 89 with system-services all + protocols ospf: got %+v, want token-admit via protocols", got)
	}
}
