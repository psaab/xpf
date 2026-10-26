// RED-on-revert tests for #6532: the gRPC ShowText{Topic:"snmp"} render must
// mask the secret SNMPv1/v2c community NAME, which IS the authenticator for
// v1/v2c and is also the Communities map KEY — the one operator secret the
// config.Secret newtype's String() redaction does not cover.
//
// Both sibling surfaces were hardened first and this one was left in the clear:
// pkg/cli `show snmp` / `show system services` (#4111, per login class) and the
// pkg/api show-text handler (#5315, unconditional). The gRPC mask is
// unconditional, matching pkg/api and the sibling gRPC ShowConfig raw-AST
// redaction (#4051): gRPC carries no login class to gate on.
//
// The usual "loopback only" mitigation does not apply: ShowText is on the
// cluster-fabric allowlist (#4122, server_fabric_allowlist_4122_test.go), so
// this render is reachable from the peer chassis over the fabric IP.
//
// These tests assert on the RENDERED ShowText response — the bytes that leave
// the process — not on an intermediate struct. Reverting the mask in
// showSNMP() makes the redaction subtest go RED (the cleartext community
// sentinel reappears in resp.Output). The over-reach subtest asserts the
// NON-secret SNMP fields still render, so a revert that masks everything is
// caught too, and it must stay GREEN under revert.
package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// snmpCommunitySentinel is the cleartext community credential staged below. A
// leak is identifiable by this string alone.
const snmpCommunitySentinel = "GRPC6532-LEAK-SNMP-COMMUNITY"

// snmpRenderConfig stages an SNMP stanza carrying the secret community
// alongside every NON-secret field the snmp topic renders, so one config
// exercises both the redaction and the over-reach guard.
var snmpRenderConfig = []string{
	"set snmp location GRPC6532-LOCATION-RACK-42",
	"set snmp contact GRPC6532-CONTACT-NOC",
	"set snmp description GRPC6532-DESCRIPTION-EDGE-FW",
	"set snmp community " + snmpCommunitySentinel + " authorization read-only",
	"set snmp trap-group tg1 targets 10.9.9.9",
	"set snmp v3 usm local-engine user u1 authentication-sha256 authentication-password GRPC6532-LEAK-V3AUTH",
	"set snmp v3 usm local-engine user u1 privacy-des privacy-password GRPC6532-LEAK-V3PRIV",
}

// newSNMPRenderServer commits snmpRenderConfig into a real configstore and
// returns a Server reading it, so ShowText renders the same typed active
// config the daemon serves.
func newSNMPRenderServer(t *testing.T) *Server {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure(): %v", err)
	}
	if _, err := store.LoadSet(strings.Join(snmpRenderConfig, "\n")); err != nil {
		t.Fatalf("LoadSet(): %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit(): %v", err)
	}
	return &Server{store: store}
}

// showTextOutput drives the real ShowText RPC and returns the rendered body.
func showTextOutput(t *testing.T, s *Server, topic string) string {
	t.Helper()
	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: topic})
	if err != nil {
		t.Fatalf("ShowText(topic=%q): %v", topic, err)
	}
	return resp.Output
}

// TestShowTextSNMPRedactsCommunity is the RED-on-revert net: the rendered gRPC
// output must carry the placeholder and must NOT carry the cleartext community.
func TestShowTextSNMPRedactsCommunity(t *testing.T) {
	out := showTextOutput(t, newSNMPRenderServer(t), "snmp")

	if strings.Contains(out, snmpCommunitySentinel) {
		t.Errorf("ShowText{snmp} LEAKED the cleartext SNMP community %q — it is the "+
			"SNMPv1/v2c authenticator and this RPC is fabric-reachable (#6532):\n%s",
			snmpCommunitySentinel, out)
	}
	if !strings.Contains(out, config.SecretDataPlaceholder) {
		t.Errorf("ShowText{snmp} missing the redaction placeholder %q:\n%s",
			config.SecretDataPlaceholder, out)
	}
}

// TestShowTextSNMPKeepsNonSecretFields is the over-reach guard: masking the
// community must not blank out the rest of the SNMP status render. It stays
// GREEN under a revert of the redaction (these fields were never masked).
func TestShowTextSNMPKeepsNonSecretFields(t *testing.T) {
	out := showTextOutput(t, newSNMPRenderServer(t), "snmp")

	// The community's authorization MODE is not a secret and must survive the
	// mask — the operator still needs to see read-only vs read-write.
	for _, want := range []string{
		"GRPC6532-LOCATION-RACK-42",    // sysLocation
		"GRPC6532-CONTACT-NOC",         // sysContact
		"GRPC6532-DESCRIPTION-EDGE-FW", // sysDescr
		"read-only",                    // community authorization mode
		"10.9.9.9",                     // trap target (name masked since #16728)
		"u1", "sha256", "des",          // v3 user + auth/priv protocols
	} {
		if !strings.Contains(out, want) {
			t.Errorf("ShowText{snmp} dropped non-secret field %q — the community mask "+
				"must not blank the rest of the render (#6532):\n%s", want, out)
		}
	}
}

// TestShowTextSNMPv3KeepsProtocolsAndMasksPasswords pins the sibling snmp-v3
// topic: it renders the USM user table, which must show the auth/priv
// PROTOCOLS but never the passwords. Those are config.Secret-typed, so the
// newtype's String() redaction covers them — this test pins that the render
// keeps relying on it (a future %s of Reveal() would go RED here).
func TestShowTextSNMPv3KeepsProtocolsAndMasksPasswords(t *testing.T) {
	out := showTextOutput(t, newSNMPRenderServer(t), "snmp-v3")

	for _, leak := range []string{"GRPC6532-LEAK-V3AUTH", "GRPC6532-LEAK-V3PRIV"} {
		if strings.Contains(out, leak) {
			t.Errorf("ShowText{snmp-v3} leaked SNMPv3 USM password %q:\n%s", leak, out)
		}
	}
	for _, want := range []string{"u1", "sha256", "des"} {
		if !strings.Contains(out, want) {
			t.Errorf("ShowText{snmp-v3} dropped non-secret field %q:\n%s", want, out)
		}
	}
}

// TestShowTextSNMPRenderIsDeterministic pins the #4712 determinism parity the
// mask makes load-bearing. Once every displayed community key is the SAME
// placeholder, an unsorted map iteration prints N indistinguishable lines
// whose authorization modes shuffle between two identical requests — the
// operator cannot tell which mode belongs to which community, and a diff of
// two captures is noise. Sorting over the real keys fixes the pairing.
// Trap groups and USM users sort for the same reason (REST sorts trap groups
// too, pkg/api/show_text.go).
func TestShowTextSNMPRenderIsDeterministic(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure(): %v", err)
	}
	// Distinct authorization modes per community so a mispairing is visible,
	// and several trap groups / USM users so their order is exercised too.
	multi := []string{
		"set snmp community ZZZ-COMMUNITY-C authorization read-write",
		"set snmp community AAA-COMMUNITY-A authorization read-only",
		"set snmp community MMM-COMMUNITY-B authorization read-only",
		"set snmp trap-group tg-z targets 10.0.0.3",
		"set snmp trap-group tg-a targets 10.0.0.1",
		"set snmp v3 usm local-engine user zeta authentication-sha256 authentication-password pw1password",
		"set snmp v3 usm local-engine user alpha authentication-md5 authentication-password pw2password",
	}
	if _, err := store.LoadSet(strings.Join(multi, "\n")); err != nil {
		t.Fatalf("LoadSet(): %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit(): %v", err)
	}
	s := &Server{store: store}

	first := showTextOutput(t, s, "snmp")
	// Go randomizes map iteration per range, so repeated renders of an
	// unsorted map diverge within a handful of attempts.
	for i := 0; i < 32; i++ {
		if got := showTextOutput(t, s, "snmp"); got != first {
			t.Fatalf("ShowText{snmp} render is NOT deterministic (attempt %d) — an "+
				"unsorted map iteration reorders lines between identical requests "+
				"(#4712/#6532).\n--- first ---\n%s\n--- attempt %d ---\n%s",
				i, first, i, got)
		}
	}
	// Guard against the render collapsing to nothing, which would make the
	// equality above vacuously true. #16728: 3 communities + 2 trap groups
	// all render the same placeholder.
	if n := strings.Count(first, config.SecretDataPlaceholder); n != 5 {
		t.Errorf("expected 5 masked community+trap-group lines, got %d:\n%s", n, first)
	}
}

// TestSNMPCommunityDisplayNameSemantics pins the shared helper's contract
// directly: it is the ONE implementation of the masking rule, and it is
// privilege-parameterised so the CLI can keep its per-login-class behaviour
// (#4111) while REST/gRPC pass redact=true unconditionally.
func TestSNMPCommunityDisplayNameSemantics(t *testing.T) {
	if got := config.SNMPCommunityDisplayName("public", true); got != config.SecretDataPlaceholder {
		t.Errorf("redact=true must mask: got %q, want %q", got, config.SecretDataPlaceholder)
	}
	if got := config.SNMPCommunityDisplayName("public", false); got != "public" {
		t.Errorf("redact=false must pass the name through (super-user CLI parity): got %q", got)
	}
}
