package ddns

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/miekg/dns"

	"github.com/psaab/xpf/pkg/config"
)

// backend_rfc2136_zone_15225_test.go: #15225 A40-05 fail-on-revert proofs.
//
// The RFC 2136 update zone was guessed by stripping one label, so every
// DHCPv6 PTR targeted a /124 nibble zone and apex/deep forward names
// targeted the wrong zone; the server answered NOTAUTH and the publish
// degraded to a counted skip blaming the server. The fix discovers the
// enclosing zone with an SOA walk (querying the update server itself)
// and honours explicit forward-zone/reverse-zone leaves when configured.
//
// RED-on-revert: restore parentZone guessing and the v6 PTR below is
// sent to the one-nibble-parent zone, answered NOTAUTH, and never lands.

func mustAddr15225(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("ParseAddr %q: %v", s, err)
	}
	return a
}

// TestRFC2136SOAWalkPublishesV6PTR15225 is the acceptance probe: with a
// server authoritative only for 8.b.d.0.1.0.0.2.ip6.arpa, the DHCPv6 PTR
// must publish (the SOA walk finds that zone) instead of NOTAUTH-skipping
// against the guessed /124 nibble zone.
func TestRFC2136SOAWalkPublishesV6PTR15225(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	srv.setStateful(true)
	// Authoritative only for the /32 reverse zone and the forward zone.
	srv.setAuthoritativeZones([]string{"example.com", "8.b.d.0.1.0.0.2.ip6.arpa"})
	var ptrNotAuth, conflict int
	u := testUpdater(t, srv, &config.DHCPDynamicDNSConfig{Enabled: true, Domain: "example.com"}, &ptrNotAuth, &conflict)
	rec := recV6("host.example.com", "2001:db8::5", 300)
	if err := u.UpsertLease(context.Background(), rec); err != nil {
		t.Fatalf("UpsertLease v6 with SOA discovery: %v", err)
	}
	if ptrNotAuth != 0 {
		t.Fatalf("PTR must publish via discovered zone, got %d NOTAUTH skips", ptrNotAuth)
	}
	ptr := u.ptrRR(rec)
	if !srv.zoneHas(ptr) {
		t.Fatalf("v6 PTR %s not in zone after SOA-walk publish; updates=%v", ptr.Header().Name, srv.recorded())
	}
	// The PTR UPDATE must have been addressed to the discovered zone.
	found := false
	for _, up := range srv.recorded() {
		if up.zone == "8.b.d.0.1.0.0.2.ip6.arpa." {
			found = true
		}
	}
	if !found {
		t.Fatalf("no UPDATE addressed to discovered reverse zone; updates=%v", srv.recorded())
	}
	// Delete must use the same discovered zone and remove the PTR.
	if err := u.DeleteLease(context.Background(), rec); err != nil {
		t.Fatalf("DeleteLease: %v", err)
	}
	if srv.zoneHas(ptr) {
		t.Fatalf("v6 PTR survived delete via discovered zone")
	}
	_ = mustAddr15225(t, "2001:db8::5")
}

// Forward apex/deep names: with no configured domain, a name two labels
// deep under its zone must publish via the SOA-discovered zone, not the
// one-label parent guess.
func TestRFC2136SOAWalkForwardDeepName15225(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	srv.setStateful(true)
	srv.setAuthoritativeZones([]string{"example.com"})
	var ptrNotAuth, conflict int
	u := testUpdater(t, srv, &config.DHCPDynamicDNSConfig{Enabled: true}, &ptrNotAuth, &conflict)
	rec := recV4("deep.wan.example.com", "10.0.1.5", 300)
	if err := u.UpsertLease(context.Background(), rec); err != nil {
		t.Fatalf("UpsertLease deep forward: %v", err)
	}
	a := &dns.A{Hdr: dns.RR_Header{Name: "deep.wan.example.com.", Rrtype: dns.TypeA}, A: net.ParseIP("10.0.1.5")}
	if !srv.zoneHas(a) {
		t.Fatalf("deep forward A not published via discovered zone; updates=%v", srv.recorded())
	}
}

// Explicit forward-zone/reverse-zone leaves, when configured, are honoured
// without any SOA walk guesswork.
func TestRFC2136ExplicitZones15225(t *testing.T) {
	c := &config.DHCPDynamicDNSConfig{
		Enabled: true, Domain: "example.com",
		ForwardZone: "example.com", ReverseZone: "8.b.d.0.1.0.0.2.ip6.arpa",
	}
	pol := policyFromConfig(c)
	if len(pol.forwardZones) != 1 || len(pol.reverseZones) != 1 {
		t.Fatalf("policyFromConfig must carry explicit zones, got %+v", pol)
	}
	u := &rfc2136Updater{forwardZones: pol.forwardZones, reverseZones: pol.reverseZones, defaultDomain: pol.domain}
	if got := u.resolveForwardZone("deep.wan.example.com"); got != "example.com." {
		t.Fatalf("explicit forward zone = %q, want example.com.", got)
	}
	if got := u.resolveReverseZone(reversePTRName(mustAddr15225(t, "2001:db8::5"))); got != "8.b.d.0.1.0.0.2.ip6.arpa." {
		t.Fatalf("explicit reverse zone = %q", got)
	}
}
