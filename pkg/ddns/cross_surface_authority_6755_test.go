package ddns

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6755: WireRRClaim carried no authority, so two ownership surfaces publishing
// an equal (FQDN, type, rdata) to DIFFERENT DNS servers compared EQUAL. What
// that equality decides is whether to SUPPRESS a DELETE — so a teardown skipped
// its own delete believing the other surface co-owned the record, and the record
// stayed published at its own authority forever.
//
// The two directions must BOTH be pinned. Without the same-authority positive,
// "include the authority" and "never suppress" are indistinguishable, and the
// second silently reverts #5748's cross-surface clobber protection — turning a
// stale-record bug into a data-loss one.

func claim6755(fqdn, rdata, authority string) WireRRClaim {
	return wireRRClaim(fqdn, "A", rdata, authority)
}

// TestDistinctAuthoritiesDoNotCoOwn6755 is the defect proper.
func TestDistinctAuthoritiesDoNotCoOwn6755(t *testing.T) {
	ns1 := authorityFingerprint("rfc2136", "ns1.example.net:53", "", "", "", "", "")
	ns2 := authorityFingerprint("rfc2136", "ns2.example.net:53", "", "", "", "", "")
	if ns1 == ns2 {
		t.Fatal("premise broken: two different update servers produced the same fingerprint")
	}

	a := claim6755("host.example.net", "192.0.2.10", ns1)
	b := claim6755("host.example.net", "192.0.2.10", ns2)

	if a.coOwns(b) {
		t.Error("two records with the same FQDN/type/rdata at DIFFERENT DNS servers were " +
			"treated as ONE wire resource. The teardown that consults this suppresses its " +
			"DELETE, so the record is never withdrawn from its own authority")
	}
	if b.coOwns(a) {
		t.Error("co-ownership is not symmetric")
	}
}

// TestSameAuthorityStillCoOwns6755 is the TIGHTENING control — the one that
// stops this fix reverting #5748.
func TestSameAuthorityStillCoOwns6755(t *testing.T) {
	ns := authorityFingerprint("rfc2136", "ns1.example.net:53", "", "", "", "", "")
	a := claim6755("host.example.net", "192.0.2.10", ns)
	b := claim6755("host.example.net", "192.0.2.10", ns)

	if !a.coOwns(b) {
		t.Error("two records at the SAME authority stopped co-owning: the cross-surface " +
			"teardown will now DELETE a record the other surface still owns, which is the " +
			"clobber #5748 exists to prevent — strictly worse than the stale record #6755 " +
			"is about")
	}
}

// TestUnknownAuthorityCannotProveDifference6755 pins the third state. An empty
// authority is UNKNOWN, not "different": a Surface A record persisted before
// #6755 has no stored BackendFingerprint, and the lease surface has none until
// its first policy resolves. Those must still co-own, or the upgrade itself
// becomes a clobber.
func TestUnknownAuthorityCannotProveDifference6755(t *testing.T) {
	ns := authorityFingerprint("rfc2136", "ns1.example.net:53", "", "", "", "", "")
	known := claim6755("host.example.net", "192.0.2.10", ns)
	legacy := claim6755("host.example.net", "192.0.2.10", "")

	if !known.coOwns(legacy) || !legacy.coOwns(known) {
		t.Error("a legacy record with no stored fingerprint stopped co-owning a known one. " +
			"On upgrade, every pre-#6755 record would lose its cross-surface protection at " +
			"once — the fail-safe direction is to suppress when no mismatch can be PROVEN")
	}
	if !legacy.coOwns(claim6755("host.example.net", "192.0.2.10", "")) {
		t.Error("two unknown authorities must still co-own")
	}
}

// TestDifferentRRNeverCoOwnsRegardlessOfAuthority6755 pins that the authority is
// an ADDITIONAL discriminator, not a replacement: a different name, type or
// rdata is still a different resource even at one authority. Without this, an
// implementation that compared ONLY the authority would pass everything above.
func TestDifferentRRNeverCoOwnsRegardlessOfAuthority6755(t *testing.T) {
	ns := authorityFingerprint("rfc2136", "ns1.example.net:53", "", "", "", "", "")
	base := claim6755("host.example.net", "192.0.2.10", ns)

	for _, tc := range []struct {
		name  string
		other WireRRClaim
	}{
		{"different FQDN", claim6755("other.example.net", "192.0.2.10", ns)},
		{"different rdata", claim6755("host.example.net", "192.0.2.11", ns)},
		{"different type", wireRRClaim("host.example.net", "AAAA", "192.0.2.10", ns)},
	} {
		if base.coOwns(tc.other) {
			t.Errorf("%s co-owned at the same authority: the authority is an additional "+
				"discriminator, not a replacement for the RR identity", tc.name)
		}
	}
}

// TestLeaseAndSurfaceAAgreeOnOneServer6755 is the cross-surface agreement test,
// and it is the one that would catch a slot-mapping mistake.
//
// rfc2136 is the ONE backend both surfaces support. The Surface A provider
// catalog and the DHCP lease policy populate different subsets of the shared
// fingerprint's fields, so this asserts that for the same server they still
// produce the SAME authority — the property the whole fix rests on. Pinning it
// to a literal would encode which side I trust; this asserts the AGREEMENT.
func TestLeaseAndSurfaceAAgreeOnOneServer6755(t *testing.T) {
	const server = "ns1.example.net:53"

	surfaceA := backendFingerprint(&config.DDNSProvider{
		Backend:      "rfc2136",
		UpdateServer: server,
	})
	// The lease policy carries a Domain — the DNS suffix it appends to client
	// names. It is NOT the Surface A `Zone` (documented as the CLOUDFLARE zone
	// and read only by backend_cloudflare.go), and an rfc2136 Surface A provider
	// leaves Zone empty. Setting Domain here is what makes this test able to
	// FAIL: with an empty Domain, mapping it onto the Zone slot would be a no-op
	// and the mistake would pass unnoticed.
	lease := leaseAuthorityFingerprint(&config.DHCPDynamicDNSConfig{
		Backend:      "rfc2136",
		UpdateServer: server,
		Domain:       "lan.example.net",
	})

	if surfaceA != lease {
		t.Fatalf("the two surfaces disagree about the SAME rfc2136 server (%q vs %q) — check "+
			"whether a lease-only field (Domain) was mapped onto a Surface-A-only slot "+
			"(Zone/HostedZoneID/AWSRegion); those are different concepts and an rfc2136 "+
			"provider leaves them empty. Every "+
			"cross-surface co-ownership check would fail, so the teardown would delete a "+
			"record the other surface still owns — #5748's clobber, reintroduced by a "+
			"slot-mapping mistake", surfaceA, lease)
	}

	// And a different server must still differ, or the agreement above is vacuous.
	other := leaseAuthorityFingerprint(&config.DHCPDynamicDNSConfig{
		Backend:      "rfc2136",
		UpdateServer: "ns2.example.net:53",
	})
	if other == surfaceA {
		t.Error("a DIFFERENT server produced the same authority: the agreement above would " +
			"hold for any two inputs and proves nothing")
	}
}

// TestAuthorityOmitsCredentials6755 pins the credential-free requirement: two
// policies differing only in TSIG key material are the SAME authority, and no
// secret may reach the fingerprint.
func TestAuthorityOmitsCredentials6755(t *testing.T) {
	a := leaseAuthorityFingerprint(&config.DHCPDynamicDNSConfig{
		Backend: "rfc2136", UpdateServer: "ns1.example.net:53",
		TSIGKeyName: "k1", TSIGAlgorithm: "hmac-sha256", TSIGSecret: config.NewSecret("SECRET-ONE"),
	})
	b := leaseAuthorityFingerprint(&config.DHCPDynamicDNSConfig{
		Backend: "rfc2136", UpdateServer: "ns1.example.net:53",
		TSIGKeyName: "k2", TSIGAlgorithm: "hmac-sha512", TSIGSecret: config.NewSecret("SECRET-TWO"),
	})
	if a != b {
		t.Error("TSIG material changed the authority fingerprint: two keys for the same " +
			"server are the same authority, and credential material must not participate")
	}
	if a == "" {
		t.Fatal("fingerprint is empty")
	}
}

// TestSurfaceARebuildStampsTheRecordsAuthority6755 binds the WIRING.
//
// Every test above builds claims through wireRRClaim directly, so they pass
// whether or not the rebuild actually stamps a record's stored fingerprint —
// making that side stamp "" leaves all of them green, because an empty
// authority is UNKNOWN and still co-owns. This drives the production rebuild
// and asserts the claim carries the record's OWN publish-time authority.
func TestSurfaceARebuildStampsTheRecordsAuthority6755(t *testing.T) {
	fp := authorityFingerprint("rfc2136", "ns7.example.net:53", "", "", "", "", "")

	m := &SurfaceAManager{state: &ddnsState{records: map[string]ownedRecord{
		"k": {
			FQDN:               "wan.example.net",
			ForwardType:        "A",
			AddrText:           "203.0.113.9",
			BackendFingerprint: fp,
		},
	}}}
	m.rebuildWireRRClaimsLocked()

	claims := m.WireRRClaims()
	if len(claims) != 1 {
		t.Fatalf("expected exactly one claim, got %d: %+v", len(claims), claims)
	}
	if claims[0].Authority != fp {
		t.Errorf("the rebuilt claim carries Authority %q, want the record's stored "+
			"BackendFingerprint %q. An unstamped claim reads as UNKNOWN, so it co-owns "+
			"everything and #6755's whole discrimination is inert while every "+
			"claim-level test still passes", claims[0].Authority, fp)
	}
	if claims[0].Rdata != "203.0.113.9" || claims[0].FQDN != dnsCanonicalFQDN("wan.example.net") {
		t.Errorf("rebuild lost the RR identity: %+v", claims[0])
	}
}
