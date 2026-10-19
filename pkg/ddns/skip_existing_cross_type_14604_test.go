package ddns

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/miekg/dns"

	"github.com/psaab/xpf/pkg/config"
)

// Regression tests for #14604: skip-existing / strict-fail guard with
// RRsetNotUsed (per type) not NameNotUsed (name-level).
// Multi-cycle crossTypeDeny reproduces the sibling allow-lists.

func seedAAAA(t *testing.T, srv *fakeDNSServer, name, addr string) {
	t.Helper()
	srv.seedRR(&dns.AAAA{Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300}, AAAA: net.ParseIP(addr)})
}

func seedMX(t *testing.T, srv *fakeDNSServer, name string, pref uint16, mx string) {
	t.Helper()
	srv.seedRR(&dns.MX{Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 300}, Preference: pref, Mx: mx})
}

func seedTXT(t *testing.T, srv *fakeDNSServer, name string) {
	t.Helper()
	srv.seedRR(&dns.TXT{Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300}, Txt: []string{"foreign"}})
}

func foreignPrereqRejected(t *testing.T, policy string, seed func(*testing.T, *fakeDNSServer, string)) {
	t.Helper()
	name := "victim.example.com"
	srv := newFakeDNSServer(t, nil)
	srv.setStateful(true)
	seed(t, srv, name)
	var ptr, conf int
	u := testUpdater(t, srv, &config.DHCPDynamicDNSConfig{
		Enabled: true, Domain: "example.com", ConflictPolicy: policy,
	}, &ptr, &conf)
	_ = ptr

	err := u.UpsertLease(context.Background(), recV4(name, "10.0.1.5", 300))
	if policy == "skip-existing" {
		if !errors.Is(err, errDDNSConflictRefused) {
			t.Fatalf("%s: foreign record must be refused with conflict sentinel; got %v", policy, err)
		}
	} else {
		if err == nil {
			t.Fatalf("%s: foreign record must error; got nil", policy)
		}
		if errors.Is(err, errDDNSConflictRefused) {
			t.Fatalf("%s: strict-fail surfaces a hard error, got conflict sentinel", policy)
		}
	}
	// The attempted A must not have been planted alongside the foreign record.
	planted := &dns.A{Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeA}, A: net.ParseIP("10.0.1.5")}
	if srv.zoneHas(planted) {
		t.Fatalf("%s: planted A at foreign name despite %s", policy, policy)
	}
}

func TestY13SkipExistingForeignAAAABlocksA14604(t *testing.T) {
	foreignPrereqRejected(t, "skip-existing", func(t *testing.T, s *fakeDNSServer, name string) { seedAAAA(t, s, name, "2001:db8::9") })
}

func TestY13SkipExistingForeignMXBlocksA14604(t *testing.T) {
	foreignPrereqRejected(t, "skip-existing", func(t *testing.T, s *fakeDNSServer, name string) { seedMX(t, s, name, 10, "mail.example.net.") })
}

func TestY13StrictFailForeignAAAABlocksA14604(t *testing.T) {
	foreignPrereqRejected(t, "strict-fail", func(t *testing.T, s *fakeDNSServer, name string) { seedAAAA(t, s, name, "2001:db8::9") })
}

func TestY13StrictFailForeignTXTBlocksAAAA14604(t *testing.T) {
	name := "victim6.example.com"
	srv := newFakeDNSServer(t, nil)
	srv.setStateful(true)
	seedTXT(t, srv, name)
	var ptr, conf int
	u := testUpdater(t, srv, &config.DHCPDynamicDNSConfig{
		Enabled: true, Domain: "example.com", ConflictPolicy: "strict-fail",
	}, &ptr, &conf)
	_ = ptr
	err := u.UpsertLease(context.Background(), recV6(name, "2001:db8::5", 300))
	if err == nil {
		t.Fatalf("strict-fail: foreign TXT must block AAAA; got nil")
	}
	if srv.zoneHas(&dns.AAAA{Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeAAAA}, AAAA: net.ParseIP("2001:db8::5")}) {
		t.Fatalf("planted AAAA at foreign TXT name")
	}
}

func TestY13SkipExistingForeignTXTBlocksAAAA14604(t *testing.T) {
	name := "victim6.example.com"
	srv := newFakeDNSServer(t, nil)
	srv.setStateful(true)
	seedTXT(t, srv, name)
	var ptr, conf int
	u := testUpdater(t, srv, &config.DHCPDynamicDNSConfig{
		Enabled: true, Domain: "example.com", ConflictPolicy: "skip-existing",
	}, &ptr, &conf)
	if err := u.UpsertLease(context.Background(), recV6(name, "2001:db8::5", 300)); !errors.Is(err, errDDNSConflictRefused) {
		t.Fatalf("skip-existing: foreign TXT must block AAAA; got %v", err)
	}
	_ = ptr
}

// Manager-level: under skip-existing, dual-stack producer identities
// (cid: v4 / duid: v6) must both publish on a fresh name; a foreign
// AAAA must block A while the manager records no ownership.
func TestManagerSkipExistingDualStackFreshPair14604(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	srv.setStateful(true)
	m, src := prodManagerTo(t, srv)
	cfg := ddnsCfgSkipExisting(srv.addrUDP)
	src.v4 = []Lease{{Family: 4, Address: "10.0.1.5", Identity: "cid:01000000000001", SubnetID: "1", HostName: "dual"}}
	src.v6 = []Lease{{Family: 6, Address: "2001:db8::5", Identity: "duid:00:03:00:01:00:00:00:00:00:01/1", SubnetID: "1", HostName: "dual"}}
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if !srv.zoneHas(&dns.A{Hdr: dns.RR_Header{Name: "dual.example.com.", Rrtype: dns.TypeA}, A: net.ParseIP("10.0.1.5")}) {
		t.Fatalf("dual: A not published under skip-existing")
	}
	if !srv.zoneHas(&dns.AAAA{Hdr: dns.RR_Header{Name: "dual.example.com.", Rrtype: dns.TypeAAAA}, AAAA: net.ParseIP("2001:db8::5")}) {
		t.Fatalf("dual: AAAA not published under skip-existing (sibling block)")
	}
	if got := m.Stats().OwnedRecords; got != 2 {
		t.Fatalf("dual owned=%d want 2", got)
	}
	// Second pass: both still wanted and equal -> no re-upsert; ownership stable.
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("reconcile cycle 2: %v", err)
	}
	if got := m.Stats().OwnedRecords; got != 2 {
		t.Fatalf("dual cycle2 owned=%d want 2", got)
	}
}

func TestManagerSkipExistingForeignMXNoOwnership14604(t *testing.T) {
	name := "victim.example.com"
	srv := newFakeDNSServer(t, nil)
	srv.setStateful(true)
	seedMX(t, srv, name, 10, "mail.example.net.")
	m, src := prodManagerTo(t, srv)
	cfg := ddnsCfgSkipExisting(srv.addrUDP)
	src.v4 = []Lease{{Family: 4, Address: "10.0.1.5", Identity: "cid:01:02:03", SubnetID: "1", HostName: "victim"}}
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if srv.zoneHas(&dns.A{Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeA}, A: net.ParseIP("10.0.1.5")}) {
		t.Fatalf("manager planted A at foreign MX name")
	}
	if got := m.Stats().OwnedRecords; got != 0 {
		t.Fatalf("manager recorded phantom ownership on refused cross-type add; owned=%d", got)
	}
}
