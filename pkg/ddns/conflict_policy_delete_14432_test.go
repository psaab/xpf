package ddns

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/psaab/xpf/pkg/config"
)

// #14432 (DR17-H3): a garbage conflict-policy must NOT take the UNGUARDED
// delete branch in sendRemoveForward. Pre-fix, any value other than
// "replace-owned" fell into `return u.sendRemove(ctx, zone, rr)` — a plain
// exact-RR delete with NO DHCID prerequisite — so a typo
// (skip-existng, none, ...) could delete a third party's record on lease
// release. The fix must refuse the DELETE (or refuse construction);
// skip-existing / strict-fail plain deletes and replace-owned
// DHCID-guarded deletes stay unchanged.

func TestRFC2136GarbageConflictPolicyRefusesDelete14432(t *testing.T) {
	for _, bad := range []string{"skip-existng", "none", "skip_existing", "replace", "SKIP-EXISTING", " replace-owned "} {
		t.Run(bad, func(t *testing.T) {
			srv := newFakeDNSServer(t, nil)
			srv.setStateful(true)
			// A third party's pre-existing record at the victim name.
			victim := &dns.A{Hdr: dns.RR_Header{Name: "victim.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("10.0.1.5")}
			srv.seedRR(victim)

			cfg := &config.DHCPDynamicDNSConfig{
				Enabled: true, Domain: "example.com", ConflictPolicy: bad,
			}
			cfg.UpdateServer = srv.addrUDP
			pol := policyFromConfig(cfg)
			var ptr, conf int
			u, err := newRFC2136Updater(pol, cfg, nil,
				func() { ptr++ }, func() { conf++ })
			if err != nil {
				// Fail-closed at construction is an acceptable refusal:
				// no DELETE was emitted and the victim survives.
				if !strings.Contains(err.Error(), bad) {
					t.Fatalf("garbage policy %q: construction error must name the value, got %v", bad, err)
				}
				if len(srv.recorded()) != 0 {
					t.Fatalf("garbage policy %q: construction errored but emitted updates", bad)
				}
				if !srv.zoneHas(victim) {
					t.Fatalf("garbage policy %q: victim record deleted despite construction refusal", bad)
				}
				return
			}
			// If construction succeeds, the DELETE itself must refuse
			// (error, and no wire DELETE), and the victim must survive.
			err = u.DeleteLease(context.Background(), recV4ID("victim.example.com", "10.0.1.5", "cid:1234", 300))
			if err == nil {
				t.Fatalf("garbage conflict-policy %q: DeleteLease succeeded (unguarded plain delete); updates=%v",
					bad, srv.recorded())
			}
			for _, up := range srv.recorded() {
				if len(up.deletes) != 0 {
					t.Fatalf("garbage conflict-policy %q: a wire DELETE was emitted despite refusal: %+v", bad, up)
				}
			}
			if !srv.zoneHas(victim) {
				t.Fatalf("#14432 BOUNDARY BREACH: garbage conflict-policy %q deleted a third party's record", bad)
			}
		})
	}
}

// A directly-built updater (struct literal, bypassing newRFC2136Updater)
// with a garbage policy must also refuse the delete: defence in depth at
// sendRemoveForward itself, the exact branch the audit anchors.
func TestRFC2136GarbageConflictPolicyRefusesDeleteDirectUpdater14432(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	srv.setStateful(true)
	victim := &dns.A{Hdr: dns.RR_Header{Name: "victim.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("10.0.1.5")}
	srv.seedRR(victim)

	u := &rfc2136Updater{
		server:         srv.addrUDP,
		defaultDomain:  "example.com",
		conflictPolicy: "bogus-policy",
		timeout:        defaultDDNSTimeout,
	}
	// Build a real client the same way the constructor would.
	u2, err := newRFC2136Updater(
		ddnsPolicy{domain: "example.com", conflictPolicy: "replace-owned", backend: "rfc2136"},
		&config.DHCPDynamicDNSConfig{UpdateServer: srv.addrUDP}, nil, nil, nil)
	if err != nil {
		t.Fatalf("newRFC2136Updater (client donor): %v", err)
	}
	u.client = u2.client

	rr, err := u.forwardRR(recV4ID("victim.example.com", "10.0.1.5", "cid:1234", 300))
	if err != nil {
		t.Fatalf("forwardRR: %v", err)
	}
	u.dhcidClientID = "cid:1234"
	if err := u.sendRemoveForward(context.Background(), "example.com.", rr, false); err == nil {
		t.Fatalf("garbage conflict-policy on a direct updater: sendRemoveForward succeeded (unguarded plain delete)")
	}
	if !srv.zoneHas(victim) {
		t.Fatalf("#14432 BOUNDARY BREACH: direct updater with garbage policy deleted a third party's record")
	}
}

// Controls: valid policies' deletes are unchanged.
//   - skip-existing / strict-fail: plain exact-RR delete (no DHCID
//     prerequisite) removes the exact tuple.
//   - replace-owned: DHCID-guarded delete removes our own record, and
//     refuses (counted skip, nil error) a name owned by another DHCID.
func TestRFC2136ValidConflictPolicyDeletesUnchanged14432(t *testing.T) {
	t.Run("plain-delete", func(t *testing.T) {
		for _, good := range []string{"skip-existing", "strict-fail"} {
			srv := newFakeDNSServer(t, nil)
			srv.setStateful(true)
			var ptr, conf int
			u := testUpdater(t, srv, &config.DHCPDynamicDNSConfig{
				Enabled: true, Domain: "example.com", ConflictPolicy: good,
			}, &ptr, &conf)
			rec := recV4("mine.example.com", "10.0.1.7", 300)
			if err := u.UpsertLease(context.Background(), rec); err != nil {
				t.Fatalf("%s: UpsertLease: %v", good, err)
			}
			a := &dns.A{Hdr: dns.RR_Header{Name: "mine.example.com.", Rrtype: dns.TypeA}, A: net.ParseIP("10.0.1.7")}
			if !srv.zoneHas(a) {
				t.Fatalf("%s: setup record not published", good)
			}
			if err := u.DeleteLease(context.Background(), rec); err != nil {
				t.Fatalf("%s: DeleteLease: %v", good, err)
			}
			if srv.zoneHas(a) {
				t.Errorf("%s: plain delete must remove the exact record", good)
			}
		}
	})

	t.Run("replace-owned-guarded", func(t *testing.T) {
		srv := newFakeDNSServer(t, nil)
		srv.setStateful(true)
		var ptr, conf int
		u := testUpdater(t, srv, &config.DHCPDynamicDNSConfig{
			Enabled: true, Domain: "example.com", ConflictPolicy: "replace-owned",
		}, &ptr, &conf)

		// Our own record: guarded delete removes A + DHCID.
		rec := recV4ID("mine.example.com", "10.0.1.7", "cid:1234", 300)
		if err := u.UpsertLease(context.Background(), rec); err != nil {
			t.Fatalf("UpsertLease: %v", err)
		}
		a := &dns.A{Hdr: dns.RR_Header{Name: "mine.example.com.", Rrtype: dns.TypeA}, A: net.ParseIP("10.0.1.7")}
		dhcid, _ := dhcidRR("cid:1234", "mine.example.com", 300)
		if !srv.zoneHas(a) || !srv.zoneHas(dhcid) {
			t.Fatalf("setup: own A + DHCID not published")
		}
		if err := u.DeleteLease(context.Background(), rec); err != nil {
			t.Fatalf("DeleteLease (own): %v", err)
		}
		if srv.zoneHas(a) || srv.zoneHas(dhcid) {
			t.Errorf("replace-owned: guarded delete must remove own A + DHCID")
		}

		// Another owner's name: guarded delete is a counted skip; the
		// other owner's records survive.
		otherA := &dns.A{Hdr: dns.RR_Header{Name: "shared.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("10.0.1.50")}
		otherDHCID, _ := dhcidRR("cid:OTHER", "shared.example.com", 300)
		srv.seedRR(otherA)
		srv.seedRR(otherDHCID)
		before := conf
		if err := u.DeleteLease(context.Background(), recV4ID("shared.example.com", "10.0.1.51", "cid:MINE", 300)); err != nil {
			t.Fatalf("DeleteLease (foreign): %v", err)
		}
		if !srv.zoneHas(otherA) || !srv.zoneHas(otherDHCID) {
			t.Errorf("replace-owned: guarded delete must not touch another owner's records")
		}
		if conf == before {
			t.Errorf("replace-owned: foreign-name delete skip must be counted as a conflict")
		}
	})

	t.Run("empty-default", func(t *testing.T) {
		// Empty policy defaults to replace-owned in policyFromConfig:
		// the guarded path, unchanged.
		srv := newFakeDNSServer(t, nil)
		srv.setStateful(true)
		var ptr, conf int
		u := testUpdater(t, srv, &config.DHCPDynamicDNSConfig{
			Enabled: true, Domain: "example.com",
		}, &ptr, &conf)
		if u.conflictPolicy != "replace-owned" {
			t.Fatalf("empty policy must default to replace-owned, got %q", u.conflictPolicy)
		}
		rec := recV4ID("mine.example.com", "10.0.1.7", "cid:1234", 300)
		if err := u.UpsertLease(context.Background(), rec); err != nil {
			t.Fatalf("UpsertLease: %v", err)
		}
		if err := u.DeleteLease(context.Background(), rec); err != nil {
			t.Fatalf("DeleteLease: %v", err)
		}
		a := &dns.A{Hdr: dns.RR_Header{Name: "mine.example.com.", Rrtype: dns.TypeA}, A: net.ParseIP("10.0.1.7")}
		if srv.zoneHas(a) {
			t.Errorf("empty-default: own record must be deleted via the guarded path")
		}
	})
}
