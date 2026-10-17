package ddns

import (
	"context"
	"net"
	"testing"

	"github.com/miekg/dns"

	"github.com/psaab/xpf/pkg/config"
)

// #14429 (DR16-H8): a garbage conflict-policy must NOT silently disable the
// DNS-ownership guard on the INSERT side. Pre-fix, any value other than the
// three valid policies fell through sendAdd's switch with NO prerequisite
// and a bare Insert, so a typo (skip-existng, none, ...) adopted a third
// party's pre-existing record and recorded phantom ownership.

func TestRFC2136GarbageConflictPolicyRefusesAdd14429(t *testing.T) {
	for _, bad := range []string{"skip-existng", "none", "skip_existing", "replace", "SKIP-EXISTING", " replace-owned "} {
		t.Run(bad, func(t *testing.T) {
			srv := newFakeDNSServer(t, nil)
			srv.setStateful(true)
			var ptr, conf int
			cfg := &config.DHCPDynamicDNSConfig{
				Enabled: true, Domain: "example.com", ConflictPolicy: bad,
			}
			cfg.UpdateServer = srv.addrUDP
			pol := policyFromConfig(cfg)
			u, err := newRFC2136Updater(pol, cfg, nil,
				func() { ptr++ }, func() { conf++ })
			if err != nil {
				// Fail-closed at construction is an acceptable refusal:
				// no UPDATE was emitted and no ownership can be recorded.
				if len(srv.recorded()) != 0 {
					t.Fatalf("garbage policy %q: construction errored but emitted updates", bad)
				}
				return
			}
			// If construction succeeds, the ADD itself must refuse and
			// must not publish the record.
			err = u.UpsertLease(context.Background(), recV4("victim.example.com", "10.0.1.5", 300))
			if err == nil {
				t.Fatalf("garbage conflict-policy %q: UpsertLease succeeded (unguarded bare Insert); updates=%v",
					bad, srv.recorded())
			}
			if srv.zoneHas(&dns.A{Hdr: dns.RR_Header{Name: "victim.example.com.", Rrtype: dns.TypeA}, A: net.ParseIP("10.0.1.5")}) {
				t.Fatalf("garbage conflict-policy %q: record was published despite refusal", bad)
			}
		})
	}
}

// Controls: the three valid policies and the empty (default) policy must
// keep working exactly as before.
func TestRFC2136ValidConflictPoliciesUnchanged14429(t *testing.T) {
	for _, good := range []string{"", "replace-owned", "skip-existing", "strict-fail"} {
		t.Run("policy="+good, func(t *testing.T) {
			srv := newFakeDNSServer(t, nil)
			srv.setStateful(true)
			var ptr, conf int
			u := testUpdater(t, srv, &config.DHCPDynamicDNSConfig{
				Enabled: true, Domain: "example.com", ConflictPolicy: good,
			}, &ptr, &conf)
			if err := u.UpsertLease(context.Background(), recV4("ok.example.com", "10.0.1.9", 300)); err != nil {
				t.Fatalf("valid policy %q: UpsertLease on fresh name: %v", good, err)
			}
			if !srv.zoneHas(&dns.A{Hdr: dns.RR_Header{Name: "ok.example.com.", Rrtype: dns.TypeA}, A: net.ParseIP("10.0.1.9")}) {
				t.Fatalf("valid policy %q: fresh record not published", good)
			}
		})
	}
}
