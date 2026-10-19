package ddns

import "testing"

// #14996 (D40-02): an unprivileged DHCP client must not claim the zone apex
// or a multi-label FQDN in DDNS derivation. Before the fix, finalizeFQDN kept
// any sanitized name for which fqdnWithinDomain was true, and that helper
// returned true for name == domain (apex) and for any ".<domain>" suffix
// (multi-label). Relabel remedy (fix direction: block the claim): the lease
// still publishes, but only as <first-label>.<domain> — never at the apex
// and never deeper than one label. These tests FAIL pre-fix (apex/multi-label
// kept verbatim) and pass post-fix.

func TestDeriveFQDNBlocksZoneApexClaim_14996(t *testing.T) {
	cases := []struct {
		name, host, clientFQDN, domain, source, want string
	}{
		{"apex via hostname equals domain", "example.com", "", "example.com", "client-hostname", "example.example.com"},
		{"apex via fqdn source", "ignored", "example.com", "example.com", "fqdn", "example.example.com"},
		{"apex trailing dot", "example.com.", "", "example.com", "client-hostname", "example.example.com"},
		{"apex case-insensitive", "EXAMPLE.COM", "", "example.com", "client-hostname", "example.example.com"},
		{"apex under corp zone", "corp.example.com", "", "corp.example.com", "client-hostname", "corp.corp.example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := deriveFQDN(tc.host, tc.clientFQDN, "mac:aa", tc.domain, tc.source)
			if err != nil {
				t.Fatalf("deriveFQDN error: %v", err)
			}
			if got == tc.domain {
				t.Fatalf("client claimed zone apex: got %q == domain %q", got, tc.domain)
			}
			if got != tc.want {
				t.Fatalf("deriveFQDN = %q, want relabeled %q", got, tc.want)
			}
		})
	}
}

func TestDeriveFQDNBlocksMultiLabelClaim_14996(t *testing.T) {
	cases := []struct {
		name, host, clientFQDN, domain, source, want string
	}{
		{"two labels under zone via hostname", "host.sub.example.com", "", "example.com", "client-hostname", "host.example.com"},
		{"three labels under zone", "a.b.c.example.com", "", "example.com", "client-hostname", "a.example.com"},
		{"multi-label via fqdn source", "ignored", "real.dept.example.com", "example.com", "fqdn", "real.example.com"},
		{"multi-label under corp zone", "host.dept.corp.example.com", "", "corp.example.com", "client-hostname", "host.corp.example.com"},
		{"www is single label control", "www.example.com", "", "example.com", "client-hostname", "www.example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := deriveFQDN(tc.host, tc.clientFQDN, "mac:aa", tc.domain, tc.source)
			if err != nil {
				t.Fatalf("deriveFQDN error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("deriveFQDN = %q, want single-label %q", got, tc.want)
			}
		})
	}
}

// Controls: legitimate single-label derivations stay byte-identical.
func TestDeriveFQDNSingleLabelControls_14996(t *testing.T) {
	cases := []struct {
		name, host, clientFQDN, domain, source, want string
	}{
		{"bare host", "laptop", "", "example.com", "client-hostname", "laptop.example.com"},
		{"single-label fqdn in zone", "host.example.com", "", "example.com", "client-hostname", "host.example.com"},
		{"single-label via fqdn source", "ignored", "real.example.com", "example.com", "fqdn", "real.example.com"},
		{"foreign still first-label relabel", "host.attacker.tld", "", "example.com", "client-hostname", "host.example.com"},
		{"bare label no domain", "host", "", "", "client-hostname", "host"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := deriveFQDN(tc.host, tc.clientFQDN, "mac:aa", tc.domain, tc.source)
			if err != nil {
				t.Fatalf("deriveFQDN error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("deriveFQDN = %q, want %q", got, tc.want)
			}
		})
	}
}

// Reconcile-level proof: a lease offering the apex or a multi-label name
// never publishes at the claimed name; it publishes relabeled.
func TestReconcileNeverPublishesApexOrMultiLabel_14996(t *testing.T) {
	up := newFakeUpdater()
	m := testDDNS(t, up)
	pol := enabledPolicy() // domain example.com
	err := runReconcile(t, m, pol, []Lease{
		leaseV4("10.0.1.5", "cid:apex", "example.com"),
		leaseV4("10.0.1.6", "cid:deep", "host.sub.example.com"),
	})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	for _, got := range up.upsertNames() {
		if got == "example.com=10.0.1.5" {
			t.Fatalf("apex published: %v", up.upsertNames())
		}
		if got == "host.sub.example.com=10.0.1.6" {
			t.Fatalf("multi-label published: %v", up.upsertNames())
		}
	}
	if !upserted(t, up, "example.example.com=10.0.1.5") {
		t.Fatalf("apex claim not relabeled; upserts=%v", up.upsertNames())
	}
	if !upserted(t, up, "host.example.com=10.0.1.6") {
		t.Fatalf("multi-label claim not relabeled; upserts=%v", up.upsertNames())
	}
}
