package policymatch

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16687: the policymatch query-snapshot cache was keyed only on the
// config pointer (+ feed digest). An in-place DNS answer change on the
// same published pointer — the apply-path write this issue removes —
// left the cached ContentRejected verdict stale: REFUSED after the
// helper would accept, or ACCEPTED after it began refusing.
//
// FAIL-ON-REVERT: dropping the dnsDigest term from querySnapshotFor
// makes the after-recovery query below hit the pointer-keyed entry and
// stay ContentRejected=true.

func dnsCacheConfig16687() *config.Config {
	return cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		AddressBook: &config.AddressBook{
			Addresses: map[string]*config.Address{
				"svc": {Name: "svc", DNSName: "svc.example.com"},
			},
		},
		Policies: []*config.ZonePairPolicies{
			zonePair("trust", "untrust", &config.Policy{
				Name: "allow-svc",
				Match: config.PolicyMatch{
					DestinationAddresses: []string{"svc"},
					Applications:         []string{"any"},
				},
				Action: config.PolicyPermit,
			}),
		},
	}, config.ApplicationsConfig{})
}

func TestPolicymatchCacheKeysOnDNSAnswers16687(t *testing.T) {
	cfg := dnsCacheConfig16687()
	q := Query{
		FromZone: "trust", ToZone: "untrust", Protocol: "tcp",
		SrcIP: net.ParseIP("10.0.1.5"), DstIP: net.ParseIP("198.51.100.20"), DstPort: 443,
	}

	// Unresolved dns-name: no usable prefixes and no lookup-failure
	// flag — a successful-but-empty answer shape the builder cannot
	// represent, so the whole snapshot is content-rejected.
	before := Match(cfg, q)
	if !before.ContentRejected {
		t.Fatalf("premise: unresolved dns config must be ContentRejected, got %+v", before)
	}
	if _, hit := querySnapshotFor(cfg, nil); !hit {
		t.Fatal("premise: first Match must populate the query snapshot cache")
	}

	// In-place recovery on the SAME pointer (the pre-#16687 apply-path
	// write shape): the answer arrives without a new generation.
	svc := cfg.Security.AddressBook.Addresses["svc"]
	svc.DNSAddresses = []string{"198.51.100.20/32"}

	after := Match(cfg, q)
	if after.ContentRejected {
		t.Fatalf("stale cache: ContentRejected=true after in-place DNS recovery on the same pointer; reasons=%v (#16687)", after.ContentRejectionReasons)
	}
	// The acceptance criterion is the cache verdict: ContentRejected
	// must clear after recovery. (policymatch's per-flow address walk
	// reads Address.Value, not UsableValues — a separate pre-existing
	// evaluation gap noted in the issue's dedup — so no Matched
	// assertion is made here.)
	if after.Matched {
		t.Fatalf("recovered config unexpectedly matched via the Value-only walk: %+v", after)
	}

	// Control: a fresh pointer with identical content agrees.
	fresh := dnsCacheConfig16687()
	fresh.Security.AddressBook.Addresses["svc"].DNSAddresses = []string{"198.51.100.20/32"}
	if got := Match(fresh, q); got.ContentRejected {
		t.Fatalf("fresh-pointer control diverged: %+v", got)
	}

	// Reverse direction: withdrawing the answer on the same pointer
	// must re-reject rather than serve the cached permit verdict.
	svc.DNSAddresses = nil
	withdrawn := Match(cfg, q)
	if !withdrawn.ContentRejected {
		t.Fatalf("stale cache: ContentRejected=false after in-place DNS withdrawal on the same pointer; got %+v (#16687)", withdrawn)
	}
}

// TestDNSAnswersDigestDistinguishes16687 pins the digest itself:
// identical content digests equal (cache may hit), any answer or
// failure-flag change digests differ (cache must miss), and a DNS-less
// config is stable.
func TestDNSAnswersDigestDistinguishes16687(t *testing.T) {
	a := dnsCacheConfig16687()
	b := dnsCacheConfig16687()
	if config.DNSAnswersDigest(a) != config.DNSAnswersDigest(b) {
		t.Fatal("identical empty DNS state digested differently")
	}
	a.Security.AddressBook.Addresses["svc"].DNSAddresses = []string{"198.51.100.20/32"}
	if config.DNSAnswersDigest(a) == config.DNSAnswersDigest(b) {
		t.Fatal("answer change did not change the DNS digest")
	}
	b.Security.AddressBook.Addresses["svc"].DNSAddresses = []string{"198.51.100.20/32"}
	if config.DNSAnswersDigest(a) != config.DNSAnswersDigest(b) {
		t.Fatal("identical recovered DNS state digested differently")
	}
	b.Security.AddressBook.Addresses["svc"].DNSLookupFailed = true
	if config.DNSAnswersDigest(a) == config.DNSAnswersDigest(b) {
		t.Fatal("DNSLookupFailed change did not change the DNS digest")
	}
	plain := cacheTestConfig11010(config.PolicyPermit)
	if config.DNSAnswersDigest(plain) != config.DNSAnswersDigest(cacheTestConfig11010(config.PolicyDeny)) {
		t.Fatal("DNS-less configs with different policies must share the empty DNS digest (policy is not DNS state)")
	}
	if config.DNSAnswersDigest(nil) == config.DNSAnswersDigest(a) {
		t.Fatal("nil config must not alias a populated DNS digest")
	}
}
