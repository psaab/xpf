package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16606: Address.DNSAddresses is json:"-", so the #6480 hybrid guard's
// JSON comparison cannot see a DNS answer change. A scheduler or
// route-overlay republish from the stale published config must be
// refused (routeOnlyPublishHybrid == true) instead of rebuilding
// address-book rows with the old answer.
//
// FAIL-ON-REVERT: removing the DNSAnswersSnapshot comparison from
// configsContentEqual makes the diverged case compare equal and this
// test REDs; the identical-answers control pins that equal DNS state
// is NOT a hybrid (no false refusal).

func dnsGuardConfig16606(answers []string) *config.Config {
	cfg := overlayTestConfig()
	cfg.Security.AddressBook = &config.AddressBook{
		Addresses: map[string]*config.Address{
			"svc": {Name: "svc", DNSName: "svc.example.com", DNSAddresses: answers},
		},
	}
	return cfg
}

func TestHybridGuardSeesDNSAnswerChange16606(t *testing.T) {
	old := dnsGuardConfig16606([]string{"198.51.100.7/32"})
	refreshed := dnsGuardConfig16606([]string{"203.0.113.99/32"})

	// Daemon-shape arm from the issue: republish cfg carries the OLD
	// answer, applied snapshot carries the NEW answer. Must be hybrid.
	if !routeOnlyPublishHybrid(old, refreshed) {
		t.Fatal("routeOnlyPublishHybrid(old, refreshed) = false, want true: DNS answer divergence must refuse the partial republish (#16606)")
	}
	if configsContentEqual(old, refreshed) {
		t.Fatal("configsContentEqual(old, refreshed) = true, want false: DNSAddresses is json:\"-\" but helper-enforced")
	}

	// Control: identical answers (distinct pointers) are NOT a hybrid.
	same := dnsGuardConfig16606([]string{"198.51.100.7/32"})
	if routeOnlyPublishHybrid(same, old) {
		t.Fatal("routeOnlyPublishHybrid(same-answers, old) = true, want false (false refusal)")
	}
	if !configsContentEqual(same, old) {
		t.Fatal("configsContentEqual(same-answers) = false, want true")
	}

	// Control: a JSON-visible divergence (system host-name) still refuses.
	diffHost := dnsGuardConfig16606([]string{"198.51.100.7/32"})
	diffHost.System.HostName = "other-host"
	if !routeOnlyPublishHybrid(diffHost, old) {
		t.Fatal("routeOnlyPublishHybrid(diff-hostname) = false, want true")
	}
	namedOld := overlayTestConfig()
	namedOld.Security.NamedAddressBooks = map[string]*config.NamedAddressBook{
		"eng": {AddressBook: config.AddressBook{Addresses: map[string]*config.Address{
			"svc": {Name: "svc", DNSName: "svc.example.com", DNSAddresses: []string{"198.51.100.7/32"}},
		}}},
	}
	namedNew := overlayTestConfig()
	namedNew.Security.NamedAddressBooks = map[string]*config.NamedAddressBook{
		"eng": {AddressBook: config.AddressBook{Addresses: map[string]*config.Address{
			"svc": {Name: "svc", DNSName: "svc.example.com", DNSAddresses: []string{"203.0.113.99/32"}},
		}}},
	}
	if !routeOnlyPublishHybrid(namedOld, namedNew) {
		t.Fatal("named-book DNS divergence not seen by hybrid guard")
	}
}

// #17723: the resolver-failed bit is runtime DNS state even when the
// successful-empty and failed states have identical prefixes.
// FAIL-ON-REVERT: dropping DNSLookupFailed from DNSAnswersSnapshot makes
// these configs compare equal and allows routeOnlyPublishHybrid to accept
// different enforced states. The identical-failure control must still pass.
func TestHybridGuardSeesDNSLookupFailureChange17723(t *testing.T) {
	successfulEmpty := dnsGuardConfig16606(nil)
	servfail := dnsGuardConfig16606(nil)
	servfail.Security.AddressBook.Addresses["svc"].DNSLookupFailed = true

	if !routeOnlyPublishHybrid(successfulEmpty, servfail) {
		t.Fatal("routeOnlyPublishHybrid(successful-empty, SERVFAIL) = false, want true")
	}
	if configsContentEqual(successfulEmpty, servfail) {
		t.Fatal("configsContentEqual(successful-empty, SERVFAIL) = true, want false")
	}

	sameFailure := dnsGuardConfig16606(nil)
	sameFailure.Security.AddressBook.Addresses["svc"].DNSLookupFailed = true
	if routeOnlyPublishHybrid(sameFailure, servfail) {
		t.Fatal("routeOnlyPublishHybrid(identical SERVFAIL state) = true, want false")
	}
	if !configsContentEqual(sameFailure, servfail) {
		t.Fatal("configsContentEqual(identical SERVFAIL state) = false, want true")
	}
}
