package userspace

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func mappedAddressBookConfig10688(value string) *config.Config {
	return &config.Config{Security: config.SecurityConfig{
		AddressBook: &config.AddressBook{
			Addresses: map[string]*config.Address{
				"mapped-v4": {Name: "mapped-v4", Value: value},
			},
			AddressSets: map[string]*config.AddressSet{},
		},
	}}
}

// #10688: a tolerated/legacy config still reaches the userspace snapshot path.
// Rust parses a mapped literal as IPv6, so the wrong-family address-book arm
// must tell the simulator and the publish diagnostic that the helper refuses
// the whole snapshot, even though Go's To4 filed the literal in prefixes_v4.
//
// FAIL-ON-REVERT: removing collectAddressBookFamilyRejections from either
// PolicyContentRejectionReasons or buildSnapshot leaves both reason lists empty.
func TestMappedAddressBookPrefixHasWrongFamilyRejectionReason10688(t *testing.T) {
	cfg := mappedAddressBookConfig10688("::ffff:10.0.0.0/104")
	books, _, err := buildAddressBookTableWithFeeds(cfg, nil)
	if err != nil {
		t.Fatalf("fixture book build: %v", err)
	}
	if len(books) != 1 || len(books[0].PrefixesV4) != 1 || books[0].PrefixesV4[0] != "::ffff:10.0.0.0/104" {
		t.Fatalf("fixture must reproduce the Go-to-v4 filing, got %+v", books)
	}

	reasons := PolicyContentRejectionReasons(cfg, nil)
	if len(reasons) != 1 || !strings.Contains(reasons[0], `address-book "mapped-v4"`) ||
		!strings.Contains(reasons[0], "prefixes_v4") || !strings.Contains(reasons[0], "IPv6") ||
		!strings.Contains(reasons[0], "entire policy snapshot") {
		t.Fatalf("wrong-family mirror must name the helper's whole-snapshot refusal, got %v", reasons)
	}

	snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)
	if err != nil {
		t.Fatalf("snapshot build: %v", err)
	}
	if len(snap.Capabilities.PolicyContentRejected) != 1 ||
		!strings.Contains(snap.Capabilities.PolicyContentRejected[0], "prefixes_v4") {
		t.Fatalf("published snapshot must carry the refusal diagnostic, got %v", snap.Capabilities.PolicyContentRejected)
	}
}

func TestAddressBookFamilyRejectionLeavesOrdinaryPrefixesAlone10688(t *testing.T) {
	cfg := &config.Config{Security: config.SecurityConfig{
		AddressBook: &config.AddressBook{
			Addresses: map[string]*config.Address{
				"v4": {Name: "v4", Value: "10.0.0.0/8"},
				"v6": {Name: "v6", Value: "2001:db8::/32"},
			},
			AddressSets: map[string]*config.AddressSet{},
		},
	}}
	if reasons := PolicyContentRejectionReasons(cfg, nil); len(reasons) != 0 {
		t.Fatalf("ordinary same-family prefixes must not trigger rejection: %v", reasons)
	}
}
