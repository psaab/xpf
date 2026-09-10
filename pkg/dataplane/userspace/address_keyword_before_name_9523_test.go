package userspace

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9523 — the snapshot builder asks the keyword question before the name
// question. Channels: the classifier directly, and config.CompileConfigLenient
// end to end (strict commit now rejects the capturing object, so only the
// tolerant path can still carry one).

func TestClassifyPolicyAddressesKeywordBeforeName9523(t *testing.T) {
	cfg := newBookCfg(map[string]string{
		"any":         "10.99.0.0/16",
		"any4":        "10.98.0.0/16",
		"any6":        "2001:db8:98::/48",
		"any-ipv4":    "10.97.0.0/16",
		"any-ipv6":    "2001:db8:97::/48",
		"10.0.1.0/24": "192.0.2.0/24",
		"corp":        "10.0.0.0/8",
	})
	_, nameToID, err := buildAddressBookTable(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, kw := range []string{"any", "any4", "any6", "any-ipv4", "any-ipv6"} {
		if _, ok := nameToID[kw]; !ok {
			t.Fatalf("fixture premise broken: no book named %q, so this cell cannot observe a capture", kw)
		}
		ids, lits := classifyPolicyAddresses(cfg, nameToID, []string{kw})
		if len(ids) != 0 || !reflect.DeepEqual(lits, []string{kw}) {
			t.Errorf("#9523: keyword %q was captured by the same-named book: ids=%v literals=%v", kw, ids, lits)
		}
	}
	// Name-before-literal is documented (Junos resolves a policy address by its
	// address-book name) and must survive: a CIDR-shaped name and an ordinary
	// name both resolve to their books.
	for _, name := range []string{"10.0.1.0/24", "corp"} {
		ids, lits := classifyPolicyAddresses(cfg, nameToID, []string{name})
		if len(ids) != 1 || ids[0] != nameToID[name] || len(lits) != 0 {
			t.Errorf("name-before-literal broke for %q: ids=%v literals=%v", name, ids, lits)
		}
	}
}

func compileLenientSet9523(t *testing.T, lines []string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, l := range lines {
		p, err := config.ParseSetCommand(l)
		if err != nil {
			t.Fatalf("parse %q: %v", l, err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("setpath %q: %v", l, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile refused the fixture: %v", err)
	}
	return cfg
}

func TestAddressNamedAnyKeepsMatchAllOnTheTolerantPath9523(t *testing.T) {
	pol := "set security policies from-zone trust to-zone untrust policy d1 "
	base := []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		pol + "match source-address any",
		pol + "match destination-address any",
		pol + "match application any",
		pol + "then deny",
	}
	for _, tc := range []struct {
		name    string
		lines   []string
		overlay map[string][]string
	}{
		{"address any", []string{"set security address-book global address any 10.99.0.0/16"}, nil},
		{"address-set any", []string{
			"set security address-book global address a1 10.99.0.0/16",
			"set security address-book global address-set any address a1",
		}, nil},
		{"dynamic-address address-name any", []string{
			"set security dynamic-address feed-server threat url https://feeds.example/list.txt",
			"set security dynamic-address feed-server threat feed-name malware path /malware.txt",
			"set security dynamic-address address-name any profile feed-name malware",
		}, map[string][]string{"any": {"10.99.0.0/16"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := compileLenientSet9523(t, append(append([]string{}, base...), tc.lines...))
			_, nameToID, err := buildAddressBookTableWithFeeds(cfg, tc.overlay)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := nameToID["any"]; !ok {
				t.Fatal("fixture premise broken: nothing named `any` reached the book table, so no capture is possible")
			}
			rules, err := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, tc.overlay)
			if err != nil || len(rules) != 1 {
				t.Fatalf("build: rules=%d err=%v", len(rules), err)
			}
			r := rules[0]
			if len(r.SourceBookIDs) != 0 || len(r.DestinationBookIDs) != 0 ||
				!reflect.DeepEqual(r.SourceLiterals, []string{"any"}) || !reflect.DeepEqual(r.DestinationLiterals, []string{"any"}) {
				t.Fatalf("#9523: `any` was captured on the wire: srcIDs=%v srcLits=%v dstIDs=%v dstLits=%v",
					r.SourceBookIDs, r.SourceLiterals, r.DestinationBookIDs, r.DestinationLiterals)
			}
			wire, _ := json.Marshal(r)
			if strings.Contains(string(wire), "source_book_ids") {
				t.Errorf("the marshalled rule still carries book ids: %s", wire)
			}
			if reasons := PolicyContentRejectionReasons(cfg, tc.overlay); len(reasons) != 0 {
				t.Errorf("a match-all keyword must be enforced, not refused: %v", reasons)
			}
		})
	}
}
