package policymatch

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func cacheTestConfig11010(defaultPolicy config.PolicyAction) *config.Config {
	return cfgWith(config.SecurityConfig{
		DefaultPolicy: defaultPolicy,
		AddressBook: &config.AddressBook{
			Addresses: map[string]*config.Address{
				"feed-backed": {Name: "feed-backed", Value: "198.51.100.0/24"},
			},
		},
		Policies: []*config.ZonePairPolicies{
			zonePair("trust", "untrust", &config.Policy{
				Name: "deny-feed-backed",
				Match: config.PolicyMatch{
					SourceAddresses: []string{"feed-backed"},
				},
				Action: config.PolicyDeny,
			}),
		},
	}, config.ApplicationsConfig{})
}

func TestMatchCachesQuerySnapshotAndInvalidatesGenerationAndFeed11010(t *testing.T) {
	cfg := cacheTestConfig11010(config.PolicyPermit)
	q := Query{
		FromZone: "trust",
		ToZone:   "untrust",
		SrcIP:    net.ParseIP("203.0.113.9"),
	}

	first := Match(cfg, q)
	second := Match(cfg, q)
	if first.Action != config.PolicyPermit || !first.DefaultUsed || first.Matched ||
		second.Action != first.Action || second.DefaultUsed != first.DefaultUsed ||
		second.Matched != first.Matched || second.PolicyName != first.PolicyName {
		t.Fatalf("repeated identical query changed verdict: first=%+v second=%+v", first, second)
	}
	if _, hit := querySnapshotFor(cfg, nil); !hit {
		t.Fatal("Match did not retain its query-ready policy snapshot for an identical generation and feed overlay")
	}

	feed := map[string][]string{"feed-backed": {"203.0.113.0/24"}}
	if _, hit := querySnapshotFor(cfg, feed); hit {
		t.Fatal("a changed feed-overlay digest reused the prior query snapshot")
	}
	q.FeedOverlay = feed
	withFeed := Match(cfg, q)
	if !withFeed.Matched || withFeed.Action != config.PolicyDeny || withFeed.PolicyName != "deny-feed-backed" {
		t.Fatalf("feed-overlay change did not change the address-book verdict: %+v", withFeed)
	}
	if _, hit := querySnapshotFor(cfg, feed); !hit {
		t.Fatal("Match did not cache the query snapshot for the changed feed-overlay digest")
	}

	newGeneration := cacheTestConfig11010(config.PolicyDeny)
	if _, hit := querySnapshotFor(newGeneration, nil); hit {
		t.Fatal("a new compiled config generation reused the previous generation's query snapshot")
	}
	q.FeedOverlay = nil
	q2 := Query{FromZone: "trust", ToZone: "untrust", SrcIP: net.ParseIP("203.0.113.9")}
	changedConfig := Match(newGeneration, q2)
	if changedConfig.Action != config.PolicyDeny || changedConfig.Matched {
		t.Fatalf("new generation did not apply its changed default policy: %+v", changedConfig)
	}
	if _, hit := querySnapshotFor(newGeneration, nil); !hit {
		t.Fatal("Match did not cache the new configuration generation")
	}
}

func TestSharedAddressSetExpansionIsMemoizedWithinQuery11010(t *testing.T) {
	cfg := cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		AddressBook: &config.AddressBook{
			Addresses: map[string]*config.Address{
				"protected": {Name: "protected", Value: "10.0.0.0/8"},
			},
			AddressSets: map[string]*config.AddressSet{
				"shared-leaf": {Name: "shared-leaf", Addresses: []string{"protected"}},
				"branch-a":    {Name: "branch-a", AddressSets: []string{"shared-leaf"}},
				"branch-b":    {Name: "branch-b", AddressSets: []string{"shared-leaf"}},
				"root":        {Name: "root", AddressSets: []string{"branch-a", "branch-b"}},
			},
		},
		Policies: []*config.ZonePairPolicies{
			zonePair("trust", "untrust",
				&config.Policy{
					Name: "skip-https",
					Match: config.PolicyMatch{
						SourceAddresses: []string{"root"},
						Applications:    []string{"junos-https"},
					},
					Action: config.PolicyDeny,
				},
				&config.Policy{
					Name:   "permit-shared-root",
					Match:  config.PolicyMatch{SourceAddresses: []string{"root"}},
					Action: config.PolicyPermit,
				},
			),
		},
	}, config.ApplicationsConfig{})
	memo := &addressExpansionMemo{}
	q := Query{
		FromZone: "trust",
		ToZone:   "untrust",
		SrcIP:    net.ParseIP("10.1.2.3"),
		DstIP:    net.ParseIP("192.0.2.1"),
		Protocol: "tcp",
		DstPort:  80,
	}

	rules := cfg.Security.Policies[0].Policies
	if ruleMatchesWithMemo(cfg, q, rules[0], memo) {
		t.Fatal("the https deny unexpectedly matched an unrelated destination port")
	}
	if !ruleMatchesWithMemo(cfg, q, rules[1], memo) {
		t.Fatal("the later rule did not match the shared nested address set")
	}
	if len(memo.resolved) != 1 {
		t.Fatalf("address tokens expanded %d times within one query, want the shared root once", len(memo.resolved))
	}
	root, ok := memo.resolved["root"]
	if !ok || len(root.v4nets) == 0 {
		t.Fatalf("memoized shared closure has no protected-address prefix: %+v", root)
	}
	firstPrefix := root.v4nets[0]
	if !firstPrefix.Contains(net.ParseIP("10.1.2.3")) {
		t.Fatal("memoized shared closure lost its protected-address prefix")
	}
	resolved := resolvePolicyAddressToken(cfg, nil, "root", memo)
	if len(resolved.v4nets) == 0 || resolved.v4nets[0] != firstPrefix {
		t.Fatal("repeated shared-root lookup did not reuse the query's resolved closure")
	}
}

func TestContentRejectionReasonsAreCopiedFromCachedSnapshot11010(t *testing.T) {
	cfg := cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyPermit,
		Policies: []*config.ZonePairPolicies{
			zonePair("trust", "untrust", &config.Policy{
				Name: "bad-app",
				Match: config.PolicyMatch{
					Applications: []string{"missing-app"},
				},
				Action: config.PolicyPermit,
			}),
		},
	}, config.ApplicationsConfig{})
	q := Query{FromZone: "trust", ToZone: "untrust"}

	first := Match(cfg, q)
	if !first.ContentRejected || len(first.ContentRejectionReasons) == 0 {
		t.Fatalf("unrepresentable policy did not return its cached rejection reason: %+v", first)
	}
	wantReason := first.ContentRejectionReasons[0]
	first.ContentRejectionReasons[0] = "caller mutation"

	second := Match(cfg, q)
	if !second.ContentRejected || len(second.ContentRejectionReasons) == 0 ||
		second.ContentRejectionReasons[0] != wantReason {
		t.Fatalf("caller mutation escaped into the immutable query snapshot: first=%+v second=%+v", first, second)
	}
}
