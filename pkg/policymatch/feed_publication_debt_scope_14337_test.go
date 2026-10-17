package policymatch

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14337: debt consulted by a rule eliminated on a static dimension
// (application, or the other address side) must not poison the query.

func debtScopeConfig14337() *config.Config {
	return cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		AddressBook: &config.AddressBook{
			Addresses: map[string]*config.Address{
				"other": {Name: "other", Value: "192.0.2.99/32"},
				"srv":   {Name: "srv", Value: "10.0.2.10/32"},
			},
		},
		DynamicAddress: config.DynamicAddressConfig{
			AddressBindings: map[string]*config.AddressBinding{
				"other": {Name: "other", FeedNames: []string{"other"}},
			},
		},
		Policies: []*config.ZonePairPolicies{
			zonePair("trust", "untrust",
				&config.Policy{
					Name: "http-via-other",
					Match: config.PolicyMatch{
						SourceAddresses:      []string{"other"},
						DestinationAddresses: []string{"any"},
						Applications:         []string{"junos-http"},
					},
					Action: config.PolicyPermit,
				},
				&config.Policy{
					Name: "ssh-to-srv",
					Match: config.PolicyMatch{
						SourceAddresses:      []string{"any"},
						DestinationAddresses: []string{"srv"},
						Applications:         []string{"junos-ssh"},
					},
					Action: config.PolicyPermit,
				},
			),
		},
	}, config.ApplicationsConfig{})
}

func TestMatch_FeedPublicationDebtNotPoisonedByAppMismatchRule(t *testing.T) {
	cfg := debtScopeConfig14337()
	q := Query{
		FromZone: "trust", ToZone: "untrust",
		SrcIP: net.ParseIP("10.0.0.5"), DstIP: net.ParseIP("10.0.2.10"),
		Protocol: "tcp", DstPort: 22,
		FeedOverlay:         map[string][]string{"other": {"192.0.2.99/32"}},
		FeedPublicationDebt: map[string]bool{"other": true},
	}
	// Control: without debt the SSH query matches rule2.
	qNoDebt := q
	qNoDebt.FeedPublicationDebt = nil
	if res := Match(cfg, qNoDebt); !res.Matched || res.PolicyName != "ssh-to-srv" {
		t.Fatalf("control without debt = %+v, want match ssh-to-srv", res)
	}
	res := Match(cfg, q)
	if res.FeedPublicationDebt {
		t.Fatalf("debt from app-mismatched earlier rule poisoned query: %+v", res)
	}
	if !res.Matched || res.PolicyName != "ssh-to-srv" || res.Action != config.PolicyPermit {
		t.Fatalf("result = %+v, want matched ssh-to-srv permit", res)
	}
}

// Same rule, but the debt-bearing side is the destination and the source
// side eliminates the rule: debt must not commit either.
func TestMatch_FeedPublicationDebtNotPoisonedBySourceMismatchRule(t *testing.T) {
	cfg := cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		AddressBook: &config.AddressBook{
			Addresses: map[string]*config.Address{
				"other": {Name: "other", Value: "192.0.2.99/32"},
				"lan":   {Name: "lan", Value: "10.0.0.0/24"},
				"srv":   {Name: "srv", Value: "10.0.2.10/32"},
			},
		},
		DynamicAddress: config.DynamicAddressConfig{
			AddressBindings: map[string]*config.AddressBinding{
				"other": {Name: "other", FeedNames: []string{"other"}},
			},
		},
		Policies: []*config.ZonePairPolicies{
			zonePair("trust", "untrust",
				&config.Policy{
					Name: "ssh-via-other-dst",
					Match: config.PolicyMatch{
						SourceAddresses:      []string{"lan"},
						DestinationAddresses: []string{"other"},
						Applications:         []string{"junos-ssh"},
					},
					Action: config.PolicyPermit,
				},
				&config.Policy{
					Name: "ssh-to-srv",
					Match: config.PolicyMatch{
						SourceAddresses:      []string{"any"},
						DestinationAddresses: []string{"srv"},
						Applications:         []string{"junos-ssh"},
					},
					Action: config.PolicyPermit,
				},
			),
		},
	}, config.ApplicationsConfig{})
	// Src is NOT in lan (10.9.0.5), so rule1 is eliminated on source;
	// its destination token "other" must never be consulted/committed.
	res := Match(cfg, Query{
		FromZone: "trust", ToZone: "untrust",
		SrcIP: net.ParseIP("10.9.0.5"), DstIP: net.ParseIP("10.0.2.10"),
		Protocol: "tcp", DstPort: 22,
		FeedOverlay:         map[string][]string{"other": {"192.0.2.99/32"}},
		FeedPublicationDebt: map[string]bool{"other": true},
	})
	if res.FeedPublicationDebt {
		t.Fatalf("debt from source-mismatched rule poisoned query: %+v", res)
	}
	if !res.Matched || res.PolicyName != "ssh-to-srv" {
		t.Fatalf("result = %+v, want matched ssh-to-srv", res)
	}
}

// Control: a rule that actually matches (or is eliminated only by the
// debt-bearing side itself) still reports debt — fail-closed preserved.
func TestMatch_FeedPublicationDebtOnMatchingRuleStillReported(t *testing.T) {
	cfg := debtScopeConfig14337()
	// HTTP query from the debt-bearing source matches rule1 exactly.
	res := Match(cfg, Query{
		FromZone: "trust", ToZone: "untrust",
		SrcIP: net.ParseIP("192.0.2.99"), DstIP: net.ParseIP("10.0.2.10"),
		Protocol: "tcp", DstPort: 80,
		FeedOverlay:         map[string][]string{"other": {"192.0.2.99/32"}},
		FeedPublicationDebt: map[string]bool{"other": true},
	})
	if !res.FeedPublicationDebt || len(res.FeedPublicationDebtNames) != 1 || res.FeedPublicationDebtNames[0] != "other" {
		t.Fatalf("matching debt rule must still report debt: %+v", res)
	}
	// Query whose only candidate is eliminated BY the debt-bearing side:
	// src not in "other", HTTP — rule1's source side decides, so the feed
	// content could have changed the verdict; debt must be reported, and
	// rule2 (SSH) does not match HTTP, so no permit is certified.
	res2 := Match(cfg, Query{
		FromZone: "trust", ToZone: "untrust",
		SrcIP: net.ParseIP("10.0.0.5"), DstIP: net.ParseIP("10.0.2.10"),
		Protocol: "tcp", DstPort: 80,
		FeedOverlay:         map[string][]string{"other": {"192.0.2.99/32"}},
		FeedPublicationDebt: map[string]bool{"other": true},
	})
	if !res2.FeedPublicationDebt {
		t.Fatalf("debt-bearing side deciding elimination must report debt: %+v", res2)
	}
	if res2.Matched {
		t.Fatalf("debt result must not certify a match: %+v", res2)
	}
}

// junos-host: debt from an unrelated transit rule must not wipe
// HostInbound admission context on a host query.
func TestMatch_FeedPublicationDebtNotPoisonedOnJunosHost(t *testing.T) {
	cfg := cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		AddressBook: &config.AddressBook{
			Addresses: map[string]*config.Address{
				"other": {Name: "other", Value: "192.0.2.99/32"},
			},
		},
		DynamicAddress: config.DynamicAddressConfig{
			AddressBindings: map[string]*config.AddressBinding{
				"other": {Name: "other", FeedNames: []string{"other"}},
			},
		},
		Policies: []*config.ZonePairPolicies{
			zonePair("trust", "untrust",
				&config.Policy{
					Name: "http-via-other",
					Match: config.PolicyMatch{
						SourceAddresses:      []string{"other"},
						DestinationAddresses: []string{"any"},
						Applications:         []string{"junos-http"},
					},
					Action: config.PolicyPermit,
				}),
			zonePair("trust", JunosHostZone,
				&config.Policy{
					Name: "allow-host-ssh",
					Match: config.PolicyMatch{
						SourceAddresses:      []string{"any"},
						DestinationAddresses: []string{"any"},
						Applications:         []string{"junos-ssh"},
					},
					Action: config.PolicyPermit,
				}),
		},
	}, config.ApplicationsConfig{})
	res := Match(cfg, Query{
		FromZone: "trust", ToZone: JunosHostZone,
		SrcIP: net.ParseIP("10.0.0.5"), DstIP: net.ParseIP("10.0.0.1"),
		Protocol: "tcp", DstPort: 22,
		FeedOverlay:         map[string][]string{"other": {"192.0.2.99/32"}},
		FeedPublicationDebt: map[string]bool{"other": true},
	})
	if res.FeedPublicationDebt {
		t.Fatalf("transit-rule debt poisoned host query: %+v", res)
	}
	if !res.Matched || res.PolicyName != "allow-host-ssh" {
		t.Fatalf("result = %+v, want matched allow-host-ssh", res)
	}
	if res.HostInbound == nil {
		t.Fatalf("HostInbound context wiped: %+v", res)
	}
}

// #14337 nil-IP: an excluded side over a defined-but-empty feed must fail
// closed even when the query omits that side's IP, exactly as it does
// with a concrete IP.
func nilIPExcludedConfig14337() *config.Config {
	return cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		DynamicAddress: config.DynamicAddressConfig{
			AddressBindings: map[string]*config.AddressBinding{
				// Default (retain) fail mode: a present-empty overlay is a
				// published empty set, NOT the fail-mode-drop empty that
				// PolicyContentRejectionReasons rejects config-wide, so the
				// per-rule excluded-empty gate is the deciding check.
				"partners": {Name: "partners", FeedNames: []string{"partner-feed"}},
			},
		},
		Policies: []*config.ZonePairPolicies{
			zonePair("trust", "untrust",
				&config.Policy{
					Name: "permit-except-partners",
					Match: config.PolicyMatch{
						SourceAddresses:       []string{"partners"},
						SourceAddressExcluded: true,
						DestinationAddresses:  []string{"any"},
						Applications:          []string{"any"},
					},
					Action: config.PolicyPermit,
				}),
		},
	}, config.ApplicationsConfig{})
}

func TestMatch_NilIPExcludedEmptyFeedFailsClosed(t *testing.T) {
	cfg := nilIPExcludedConfig14337()
	overlay := map[string][]string{"partners": {}}
	// Concrete-IP control: excluded empty set does not match.
	concrete := Match(cfg, Query{
		FromZone: "trust", ToZone: "untrust",
		SrcIP: net.ParseIP("203.0.113.7"), DstIP: net.ParseIP("192.0.2.80"),
		Protocol: "tcp", DstPort: 80,
		FeedOverlay: overlay,
	})
	if concrete.ContentRejected {
		t.Fatalf("fixture must not be content-rejected (would mask the per-rule gate): %+v", concrete)
	}
	if concrete.Matched {
		t.Fatalf("concrete-IP control matched excluded empty feed: %+v", concrete)
	}
	// Nil source IP: must agree — no fail-open permit.
	nilSrc := Match(cfg, Query{
		FromZone: "trust", ToZone: "untrust",
		DstIP:    net.ParseIP("192.0.2.80"),
		Protocol: "tcp", DstPort: 80,
		FeedOverlay: overlay,
	})
	if nilSrc.Matched || nilSrc.Action == config.PolicyPermit {
		t.Fatalf("nil-IP query failed open on excluded empty feed: %+v", nilSrc)
	}
}

// Defined-but-empty feed binding absent from the overlay entirely is
// unrepresentable content: the whole snapshot is rejected (fail-closed),
// which the simulator must report — never a permit. This also guards
// leg (3): the binding is recognised as a name, not parsed as a literal
// that would keep an excluded side "non-empty" and matching.
func TestMatch_ExcludedEmptyBindingAbsentFromOverlayFailsClosed(t *testing.T) {
	cfg := nilIPExcludedConfig14337()
	for _, tc := range []struct {
		name string
		src  net.IP
	}{
		{"concrete", net.ParseIP("203.0.113.7")},
		{"nil", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := Match(cfg, Query{
				FromZone: "trust", ToZone: "untrust",
				SrcIP: tc.src, DstIP: net.ParseIP("192.0.2.80"),
				Protocol: "tcp", DstPort: 80,
				// No overlay entry for "partners" at all.
			})
			if res.Matched || res.Action == config.PolicyPermit {
				t.Fatalf("excluded empty binding (absent overlay) failed open (%s): %+v", tc.name, res)
			}
			if !res.ContentRejected {
				t.Fatalf("absent-overlay binding must fail closed via content rejection (%s): %+v", tc.name, res)
			}
		})
	}
	// Direct leg-(3) guard: a declared binding token is a book name even
	// with no overlay entry and no static book entry.
	if !isBookName(cfg, nil, "partners") {
		t.Fatal("isBookName must recognise a declared AddressBinding absent from overlay")
	}
}

// Nil-IP debt recording: resolving an excluded-empty debt-bearing side
// with no IP must still consult (and report) the feed debt.
func TestMatch_NilIPExcludedEmptyFeedRecordsDebt(t *testing.T) {
	cfg := nilIPExcludedConfig14337()
	res := Match(cfg, Query{
		FromZone: "trust", ToZone: "untrust",
		DstIP:    net.ParseIP("192.0.2.80"),
		Protocol: "tcp", DstPort: 80,
		FeedOverlay:         map[string][]string{"partners": {}},
		FeedPublicationDebt: map[string]bool{"partner-feed": true},
	})
	if res.Matched {
		t.Fatalf("nil-IP excluded empty feed matched: %+v", res)
	}
	if !res.FeedPublicationDebt {
		t.Fatalf("nil-IP evaluation must record consulted debt: %+v", res)
	}
}
