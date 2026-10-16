package policymatch

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// fragmentDenyCfg builds the #5572 fixture: an EARLIER source-scoped
// `deny junos-https` (TCP dst 443) then a `permit any`, trust->untrust. The
// dataplane's #4569 fragment-associated deny fails a non-first fragment closed
// against the port-bearing deny the first fragment WOULD hit, even though the
// fragment carries no L4 port; the simulator must reproduce that instead of
// certifying the later permit.
//
// The deny is source-scoped to 10.0.0.0/8 so overlap vs non-overlap can be
// exercised (the permit is unconstrained, so a fragment outside the deny's
// source set still permits).
func fragmentDenyCfg() *config.Config {
	sec := config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		Zones:         zones("trust", "untrust"),
		AddressBook: &config.AddressBook{
			Addresses: map[string]*config.Address{
				"trust-net": {Name: "trust-net", Value: "10.0.0.0/8"},
			},
		},
		Policies: []*config.ZonePairPolicies{
			{
				FromZone: "trust",
				ToZone:   "untrust",
				Policies: []*config.Policy{
					{
						Name:   "block-https",
						Action: config.PolicyDeny,
						Match: config.PolicyMatch{
							SourceAddresses:      []string{"trust-net"},
							DestinationAddresses: []string{"any"},
							Applications:         []string{"junos-https"},
						},
					},
					{
						Name:   "permit-all",
						Action: config.PolicyPermit,
						Match: config.PolicyMatch{
							SourceAddresses:      []string{"any"},
							DestinationAddresses: []string{"any"},
							Applications:         []string{"any"},
						},
					},
				},
			},
		},
	}
	return cfgWith(sec, config.ApplicationsConfig{})
}

// TestNonFirstFragmentInheritsPortBearingDeny is the #5572 FAIL-ON-REVERT pin.
//
// A non-first TCP fragment (NonFirstFragment=true — the dataplane's
// l4_present==false, no readable ports) whose L3 OVERLAPS the earlier
// port-bearing `deny junos-https` must be DENIED and attributed to that deny,
// exactly like the dataplane's #4569 override — NOT reported as the later
// `permit any` (the simulator-vs-dataplane divergence the issue names).
//
// FAIL-ON-REVERT: revert the discriminator so the fragment query is evaluated
// as a plain port-0 packet (drop the NonFirstFragment plumbing / the Match
// override) and the port-bearing deny fails closed for a port-0 packet, so the
// walk falls through to `permit any` and this reports Matched permit — failing
// the want-deny assertion. The parallel port-0 NORMAL query below proves the
// two shapes MUST diverge: a normal omitted-port packet permits, a fragment
// denies. Runs IPv4 + IPv6 (the issue notes it is family-independent).
func TestNonFirstFragmentInheritsPortBearingDeny(t *testing.T) {
	cfg := fragmentDenyCfg()

	cases := []struct {
		name string
		src  net.IP
		dst  net.IP
	}{
		{"ipv4", net.ParseIP("10.1.2.3"), net.ParseIP("203.0.113.9")},
		{"ipv6", net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8:ffff::9")},
	}
	// The IPv6 case needs the source book to cover v6; extend the fixture so the
	// deny's source set overlaps the v6 fragment too (the deny is otherwise
	// v4-only and would not overlap a v6 fragment).
	cfg.Security.AddressBook.AddressSets = nil
	cfg.Security.AddressBook.Addresses["trust-net6"] = &config.Address{Name: "trust-net6", Value: "2001:db8::/32"}
	cfg.Security.Policies[0].Policies[0].Match.SourceAddresses = []string{"trust-net", "trust-net6"}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The FRAGMENT query: no L4 port, NonFirstFragment set.
			frag := Query{
				FromZone:         "trust",
				ToZone:           "untrust",
				SrcIP:            tc.src,
				DstIP:            tc.dst,
				Protocol:         "tcp",
				NonFirstFragment: true,
			}
			res := Match(cfg, frag)
			if !res.Matched || res.Action != config.PolicyDeny {
				t.Fatalf("non-first fragment must inherit the overlapping port-bearing deny "+
					"(#5572); want Matched deny, got %+v", res)
			}
			if res.PolicyName != "block-https" {
				t.Fatalf("fragment deny must be attributed to the enforcing deny policy "+
					"(so incident response sees the real policy id); want block-https, got %q", res.PolicyName)
			}
			if !res.FragmentAssociatedDeny {
				t.Fatalf("fragment-associated deny must set FragmentAssociatedDeny so the "+
					"advisory renders; got %+v", res)
			}
			if res.FragmentDenyNote() == "" {
				t.Fatalf("FragmentAssociatedDeny result must produce a FragmentDenyNote advisory")
			}

			// The CONTRAST: the SAME tuple as a NORMAL L4-present packet with an
			// omitted (0) port permits — the port-bearing deny fails closed for a
			// port-0 packet and the walk lands on permit-all. This is exactly why
			// the fragment discriminator is required: without it the fragment
			// would ALSO permit (the bug).
			normal := frag
			normal.NonFirstFragment = false
			nres := Match(cfg, normal)
			if !nres.Matched || nres.Action != config.PolicyPermit {
				t.Fatalf("a NORMAL omitted-port packet on this tuple must permit via permit-all "+
					"(the contrast that proves the shapes diverge); got %+v", nres)
			}
			if nres.FragmentAssociatedDeny {
				t.Fatalf("a normal (non-fragment) query must never carry FragmentAssociatedDeny; got %+v", nres)
			}
		})
	}
}

// TestNonFirstFragmentConcretePortStillDeniesDirectly is the positive control
// for a FIRST fragment / full packet: a concrete TCP/443 query (L4 present)
// still matches the deny DIRECTLY (a normal deny match), and is NOT flagged as a
// fragment-associated (override) deny. This proves the #5572 override is scoped
// to the flowless fragment path and does not change the L4 verdict.
func TestNonFirstFragmentConcretePortStillDeniesDirectly(t *testing.T) {
	cfg := fragmentDenyCfg()
	res := Match(cfg, Query{
		FromZone: "trust", ToZone: "untrust",
		SrcIP: net.ParseIP("10.1.2.3"), DstIP: net.ParseIP("203.0.113.9"),
		Protocol: "tcp", DstPort: 443,
	})
	if !res.Matched || res.Action != config.PolicyDeny || res.PolicyName != "block-https" {
		t.Fatalf("concrete TCP/443 must deny directly via block-https; got %+v", res)
	}
	if res.FragmentAssociatedDeny {
		t.Fatalf("a direct L4 deny must NOT be flagged as a fragment-associated override; got %+v", res)
	}
}

// TestNonFirstFragmentNonOverlappingSourcePermits pins the scoping: a non-first
// fragment whose SOURCE is OUTSIDE the deny's source set does NOT overlap the
// port-bearing deny, so it is NOT failed closed — it forwards via permit-all.
// This mirrors the dataplane's rule_l3_matches gate (a non-overlapping deny
// leaves the fragment on its normal path).
func TestNonFirstFragmentNonOverlappingSourcePermits(t *testing.T) {
	cfg := fragmentDenyCfg()
	res := Match(cfg, Query{
		FromZone: "trust", ToZone: "untrust",
		SrcIP:            net.ParseIP("192.168.1.1"), // NOT in 10.0.0.0/8
		DstIP:            net.ParseIP("203.0.113.9"),
		Protocol:         "tcp",
		NonFirstFragment: true,
	})
	if !res.Matched || res.Action != config.PolicyPermit {
		t.Fatalf("a non-overlapping fragment must forward via permit-all, not inherit the "+
			"source-scoped deny; got %+v", res)
	}
	if res.FragmentAssociatedDeny {
		t.Fatalf("no overlapping deny → FragmentAssociatedDeny must be false; got %+v", res)
	}
}

// TestNonFirstFragmentDifferentProtocolPermits pins has_l4_constrained_term: a
// UDP fragment is NOT denied by a TCP-only port-bearing deny (the deny has no
// term for UDP), so it forwards via permit-all. Without the
// hasL4ConstrainedTerm discriminator every zero-port deny would falsely snare
// the fragment.
func TestNonFirstFragmentDifferentProtocolPermits(t *testing.T) {
	cfg := fragmentDenyCfg()
	res := Match(cfg, Query{
		FromZone: "trust", ToZone: "untrust",
		SrcIP: net.ParseIP("10.1.2.3"), DstIP: net.ParseIP("203.0.113.9"),
		Protocol:         "udp", // deny junos-https is TCP-only
		NonFirstFragment: true,
	})
	if !res.Matched || res.Action != config.PolicyPermit {
		t.Fatalf("a UDP fragment must not inherit a TCP-only deny; got %+v", res)
	}
	if res.FragmentAssociatedDeny {
		t.Fatalf("different-protocol deny does not overlap → FragmentAssociatedDeny false; got %+v", res)
	}
}

// TestNonFirstFragmentProtocolOnlyDenyMatchesDirectly pins the "real deny"
// distinction: a deny whose application term is PROTOCOL-ONLY (a custom TCP app
// with no port) matches a TCP fragment DIRECTLY on the known protocol — it is a
// real deny match, not an override — so FragmentAssociatedDeny is false.
func TestNonFirstFragmentProtocolOnlyDenyMatchesDirectly(t *testing.T) {
	sec := config.SecurityConfig{
		DefaultPolicy: config.PolicyPermit,
		Zones:         zones("trust", "untrust"),
		Policies: []*config.ZonePairPolicies{
			{
				FromZone: "trust", ToZone: "untrust",
				Policies: []*config.Policy{
					{
						Name:   "deny-all-tcp",
						Action: config.PolicyDeny,
						Match: config.PolicyMatch{
							SourceAddresses:      []string{"any"},
							DestinationAddresses: []string{"any"},
							Applications:         []string{"tcp-any"},
						},
					},
				},
			},
		},
	}
	apps := config.ApplicationsConfig{
		Applications: map[string]*config.Application{
			// Protocol-only: matches every TCP packet (and TCP fragment) regardless
			// of port — the dataplane's empty-range term matches flowlessly.
			"tcp-any": {Name: "tcp-any", Protocol: "tcp"},
		},
	}
	cfg := cfgWith(sec, apps)
	res := Match(cfg, Query{
		FromZone: "trust", ToZone: "untrust",
		Protocol: "tcp", NonFirstFragment: true,
	})
	if !res.Matched || res.Action != config.PolicyDeny || res.PolicyName != "deny-all-tcp" {
		t.Fatalf("a protocol-only deny must match a TCP fragment directly; got %+v", res)
	}
	if res.FragmentAssociatedDeny {
		t.Fatalf("a direct protocol-only deny is a real match, not an override; got %+v", res)
	}
}

// TestNonFirstFragmentDefaultPermitOverridden pins the default-policy arm of the
// #4569 override: with default-policy PERMIT and no permit rule, a fragment that
// skipped an overlapping port-bearing deny is still failed closed to that deny
// rather than counted as a default-permit.
func TestNonFirstFragmentDefaultPermitOverridden(t *testing.T) {
	sec := config.SecurityConfig{
		DefaultPolicy: config.PolicyPermit, // default-permit
		Zones:         zones("trust", "untrust"),
		Policies: []*config.ZonePairPolicies{
			{
				FromZone: "trust", ToZone: "untrust",
				Policies: []*config.Policy{
					{
						Name:   "block-https",
						Action: config.PolicyDeny,
						Match: config.PolicyMatch{
							SourceAddresses:      []string{"any"},
							DestinationAddresses: []string{"any"},
							Applications:         []string{"junos-https"},
						},
					},
				},
			},
		},
	}
	cfg := cfgWith(sec, config.ApplicationsConfig{})
	res := Match(cfg, Query{
		FromZone: "trust", ToZone: "untrust",
		Protocol: "tcp", NonFirstFragment: true,
	})
	if !res.Matched || res.Action != config.PolicyDeny || !res.FragmentAssociatedDeny {
		t.Fatalf("a fragment skipping a port-bearing deny under default-permit must fail "+
			"closed to that deny (#4569 default arm); got %+v", res)
	}
	// The normal contrast: a plain omitted-port packet permits by default here.
	nres := Match(cfg, Query{FromZone: "trust", ToZone: "untrust", Protocol: "tcp"})
	if nres.Matched || nres.Action != config.PolicyPermit || !nres.DefaultUsed {
		t.Fatalf("a normal omitted-port packet must take the default-permit; got %+v", nres)
	}
}

// TestNonFirstFragmentSkippedRejectKeepsAction is the reject-preservation parity
// pin (#13705). A non-first fragment that SKIPS a port-bearing REJECT
// (isSkippedFragDeny accepts PolicyReject — a reject shadows the fragment
// identically to a deny) and then lands on `permit any` is reported with
// Action=REJECT, matching the Rust dataplane, whose #13705 change carries the
// skipped rule's action and logging metadata in SkippedFragDeny /
// frag_associated_deny_result. The fragment still DROPs silently (no L4 header
// → no RST/ICMP); only the reported verdict label preserves the configured rule
// action, exactly as the dataplane's RT_FLOW emission downgrades a reply-free
// Reject to a truthful DENY on the wire.
//
// FAIL-ON-REVERT: restore the `r.Action = config.PolicyDeny` force in
// fragDenyResult and the verdict is normalized back to Deny, flipping this red
// (Action=deny), catching the simulator/dataplane label divergence.
func TestNonFirstFragmentSkippedRejectKeepsAction(t *testing.T) {
	sec := config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		Zones:         zones("trust", "untrust"),
		AddressBook: &config.AddressBook{
			Addresses: map[string]*config.Address{
				"trust-net": {Name: "trust-net", Value: "10.0.0.0/8"},
			},
		},
		Policies: []*config.ZonePairPolicies{
			{
				FromZone: "trust", ToZone: "untrust",
				Policies: []*config.Policy{
					{
						Name:   "reject-https",
						Action: config.PolicyReject, // a REJECT, not a plain deny
						Match: config.PolicyMatch{
							SourceAddresses:      []string{"trust-net"},
							DestinationAddresses: []string{"any"},
							Applications:         []string{"junos-https"},
						},
					},
					{
						Name:   "permit-all",
						Action: config.PolicyPermit,
						Match: config.PolicyMatch{
							SourceAddresses:      []string{"any"},
							DestinationAddresses: []string{"any"},
							Applications:         []string{"any"},
						},
					},
				},
			},
		},
	}
	cfg := cfgWith(sec, config.ApplicationsConfig{})

	res := Match(cfg, Query{
		FromZone: "trust", ToZone: "untrust",
		SrcIP: net.ParseIP("10.1.2.3"), DstIP: net.ParseIP("203.0.113.9"),
		Protocol: "tcp", NonFirstFragment: true,
	})
	if !res.Matched || !res.FragmentAssociatedDeny {
		t.Fatalf("fragment must inherit the overlapping port-bearing reject as an override; got %+v", res)
	}
	// Identity still names the enforcing rule.
	if res.PolicyName != "reject-https" {
		t.Fatalf("fragment verdict must name the enforcing rule reject-https; got %q", res.PolicyName)
	}
	// The ACTION preserves the skipped rule's reject (#13705): the fragment
	// drops silently (no RST/ICMP without an L4 header), but the verdict label
	// names the configured disposition, matching the dataplane's result.
	if res.Action != config.PolicyReject {
		t.Fatalf("a fragment-associated verdict for a skipped REJECT must report Action=reject "+
			"(configured disposition preserved; packet still drops silently); got Action=%v", res.Action)
	}
	// The positive control: a concrete TCP/443 packet still REJECTS directly
	// (the reject label is preserved for a real L4 match too).
	direct := Match(cfg, Query{
		FromZone: "trust", ToZone: "untrust",
		SrcIP: net.ParseIP("10.1.2.3"), DstIP: net.ParseIP("203.0.113.9"),
		Protocol: "tcp", DstPort: 443,
	})
	if !direct.Matched || direct.Action != config.PolicyReject || direct.FragmentAssociatedDeny {
		t.Fatalf("a concrete L4 reject must still report reject (not normalized); got %+v", direct)
	}
}

// TestParseSelectorArgsNonFirstFragmentFlag pins the CLI selector plumbing: the
// valueless `non-first-fragment` token sets SelectorArgs.NonFirstFragment and
// threads into Query, and a duplicate is rejected (fail-closed, #3709 posture).
func TestParseSelectorArgsNonFirstFragmentFlag(t *testing.T) {
	sel, err := ParseSelectorArgs([]string{"from-zone", "trust", "to-zone", "untrust", "protocol", "tcp", "non-first-fragment"})
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if !sel.NonFirstFragment {
		t.Fatalf("non-first-fragment selector must set NonFirstFragment; got %+v", sel)
	}
	if q := sel.Query(); !q.NonFirstFragment {
		t.Fatalf("SelectorArgs.Query() must carry NonFirstFragment; got %+v", q)
	}
	// Default (selector absent) stays false.
	sel2, err := ParseSelectorArgs([]string{"from-zone", "trust", "to-zone", "untrust"})
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if sel2.NonFirstFragment {
		t.Fatalf("NonFirstFragment must default false when the selector is absent; got %+v", sel2)
	}
	// Duplicate is an error (it is duplicate-checked like every other selector).
	if _, err := ParseSelectorArgs([]string{"from-zone", "trust", "to-zone", "untrust", "non-first-fragment", "non-first-fragment"}); err == nil {
		t.Fatalf("duplicate non-first-fragment selector must be rejected")
	}
}
