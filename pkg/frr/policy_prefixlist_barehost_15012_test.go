package frr

import (
	"fmt"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15012 (A10-01): a bare-host prefix-list entry (no "/len") is commit-valid
// — the #7273 firewall classifier accepts it as /32 or /128, and Junos
// treats a mask-less entry as a host route — but the #10823 render belt
// required net.ParseCIDR, so it warned "malformed" and omitted the entry
// from both FRR prefix-list definitions and inline ACLs, and
// prefixListRefMissingAtRender treated an all-bare list as dangling
// (deny-all for a reject term / dropped branch for accept). In a mixed
// list the host route silently escaped a `then reject` term (fail-open).
//
// FAIL-ON-REVERT: restoring the bare net.ParseCIDR predicate at the three
// #10823 sites makes every bare-host assertion below fail: bare_mixed
// renders no 10.0.0.1/32 line, bare_only renders no matching prefix-list
// and its reject term degrades to deny-all.

func bareHostRender15012(t *testing.T, src string) string {
	t.Helper()
	tree, parseErrs := config.NewParser(src).Parse()
	if len(parseErrs) != 0 {
		t.Fatalf("parse: %v", parseErrs)
	}
	var got string
	for _, tc := range []struct {
		name    string
		compile func(*config.ConfigTree) (*config.Config, error)
	}{
		{name: "strict", compile: config.CompileConfig},
		{name: "tolerant", compile: config.CompileConfigLenient},
	} {
		cfg, err := tc.compile(tree)
		if err != nil {
			t.Fatalf("%s compile must accept bare-host prefix-list entries: %v", tc.name, err)
		}
		got = New().generatePolicyOptions(&cfg.PolicyOptions)
	}
	return got
}

// bare_mixed: a bare host alongside a valid CIDR renders as /32, keeping
// its seq slot, in both the top-level definition and the inline ACL
// (the route-filter + from-prefix-list same-term collision form).
func TestBareHostPrefixListMixedRendersHost32_15012(t *testing.T) {
	got := bareHostRender15012(t, `policy-options {
  prefix-list PL {
    10.0.0.0/8;
    10.0.0.1;
    2001:db8::1;
  }
  policy-statement P {
    term t1 {
      from {
        prefix-list PL;
        route-filter 192.0.2.0/24 exact;
      }
      then reject;
    }
  }
}`)
	for _, want := range []string{
		"ip prefix-list PL seq 5 permit 10.0.0.0/8\n",
		"ip prefix-list PL seq 10 permit 10.0.0.1/32\n",
		"ipv6 prefix-list PL seq 15 permit 2001:db8::1/128\n",
		" permit 10.0.0.1/32 exact-match\n",
		" permit 10.0.0.0/8 exact-match\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("bare-host entry not rendered as host route %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "permit 10.0.0.1\n") || strings.Contains(got, "permit 2001:db8::1\n") {
		t.Errorf("bare host rendered without host mask (FRR-invalid):\n%s", got)
	}
	// The reject term must keep its match — here via the #5730 inline ACL
	// (the term also carries a route-filter), not a bare deny-all — so the
	// host route must not escape the reject.
	if !strings.Contains(got, "match ip address xpf-rf-PL-") {
		t.Errorf("reject term lost its inline prefix-list ACL match:\n%s", got)
	}
}

// bare_only: a list whose only entries are bare hosts renders a matching
// prefix-list, and a reject term over it keeps its match (no deny-all
// downgrade from prefixListRefMissingAtRender).
func TestBareHostPrefixListOnlyRendersMatchingList_15012(t *testing.T) {
	for _, tc := range []struct {
		name   string
		bare   string
		wantPL string
		match  string
	}{
		{name: "v4", bare: "10.0.0.1", wantPL: "ip prefix-list PL seq 5 permit 10.0.0.1/32\n", match: "match ip address prefix-list PL"},
		{name: "v6", bare: "2001:db8::1", wantPL: "ipv6 prefix-list PL seq 5 permit 2001:db8::1/128\n", match: "match ipv6 address prefix-list PL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := bareHostRender15012(t, fmt.Sprintf(`policy-options {
  prefix-list PL {
    %s;
  }
  policy-statement P {
    term t-reject {
      from prefix-list PL;
      then reject;
    }
    term t-accept {
      then accept;
    }
  }
}`, tc.bare))
			if !strings.Contains(got, tc.wantPL) {
				t.Fatalf("bare-only list rendered no matching prefix-list %q:\n%s", tc.wantPL, got)
			}
			if !strings.Contains(got, tc.match) {
				t.Fatalf("reject term over bare-only list lost its match (deny-all downgrade):\n%s", got)
			}
			if strings.Contains(got, "route-map P deny 10\nexit\n") {
				t.Fatalf("reject term over bare-only list degraded to bare deny-all:\n%s", got)
			}
		})
	}
}

// Control: genuinely malformed entries still fail closed at the same
// predicate — bad octet with mask, out-of-range mask, and non-IP tokens
// (including a zone-scoped bare host, which FRR cannot represent) render
// nothing, while the bare sibling renders.
func TestBareHostPrefixListMalformedStillOmitted_15012(t *testing.T) {
	po := prefixListPolicyPO(
		map[string]*config.PrefixList{
			"PL": {Name: "PL", Prefixes: []string{"10.0.0.1", "999.0.0.0/8", "10.0.0.0/33", "foo", "fe80::1%eth0"}},
		},
		[]*config.PolicyTerm{
			{Name: "t-reject", PrefixList: []string{"PL"}, Action: "reject"},
		},
		"reject",
	)
	got := New().generatePolicyOptions(po)
	if !strings.Contains(got, "ip prefix-list PL seq 5 permit 10.0.0.1/32\n") {
		t.Fatalf("bare sibling was omitted with the malformed entries:\n%s", got)
	}
	for _, bad := range []string{"999.0.0.0", "10.0.0.0/33", "foo", "fe80::1"} {
		if strings.Contains(got, bad) {
			t.Errorf("malformed entry %q reached FRR output:\n%s", bad, got)
		}
	}
	if !strings.Contains(got, "match ip address prefix-list PL") {
		t.Errorf("term over mixed bare+malformed list lost its match:\n%s", got)
	}
}

// Control: an all-malformed list still counts as missing (deny-all for
// reject) — normalisation must not resurrect garbage.
func TestBareHostAllMalformedStillMissing_15012(t *testing.T) {
	po := prefixListPolicyPO(
		map[string]*config.PrefixList{
			"BAD": {Name: "BAD", Prefixes: []string{"999.0.0.0/8", "not-a-cidr"}},
		},
		[]*config.PolicyTerm{
			{Name: "t-reject", PrefixList: []string{"BAD"}, Action: "reject"},
			{Name: "t-accept", Action: "accept"},
		},
		"accept",
	)
	got := New().generatePolicyOptions(po)
	if strings.Contains(got, "address prefix-list BAD") {
		t.Fatalf("all-malformed list kept a dangling match:\n%s", got)
	}
	if !strings.Contains(got, "route-map P deny 10\nexit\n") {
		t.Fatalf("all-malformed reject must stay deny-all:\n%s", got)
	}
}
