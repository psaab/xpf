package config

import (
	"math/big"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

// assertCoverExact16563 proves prefixes are pairwise disjoint and their
// union is exactly [low, high]: total size matches, both endpoints are
// covered, and both neighbours just outside are not (when they exist).
func assertCoverExact16563(t *testing.T, prefixes []string, lowS, highS string) {
	t.Helper()
	low, err := netip.ParseAddr(lowS)
	if err != nil {
		t.Fatalf("low: %v", err)
	}
	high, err := netip.ParseAddr(highS)
	if err != nil {
		t.Fatalf("high: %v", err)
	}
	parsed := make([]netip.Prefix, 0, len(prefixes))
	total := new(big.Int)
	for _, s := range prefixes {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			t.Fatalf("cover prefix %q: %v", s, err)
		}
		if p != p.Masked() {
			t.Fatalf("cover prefix %q is not a network address", s)
		}
		parsed = append(parsed, p)
		hostBits := p.Addr().BitLen() - p.Bits()
		total.Add(total, new(big.Int).Lsh(big.NewInt(1), uint(hostBits)))
	}
	for i := range parsed {
		for j := i + 1; j < len(parsed); j++ {
			if parsed[i].Overlaps(parsed[j]) {
				t.Fatalf("cover prefixes %s and %s overlap", parsed[i], parsed[j])
			}
		}
	}
	span := new(big.Int).Sub(addrBig16563(high), addrBig16563(low))
	span.Add(span, big.NewInt(1))
	if total.Cmp(span) != 0 {
		t.Fatalf("cover size %s, want range size %s (%v)", total, span, prefixes)
	}
	contains := func(a netip.Addr) bool {
		for _, p := range parsed {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}
	if !contains(low) || !contains(high) {
		t.Fatalf("cover %v misses an endpoint of %s-%s", prefixes, lowS, highS)
	}
	if prev, ok := prevAddr16563(low); ok && contains(prev) {
		t.Fatalf("cover %v wrongly contains %s (just below low)", prefixes, prev)
	}
	if next, ok := nextAddr16563(high); ok && contains(next) {
		t.Fatalf("cover %v wrongly contains %s (just above high)", prefixes, next)
	}
}

func addrBig16563(a netip.Addr) *big.Int {
	b := a.As16()
	return new(big.Int).SetBytes(b[:])
}

func prevAddr16563(a netip.Addr) (netip.Addr, bool) {
	zero := netip.AddrFrom16([16]byte{})
	if a.Is4() {
		zero = netip.AddrFrom4([4]byte{})
	}
	if a.Compare(zero) == 0 {
		return netip.Addr{}, false
	}
	return a.Prev(), true
}

func nextAddr16563(a netip.Addr) (netip.Addr, bool) {
	max := netip.AddrFrom16([16]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	if a.Is4() {
		max = netip.AddrFrom4([4]byte{0xff, 0xff, 0xff, 0xff})
	}
	if a.Compare(max) == 0 {
		return netip.Addr{}, false
	}
	return a.Next(), true
}

// #15673 — sole dns-name/range-address/wildcard-address forms must be caught
// at strict commit (not silently warn-only), range-address must expand
// natively, wildcard-address must expand, and mergeAddressNode /
// parseAddressBookEntries must not drop sub-stanzas / leaf names.

func soleFormTree(t *testing.T, body string) *ConfigTree {
	t.Helper()
	return parseHierText(t, `security { address-book { global { `+body+` } } zones { security-zone trust; } }`)
}

// Sole unsupported forms: strict must reject deterministically.
func TestSoleAddressFormsRejectedAtCommit15673(t *testing.T) {
	for _, r := range []struct {
		name, body, form string
	}{
		{"sole future form hier", `address partner-api { future-address-form value; }`, "future-address-form"},
		{"sole noncontiguous wildcard hier", `address wc { wildcard-address 10.1.2.3/255.255.0.255; }`, "wildcard-address"},
		{"sole noncontiguous doc-example wildcard hier", `address wc { wildcard-address 192.168.0.11/255.255.0.255; }`, "wildcard-address"},
	} {
		t.Run(r.name, func(t *testing.T) {
			_, err := CompileConfig(soleFormTree(t, r.body))
			if err == nil || !strings.Contains(err.Error(), r.form) {
				t.Fatalf("#15673: strict commit must reject sole %s, got %v", r.form, err)
			}
			cfg, lerr := CompileConfigLenient(soleFormTree(t, r.body))
			if lerr != nil {
				t.Fatalf("lenient must boot (#1960): %v", lerr)
			}
			a := cfg.Security.AddressBook.Addresses[strings.Fields(strings.TrimPrefix(r.body, "address "))[0]]
			_ = a
			warned := false
			for _, w := range cfg.Warnings {
				if strings.Contains(w, r.form) {
					warned = true
				}
			}
			if !warned {
				t.Errorf("lenient must warn naming %s; warnings=%v", r.form, cfg.Warnings)
			}
			// ValidateConfig must name the form, not generic "no usable prefix".
			named := false
			for _, w := range ValidateConfig(cfg) {
				if strings.Contains(w, r.form) {
					named = true
				}
			}
			if !named {
				t.Errorf("ValidateConfig must name %s; got %v", r.form, ValidateConfig(cfg))
			}
		})
	}
	// Flat sole forms.
	for _, r := range []struct {
		name, line, form string
	}{
		{"sole future form flat", "set security address-book global address partner-api future-address-form value", "future-address-form"},
		{"unused", "", ""},
	} {
		if r.line == "" {
			continue
		}
		t.Run(r.name, func(t *testing.T) {
			tree := buildTree(t, []string{"set security zones security-zone trust", r.line})
			_, err := CompileConfig(tree)
			if err == nil || !strings.Contains(err.Error(), r.form) {
				t.Fatalf("#15673: strict must reject sole flat %s, got %v", r.form, err)
			}
		})
	}
}

// range-address expands natively to its minimal CIDR cover and is usable
// (#16563: no host-count cap for address-book entries; NAT pools keep the
// per-host 256 cap on expandAddressRange).
func TestRangeAddressExpands15673(t *testing.T) {
	for _, tc := range []struct {
		name string
		tree func(t *testing.T) *ConfigTree
		want []string
	}{
		{"hier", func(t *testing.T) *ConfigTree {
			return soleFormTree(t, `address rng { range-address 192.0.2.1 { to { 192.0.2.3; } } }`)
		}, []string{"192.0.2.1/32", "192.0.2.2/31"}},
		{"flat", func(t *testing.T) *ConfigTree {
			return buildTree(t, []string{
				"set security zones security-zone trust",
				"set security address-book global address rng range-address 192.0.2.1 to 192.0.2.3",
			})
		}, []string{"192.0.2.1/32", "192.0.2.2/31"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(tc.tree(t))
			if err != nil {
				t.Fatalf("#15673: valid range-address must commit: %v", err)
			}
			a := cfg.Security.AddressBook.Addresses["rng"]
			if a == nil {
				t.Fatal("rng missing")
			}
			if got := a.UsableValues(); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("UsableValues = %v, want %v (a=%+v)", got, tc.want, a)
			}
			if a.UsableValue() == "" {
				t.Errorf("range entry must be usable, got Value=%q forms=%v", a.Value, a.UnimplementedForms)
			}
		})
	}
	// Invalid range: strict rejects, lenient boots unusable.
	t.Run("invalid", func(t *testing.T) {
		tree := func() *ConfigTree {
			return buildTree(t, []string{
				"set security zones security-zone trust",
				"set security address-book global address bad range-address 10.0.1.0 to 10.0.0.0",
			})
		}
		if _, err := CompileConfig(tree()); err == nil {
			t.Fatal("reversed range-address must reject at strict commit")
		}
		cfg, err := CompileConfigLenient(tree())
		if err != nil {
			t.Fatalf("lenient must boot: %v", err)
		}
		if a := cfg.Security.AddressBook.Addresses["bad"]; a == nil || a.UsableValue() != "" || len(a.UsableValues()) != 0 {
			t.Fatalf("invalid lenient entry must be unusable, got %+v", a)
		}
	})
}

// #16563: address-book range-address commits at any host count via a
// minimal CIDR cover — the cases PROBE pinned (512 and 1026 hosts, and
// the IPv6 analogue) — and matches exactly [low, high]: every address
// inside is covered, both neighbours outside are not, and the cover is
// pairwise disjoint. A 256-host range yields at most 16 prefixes.
func TestRangeAddressCIDRCover16563(t *testing.T) {
	cases := []struct {
		name, low, high string
		want            []string
		maxPrefixes     int
	}{
		{"v4-512-aligned", "10.0.0.0", "10.0.1.255", []string{"10.0.0.0/23"}, 16},
		{"v4-1026-unaligned", "10.0.0.1", "10.0.4.2", []string{
			"10.0.0.1/32", "10.0.0.2/31", "10.0.0.4/30", "10.0.0.8/29",
			"10.0.0.16/28", "10.0.0.32/27", "10.0.0.64/26", "10.0.0.128/25",
			"10.0.1.0/24", "10.0.2.0/23", "10.0.4.0/31", "10.0.4.2/32",
		}, 16},
		{"v4-256-bound", "10.0.0.1", "10.0.1.0", nil, 16},
		{"v4-single", "192.0.2.7", "192.0.2.7", []string{"192.0.2.7/32"}, 16},
		{"v4-full", "0.0.0.0", "255.255.255.255", []string{"0.0.0.0/0"}, 16},
		{"v6-257", "2001:db8::", "2001:db8::100", []string{"2001:db8::/120", "2001:db8::100/128"}, 16},
		{"v6 hi-aligned", "2001:db8::1", "2001:db8::ffff", []string{
			"2001:db8::1/128", "2001:db8::2/127", "2001:db8::4/126",
			"2001:db8::8/125", "2001:db8::10/124", "2001:db8::20/123",
			"2001:db8::40/122", "2001:db8::80/121", "2001:db8::100/120",
			"2001:db8::200/119", "2001:db8::400/118", "2001:db8::800/117",
			"2001:db8::1000/116", "2001:db8::2000/115", "2001:db8::4000/114",
			"2001:db8::8000/113",
		}, 32},
		{"v6 spanning", "2001:db8::1", "2001:db8::1:0", []string{
			"2001:db8::1/128", "2001:db8::2/127", "2001:db8::4/126",
			"2001:db8::8/125", "2001:db8::10/124", "2001:db8::20/123",
			"2001:db8::40/122", "2001:db8::80/121", "2001:db8::100/120",
			"2001:db8::200/119", "2001:db8::400/118", "2001:db8::800/117",
			"2001:db8::1000/116", "2001:db8::2000/115", "2001:db8::4000/114",
			"2001:db8::8000/113", "2001:db8::1:0/128",
		}, 32},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTree(t, []string{
				"set security zones security-zone trust",
				"set security address-book global address rng range-address " + tc.low + " to " + tc.high,
			})
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("#16563: range %s to %s must commit: %v", tc.low, tc.high, err)
			}
			a := cfg.Security.AddressBook.Addresses["rng"]
			if a == nil {
				t.Fatal("rng missing")
			}
			if a.OversizedRange != "" {
				t.Fatalf("OversizedRange must be empty for a valid range, got %q", a.OversizedRange)
			}
			got := a.UsableValues()
			if tc.want != nil && !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("cover = %v, want %v", got, tc.want)
			}
			if len(got) > tc.maxPrefixes {
				t.Fatalf("cover has %d prefixes, want at most %d: %v", len(got), tc.maxPrefixes, got)
			}
			assertCoverExact16563(t, got, tc.low, tc.high)
		})
	}
	// Direct cover-expander error shapes mirror the per-host expander.
	for _, tc := range [][2]string{
		{"10.0.0.10", "10.0.0.1"},
		{"10.0.0.1", "2001:db8::1"},
		{"10.0.0.1/24", "10.0.0.9"},
		{"bogus", "10.0.0.9"},
	} {
		if _, err := expandAddressRangeToCIDRCover(tc[0], tc[1]); err == nil {
			t.Errorf("cover(%q,%q) must error", tc[0], tc[1])
		}
	}
	if got, err := expandAddressRangeToCIDRCover("10.0.0.1/32", "10.0.0.1"); err != nil || !reflect.DeepEqual(got, []string{"10.0.0.1/32"}) {
		t.Errorf("host-prefix endpoints: got %v err %v", got, err)
	}
}

// wildcard-address expands to the wildcard-matched prefix (Junos polarity
// #16544: mask 1 bits are compared, 0 bits are ignored).
func TestWildcardAddressExpands15673(t *testing.T) {
	for _, tc := range []struct{ spec, want string }{
		{"10.1.2.3/255.255.255.0", "10.1.2.0/24"},
		{"10.1.2.3/255.255.255.255", "10.1.2.3/32"},
		{"10.1.2.3/255.0.0.0", "10.0.0.0/8"},
		{"192.168.0.11/255.255.0.0", "192.168.0.0/16"},
		{"10.1.2.3/0.0.0.0", "0.0.0.0/0"},
		{"2001:db8::1/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "2001:db8::1/128"},
		{"2001:db8:1:2::3/ffff:ffff:ffff:ffff:0000:0000:0000:0000", "2001:db8:1:2::/64"},
	} {
		cfg, err := CompileConfig(soleFormTree(t, `address wc { wildcard-address `+tc.spec+`; }`))
		if err != nil {
			t.Fatalf("wildcard-address %s must commit: %v", tc.spec, err)
		}
		a := cfg.Security.AddressBook.Addresses["wc"]
		if a == nil || !reflect.DeepEqual(a.UsableValues(), []string{tc.want}) {
			t.Fatalf("wildcard %s must expand to %s, got %+v", tc.spec, tc.want, a)
		}
	}
	// Flat form (Junos polarity).
	cfg2, err := CompileConfig(buildTree(t, []string{
		"set security zones security-zone trust",
		"set security address-book global address wc wildcard-address 10.1.2.3/255.255.255.0",
	}))
	if err != nil {
		t.Fatalf("flat wildcard must commit: %v", err)
	}
	if a := cfg2.Security.AddressBook.Addresses["wc"]; a == nil || !reflect.DeepEqual(a.UsableValues(), []string{"10.1.2.0/24"}) {
		t.Fatalf("flat wildcard wrong: %+v", a)
	}
	// Direct expander: Cisco-polarity and non-contiguous Junos masks never
	// yield the inverted set; the Juniper doc example is non-contiguous and
	// must be refused (no single CIDR), not silently widened/narrowed.
	for _, spec := range []string{
		"10.1.2.3/0.0.0.255",
		"192.168.0.11/255.255.0.255",
		"10.1.2.3/255.255.0.255",
		"2001:db8::1/ffff:ffff:0000:ffff:ffff:ffff:ffff:ffff",
		"10.1.2.3/255.255.255.0/extra",
	} {
		got, err := expandWildcardAddress(spec)
		if err == nil {
			t.Errorf("expandWildcardAddress(%q) = %q, want non-contiguous refusal", spec, got)
		} else if !strings.Contains(err.Error(), "non-contiguous") && !strings.Contains(err.Error(), "invalid") {
			t.Errorf("expandWildcardAddress(%q) error %q must name non-contiguous/invalid", spec, err)
		}
		if got == "10.1.2.0/24" || got == "0.0.0.0/0" {
			t.Errorf("expandWildcardAddress(%q) yielded forbidden %q", spec, got)
		}
	}
}

// dns-name is modelled: strict commits, entry carries DNSName, and a resolver
// seam produces usable prefixes (via test resolver, no network).
func TestDNSNameModelled15673(t *testing.T) {
	orig := lookupAddressDNSName
	defer func() { lookupAddressDNSName = orig }()
	lookupAddressDNSName = func(fqdn string) ([]string, error) {
		if fqdn != "api.example.com" {
			return nil, nil
		}
		return []string{"203.0.113.10", "2001:db8::10"}, nil
	}
	cfg, err := CompileConfig(soleFormTree(t, `address partner-api { dns-name api.example.com; }`))
	if err != nil {
		t.Fatalf("dns-name must commit as modelled form: %v", err)
	}
	a := cfg.Security.AddressBook.Addresses["partner-api"]
	if a == nil || a.DNSName != "api.example.com" {
		t.Fatalf("DNSName not modelled: %+v", a)
	}
	// #16601: compile does no network I/O, so the fresh entry is
	// fail-closed empty until an off-lock RefreshDNSAddressBooks.
	if got := a.UsableValues(); len(got) != 0 {
		t.Fatalf("compile must not resolve; got %v before refresh", got)
	}
	RefreshDNSAddressBooks(cfg)
	a = cfg.Security.AddressBook.Addresses["partner-api"]
	want := []string{"2001:db8::10/128", "203.0.113.10/32"}
	if got := a.UsableValues(); !reflect.DeepEqual(got, want) {
		t.Fatalf("dns UsableValues = %v, want %v", got, want)
	}
	// ipv4-only filters v6 (cache now holds the refreshed answer above;
	// the family filter is applied per-entry at populate time).
	cfg4, err := CompileConfig(soleFormTree(t, `address partner-api { dns-name api.example.com { ipv4-only; } }`))
	if err != nil {
		t.Fatalf("ipv4-only must commit: %v", err)
	}
	RefreshDNSAddressBooks(cfg4)
	a4 := cfg4.Security.AddressBook.Addresses["partner-api"]
	if a4 == nil || a4.DNSFamily != "ipv4-only" {
		t.Fatalf("DNSFamily not modelled: %+v", a4)
	}
	if got := a4.UsableValues(); !reflect.DeepEqual(got, []string{"203.0.113.10/32"}) {
		t.Fatalf("ipv4-only UsableValues = %v", got)
	}
	// ipv6-only filters v4 (flat).
	cfg6, err := CompileConfig(buildTree(t, []string{
		"set security zones security-zone trust",
		"set security address-book global address partner-api dns-name api.example.com ipv6-only",
	}))
	if err != nil {
		t.Fatalf("flat ipv6-only must commit: %v", err)
	}
	RefreshDNSAddressBooks(cfg6)
	a6 := cfg6.Security.AddressBook.Addresses["partner-api"]
	if a6 == nil || a6.DNSFamily != "ipv6-only" || !reflect.DeepEqual(a6.UsableValues(), []string{"2001:db8::10/128"}) {
		t.Fatalf("ipv6-only flat wrong: %+v values=%v", a6, a6.UsableValues())
	}
	// Unresolvable DNS: usable empty (fail-closed), not an error.
	lookupAddressDNSName = func(string) ([]string, error) { return nil, nil }
	cfgU, err := CompileConfig(soleFormTree(t, `address partner-api { dns-name never.example.com; }`))
	if err != nil {
		t.Fatalf("unresolvable dns-name must still commit (dynamic): %v", err)
	}
	RefreshDNSAddressBooks(cfgU)
	if a := cfgU.Security.AddressBook.Addresses["partner-api"]; a == nil || len(a.UsableValues()) != 0 {
		t.Fatalf("unresolvable dns must be match-none, got %+v", a)
	}
}

// mergeAddressNode: described address node must still inspect children —
// a prefix child under/behind description must not be dropped, and a form
// child after description must be classified.
func TestDescribedAddressKeepsSubStanzas15673(t *testing.T) {
	// Hierarchical: description first, then prefix, then dns-name sibling
	// definitions merged by name.
	cfg, err := CompileConfigLenient(soleFormTree(t, `address mixed { description "web"; 10.10.0.0/24; }`))
	if err != nil {
		t.Fatal(err)
	}
	a := cfg.Security.AddressBook.Addresses["mixed"]
	if a == nil || a.Value != "10.10.0.0/24" || a.Description != "web" {
		t.Fatalf("described hier address lost prefix/desc: %+v", a)
	}
	// Flat: description node carrying a nested form child (legacy split shape
	// is exercised via hierarchical dns-name after description block).
	tree := soleFormTree(t, `address mixed { description "web"; dns-name evil.example; 10.10.0.0/24; }`)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("prefix+dns-name after description must still reject at strict (form not dropped)")
	}
}

// parseAddressBookEntries: hierarchical leaf entries inside an unknown book
// stanza must populate Names and quarantine collisions.
func TestUnknownBookLeafNamesQuarantined15673(t *testing.T) {
	tree := parseHierText(t, `security { address-book { global { address good 10.0.0.1/32; bogus-book { address leafname 10.9.9.9/32; } } } zones { security-zone trust; } }`)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatal(err)
	}
	ab := cfg.Security.AddressBook
	found := false
	for _, e := range ab.UnknownBookEntries {
		for _, n := range e.Names {
			if n == "leafname" {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("leaf name inside unknown stanza not recorded: %+v", ab.UnknownBookEntries)
	}
	if _, ok := ab.CollidingNames["leafname"]; !ok {
		t.Fatalf("leafname not quarantined in CollidingNames: %v", ab.CollidingNames)
	}
	_ = reflect.DeepEqual
}
