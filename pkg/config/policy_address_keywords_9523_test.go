package config

import (
	"strings"
	"testing"
)

// #9523 — a policy match-all address keyword is reserved out of the address
// namespaces. Channel: CompileConfig (strict; the commit gate CheckText runs)
// rejects; CompileConfigLenient (boot load, HA sync, upgrade) keeps the object
// with a warning. The keyword-before-name resolution that keeps the keyword a
// keyword on the tolerant path is asserted in pkg/dataplane/userspace and
// pkg/policymatch.

func TestIsPolicyAddressWildcardKeyword9523(t *testing.T) {
	for _, kw := range []string{"any", "any4", "any6", "any-ipv4", "any-ipv6"} {
		if !IsPolicyAddressWildcardKeyword(kw) {
			t.Errorf("%q must be a match-all keyword", kw)
		}
	}
	// The accepting rows. Name-before-literal is documented and stays in force
	// for every token that is not a keyword, including the match-all CIDRs.
	for _, tok := range []string{"", "ANY", "anyhost", "any-host", "any-ipv4-edge", "0.0.0.0/0", "::/0", "10.0.1.0/24", "company"} {
		if IsPolicyAddressWildcardKeyword(tok) {
			t.Errorf("%q is not a keyword; treating it as one would break name-before-literal", tok)
		}
	}
}

func TestReservedAddressNamesRejectedAtCommit9523(t *testing.T) {
	feed := []string{
		"set security dynamic-address feed-server threat url https://feeds.example/list.txt",
		"set security dynamic-address feed-server threat feed-name malware path /malware.txt",
	}
	type row struct {
		name     string
		lines    []string
		wantKind string
		wantName string
	}
	var rows []row
	for _, kw := range []string{"any", "any4", "any6", "any-ipv4", "any-ipv6"} {
		rows = append(rows, row{"global address " + kw,
			[]string{"set security address-book global address " + kw + " 10.99.0.0/16"},
			"security address-book global address", kw})
	}
	rows = append(rows,
		row{"global address-set any", []string{
			"set security address-book global address a1 10.99.0.0/16",
			"set security address-book global address-set any address a1",
		}, "security address-book global address-set", "any"},
		row{"zone-local address any", []string{
			"set security zones security-zone trust address-book address any 10.99.0.0/16",
		}, `security-zone "trust" address-book address`, "any"},
		row{"dynamic-address address-name any", append(append([]string{}, feed...),
			"set security dynamic-address address-name any profile feed-name malware",
		), "security dynamic-address address-name", "any"},
	)
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			lines := append([]string{"set security zones security-zone trust"}, r.lines...)
			_, err := CompileConfig(buildTree(t, lines))
			want := r.wantKind + ` "` + r.wantName + `" uses a reserved name`
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("strict commit must reject the object and name it (%q), got %v", want, err)
			}
			cfg, lerr := CompileConfigLenient(buildTree(t, lines))
			if lerr != nil {
				t.Fatalf("tolerant compile must keep the object (#1960 no-brick): %v", lerr)
			}
			warned := false
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "reserved address name") && strings.Contains(w, want) {
					warned = true
				}
			}
			if !warned {
				t.Errorf("tolerant compile did not warn; warnings=%v", cfg.Warnings)
			}
		})
	}
}

// The load-bearing half: names that merely resemble a keyword, and the
// prefix-as-name convention, must still commit. `0.0.0.0/0` is a legal Junos
// name and must stay one.
func TestReservedAddressNamesAcceptingControls9523(t *testing.T) {
	for _, name := range []string{"anyhost", "any-host", "company", "net_any", "any-ipv4-edge", "10.0.1.0/24", "0.0.0.0/0"} {
		t.Run(name, func(t *testing.T) {
			lines := []string{
				"set security zones security-zone trust",
				"set security address-book global address " + name + " 192.0.2.0/24",
			}
			if _, err := CompileConfig(buildTree(t, lines)); err != nil {
				t.Fatalf("#9523 OVER-REJECTION: a legitimate address name did not commit: %v", err)
			}
			cfg, err := CompileConfigLenient(buildTree(t, lines))
			if err != nil {
				t.Fatal(err)
			}
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "reserved address name") {
					t.Errorf("#9523 OVER-REJECTION: warned for %q: %s", name, w)
				}
			}
		})
	}
}
