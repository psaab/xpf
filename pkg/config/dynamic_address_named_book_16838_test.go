package config

import (
	"strings"
	"testing"
)

// #16838: the #15685 dynamic-address/static name-collision gate walked only
// the global and zone-local books. A `security address-book <book>` entry
// (#15672) sharing a binding's name therefore committed strict-clean, was
// folded into its attached zone as zone-local/<zone>/<name>, and then hit
// the same declared-binding-first userspace lowering refusal as a direct
// zone-local collision: while the feed was unready the whole policy
// snapshot publication was refused (previous-good retained, or default-deny
// on a fresh boot), and once ready the name enforced feed ∪ static.
//
// These tests pin the fix: validateDynamicAddressStaticCollisionStrict also
// walks the pristine NamedAddressBooks (attached or not), naming the book,
// and the sibling pristine gates keep walking all three book kinds.
//
// RED-on-revert: removing the NamedAddressBooks loop from
// validateDynamicAddressStaticCollisionStrict makes the attached,
// unattached, address-set, and lenient subtests accept/warn-miss the
// shadowing pair; the census subtests fail if any listed pristine gate
// stops walking a book kind.

func feedBindingLines16838() []string {
	return []string{
		"set security dynamic-address feed-server threat url https://feeds.example/list.txt",
		"set security dynamic-address feed-server threat feed-name malware path /malware.txt",
		"set security dynamic-address address-name blocked profile feed-name malware",
	}
}

func TestDynamicAddressNamedBookCollision16838(t *testing.T) {
	t.Run("commit rejects binding colliding with attached named-book address", func(t *testing.T) {
		lines := append(feedBindingLines16838(),
			"set security zones security-zone trust interfaces eth0",
			"set security address-book eng-book address blocked 10.0.0.0/24",
			"set security address-book eng-book attach zone trust",
		)
		_, err := CompileConfig(buildTree3300(t, lines))
		if err == nil {
			t.Fatal("CompileConfig should reject dynamic address-name colliding with an attached named-book address")
		}
		if !strings.Contains(err.Error(), `"blocked"`) || !strings.Contains(err.Error(), "collides") ||
			!strings.Contains(err.Error(), `"eng-book"`) {
			t.Fatalf("error should name the binding, the collision, and the named book, got: %v", err)
		}
	})

	t.Run("commit rejects binding colliding with attached named-book address-set", func(t *testing.T) {
		lines := append(feedBindingLines16838(),
			"set security zones security-zone trust interfaces eth0",
			"set security address-book eng-book address inner 10.0.0.1/32",
			"set security address-book eng-book address-set blocked address inner",
			"set security address-book eng-book attach zone trust",
		)
		_, err := CompileConfig(buildTree3300(t, lines))
		if err == nil {
			t.Fatal("CompileConfig should reject dynamic address-name colliding with an attached named-book address-set")
		}
		if !strings.Contains(err.Error(), `"blocked"`) || !strings.Contains(err.Error(), `"eng-book"`) ||
			!strings.Contains(err.Error(), "address-set") {
			t.Fatalf("error should name the binding, the named book, and the address-set kind, got: %v", err)
		}
	})

	t.Run("commit rejects binding colliding with unattached named-book address", func(t *testing.T) {
		// The pristine gates walk named books attached or not (same
		// convention as the #5676/#10688/#14967 gates): an unattached
		// book can be attached later without re-authoring its entries,
		// and Junos forbids the name ambiguity in the book itself.
		lines := append(feedBindingLines16838(),
			"set security address-book eng-book address blocked 10.0.0.0/24",
		)
		_, err := CompileConfig(buildTree3300(t, lines))
		if err == nil {
			t.Fatal("CompileConfig should reject dynamic address-name colliding with an unattached named-book address")
		}
		if !strings.Contains(err.Error(), `"blocked"`) || !strings.Contains(err.Error(), `"eng-book"`) {
			t.Fatalf("error should name the binding and the named book, got: %v", err)
		}
	})

	t.Run("lenient load downgrades named-book collision to warning", func(t *testing.T) {
		lines := append(feedBindingLines16838(),
			"set security zones security-zone trust interfaces eth0",
			"set security address-book eng-book address blocked 10.0.0.0/24",
			"set security address-book eng-book attach zone trust",
		)
		cfg, err := CompileConfigLenient(buildTree3300(t, lines))
		if err != nil {
			t.Fatalf("lenient compile should not brick on a named-book collision, got: %v", err)
		}
		var collisionWarn bool
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "collides") && strings.Contains(w, `"eng-book"`) {
				collisionWarn = true
			}
		}
		if !collisionWarn {
			t.Fatalf("lenient compile should warn about the named-book collision, warnings=%v", cfg.Warnings)
		}
		if cfg.Security.DynamicAddress.AddressBindings["blocked"] == nil {
			t.Fatal("lenient load must retain the colliding binding, not drop it silently")
		}
	})

	t.Run("control global book collision still rejected", func(t *testing.T) {
		lines := append(feedBindingLines16838(),
			"set security address-book global address blocked 10.0.0.0/24",
		)
		_, err := CompileConfig(buildTree3300(t, lines))
		if err == nil || !strings.Contains(err.Error(), `"blocked"`) ||
			!strings.Contains(err.Error(), "global") {
			t.Fatalf("global control must still reject, got: %v", err)
		}
	})

	t.Run("control zone-local collision still rejected", func(t *testing.T) {
		lines := append(feedBindingLines16838(),
			"set security zones security-zone trust interfaces eth0",
			"set security zones security-zone trust address-book address blocked 10.0.0.0/24",
		)
		_, err := CompileConfig(buildTree3300(t, lines))
		if err == nil || !strings.Contains(err.Error(), `"blocked"`) ||
			!strings.Contains(err.Error(), `"trust"`) {
			t.Fatalf("zone-local control must still reject, got: %v", err)
		}
	})

	t.Run("distinct named-book names still compile", func(t *testing.T) {
		lines := append(feedBindingLines16838(),
			"set security zones security-zone trust",
			"set security address-book eng-book address good-host 10.0.0.0/24",
			"set security address-book eng-book attach zone trust",
		)
		if _, err := CompileConfig(buildTree3300(t, lines)); err != nil {
			t.Fatalf("distinct dynamic/static names must compile clean, got: %v", err)
		}
	})

	t.Run("direct validator names the named book deterministically", func(t *testing.T) {
		cfg := &Config{}
		cfg.Security.DynamicAddress.AddressBindings = map[string]*AddressBinding{
			"blocked": {Name: "blocked", FeedNames: []string{"malware"}},
		}
		cfg.Security.NamedAddressBooks = map[string]*NamedAddressBook{
			"eng-book": {Name: "eng-book", AddressBook: AddressBook{
				Addresses: map[string]*Address{"blocked": {Name: "blocked", Value: "10.0.0.0/24"}},
			}},
		}
		err := validateDynamicAddressStaticCollisionStrict(cfg)
		if err == nil || !strings.Contains(err.Error(), `"blocked"`) ||
			!strings.Contains(err.Error(), `"eng-book"`) {
			t.Fatalf("validator should report the named-book collision, got: %v", err)
		}
		// Nil named-book values must not panic (hand-built configs).
		cfg.Security.NamedAddressBooks["eng-book"] = nil
		cfg.Security.NamedAddressBooks["other-book"] = &NamedAddressBook{Name: "other-book", AddressBook: AddressBook{
			Addresses: map[string]*Address{"blocked": {Name: "blocked", Value: "10.0.0.0/24"}},
		}}
		if err := validateDynamicAddressStaticCollisionStrict(cfg); err == nil ||
			!strings.Contains(err.Error(), `"other-book"`) {
			t.Fatalf("validator should skip nil books and report other-book, got: %v", err)
		}
	})
}

// TestPristineAddressBookGatesWalkAllBookKinds16838 is the cross-gate census
// required by #16838: every pristine gate in runEarlyStrictAndFolds that
// validates address-book entries must walk all three book kinds (global,
// named, zone-local), so a future gate (or a refactor dropping a walk)
// cannot silently re-open the named-book hole for one defect class.
//
// Each row is behaviour, not source text: the same defect is planted in
// each book kind in turn and the gate must reject it strict and warn
// lenient in every kind. A gate that stops walking a kind fails that row.
//
// Scope note: validateReservedZoneLocalRefTokensStrict walks books only
// for address-set MEMBER tokens (its surface is authored references, not
// entry definitions), so its book-kind coverage is pinned by
// TestReservedZoneLocalRefCensus16838 below rather than an entry row here.
func TestPristineAddressBookGatesWalkAllBookKinds16838(t *testing.T) {
	// plantFor rewrites the canonical global-book defect lines for a kind:
	// global lines are authored verbatim; named lines swap the
	// `address-book global` prefix for `address-book eng-book`; zone-local
	// lines swap it for the zone book prefix.
	plantFor := func(kind string, globalLines []string) []string {
		switch kind {
		case "global":
			return globalLines
		case "named-attached", "named-unattached":
			out := make([]string, 0, len(globalLines)+2)
			for _, l := range globalLines {
				out = append(out, strings.Replace(l,
					"set security address-book global ",
					"set security address-book eng-book ", 1))
			}
			if kind == "named-attached" {
				out = append([]string{"set security zones security-zone trust interfaces eth0"}, out...)
				out = append(out, "set security address-book eng-book attach zone trust")
			}
			return out
		case "zone-local":
			out := []string{"set security zones security-zone trust interfaces eth0"}
			for _, l := range globalLines {
				out = append(out, strings.Replace(l,
					"set security address-book global ",
					"set security zones security-zone trust address-book ", 1))
			}
			return out
		default:
			panic(kind)
		}
	}

	rows := []struct {
		gate string
		// defect authored in the GLOBAL book; plantFor relocates it.
		defect []string
		// extra lines needed in every kind (e.g. the dynamic binding).
		extra []string
	}{
		{
			gate: "entry-names zone-local prefix (#3061)",
			defect: []string{
				"set security address-book global address zone-local/trust/web 10.0.0.0/24",
			},
		},
		{
			gate: "address+address-set same-name collision (#5676)",
			defect: []string{
				"set security address-book global address dup 10.0.0.0/24",
				"set security address-book global address inner 10.0.0.1/32",
				"set security address-book global address-set dup address inner",
			},
		},
		{
			gate: "reserved wildcard name (#9523)",
			defect: []string{
				"set security address-book global address any 10.0.0.0/24",
			},
		},
		{
			gate: "dynamic-address/static collision (#15685/#16838)",
			defect: []string{
				"set security address-book global address blocked 10.0.0.0/24",
			},
			extra: feedBindingLines16838(),
		},
		{
			gate: "IPv4-mapped IPv6 prefix (#10688)",
			defect: []string{
				"set security address-book global address mapped-v4 ::ffff:10.0.0.0/104",
			},
		},
		{
			gate: "helper-refused CIDR mask spelling (#12047)",
			defect: []string{
				"set security address-book global address padded 10.0.0.0/008",
			},
		},
		{
			gate: "duplicate distinct prefixes (#14967)",
			defect: []string{
				"set security address-book global address dup 10.0.0.0/24",
				"set security address-book global address dup 10.1.0.0/24",
			},
		},
	}

	for _, row := range rows {
		for _, kind := range []string{"global", "named-attached", "named-unattached", "zone-local"} {
			lines := append(append([]string{}, row.extra...), plantFor(kind, row.defect)...)
			t.Run(row.gate+"/"+kind+"/strict", func(t *testing.T) {
				if _, err := CompileConfig(buildTree3300(t, lines)); err == nil {
					t.Fatalf("gate %s must reject the defect in the %s book", row.gate, kind)
				}
			})
			t.Run(row.gate+"/"+kind+"/lenient-warns", func(t *testing.T) {
				cfg, err := CompileConfigLenient(buildTree3300(t, lines))
				if err != nil {
					t.Fatalf("gate %s lenient load must boot for the %s book: %v", row.gate, kind, err)
				}
				if len(cfg.Warnings) == 0 {
					t.Fatalf("gate %s lenient load must warn for the defect in the %s book", row.gate, kind)
				}
			})
		}
	}
}

// TestReservedZoneLocalRefCensus16838 pins the one pristine gate whose
// book walk is over address-set members rather than entry definitions:
// a reserved zone-local/ member token must be rejected in every book kind.
func TestReservedZoneLocalRefCensus16838(t *testing.T) {
	defectGlobal := []string{
		"set security address-book global address inner 10.0.0.1/32",
		"set security address-book global address-set grp address zone-local/trust/web",
	}
	relocate := func(kind string, globalLines []string) []string {
		switch kind {
		case "global":
			return globalLines
		case "named":
			out := make([]string, 0, len(globalLines)+2)
			for _, l := range globalLines {
				out = append(out, strings.Replace(l,
					"set security address-book global ",
					"set security address-book eng-book ", 1))
			}
			out = append([]string{"set security zones security-zone trust interfaces eth0"}, out...)
			out = append(out, "set security address-book eng-book attach zone trust")
			return out
		case "zone-local":
			out := []string{"set security zones security-zone trust interfaces eth0"}
			for _, l := range globalLines {
				out = append(out, strings.Replace(l,
					"set security address-book global ",
					"set security zones security-zone trust address-book ", 1))
			}
			return out
		default:
			panic(kind)
		}
	}
	for _, kind := range []string{"global", "named", "zone-local"} {
		lines := relocate(kind, defectGlobal)
		t.Run(kind, func(t *testing.T) {
			if _, err := CompileConfig(buildTree3300(t, lines)); err == nil ||
				!strings.Contains(err.Error(), "zone-local/") {
				t.Fatalf("reserved-member gate must reject in the %s book, got: %v", kind, err)
			}
			cfg, err := CompileConfigLenient(buildTree3300(t, lines))
			if err != nil {
				t.Fatalf("lenient load must boot for %s book: %v", kind, err)
			}
			if len(cfg.Warnings) == 0 {
				t.Fatalf("lenient load must warn for reserved member in the %s book", kind)
			}
		})
	}
}
