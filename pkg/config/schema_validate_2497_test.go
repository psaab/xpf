package config_test

// Regression tests for #2497: five router-advertisement config leaves were
// accepted untyped at commit and then silently skipped or mis-advertised by
// the RA sender (pkg/ra/sender.go buildRA) at runtime. #2008 typed only the
// integer interval/lifetime leaves; these string/identity leaves were left
// untyped. Each "RejectsBad" case FAILS to error before the fix (the gate
// has no validator) and errors after it; each "AcceptsValid" case guards
// the spellings the compiler already accepts against a false-reject.
//
// Items covered (issue findings a-e):
//   - (a) prefix             -> ValidateIPv6CIDR keyValidator
//   - (b) nat-prefix/        -> ValidatePREF64CIDR keyValidator
//         nat64prefix           (+ RFC 8781 length set, + lifetime integer)
//   - (c) preference         -> ValidateEnum(high|medium|low)
//   - (d) dns-server-address -> ValidateIPv6Address (IPv6 literal only)
//   - (e) link-mtu           -> ValidateIntegerMin(1280) (RFC 8200 §5)

import (
	"strings"
	"testing"
)

// --- (a) prefix: must be a valid IPv6 CIDR ------------------------------

func TestSchema2497_RAPrefix_RejectsBad(t *testing.T) {
	err := schemaCheck(t, `protocols {
    router-advertisement {
        interface ge-0-0-0 {
            prefix 2001:db8::garbage/64;
        }
    }
}`)
	if err == nil {
		t.Fatal("expected error for malformed RA prefix, got nil")
	}
	if !strings.Contains(err.Error(), "prefix") {
		t.Fatalf("error should reference prefix: %v", err)
	}
}

// A bare IP without a prefix length must be rejected: the RA sender uses
// netip.ParsePrefix and skips the prefix entirely on error.
func TestSchema2497_RAPrefix_RejectsMissingLength(t *testing.T) {
	err := schemaCheck(t, `protocols {
    router-advertisement {
        interface ge-0-0-0 {
            prefix 2001:db8::1;
        }
    }
}`)
	if err == nil {
		t.Fatal("expected error for RA prefix without /prefix-length, got nil")
	}
}

// An IPv4 CIDR under prefix must be rejected (RA PIO is IPv6-only).
func TestSchema2497_RAPrefix_RejectsIPv4(t *testing.T) {
	err := schemaCheck(t, `protocols {
    router-advertisement {
        interface ge-0-0-0 {
            prefix 192.0.2.0/24;
        }
    }
}`)
	if err == nil {
		t.Fatal("expected error for IPv4 RA prefix, got nil")
	}
}

func TestSchema2497_RAPrefix_AcceptsValid(t *testing.T) {
	if err := schemaCheck(t, `protocols {
    router-advertisement {
        interface ge-0-0-0 {
            prefix 2001:db8:abcd::/64 {
                autonomous;
                on-link;
            }
        }
    }
}`); err != nil {
		t.Fatalf("unexpected error for valid RA prefix: %v", err)
	}
}

// --- (b) nat-prefix / nat64prefix: PREF64-legal IPv6 CIDR ---------------

func TestSchema2497_RANAT64Prefix_RejectsBad(t *testing.T) {
	for _, leaf := range []string{"nat-prefix", "nat64prefix"} {
		err := schemaCheck(t, `protocols {
    router-advertisement {
        interface ge-0-0-0 {
            `+leaf+` not-a-prefix;
        }
    }
}`)
		if err == nil {
			t.Fatalf("expected error for %s not-a-prefix, got nil", leaf)
		}
	}
}

// RFC 8781 §4 permits only /32 /40 /48 /56 /64 /96. A syntactically valid
// IPv6 CIDR with an out-of-set length parses cleanly in netip.ParsePrefix
// today and is then mis-encoded / omitted; the gate must reject it.
func TestSchema2497_RANAT64Prefix_RejectsBadLength(t *testing.T) {
	for _, leaf := range []string{"nat-prefix", "nat64prefix"} {
		err := schemaCheck(t, `protocols {
    router-advertisement {
        interface ge-0-0-0 {
            `+leaf+` 64:ff9b::/60;
        }
    }
}`)
		if err == nil {
			t.Fatalf("expected error for %s /60 (not in RFC 8781 set), got nil", leaf)
		}
		if !strings.Contains(err.Error(), "8781") && !strings.Contains(err.Error(), "/60") {
			t.Fatalf("error should reference the PREF64 length rule: %v", err)
		}
	}
}

// The lifetime child was an Atoi-on-error-zero leaf; garbage must now fail.
func TestSchema2497_RANAT64PrefixLifetime_RejectsBad(t *testing.T) {
	err := schemaCheck(t, `protocols {
    router-advertisement {
        interface ge-0-0-0 {
            nat64prefix 64:ff9b::/96 {
                lifetime abc;
            }
        }
    }
}`)
	if err == nil {
		t.Fatal("expected error for nat64prefix lifetime abc, got nil")
	}
	if !strings.Contains(err.Error(), "lifetime") {
		t.Fatalf("error should reference lifetime: %v", err)
	}
}

func TestSchema2497_RANAT64Prefix_AcceptsValid(t *testing.T) {
	for _, leaf := range []string{"nat-prefix", "nat64prefix"} {
		for _, length := range []string{"32", "40", "48", "56", "64", "96"} {
			cfg := `protocols {
    router-advertisement {
        interface ge-0-0-0 {
            ` + leaf + ` 64:ff9b::/` + length + ` {
                lifetime 1800;
            }
        }
    }
}`
			if err := schemaCheck(t, cfg); err != nil {
				t.Fatalf("unexpected error for %s /%s: %v", leaf, length, err)
			}
		}
	}
}

// --- (c) preference: enum high|medium|low -------------------------------

func TestSchema2497_RAPreference_RejectsBad(t *testing.T) {
	err := schemaCheck(t, `protocols {
    router-advertisement {
        interface ge-0-0-0 {
            preference mdeium;
        }
    }
}`)
	if err == nil {
		t.Fatal("expected error for preference mdeium, got nil")
	}
	if !strings.Contains(err.Error(), "mdeium") {
		t.Fatalf("error should quote the bad preference: %v", err)
	}
}

func TestSchema2497_RAPreference_AcceptsValid(t *testing.T) {
	for _, p := range []string{"high", "medium", "low"} {
		if err := schemaCheck(t, `protocols {
    router-advertisement {
        interface ge-0-0-0 {
            preference `+p+`;
        }
    }
}`); err != nil {
			t.Fatalf("unexpected error for preference %s: %v", p, err)
		}
	}
}

// --- (d) dns-server-address: IPv6 literal only --------------------------

// A valid IPv4 literal parses in netip.ParseAddr and was appended to the
// IPv6-only RDNSS option on the wire — worse than a skip. The gate must
// reject it.
func TestSchema2497_RADNSServer_RejectsIPv4(t *testing.T) {
	err := schemaCheck(t, `protocols {
    router-advertisement {
        interface ge-0-0-0 {
            dns-server-address 8.8.8.8;
        }
    }
}`)
	if err == nil {
		t.Fatal("expected error for IPv4 RDNSS address, got nil")
	}
	if !strings.Contains(err.Error(), "8.8.8.8") {
		t.Fatalf("error should quote the bad address: %v", err)
	}
}

func TestSchema2497_RADNSServer_RejectsGarbage(t *testing.T) {
	err := schemaCheck(t, `protocols {
    router-advertisement {
        interface ge-0-0-0 {
            dns-server-address not-an-address;
        }
    }
}`)
	if err == nil {
		t.Fatal("expected error for garbage RDNSS address, got nil")
	}
}

func TestSchema2497_RADNSServer_AcceptsValid(t *testing.T) {
	if err := schemaCheck(t, `protocols {
    router-advertisement {
        interface ge-0-0-0 {
            dns-server-address 2001:db8::53;
        }
    }
}`); err != nil {
		t.Fatalf("unexpected error for valid IPv6 RDNSS address: %v", err)
	}
}

// --- (e) link-mtu: IPv6 minimum 1280 ------------------------------------

// RFC 8200 §5 requires a minimum link MTU of 1280. A smaller value was
// advertised verbatim and blackholes hosts that honor it.
func TestSchema2497_RALinkMTU_RejectsBelowMinimum(t *testing.T) {
	err := schemaCheck(t, `protocols {
    router-advertisement {
        interface ge-0-0-0 {
            link-mtu 576;
        }
    }
}`)
	if err == nil {
		t.Fatal("expected error for link-mtu 576 (below IPv6 minimum 1280), got nil")
	}
	if !strings.Contains(err.Error(), "link-mtu") {
		t.Fatalf("error should reference link-mtu: %v", err)
	}
}

func TestSchema2497_RALinkMTU_AcceptsMinimumAndAbove(t *testing.T) {
	for _, mtu := range []string{"1280", "1500", "9000", "65535"} {
		if err := schemaCheck(t, `protocols {
    router-advertisement {
        interface ge-0-0-0 {
            link-mtu `+mtu+`;
        }
    }
}`); err != nil {
			t.Fatalf("unexpected error for link-mtu %s: %v", mtu, err)
		}
	}
}

// #9914: the runtime sink uses the same uint16 ceiling as the strict schema.
// Tolerant load / peer-sync still needs the sender clamp, but a fresh commit
// must reject a value that cannot fit the owning LinkMTU contract.
func TestSchema9914_RALinkMTU_RejectsAboveUint16(t *testing.T) {
	err := schemaCheck(t, `protocols {
    router-advertisement {
        interface ge-0-0-0 {
            link-mtu 65536;
        }
    }
}`)
	if err == nil {
		t.Fatal("expected error for link-mtu 65536 (above uint16 ceiling), got nil")
	}
	if !strings.Contains(err.Error(), "link-mtu") {
		t.Fatalf("error should reference link-mtu: %v", err)
	}
}

// --- flat-set parity ----------------------------------------------------

// The #1319 gate runs against the tree expanded from set commands at commit
// time; the flat-set shape must validate identically to the hierarchical one.
func TestSchema2497_FlatSet_RAPreference_RejectsBad(t *testing.T) {
	err := flatSchemaCheck(t,
		"set protocols router-advertisement interface ge-0-0-0 preference bogus",
	)
	if err == nil {
		t.Fatal("expected error for flat-set preference bogus, got nil")
	}
	if !strings.Contains(err.Error(), "bogus") {
		t.Fatalf("error should quote the bad preference: %v", err)
	}
}

func TestSchema2497_FlatSet_RAPrefix_RejectsBad(t *testing.T) {
	err := flatSchemaCheck(t,
		"set protocols router-advertisement interface ge-0-0-0 prefix 192.0.2.0/24",
	)
	if err == nil {
		t.Fatal("expected error for flat-set IPv4 RA prefix, got nil")
	}
}

func TestSchema2497_FlatSet_RA_AcceptsValid(t *testing.T) {
	if err := flatSchemaCheck(t,
		"set protocols router-advertisement interface ge-0-0-0 prefix 2001:db8::/64 autonomous",
		"set protocols router-advertisement interface ge-0-0-0 preference high",
		"set protocols router-advertisement interface ge-0-0-0 dns-server-address 2001:db8::53",
		"set protocols router-advertisement interface ge-0-0-0 nat64prefix 64:ff9b::/96 lifetime 1800",
		"set protocols router-advertisement interface ge-0-0-0 link-mtu 1500",
	); err != nil {
		t.Fatalf("unexpected error for valid flat-set RA config: %v", err)
	}
}
