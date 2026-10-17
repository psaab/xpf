package config

import (
	"strings"
	"testing"
)

// #14397 (DR9-H1): an OSPF `authentication md5 <id>` with no `key` child (or an
// empty key), and `authentication simple-password ""`, used to compile cleanly
// on the STRICT path: the compiler set AuthType with an empty secret, no
// validator rejected the keyless selection, and the FRR renderer silently
// dropped the empty keys — so ospfd ran the interface with NO authentication
// while the operator believed MD5/simple auth was on. Any LAN-adjacent peer
// could then form an adjacency and inject LSAs area-wide.
//
// Fix: validateOSPFAuthKeyPresenceStrict rejects a keyless auth selection at
// strict compile (naming area/interface), warns on the tolerant path (#1960),
// and the renderer refuses to activate a keyless-auth interface (see
// pkg/frr). Rollover mixes with at least one non-empty key stay valid, and
// keyed auth is unchanged.

func ospfKeylessTree14397(t *testing.T, variant string) *ConfigTree {
	t.Helper()
	switch variant {
	case "md5-no-key-child":
		return flatTreeFromSets(t,
			"set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 authentication md5 1")
	case "md5-empty-key":
		return flatTreeFromSets(t,
			`set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 authentication md5 1 key ""`)
	case "simple-empty-password":
		return flatTreeFromSets(t,
			`set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 authentication simple-password ""`)
	case "md5-no-key-braced":
		src := `protocols { ospf { area 0.0.0.0 { interface ge-0/0/1.0 { authentication { md5 1; } } } } }`
		tree, perrs := NewParser(src).Parse()
		if len(perrs) > 0 {
			t.Fatalf("fixture did not parse: %v", perrs)
		}
		return tree
	case "ri-md5-no-key-child":
		return flatTreeFromSets(t,
			"set routing-instances VRF-A protocols ospf area 0.0.0.0 interface ge-0/0/1.0 authentication md5 1")
	}
	t.Fatalf("unknown variant %q", variant)
	return nil
}

var ospfKeylessVariants14397 = []string{
	"md5-no-key-child",
	"md5-empty-key",
	"simple-empty-password",
	"md5-no-key-braced",
	"ri-md5-no-key-child",
}

// Strict compile must reject every keyless-auth spelling, naming the
// interface and the missing key, instead of silently rendering no auth.
func TestOSPFAuthKeyPresenceStrictRejects14397(t *testing.T) {
	for _, variant := range ospfKeylessVariants14397 {
		t.Run(variant, func(t *testing.T) {
			_, err := CompileConfig(ospfKeylessTree14397(t, variant))
			if err == nil {
				t.Fatalf("CompileConfig accepted keyless OSPF authentication (%s); want strict rejection (#14397)", variant)
			}
			if !strings.Contains(err.Error(), "ge-0/0/1.0") {
				t.Fatalf("strict error must name the interface: %v", err)
			}
			if !strings.Contains(err.Error(), "key") {
				t.Fatalf("strict error must name the missing key: %v", err)
			}
		})
	}
}

// The tolerant load / peer-sync path must still boot (#1960) but must warn,
// naming the interface, instead of silently dropping the authentication.
func TestOSPFAuthKeyPresenceLenientWarns14397(t *testing.T) {
	for _, variant := range ospfKeylessVariants14397 {
		t.Run(variant, func(t *testing.T) {
			cfg, err := CompileConfigLenient(ospfKeylessTree14397(t, variant))
			if err != nil {
				t.Fatalf("CompileConfigLenient hard-rejected keyless OSPF authentication (%s), want warn: %v", variant, err)
			}
			found := false
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "ge-0/0/1.0") && strings.Contains(w, "key") {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("lenient compile produced no keyless-auth warning naming the interface; got %v", cfg.Warnings)
			}
		})
	}
}

// Controls: keyed MD5, keyed simple, a rollover mix with one empty + one
// valid key (at-least-one-non-empty-key rule), and no authentication at all
// must all still compile strict.
func TestOSPFAuthKeyPresenceControlsCompile14397(t *testing.T) {
	cases := map[string][]string{
		"keyed-md5": {
			`set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 authentication md5 1 key "s3cret"`,
		},
		"keyed-simple": {
			`set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 authentication simple-password "s3cret"`,
		},
		"rollover-mix-one-valid": {
			`set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 authentication md5 1 key ""`,
			`set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 authentication md5 2 key "s3cret"`,
		},
		"no-authentication": {
			"set protocols ospf area 0.0.0.0 interface ge-0/0/1.0",
		},
	}
	for name, sets := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := CompileConfig(flatTreeFromSets(t, sets...)); err != nil {
				t.Fatalf("CompileConfig rejected control %s: %v", name, err)
			}
		})
	}
}
