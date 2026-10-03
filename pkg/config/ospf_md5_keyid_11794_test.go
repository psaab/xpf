package config

import (
	"strings"
	"testing"
)

// #11794: the OSPF MD5 key-id is a named-instance IDENTITY token (`md5 <key-id>
// { key ...; }`), so the schema types it with keyValidator (not valueType —
// setting valueType would flip the walker into the typed-LEAF branch and
// mis-validate the container's real `key` child), the compiler's Atoi-swallow
// must not let garbage fall back to AuthKeyID 0, and the FRR renderer must
// never fabricate key-id 1 for an unset/out-of-range id nor emit an id outside
// 1..255 verbatim (one vtysh-rejected line fails the whole managed-section
// reload, #1880/#2223).
//
// Channel split (the #1319/#1960 doctrine): SchemaValidate is strict ONLY on
// the operator commit path — Store.compileTreeLenient downgrades a key-slot
// violation to a warning — so the compiler layer must ALSO gate: strict commit
// rejects, tolerant load warns and renders nothing for the bad interface (the
// #9050 omit-both posture), instead of rendering a fabricated or verbatim
// out-of-range id.

func ospfMD5KeyIDTree11794(t *testing.T, keyID string) *ConfigTree {
	t.Helper()
	return flatTreeFromSets(t,
		"set protocols ospf area 0.0.0.0 interface ge-0/0/0.0 authentication md5 "+keyID+` key "SEKRIT11794"`)
}

// The key-id slot rejects garbage, 0, negatives, and >255 at commit-check,
// in BOTH spellings (hierarchical and flat set — a gate that holds on one is
// half a gate), while the 1..255 boundaries still commit.
func TestOSPFMD5KeyIDSchemaGate11794(t *testing.T) {
	bad := []string{"banana", "0", "-5", "256", "999", "99999999999999999999"}
	for _, tok := range bad {
		t.Run("reject-"+tok, func(t *testing.T) {
			if err := SchemaValidate(ospfMD5KeyIDTree11794(t, tok), nil); err == nil {
				t.Fatalf("SchemaValidate accepted md5 key-id %q; want commit rejection", tok)
			} else if !strings.Contains(err.Error(), "md5") {
				t.Fatalf("rejection for key-id %q must name the md5 slot: %v", tok, err)
			}
			src := `protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 { authentication { md5 ` + tok + ` { key "SEKRIT11794"; } } } } } }`
			tree, perrs := NewParser(src).Parse()
			if len(perrs) > 0 {
				t.Fatalf("fixture did not parse: %v", perrs)
			}
			if err := SchemaValidate(tree, nil); err == nil {
				t.Fatalf("hierarchical: SchemaValidate accepted md5 key-id %q; want commit rejection", tok)
			} else if !strings.Contains(err.Error(), "md5") {
				t.Fatalf("hierarchical: rejection for key-id %q must name the md5 slot: %v", tok, err)
			}
		})
	}
	for _, tok := range []string{"1", "7", "255"} {
		t.Run("accept-"+tok, func(t *testing.T) {
			if err := SchemaValidate(ospfMD5KeyIDTree11794(t, tok), nil); err != nil {
				t.Fatalf("SchemaValidate rejected in-range md5 key-id %q: %v", tok, err)
			}
		})
	}
}

// The strict compile path rejects a malformed/out-of-range key-id even when
// the config bypasses SchemaValidate (the flat AST helper models that path),
// naming the interface and the invalid key-id domain. Without this, garbage
// compiled to AuthKeyID 0 (Atoi-swallow) and the renderer fabricated key 1 —
// the operator's adjacency authenticated under an ID they never wrote.
func TestOSPFMD5KeyIDStrictCompileRejects11794(t *testing.T) {
	for _, tok := range []string{"banana", "0", "-5", "999"} {
		t.Run("reject-"+tok, func(t *testing.T) {
			_, err := CompileConfig(ospfMD5KeyIDTree11794(t, tok))
			if err == nil {
				t.Fatal("CompileConfig accepted a malformed md5 key-id; want strict rejection")
			}
			if !strings.Contains(err.Error(), "ge-0/0/0.0") {
				t.Fatalf("strict error must name the interface: %v", err)
			}
			if !strings.Contains(err.Error(), "md5") && !strings.Contains(err.Error(), "key-id") {
				t.Fatalf("strict error must name the md5 key-id slot: %v", err)
			}
		})
	}
}

// Control: in-range key-ids still compile AND bind (the compiled AuthKeyID is
// the configured value, not a fallback).
func TestOSPFMD5KeyIDValidBinds11794(t *testing.T) {
	for _, tc := range []struct {
		tok  string
		want int
	}{{"1", 1}, {"7", 7}, {"255", 255}} {
		t.Run("key-id-"+tc.tok, func(t *testing.T) {
			cfg, err := CompileConfig(ospfMD5KeyIDTree11794(t, tc.tok))
			if err != nil {
				t.Fatalf("CompileConfig rejected in-range md5 key-id %q: %v", tc.tok, err)
			}
			iface := ospfIface6818(t, cfg, "md5 key-id "+tc.tok)
			if iface.AuthKeyID != tc.want {
				t.Fatalf("AuthKeyID = %d, want %d", iface.AuthKeyID, tc.want)
			}
		})
	}
}

// The tolerant load / peer-sync path warns (naming the interface and invalid
// key-id value) instead of hard-erroring (#1960 no-brick), and the malformed
// auth is INERT — the renderer emits no fabricated key-1 or out-of-range ID.
func TestOSPFMD5KeyIDLenientWarns11794(t *testing.T) {
	for _, tok := range []string{"banana", "999"} {
		t.Run("warn-"+tok, func(t *testing.T) {
			cfg, err := CompileConfigLenient(ospfMD5KeyIDTree11794(t, tok))
			if err != nil {
				t.Fatalf("CompileConfigLenient hard-rejected md5 key-id %q (want warn): %v", tok, err)
			}
			found := false
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "ge-0/0/0.0") && (strings.Contains(w, "md5") || strings.Contains(w, "key-id")) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("lenient compile produced no md5 key-id warning naming the interface; got %v", cfg.Warnings)
			}
		})
	}
}

// The RI copy shares the SAME md5 schema pointer as the global one (#9351), so
// a keyValidator on the global node reaches it — but this cell pins the
// routing-instances verdict directly so a future split reds loud.
func TestOSPFMD5KeyIDReachesTheRoutingInstanceCopy11794(t *testing.T) {
	src := `routing-instances { VRF-A { protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 { authentication { md5 banana { key "SEKRIT11794"; } } } } } } } }`
	tree, perrs := NewParser(src).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture did not parse: %v", perrs)
	}
	if err := SchemaValidate(tree, nil); err == nil {
		t.Fatal("SchemaValidate accepted an RI md5 key-id banana; want commit rejection")
	} else if !strings.Contains(err.Error(), "md5") {
		t.Fatalf("RI rejection must name the md5 slot: %v", err)
	}
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("CompileConfig accepted an RI md5 key-id banana; want strict rejection")
	}
}
