package config

import (
	"strings"
	"testing"
)

// #15715 (V44-01): OSPF multi-key MD5 rollover validation was incomplete in
// both strict gates.
//
//   - validateFRRAuthValuesStrict checked only the scalar iface.AuthKey
//     (overwritten by the last keyPresent md5 entry), so a rollover where
//     an earlier key carries whitespace ("bad secret") and a later valid
//     key overwrites AuthKey compiled clean; the renderer then silently
//     dropped the bad key (breaking rollover adjacency) or, when the last
//     key was bad/empty, dropped keys it never validated.
//   - validateOSPFAuthKeyPresenceStrict accepted a rollover mix when ANY
//     entry was non-empty, so an empty/keyless md5 entry beside a valid
//     one compiled clean and was silently dropped at render (Case C),
//     and an empty entry was documented as a valid control (#14397
//     "at-least-one-non-empty-key rule").
//
// Fix: validateFRRAuthValuesStrict checks every AuthMD5Keys entry by
// key-id, and validateOSPFAuthKeyPresenceStrict requires every configured
// MD5 entry to be non-empty (when AuthMD5Keys is populated). The renderer
// belt (#14388/#14397) is unchanged and stays the tolerant-path backstop.
//
// RED on revert: restoring either gate's any/scalar-only logic makes the
// corresponding reject subtests compile clean (err=nil).

func TestOSPFRolloverBadKeyRejected15715(t *testing.T) {
	cases := map[string]struct {
		sets    []string
		wantSub []string
	}{
		// Case A: bad first key, valid second key (AuthKey ends valid, so
		// the scalar-only gate saw a clean secret).
		"caseA-bad-first-valid-second": {
			sets: []string{
				`set protocols ospf area 0.0.0.0 interface ge-0/0/0.0 authentication md5 1 key "bad secret"`,
				`set protocols ospf area 0.0.0.0 interface ge-0/0/0.0 authentication md5 2 key "goodsecret"`,
			},
			wantSub: []string{"ge-0/0/0.0", "md5 1 key"},
		},
		// Case B: bad first key, empty second key. AuthKey ends empty, so
		// both gates passed pre-fix; renderer dropped the whole block.
		"caseB-bad-first-empty-second": {
			sets: []string{
				`set protocols ospf area 0.0.0.0 interface ge-0/0/0.0 authentication md5 1 key "bad secret"`,
				`set protocols ospf area 0.0.0.0 interface ge-0/0/0.0 authentication md5 2 key ""`,
			},
			wantSub: []string{"ge-0/0/0.0"},
		},
		// Bad second key: scalar AuthKey ends bad, so the scalar gate
		// already caught this; kept to pin the per-key field name.
		"bad-second-valid-first": {
			sets: []string{
				`set protocols ospf area 0.0.0.0 interface ge-0/0/0.0 authentication md5 1 key "goodsecret"`,
				`set protocols ospf area 0.0.0.0 interface ge-0/0/0.0 authentication md5 2 key "bad secret"`,
			},
			wantSub: []string{"ge-0/0/0.0", "md5 2 key"},
		},
		// Routing-instance scope must be checked per-key too.
		"ri-bad-first-valid-second": {
			sets: []string{
				`set routing-instances VRF-A protocols ospf area 0.0.0.0 interface ge-0/0/0.0 authentication md5 1 key "bad secret"`,
				`set routing-instances VRF-A protocols ospf area 0.0.0.0 interface ge-0/0/0.0 authentication md5 2 key "goodsecret"`,
			},
			wantSub: []string{"ge-0/0/0.0", "md5 1 key"},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := CompileConfig(flatTreeFromSets(t, tc.sets...))
			if err == nil {
				t.Fatalf("CompileConfig accepted multi-key OSPF MD5 rollover with an invalid key (%s); want strict rejection (#15715)", name)
			}
			for _, sub := range tc.wantSub {
				if !strings.Contains(err.Error(), sub) {
					t.Fatalf("strict error must contain %q, got: %v", sub, err)
				}
			}
		})
	}
}

func TestOSPFRolloverEmptyKeyRejected15715(t *testing.T) {
	cases := map[string]struct {
		sets       []string
		emptyKeyID string
	}{
		// Case C: valid first key, keyless second entry (no key child).
		"caseC-valid-first-keyless-second": {
			sets: []string{
				`set protocols ospf area 0.0.0.0 interface ge-0/0/0.0 authentication md5 1 key "goodsecret"`,
				`set protocols ospf area 0.0.0.0 interface ge-0/0/0.0 authentication md5 2`,
			},
			emptyKeyID: "md5 2",
		},
		// Empty-string key beside a valid one (the former #14397 control).
		"empty-first-valid-second": {
			sets: []string{
				`set protocols ospf area 0.0.0.0 interface ge-0/0/0.0 authentication md5 1 key ""`,
				`set protocols ospf area 0.0.0.0 interface ge-0/0/0.0 authentication md5 2 key "goodsecret"`,
			},
			emptyKeyID: "md5 1",
		},
		// Valid first, empty second (order must not matter).
		"valid-first-empty-second": {
			sets: []string{
				`set protocols ospf area 0.0.0.0 interface ge-0/0/0.0 authentication md5 1 key "goodsecret"`,
				`set protocols ospf area 0.0.0.0 interface ge-0/0/0.0 authentication md5 2 key ""`,
			},
			emptyKeyID: "md5 2",
		},
		// Routing-instance rollover with a keyless entry.
		"ri-valid-first-keyless-second": {
			sets: []string{
				`set routing-instances VRF-A protocols ospf area 0.0.0.0 interface ge-0/0/0.0 authentication md5 1 key "goodsecret"`,
				`set routing-instances VRF-A protocols ospf area 0.0.0.0 interface ge-0/0/0.0 authentication md5 2`,
			},
			emptyKeyID: "md5 2",
		},
	}
	for name, tc := range cases {
		sets, emptyKeyID := tc.sets, tc.emptyKeyID
		t.Run(name, func(t *testing.T) {
			_, err := CompileConfig(flatTreeFromSets(t, sets...))
			if err == nil {
				t.Fatalf("CompileConfig accepted OSPF MD5 rollover with an empty/keyless entry (%s); want strict rejection (#15715)", name)
			}
			if !strings.Contains(err.Error(), "ge-0/0/0.0") {
				t.Fatalf("strict error must name the interface, got: %v", err)
			}
			if !strings.Contains(err.Error(), emptyKeyID) {
				t.Fatalf("strict error must name the empty %s, got: %v", emptyKeyID, err)
			}
		})
		t.Run(name+"-lenient-warns", func(t *testing.T) {
			cfg, err := CompileConfigLenient(flatTreeFromSets(t, sets...))
			if err != nil {
				t.Fatalf("CompileConfigLenient hard-rejected rollover with empty entry (%s), want warn (#1960): %v", name, err)
			}
			found := false
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "ge-0/0/0.0") && strings.Contains(w, emptyKeyID) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("lenient compile produced no empty-md5-entry warning naming interface + key-id; got %v", cfg.Warnings)
			}
		})
	}
}

// Controls: a rollover where every key is valid, keyed simple, and no
// authentication must still compile strict; the valid rollover must keep
// both keys.
func TestOSPFRolloverValidControls15715(t *testing.T) {
	t.Run("all-valid-rollover", func(t *testing.T) {
		cfg, err := CompileConfig(flatTreeFromSets(t,
			`set protocols ospf area 0.0.0.0 interface ge-0/0/0.0 authentication md5 1 key "goodsecret1"`,
			`set protocols ospf area 0.0.0.0 interface ge-0/0/0.0 authentication md5 2 key "goodsecret2"`,
		))
		if err != nil {
			t.Fatalf("CompileConfig rejected all-valid rollover: %v", err)
		}
		iface := cfg.Protocols.OSPF.Areas[0].Interfaces[0]
		if len(iface.AuthMD5Keys) != 2 {
			t.Fatalf("AuthMD5Keys = %+v, want both rollover keys retained", iface.AuthMD5Keys)
		}
	})
	t.Run("keyed-simple", func(t *testing.T) {
		if _, err := CompileConfig(flatTreeFromSets(t,
			`set protocols ospf area 0.0.0.0 interface ge-0/0/0.0 authentication simple-password "s3cret"`,
		)); err != nil {
			t.Fatalf("CompileConfig rejected keyed simple: %v", err)
		}
	})
	t.Run("no-authentication", func(t *testing.T) {
		if _, err := CompileConfig(flatTreeFromSets(t,
			"set protocols ospf area 0.0.0.0 interface ge-0/0/0.0",
		)); err != nil {
			t.Fatalf("CompileConfig rejected no-auth interface: %v", err)
		}
	})
	t.Run("single-valid-md5", func(t *testing.T) {
		if _, err := CompileConfig(flatTreeFromSets(t,
			`set protocols ospf area 0.0.0.0 interface ge-0/0/0.0 authentication md5 1 key "s3cret"`,
		)); err != nil {
			t.Fatalf("CompileConfig rejected single valid md5: %v", err)
		}
	})
}

// The tolerant path must still boot a persisted bad-whitespace rollover
// (#1960): the FRR auth-value gate downgrades to a warning there.
func TestOSPFRolloverBadKeyLenientWarns15715(t *testing.T) {
	cfg, err := CompileConfigLenient(flatTreeFromSets(t,
		`set protocols ospf area 0.0.0.0 interface ge-0/0/0.0 authentication md5 1 key "bad secret"`,
		`set protocols ospf area 0.0.0.0 interface ge-0/0/0.0 authentication md5 2 key "goodsecret"`,
	))
	if err != nil {
		t.Fatalf("CompileConfigLenient hard-rejected bad-whitespace rollover, want warn: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "ge-0/0/0.0") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("lenient compile produced no FRR auth-value warning naming the interface; got %v", cfg.Warnings)
	}
}
