package userspace

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestSessionDeltaPolicyAttributionWireKeysLockstepWithRust6949 pins the Go
// DECODER's JSON keys for policy attribution and the app-timeout/log presence
// marker on SessionDeltaInfo to the keys the Rust producer actually emits.
//
// #6949: the binary event-stream open frame had carried policy_id (#3056/#3301),
// policy_counter_idx (#3073), the per-application inactivity timeout (#3227) and
// the NAT64 marker + pool source (#4565) as trailing fields, while the JSON
// RPC-fallback delta carried NONE of them — and this file declared and read all
// five unconditionally. Every session learned through that leg (drained every
// 100 ms while the event stream is down, every 5 s while it is up, and on every
// helper-requested FullResync) therefore imported PolicyID 0, PolicyCounterIdx
// 0, no application timeout and no reverse-BIB pool source.
//
// A key mismatch is SILENT on both planes, and worse here than for most wire
// fields: the field is simply absent from the decoded struct, Go leaves it 0,
// and 0 is a legitimate value on all five — "no policy admitted this",
// "no per-rule counter", "use the global timeout", "not a NAT64 session". A
// rendered PolicyID of 0 displays as `unattributed` (#6851), indistinguishable
// from a session an operator really did admit under policy 0. That is exactly
// why #6949 went unnoticed for four releases, and it means the fix would look
// applied and do nothing if either spelling drifted.
//
// The keys are therefore PARSED OUT of the Rust source rather than restated
// here: a constant written down twice is two constants, and pinning one side to
// a literal would encode which side is believed correct. Reverting either
// side's spelling reds this.
func TestSessionDeltaPolicyAttributionWireKeysLockstepWithRust6949(t *testing.T) {
	// Test cwd is pkg/dataplane/userspace.
	binding := filepath.Join("..", "..", "..", "userspace-dp", "src", "protocol", "binding.rs")

	// Every value below is NON-ZERO / non-empty on purpose. The zero case
	// cannot distinguish a correctly decoded field from an absent one, which is
	// the whole shape of the #6949 defect.
	numeric := []struct {
		rustField string
		want      uint32
		got       func(SessionDeltaInfo) uint32
		why       string
	}{
		{"policy_id", 4242, func(d SessionDeltaInfo) uint32 { return d.PolicyID },
			"the session renders `unattributed` and is skipped by the commit-time " +
				"deletion-clear and the #4234 policy-rematch, both of which exclude id 0"},
		{"policy_counter_idx", 9, func(d SessionDeltaInfo) uint32 { return d.PolicyCounterIdx },
			"no per-rule hit counter is attributed after a failover promotion (#3073)"},
		{"app_timeout", 1800, func(d SessionDeltaInfo) uint32 { return d.AppTimeout },
			"the session ages on the global per-protocol timeout, not its per-application " +
				"one (#3227/#3301)"},
	}
	for _, c := range numeric {
		rustKey := rustWireKeyInStruct(t, binding, "SessionDeltaInfo", c.rustField, false)
		doc := fmt.Sprintf(`{"event":"open","addr_family":2,"protocol":6,`+
			`"src_ip":"10.0.61.102","dst_ip":"172.16.80.200","src_port":12345,"dst_port":5201,`+
			`%q:%d}`, rustKey, c.want)
		var info SessionDeltaInfo
		if err := json.Unmarshal([]byte(doc), &info); err != nil {
			t.Fatalf("unmarshal %s: %v", doc, err)
		}
		if got := c.got(info); got != c.want {
			t.Fatalf("%s = %d, want %d. userspace-dp emits it under the key %q "+
				"(`#[serde(rename = ...)]` in protocol/binding.rs); a Go struct tag that spells "+
				"it differently drops it back to 0 on the JSON resync leg, and then %s",
				c.rustField, got, c.want, rustKey, c.why)
		}
		// The tuple decoded too, so the assertion above is about this key and
		// not about a document the decoder rejected wholesale.
		if info.SrcPort != 12345 || info.Event != "open" {
			t.Fatalf("delta decoded as %+v, want the seeded open tuple", info)
		}
	}

	statedKey := rustWireKeyInStruct(t, binding, "SessionDeltaInfo", "app_timeout_log_stated", false)
	var stated SessionDeltaInfo
	if err := json.Unmarshal([]byte(fmt.Sprintf(`{"event":"open",%q:true}`, statedKey)), &stated); err != nil {
		t.Fatalf("unmarshal stated app-timeout/log delta: %v", err)
	}
	if !stated.AppTimeoutLogStated {
		t.Fatalf("AppTimeoutLogStated = false for a %q:true delta", statedKey)
	}

	// nat64 is a bool and nat64_snat_v4 a string; both are asserted on their
	// TRUE / non-empty value for the same reason — false and "" are what an
	// absent key decodes to.
	nat64Key := rustWireKeyInStruct(t, binding, "SessionDeltaInfo", "nat64", false)
	snatKey := rustWireKeyInStruct(t, binding, "SessionDeltaInfo", "nat64_snat_v4", false)
	doc := fmt.Sprintf(`{"event":"open","src_port":12345,%q:true,%q:"203.0.113.5"}`,
		nat64Key, snatKey)
	var info SessionDeltaInfo
	if err := json.Unmarshal([]byte(doc), &info); err != nil {
		t.Fatalf("unmarshal %s: %v", doc, err)
	}
	if !info.Nat64 {
		t.Fatalf("Nat64 = false for a %q:true delta, want true", nat64Key)
	}
	if info.Nat64SnatV4 != "203.0.113.5" {
		t.Fatalf("Nat64SnatV4 = %q, want %q. userspace-dp emits the pool source under %q; "+
			"a spelling mismatch leaves it empty, and daemon_ha_userspace_convert.go then "+
			"stamps no Nat64SnatV4 — a NAT64 session promoted from this leg cannot rebuild "+
			"its reverse (v4->v6) BIB at all, because that address is the one datum not "+
			"reconstructable from the synced forward v6 key (#4565)",
			info.Nat64SnatV4, "203.0.113.5", snatKey)
	}

	// An old helper omits these fields. Their zero values must remain valid,
	// which is what makes the addition rolling-upgrade safe in the helper-older direction.
	var legacy SessionDeltaInfo
	if err := json.Unmarshal([]byte(`{"event":"open","src_port":12345}`), &legacy); err != nil {
		t.Fatalf("unmarshal legacy delta: %v", err)
	}
	if legacy.PolicyID != 0 || legacy.PolicyCounterIdx != 0 || legacy.AppTimeout != 0 ||
		legacy.AppTimeoutLogStated || legacy.Nat64 || legacy.Nat64SnatV4 != "" {
		t.Fatalf("legacy delta decoded as %+v, want the zero attribution and absent marker", legacy)
	}
}

// #17142: the keys below are resolved on SessionDeltaInfo ITSELF via the
// shared struct-scoped helper (rustwire_test.go). The previous file-wide
// first-match lookup read ExceptionStatus's `ingress_ifindex` — declared
// earlier in binding.rs — so swapping SessionDeltaInfo's ingress and
// NAT-scope renames passed this cell (issue mutant C) even though the
// key set, and therefore every set cell, is blind to a swap. See
// TestSessionDeltaPopulatedSpecimenValues17142 for the value-level cell
// that catches a swap without reading Rust source at all.
func TestSessionDeltaIngressAndPolicyRuleIdentityKeys11070(t *testing.T) {
	binding := filepath.Join("..", "..", "..", "userspace-dp", "src", "protocol", "binding.rs")
	ingressKey := rustWireKeyInStruct(t, binding, "SessionDeltaInfo", "ingress_ifindex", false)
	vlanKey := rustWireKeyInStruct(t, binding, "SessionDeltaInfo", "ingress_vlan_id", false)
	ruleKey := rustWireKeyInStruct(t, binding, "SessionDeltaInfo", "policy_rule_id", false)
	doc := fmt.Sprintf(`{"event":"open","addr_family":2,"protocol":6,%q:42,%q:51,%q:"lan->wan/allow-web"}`,
		ingressKey, vlanKey, ruleKey)
	var delta SessionDeltaInfo
	if err := json.Unmarshal([]byte(doc), &delta); err != nil {
		t.Fatalf("unmarshal delta: %v", err)
	}
	if delta.IngressIfindex != 42 || delta.IngressVLANID != 51 || delta.PolicyRuleID != "lan->wan/allow-web" {
		t.Fatalf("delta identities = ifindex %d vlan %d rule %q",
			delta.IngressIfindex, delta.IngressVLANID, delta.PolicyRuleID)
	}
}

// TestSessionDeltaPolicyAttributionCommentIsNotFalse6949 guards the sentence
// this file used to tell auditors.
//
// From #3301 until #6949 the SessionDeltaInfo doc said the three policy fields
// were "decoded from the trailing fields of the binary open frame AND mirrored
// on the JSON RPC-fallback delta". The second half was untrue for four
// releases: the Rust producer had no such fields. Anyone auditing the JSON leg
// by reading this consumer — the natural place to look — concluded it was
// already at parity and stopped.
//
// A claim fix owes two proofs: that it landed, and that it is TRUE. This
// asserts the second: the Rust producer really does declare all policy fields and
// the app-timeout/log presence marker that the comment claims parity on. Deleting
// a field from binding.rs makes the sentence false again and reds this, which a
// wording-only guard could not see.
func TestSessionDeltaPolicyAttributionCommentIsNotFalse6949(t *testing.T) {
	binding := filepath.Join("..", "..", "..", "userspace-dp", "src", "protocol", "binding.rs")
	for _, f := range []string{
		"policy_id", "policy_counter_idx", "app_timeout", "app_timeout_log_stated", "nat64", "nat64_snat_v4",
	} {
		// rustWireKeyInStruct Fatalf's when the field (or its struct) is
		// gone, which is the RED this test exists for.
		key := rustWireKeyInStruct(t, binding, "SessionDeltaInfo", f, false)
		if strings.TrimSpace(key) == "" {
			t.Fatalf("empty serde rename for %s", f)
		}
	}
}

// TestSessionDeltaInfoKeySetsAreInParityWithRust6949 is the guard that would
// have caught #6949 on the day #3301 shipped, and the answer to the issue's
// "worth also checking the same struct against the binary codec for any other
// field that has drifted out of parity".
//
// The per-field lockstep tests above pin the SPELLING of the keys someone
// thought to write a test for. This one pins the SET: every JSON key this Go
// consumer declares must exist on the Rust producer, and vice versa. #6949 was
// not a misspelling — it was five fields the consumer read and the producer had
// never emitted, invisible for four releases because each one decodes to a
// legitimate zero. No spelling assertion can see that; only a set comparison
// can.
//
// Both sides are parsed, neither is restated: a field list written down twice is
// two field lists, and the whole defect class is the two drifting apart. Adding
// a field to either struct alone reds this.
//
// SCOPE: this is the delta struct only, and it proves the two spellings agree —
// not that a MIXED-VERSION cluster is safe. An old helper still omits keys a new
// daemon reads, and serde(default) decodes them to the same legitimate zeros.
// Fail-closed capability negotiation, and the canonical-schema equivalence test
// that generalizes this across every wire struct, are #7194.
func TestSessionDeltaInfoKeySetsAreInParityWithRust6949(t *testing.T) {
	goKeys := goJSONTagsInStruct(t,
		filepath.Join("protocol_ha.go"), "SessionDeltaInfo")
	rustKeys := rustWireKeysInStruct(t,
		filepath.Join("..", "..", "..", "userspace-dp", "src", "protocol", "binding.rs"),
		"SessionDeltaInfo")

	// A parse that found nothing would make this test vacuously green, which is
	// the same failure shape it exists to catch.
	if len(goKeys) < 30 || len(rustKeys) < 30 {
		t.Fatalf("parsed %d Go keys and %d Rust keys; the parse broke, so this guard is "+
			"vacuous. FIX THE PARSE — do not delete the guard", len(goKeys), len(rustKeys))
	}

	for k := range goKeys {
		if !rustKeys[k] {
			t.Errorf("Go SessionDeltaInfo declares JSON key %q that the Rust producer "+
				"(userspace-dp/src/protocol/binding.rs) never emits. Every session learned "+
				"through the JSON RPC-fallback leg — drained every 100 ms while the event "+
				"stream is down, every 5 s while it is up, and re-serialized whole on every "+
				"FullResync — will decode it as the zero value. That is #6949 exactly, and "+
				"it is silent: the zero is a legitimate value on each of these fields", k)
		}
	}
	for k := range rustKeys {
		if !goKeys[k] {
			t.Errorf("the Rust producer emits JSON key %q that Go SessionDeltaInfo does not "+
				"declare, so the value is dropped on arrival. Add the Go field (with the "+
				"matching struct tag) or stop emitting the key", k)
		}
	}
}

// goJSONTagsInStruct returns the set of `json:"..."` tag names declared by
// the named Go struct in the given file. (Go-side only; the Rust side is
// the shared parser in rustwire_test.go — #17142 deleted the per-issue
// Rust copies that lived here, including the visibility-blind field regex
// behind mutant B.)
func goJSONTagsInStruct(t *testing.T, path, name string) map[string]bool {
	t.Helper()
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v (the #6949 key-set parity guard cannot run)", path, err)
	}
	start := strings.Index(string(src), "type "+name+" struct {")
	if start < 0 {
		t.Fatalf("no Go struct %q in %s — update this guard rather than deleting it (#6949/#17142)", name, path)
	}
	rest := string(src)[start:]
	end := strings.Index(rest, "\n}")
	if end < 0 {
		t.Fatalf("unterminated Go struct %q in %s", name, path)
	}
	re := regexp.MustCompile("`json:\"([A-Za-z0-9_]+)")
	out := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(rest[:end], -1) {
		out[m[1]] = true
	}
	return out
}

func TestSessionDeltaSourceNatProvenanceJSON12187(t *testing.T) {
	for _, tc := range []struct {
		name        string
		provenance  uint8
		wantPresent bool
	}{
		{name: "unknown omitted", provenance: 0, wantPresent: false},
		{name: "dynamic numeric", provenance: 1, wantPresent: true},
		{name: "static numeric", provenance: 2, wantPresent: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire, err := json.Marshal(SessionDeltaInfo{SourceNatProvenance: tc.provenance})
			if err != nil {
				t.Fatalf("marshal session delta: %v", err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(wire, &fields); err != nil {
				t.Fatalf("decode session-delta JSON: %v", err)
			}
			raw, present := fields["source_nat_provenance"]
			if present != tc.wantPresent {
				t.Fatalf("source_nat_provenance presence=%v in %s, want %v", present, wire, tc.wantPresent)
			}
			if present {
				var got uint8
				if err := json.Unmarshal(raw, &got); err != nil {
					t.Fatalf("decode source_nat_provenance %s: %v", raw, err)
				}
				if got != tc.provenance {
					t.Fatalf("JSON provenance=%d, want %d", got, tc.provenance)
				}
			}
			var decoded SessionDeltaInfo
			if err := json.Unmarshal(wire, &decoded); err != nil {
				t.Fatalf("unmarshal session delta: %v", err)
			}
			if decoded.SourceNatProvenance != tc.provenance {
				t.Fatalf("decoded provenance=%d, want %d", decoded.SourceNatProvenance, tc.provenance)
			}
		})
	}

	var legacy SessionDeltaInfo
	if err := json.Unmarshal([]byte(`{"event":"open"}`), &legacy); err != nil {
		t.Fatalf("unmarshal legacy session delta: %v", err)
	}
	if legacy.SourceNatProvenance != 0 {
		t.Fatalf("legacy delta provenance=%d, want unknown (0)", legacy.SourceNatProvenance)
	}
}
