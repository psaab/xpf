package dataplane

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// session_sync_parity_16176_test.go — #16176 (data-model P1a, parity test only).
//
// SessionValue and SessionValueV6 are hand-maintained twins. Their trailing
// ~15 HA-sync fields are duplicated verbatim, and the struct comments document
// the failure mode directly: a field added to the v4 value was once forgotten
// on v6 ("every IPv6 session degraded after a failover"). This test is the
// survivor of the SessionSyncMeta proposal after hostile review: it changes
// NO struct, NO composite literal and NO census — it only pins that the two
// twins cannot drift apart again. The embed is NOT endorsed by #16176 (see
// the issue: promoted fields cannot be composite-literal keys, and the #7097
// scrub census would silently weaken under an embed); do not add a
// SessionSyncMeta type on the strength of this file.
//
// THE EXACT EXCLUSION / CLASSIFICATION SET (the parity universe)
//
// Parity is asserted over field NAME+TYPE after removing exactly these
// declared exceptions. Nothing else may be excluded: a future field that
// lands on only one twin, or with a different type on the other, fails here
// and must either be mirrored or be added to this list WITH its reason.
//
//  1. NAT address width — ABI-32 vs ABI-128, intentional:
//     NATSrcIP, NATDstIP are uint32 on SessionValue and [16]byte on
//     SessionValueV6. The NAT *ports* (NATSrcPort/NATDstPort) are NOT
//     excluded: they are uint16 on both and are parity-checked.
//
//  2. ReverseKey — the embedded reverse 5-tuple key, whose type follows the
//     address family: SessionKey vs SessionKeyV6. Excluded by name; its own
//     v4/v6 key parity is the C session_key/session_key_v6 ABI's business.
//
//  3. Nat64SnatV4 [4]byte — V6-ONLY, by design (#4565). A NAT64 forward flow
//     is keyed on the original IPv6 5-tuple, so only the v6 value carries
//     the translated IPv4 pool source the peer needs to rebuild the reverse
//     BIB. There is no v4 counterpart to mirror; adding one would be wrong.
//
// Every other field falls in exactly one of three classes, and the class
// determines where the field is allowed to live:
//
//   - ABI (on-map): present in bpfSessionValue/bpfSessionValueV6 AND in the
//     sync codec AND on both Go values (e.g. State, Flags, PolicyID, the NAT
//     fields, ReverseKey, RoutingDomain since #9546). Being in both places is
//     legitimate and common — see the boundary test below.
//   - Sync-wire: present in the pkg/cluster session codec (encode/decode
//     Session{,V6}Payload) and on both Go values, but in NEITHER BPF ABI
//     struct (e.g. Generation, PolicyCounterIdx, ConfigEpoch,
//     RTFlowSessionID, IngressIfaceFold, EgressIfaceFold, NatScopeFold,
//     TunnelDiscriminator, PptpCallIDs, TCPCloseClass, TCPHandshakeState,
//     InstallTableDomain, InstallTableCheck, SourceNatICMPValid/Type/Code,
//     PolicyRuleID, and v6-only Nat64SnatV4). These MUST NOT be added to
//     bpfSessionValue{,V6}: the maps are registered at the C/Rust ABI size
//     (152/200, pinned by TestBPFSessionValueMatchesConntrackABI) and a
//     sync-only field there over-sizes value_size into the Rust helper's
//     smaller lookup buffer (#2360).
//   - Go-local: present on the Go values but in NEITHER the BPF ABI NOR the
//     sync codec. Exactly one field is Go-local today: NatScopeIfindex
//     (int32, both twins). Justification: it is the NODE-LOCAL logical
//     NAT-scope ingress ifindex recorded at admission from the helper delta
//     (#15176); an ifindex names a different NIC on the peer, so the raw
//     number must never cross the wire. What crosses instead is NatScopeFold,
//     the cluster-stable fold stamped from it at sync_conn_gen.go
//     (stampNatScopeFold), and the importer resolves the fold back to its own
//     ifindex. NatScopeIfindex therefore has no BPF slot and no wire slot,
//     and that is correct — do not "fix" its absence from either.
//
// CORRECTED BOUNDARY RULE (this is the form #16176 mandates; the literal
// report assertion "no sync-wire field name appears in bpfSessionValue" is
// UNSOUND and already false — State, Flags, PolicyID, the NAT addresses and
// ReverseKey are intentionally in BOTH the codec and the ABI structs):
//
//	No field that exists ONLY for HA sync — i.e. present in the sync codec
//	but in neither BPF struct's field set — may be added to
//	bpfSessionValue or bpfSessionValueV6.
//
// TestSyncOnlyFieldsStayOutOfTheBPFABI16176 encodes exactly that, classifying
// by codec presence rather than by name-matching against the wire.

// sessionSyncParityExclusions is the declared exception set above. It is a
// var (not a literal inside the test) so the boundary test can assert the
// V6-only member really is sync-wire and really is absent from both ABI
// structs, instead of the exclusion being taken on faith.
var sessionSyncParityExclusions = map[string]string{
	"NATSrcIP":    "NAT address width: uint32 (v4) vs [16]byte (v6)",
	"NATDstIP":    "NAT address width: uint32 (v4) vs [16]byte (v6)",
	"ReverseKey":  "reverse 5-tuple key type follows the address family: SessionKey vs SessionKeyV6",
	"Nat64SnatV4": "v6-only NAT64 pool source (#4565); no v4 counterpart exists by design",
}

// sessionFieldTypes returns name -> type string for every field of typ,
// skipping blank padding fields (the explicit `_ [N]byte` ABI pads, #6082),
// which are layout, not session data.
func sessionFieldTypes(typ reflect.Type) map[string]string {
	out := make(map[string]string, typ.NumField())
	for i := range typ.NumField() {
		f := typ.Field(i)
		if f.Name == "_" {
			continue
		}
		out[f.Name] = f.Type.String()
	}
	return out
}

func sortedSessionFieldNames16176(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// codecReferencedSessionFields extracts the simple selector field accesses
// (`.Name` followed by a non-identifier byte) in pkg/cluster/sync_protocol.go.
// dataplane does not import pkg/cluster, so this pins the boundary
// classification to the hand-written codec source instead of merely
// restating the test's own list. The pkg/cluster round-trip tests remain the
// authority for wire bytes and truncation behaviour.
func codecReferencedSessionFields(t *testing.T) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(headroomRepoRoot(t), "pkg", "cluster", "sync_protocol.go"))
	if err != nil {
		t.Fatalf("read sync codec: %v", err)
	}
	source := string(raw)
	fields := make(map[string]bool)
	names := append(append([]string{}, syncWireOnlySessionFields...), goLocalSessionFields...)
	names = append(names, "State", "Flags", "PolicyID", "NATSrcPort", "NATDstPort", "ReverseKey", "RoutingDomain")
	for _, name := range names {
		if containsFieldAccess(source, name) {
			fields[name] = true
		}
	}
	return fields
}

func containsFieldAccess(source, name string) bool {
	needle := "." + name
	for start := 0; ; {
		idx := strings.Index(source[start:], needle)
		if idx < 0 {
			return false
		}
		pos := start + idx
		after := pos + len(needle)
		if after >= len(source) || !isFieldNameByte(source[after]) {
			return true
		}
		start = after
	}
}

func isFieldNameByte(b byte) bool {
	return b == '_' || ('0' <= b && b <= '9') || ('A' <= b && b <= 'Z') || ('a' <= b && b <= 'z')
}

// TestSessionValueSyncFieldParity16176 is the decisive #16176 check: after
// removing the declared exclusions, SessionValue and SessionValueV6 must
// have IDENTICAL field name+type sets. A field added to one twin only (the
// historical "forgot V6" defect), or re-typed on one twin only, fails here
// naming the field and both types.
//
// RED PROOF (performed at authoring, recorded in the PR): planting
// `ParityPlant uint32 // TEMP` on SessionValue only makes this test fail
// with "in SessionValue only: ParityPlant uint32"; removing the plant
// returns it to green. The plant is not shipped.
func TestSessionValueSyncFieldParity16176(t *testing.T) {
	v4 := sessionFieldTypes(reflect.TypeOf(SessionValue{}))
	v6 := sessionFieldTypes(reflect.TypeOf(SessionValueV6{}))

	// The exclusions must be honest: every excluded name must actually exist
	// on at least one twin (a renamed field must not leave a stale exclusion
	// silently exempting nothing while the renamed field drifts), and the
	// two NAT exclusions must be present on BOTH twins with the declared
	// width difference — otherwise the exclusion is masking a real deletion.
	for name := range sessionSyncParityExclusions {
		_, in4 := v4[name]
		_, in6 := v6[name]
		if !in4 && !in6 {
			t.Errorf("parity exclusion %q names a field present on NEITHER twin — "+
				"stale exclusion; remove it or fix the rename (#16176)", name)
		}
	}
	for _, name := range []string{"NATSrcIP", "NATDstIP", "ReverseKey"} {
		if _, ok := v4[name]; !ok {
			t.Errorf("%s missing from SessionValue; the parity exclusion must not mask its deletion (#16176)", name)
		}
		if _, ok := v6[name]; !ok {
			t.Errorf("%s missing from SessionValueV6; the parity exclusion must not mask its deletion (#16176)", name)
		}
	}
	if _, ok := v4["Nat64SnatV4"]; ok {
		t.Error("Nat64SnatV4 appeared on SessionValue: it is v6-only by design (#4565); " +
			"a v4 copy needs a stated reason and must leave the exclusion set (#16176)")
	}
	if got, ok := v6["Nat64SnatV4"]; !ok || got != "[4]uint8" {
		t.Errorf("SessionValueV6.Nat64SnatV4 = %q (present=%v), want [4]uint8 (#4565/#16176)", got, ok)
	}

	for name := range sessionSyncParityExclusions {
		delete(v4, name)
		delete(v6, name)
	}

	for _, name := range sortedSessionFieldNames16176(v4) {
		got6, ok := v6[name]
		if !ok {
			t.Errorf("field %s %s is in SessionValue only — mirror it on SessionValueV6 "+
				"or declare it in sessionSyncParityExclusions with its reason (#16176: the "+
				"forgot-V6 class)", name, v4[name])
			continue
		}
		if got6 != v4[name] {
			t.Errorf("field %s type drift: SessionValue %s vs SessionValueV6 %s (#16176)",
				name, v4[name], got6)
		}
	}
	for _, name := range sortedSessionFieldNames16176(v6) {
		if _, ok := v4[name]; !ok {
			t.Errorf("field %s %s is in SessionValueV6 only — mirror it on SessionValue "+
				"or declare it in sessionSyncParityExclusions with its reason (#16176)",
				name, v6[name])
		}
	}
}

// syncWireOnlySessionFields are the HA-sync-only fields: carried by the
// pkg/cluster session codec (the length-gated trailing fields of
// encode/decodeSession{,V6}Payload in pkg/cluster/sync_protocol.go) and by
// the userspace helper-delta conversion, present on the Go session values,
// and in NEITHER BPF ABI struct. Nat64SnatV4 is the v6-only member.
//
// This list is the boundary test's input, stated explicitly because the
// codec is a hand-written byte encoder, not a reflection-driven one: there
// is no codec registry to reflect over. If a field is added to the codec,
// add it here; TestSyncOnlyFieldsStayOutOfTheBPFABI16176 then proves it
// stayed out of the ABI structs, and the parity test above proves it was
// mirrored on both Go twins (or declared v6-only like Nat64SnatV4).
var syncWireOnlySessionFields = []string{
	"Generation",
	"PolicyCounterIdx",
	"ConfigEpoch",
	"RTFlowSessionID",
	"IngressIfaceFold",
	"EgressIfaceFold",
	"NatScopeFold",
	"TunnelDiscriminator",
	"PptpCallIDs",
	"TCPCloseClass",
	"TCPHandshakeState",
	"InstallTableDomain",
	"InstallTableCheck",
	"SourceNatICMPValid",
	"SourceNatICMPType",
	"SourceNatICMPCode",
	"PolicyRuleID",
	"Nat64SnatV4", // v6-only member
}

// goLocalSessionFields are present on the Go session values but in NEITHER
// the BPF ABI structs NOR the sync codec. See the file header for why
// NatScopeIfindex is Go-local: the node-local ifindex never crosses the
// wire; only its cluster-stable fold (NatScopeFold, sync-wire above) does.
var goLocalSessionFields = []string{
	"NatScopeIfindex",
}

// TestSyncOnlyFieldsStayOutOfTheBPFABI16176 encodes the CORRECTED boundary
// rule from #16176: a field that exists only for HA sync (in the sync codec
// but in neither BPF struct's field set) must not be added to
// bpfSessionValue/bpfSessionValueV6. It deliberately does NOT assert the
// report's literal form ("no sync-wire field name appears in
// bpfSessionValue"), which is already false: State, Flags, PolicyID, the NAT
// addresses/ports and ReverseKey are carried by the codec AND are legitimate
// ABI fields. The positive control at the end pins that overlap as expected,
// so a future "fix" that drops an ABI field to satisfy the literal reading
// fails here instead.
func TestSyncOnlyFieldsStayOutOfTheBPFABI16176(t *testing.T) {
	abiV4 := sessionFieldTypes(reflect.TypeOf(bpfSessionValue{}))
	abiV6 := sessionFieldTypes(reflect.TypeOf(bpfSessionValueV6{}))
	goV4 := sessionFieldTypes(reflect.TypeOf(SessionValue{}))
	goV6 := sessionFieldTypes(reflect.TypeOf(SessionValueV6{}))
	codecFields := codecReferencedSessionFields(t)

	// The classification lists must agree with the codec itself: every
	// declared sync-only and shared field must actually be referenced by the
	// hand-written codec, while the Go-local ifindex must not be. This keeps
	// the boundary test from becoming a self-consistent list disconnected
	// from sync_protocol.go after a codec edit.
	for _, name := range append(append([]string{}, syncWireOnlySessionFields...), "State", "Flags", "PolicyID", "NATSrcPort", "NATDstPort", "ReverseKey", "RoutingDomain") {
		if !codecFields[name] {
			t.Errorf("declared codec field %s is not referenced in pkg/cluster/sync_protocol.go — update the #16176 classification", name)
		}
	}
	for _, name := range goLocalSessionFields {
		if codecFields[name] {
			t.Errorf("Go-local field %s is referenced in pkg/cluster/sync_protocol.go — it is no longer Go-local; reclassify it in #16176", name)
		}
	}

	for _, name := range syncWireOnlySessionFields {
		if _, ok := abiV4[name]; ok {
			t.Errorf("sync-only field %s was added to bpfSessionValue — sync-wire fields "+
				"must stay out of the map ABI structs (#16176 corrected boundary; #2360)", name)
		}
		if _, ok := abiV6[name]; ok {
			t.Errorf("sync-only field %s was added to bpfSessionValueV6 — sync-wire fields "+
				"must stay out of the map ABI structs (#16176 corrected boundary; #2360)", name)
		}
		// Every declared sync-only field must exist on at least one Go twin,
		// or this list has gone stale and the boundary above guards nothing.
		_, in4 := goV4[name]
		_, in6 := goV6[name]
		if !in4 && !in6 {
			t.Errorf("sync-only field %q is on NEITHER Go session value — stale entry in "+
				"syncWireOnlySessionFields (#16176)", name)
		}
	}

	// Go-local fields: on both Go twins (parity), in neither ABI struct, and
	// — by the classification in the header — represented on the wire only
	// by a fold, never by the raw field. The ABI half is checkable here; the
	// wire half is the codec's hand-written encoder, pinned by the sync
	// round-trip tests in pkg/cluster.
	for _, name := range goLocalSessionFields {
		if _, ok := abiV4[name]; ok {
			t.Errorf("Go-local field %s was added to bpfSessionValue (#16176)", name)
		}
		if _, ok := abiV6[name]; ok {
			t.Errorf("Go-local field %s was added to bpfSessionValueV6 (#16176)", name)
		}
	}

	// Positive control for the corrected rule: these fields are in BOTH the
	// sync codec and the ABI structs on purpose. If one disappears from an
	// ABI struct, that is ABI breakage, not boundary hygiene.
	for _, name := range []string{"State", "Flags", "PolicyID", "NATSrcPort", "NATDstPort", "ReverseKey", "RoutingDomain"} {
		if _, ok := abiV4[name]; !ok {
			t.Errorf("shared codec+ABI field %s missing from bpfSessionValue — the corrected "+
				"boundary does not ask for this removal (#16176)", name)
		}
		if _, ok := abiV6[name]; !ok {
			t.Errorf("shared codec+ABI field %s missing from bpfSessionValueV6 — the corrected "+
				"boundary does not ask for this removal (#16176)", name)
		}
	}

	// And the converse containment: every ABI field must exist on the Go
	// value it mirrors (the converters in bpf_session_value.go are
	// field-by-field; an ABI-only field would be dropped silently by them).
	// NAT IPs / ReverseKey are present on both sides under the same names,
	// so no exclusion is needed here.
	for _, name := range sortedSessionFieldNames16176(abiV4) {
		if _, ok := goV4[name]; !ok {
			t.Errorf("bpfSessionValue field %s has no SessionValue counterpart (#16176)", name)
		}
	}
	for _, name := range sortedSessionFieldNames16176(abiV6) {
		if _, ok := goV6[name]; !ok {
			t.Errorf("bpfSessionValueV6 field %s has no SessionValueV6 counterpart (#16176)", name)
		}
	}
}
