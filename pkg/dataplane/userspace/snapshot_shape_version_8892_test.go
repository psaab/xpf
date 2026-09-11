package userspace

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// Issue 8892: `routing_domain` was added to the config snapshot WITHOUT bumping
// ProtocolVersion, so a helper built before it advertised the same 8, passed
// the exact-equality gate, ignored the field, and resolved every interface to
// domain 0 -- the cross-tenant session aliasing #7160 exists to close.
//
// WHAT A LOCKSTEP CHECK WOULD NOT HAVE CAUGHT, and this is the whole design of
// the guard below. A cell asserting "the Go constant equals the Rust constant"
// is the obvious defence and it would have passed straight through this defect:
// BOTH sides stayed at 8 and therefore AGREED. The drift was not between the
// two constants -- it was between the snapshot's SHAPE and its version.
//
// The existing TestSnapshotProtocolVersionLockstepWithRust already pins the two
// constants to each other and is NOT duplicated here: it answers the other
// question (did someone bump one side alone), and it would have passed straight
// through this defect.
//
// So this pins the shape. Add, remove or retype a field on a snapshot struct
// and the digest moves; the cell then demands that ProtocolVersion moved too.
// It cannot tell a compatible addition from an incompatible one, and does not
// try: it forces a human decision at the one moment the decision is cheap,
// which is the moment the field is added.

// snapshotShapeStructs8892 are the structs whose wire shape the helper parses.
// Adding a new snapshot struct here is part of adding one to the protocol.
func snapshotShapeStructs8892() []any {
	return []any{
		ConfigSnapshot{}, InterfaceSnapshot{}, FlowSnapshot{},
		AddressBookSnapshot{}, SnapshotSummary{}, FabricSnapshot{},
	}
}

func shapeDigest8892(t *testing.T) (string, int) {
	t.Helper()
	var lines []string
	var walk func(rt reflect.Type, prefix string, depth int)
	walk = func(rt reflect.Type, prefix string, depth int) {
		if depth > 4 || rt == nil {
			return
		}
		for rt.Kind() == reflect.Ptr || rt.Kind() == reflect.Slice || rt.Kind() == reflect.Array {
			rt = rt.Elem()
		}
		if rt.Kind() != reflect.Struct {
			return
		}
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)
			if f.PkgPath != "" {
				continue // unexported: not on the wire
			}
			tag := f.Tag.Get("json")
			lines = append(lines, fmt.Sprintf("%s%s %s %q", prefix, f.Name, f.Type.String(), tag))
			walk(f.Type, prefix+f.Name+".", depth+1)
		}
	}
	for _, s := range snapshotShapeStructs8892() {
		rt := reflect.TypeOf(s)
		walk(rt, rt.Name()+".", 0)
	}
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:]), len(lines)
}

// snapshotShapeGolden8892 is the digest of the wire shape AT ProtocolVersion 10.
// If it moves, the shape changed: either bump ProtocolVersion and update this
// value in the same commit, or explain in the commit message why the change is
// invisible to a helper.
//
// v10 (issue 9054): `ConfigSnapshot.LearnedRouteImportCapped`. ProtocolVersion
// WAS bumped alongside it, deliberately, and the reason is the one this cell's
// header states: an old helper that ignores the field keeps black-holing every
// learned destination whenever the #8355 cap trips, and black-holing IS the
// defect the field was added to fix. That is the "is what it enforced before
// acceptable?" question answering no, so the exact-equality gate must REFUSE
// the pairing rather than let it degrade silently.
// v10 STANDS (issue 9125): `StaticRoute.HasPreference` was added to the typed
// config, which moved this digest because ConfigSnapshot embeds the whole
// Config. It is tagged `json:"-"`, so it is NOT serialized and no helper --
// old or new -- can observe it. This is the "explain why the change is
// invisible to a helper" arm the header offers, not a version bump: bumping for
// a field nothing transmits would spend the one signal that tells a helper the
// wire actually changed.
//
// The digest still moved because this walk records the json TAG, deliberately:
// adding `json:"-"` to an EXISTING wire field would be a silent removal, and
// the cell has to see that. So a tag change costs a golden update and a
// sentence, which is the intended price.
//
// v10 STANDS (issue 9246): `SecurityConfig.MalformedZonePairs` was added to the
// typed config, and ConfigSnapshot embeds the whole Config, so it moved this
// digest for the same reason HasPreference did. Same arm, same answer: it is
// tagged `json:"-"`, it is a COMPILE-TIME DIAGNOSTIC recording zone-pair
// statements whose shape shows a bracketed-list collapse, and it is nil in
// every valid config. Nothing transmits it, so no helper of any vintage can
// observe it, and bumping the protocol for it would spend the one signal that
// says the wire really changed.
//
// v10 STANDS (issue 9424): `InterfacesConfig.MalformedAddresses` was added to
// the typed config, and ConfigSnapshot embeds the whole Config, so it moved
// this digest for the same reason HasPreference and MalformedZonePairs did.
// Same arm, same answer: it is tagged `json:"-"`, it is a COMPILE-TIME
// DIAGNOSTIC recording a token inside a bracketed interface address list that
// is neither a valid address for its family nor an `address` sub-statement, and
// it is nil in every valid config. Nothing transmits it, so no helper of any
// vintage can observe it, and bumping the protocol for it would spend the one
// signal that says the wire really changed.
//
// Recorded here rather than only in a commit message because this is now the
// FOURTH field to reach this cell by embedding, and the fourth to need the same
// paragraph. The general rule the four share: a field added to ANY pkg/config
// struct lands on the helper wire via ConfigSnapshot, so it is answerable to
// this cell whether or not the author was thinking about the helper -- and the
// gate that catches it is `go test ./...`, not the packages the diff touched.
// #9424 is the case in point: its change is entirely inside pkg/config and
// pkg/configstore, and a scoped run over those two packages is green.
//
// v10 -> v11 (issue 9425): `ScreenMissingProfileRef.alarm_without_drop`. This
// one is the OTHER arm — a real, transmitted wire field, so the version moved.
// A zone whose screen profile is DEFINED but enables no check gets no `screens`
// entry, so the helper's resolved `alarm_without_drop` lookup missed and the
// #7888 substituted conservative default HARD-DROPPED. An old helper that
// ignores the new field decodes false and keeps hard-dropping, and hard-dropping
// IS the defect — so the answer to "is what it enforced before acceptable?" is
// no. "Purely additive needs no bump" is a TRUE rule that would have licensed
// exactly this regression, which is what this cell exists to refuse.
//
// v11 STANDS (issue 9408): `OSPFConfig.ReferenceBandwidth` was RENAMED to
// `ReferenceBandwidthMbps`, so the compiled field carries the unit that
// separates the Junos leaf (bits per second) from the FRR directive it feeds
// (megabits per second).
//
// THIS IS NOT LIKE THE THREE "STANDS" ENTRIES ABOVE, and the difference is why
// it is spelled out rather than pointed at them. Those were ADDITIONS of
// `json:"-"` fields -- nothing transmits them, so the reasoning is one
// sentence. This is a RENAME of a field with NO json tag, which means its Go
// name IS its wire key: an old helper looking for the old key would find
// nothing, which is exactly the shape this cell exists to refuse. So the
// invisibility was MEASURED, not argued by analogy:
//
//   - the Rust side models this whole subtree as ONE opaque value --
//     `pub config: serde_json::Value` in userspace-dp/src/protocol/snapshot.rs.
//     It names no field inside it, so no deserialization can break and
//     `deny_unknown_fields` cannot bite;
//   - `grep -rn "reference_bandwidth\|ReferenceBandwidth" userspace-dp/src/`
//     returns ZERO hits. Nothing in the dataplane reads it, of any vintage;
//   - the field's only consumer is pkg/frr, which renders the FRR managed
//     section Go-side, and every Go reader is compiler-checked by the rename.
//
// Bumping here would make a mixed-base pair REFUSE to apply any snapshot (the
// handler gates on exact equality) in exchange for a wire change no helper can
// observe -- spending the one signal that says the wire really moved. It is the
// FIFTH field to reach this cell by embedding, and #9424's "the gate that
// catches it is `go test ./...`, not the packages the diff touched" applies
// unchanged: this change lives in pkg/config and pkg/frr, and a scoped run over
// those two packages is green.
// v11 STANDS (issue 9416): `SNMPCommunity.ClientListNames` and
// `SNMPConfig.ClientLists` were added to the typed config, and ConfigSnapshot
// embeds the whole Config, so they moved this digest.
//
// UNLIKE the three "STANDS" entries above these are NOT `json:"-"` — they are
// serialized, so an old helper really does receive two new keys. They are
// nonetheless unobservable to it, and this was MEASURED rather than argued from
// the additive-field rule (a rule that is TRUE and would have licensed a
// regression once already):
//
//   - the Rust side models this whole subtree as ONE opaque value --
//     `pub config: serde_json::Value` in userspace-dp/src/protocol/snapshot.rs
//     (line 560). It names no field inside it, so a new key cannot break a
//     deserialization and `deny_unknown_fields` cannot bite;
//   - `grep -rn "ClientList\|client_list" userspace-dp/src/` returns ZERO
//     hits, as does a search for `snmp` in the snapshot protocol -- the
//     dataplane does not serve SNMP at all;
//   - the fields' only consumers are pkg/config (resolution), pkg/snmp (the
//     agent, in-process) and pkg/daemon (the reconcile hash), all Go-side.
//
// The snapshot handler gates on EXACT version equality, so bumping for a field
// no helper can observe would make a mixed-base pair refuse every snapshot in
// exchange for nothing -- spending the one signal that says the wire moved.
// v12 BUMPED (issue 9546): `session_value.routing_domain` was appended to the
// on-map conntrack ABI (144 -> 152 / 192 -> 200). The digest above did NOT move
// -- the BPF value is not a snapshot struct -- so this cell fired on its VERSION
// pin alone, which is the correct behaviour, and the entry is recorded rather
// than waved through.
//
// It is the mirror image of the STANDS entries above, and they supply the test:
// is the change OBSERVABLE to a mismatched helper? For those, measurably not.
// Here, measurably yes, and harmfully. The helper WRITES the struct: a new
// daemon creates the map at 152 bytes, an old helper hands bpf_map_update_elem
// a 144-byte buffer, and the kernel copies value_size bytes -- 8 past the
// helper's struct, into the routing_domain slot a new reader trusts. That is a
// garbage domain on a delete, which can name ANOTHER TENANT's row. Exact-
// equality refusal is the only mechanism that stops the pairing.
const (
	snapshotShapeGolden8892 = "6ba8027754216f49b2b20319239563c63ff2c7a45a4edfa70b442d37ddc1fdde"
	// v13 BUMPED (issue 9412) against the SAME digest. The TCP close class
	// crosses the HA session-sync path, and the old behaviour is the defect it
	// fixes, so the v9 rule requires the bump. The session-sync messages are not
	// snapshot structs, which is why the digest below did not move.
	// v13 -> v14 BUMPED (issue 9521), and this one DID move the digest above:
	// `ConfigSnapshot.WgSteeredListenPort` is a real, transmitted field. It is the
	// one WireGuard listen port the shim steers, and the helper uses it to refuse
	// writing any OTHER port's kernel-path transport plaintext to that tunnel's
	// wgN TUN, plaintext the kernel would otherwise forward with no zone policy.
	// An old helper ignores the field and keeps writing it, and that IS the
	// defect; a new helper under an old daemon reads 0 and refuses kernel-path
	// transport for every endpoint — the v10/v11 arm, not a STANDS entry. #9521
	// had claimed 13 against v12; #9412 took 13 first, so by the v8 rule this
	// change moves past both numbers.
	// v14 -> v15 BUMPED (issue 9520), and it moved the digest:
	// `ConfigSnapshot.ContentDigest` is transmitted. The helper compares it when an
	// apply reuses its installed generation; an old helper ignores it and keeps
	// admitting that apply content-blind, which IS the defect, so this is the
	// v10/v11 arm again.
	snapshotShapeVersion8892 = 15
)

func TestSnapshotShapeIsPinnedToProtocolVersion8892(t *testing.T) {
	got, fields := shapeDigest8892(t)
	// LIVENESS: a digest over an empty field set would be stable and would
	// assert nothing. RoutingDomain in particular must be in the walk, since it
	// is the field whose silent addition this cell exists to catch.
	if fields < 50 {
		t.Fatalf("shape walk collected only %d fields — it is not reaching the snapshot structs, "+
			"so the digest below is stable for the wrong reason", fields)
	}
	if !strings.Contains(strings.Join(func() []string {
		var out []string
		rt := reflect.TypeOf(InterfaceSnapshot{})
		for i := 0; i < rt.NumField(); i++ {
			out = append(out, rt.Field(i).Name)
		}
		return out
	}(), ","), "RoutingDomain") {
		t.Fatal("InterfaceSnapshot no longer carries RoutingDomain — this cell was written to " +
			"guard that field's wire contract and can no longer see it")
	}

	if ProtocolVersion != snapshotShapeVersion8892 {
		t.Fatalf("ProtocolVersion is %d but this cell's golden was recorded at %d. "+
			"Update snapshotShapeVersion8892 AND snapshotShapeGolden8892 together, "+
			"in the commit that changes the wire", ProtocolVersion, snapshotShapeVersion8892)
	}
	if got != snapshotShapeGolden8892 {
		t.Errorf("the config-snapshot WIRE SHAPE changed while ProtocolVersion stayed at %d.\n"+
			"  want digest %s\n  got  digest %s\n"+
			"A helper built before this change advertises the same version, passes the "+
			"exact-equality gate, and reads the rows differently. That is #8892: routing_domain "+
			"was added at v8 with no bump, so an old helper resolved every interface to domain 0 "+
			"and reverted #7160's cross-tenant isolation.\n"+
			"Bump ProtocolVersion (and CONFIG_SNAPSHOT_PROTOCOL_VERSION in "+
			"userspace-dp/src/protocol/control.rs) and update both constants here.",
			ProtocolVersion, snapshotShapeGolden8892, got)
	}
}
