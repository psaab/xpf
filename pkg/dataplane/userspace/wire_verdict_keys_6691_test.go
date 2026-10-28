package userspace

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #17142: rustSnapshotSerdeRename / rustSerdeRenameIn / rustProcessStatusRename
// are DELETED. They were the file-wide first-match scanner the #11070 cell
// was bound to: `rustSerdeRenameIn(t, binding.rs, "ingress_ifindex")`
// returned ExceptionStatus's rename (declared first in binding.rs)
// instead of SessionDeltaInfo's, so a swap of SessionDeltaInfo's ingress
// and NAT-scope renames passed every Go cell (issue mutant C). Every
// caller now resolves through the struct-scoped shared parser in
// rustwire_test.go: rustWireKeyInStruct (file + struct) or
// rustWireKeyInProtocolStruct (struct located by name under protocol/,
// the #7160 directory search, now also requiring exactly one struct
// declaration instead of silently taking the first field match).

// TestSecureTunnelWireKeyLockstepWithRust pins the JSON KEY of
// InterfaceSnapshot.SecureTunnel to the key userspace-dp decodes (#6691 round
// 12).
//
// The version guard is not this guard. Go ProtocolVersion and Rust
// CONFIG_SNAPSHOT_PROTOCOL_VERSION are both 7 and are held in lockstep by
// TestSnapshotProtocolVersionLockstepWithRust — but a version says only that
// both planes agree on what the fields MEAN. Rename the Go struct tag and both
// planes still report 7, so `apply_snapshot` accepts the snapshot; the field is
// simply ABSENT from the bytes and serde defaults it to false. Measured at
// 29b9b84c0: `json:"secure_tunnel,omitempty"` ->
// `json:"secureTunnelXX,omitempty"` left `go test ./pkg/dataplane/... ./pkg/daemon/...`
// at rc=0. The Rust fixture pins only a RUST-side rename; nothing pinned the Go
// emitter's key.
//
// THE FALSE CASE PROVES NOTHING ABOUT THE SPELLING, which is why this marshals
// a row with SecureTunnel = TRUE. The field is `omitempty` in Go and
// `skip_serializing_if = "std::ops::Not::not"` in Rust, so a false value is
// byte-absent by design on both planes — and a misspelled key is byte-absent
// too. Only the true case distinguishes them.
//
// FAIL-ON-REVERT: change the Go struct tag (or the Rust rename) without changing
// the other and this reds.
func TestSecureTunnelWireKeyLockstepWithRust(t *testing.T) {
	rustKey := rustWireKeyInStruct(t, filepath.Join("..", "..", "..", "userspace-dp", "src", "protocol", "snapshot.rs"), "InterfaceSnapshot", "secure_tunnel", false)

	row := InterfaceSnapshot{
		Name:      "st10",
		LinuxName: "st10",
		Ifindex:   11,
		Zone:      "vpn",
		// The verdict itself. Present on the row => an older helper plans an
		// AF_XDP binding this control plane refuses.
		SecureTunnel: true,
	}
	b, err := json.Marshal(row)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(b)
	want := `"` + rustKey + `":true`
	if !strings.Contains(got, want) {
		t.Fatalf("InterfaceSnapshot JSON %q does not carry %s. userspace-dp decodes this "+
			"verdict under the key %q (`#[serde(rename = ...)]` in protocol/snapshot.rs); a Go "+
			"emitter that spells it differently ships a snapshot in which the field is ABSENT, "+
			"serde defaults it to false, and the xfrmi gets the AF_XDP binding the #5619 "+
			"exclusion exists to refuse — with both planes reporting the same protocol version, "+
			"so the version gate cannot see it", got, want, rustKey)
	}

	// Round-trip, so the key is not merely PRESENT but is the one the Go
	// decoder reads back.
	var back InterfaceSnapshot
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !back.SecureTunnel {
		t.Fatalf("round-trip SecureTunnel = false, want true")
	}

	// The omitempty/skip_serializing_if AGREEMENT, asserted separately and
	// explicitly NOT as a key pin: a false row must be byte-absent on the Go
	// side because the Rust side is, so the two planes' default specimens
	// agree (wire_invariant_default_specimens regenerates from those bytes).
	quiet, err := json.Marshal(InterfaceSnapshot{Name: "ge-0/0/0", LinuxName: "ge-0-0-0", Ifindex: 20})
	if err != nil {
		t.Fatalf("marshal quiet: %v", err)
	}
	if strings.Contains(string(quiet), rustKey) {
		t.Errorf("InterfaceSnapshot JSON %q carries %q for a row that is not a secure tunnel: "+
			"Go must stay `omitempty` to match Rust's `skip_serializing_if`, or every default "+
			"specimen gains a field the Rust side does not emit", quiet, rustKey)
	}
}

// TestFabricParentUnbindableWireKeyLockstepWithRust pins the JSON KEY of
// FabricSnapshot.ParentUnbindable to the key userspace-dp decodes (#6691 round
// 12).
//
// This is the field the protocol moved 6 -> 7 for. It is the ONLY carrier of the
// device-level verdict for a fabric parent that has no interface stanza — a
// fabric MEMBER needs none — and the Rust plane cannot recompute it, because
// half its evidence is a Go-side RTM_GETLINK kind dump.
//
// Measured at 29b9b84c0: `json:"parent_unbindable"` ->
// `json:"parentUnbindableXX"` left both suites GREEN. The consequence is not
// cosmetic. An ownerless fabric parent that IS an xfrm device stops being
// refused: `replan_queues` admits it, the xfrmi reports 1 RX queue, and
// `replan_bindings_from_candidates` takes the GLOBAL MINIMUM — so every physical
// NIC drops to one queue and one worker. That is the #3091 ~6 Gbps
// single-worker regression, i.e. exactly what the v7 bump exists to prevent,
// reached with both planes reporting version 7.
//
// Both polarities are asserted because this field is deliberately NOT omitempty:
// an absent field decodes to false (bindable) in Rust, which is the pre-round-10
// behaviour, so a genuinely-unbindable parent must put `false` on the wire when
// it is bindable rather than letting absence stand in for it.
//
// FAIL-ON-REVERT: change the Go struct tag (or the Rust rename) without changing
// the other and this reds.
func TestFabricParentUnbindableWireKeyLockstepWithRust(t *testing.T) {
	rustKey := rustWireKeyInStruct(t, filepath.Join("..", "..", "..", "userspace-dp", "src", "protocol", "snapshot.rs"), "FabricSnapshot", "parent_unbindable", false)

	for _, tc := range []struct {
		name       string
		unbindable bool
	}{
		{name: "bindable", unbindable: false},
		{name: "unbindable", unbindable: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := json.Marshal(FabricSnapshot{
				Name:             "fab0",
				ParentLinuxName:  "ge-0-0-0",
				ParentIfindex:    20,
				ParentUnbindable: tc.unbindable,
			})
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			got := string(b)
			want := `"` + rustKey + `":` + map[bool]string{true: "true", false: "false"}[tc.unbindable]
			if !strings.Contains(got, want) {
				t.Fatalf("FabricSnapshot JSON %q does not carry %s. userspace-dp decodes the "+
					"fabric parent's device verdict under the key %q; a Go emitter that spells "+
					"it differently ships a snapshot with the field ABSENT, serde defaults it to "+
					"false, and an unbindable ownerless parent is planned as an AF_XDP candidate "+
					"— collapsing the global queue count to the xfrmi's single queue (#3091). "+
					"The version gate cannot catch it: both planes still report %d",
					got, want, rustKey, ProtocolVersion)
			}

			var back FabricSnapshot
			if err := json.Unmarshal(b, &back); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if back.ParentUnbindable != tc.unbindable {
				t.Fatalf("round-trip ParentUnbindable = %v, want %v", back.ParentUnbindable, tc.unbindable)
			}
		})
	}

	// THE THIRD LEG. The Rust decoder is regression-tested against
	// tests/fixtures/protocol_wire_v1.json (wire_invariant_default_specimens
	// regenerates it), so asserting that the Go key appears in those literal
	// bytes closes the loop Go tag -> Rust rename -> the bytes Rust actually
	// decodes. Only possible for this field: `secure_tunnel` is
	// skip_serializing_if and so is absent from a default specimen by design.
	fixture := filepath.Join("..", "..", "..", "userspace-dp", "tests", "fixtures", "protocol_wire_v1.json")
	raw, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatalf("read %s: %v", fixture, err)
	}
	if !strings.Contains(string(raw), `"`+rustKey+`"`) {
		t.Errorf("%s does not contain the key %q that FabricSnapshot emits. The fixture is the "+
			"byte-level record of what this wire looks like; a fabric row missing this key there "+
			"means the specimen predates the v7 field or the key moved on one plane only",
			fixture, rustKey)
	}
}
