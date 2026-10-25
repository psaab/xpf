package dataplane

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// session_sync_parity_16176_test.go — #16176 (data-model P1a, parity test only).
//
// SessionValue and SessionValueV6 are hand-maintained twins. Their trailing
// HA-sync fields are duplicated verbatim, and the struct comments document
// the failure mode directly: a field added to the v4 value was once forgotten
// on v6 ("every IPv6 session degraded after a failover"). This file is the
// survivor of the SessionSyncMeta proposal after hostile review: it changes
// NO struct, NO composite literal and NO existing census — it only pins that
// the twins cannot drift apart and that every field is classified. The embed
// is NOT endorsed by #16176 (promoted fields cannot be composite-literal
// keys, and the #7097 scrub census would silently weaken under an embed);
// do not add a SessionSyncMeta type on the strength of this file.
//
// ============================================================
// THE CLOSED CLASSIFICATION CENSUS (review fold for PR #16227)
// ============================================================
//
// Every field of SessionValue / SessionValueV6 — and every session-value
// field the cluster codec actually references — must belong to EXACTLY ONE
// of the classes below. The census is closed: it is driven by enumerating
// the Go structs by reflection and the codec by Go AST, NOT by iterating
// the declared lists. A field that appears in a struct or in the codec
// without a declaration fails by name ("unclassified field"), and a
// declaration that names nothing fails as stale. This closes the original
// fold finding: previously a new sync field added to both twins AND the
// codec escaped every guard because nothing ever asked about its name.
//
// The classes (a field's class is a property of WHERE it may live):
//
//   - ABI (on-map): present in bpfSessionValue/bpfSessionValueV6 and on the
//     Go twins. Most ABI fields are ALSO carried by the sync codec (State,
//     Flags, PolicyID, NAT addresses/ports, ReverseKey, RoutingDomain
//     #9546, the FIB result, counters, ...): that overlap is legitimate and
//     expected. Three ABI fields are NOT in the codec — AppID,
//     IngressIfindex, IngressVlanID — and must not be added to it: AppID is
//     re-derived from policy on the peer, and the ingress ifindex/vlan are
//     node-local (#4983) whose cluster-stable counterparts are the sync-wire
//     folds IngressIfaceFold/EgressIfaceFold. (An earlier draft of this file
//     defined ABI as "in BPF AND codec"; that was wrong for these three.)
//   - Sync-wire: present in the pkg/cluster session codec and on the Go
//     twins, but in NEITHER BPF ABI struct (Generation, PolicyCounterIdx,
//     ConfigEpoch, RTFlowSessionID, the folds, TunnelDiscriminator,
//     PptpCallIDs, TCPCloseClass, TCPHandshakeState, InstallTableDomain/
//     Check, SourceNatICMP*, PolicyRuleID, and v6-only Nat64SnatV4). These
//     MUST NOT be added to bpfSessionValue{,V6}: the maps are registered at
//     the C/Rust ABI size (152/200) and a sync-only field there over-sizes
//     value_size into the Rust helper's smaller lookup buffer (#2360).
//   - Go-local: present on the Go twins but in NEITHER the BPF ABI NOR the
//     sync codec. Exactly one field today: NatScopeIfindex (int32, both
//     twins), the NODE-LOCAL logical NAT-scope ingress ifindex recorded at
//     admission from the helper delta (#15176). An ifindex names a different
//     NIC on the peer, so the raw number must never cross the wire; what
//     crosses is NatScopeFold, the cluster-stable fold stamped from it at
//     sync_conn_gen.go (stampNatScopeFold). Do not "fix" its absence from
//     either the ABI or the codec.
//
// CORRECTED BOUNDARY RULE (#16176's mandated form; the report's literal
// "no sync-wire field name appears in bpfSessionValue" is UNSOUND and
// already false):
//
//	No field that exists ONLY for HA sync — i.e. present in the sync codec
//	but in neither BPF struct's field set — may be added to
//	bpfSessionValue or bpfSessionValueV6.
//
// FAMILY EXCEPTIONS (the parity universe): parity is asserted over field
// name+type after removing exactly NATSrcIP/NATDstIP (uint32 vs [16]byte),
// ReverseKey (SessionKey vs SessionKeyV6) and v6-only Nat64SnatV4. Their
// exact per-family types are pinned in the parity test, not just presence.

// sessionClass16176 names the one class a session field belongs to.
type sessionClass16176 string

const (
	classABI16176      sessionClass16176 = "ABI"
	classSyncWire16176 sessionClass16176 = "sync-wire"
	classGoLocal16176  sessionClass16176 = "Go-local"
)

// fieldClass16176 is one classified field: its class and WHY. A class entry
// without a justification, or a justification for a field that no longer
// exists, fails the census — classification is a reviewed decision, not a
// name list.
type fieldClass16176 struct {
	class sessionClass16176
	why   string
}

// abiSessionFields16176 are the on-map fields (present in both
// bpfSessionValue/bpfSessionValueV6 and on both Go twins). Most are also
// codec-carried; the three marked ABI-only are deliberately absent from the
// wire. NAT addresses/ports and ReverseKey are ABI on both families under
// the same names (their per-family TYPES differ — see the parity test).
var abiSessionFields16176 = map[string]string{
	"State":          "C session_value.state; codec-carried",
	"Flags":          "C flags (uint16 since #5460); codec low byte + high-byte trailer",
	"TCPState":       "C tcp_state; codec-carried (distinct from sync-only TCPCloseClass)",
	"IsReverse":      "C is_reverse; codec-carried",
	"AppTimeout":     "C app_timeout; codec-carried as a length-gated trailer (#3301 encoding)",
	"SessionID":      "node-local conntrack id; codec-carried for correlation, never a lookup key",
	"Created":        "install timestamp; codec-carried",
	"LastSeen":       "last-seen timestamp; codec-carried",
	"Timeout":        "inactivity timeout; codec-carried",
	"PolicyID":       "admitting policy id; codec-carried",
	"IngressZone":    "ingress zone id; codec-carried",
	"EgressZone":     "egress zone id; codec-carried",
	"NATSrcIP":       "translated source address; codec-carried (width differs by family)",
	"NATDstIP":       "translated destination address; codec-carried (width differs by family)",
	"NATSrcPort":     "translated source port; codec-carried",
	"NATDstPort":     "translated destination port; codec-carried",
	"FwdPackets":     "forward packet counter; codec-carried",
	"FwdBytes":       "forward byte counter; codec-carried",
	"RevPackets":     "reverse packet counter; codec-carried",
	"RevBytes":       "reverse byte counter; codec-carried",
	"ReverseKey":     "embedded reverse 5-tuple; codec-carried field-by-field (key type differs by family)",
	"ALGType":        "ALG tag; codec-carried with direction revalidation (#11672)",
	"LogFlags":       "log/userspace flag bits; codec-carried",
	"AppID":          "ABI-only: identified application; NOT codec-carried (re-derived from policy on the peer)",
	"FibIfindex":     "cached FIB egress ifindex; codec-carried but scrubbed node-local on peer install (#7097)",
	"FibVlanID":      "cached FIB egress vlan; codec-carried, scrubbed on peer install",
	"FibDmac":        "cached FIB destination MAC; codec-carried, scrubbed on peer install",
	"FibSmac":        "cached FIB source MAC; codec-carried, scrubbed on peer install",
	"FibGen":         "FIB generation / tunnel-endpoint id under its LogFlags bit; codec-carried",
	"IngressIfindex": "ABI-only: #4983 node-local ingress ifindex; NOT codec-carried (node-local; the wire carries IngressIfaceFold instead)",
	"IngressVlanID":  "ABI-only: #4983 ingress vlan; NOT codec-carried (same node-local reason as IngressIfindex)",
	"RoutingDomain":  "#9546 on-map routing domain; codec-carried at its own trailing slot (#7239)",
}

// abiOnlySessionFields16176 are the ABI fields deliberately absent from the
// sync codec. Derived from abiSessionFields16176 is NOT possible (the why
// strings are prose), so this subset is declared explicitly and the census
// cross-checks it against the AST-discovered codec set both ways.
var abiOnlySessionFields16176 = map[string]bool{
	"AppID":          true,
	"IngressIfindex": true,
	"IngressVlanID":  true,
}

// syncWireOnlySessionFields16176 are the fields that exist only for HA sync:
// in the cluster codec (and the Go twins) but in neither BPF ABI struct.
// Nat64SnatV4 is the sole v6-only member.
var syncWireOnlySessionFields16176 = map[string]string{
	"Generation":          "#2170 install generation for the deferred-delete guard",
	"PolicyCounterIdx":    "#3301 per-rule hit-counter handle",
	"ConfigEpoch":         "#5274 admitting config epoch",
	"RTFlowSessionID":     "#5212 originating node's stable RT_FLOW session id",
	"IngressIfaceFold":    "#7095 cluster-stable ingress-interface name fold",
	"EgressIfaceFold":     "#12075 cluster-stable egress-interface name fold",
	"NatScopeFold":        "#15176 cluster-stable NAT-scope fold (the wire form of Go-local NatScopeIfindex)",
	"TunnelDiscriminator": "#7188 tunnel session-identity discriminator",
	"PptpCallIDs":         "#13965 learned PPTP call-id pair",
	"TCPCloseClass":       "#9412 TCP close class (deliberately not TCPState)",
	"TCPHandshakeState":   "#10888 TCP handshake phase",
	"InstallTableDomain":  "#9752 installing route-table domain id",
	"InstallTableCheck":   "#9752 installing route-table owner check",
	"SourceNatICMPValid":  "#11064 source-NAT ICMP identity validity bit",
	"SourceNatICMPType":   "#11064 source-NAT ICMP type",
	"SourceNatICMPCode":   "#11064 source-NAT ICMP code",
	"PolicyRuleID":        "#11070 stable admitting-rule identity (string, tail-carried)",
	"PrimaryLiveness":     "#16880 low-rate primary-side liveness marker; sync-only, never in either BPF ABI",
	"Nat64SnatV4":         "#4565 v6-only NAT64 pool source; NO v4 member by design (v6-only exception)",
}

// goLocalSessionFields16176 are on the Go twins only: neither ABI nor codec.
var goLocalSessionFields16176 = map[string]string{
	"NatScopeIfindex": "#15176 node-local logical NAT-scope ifindex from the helper delta; never crosses the wire raw — only its cluster-stable fold NatScopeFold does (stampNatScopeFold, sync_conn_gen.go). No BPF slot, no wire slot, by design",
}

// sessionSyncParityExclusions16176 are the four family exceptions removed
// before the name+type parity comparison. Nat64SnatV4 is also declared
// sync-wire above; the others are ABI fields whose TYPES differ by family.
var sessionSyncParityExclusions16176 = map[string]string{
	"NATSrcIP":    "NAT address width: uint32 (v4) vs [16]byte (v6)",
	"NATDstIP":    "NAT address width: uint32 (v4) vs [16]byte (v6)",
	"ReverseKey":  "reverse 5-tuple key type follows the address family: SessionKey vs SessionKeyV6",
	"Nat64SnatV4": "v6-only NAT64 pool source (#4565); no v4 counterpart exists by design",
}

// sessionClassification16176 merges the three class maps and rejects overlap:
// a field declared in two classes is a census bug, not a choice.
func sessionClassification16176(t *testing.T) map[string]fieldClass16176 {
	t.Helper()
	out := make(map[string]fieldClass16176)
	add := func(m map[string]string, class sessionClass16176) {
		for name, why := range m {
			if why == "" {
				t.Errorf("classified field %s (%s) has no justification (#16176)", name, class)
			}
			if prev, dup := out[name]; dup {
				t.Errorf("field %s classified twice: %s and %s — exactly one class is allowed (#16176)", name, prev.class, class)
			}
			out[name] = fieldClass16176{class: class, why: why}
		}
	}
	add(abiSessionFields16176, classABI16176)
	add(syncWireOnlySessionFields16176, classSyncWire16176)
	add(goLocalSessionFields16176, classGoLocal16176)
	return out
}

// sessionFieldTypes returns name -> type string for every field of typ,
// skipping blank padding fields (the explicit `_ [N]byte` ABI pads, #6082).
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

func sortedSessionFieldNames16176[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// sessionCodecFuncs16176 are the four session codec functions whose bodies
// define wire membership. Scoping discovery to these functions (instead of
// the whole file) is what keeps delete/IPsec/DHCP codecs and unrelated
// helpers from contaminating the census.
var sessionCodecFuncs16176 = map[string]bool{
	"encodeSessionV4Payload": true,
	"encodeSessionV6Payload": true,
	"decodeSessionV4Payload": true,
	"decodeSessionV6Payload": true,
	// The shared metadata tail both encoders delegate to (PolicyRuleID,
	// TCPHandshakeState, EgressIfaceFold, NatScopeFold carrier).
	"appendSessionSyncMetadataTail": true,
	"appendPptpCallIDs":             true,
	// #16173: the shared sessionTail ladder both codec families delegate
	// the length-gated trailing fields to. Its fields arrive as the
	// sessionTail struct (built by the per-family views below), so its
	// contribution is recovered from the tail struct's field names —
	// see collectTailRefs16176.
	"encodeSessionTailPreNat64":  true,
	"encodeSessionTailPostNat64": true,
	"decodeSessionTailPreNat64":  true,
	"decodeSessionTailPostNat64": true,
	// Per-family views adapting SessionValue/V6 to sessionTail.
	"sessionTail":    true,
	"setSessionTail": true,
}

// codecFieldRefs16176 is the AST-discovered codec membership for one family:
// which session-value fields each codec direction touches.
type codecFieldRefs16176 struct {
	encode map[string]bool
	decode map[string]bool
}

// sessionCodecFieldRefs16176 parses pkg/cluster/sync_protocol.go with
// go/parser (syntax-aware: comments and string literals are not selector
// expressions and can never register) and collects, per family and
// direction, the field names selected on the codec's session-value
// variables:
//
//   - encode: `val.Field` reads in encodeSession{,V6}Payload (plus the
//     shared tail helpers' parameters — see below);
//   - decode: `val.Field` writes (selector on the left of an assignment,
//     or passed by pointer) in decodeSession{,V6}Payload.
//
// The shared tail (appendSessionSyncMetadataTail / appendPptpCallIDs)
// receives individual fields as arguments rather than the value, so its
// contribution is recovered from the CALL SITES inside the encoders:
// each argument that is a `val.Field` selector counts, in argument order.
// The helper's own parameter references are never counted — a comment or
// an unrelated function mentioning a field name therefore cannot satisfy
// or break the census (this replaces the previous raw `.Name` text scan,
// which did exactly that).
//
// Deliberately NOT discovered here: fields reached only through the
// helper-delta conversion in pkg/daemon or the userspace request path.
// Wire membership means the cluster session codec only; a field carried
// solely on the helper delta belongs to the Go-local class with that
// stated in its justification.
func sessionCodecFieldRefs16176(t *testing.T) (v4, v6 codecFieldRefs16176) {
	t.Helper()
	v4 = codecFieldRefs16176{encode: map[string]bool{}, decode: map[string]bool{}}
	v6 = codecFieldRefs16176{encode: map[string]bool{}, decode: map[string]bool{}}

	path := filepath.Join(headroomRepoRoot(t), "pkg", "cluster", "sync_protocol.go")
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse sync codec %s: %v", path, err)
	}

	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || !sessionCodecFuncs16176[fn.Name.Name] {
			continue
		}
		switch fn.Name.Name {
		case "encodeSessionV4Payload":
			collectEncodeRefs16176(fn, v4.encode)
		case "encodeSessionV6Payload":
			collectEncodeRefs16176(fn, v6.encode)
		case "decodeSessionV4Payload":
			collectDecodeRefs16176(fn, v4.decode)
		case "decodeSessionV6Payload":
			collectDecodeRefs16176(fn, v6.decode)
		case "sessionTail":
			// #16173 view getters: val.<Field> reads feeding the shared
			// tail belong to BOTH families' encode sets (each view is
			// per-family, but the tail fields are symmetric by census).
			if recv := fn.Recv; recv != nil && len(recv.List) > 0 {
				collectEncodeRefs16176(fn, v4.encode)
				collectEncodeRefs16176(fn, v6.encode)
			}
		case "setSessionTail":
			if recv := fn.Recv; recv != nil && len(recv.List) > 0 {
				collectDecodeRefs16176(fn, v4.decode)
				collectDecodeRefs16176(fn, v6.decode)
			}
		case "encodeSessionTailPreNat64", "encodeSessionTailPostNat64":
			collectTailRefs16176(fn, v4.encode, v6.encode)
		case "decodeSessionTailPreNat64", "decodeSessionTailPostNat64":
			collectTailRefs16176(fn, v4.decode, v6.decode)
		}
	}
	if len(v4.encode) == 0 || len(v4.decode) == 0 || len(v6.encode) == 0 || len(v6.decode) == 0 {
		t.Fatalf("codec AST census found an empty direction (v4 enc=%d dec=%d, v6 enc=%d dec=%d) — "+
			"the codec functions were renamed or the parser scope is wrong (#16176)",
			len(v4.encode), len(v4.decode), len(v6.encode), len(v6.decode))
	}
	return v4, v6
}

// collectEncodeRefs16176 records every `val.<Field>` selector read inside an
// encoder, including selectors passed as arguments to the shared tail
// helpers (the tail's fields arrive exactly that way).
func collectEncodeRefs16176(fn *ast.FuncDecl, out map[string]bool) {
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); ok && id.Name == "val" {
			out[sel.Sel.Name] = true
		}
		return true
	})
}

// collectDecodeRefs16176 records every `val.<Field>` selector that is
// WRITTEN in a decoder (assignment LHS, compound assignment, ++/--, or the
// copy() destination head). Plain reads (e.g. `val.TunnelDiscriminator`
// inspected to locate the PPTP tail) do not by themselves put a field on
// the wire in the decode direction, so they are not counted here; the
// census requires decode-membership to mean "the decoder restores it".
func collectDecodeRefs16176(fn *ast.FuncDecl, out map[string]bool) {
	record := func(expr ast.Expr) {
		// Unwrap indexing/slicing/parentheses to the selector they write
		// through: copy(val.FibDmac[:], ...) writes FibDmac, and
		// val.ReverseKey.SrcPort = ... writes ReverseKey (the nested
		// selector's head is the session field; its leaf is a key field).
		for {
			switch e := expr.(type) {
			case *ast.SelectorExpr:
				if id, ok := e.X.(*ast.Ident); ok && id.Name == "val" {
					out[e.Sel.Name] = true
					return
				}
				expr = e.X
			case *ast.IndexExpr:
				expr = e.X
			case *ast.SliceExpr:
				expr = e.X
			case *ast.ParenExpr:
				expr = e.X
			default:
				return
			}
		}
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range node.Lhs {
				// `val.Field = ...` (incl. `val.Flags |= ...`) and nested
				// writes like `val.ReverseKey.SrcPort = ...`.
				record(lhs)
			}
		case *ast.IncDecStmt:
			record(node.X)
		case *ast.ExprStmt:
			// `copy(val.Field[:], payload[...])` writes the field through
			// a slice of it.
			call, ok := node.X.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "copy" {
				record(call.Args[0])
			}
		}
		return true
	})
}

// collectTailRefs16176 recovers the #16173 shared-tail membership: the
// tail helpers select fields on a sessionTail value (receiver/param
// named t), whose field names are exactly the session-value field
// names, plus FlagsHigh which the views expand into Flags. Every such
// selector counts for both families, encode or decode per helper.
func collectTailRefs16176(fn *ast.FuncDecl, outs ...map[string]bool) {
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); ok && (id.Name == "t" || id.Name == "tail") {
			name := sel.Sel.Name
			if name == "FlagsHigh" {
				name = "Flags"
			}
			for _, out := range outs {
				out[name] = true
			}
		}
		return true
	})
}

// codecTailFields16176 are the fields the encoders pass to the shared
// metadata tail. They are discovered from the encoder AST like every other
// field; this list exists only so the census can assert the tail delegation
// itself is still wired (deleting the return-tail call would otherwise drop
// five fields from the encode set and read as "five fields left the codec"
// rather than "the tail broke"). Kept next to the mechanism it pins.
var codecTailFields16176 = []string{"PolicyRuleID", "TCPHandshakeState", "EgressIfaceFold", "PptpCallIDs", "NatScopeFold"}

// TestSessionValueSyncFieldParity16176 is the decisive #16176 check: after
// removing the declared family exceptions, SessionValue and SessionValueV6
// must have IDENTICAL field name+type sets. A field added to one twin only
// (the historical "forgot V6" defect), or re-typed on one twin only, fails
// here naming the field and both types.
//
// RED PROOF (performed at authoring, recorded in the PR): planting
// `ParityPlant uint32 // TEMP` on SessionValue only makes this test fail
// naming ParityPlant as v4-only; removing the plant returns it to green.
// The plant is not shipped.
func TestSessionValueSyncFieldParity16176(t *testing.T) {
	v4 := sessionFieldTypes(reflect.TypeOf(SessionValue{}))
	v6 := sessionFieldTypes(reflect.TypeOf(SessionValueV6{}))

	// Every exclusion must name a real field (a rename must not leave a
	// stale exemption), and the excluded fields' exact per-family types are
	// pinned — presence alone would let a width edit hide behind the
	// exclusion (PR #16227 review, claim 1 remedy).
	for name := range sessionSyncParityExclusions16176 {
		_, in4 := v4[name]
		_, in6 := v6[name]
		if !in4 && !in6 {
			t.Errorf("parity exclusion %q names a field present on NEITHER twin — "+
				"stale exclusion; remove it or fix the rename (#16176)", name)
		}
	}
	for name, want := range map[string][2]string{
		"NATSrcIP":   {"uint32", "[16]uint8"},
		"NATDstIP":   {"uint32", "[16]uint8"},
		"ReverseKey": {"dataplane.SessionKey", "dataplane.SessionKeyV6"},
	} {
		if got := v4[name]; got != want[0] {
			t.Errorf("SessionValue.%s = %s, want %s (excluded from parity only for this exact width/key difference; #16176)", name, got, want[0])
		}
		if got := v6[name]; got != want[1] {
			t.Errorf("SessionValueV6.%s = %s, want %s (excluded from parity only for this exact width/key difference; #16176)", name, got, want[1])
		}
	}
	if _, ok := v4["Nat64SnatV4"]; ok {
		t.Error("Nat64SnatV4 appeared on SessionValue: it is v6-only by design (#4565); " +
			"a v4 copy needs a stated reason and must leave the exclusion set (#16176)")
	}
	if got, ok := v6["Nat64SnatV4"]; !ok || got != "[4]uint8" {
		t.Errorf("SessionValueV6.Nat64SnatV4 = %q (present=%v), want [4]uint8 (#4565/#16176)", got, ok)
	}

	for name := range sessionSyncParityExclusions16176 {
		delete(v4, name)
		delete(v6, name)
	}

	for _, name := range sortedSessionFieldNames16176(v4) {
		got6, ok := v6[name]
		if !ok {
			t.Errorf("field %s %s is in SessionValue only — mirror it on SessionValueV6 "+
				"or declare it in sessionSyncParityExclusions16176 with its reason (#16176: the "+
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
				"or declare it in sessionSyncParityExclusions16176 with its reason (#16176)",
				name, v6[name])
		}
	}
}

// TestSessionFieldClassificationIsExhaustive16176 is the closed census from
// the PR #16227 fold. It enumerates the actual field universe — both Go
// twins, both BPF mirrors, and the AST-discovered codec references — and
// requires every name in that universe to be classified in exactly one
// class, every classification to name a real field, and each class's
// membership to match its definition:
//
//   - ABI: on both BPF mirrors and both Go twins; in the codec unless
//     declared ABI-only (AppID, IngressIfindex, IngressVlanID).
//   - Sync-wire: in the codec (encode AND decode, both families except the
//     v6-only Nat64SnatV4), on the Go twins, and in NEITHER BPF mirror —
//     the corrected boundary rule.
//   - Go-local: on both Go twins; in neither BPF mirror and not referenced
//     by the codec in either direction or family.
//
// A maintainer who adds a field to both twins and the codec without
// classifying it fails HERE, by name, even though parity passes — that was
// the fold's counterexample. Classifying a sync field and then adding it
// to a BPF mirror fails the sync-wire "neither BPF mirror" check.
//
// Helper self-check: TestCodecFieldRefsIgnoreComments16176 proves the AST
// discovery cannot be satisfied or broken by comment/string mentions.
func TestSessionFieldClassificationIsExhaustive16176(t *testing.T) {
	class := sessionClassification16176(t)
	goV4 := sessionFieldTypes(reflect.TypeOf(SessionValue{}))
	goV6 := sessionFieldTypes(reflect.TypeOf(SessionValueV6{}))
	abiV4 := sessionFieldTypes(reflect.TypeOf(bpfSessionValue{}))
	abiV6 := sessionFieldTypes(reflect.TypeOf(bpfSessionValueV6{}))
	codecV4, codecV6 := sessionCodecFieldRefs16176(t)

	// The shared tail must still be wired into both encoders. Since
	// #16173 the fields reach the metadata tail through the shared
	// sessionTail (per-family views -> encodeSessionTailPostNat64 ->
	// appendSessionSyncMetadataTail); encode-set membership in both
	// families is the wired proof.
	for _, name := range codecTailFields16176 {
		if !codecV4.encode[name] || !codecV6.encode[name] {
			t.Errorf("codec tail field %s is no longer carried by the shared session tail in both encoders — "+
				"the tail delegation changed; re-derive the codec census (#16176)", name)
		}
	}

	// Universe: every name seen anywhere must be classified exactly once.
	// (sessionClassification16176 already rejects double classification.)
	universe := map[string]bool{}
	for _, set := range []map[string]string{goV4, goV6, abiV4, abiV6} {
		for name := range set {
			universe[name] = true
		}
	}
	for _, refs := range []codecFieldRefs16176{codecV4, codecV6} {
		for name := range refs.encode {
			universe[name] = true
		}
		for name := range refs.decode {
			universe[name] = true
		}
	}
	for _, name := range sortedSessionFieldNames16176(universe) {
		if _, ok := class[name]; !ok {
			t.Errorf("unclassified session field %s: present in a Go twin, a BPF mirror, or the cluster codec "+
				"but declared in no class — classify it in exactly one of abiSessionFields16176 / "+
				"syncWireOnlySessionFields16176 / goLocalSessionFields16176 with its justification (#16176)", name)
		}
	}
	// And every classification must name a field that exists (in a Go twin
	// or the codec); a stale entry silently guards nothing.
	for _, name := range sortedSessionFieldNames16176(class) {
		if !universe[name] {
			t.Errorf("classified field %s (%s) exists in no Go twin, BPF mirror, or codec reference — "+
				"stale classification entry; remove or rename it (#16176)", name, class[name].class)
		}
	}

	// ABI mirrors must agree with each other by name (their TYPES differ by
	// family for the NAT addresses and ReverseKey, exactly like the Go
	// twins; the size/offset pins live in bpf_session_value_test.go).
	for _, name := range sortedSessionFieldNames16176(abiV4) {
		if _, ok := abiV6[name]; !ok {
			t.Errorf("bpfSessionValue field %s has no bpfSessionValueV6 counterpart (#16176)", name)
		}
	}
	for _, name := range sortedSessionFieldNames16176(abiV6) {
		if _, ok := abiV4[name]; !ok {
			t.Errorf("bpfSessionValueV6 field %s has no bpfSessionValue counterpart (#16176)", name)
		}
	}

	// Per-class membership, checked against the discovered sets.
	for _, name := range sortedSessionFieldNames16176(class) {
		fc := class[name]
		_, inGo4 := goV4[name]
		_, inGo6 := goV6[name]
		_, inABI4 := abiV4[name]
		_, inABI6 := abiV6[name]
		enc := codecV4.encode[name] || codecV6.encode[name]
		dec := codecV4.decode[name] || codecV6.decode[name]

		switch fc.class {
		case classABI16176:
			if !inGo4 || !inGo6 {
				t.Errorf("ABI field %s must be present on both Go twins (v4=%v v6=%v) (#16176)", name, inGo4, inGo6)
			}
			if !inABI4 || !inABI6 {
				t.Errorf("ABI field %s must be present in both BPF mirrors (v4=%v v6=%v); "+
					"if it left the ABI it is sync-wire or Go-local now — reclassify (#16176)", name, inABI4, inABI6)
			}
			if abiOnlySessionFields16176[name] {
				if enc || dec {
					t.Errorf("ABI-only field %s is now referenced by the cluster codec (enc=%v dec=%v) — "+
						"it stopped being ABI-only; remove it from abiOnlySessionFields16176 and state the wire "+
						"contract in its justification, or take it back out of the codec (#16176)", name, enc, dec)
				}
			} else {
				// ABI fields carried by the codec must round-trip: encoded
				// and decoded in BOTH families (their widths differ, their
				// presence does not).
				if !codecV4.encode[name] || !codecV6.encode[name] || !codecV4.decode[name] || !codecV6.decode[name] {
					t.Errorf("codec-carried ABI field %s is not encoded+decoded in both families "+
						"(v4 enc=%v dec=%v; v6 enc=%v dec=%v) — wire presence drifted from the ABI class (#16176)",
						name, codecV4.encode[name], codecV4.decode[name], codecV6.encode[name], codecV6.decode[name])
				}
			}
		case classSyncWire16176:
			if inABI4 || inABI6 {
				t.Errorf("sync-wire field %s was added to a BPF mirror (v4=%v v6=%v) — sync-only fields "+
					"must stay out of bpfSessionValue{,V6} (#16176 corrected boundary; #2360)", name, inABI4, inABI6)
			}
			if name == "Nat64SnatV4" {
				// The one declared v6-only member: v6 twin + v6 codec only.
				if inGo4 || !inGo6 {
					t.Errorf("v6-only sync field Nat64SnatV4 must be on SessionValueV6 only (v4=%v v6=%v) (#4565/#16176)", inGo4, inGo6)
				}
				if codecV4.encode[name] || codecV4.decode[name] || !codecV6.encode[name] || !codecV6.decode[name] {
					t.Errorf("Nat64SnatV4 must be encoded+decoded by the v6 codec only (v4 enc=%v dec=%v; v6 enc=%v dec=%v) (#16176)",
						codecV4.encode[name], codecV4.decode[name], codecV6.encode[name], codecV6.decode[name])
				}
				break
			}
			if !inGo4 || !inGo6 {
				t.Errorf("sync-wire field %s must be present on both Go twins (v4=%v v6=%v); "+
					"a one-family sync field needs the Nat64SnatV4-style v6-only declaration (#16176)", name, inGo4, inGo6)
			}
			if !codecV4.encode[name] || !codecV6.encode[name] || !codecV4.decode[name] || !codecV6.decode[name] {
				t.Errorf("sync-wire field %s is not encoded+decoded in both codec families "+
					"(v4 enc=%v dec=%v; v6 enc=%v dec=%v) — it is declared sync-wire but does not fully "+
					"cross the wire; fix the codec or reclassify (#16176)",
					name, codecV4.encode[name], codecV4.decode[name], codecV6.encode[name], codecV6.decode[name])
			}
		case classGoLocal16176:
			if !inGo4 || !inGo6 {
				t.Errorf("Go-local field %s must be present on both Go twins (v4=%v v6=%v) (#16176)", name, inGo4, inGo6)
			}
			if inABI4 || inABI6 {
				t.Errorf("Go-local field %s was added to a BPF mirror (v4=%v v6=%v) (#16176)", name, inABI4, inABI6)
			}
			if enc || dec {
				t.Errorf("Go-local field %s is now referenced by the cluster codec (enc=%v dec=%v) — "+
					"the raw node-local value crosses the wire; reclassify it sync-wire with its fold "+
					"contract or take it back out of the codec (#16176)", name, enc, dec)
			}
		}
	}

	// The ABI-only declared set must be exactly the ABI fields the codec
	// does not reference: an ABI field dropping out of the codec, or an
	// undeclared one never in it, is a classification event either way.
	for _, name := range sortedSessionFieldNames16176(abiSessionFields16176) {
		inCodec := codecV4.encode[name] || codecV6.encode[name] || codecV4.decode[name] || codecV6.decode[name]
		if abiOnlySessionFields16176[name] && inCodec {
			t.Errorf("field %s declared ABI-only but referenced by the codec (#16176)", name)
		}
		if !abiOnlySessionFields16176[name] && !inCodec {
			t.Errorf("ABI field %s is referenced by neither codec direction nor family but is not declared "+
				"ABI-only — declare it in abiOnlySessionFields16176 with its reason, or wire it (#16176)", name)
		}
	}
	for name := range abiOnlySessionFields16176 {
		if _, ok := abiSessionFields16176[name]; !ok {
			t.Errorf("abiOnlySessionFields16176 names %s, which is not an ABI-classified field (#16176)", name)
		}
	}
}

// TestSyncOnlyFieldsStayOutOfTheBPFABI16176 encodes the CORRECTED boundary
// rule from #16176 in its positive form: the sync-wire set is DISCOVERED
// from the codec AST (not restated), and every discovered codec field that
// is in neither BPF mirror must be a declared sync-wire field — while the
// declared sync-wire fields must all be genuinely codec-carried and absent
// from both mirrors. It deliberately does NOT assert the report's literal
// form ("no sync-wire field name appears in bpfSessionValue"), which is
// already false: State, Flags, PolicyID, the NAT addresses/ports and
// ReverseKey are carried by the codec AND are legitimate ABI fields. That
// intentional overlap is pinned as a positive control, so a future "fix"
// that drops an ABI field to satisfy the literal reading fails here.
//
// The exhaustive census (TestSessionFieldClassificationIsExhaustive16176)
// is the general guard; this test keeps the boundary rule readable as a
// single statement and catches the specific regression the issue names:
// a sync-only field migrating into a map-ABI struct.
func TestSyncOnlyFieldsStayOutOfTheBPFABI16176(t *testing.T) {
	abiV4 := sessionFieldTypes(reflect.TypeOf(bpfSessionValue{}))
	abiV6 := sessionFieldTypes(reflect.TypeOf(bpfSessionValueV6{}))
	codecV4, codecV6 := sessionCodecFieldRefs16176(t)
	class := sessionClassification16176(t)

	// Discovered boundary: any field the codec touches that is in neither
	// mirror is sync-only BY CONSTRUCTION here — and must be declared so.
	discovered := map[string]bool{}
	for _, refs := range []codecFieldRefs16176{codecV4, codecV6} {
		for name := range refs.encode {
			discovered[name] = true
		}
		for name := range refs.decode {
			discovered[name] = true
		}
	}
	for _, name := range sortedSessionFieldNames16176(discovered) {
		_, inABI4 := abiV4[name]
		_, inABI6 := abiV6[name]
		fc, classified := class[name]
		if !inABI4 && !inABI6 {
			if !classified || fc.class != classSyncWire16176 {
				t.Errorf("codec field %s is in neither BPF mirror but is not classified sync-wire "+
					"(classified=%v) — declare it in syncWireOnlySessionFields16176 or it is unguarded (#16176)", name, classified)
			}
			continue
		}
		// In a mirror: it must be ABI-classified. (It cannot be sync-wire —
		// the census checks that direction; this keeps the boundary test
		// self-contained.)
		if !classified || fc.class != classABI16176 {
			t.Errorf("codec field %s is present in a BPF mirror but classified %v — "+
				"only ABI fields may occupy the mirrors (#16176)", name, fc.class)
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
		if !discovered[name] {
			t.Errorf("shared codec+ABI field %s is no longer discovered in the codec — "+
				"the positive control lost its codec half (#16176)", name)
		}
	}
}

// TestCodecFieldRefsIgnoreComments16176 is the census's own guard: the AST
// discovery must not be satisfiable — or breakable — by comment or string
// mentions of a field name, which is what made the previous raw text scan
// fragile (PR #16227 claim 3). It parses a synthetic source snippet with
// the same collector functions and requires that only real selector writes
// and reads register.
func TestCodecFieldRefsIgnoreComments16176(t *testing.T) {
	src := `package codecfixture

// val.Generation mentioned in a comment must not register.
// val.NatScopeIfindex in a comment must not register either.
const note = "val.ConfigEpoch inside a string must not register"

type value struct{ Generation, ConfigEpoch, NatScopeIfindex, Real uint64 }

func encodeSessionV4Payload(val value) {
	_ = val.Real
	// val.Generation in a trailing comment.
}

func decodeSessionV4Payload(val *value) {
	// val.NatScopeIfindex in a decoder comment.
	val.Real = 1
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "fixture.go", src, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	enc := map[string]bool{}
	dec := map[string]bool{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		switch fn.Name.Name {
		case "encodeSessionV4Payload":
			// The collectors key on the receiver name "val"; the fixture
			// uses a value (not pointer) precisely as the real encoders do.
			collectEncodeRefs16176(fn, enc)
		case "decodeSessionV4Payload":
			// Real decoders declare `var val dataplane.SessionValue` and
			// write val.Field; the fixture's pointer receiver still yields
			// the same selector shape the collector inspects.
			collectDecodeRefs16176(fn, dec)
		}
	}
	if !enc["Real"] || len(enc) != 1 {
		t.Errorf("encode discovery = %v, want exactly {Real}: comment/string mentions must not register (#16176)", enc)
	}
	if !dec["Real"] || len(dec) != 1 {
		t.Errorf("decode discovery = %v, want exactly {Real}: comment/string mentions must not register (#16176)", dec)
	}
}
