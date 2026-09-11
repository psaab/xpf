package userspace

import (
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #9146: the HA session-sync DELETE wire carried no routing domain, so a
// standby's delete hit #8636's ambiguous-routing-domain refusal.
//
// THE MEASUREMENT THAT RESOLVED IT. The issue was filed NEEDS_VALIDATION with
// one link explicitly not established: whether a standby can ever hold two
// synced sessions with the SAME 5-tuple in two DIFFERENT non-zero routing
// domains, which is what the refusal requires. The validator could only see
// "alternation" as a route and did not demonstrate it. It is simpler than that,
// and the cells below measure it:
//
//  1. INSTALL and DELETE disagree by construction. Measured on the built wire
//     request:
//
//     upsert tenant A: 10.0.0.5:1234->10.0.0.9:443/6 routing_domain=100007
//     upsert tenant B: 10.0.0.5:1234->10.0.0.9:443/6 routing_domain=100008
//     DELETE         : 10.0.0.5:1234->10.0.0.9:443/6 routing_domain=0
//
//  2. Swapping the tenant behind one bare 5-tuple emits NO delete. Measured on
//     a recording session socket: two upserts, ZERO deletes. The Go mirror is
//     bare-keyed so it remembers one row, but nothing retracts the row the
//     STANDBY already holds — and the standby keys synced sessions BY domain,
//     which the in-tree #8636 fixture already proves (two tenants x
//     forward+reverse = 4 rows, `state_holding_the_same_tuple_in`).
//
//  3. The helper then matches two domains and REFUSES — pinned in-tree by
//     `an_ambiguous_bare_tuple_delete_is_refused_and_touches_nothing_8636`.
//
// So no alternation is needed: two tenants sharing a 5-tuple is the ordinary
// case for overlapping VRF address space, and is exactly the #8636 fixture.
// That resolves the issue as MATERIAL rather than NEG.
//
// FAIL-ON-REVERT: pass nil instead of the scope value at either delete site and
// TestDeleteNamesTheInstalledRoutingDomain9146 goes RED.

type syncRec9146 struct {
	ln   net.Listener
	mu   sync.Mutex
	reqs []SessionSyncRequest
	// refusal, when set, is the in-band error the FIRST request is answered with
	// (#9714); every other request is answered OK.
	refusal string
}

// refuseFirst makes the recorder answer its first request with the in-band error
// refusal, as the helper answers a delete it refused (#9714).
func (r *syncRec9146) refuseFirst(refusal string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.refusal = refusal
}

func (r *syncRec9146) all() []SessionSyncRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]SessionSyncRequest(nil), r.reqs...)
}

func startSyncRec9146(t *testing.T, sock string) *syncRec9146 {
	t.Helper()
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	r := &syncRec9146{ln: ln}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				var req ControlRequest
				if json.NewDecoder(conn).Decode(&req) != nil {
					return
				}
				resp := ControlResponse{OK: true}
				if req.SessionSync != nil {
					r.mu.Lock()
					r.reqs = append(r.reqs, *req.SessionSync)
					if len(r.reqs) == 1 && r.refusal != "" {
						resp = ControlResponse{OK: false, Error: r.refusal}
					}
					r.mu.Unlock()
				}
				_ = json.NewEncoder(conn).Encode(resp)
			}()
		}
	}()
	return r
}

// newSyncOnlyManager9146 builds a Manager wired to a recording session socket.
// It touches NO BPF map, so it runs without CAP_BPF — the BPF-backed harnesses
// in this package skip when RemoveMemlock is denied, and the wire contract is
// exactly what this issue is about.
func newSyncOnlyManager9146(t *testing.T) (*Manager, *syncRec9146) {
	t.Helper()
	dir, err := os.MkdirTemp("", "x9146")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	m := New()
	m.proc = &exec.Cmd{}
	m.cfg.ControlSocket = filepath.Join(dir, "control.sock")
	rec := startSyncRec9146(t, filepath.Join(dir, "userspace-dp-sessions.sock"))
	return m, rec
}

func key9146() dataplane.SessionKey {
	return dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 0, 5}, DstIP: [4]byte{10, 0, 0, 9},
		SrcPort: hostToNetwork16(1234), DstPort: hostToNetwork16(443), Protocol: 6,
	}
}

// THE ACCEPTANCE CRITERION the issue names: a delete for a tenant session names
// its domain.
func TestDeleteNamesTheInstalledRoutingDomain9146(t *testing.T) {
	m := New()
	const tenant = uint32(100007)

	install := m.buildSessionSyncRequestV4("upsert", key9146(),
		&dataplane.SessionValue{RoutingDomain: tenant})
	del := m.buildSessionSyncRequestV4("delete", key9146(), deleteScopeVal(tenant))

	if install.RoutingDomain != tenant {
		t.Fatalf("install carried routing_domain=%d, want %d", install.RoutingDomain, tenant)
	}
	if del.RoutingDomain != tenant {
		t.Fatalf("delete carried routing_domain=%d, want %d — a bare delete makes the standby "+
			"probe every routing instance, and two tenants sharing the tuple make it REFUSE (#9146)",
			del.RoutingDomain, tenant)
	}
	// The install and delete must name the SAME row. This is the invariant the
	// defect broke, stated as an invariant rather than as two numbers.
	if install.SrcIP != del.SrcIP || install.DstIP != del.DstIP ||
		install.SrcPort != del.SrcPort || install.DstPort != del.DstPort ||
		install.Protocol != del.Protocol || install.RoutingDomain != del.RoutingDomain {
		t.Fatalf("install and delete name different rows:\n install=%+v\n delete=%+v", install, del)
	}
}

// THE SECOND ACCEPTANCE CRITERION: a delete for a DEFAULT-instance session still
// resolves domain 0. Without this control the fix could be "always send some
// non-zero domain", which would break every non-VRF deployment.
func TestDefaultInstanceDeleteStillCarriesDomainZero9146(t *testing.T) {
	m := New()
	del := m.buildSessionSyncRequestV4("delete", key9146(), deleteScopeVal(0))
	if del.RoutingDomain != 0 {
		t.Fatalf("default-instance delete carried routing_domain=%d, want 0", del.RoutingDomain)
	}
	if deleteScopeVal(0) != nil {
		t.Fatal("deleteScopeVal(0) must be nil so the request is built exactly as before #9146 " +
			"for a deployment with no routing-instance membership")
	}
}

// The measurement that closed the open link, kept as a cell so the premise
// cannot rot: swapping the tenant behind one bare 5-tuple emits two upserts
// under two domains and NO delete, so the standby accumulates both rows.
func TestTenantSwapEmitsNoRetractionSoTheStandbyAccumulates9146(t *testing.T) {
	m, rec := newSyncOnlyManager9146(t)
	k := key9146()

	m.mirrorSessionV4(k, dataplane.SessionValue{RoutingDomain: 100007})
	m.mirrorSessionV4(k, dataplane.SessionValue{RoutingDomain: 100008})

	got := rec.all()
	var upserts []uint32
	deletes := 0
	for _, r := range got {
		switch r.Operation {
		case "upsert":
			upserts = append(upserts, r.RoutingDomain)
		case "delete":
			deletes++
		}
	}
	if len(upserts) != 2 || upserts[0] != 100007 || upserts[1] != 100008 {
		t.Fatalf("upsert domains = %v, want [100007 100008] — the premise of this issue is that the "+
			"standby is told about BOTH tenants for one bare tuple", upserts)
	}
	if deletes != 0 {
		t.Fatalf("%d delete(s) emitted when the bare mirror row swapped tenants; if the sender DID "+
			"retract the old row the standby would hold only one and the ambiguity could not arise "+
			"— re-check whether this issue is still real", deletes)
	}
}

// WIRING BIND (as far as it goes without CAP_BPF). syncDeleteV4Locked is the
// function DeleteSession delegates to, so this drives the REAL scope derivation
// and both sends rather than restating them. DeleteSession itself reads and
// writes BPF maps, so a cell for it skips wherever BPF is unavailable — and a
// skipping cell scores a mutation as SURVIVED, which is the reading that argues
// for deleting a working guard. This is the deepest bind that runs everywhere.
func TestDeleteSessionWireCarriesDomainForBothHalves9146(t *testing.T) {
	m, rec := newSyncOnlyManager9146(t)
	const tenant = uint32(100007)
	k := key9146()
	rev := dataplane.SessionKey{
		SrcIP: k.DstIP, DstIP: k.SrcIP,
		SrcPort: k.DstPort, DstPort: k.SrcPort, Protocol: k.Protocol,
	}

	m.mu.Lock()
	m.syncDeleteV4Locked(k, dataplane.SessionValue{
		RoutingDomain: tenant,
		ReverseKey:    rev,
	}, true)
	m.mu.Unlock()

	got := rec.all()
	if len(got) != 2 {
		t.Fatalf("got %d sync requests, want 2 (forward + reverse companion)", len(got))
	}
	for i, r := range got {
		if r.Operation != "delete" {
			t.Fatalf("request %d op = %q, want delete", i, r.Operation)
		}
		if r.RoutingDomain != tenant {
			t.Fatalf("delete half %d carried routing_domain=%d, want %d — the reverse companion is "+
				"the same flow in the same tenant and must not fall back to the ambiguous bare tuple",
				i, r.RoutingDomain, tenant)
		}
	}
}

// A delete with NO known value (the GetSessionV4 lookup failed) must behave
// exactly as it did before #9146: one bare delete, no invented domain, and no
// reverse companion send.
func TestDeleteWithNoKnownValueIsUnchanged9146(t *testing.T) {
	m, rec := newSyncOnlyManager9146(t)
	m.mu.Lock()
	m.syncDeleteV4Locked(key9146(), dataplane.SessionValue{}, false)
	m.mu.Unlock()

	got := rec.all()
	if len(got) != 1 {
		t.Fatalf("got %d requests, want 1 (no value means no companion to delete)", len(got))
	}
	if got[0].RoutingDomain != 0 {
		t.Fatalf("a delete with no known value carried routing_domain=%d, want 0", got[0].RoutingDomain)
	}
}

// The v6 half must not be left behind: the same wire, the same defect.
func TestDeleteV6WireCarriesDomainForBothHalves9146(t *testing.T) {
	m, rec := newSyncOnlyManager9146(t)
	const tenant = uint32(100007)
	var s6, d6 [16]byte
	copy(s6[:], net.ParseIP("2001:db8::5").To16())
	copy(d6[:], net.ParseIP("2001:db8::9").To16())
	k := dataplane.SessionKeyV6{
		SrcIP: s6, DstIP: d6,
		SrcPort: hostToNetwork16(1234), DstPort: hostToNetwork16(443), Protocol: 6,
	}
	rev := dataplane.SessionKeyV6{
		SrcIP: d6, DstIP: s6,
		SrcPort: k.DstPort, DstPort: k.SrcPort, Protocol: k.Protocol,
	}

	m.mu.Lock()
	m.syncDeleteV6Locked(k, dataplane.SessionValueV6{
		RoutingDomain: tenant,
		ReverseKey:    rev,
	}, true)
	m.mu.Unlock()

	got := rec.all()
	if len(got) != 2 {
		t.Fatalf("got %d v6 sync requests, want 2", len(got))
	}
	for i, r := range got {
		if r.RoutingDomain != tenant {
			t.Fatalf("v6 delete half %d carried routing_domain=%d, want %d", i, r.RoutingDomain, tenant)
		}
	}
}

// THE FULL WIRING BIND — DeleteSession itself.
//
// Mutation M5 severed DeleteSession's call to syncDeleteV4Locked and SURVIVED,
// and that survival was not a privilege artifact: at the time, NO test in this
// package called Manager.DeleteSession at all, so the userspace dataplane's
// per-session delete had no cell whatsoever. Every cell above drives
// syncDeleteV4Locked directly and stays green while DeleteSession quietly stops
// calling it.
//
// This closes that. It needs real BPF maps (DeleteSession reads the value out of
// the sessions map before deleting it), so it SKIPS without CAP_BPF — like the
// 54 other BPF-gated cells in this package. A skipping cell cannot score a
// mutation, which is stated here so nobody reads a local "survived" off a run
// where this never executed.
func TestDeleteSessionItselfNamesTheDomainOnTheWire9146(t *testing.T) {
	dir, err := os.MkdirTemp("", "x9146w")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	m := New()
	m.proc = &exec.Cmd{}
	m.cfg.ControlSocket = filepath.Join(dir, "control.sock")
	injectSessionMaps(t, m) // skips without BPF privileges
	rec := startSyncRec9146(t, filepath.Join(dir, "userspace-dp-sessions.sock"))

	const tenant = uint32(100007)
	k := key9146()
	rev := dataplane.SessionKey{
		SrcIP: k.DstIP, DstIP: k.SrcIP,
		SrcPort: k.DstPort, DstPort: k.SrcPort, Protocol: k.Protocol,
	}
	if err := m.bpfShim.SetSessionV4(k, dataplane.SessionValue{
		RoutingDomain: tenant,
		ReverseKey:    rev,
	}); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	if err := m.DeleteSession(k); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}

	got := rec.all()
	if len(got) == 0 {
		t.Fatal("DeleteSession emitted no helper sync at all — the delete never reaches the standby")
	}
	for i, r := range got {
		if r.Operation != "delete" {
			continue
		}
		if r.RoutingDomain != tenant {
			t.Fatalf("DeleteSession wire[%d] carried routing_domain=%d, want %d — the value is "+
				"fetched three lines earlier and its domain must reach the wire (#9146)",
				i, r.RoutingDomain, tenant)
		}
	}
}
