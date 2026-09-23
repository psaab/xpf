package userspace

import (
	"encoding/json"
	"net"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #8015: the local session mirror sends ONE upsert — the forward — and never an
// explicitly built `is_reverse=1` companion.
//
// The helper synthesizes the companion itself on every non-reverse import
// (`synthesized_synced_reverse_entry`, a total function on forwards, published
// by `upsert_synced_session`), so the second request was a REPLACEMENT for a
// companion that already existed, resolved against this side's snapshot rather
// than the helper's live node-local state. Its only distinct effect was a
// failure mode: a forward the helper semantically REFUSED left the explicit
// reverse published alone, and no later forward delete removes it because
// `delete_synced_session_gen` derives the companion from the stored forward.
//
// WHAT THIS ASSERTS AND WHY IT IS A COUNT, NOT A PREDICATE. "No request carries
// is_reverse" would also pass if the mirror emitted the companion under the
// forward's own flag, or emitted a third request, or emitted nothing at all.
// The subject is the SHAPE of the transmission, so the cell asserts the exact
// request set: one request, the forward key, `IsReverse` false.
//
// AND IT KEEPS #7917's OVER-REACH CONTROL. The forward request must still carry
// the #4983 ingress identity resolved from the #7095 fold. A mirror that
// emitted one request carrying nothing would satisfy every assertion about the
// absent companion while destroying the datum the mirror exists to deliver.

// captureSessionSync stands up the helper session socket, runs `emit`, and
// returns EVERY sync request the manager transmitted, in order.
//
// It waits for the first request and then keeps draining for `settleWindow`
// before returning, so a SECOND request is observed rather than missed. That
// window is what makes the "exactly one" assertion falsifiable: the transmit is
// synchronous (the server pushes each request onto `got` before encoding its
// response, so every request of a completed `emit` has already been pushed),
// but an instrument that stopped at the first request would report "one" for a
// mirror that sent two and could never fail. Re-adding the explicit reverse
// must turn this green cell red, and it does.
func captureSessionSync(t *testing.T, emit func(m *Manager)) []SessionSyncRequest {
	t.Helper()
	dir := t.TempDir()
	ln, err := net.Listen("unix", filepath.Join(dir, "userspace-dp-sessions.sock"))
	if err != nil {
		t.Fatalf("listen session socket: %v", err)
	}
	defer ln.Close()

	got := make(chan SessionSyncRequest, 8)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				dec := json.NewDecoder(conn)
				enc := json.NewEncoder(conn)
				for {
					var req ControlRequest
					if err := dec.Decode(&req); err != nil {
						return
					}
					if req.SessionSync != nil {
						got <- *req.SessionSync
					}
					if err := enc.Encode(ControlResponse{OK: true}); err != nil {
						return
					}
				}
			}()
		}
	}()

	m := New()
	m.proc = &exec.Cmd{}
	m.cfg.ControlSocket = filepath.Join(dir, "control.sock")
	// #7095: make the fold RESOLVE, so the ingress identity on the wire is a
	// non-zero number rather than the 0 an unresolved fold would produce — the
	// over-reach control below is about nothing otherwise.
	m.SetIngressFoldResolver(func(fold uint32) (uint32, uint16, bool) {
		if fold == forwardTestFold {
			return forwardTestIfindex, forwardTestVLAN, true
		}
		return 0, 0, false
	})

	emit(m)

	var out []SessionSyncRequest
	select {
	case req := <-got:
		out = append(out, req)
	case <-time.After(5 * time.Second):
		t.Fatalf("no session sync request arrived in 5s; the mirror must send the forward upsert")
	}
	settle := time.After(settleWindow)
	for {
		select {
		case req := <-got:
			out = append(out, req)
		case <-settle:
			return out
		}
	}
}

const (
	forwardTestFold    uint32 = 0xC0FFEE01
	forwardTestIfindex uint32 = 4242
	forwardTestVLAN    uint16 = 80
	// settleWindow is how long captureSessionSync keeps listening after the
	// first request. The transmit is synchronous, so a second request would
	// already be queued when `emit` returns; the window is slack for the
	// server goroutine's scheduling, not a race with the transmit.
	settleWindow = 300 * time.Millisecond
)

// assertSingleForwardUpsert checks the shape both families must have.
func assertSingleForwardUpsert(t *testing.T, reqs []SessionSyncRequest, wantSrcIP string) {
	t.Helper()
	if len(reqs) != 1 {
		got := make([]string, 0, len(reqs))
		for _, r := range reqs {
			got = append(got, r.Operation+" src="+r.SrcIP+" is_reverse="+boolText(r.IsReverse))
		}
		t.Fatalf("the mirror sent %d session sync requests, want exactly 1 (the forward "+
			"upsert). The helper synthesizes the reverse companion itself on every "+
			"non-reverse import, so a second request is a redundant replacement whose "+
			"only distinct effect is the reverse-only orphan a refused forward leaves "+
			"behind (#8015). Requests: %v", len(reqs), got)
	}
	req := reqs[0]
	if req.Operation != "mirror_upsert" {
		t.Errorf("mirror request operation = %q, want %q", req.Operation, "mirror_upsert")
	}
	if req.IsReverse {
		t.Errorf("the mirror's single request carries is_reverse=true; the only request " +
			"it may send is the FORWARD upsert (#8015)")
	}
	if req.SrcIP != wantSrcIP {
		t.Errorf("mirror request src_ip = %q, want the FORWARD source %q — the one "+
			"request must be the forward, not the companion (#8015)", req.SrcIP, wantSrcIP)
	}
	// #7917 over-reach control: the forward must still carry its own #4983
	// ingress identity, resolved from the #7095 fold.
	if req.IngressIfindex != int(forwardTestIfindex) || req.IngressVLANID != forwardTestVLAN {
		t.Errorf("the FORWARD request lost its ingress identity {ifindex %d, vlan %d}, "+
			"want {%d, %d}. Emitting one request that carries nothing would satisfy "+
			"every assertion about the absent companion while destroying the datum "+
			"#4983 exists to provide (#7917)",
			req.IngressIfindex, req.IngressVLANID, forwardTestIfindex, forwardTestVLAN)
	}
}

func boolText(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func TestMirrorSessionSendsOnlyTheForwardUpsertV4_8015(t *testing.T) {
	key := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 61, 102}, DstIP: [4]byte{172, 16, 80, 200},
		SrcPort: 1111, DstPort: 2222, Protocol: 6,
	}
	// ReverseKey is POPULATED on purpose: it is the field the deleted explicit
	// companion was built from, so a fixture without it would make this cell
	// pass for the wrong reason — the old code skipped the second request when
	// ReverseKey.Protocol was 0.
	val := dataplane.SessionValue{
		ReverseKey: dataplane.SessionKey{
			SrcIP: [4]byte{172, 16, 80, 200}, DstIP: [4]byte{10, 0, 61, 102},
			SrcPort: 2222, DstPort: 1111, Protocol: 6,
		},
		IngressIfindex:   77,
		IngressVlanID:    80,
		IngressIfaceFold: forwardTestFold,
	}
	reqs := captureSessionSync(t, func(m *Manager) { m.mirrorSessionV4(key, val) })
	assertSingleForwardUpsert(t, reqs, "10.0.61.102")
}

// The IPv6 mirror is a SEPARATE call site with its own request build, so the v4
// cell cannot see mirrorSessionV6 keep its explicit companion. This is not
// duplication — it is the second half of the wiring (#7179's v6 cell made the
// same argument about the same pair of methods).
func TestMirrorSessionSendsOnlyTheForwardUpsertV6_8015(t *testing.T) {
	var src, dst [16]byte
	copy(src[:], net.ParseIP("2001:db8:1::102").To16())
	copy(dst[:], net.ParseIP("2001:db8:2::200").To16())
	key := dataplane.SessionKeyV6{SrcIP: src, DstIP: dst, SrcPort: 1111, DstPort: 2222, Protocol: 6}
	val := dataplane.SessionValueV6{
		ReverseKey:       dataplane.SessionKeyV6{SrcIP: dst, DstIP: src, SrcPort: 2222, DstPort: 1111, Protocol: 6},
		IngressIfindex:   77,
		IngressVlanID:    80,
		IngressIfaceFold: forwardTestFold,
	}
	reqs := captureSessionSync(t, func(m *Manager) { m.mirrorSessionV6(key, val) })
	assertSingleForwardUpsert(t, reqs, "2001:db8:1::102")
}
