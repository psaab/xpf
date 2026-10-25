// #7315: the gRPC ShowText NAT topics must run their conntrack walk under the
// admission-LEASE context, so a client that has hung up stops the walk.
//
// This file binds the WIRING, not the mechanism. pkg/natshow's own
// walk_cancellation_7315_test.go proves the renderers honour a cancelled
// context; nothing there can see server_show_nat.go passing
// context.Background(), or server_show.go failing to hand ShowText's ctx to
// the topic handler. Both of those leave the natshow cells green while the
// production path walks the whole table for a departed client — which is the
// defect, and it is a defect precisely because REST and gRPC alias ONE 4-slot
// diagcmd.SessionWalkLimiter: the slot the walk keeps is one the REST
// surfaces that DO honour cancellation are queueing for.
//
// FAIL-ON-REVERT: pass context.Background() (or any fresh context) instead of
// the request/lease context at any of the three call sites and that topic's
// cell reports the full 2*natShowRows7315 visits.
package grpcapi

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// natShowRows7315 is per FAMILY; a completed walk visits twice this.
const natShowRows7315 = 500

// natShowWalkDP is the grpcRuntime fake the ShowText NAT topics walk through.
//
// It is deliberately NOT the #6553 natWalkDP: these topics reach pkg/natshow
// via s.dp directly (Iterate*), while the #6553 RPCs reach the session store
// via Sessions(), and this fake additionally has to supply a non-nil apply
// result — without one the source and destination renderers skip the tally
// entirely and every assertion below would be vacuously green.
type natShowWalkDP struct {
	*dataplane.Manager
	visited         *int
	ingress, egress uint16
}

func (natShowWalkDP) IsLoaded() bool { return true }

// LastApplyResult shadows the embedded Manager's, which returns nil for a
// freshly constructed Manager. dataplane.LastApplyResultOf reaches this method
// because *Manager implements no LiveUnwrapper, so Unwrap hands back the
// wrapper and the assertion resolves to THIS override.
//
// The three zone ids are distinct: the renderers invert the map, so a
// collision would silently make one rule-set key unreachable.
func (natShowWalkDP) LastApplyResult() *dataplane.ApplyResult {
	return &dataplane.ApplyResult{ZoneIDs: map[string]uint32{"trust": 7, "untrust": 8, "dmz": 9}}
}

func (d natShowWalkDP) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	for i := 0; i < natShowRows7315; i++ {
		*d.visited++
		if !fn(dataplane.SessionKey{}, dataplane.SessionValue{
			Flags:       dataplane.SessFlagSNAT | dataplane.SessFlagDNAT,
			IngressZone: d.ingress, EgressZone: d.egress,
		}) {
			return nil
		}
	}
	return nil
}

func (d natShowWalkDP) IterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	for i := 0; i < natShowRows7315; i++ {
		*d.visited++
		if !fn(dataplane.SessionKeyV6{}, dataplane.SessionValueV6{
			Flags:       dataplane.SessFlagSNAT | dataplane.SessFlagDNAT,
			IngressZone: d.ingress, EgressZone: d.egress,
		}) {
			return nil
		}
	}
	return nil
}

// newNATShowWalkServer seeds the same committed NAT config the #6553
// admission cells use (rule-sets trust->untrust and untrust->dmz) plus one
// persistent-NAT binding, so persistent-nat-detail reaches its tally instead
// of short-circuiting on an empty binding table.
func newNATShowWalkServer(t *testing.T, visited *int, ingress, egress uint16) *Server {
	t.Helper()
	mgr := dataplane.New()
	mgr.PersistentNAT.Save(&dataplane.PersistentNATBinding{
		SrcIP:    netip.MustParseAddr("10.0.1.5"),
		SrcPort:  1111,
		NatIP:    netip.MustParseAddr("203.0.113.1"),
		NatPort:  40000,
		PoolName: "p1",
		LastSeen: time.Now(),
		Timeout:  600 * time.Second,
	})
	return &Server{
		dp:    natShowWalkDP{Manager: mgr, visited: visited, ingress: ingress, egress: egress},
		store: newNATWalkStore(t),
	}
}

func TestShowTextNATWalksRunUnderTheRequestContext7315(t *testing.T) {
	topics := []struct {
		topic           string
		ingress, egress uint16
	}{
		{"persistent-nat-detail", 7, 8},
		{"nat-source-rule-detail", 7, 8},
		{"nat-dest-rule-detail", 8, 9},
	}

	for _, tc := range topics {
		t.Run(tc.topic, func(t *testing.T) {
			cancelled, cancel := context.WithCancel(context.Background())
			cancel()

			visited := 0
			s := newNATShowWalkServer(t, &visited, tc.ingress, tc.egress)
			if _, err := s.ShowText(cancelled, &pb.ShowTextRequest{Topic: tc.topic}); err != nil {
				t.Fatalf("ShowText(%s) with a cancelled context: %v (a cancelled "+
					"client is not an error path — the topic renders what it has)",
					tc.topic, err)
			}
			if visited > 2 {
				t.Errorf("ShowText(%s) visited %d of %d rows after the client was "+
					"gone — the handler is not passing the request/lease context "+
					"into pkg/natshow, so the walk holds a shared "+
					"diagcmd.SessionWalkLimiter slot to completion",
					tc.topic, visited, 2*natShowRows7315)
			}
			if visited == 0 {
				t.Fatalf("ShowText(%s) never started a walk, so this cell proves "+
					"nothing — check the fixture still reaches the tally", tc.topic)
			}

			// Control: the same topic on a LIVE context walks the whole
			// table, so the assertion above is about cancellation rather
			// than about a fixture that never iterates.
			liveVisited := 0
			ls := newNATShowWalkServer(t, &liveVisited, tc.ingress, tc.egress)
			if _, err := ls.ShowText(context.Background(), &pb.ShowTextRequest{Topic: tc.topic}); err != nil {
				t.Fatalf("ShowText(%s) with a live context: %v", tc.topic, err)
			}
			if liveVisited != 2*natShowRows7315 {
				t.Errorf("ShowText(%s) on a live context visited %d rows, want %d",
					tc.topic, liveVisited, 2*natShowRows7315)
			}
		})
	}
}

// TestShowTextPersistentNATDrivesNoWalk7315 is the over-reach control for the
// premise correction. #7315 named FOUR walking topics; persistent-nat is not
// one of them — RenderPersistent's only dataplane read is a snapshot copy of
// the in-process persistent-NAT map, so it takes no context. If a future edit
// gives it a session walk, that walk starts life with no context to stop it
// and this cell says so.
//
// It also guards the direction the fix could over-reach in: adding the ctx
// plumbing to every NAT topic on the assumption that all four walk.
func TestShowTextPersistentNATDrivesNoWalk7315(t *testing.T) {
	visited := 0
	s := newNATShowWalkServer(t, &visited, 7, 8)

	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "persistent-nat"})
	if err != nil {
		t.Fatalf("ShowText(persistent-nat): %v", err)
	}
	if visited != 0 {
		t.Errorf("ShowText(persistent-nat) visited %d conntrack rows — it now "+
			"drives a session walk and needs the lease context the other three "+
			"topics carry (#7315)", visited)
	}
	if resp.GetOutput() == "" {
		t.Fatal("ShowText(persistent-nat) rendered nothing, so the zero-visit " +
			"assertion above is vacuous")
	}
}
