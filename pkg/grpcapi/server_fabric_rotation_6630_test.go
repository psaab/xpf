package grpcapi

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	fabricRotOld = "fabric-rotation-old-key-6630"
	fabricRotNew = "fabric-rotation-new-key-6630"
)

// rotatingFabricServer wires a REAL cluster.Manager rather than the
// fabricAuthKeyFn seam, because the seam is exactly what this test must not
// use: it returns one key and bypasses the accepted-set widening. Driving the
// manager also exercises the config plumbing the rotation depends on.
func rotatingFabricServer(t *testing.T, signing, additional string) *Server {
	t.Helper()
	m := cluster.NewManager(0, 42)
	m.UpdateConfig(&config.ClusterConfig{
		ControlLinkAuthKey:    config.Secret(signing),
		ControlLinkAuthKeyAlt: config.Secret(additional),
	})
	return &Server{cluster: m}
}

// TestFabricRotation6630 binds the fabric listener to the same rotation
// overlap as the heartbeat.
//
// Both control surfaces key off the SAME PSK and both are consulted during a
// failover. Widening only the heartbeat would turn a rotation from "no outage"
// into "no outage on the heartbeat, codes.Unauthenticated on every
// peer-proxied RPC" — a partial fix that looks like a whole one until an
// operator needs a cross-node RPC mid-rotation, which is precisely when they
// are most likely to.
//
// FAIL-ON-REVERT: make fabricAcceptedKeys return only
// cluster.ControlLinkAuthKey() and the mid-rotation case reds.
func TestFabricRotation6630(t *testing.T) {
	info := &grpc.UnaryServerInfo{FullMethod: pb.BpfrxService_GetSessions_FullMethodName}

	// Mid-rotation: this node signs the NEW key, still accepts the OLD one.
	// The peer has not moved yet, so its token is minted under the old key.
	s := rotatingFabricServer(t, fabricRotNew, fabricRotOld)
	peerToken := fabricAuthTokenHex([]byte(fabricRotOld), time.Now(), info.FullMethod)
	probe := &unaryCallProbe{}
	if _, err := s.fabricAuthUnaryInterceptor(ctxWithToken(peerToken), nil, info, probe.handler); err != nil {
		t.Fatalf("mid-rotation, a token minted under the ACCEPTED (not-yet-retired) key must "+
			"be admitted; got %v. Otherwise every peer-proxied RPC returns Unauthenticated "+
			"for the window between the two nodes' commits (#6630)", err)
	}
	if !probe.called {
		t.Fatal("mid-rotation: the handler must run")
	}

	// The current key obviously still works — so the acceptance above is the
	// overlap, not the gate having stopped checking anything.
	probe2 := &unaryCallProbe{}
	newToken := fabricAuthTokenHex([]byte(fabricRotNew), time.Now(), info.FullMethod)
	if _, err := s.fabricAuthUnaryInterceptor(ctxWithToken(newToken), nil, info, probe2.handler); err != nil {
		t.Fatalf("the signing key must still authenticate mid-rotation: %v", err)
	}

	// A third, unrelated key must NOT be admitted — the overlap widens to
	// exactly the configured additional key, not to anything presented.
	probe3 := &unaryCallProbe{}
	strangerToken := fabricAuthTokenHex([]byte("some-other-key-entirely"), time.Now(), info.FullMethod)
	_, err := s.fabricAuthUnaryInterceptor(ctxWithToken(strangerToken), nil, info, probe3.handler)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("a token under an unconfigured key must be rejected, got %v", err)
	}

	// After FINALIZE the retired key stops working — an overlap that cannot be
	// closed is a second permanent key, not a rotation.
	fin := rotatingFabricServer(t, fabricRotNew, "")
	probe4 := &unaryCallProbe{}
	_, err = fin.fabricAuthUnaryInterceptor(ctxWithToken(peerToken), nil, info, probe4.handler)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("after finalize the retired key must not authenticate a fabric RPC, got %v", err)
	}
	if probe4.called {
		t.Fatal("after finalize the handler must not run for a retired-key token")
	}
}

// TestFabricAuthKeyFnSeamIsNotWidened6630: a test that pins fabricAuthKeyFn
// gets exactly that one key and no widening, so the #4107 fixtures keep
// meaning what they meant. Without this, adding the accepted-set could quietly
// change what every existing fabric-auth test is asserting.
func TestFabricAuthKeyFnSeamIsNotWidened6630(t *testing.T) {
	s := keyedServer(fabricTestKey)
	keys := s.fabricAcceptedKeys()
	if len(keys) != 1 || string(keys[0]) != fabricTestKey {
		t.Fatalf("the fabricAuthKeyFn seam must yield exactly the injected key; got %d keys", len(keys))
	}
	empty := keyedServer("")
	if len(empty.fabricAcceptedKeys()) != 0 {
		t.Fatal("an empty injected key must yield no accepted keys, not a one-element slice " +
			"containing nothing — len(keys) > 0 is what the gate reads as 'keyed'")
	}
}
