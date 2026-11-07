package grpcapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/dynamicpb"
)

func nonceForFabricNonce18999(req proto.Message) []byte {
	switch r := req.(type) {
	case *pb.ClearSessionsRequest:
		return r.GetFabricNonce()
	case *pb.SystemActionRequest:
		return r.GetFabricNonce()
	default:
		return nil
	}
}

func setFabricNonce18999(req proto.Message, nonce []byte) {
	switch r := req.(type) {
	case *pb.ClearSessionsRequest:
		r.FabricNonce = nonce
	case *pb.SystemActionRequest:
		r.FabricNonce = nonce
	}
}

func tokenForFabricNonce18999(t *testing.T, method string, req interface{}, now time.Time) string {
	t.Helper()
	digest, err := fabricRequestDigest(req)
	if err != nil {
		t.Fatalf("fabric request digest: %v", err)
	}
	return fabricAuthTokenHexForDigest([]byte(fabricTestKey), now, method, digest)
}

func TestFabricNonce18999_DistinctMutationsAcceptedAndReplaysRejected(t *testing.T) {
	cases := []struct {
		name   string
		method string
		req    proto.Message
		change func(proto.Message)
	}{
		{
			name:   "clear-sessions",
			method: pb.BpfrxService_ClearSessions_FullMethodName,
			req:    &pb.ClearSessionsRequest{Protocol: "tcp"},
			change: func(req proto.Message) { req.(*pb.ClearSessionsRequest).Protocol = "udp" },
		},
		{
			name:   "cluster-failover",
			method: pb.BpfrxService_SystemAction_FullMethodName,
			req:    &pb.SystemActionRequest{Action: "cluster-failover:1:node1"},
			change: func(req proto.Message) { req.(*pb.SystemActionRequest).Action = "cluster-failover:2:node1" },
		},
		{
			name:   "cluster-data-failover",
			method: pb.BpfrxService_SystemAction_FullMethodName,
			req:    &pb.SystemActionRequest{Action: "cluster-failover-data:node1"},
			change: func(req proto.Message) { req.(*pb.SystemActionRequest).Action = "cluster-failover-data:node0" },
		},
		{
			name:   "persistent-nat-clear",
			method: pb.BpfrxService_SystemAction_FullMethodName,
			req:    &pb.SystemActionRequest{Action: "clear-persistent-nat", PersistentNatOrigin: "0123456789abcdef0123456789abcdef", PersistentNatGeneration: 3},
			change: func(req proto.Message) { req.(*pb.SystemActionRequest).PersistentNatGeneration++ },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			original := proto.Clone(tc.req)
			creds := fabricAuthCreds{keyFn: func() []byte { return []byte(fabricTestKey) }}
			var requests []proto.Message
			var tokens []string
			invoker := func(ctx context.Context, _ string, req, _ interface{}, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
				md, err := creds.GetRequestMetadata(ctx)
				if err != nil {
					return err
				}
				requests = append(requests, proto.Clone(req.(proto.Message)))
				tokens = append(tokens, md[fabricAuthMetadataKey])
				return nil
			}

			for range 2 {
				if err := FabricAuthUnaryClientInterceptor(context.Background(), tc.method, tc.req, nil, nil, invoker); err != nil {
					t.Fatalf("fabric client interceptor: %v", err)
				}
			}
			if !proto.Equal(original, tc.req) || len(nonceForFabricNonce18999(tc.req)) != 0 {
				t.Fatalf("client mutated caller-owned request: got %v, want original without a nonce", tc.req)
			}
			if len(requests) != 2 || len(tokens) != 2 {
				t.Fatalf("client invocations = %d requests / %d tokens, want 2/2", len(requests), len(tokens))
			}
			firstNonce := nonceForFabricNonce18999(requests[0])
			secondNonce := nonceForFabricNonce18999(requests[1])
			if len(firstNonce) != sha256.Size || len(secondNonce) != sha256.Size || bytes.Equal(firstNonce, secondNonce) {
				t.Fatalf("per-invocation nonces = %x / %x, want distinct %d-byte values", firstNonce, secondNonce, sha256.Size)
			}
			if tokens[0] == "" || tokens[1] == "" || tokens[0] == tokens[1] {
				t.Fatalf("tokens = %q / %q, want distinct authenticated tokens", tokens[0], tokens[1])
			}

			s := keyedServer(fabricTestKey)
			info := &grpc.UnaryServerInfo{FullMethod: tc.method}
			var handlerCalls atomic.Int32
			handler := func(context.Context, interface{}) (interface{}, error) {
				handlerCalls.Add(1)
				return "ok", nil
			}
			invoke := func(req proto.Message, token string) error {
				_, err := s.fabricAuthUnaryInterceptor(ctxWithToken(token), req, info,
					func(ctx context.Context, req interface{}) (interface{}, error) {
						return s.fabricAllowlistUnaryInterceptor(ctx, req, info, handler)
					})
				return err
			}
			for i := range requests {
				if err := invoke(requests[i], tokens[i]); err != nil {
					t.Fatalf("nonce-distinct mutation %d rejected: %v", i+1, err)
				}
			}
			if got := handlerCalls.Load(); got != 2 {
				t.Fatalf("handler calls after distinct invocations = %d, want 2", got)
			}

			if err := invoke(requests[0], tokens[0]); status.Code(err) != codes.Unauthenticated {
				t.Fatalf("verbatim request+token replay status = %s, err=%v; want Unauthenticated", status.Code(err), err)
			}

			// A key holder cannot reuse a nonce by signing changed arguments: the
			// server's replay identity is the nonce, after normal HMAC verification.
			changed := proto.Clone(requests[0])
			tc.change(changed)
			changedToken := tokenForFabricNonce18999(t, tc.method, changed, time.Now())
			if err := invoke(changed, changedToken); status.Code(err) != codes.Unauthenticated {
				t.Fatalf("same-nonce changed-argument replay status = %s, err=%v; want Unauthenticated", status.Code(err), err)
			}

			// Changing the nonce without re-signing the request cannot preserve
			// the original token's argument binding.
			swapped := proto.Clone(requests[0])
			swappedNonce := append([]byte(nil), firstNonce...)
			swappedNonce[0] ^= 0xff
			setFabricNonce18999(swapped, swappedNonce)
			if err := invoke(swapped, tokens[0]); status.Code(err) != codes.Unauthenticated {
				t.Fatalf("captured token with substituted nonce status = %s, err=%v; want Unauthenticated", status.Code(err), err)
			}
			if got := handlerCalls.Load(); got != 2 {
				t.Fatalf("replay reached mutation handler: calls=%d, want 2", got)
			}
		})
	}
}

func TestFabricNonce18999_UnprotectedRequestsPassThrough(t *testing.T) {
	cases := []struct {
		name   string
		method string
		req    proto.Message
	}{
		{name: "read-only", method: pb.BpfrxService_GetStatus_FullMethodName, req: &pb.GetStatusRequest{}},
		{name: "non-fabric-system-action", method: pb.BpfrxService_SystemAction_FullMethodName, req: &pb.SystemActionRequest{Action: "zeroize"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			invoker := func(_ context.Context, _ string, req, _ interface{}, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
				if req != tc.req {
					t.Fatalf("unprotected request was cloned: got %p, want %p", req, tc.req)
				}
				if len(nonceForFabricNonce18999(tc.req)) != 0 {
					t.Fatalf("unprotected request received a nonce: %v", tc.req)
				}
				return nil
			}
			if err := FabricAuthUnaryClientInterceptor(context.Background(), tc.method, tc.req, nil, nil, invoker); err != nil {
				t.Fatalf("fabric client interceptor: %v", err)
			}
		})
	}
}

func TestFabricNonce18999_LegacyNoNonceReplayUnchanged(t *testing.T) {
	cases := []struct {
		name   string
		method string
		req    proto.Message
	}{
		{name: "clear-sessions", method: pb.BpfrxService_ClearSessions_FullMethodName, req: &pb.ClearSessionsRequest{Protocol: "tcp"}},
		{name: "cluster-failover", method: pb.BpfrxService_SystemAction_FullMethodName, req: &pb.SystemActionRequest{Action: "cluster-failover:1:node1"}},
		{name: "cluster-data-failover", method: pb.BpfrxService_SystemAction_FullMethodName, req: &pb.SystemActionRequest{Action: "cluster-failover-data:node1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := keyedServer(fabricTestKey)
			token := tokenForFabricNonce18999(t, tc.method, tc.req, time.Now())
			info := &grpc.UnaryServerInfo{FullMethod: tc.method}
			var calls atomic.Int32
			handler := func(context.Context, interface{}) (interface{}, error) {
				calls.Add(1)
				return "ok", nil
			}
			invoke := func() error {
				_, err := s.fabricAuthUnaryInterceptor(ctxWithToken(token), tc.req, info, handler)
				return err
			}
			if err := invoke(); err != nil {
				t.Fatalf("first legacy mutation rejected: %v", err)
			}
			if err := invoke(); status.Code(err) != codes.Unauthenticated {
				t.Fatalf("identical legacy repeat status = %s, err=%v; want Unauthenticated", status.Code(err), err)
			}
			if got := calls.Load(); got != 1 {
				t.Fatalf("legacy handler calls = %d, want 1", got)
			}
		})
	}
}

func TestFabricNonce18999_ReplayIdentityExpiresWithAuthWindow(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	clock := func() time.Time { return now }
	s := keyedServer(fabricTestKey)
	s.fabricAuthNowFn = clock
	s.fabricMutationReplay.nowFn = clock
	method := pb.BpfrxService_SystemAction_FullMethodName
	req := &pb.SystemActionRequest{Action: "cluster-failover:1:node1", FabricNonce: bytes.Repeat([]byte{0xa5}, sha256.Size)}
	info := &grpc.UnaryServerInfo{FullMethod: method}
	var calls atomic.Int32
	handler := func(context.Context, interface{}) (interface{}, error) {
		calls.Add(1)
		return "ok", nil
	}
	invoke := func(token string) error {
		_, err := s.fabricAuthUnaryInterceptor(ctxWithToken(token), req, info, handler)
		return err
	}

	firstToken := tokenForFabricNonce18999(t, method, req, now)
	if err := invoke(firstToken); err != nil {
		t.Fatalf("first nonce-bearing mutation: %v", err)
	}
	now = now.Add(time.Duration(fabricAuthWindowSeconds) * time.Second)
	nextWindowToken := tokenForFabricNonce18999(t, method, req, now)
	if err := invoke(nextWindowToken); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("same nonce in the adjacent accepted window status = %s, err=%v; want replay rejection", status.Code(err), err)
	}

	now = now.Add(time.Duration(fabricAuthWindowSeconds) * time.Second)
	if err := invoke(firstToken); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expired old-window token status = %s, err=%v; want Unauthenticated", status.Code(err), err)
	}
	currentToken := tokenForFabricNonce18999(t, method, req, now)
	if err := invoke(currentToken); err != nil {
		t.Fatalf("new-window mutation after replay entry expiry: %v", err)
	}
	if err := invoke(currentToken); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("current-window verbatim replay status = %s, err=%v; want Unauthenticated", status.Code(err), err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("handler calls across expiry = %d, want 2", got)
	}
}

func legacyRequestDescriptor18999(t *testing.T, name protoreflect.Name) protoreflect.MessageDescriptor {
	t.Helper()
	file := protodesc.ToFileDescriptorProto((&pb.SystemActionRequest{}).ProtoReflect().Descriptor().ParentFile())
	for _, message := range file.MessageType {
		if message.GetName() != "ClearSessionsRequest" && message.GetName() != "SystemActionRequest" {
			continue
		}
		fields := message.Field[:0]
		for _, field := range message.Field {
			if field.GetName() != "fabric_nonce" {
				fields = append(fields, field)
			}
		}
		message.Field = fields
	}
	legacyFile, err := protodesc.NewFile(file, protoregistry.GlobalFiles)
	if err != nil {
		t.Fatalf("constructing legacy protobuf descriptor: %v", err)
	}
	desc := legacyFile.Messages().ByName(name)
	if desc == nil {
		t.Fatalf("legacy descriptor has no message %s", name)
	}
	return desc
}

func TestFabricNonce18999_NewClientOldServerWireCompatibility(t *testing.T) {
	cases := []struct {
		name       string
		method     string
		descriptor protoreflect.Name
		request    proto.Message
	}{
		{
			name:       "clear-sessions",
			method:     pb.BpfrxService_ClearSessions_FullMethodName,
			descriptor: "ClearSessionsRequest",
			request:    &pb.ClearSessionsRequest{Protocol: "tcp"},
		},
		{
			name:       "system-action",
			method:     pb.BpfrxService_SystemAction_FullMethodName,
			descriptor: "SystemActionRequest",
			request:    &pb.SystemActionRequest{Action: "cluster-failover:1:node1"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			oldDescriptor := legacyRequestDescriptor18999(t, tc.descriptor)
			oldCache := fabricMutationReplayCache{}
			now := time.Now()
			window := fabricAuthWindow(now)
			var firstToken [sha256.Size]byte
			for i := range 2 {
				request := proto.Clone(tc.request)
				setFabricNonce18999(request, bytes.Repeat([]byte{byte(i + 1)}, sha256.Size))
				wire, err := fabricAuthDeterministicMarshal.Marshal(request)
				if err != nil {
					t.Fatalf("marshal new request: %v", err)
				}
				oldRequest := dynamicpb.NewMessage(oldDescriptor)
				if err := proto.Unmarshal(wire, oldRequest); err != nil {
					t.Fatalf("old-schema unmarshal: %v", err)
				}
				if len(oldRequest.ProtoReflect().GetUnknown()) == 0 {
					t.Fatal("old schema did not retain the nonce as an unknown field")
				}
				oldWire, err := fabricAuthDeterministicMarshal.Marshal(oldRequest)
				if err != nil {
					t.Fatalf("old-schema deterministic marshal: %v", err)
				}
				if !bytes.Equal(wire, oldWire) {
					t.Fatalf("old schema changed the signed protobuf wire: new=%x old-roundtrip=%x", wire, oldWire)
				}
				newDigest, err := fabricRequestDigest(request)
				if err != nil {
					t.Fatalf("new-schema digest: %v", err)
				}
				oldDigest, err := fabricRequestDigest(oldRequest)
				if err != nil {
					t.Fatalf("old-schema digest: %v", err)
				}
				if !bytes.Equal(newDigest, oldDigest) {
					t.Fatalf("old server digest differs: new=%x old=%x", newDigest, oldDigest)
				}
				tokenHex := fabricAuthTokenHexForDigest([]byte(fabricTestKey), now, tc.method, newDigest)
				token, ok := decodeFabricAuthToken(tokenHex)
				if !ok {
					t.Fatal("new client produced a malformed token")
				}
				if _, valid := verifyFabricAuthTokenBytesForDigestAt([]byte(fabricTestKey), token, tc.method, oldDigest, now); !valid {
					t.Fatal("old server could not verify the new client's nonce-bearing token")
				}
				if got := oldCache.consumeAt(token, window, window); got != fabricReplayAccepted {
					t.Fatalf("old token-keyed replay cache claim %d = %v, want accepted", i+1, got)
				}
				if i == 0 {
					firstToken = token
				}
			}
			if got := oldCache.consumeAt(firstToken, window, window); got != fabricReplayDuplicate {
				t.Fatalf("old token-keyed cache accepted a verbatim replay: got %v", got)
			}
		})
	}
}
