package grpcapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/authz"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/feeds"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func shrinkAckRequest11059(feed string, candidateID uint64, reason string) *pb.SystemActionRequest {
	return &pb.SystemActionRequest{
		Action:      "dynamic-address-shrink-ack",
		Target:      feed,
		CandidateId: candidateID,
		Reason:      reason,
	}
}

func TestDynamicAddressShrinkAckRequiresAdmissionPrincipal11059(t *testing.T) {
	var calls int
	s := &Server{
		feedsAckFn: func(string, uint64, string, string) error {
			calls++
			return nil
		},
		feedsFn: func() map[string]feeds.FeedInfo {
			return map[string]feeds.FeedInfo{
				"threats": {ShrinkRefused: true, ShrinkRefusalID: 41},
			}
		},
	}
	contexts := []struct {
		name string
		ctx  context.Context
	}{
		{name: "missing principal", ctx: context.Background()},
		{name: "unauthenticated principal", ctx: context.WithValue(context.Background(), authorizedPrincipalKey{}, authz.Principal{Source: authz.SourceNone})},
	}
	for _, tc := range contexts {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.SystemAction(tc.ctx, shrinkAckRequest11059("threats", 41, "reviewed upstream change"))
			if got := status.Code(err); got != codes.Unauthenticated {
				t.Fatalf("status = %s, want Unauthenticated (err=%v)", got, err)
			}
		})
	}
	if calls != 0 {
		t.Fatalf("manager callback called %d times without an admitted principal", calls)
	}
}

func TestDynamicAddressShrinkAckRejectsMalformedAndStaleRequests11059(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	ctx := context.WithValue(context.Background(), authorizedPrincipalKey{}, authz.Principal{
		Source: authz.SourcePeerUID, UID: 4243, Username: "opuser", Class: "operator",
	})
	var calls int
	callbackErr := errors.New("candidate changed while acknowledging")
	s := &Server{
		store: store,
		feedsFn: func() map[string]feeds.FeedInfo {
			return map[string]feeds.FeedInfo{
				"threats": {ShrinkRefused: true, ShrinkRefusalID: 41},
				"current": {ShrinkRefusalID: 41},
			}
		},
		feedsAckFn: func(string, uint64, string, string) error {
			calls++
			return callbackErr
		},
	}
	cases := []struct {
		name       string
		request    *pb.SystemActionRequest
		noCallback bool
		want       codes.Code
	}{
		{name: "empty feed", request: shrinkAckRequest11059("", 41, "reviewed"), noCallback: true, want: codes.InvalidArgument},
		{name: "whitespace feed", request: shrinkAckRequest11059(" threats", 41, "reviewed"), noCallback: true, want: codes.InvalidArgument},
		{name: "zero candidate ID", request: shrinkAckRequest11059("threats", 0, "reviewed"), noCallback: true, want: codes.InvalidArgument},
		{name: "missing reason", request: shrinkAckRequest11059("threats", 41, " \t"), noCallback: true, want: codes.InvalidArgument},
		{name: "overlong reason", request: shrinkAckRequest11059("threats", 41, strings.Repeat("x", 513)), noCallback: true, want: codes.InvalidArgument},
		{name: "control character reason", request: shrinkAckRequest11059("threats", 41, "reviewed\nchange"), noCallback: true, want: codes.InvalidArgument},
		{name: "unknown feed", request: shrinkAckRequest11059("missing", 41, "reviewed"), noCallback: true, want: codes.NotFound},
		{name: "no current refusal", request: shrinkAckRequest11059("current", 41, "reviewed"), noCallback: true, want: codes.FailedPrecondition},
		{name: "stale candidate ID", request: shrinkAckRequest11059("threats", 42, "reviewed"), noCallback: true, want: codes.FailedPrecondition},
		{name: "manager rejects a race", request: shrinkAckRequest11059("threats", 41, "reviewed"), want: codes.FailedPrecondition},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := calls
			_, err := s.SystemAction(ctx, tc.request)
			if got := status.Code(err); got != tc.want {
				t.Fatalf("status = %s, want %s (err=%v)", got, tc.want, err)
			}
			wantCalls := 0
			if !tc.noCallback {
				wantCalls = 1
			}
			if got := calls - before; got != wantCalls {
				t.Fatalf("manager calls = %d, want %d", got, wantCalls)
			}
		})
	}

	withoutCallback := &Server{store: s.store, feedsFn: s.feedsFn}
	_, err := withoutCallback.SystemAction(ctx, shrinkAckRequest11059("threats", 41, "reviewed"))
	if got := status.Code(err); got != codes.Unavailable {
		t.Fatalf("nil manager callback status = %s, want Unavailable (err=%v)", got, err)
	}
}

func TestDynamicAddressShrinkAckUsesAdmittedActorAndJournalsReason11059(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "xpf.conf")
	store := newConfigStore(t, configPath)
	principal := authz.Principal{
		Source: authz.SourcePeerUID, UID: 4243, Username: "opuser", Class: "config-operator",
	}
	ctx := context.WithValue(context.Background(), authorizedPrincipalKey{}, principal)
	var gotName, gotActor, gotReason string
	var gotID uint64
	s := &Server{
		store: store,
		feedsFn: func() map[string]feeds.FeedInfo {
			return map[string]feeds.FeedInfo{
				"threats": {ShrinkRefused: true, ShrinkRefusalID: 41},
			}
		},
		feedsAckFn: func(name string, refusalID uint64, actor, reason string) error {
			gotName, gotID, gotActor, gotReason = name, refusalID, actor, reason
			return nil
		},
	}
	resp, err := s.SystemAction(ctx, shrinkAckRequest11059("threats", 41, "  reviewed upstream correction  "))
	if err != nil {
		t.Fatalf("SystemAction acknowledgement: %v", err)
	}
	if !strings.Contains(resp.GetMessage(), "candidate 41") || !strings.Contains(resp.GetMessage(), "threats") {
		t.Fatalf("response %q does not identify the acknowledged feed and candidate", resp.GetMessage())
	}
	wantActor := configstore.FormatJournalPrincipal("peer-uid", principal.UID, principal.Username, principal.Class, "")
	if gotName != "threats" || gotID != 41 || gotActor != wantActor || gotReason != "reviewed upstream correction" {
		t.Fatalf("manager callback got (%q, %d, %q, %q), want (%q, 41, %q, %q)",
			gotName, gotID, gotActor, gotReason, "threats", wantActor, "reviewed upstream correction")
	}

	raw, err := os.ReadFile(filepath.Join(filepath.Dir(configPath), ".config.journal"))
	if err != nil {
		t.Fatalf("read acknowledgement journal: %v", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	found := false
	for {
		var entry struct {
			Action    string `json:"action"`
			Detail    string `json:"detail"`
			Principal string `json:"principal"`
		}
		if err := decoder.Decode(&entry); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatalf("decode acknowledgement journal entry: %v", err)
		}
		if entry.Action == "system_action" && entry.Principal == wantActor &&
			strings.Contains(entry.Detail, `feed="threats"`) &&
			strings.Contains(entry.Detail, "candidate_id=41") &&
			strings.Contains(entry.Detail, `reason="reviewed upstream correction"`) {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("journal has no attributable feed/candidate/reason acknowledgement entry")
	}
}
