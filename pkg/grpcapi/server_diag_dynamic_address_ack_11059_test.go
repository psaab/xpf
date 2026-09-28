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

var (
	shrinkAckCandidateHash11059 = strings.Repeat("a", 64)
	shrinkAckBaselineHash11059  = strings.Repeat("b", 64)
)

func shrinkAckRequest11059(feed string, candidateID uint64, reason string) *pb.SystemActionRequest {
	return &pb.SystemActionRequest{
		Action:            "dynamic-address-shrink-ack",
		Target:            feed,
		CandidateId:       candidateID,
		CandidateHash:     shrinkAckCandidateHash11059,
		BaselineHash:      shrinkAckBaselineHash11059,
		CandidateOldCount: 100,
		CandidateNewCount: 5,
		Reason:            reason,
	}
}

func TestDynamicAddressShrinkAckRequiresAdmissionPrincipal11059(t *testing.T) {
	var calls int
	s := &Server{
		feedsAckFn: func(string, uint64, string, string, int, int, string, string) error {
			calls++
			return nil
		},
		feedsFn: func() map[string]feeds.FeedInfo {
			return map[string]feeds.FeedInfo{
				"threats": {ShrinkRefused: true, ShrinkRefusalID: 41, ShrinkCandidateHash: shrinkAckCandidateHash11059, ShrinkBaselineHash: shrinkAckBaselineHash11059, ShrinkCandidateOldCount: 100, ShrinkCandidateNewCount: 5},
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
				"threats": {ShrinkRefused: true, ShrinkRefusalID: 41, ShrinkCandidateHash: shrinkAckCandidateHash11059, ShrinkBaselineHash: shrinkAckBaselineHash11059, ShrinkCandidateOldCount: 100, ShrinkCandidateNewCount: 5},
				"current": {ShrinkRefusalID: 41},
			}
		},
		feedsAckFn: func(string, uint64, string, string, int, int, string, string) error {
			calls++
			return callbackErr
		},
	}
	staleHash := shrinkAckRequest11059("threats", 41, "reviewed")
	staleHash.CandidateHash = strings.Repeat("c", 64)
	staleBaselineHash := shrinkAckRequest11059("threats", 41, "reviewed")
	staleBaselineHash.BaselineHash = strings.Repeat("c", 64)
	staleOldCount := shrinkAckRequest11059("threats", 41, "reviewed")
	staleOldCount.CandidateOldCount--
	staleNewCount := shrinkAckRequest11059("threats", 41, "reviewed")
	staleNewCount.CandidateNewCount++
	missingTuple := shrinkAckRequest11059("threats", 41, "reviewed")
	missingTuple.CandidateHash = ""
	missingBaseline := shrinkAckRequest11059("threats", 41, "reviewed")
	missingBaseline.BaselineHash = ""
	zeroOldCount := shrinkAckRequest11059("threats", 41, "reviewed")
	zeroOldCount.CandidateOldCount = 0
	cases := []struct {
		name       string
		request    *pb.SystemActionRequest
		noCallback bool
		want       codes.Code
	}{
		{name: "missing candidate hash", request: missingTuple, noCallback: true, want: codes.InvalidArgument},
		{name: "missing baseline hash", request: missingBaseline, noCallback: true, want: codes.InvalidArgument},
		{name: "zero old count", request: zeroOldCount, noCallback: true, want: codes.InvalidArgument},
		{name: "stale candidate hash", request: staleHash, noCallback: true, want: codes.FailedPrecondition},
		{name: "stale baseline hash", request: staleBaselineHash, noCallback: true, want: codes.FailedPrecondition},
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

func TestDynamicAddressShrinkAckUsesAdmittedActorAndJournalsCandidateTuple11059(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "xpf.conf")
	store := newConfigStore(t, configPath)
	principal := authz.Principal{
		Source: authz.SourcePeerUID, UID: 4243, Username: "opuser", Class: "config-operator",
	}
	ctx := context.WithValue(context.Background(), authorizedPrincipalKey{}, principal)
	var gotName, gotActor, gotReason, gotHash, gotBaselineHash string
	var gotID uint64
	var gotOldCount, gotNewCount int
	s := &Server{
		store: store,
		feedsFn: func() map[string]feeds.FeedInfo {
			return map[string]feeds.FeedInfo{
				"threats": {ShrinkRefused: true, ShrinkRefusalID: 41, ShrinkCandidateHash: shrinkAckCandidateHash11059, ShrinkBaselineHash: shrinkAckBaselineHash11059, ShrinkCandidateOldCount: 100, ShrinkCandidateNewCount: 5},
			}
		},
		feedsAckFn: func(name string, refusalID uint64, candidateHash, baselineHash string, oldCount, newCount int, actor, reason string) error {
			gotName, gotID, gotHash, gotBaselineHash, gotOldCount, gotNewCount, gotActor, gotReason = name, refusalID, candidateHash, baselineHash, oldCount, newCount, actor, reason
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
	if gotName != "threats" || gotID != 41 || gotHash != shrinkAckCandidateHash11059 ||
		gotBaselineHash != shrinkAckBaselineHash11059 || gotOldCount != 100 ||
		gotNewCount != 5 || gotActor != wantActor || gotReason != "reviewed upstream correction" {
		t.Fatalf("manager callback got (%q, %d, %q, %q, %d, %d, %q, %q), want (%q, 41, %q, %q, 100, 5, %q, %q)",
			gotName, gotID, gotHash, gotBaselineHash, gotOldCount, gotNewCount, gotActor, gotReason,
			"threats", shrinkAckCandidateHash11059, shrinkAckBaselineHash11059, wantActor, "reviewed upstream correction")
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
			strings.Contains(entry.Detail, `candidate_sha256="`+shrinkAckCandidateHash11059+`"`) &&
			strings.Contains(entry.Detail, `baseline_sha256="`+shrinkAckBaselineHash11059+`"`) &&
			strings.Contains(entry.Detail, "old_count=100") &&
			strings.Contains(entry.Detail, "new_count=5") &&
			strings.Contains(entry.Detail, `reason="reviewed upstream correction"`) {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("journal has no attributable feed/candidate/reason acknowledgement entry")
	}
}
