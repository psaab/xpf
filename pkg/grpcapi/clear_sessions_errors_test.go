// #2468: the gRPC ClearSessions RPC must report sub-operation failures
// (iterator, reverse/companion deletes) via the response Failures /
// FailureSummary fields instead of returning a bare success. These
// tests inject failures through a grpcRuntime that embeds
// *dataplane.Manager and overrides the session methods. They are
// fail-on-revert: the old `_ =`/fire-and-forget discards leave Failures
// at 0 and the assertions go RED.
package grpcapi

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

type clearFaultGRPCDP struct {
	*dataplane.Manager

	v4Sessions map[dataplane.SessionKey]dataplane.SessionValue

	iterErr   error
	iterV6Err error
	// fwdDelErr is returned for a DeleteSession on a seeded (forward)
	// key; revDelErr for any other (computed reverse) key. This split
	// lets a test inject ErrKeyNotExist on the reverse delete (a
	// successful NAT'd clear) independent of the forward delete.
	fwdDelErr  error
	revDelErr  error
	delDNATErr error

	iterCalls       int
	iterV6Calls     int
	iterFromCalls   int
	iterV6FromCalls int
	deleteCalls     int
	deleteV6Calls   int
	dnatCalls       int
	dnatV6Calls     int
	clearAllCalls   int
}

func (d *clearFaultGRPCDP) IsLoaded() bool { return true }

func (d *clearFaultGRPCDP) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	d.iterCalls++
	for k, v := range d.v4Sessions {
		if !fn(k, v) {
			break
		}
	}
	return d.iterErr
}

func (d *clearFaultGRPCDP) IterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	d.iterV6Calls++
	return d.iterV6Err
}

// IterateSessionsFrom / IterateSessionsV6From model the cursor iterator the
// #5454 filtered-clear path uses. Without them the embedded *dataplane.Manager
// promotes a real (empty-map) cursor iterator that would silently iterate
// nothing. They route through the in-memory sessions and preserve the injected
// iterator errors.
func (d *clearFaultGRPCDP) IterateSessionsFrom(cursor *dataplane.SessionKey, fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	d.iterFromCalls++
	iterateV4From(d.v4Sessions, cursor, fn)
	return d.iterErr
}

func (d *clearFaultGRPCDP) IterateSessionsV6From(cursor *dataplane.SessionKeyV6, fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	d.iterV6FromCalls++
	return d.iterV6Err
}

func (d *clearFaultGRPCDP) DeleteSession(key dataplane.SessionKey) error {
	d.deleteCalls++
	if _, isForward := d.v4Sessions[key]; isForward {
		return d.fwdDelErr
	}
	return d.revDelErr
}
func (d *clearFaultGRPCDP) DeleteSessionV6(dataplane.SessionKeyV6) error {
	d.deleteV6Calls++
	return nil
}
func (d *clearFaultGRPCDP) DeleteDNATEntry(dataplane.DNATKey) error {
	d.dnatCalls++
	return d.delDNATErr
}
func (d *clearFaultGRPCDP) DeleteDNATEntryV6(dataplane.DNATKeyV6) error {
	d.dnatV6Calls++
	return nil
}
func (d *clearFaultGRPCDP) ClearAllSessions() (int, int, error) {
	d.clearAllCalls++
	return 0, 0, nil
}
func seedGRPCV4(snat bool) map[dataplane.SessionKey]dataplane.SessionValue {
	// Distinct src/dst ports so the reverse companion key differs from
	// the forward key (the mock distinguishes them by key membership). A
	// reverse companion (val.ReverseKey) is always populated so the clear
	// issues a reverse delete the mock routes to revDelErr (#2733: the
	// clear keys the reverse delete on val.ReverseKey and skips it when
	// ReverseKey.Protocol == 0).
	key := dataplane.SessionKey{Protocol: 6, SrcPort: 0x3930, DstPort: 0x0050}
	val := dataplane.SessionValue{
		ReverseKey: dataplane.SessionKey{Protocol: 6, SrcPort: 0x0050, DstPort: 0x3930},
	}
	if snat {
		val.Flags = dataplane.SessFlagSNAT
	}
	return map[dataplane.SessionKey]dataplane.SessionValue{key: val}
}

func newClearServer(t *testing.T, dp grpcRuntime) *Server {
	t.Helper()
	return &Server{
		store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf")),
		dp:    dp,
		// cluster nil -> standalone, peer-clear is a clean no-op.
	}
}

// protocol-only request -> filtered clear path.
func protoReq() *pb.ClearSessionsRequest {
	return &pb.ClearSessionsRequest{Protocol: "tcp"}
}

func TestClearSessionsRPCReportsIteratorFailure(t *testing.T) {
	dp := &clearFaultGRPCDP{
		Manager:    dataplane.New(),
		v4Sessions: seedGRPCV4(false),
		iterErr:    fmt.Errorf("map dump truncated"),
	}
	s := newClearServer(t, dp)
	resp, err := s.ClearSessions(context.Background(), protoReq())
	if err != nil {
		t.Fatalf("ClearSessions unexpected RPC error: %v", err)
	}
	if resp.Failures == 0 {
		t.Fatalf("iterator failure not reported: Failures=0, summary=%q", resp.FailureSummary)
	}
}

func TestClearSessionsRPCReportsForwardDeleteFailure(t *testing.T) {
	dp := &clearFaultGRPCDP{
		Manager:    dataplane.New(),
		v4Sessions: seedGRPCV4(false),
		fwdDelErr:  fmt.Errorf("kernel map delete EBUSY"),
	}
	s := newClearServer(t, dp)
	resp, err := s.ClearSessions(context.Background(), protoReq())
	if err != nil {
		t.Fatalf("ClearSessions unexpected RPC error: %v", err)
	}
	if resp.Failures == 0 {
		t.Fatalf("forward delete failure not reported: Failures=0, summary=%q", resp.FailureSummary)
	}
	// forward delete failed -> not counted as cleared.
	if resp.Ipv4Cleared != 0 {
		t.Fatalf("Ipv4Cleared=%d, want 0 when forward delete fails", resp.Ipv4Cleared)
	}
}

// A NON-not-found reverse-delete error (EIO etc.) is a real failure and
// MUST still be reported — guards against swinging from over-reporting
// to under-reporting.
func TestClearSessionsRPCReportsReverseDeleteRealError(t *testing.T) {
	dp := &clearFaultGRPCDP{
		Manager:    dataplane.New(),
		v4Sessions: seedGRPCV4(false),
		revDelErr:  fmt.Errorf("map delete EIO"),
	}
	s := newClearServer(t, dp)
	resp, err := s.ClearSessions(context.Background(), protoReq())
	if err != nil {
		t.Fatalf("ClearSessions unexpected RPC error: %v", err)
	}
	if resp.Failures == 0 {
		t.Fatalf("real reverse-delete error not reported: Failures=0, summary=%q", resp.FailureSummary)
	}
	// forward delete still succeeded.
	if resp.Ipv4Cleared != 1 {
		t.Fatalf("Ipv4Cleared=%d, want 1 (forward delete succeeded)", resp.Ipv4Cleared)
	}
}

// #2468 finding 6: the naive-swap reverse key and the DNAT companion key
// are absent for a NAT'd session (the real reverse companion is keyed on
// the translated tuple val.ReverseKey), so both deletes return
// ErrKeyNotExist on a fully-successful clear. That benign not-found must
// NOT inflate Failures. Fail-on-revert: addExceptNotFound -> add() turns
// this RED.
func TestClearSessionsRPCNATReverseNotFoundNotReported(t *testing.T) {
	dp := &clearFaultGRPCDP{
		Manager:    dataplane.New(),
		v4Sessions: seedGRPCV4(true),    // SNAT session
		revDelErr:  ebpf.ErrKeyNotExist, // naive-swap reverse key absent
		delDNATErr: ebpf.ErrKeyNotExist, // DNAT companion key absent
	}
	s := newClearServer(t, dp)
	resp, err := s.ClearSessions(context.Background(), protoReq())
	if err != nil {
		t.Fatalf("ClearSessions unexpected RPC error: %v", err)
	}
	if resp.Failures != 0 {
		t.Fatalf("benign ErrKeyNotExist inflated Failures=%d summary=%q", resp.Failures, resp.FailureSummary)
	}
	if resp.Ipv4Cleared != 1 {
		t.Fatalf("Ipv4Cleared=%d, want 1", resp.Ipv4Cleared)
	}
}

func TestClearSessionsRPCReportsDNATCompanionFailure(t *testing.T) {
	dp := &clearFaultGRPCDP{
		Manager:    dataplane.New(),
		v4Sessions: seedGRPCV4(true), // SNAT -> DNAT companion delete attempted
		delDNATErr: fmt.Errorf("dnat map delete failed"),
	}
	s := newClearServer(t, dp)
	resp, err := s.ClearSessions(context.Background(), protoReq())
	if err != nil {
		t.Fatalf("ClearSessions unexpected RPC error: %v", err)
	}
	if resp.Failures == 0 {
		t.Fatalf("DNAT companion failure not reported: Failures=0, summary=%q", resp.FailureSummary)
	}
}

// Happy path: all sub-operations succeed -> Failures==0, cleared count
// accurate, no spurious failure summary.
func TestClearSessionsRPCHappyPathNoFailures(t *testing.T) {
	dp := &clearFaultGRPCDP{
		Manager:    dataplane.New(),
		v4Sessions: seedGRPCV4(true),
	}
	s := newClearServer(t, dp)
	resp, err := s.ClearSessions(context.Background(), protoReq())
	if err != nil {
		t.Fatalf("ClearSessions unexpected RPC error: %v", err)
	}
	if resp.Failures != 0 {
		t.Fatalf("happy path reported Failures=%d summary=%q, want 0", resp.Failures, resp.FailureSummary)
	}
	if resp.Ipv4Cleared != 1 {
		t.Fatalf("Ipv4Cleared=%d, want 1", resp.Ipv4Cleared)
	}
}
