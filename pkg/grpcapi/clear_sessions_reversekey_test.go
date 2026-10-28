// #2733: the gRPC ClearSessions RPC must delete a NAT'd session's reverse
// companion at the TRANSLATED tuple (val.ReverseKey), not the naive
// src/dst swap of the forward key. These tests record the exact keys
// DeleteSession is called with. Fail-on-revert: restoring the naive-swap
// key construction leaks val.ReverseKey and the assertion goes RED.
package grpcapi

import (
	"context"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

type recordingClearGRPCDP struct {
	*dataplane.Manager

	v4Sessions map[dataplane.SessionKey]dataplane.SessionValue

	deletedV4 []dataplane.SessionKey
	missingV4 map[dataplane.SessionKey]bool
}

func (d *recordingClearGRPCDP) IsLoaded() bool { return true }

func (d *recordingClearGRPCDP) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	for k, v := range d.v4Sessions {
		if !fn(k, v) {
			break
		}
	}
	return nil
}

func (d *recordingClearGRPCDP) IterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	return nil
}

// Cursor iterators for the #5454 filtered-clear path (the embedded
// *dataplane.Manager would otherwise promote empty-map iterators).
func (d *recordingClearGRPCDP) IterateSessionsFrom(cursor *dataplane.SessionKey, fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	iterateV4From(d.v4Sessions, cursor, fn)
	return nil
}

func (d *recordingClearGRPCDP) IterateSessionsV6From(cursor *dataplane.SessionKeyV6, fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	return nil
}

func (d *recordingClearGRPCDP) DeleteSession(key dataplane.SessionKey) error {
	d.deletedV4 = append(d.deletedV4, key)
	if d.missingV4[key] {
		return ebpf.ErrKeyNotExist
	}
	return nil
}

func (d *recordingClearGRPCDP) DeleteSessionV6(dataplane.SessionKeyV6) error { return nil }

func recContainsV4(keys []dataplane.SessionKey, want dataplane.SessionKey) bool {
	for _, k := range keys {
		if k == want {
			return true
		}
	}
	return false
}

func TestClearSessionsRPCDeletesTranslatedReverseKey(t *testing.T) {
	fwd := dataplane.SessionKey{
		Protocol: 6,
		SrcIP:    [4]byte{10, 0, 1, 10},
		DstIP:    [4]byte{8, 8, 8, 8},
		SrcPort:  0x03e8,
		DstPort:  0x01bb,
	}
	translatedRev := dataplane.SessionKey{
		Protocol: 6,
		SrcIP:    [4]byte{8, 8, 8, 8},
		DstIP:    [4]byte{203, 0, 113, 5},
		SrcPort:  0x01bb,
		DstPort:  0xc350,
	}
	naiveSwap := dataplane.SessionKey{
		Protocol: 6,
		SrcIP:    fwd.DstIP,
		DstIP:    fwd.SrcIP,
		SrcPort:  fwd.DstPort,
		DstPort:  fwd.SrcPort,
	}
	val := dataplane.SessionValue{
		Flags:      dataplane.SessFlagSNAT,
		ReverseKey: translatedRev,
	}

	dp := &recordingClearGRPCDP{
		Manager:    dataplane.New(),
		v4Sessions: map[dataplane.SessionKey]dataplane.SessionValue{fwd: val},
		missingV4:  map[dataplane.SessionKey]bool{naiveSwap: true},
	}
	s := newClearServer(t, dp)
	resp, err := s.ClearSessions(context.Background(), &pb.ClearSessionsRequest{Protocol: "tcp"})
	if err != nil {
		t.Fatalf("ClearSessions RPC error: %v", err)
	}
	if !recContainsV4(dp.deletedV4, fwd) {
		t.Fatalf("forward key not deleted; deleted=%v", dp.deletedV4)
	}
	if !recContainsV4(dp.deletedV4, translatedRev) {
		t.Fatalf("translated reverse companion (val.ReverseKey) NOT deleted — leak (#2733); deleted=%v", dp.deletedV4)
	}
	if recContainsV4(dp.deletedV4, naiveSwap) {
		t.Fatalf("naive src/dst swap deleted — wrong key (#2733); deleted=%v", dp.deletedV4)
	}
	if resp.Failures != 0 {
		t.Fatalf("Failures=%d summary=%q, want 0", resp.Failures, resp.FailureSummary)
	}
	if resp.Ipv4Cleared != 1 {
		t.Fatalf("Ipv4Cleared=%d, want 1", resp.Ipv4Cleared)
	}
}

func TestClearSessionsRPCNonNATReverseUnchanged(t *testing.T) {
	fwd := dataplane.SessionKey{
		Protocol: 6,
		SrcIP:    [4]byte{10, 0, 1, 10},
		DstIP:    [4]byte{10, 0, 2, 20},
		SrcPort:  0x03e8,
		DstPort:  0x01bb,
	}
	rev := dataplane.SessionKey{
		Protocol: 6,
		SrcIP:    fwd.DstIP,
		DstIP:    fwd.SrcIP,
		SrcPort:  fwd.DstPort,
		DstPort:  fwd.SrcPort,
	}
	val := dataplane.SessionValue{ReverseKey: rev}

	dp := &recordingClearGRPCDP{
		Manager:    dataplane.New(),
		v4Sessions: map[dataplane.SessionKey]dataplane.SessionValue{fwd: val},
	}
	s := newClearServer(t, dp)
	if _, err := s.ClearSessions(context.Background(), &pb.ClearSessionsRequest{Protocol: "tcp"}); err != nil {
		t.Fatalf("ClearSessions RPC error: %v", err)
	}
	if !recContainsV4(dp.deletedV4, fwd) || !recContainsV4(dp.deletedV4, rev) {
		t.Fatalf("non-NAT forward/reverse not both deleted; deleted=%v", dp.deletedV4)
	}
}

func TestClearSessionsRPCNoReverseCompanionSkipsReverseDelete(t *testing.T) {
	fwd := dataplane.SessionKey{
		Protocol: 6,
		SrcIP:    [4]byte{10, 0, 1, 10},
		DstIP:    [4]byte{10, 0, 2, 20},
		SrcPort:  0x03e8,
		DstPort:  0x01bb,
	}
	val := dataplane.SessionValue{} // ReverseKey zero -> Protocol==0

	dp := &recordingClearGRPCDP{
		Manager:    dataplane.New(),
		v4Sessions: map[dataplane.SessionKey]dataplane.SessionValue{fwd: val},
	}
	s := newClearServer(t, dp)
	if _, err := s.ClearSessions(context.Background(), &pb.ClearSessionsRequest{Protocol: "tcp"}); err != nil {
		t.Fatalf("ClearSessions RPC error: %v", err)
	}
	if len(dp.deletedV4) != 1 || dp.deletedV4[0] != fwd {
		t.Fatalf("expected only forward key deleted, got %v", dp.deletedV4)
	}
}
