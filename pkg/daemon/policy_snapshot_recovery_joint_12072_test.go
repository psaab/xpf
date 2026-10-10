package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"golang.org/x/sync/semaphore"
)

type policySnapshotRecoveryDP12072 struct {
	*policyInvalTestDP
	manager *dpuserspace.Manager
}

func (d *policySnapshotRecoveryDP12072) Manager() *dpuserspace.Manager {
	return d.manager
}

func (d *policySnapshotRecoveryDP12072) ListSessionsByPolicy(
	req dpuserspace.SessionPolicyListRequest,
) (dpuserspace.ControlResponse, error) {
	return d.manager.ListSessionsByPolicy(req)
}

func TestDeferredLostACKNeighborInterleavingFourCells12072(t *testing.T) {
	for _, debtGeneration := range []uint64{0, 7} {
		for _, neighborChange := range []bool{false, true} {
			t.Run(fmt.Sprintf("debt_%d_neighbor_change_%t", debtGeneration, neighborChange), func(t *testing.T) {
				sockdir, err := os.MkdirTemp("", "r5-")
				if err != nil {
					t.Fatal(err)
				}
				socket := filepath.Join(sockdir, "control.sock")
				ln, err := net.Listen("unix", socket)
				if err != nil {
					_ = os.RemoveAll(sockdir)
					t.Fatal(err)
				}
				var reads atomic.Int32
				serverDone := make(chan struct{})
				go func() {
					defer close(serverDone)
					for {
						conn, err := ln.Accept()
						if err != nil {
							return
						}
						var req dpuserspace.ControlRequest
						if json.NewDecoder(conn).Decode(&req) == nil {
							if req.SessionPolicyList != nil {
								reads.Add(1)
							}
							_ = json.NewEncoder(conn).Encode(dpuserspace.ControlResponse{
								OK: true, SessionPolicyComplete: true,
							})
						}
						_ = conn.Close()
					}
				}()
				t.Cleanup(func() {
					_ = ln.Close()
					<-serverDone
					_ = os.RemoveAll(sockdir)
				})

				oldCfg := twoPolicyConfig([]string{"p-first", "a", "web"}, nil)
				nextCfg := twoPolicyConfig([]string{"p-first", "web"}, nil)
				fixture := dpuserspace.NewPolicySnapshotRecoveryFixtureForTest(oldCfg, nextCfg, socket)
				d := &Daemon{applySem: semaphore.NewWeighted(1)}
				d.setDataplane(&policySnapshotRecoveryDP12072{
					policyInvalTestDP: &policyInvalTestDP{},
					manager:           fixture.ManagerForTest(),
				})

				if err := d.applySem.Acquire(context.Background(), 1); err != nil {
					t.Fatal(err)
				}
				d.armPolicyInvalidationPlan(oldCfg, nextCfg)
				d.capturePolicyInvalidationLocked(nextCfg)
				capture := d.policyInvalidationCapture
				if capture == nil || capture.readErr != nil || capture.v4Err != nil || capture.v6Err != nil ||
					capture.deleted.enumFailed || capture.modified.enumFailed || capture.deflt.enumFailed {
					d.applySem.Release(1)
					t.Fatalf("initial prepublish capture was incomplete: %+v", capture)
				}
				d.notePolicyInvalidationPublish(nextCfg, debtGeneration)
				d.applySem.Release(1)

				prepublishCalls, unknownCalls := 0, 0
				manager := fixture.ManagerForTest()
				manager.SetPolicySnapshotPrePublisher(func(generation uint64) error {
					prepublishCalls++
					if manager.PolicyReadConfig() == nil {
						unknownCalls++
					}
					return d.capturePolicyInvalidationBeforeDeferredPublish(generation)
				})
				fixture.ScriptLostNextApplyAckForTest()
				prepared, err := fixture.TickForTest()
				state := fixture.StateForTest()
				if !prepared || err == nil || state.Sends != 1 || !state.Unknown || !state.Pending ||
					!state.CtrlHeld || state.CtrlEnabled != 0 || state.Stamp != 7 || prepublishCalls != 1 {
					t.Fatalf("lost-ACK setup: prepared=%v err=%v state=%+v prepublish=%d",
						prepared, err, state, prepublishCalls)
				}

				beforeCaptures, beforeReads := prepublishCalls, reads.Load()
				if neighborChange {
					fixture.RegenerateNeighborForTest()
					state = fixture.StateForTest()
					if state.NeighborSends != 1 || state.Retained != 8 || state.Stamp != 7 {
						t.Fatalf("actual neighbor refresh did not advance retained generation: %+v", state)
					}
				}
				for turn := 1; turn <= 3; turn++ {
					prepared, err = fixture.TickForTest()
					if err != nil {
						t.Errorf("healthy recovery turn %d: prepared=%v err=%v", turn, prepared, err)
					}
				}

				state = fixture.StateForTest()
				wantGeneration := uint64(7)
				if neighborChange {
					wantGeneration = 8
				}
				if state.Sends != 2 || state.Unknown || state.Pending || state.CtrlHeld || state.CtrlEnabled != 1 ||
					state.Published != wantGeneration || state.Retained != wantGeneration ||
					manager.PolicyReadConfig() != nextCfg {
					t.Errorf("deferred snapshot did not recover: state=%+v policyAuthority=%p want=%p",
						state, manager.PolicyReadConfig(), nextCfg)
				}
				if got := reads.Load(); got != beforeReads {
					t.Errorf("recovery issued a fresh positional SessionPolicyList: reads %d -> %d", beforeReads, got)
				}
				if !neighborChange && (prepublishCalls != beforeCaptures || unknownCalls != 0) {
					t.Errorf("unchanged generation unexpectedly recaptured: calls %d -> %d, unknown calls %d",
						beforeCaptures, prepublishCalls, unknownCalls)
				}
			})
		}
	}
}
