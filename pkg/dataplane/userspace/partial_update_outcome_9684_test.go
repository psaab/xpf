package userspace

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	gotypes "go/types"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #9684: a partial update whose response is lost must not be rolled back by the
// next publish that starts from m.lastSnapshot. The mechanism and its reasoning
// are stated once, in partial_update_outcome_9684.go.

var (
	staleNeighbor9684 = NeighborSnapshot{Ifindex: 13, Family: "inet", IP: "172.16.80.200", MAC: "02:00:00:00:96:01", State: "reachable"}
	freshNeighbor9684 = NeighborSnapshot{Ifindex: 13, Family: "inet", IP: "172.16.80.200", MAC: "02:00:00:00:96:02", State: "reachable"}
	staleFabric9684   = FabricSnapshot{Name: "fab0", ParentInterface: "ge-0/0/0", ParentLinuxName: "ge-0-0-0", PeerAddress: "10.99.1.2", Up: true}
	freshFabric9684   = FabricSnapshot{Name: "fab0", ParentInterface: "ge-0/0/0", ParentLinuxName: "ge-0-0-0", PeerAddress: "10.99.1.2", PeerMAC: "02:aa:bb:cc:96:84", Up: true}
)

// partialRecorder9684 is a fake helper for the two partial updates and
// apply_snapshot. verbReply answers update_neighbors / update_fabrics and
// applyReply answers apply_snapshot; nil is success. A successful
// update_neighbors ACKs the generation it carried unless fenceACK is set.
type partialRecorder9684 struct {
	verbReply  error
	applyReply error
	fenceACK   uint64
	verbs      []ControlRequest
	applies    []ConfigSnapshot
}

func (r *partialRecorder9684) hook(req ControlRequest, status *ProcessStatus) error {
	switch req.Type {
	case "update_neighbors", "update_fabrics":
		r.verbs = append(r.verbs, req)
		if r.verbReply != nil {
			return r.verbReply
		}
		if status != nil {
			ack := req.NeighborGeneration
			if r.fenceACK != 0 {
				ack = r.fenceACK
			}
			*status = ProcessStatus{ConfigSnapshotProtocolVersion: ProtocolVersion, ManagerNeighborGeneration: ack}
		}
	case "apply_snapshot":
		r.applies = append(r.applies, *req.Snapshot)
		if r.applyReply != nil {
			return r.applyReply
		}
		if status != nil {
			*status = ProcessStatus{
				ConfigSnapshotProtocolVersion: ProtocolVersion,
				LastSnapshotGeneration:        req.Snapshot.Generation,
				LastFIBGeneration:             req.Snapshot.FIBGeneration,
			}
		}
	}
	return nil
}

func (r *partialRecorder9684) neighborUpdates() int {
	n := 0
	for _, v := range r.verbs {
		if v.Type == "update_neighbors" {
			n++
		}
	}
	return n
}

// section9684 is one partial-update section: the update that carries it, the
// mark it sets, and how a snapshot's copy of it is named in a failure message.
type section9684 struct {
	name         string
	mark         partialSections
	update       func(m *Manager)
	carried      func(s *ConfigSnapshot) string
	stale, fresh string
}

func sections9684() []section9684 {
	return []section9684{
		{
			name:    "neighbors",
			mark:    partialNeighbors,
			update:  func(m *Manager) { m.RegenerateNeighborSnapshot() },
			carried: func(s *ConfigSnapshot) string { return neighborsCarried9684(s.Neighbors) },
			stale:   staleNeighbor9684.MAC,
			fresh:   freshNeighbor9684.MAC,
		},
		{
			name:    "fabrics",
			mark:    partialFabrics,
			update:  func(m *Manager) { m.SyncFabricState() },
			carried: func(s *ConfigSnapshot) string { return fabricsCarried9684(s.Fabrics) },
			stale:   "unresolved",
			fresh:   freshFabric9684.PeerMAC,
		},
	}
}

// neighborSenders9684 are the two update_neighbors senders.
func neighborSenders9684() []struct {
	name string
	send func(m *Manager)
} {
	return []struct {
		name string
		send func(m *Manager)
	}{
		{"RegenerateNeighborSnapshot", func(m *Manager) { m.RegenerateNeighborSnapshot() }},
		{"BumpFIBGeneration", func(m *Manager) { _, _ = m.BumpFIBGeneration() }},
	}
}

func neighborsCarried9684(rows []NeighborSnapshot) string {
	if len(rows) != 1 {
		return fmt.Sprintf("%d neighbor rows", len(rows))
	}
	return rows[0].MAC
}

func fabricsCarried9684(rows []FabricSnapshot) string {
	if len(rows) != 1 {
		return fmt.Sprintf("%d fabric rows", len(rows))
	}
	if rows[0].PeerMAC == "" {
		return "unresolved"
	}
	return rows[0].PeerMAC
}

// staleSections9684 gives snap the neighbor and fabric sections the helper held
// before the lost update.
func staleSections9684(snap *ConfigSnapshot) *ConfigSnapshot {
	snap.Neighbors = []NeighborSnapshot{staleNeighbor9684}
	snap.Fabrics = []FabricSnapshot{staleFabric9684}
	return snap
}

// withFreshKernel9684 routes m's control requests to rec and makes the kernel
// samples return the fresh sections.
func withFreshKernel9684(m *Manager, rec *partialRecorder9684) *Manager {
	m.controlRequestHook = rec.hook
	m.neighborSnapshotBuilder = func(*config.Config) []NeighborSnapshot { return []NeighborSnapshot{freshNeighbor9684} }
	m.fabricSnapshotBuilder = func(*config.Config) []FabricSnapshot { return []FabricSnapshot{freshFabric9684} }
	return m
}

// withStaleKernel9684 makes the kernel samples return lastSnapshot's copies: the
// kernel went back after the lost update.
func withStaleKernel9684(m *Manager) {
	m.neighborSnapshotBuilder = func(*config.Config) []NeighborSnapshot { return []NeighborSnapshot{staleNeighbor9684} }
	m.fabricSnapshotBuilder = func(*config.Config) []FabricSnapshot { return []FabricSnapshot{staleFabric9684} }
}

func runDeferredSync9684(m *Manager) error {
	m.mu.Lock()
	err := m.syncSnapshotLocked()
	cancel := m.syncCancel
	m.syncCancel = nil
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return err
}

// newDeferredSyncManager9684 is the #9337 deferred-publish fixture with the stale
// sections and a published plan keyed on them.
func newDeferredSyncManager9684(t *testing.T, rec *partialRecorder9684) (*Manager, *ConfigSnapshot) {
	t.Helper()
	f := newDeferredPublishFixture9337(t, nil)
	staleSections9684(f.snap)
	// The fixture keyed the published plan before the sections were set.
	f.m.publishedPlanKey = snapshotBindingPlanKey(f.snap)
	return withFreshKernel9684(f.m, rec), f.snap
}

// republishPath9684 is one publish that starts from m.lastSnapshot.
type republishPath9684 struct {
	name string
	// newManager returns a running-helper manager whose last snapshot carries the
	// stale sections and whose kernel samples are the fresh ones.
	newManager func(t *testing.T, rec *partialRecorder9684) *Manager
	run        func(m *Manager) error
}

func republishPaths9684() []republishPath9684 {
	return []republishPath9684{
		{
			name: "policy-scheduler republish",
			newManager: func(t *testing.T, rec *partialRecorder9684) *Manager {
				snap := staleSections9684(mustBuildSnapshot(t, scheduledPolicyConfig9520(), config.UserspaceConfig{}, 7, 0))
				return withFreshKernel9684(newRepublishManager9520(snap, &applyRecorder9520{}), rec)
			},
			run: func(m *Manager) error {
				return m.UpdatePolicyScheduleState(m.lastSnapshot.Config, map[string]bool{"workhours": true})
			},
		},
		{
			name: "route-overlay republish",
			newManager: func(t *testing.T, rec *partialRecorder9684) *Manager {
				snap := staleSections9684(mustBuildSnapshot(t, overlayTestConfig(), config.UserspaceConfig{}, 7, 0))
				return withFreshKernel9684(newRepublishManager9520(snap, &applyRecorder9520{}), rec)
			},
			run: func(m *Manager) error {
				overlay := []config.RouteOverlayEntry{{Destination: "0.0.0.0/0", NextHop: "172.16.80.1", Policy: "wan-failover"}}
				published, err := m.PublishRouteOverlaySnapshot(m.lastSnapshot.Config, overlay, nil)
				if err == nil && !published {
					return fmt.Errorf("the overlay publish was skipped")
				}
				return err
			},
		},
		{
			name: "#5134 worker-arm re-apply",
			newManager: func(t *testing.T, rec *partialRecorder9684) *Manager {
				snap, err := buildSnapshot(&config.Config{}, config.UserspaceConfig{}, 7, 0)
				if err != nil {
					t.Fatalf("buildSnapshot: %v", err)
				}
				snap.DeferWorkers = true
				m := withFreshKernel9684(newRepublishManager9520(staleSections9684(snap), &applyRecorder9520{}), rec)
				m.RecordDeferredWorkerArmDebt()
				return m
			},
			run: func(m *Manager) error {
				m.mu.Lock()
				defer m.mu.Unlock()
				return m.retryDeferredWorkerArmLocked()
			},
		},
		{
			name: "deferred syncSnapshotLocked publish",
			newManager: func(t *testing.T, rec *partialRecorder9684) *Manager {
				m, _ := newDeferredSyncManager9684(t, rec)
				return m
			},
			run: runDeferredSync9684,
		},
	}
}

// TestALostPartialUpdateIsNotRolledBackByARepublish9684 is the issue's
// acceptance shape, for every publish that starts from m.lastSnapshot and both
// sections. The helper applied the update but the response was lost. The next
// publish must carry a fresh sample, not lastSnapshot's copy, which is the one it
// replaced, and it must do so in the same call.
func TestALostPartialUpdateIsNotRolledBackByARepublish9684(t *testing.T) {
	for _, path := range republishPaths9684() {
		for _, sec := range sections9684() {
			t.Run(path.name+"/"+sec.name, func(t *testing.T) {
				rec := &partialRecorder9684{verbReply: errLostResponse9520}
				m := path.newManager(t, rec)

				sec.update(m)
				if len(rec.verbs) != 1 {
					t.Fatalf("premise: the %s update was not sent (%d requests)", sec.name, len(rec.verbs))
				}
				if !m.partialSectionUnknownLocked(sec.mark) {
					t.Fatalf("a lost %s response must mark the section unknown", sec.name)
				}
				if got := sec.carried(m.lastSnapshot); got != sec.stale {
					t.Fatalf("premise: a lost update must leave lastSnapshot's %s at the old copy, got %q", sec.name, got)
				}

				rec.verbReply = nil
				if err := path.run(m); err != nil {
					t.Fatalf("%s after a lost %s response: %v", path.name, sec.name, err)
				}
				if len(rec.applies) != 1 {
					t.Fatalf("%s sent %d apply_snapshot requests, want 1 in the same call", path.name, len(rec.applies))
				}
				sent := rec.applies[0]
				if got := sec.carried(&sent); got != sec.fresh {
					t.Fatalf("%s re-sent %s %q after a lost update, want the fresh sample %q: "+
						"the helper is rolled back to the copy the update replaced", path.name, sec.name, got, sec.fresh)
				}
				for _, other := range sections9684() {
					if other.mark == sec.mark {
						continue
					}
					if got := other.carried(&sent); got != other.stale {
						t.Fatalf("%s re-sampled %s (%q) with no lost update to it: only a marked section is re-sampled",
							path.name, other.name, got)
					}
				}
				if m.partialSectionUnknownLocked(sec.mark) {
					t.Fatalf("%s landed a re-sampled %s section, which must unmark it", path.name, sec.name)
				}
				if got := sec.carried(m.lastSnapshot); got != sec.fresh {
					t.Fatalf("after %s, lastSnapshot must record the %s the helper holds: got %q, want %q",
						path.name, sec.name, got, sec.fresh)
				}
				if h, ok := snapshotContentHash(m.lastSnapshot); !ok || h != m.lastSnapshotHash {
					t.Fatalf("after %s, lastSnapshotHash must describe lastSnapshot's content, re-sampled %s included",
						path.name, sec.name)
				}
			})
		}
	}
}

// TestAResampleEqualToLastSnapshotIsStillPublished9684: after a lost update, a
// kernel back at lastSnapshot's copy re-samples to content that hashes the same
// as the last publish. The shortcuts that would skip that publish infer the
// helper's content from m.lastSnapshot, which is exactly what a lost update made
// unknown. So they must stand down, or the helper keeps the lost update's
// content. Each cell has an unmarked control that proves the shortcut is live.
func TestAResampleEqualToLastSnapshotIsStillPublished9684(t *testing.T) {
	cells := []struct {
		name string
		// newManager arms the shortcut: an unmarked run of it publishes nothing.
		newManager func(t *testing.T, rec *partialRecorder9684) *Manager
		run        func(m *Manager) error
	}{
		{
			name: "route-overlay content-hash dedup",
			newManager: func(t *testing.T, rec *partialRecorder9684) *Manager {
				snap := staleSections9684(mustBuildSnapshot(t, overlayTestConfig(), config.UserspaceConfig{}, 7, 0))
				return withFreshKernel9684(newRepublishManager9520(snap, &applyRecorder9520{}), rec)
			},
			run: func(m *Manager) error {
				_, err := m.PublishRouteOverlaySnapshot(m.lastSnapshot.Config, nil, nil)
				return err
			},
		},
		{
			name: "syncSnapshotLocked hash dedup",
			newManager: func(t *testing.T, rec *partialRecorder9684) *Manager {
				m, snap := newDeferredSyncManager9684(t, rec)
				h, ok := snapshotContentHash(snap)
				if !ok {
					t.Fatal("fixture: the snapshot must hash")
				}
				m.lastSnapshotHash = h
				return m
			},
			run: runDeferredSync9684,
		},
		{
			name: "syncSnapshotLocked generation catch-up",
			newManager: func(t *testing.T, rec *partialRecorder9684) *Manager {
				m, snap := newDeferredSyncManager9684(t, rec)
				m.lastStatus.LastSnapshotGeneration = snap.Generation
				return m
			},
			run: runDeferredSync9684,
		},
	}
	for _, c := range cells {
		t.Run(c.name, func(t *testing.T) {
			control := &partialRecorder9684{}
			cm := c.newManager(t, control)
			withStaleKernel9684(cm)
			if err := c.run(cm); err != nil {
				t.Fatalf("control: %v", err)
			}
			if len(control.applies) != 0 {
				t.Fatalf("premise: with nothing marked, the %s must skip this publish (sent %d)", c.name, len(control.applies))
			}

			for _, sec := range sections9684() {
				rec := &partialRecorder9684{verbReply: errLostResponse9520}
				m := c.newManager(t, rec)
				sec.update(m)
				withStaleKernel9684(m)
				rec.verbReply = nil
				if err := c.run(m); err != nil {
					t.Fatalf("%s after a lost %s response: %v", c.name, sec.name, err)
				}
				if len(rec.applies) != 1 {
					t.Fatalf("the %s skipped the publish while %s was unknown (sent %d): the helper keeps the lost update's content",
						c.name, sec.name, len(rec.applies))
				}
				if got := sec.carried(&rec.applies[0]); got != sec.stale {
					t.Fatalf("the publish carried %s %q, want the kernel's current copy %q", sec.name, got, sec.stale)
				}
				if m.partialSectionUnknownLocked(sec.mark) {
					t.Fatalf("the landed publish must unmark %s", sec.name)
				}
			}
		})
	}
}

// TestARefusedPartialUpdateMarksNothingAndHoldsNothing9684: an in-band refusal,
// and a #6034 fence the ACK check recognises, prove the helper kept what it had.
// Neither may mark the section, and the next publish goes out in the same call
// carrying lastSnapshot's copy.
func TestARefusedPartialUpdateMarksNothingAndHoldsNothing9684(t *testing.T) {
	neighbors, fabrics := sections9684()[0], sections9684()[1]
	cells := []struct {
		name    string
		section section9684
		arrange func(rec *partialRecorder9684, m *Manager)
	}{
		{"neighbors refused in band", neighbors, func(rec *partialRecorder9684, _ *Manager) {
			rec.verbReply = newHelperRejection("update_neighbors refused")
		}},
		{"fabrics refused in band", fabrics, func(rec *partialRecorder9684, _ *Manager) {
			rec.verbReply = newHelperRejection("update_fabrics refused")
		}},
		{"neighbors fenced (#6034)", neighbors, func(rec *partialRecorder9684, m *Manager) {
			m.neighborReplaceGen = 4
			rec.fenceACK = 4
		}},
	}
	scheduler := republishPaths9684()[0]
	for _, c := range cells {
		t.Run(c.name, func(t *testing.T) {
			rec := &partialRecorder9684{}
			m := scheduler.newManager(t, rec)
			c.arrange(rec, m)

			c.section.update(m)
			if len(rec.verbs) != 1 {
				t.Fatalf("premise: the %s update was not sent", c.section.name)
			}
			if m.partialSectionUnknownLocked(c.section.mark) {
				t.Fatalf("%s: the helper answered and kept what it had, so nothing may be marked", c.name)
			}

			rec.verbReply, rec.fenceACK = nil, 0
			if err := scheduler.run(m); err != nil {
				t.Fatalf("scheduler republish: %v", err)
			}
			if len(rec.applies) != 1 {
				t.Fatalf("%s: the republish sent %d apply_snapshot requests, want 1 in the same call", c.name, len(rec.applies))
			}
			if got := c.section.carried(&rec.applies[0]); got != c.section.stale {
				t.Fatalf("%s: the republish carried %s %q, want lastSnapshot's copy %q", c.name, c.section.name, got, c.section.stale)
			}
		})
	}
}

// TestAnUnchangedNeighborSetIsReSentWhileItsOutcomeIsUnknown9684: after a lost
// replace, a kernel back at lastSnapshot's set proves nothing about what the
// helper holds. Both neighbor senders must re-send it once, then go quiet.
func TestAnUnchangedNeighborSetIsReSentWhileItsOutcomeIsUnknown9684(t *testing.T) {
	stale := func(*config.Config) []NeighborSnapshot { return []NeighborSnapshot{staleNeighbor9684} }
	fresh := func(*config.Config) []NeighborSnapshot { return []NeighborSnapshot{freshNeighbor9684} }
	for _, s := range neighborSenders9684() {
		t.Run(s.name, func(t *testing.T) {
			rec := &partialRecorder9684{}
			m := republishPaths9684()[0].newManager(t, rec)

			m.neighborSnapshotBuilder = stale
			s.send(m)
			if n := rec.neighborUpdates(); n != 0 {
				t.Fatalf("control: a known, unchanged neighbor set was sent %d times", n)
			}

			m.neighborSnapshotBuilder = fresh
			rec.verbReply = errLostResponse9520
			s.send(m)
			if rec.neighborUpdates() != 1 || !m.partialSectionUnknownLocked(partialNeighbors) {
				t.Fatalf("premise: the lost replace of a changed set must be sent and mark the section (sent %d)", rec.neighborUpdates())
			}

			m.neighborSnapshotBuilder = stale
			rec.verbReply = nil
			s.send(m)
			if n := rec.neighborUpdates(); n != 2 {
				t.Fatalf("%s sent %d neighbor updates, want the unchanged set re-sent while the section is unknown", s.name, n)
			}
			if got := neighborsCarried9684(rec.verbs[len(rec.verbs)-1].Neighbors); got != staleNeighbor9684.MAC {
				t.Fatalf("the re-send carried %q, want the kernel's current set %q", got, staleNeighbor9684.MAC)
			}
			if m.partialSectionUnknownLocked(partialNeighbors) {
				t.Fatal("a landed re-send must unmark the section")
			}

			s.send(m)
			if n := rec.neighborUpdates(); n != 2 {
				t.Fatalf("once the re-send landed, the unchanged set must not be sent again (sent %d)", n)
			}
		})
	}
}

// TestAnACKAboveTheSentGenerationKeepsTheSectionUnknown9684: the helper ACKs its
// applied generation, so an ACK above the one sent means this replace was fenced
// (#9696 owns the Go check that does not yet recognise that). A landed-looking
// response of that kind must not unmark a section a lost update left unknown.
func TestAnACKAboveTheSentGenerationKeepsTheSectionUnknown9684(t *testing.T) {
	for _, s := range neighborSenders9684() {
		t.Run(s.name, func(t *testing.T) {
			rec := &partialRecorder9684{verbReply: errLostResponse9520}
			m := republishPaths9684()[0].newManager(t, rec)
			m.neighborReplaceGen = 4
			s.send(m)
			if !m.partialSectionUnknownLocked(partialNeighbors) {
				t.Fatal("premise: the lost replace must mark the section")
			}

			rec.verbReply, rec.fenceACK = nil, 100
			s.send(m)
			if n := rec.neighborUpdates(); n != 2 {
				t.Fatalf("premise: the second replace was not sent (%d updates)", n)
			}
			if sent := rec.verbs[len(rec.verbs)-1].NeighborGeneration; sent >= 100 {
				t.Fatalf("premise: the second replace carried generation %d, want one below the ACK of 100", sent)
			}
			if !m.partialSectionUnknownLocked(partialNeighbors) {
				t.Fatalf("%s: an ACK of 100 for a replace sent below it is a fence, so the section must stay unknown", s.name)
			}
		})
	}
}

// TestALandedPartialUpdateUnmarksItsSection9684: after a lost update, the next
// update of the same section that lands records exactly what the helper holds,
// so it unmarks the section itself instead of leaving that to a republish.
func TestALandedPartialUpdateUnmarksItsSection9684(t *testing.T) {
	for _, sec := range sections9684() {
		t.Run(sec.name, func(t *testing.T) {
			rec := &partialRecorder9684{verbReply: errLostResponse9520}
			m := republishPaths9684()[0].newManager(t, rec)
			sec.update(m)
			if !m.partialSectionUnknownLocked(sec.mark) {
				t.Fatalf("premise: a lost %s response must mark the section", sec.name)
			}

			rec.verbReply = nil
			sec.update(m)
			if len(rec.verbs) != 2 {
				t.Fatalf("premise: the second %s update was not sent (%d requests)", sec.name, len(rec.verbs))
			}
			if m.partialSectionUnknownLocked(sec.mark) {
				t.Fatalf("a landed %s update must unmark the section", sec.name)
			}
			if got := sec.carried(m.lastSnapshot); got != sec.fresh {
				t.Fatalf("a landed %s update must record the fresh copy, got %q", sec.name, got)
			}
		})
	}
}

// TestALostRepublishKeepsTheSectionUnknown9684: Go learns what the helper holds
// only from a publish that lands. A re-sampled republish whose own response is
// lost must leave the section marked and lastSnapshot's copy untouched; the next
// one re-samples again.
func TestALostRepublishKeepsTheSectionUnknown9684(t *testing.T) {
	scheduler := republishPaths9684()[0]
	for _, sec := range sections9684() {
		t.Run(sec.name, func(t *testing.T) {
			rec := &partialRecorder9684{verbReply: errLostResponse9520}
			m := scheduler.newManager(t, rec)
			sec.update(m)

			rec.verbReply, rec.applyReply = nil, errLostResponse9520
			if err := scheduler.run(m); err == nil {
				t.Fatal("premise: the lost apply_snapshot response must surface as an error")
			}
			if !m.partialSectionUnknownLocked(sec.mark) {
				t.Fatalf("a republish with no response must not unmark %s", sec.name)
			}
			if got := sec.carried(m.lastSnapshot); got != sec.stale {
				t.Fatalf("a republish with no response must not record %s into lastSnapshot, got %q", sec.name, got)
			}

			rec.applyReply = nil
			if err := scheduler.run(m); err != nil {
				t.Fatalf("second republish: %v", err)
			}
			last := rec.applies[len(rec.applies)-1]
			if got := sec.carried(&last); got != sec.fresh {
				t.Fatalf("the second republish carried %s %q, want the fresh sample %q", sec.name, got, sec.fresh)
			}
			if m.partialSectionUnknownLocked(sec.mark) {
				t.Fatalf("the landed republish must unmark %s", sec.name)
			}
		})
	}
}

// TestAFabricResampleNeverMovesTheBindingPlan9684: the binding plan key (on both
// planes) and the classifier maps read a fabric row's parent netdev, ifindex and
// queue count, and its device verdict. A publish that moved that half would make
// the helper replan while Go's maps still carry the old answer. So a re-sample
// may refresh only the MAC and link-state half. Every publish that re-samples
// must keep the plan half of the snapshot it sends, and the plan key with it.
func TestAFabricResampleNeverMovesTheBindingPlan9684(t *testing.T) {
	for _, path := range republishPaths9684() {
		t.Run(path.name, func(t *testing.T) {
			rec := &partialRecorder9684{verbReply: errLostResponse9520}
			m := path.newManager(t, rec)
			moved := freshFabric9684
			moved.ParentIfindex, moved.RXQueues, moved.ParentUnbindable = 21, 8, true
			moved.ParentInterface, moved.ParentLinuxName = "ge-0/0/1", "ge-0-0-1"
			moved.OverlayLinux, moved.OverlayIfindex = "fab0-new", 202
			m.fabricSnapshotBuilder = func(*config.Config) []FabricSnapshot { return []FabricSnapshot{moved} }
			pre := *m.lastSnapshot
			pre.DeferWorkers = false
			before := snapshotBindingPlanKey(&pre)

			m.SyncFabricState()
			if !m.partialSectionUnknownLocked(partialFabrics) {
				t.Fatal("premise: the lost update_fabrics must mark the section")
			}
			rec.verbReply = nil
			if err := path.run(m); err != nil {
				t.Fatalf("%s: %v", path.name, err)
			}
			if len(rec.applies) != 1 {
				t.Fatalf("%s sent %d apply_snapshot requests, want 1", path.name, len(rec.applies))
			}
			sent := rec.applies[0].Fabrics
			if len(sent) != 1 || sent[0].PeerMAC != moved.PeerMAC {
				t.Fatalf("%s sent fabrics %+v, want the re-sampled peer MAC %q", path.name, sent, moved.PeerMAC)
			}
			if sent[0].ParentIfindex != staleFabric9684.ParentIfindex || sent[0].RXQueues != staleFabric9684.RXQueues ||
				sent[0].ParentUnbindable != staleFabric9684.ParentUnbindable ||
				sent[0].ParentInterface != staleFabric9684.ParentInterface ||
				sent[0].ParentLinuxName != staleFabric9684.ParentLinuxName {
				t.Fatalf("%s re-sampled the fabric row's plan half (%+v): a re-sample must keep it", path.name, sent[0])
			}
			if sent[0].OverlayLinux != moved.OverlayLinux || sent[0].OverlayIfindex != moved.OverlayIfindex {
				t.Errorf("%s kept the fabric overlay %s/%d, want the re-sampled %s/%d: the helper recognises fabric ingress by it",
					path.name, sent[0].OverlayLinux, sent[0].OverlayIfindex, moved.OverlayLinux, moved.OverlayIfindex)
			}
			if got := snapshotBindingPlanKey(&rec.applies[0]); got != before {
				t.Fatalf("%s moved the binding plan key with a re-sample:\n  before %s\n  sent   %s", path.name, before, got)
			}
		})
	}
}

// TestADeferredXSKStartupTickSamplesNothing9684: during XSK startup,
// syncSnapshotLocked defers a publish whose plan differs from the published one.
// The probe can extend without bound while a link is idle, so a deferred tick
// must not sample the kernel for a marked section it is not going to send.
func TestADeferredXSKStartupTickSamplesNothing9684(t *testing.T) {
	rec := &partialRecorder9684{verbReply: errLostResponse9520}
	m, _ := newDeferredSyncManager9684(t, rec)
	samples := 0
	m.fabricSnapshotBuilder = func(*config.Config) []FabricSnapshot {
		samples++
		return []FabricSnapshot{freshFabric9684}
	}
	m.SyncFabricState()
	if samples != 1 || !m.partialSectionUnknownLocked(partialFabrics) {
		t.Fatalf("premise: the lost update_fabrics must sample once and mark the section (samples %d)", samples)
	}
	// The published plan differs, so every XSK-startup tick defers this publish.
	m.publishedPlanKey = "a-plan-this-snapshot-does-not-have"
	rec.verbReply = nil
	for i := 0; i < 3; i++ {
		if err := runDeferredSync9684(m); err != nil {
			t.Fatalf("deferred tick %d: %v", i, err)
		}
	}
	if len(rec.applies) != 0 {
		t.Fatalf("premise: a plan change during XSK startup must defer the publish (sent %d)", len(rec.applies))
	}
	if samples != 1 {
		t.Fatalf("deferred XSK-startup ticks sampled the kernel %d more times: they must defer before re-sampling", samples-1)
	}
	if !m.partialSectionUnknownLocked(partialFabrics) {
		t.Fatal("a deferred publish must leave the section unknown")
	}
}

// callName9684 is the name a call expression calls: the selector for a method or
// qualified call, the identifier for a plain function.
func callName9684(call *ast.CallExpr) string {
	switch fun := call.Fun.(type) {
	case *ast.SelectorExpr:
		return fun.Sel.Name
	case *ast.Ident:
		return fun.Name
	}
	return ""
}

// isResampleStmt9684 reports whether stmt itself re-samples every marked section:
// a plain or assigned call to resampleUnresolvedSectionsLocked or
// resampleForCompileLocked, or to resampleSectionsLocked for both sections. A call
// nested in a branch does not count.
func isResampleStmt9684(stmt ast.Stmt) bool {
	var expr ast.Expr
	switch s := stmt.(type) {
	case *ast.AssignStmt:
		if len(s.Rhs) != 1 {
			return false
		}
		expr = s.Rhs[0]
	case *ast.ExprStmt:
		expr = s.X
	default:
		return false
	}
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	switch callName9684(call) {
	case "resampleUnresolvedSectionsLocked", "resampleForCompileLocked":
		return true
	case "resampleSectionsLocked":
		// Only the both-sections form re-samples whatever is marked.
		return len(call.Args) == 2 && gotypes.ExprString(call.Args[1]) == "partialNeighbors | partialFabrics"
	}
	return false
}

// TestEveryApplySnapshotPublishReSamplesUnknownSections9684 finds every function
// that publishes an apply_snapshot, whatever it builds the snapshot from. Each
// must re-sample in a TOP-LEVEL statement of its body placed before every publish,
// unless it is allow-listed below with a reason. A top-level statement runs on
// every path that reaches a later one, so a re-sample hidden in a branch, or
// placed after the publish, fails. A new publish that forgets is the #9684
// rollback again. The census keys on the publish call rather than on how the
// snapshot was copied. It cannot see whether the re-sampled struct is the one
// passed to the publish; the behavioural cells above cover that for every
// publisher they can drive.
func TestEveryApplySnapshotPublishReSamplesUnknownSections9684(t *testing.T) {
	exempt := map[string]string{
		"publishSnapshotFailClosedLocked": "the fail-closed wrapper; its callers re-sample",
	}
	fset := token.NewFileSet()
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	resamplesFirst := map[string]bool{}
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			var publishes []token.Pos
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					switch callName9684(call) {
					case "requestApplySnapshotLocked", "publishSnapshotFailClosedLocked":
						publishes = append(publishes, call.Pos())
					}
				}
				return true
			})
			if len(publishes) == 0 {
				continue
			}
			resample := token.NoPos
			for _, stmt := range fn.Body.List {
				if isResampleStmt9684(stmt) {
					resample = stmt.Pos()
					break
				}
			}
			ok = resample != token.NoPos
			for _, p := range publishes {
				ok = ok && resample < p
			}
			resamplesFirst[fn.Name.Name] = ok
		}
	}
	for _, name := range []string{"UpdatePolicyScheduleState", "PublishRouteOverlaySnapshot", "retryDeferredWorkerArmLocked",
		"syncSnapshotLocked", "applyCompiledSnapshot"} {
		if _, ok := resamplesFirst[name]; !ok {
			t.Fatalf("liveness: %s no longer publishes an apply_snapshot, so the scan is not reading the publishes it guards", name)
		}
	}
	for name := range exempt {
		if _, ok := resamplesFirst[name]; !ok {
			t.Fatalf("exemption %q names no apply_snapshot publish any more; remove it", name)
		}
	}
	var missing []string
	for name, ok := range resamplesFirst {
		if _, exempted := exempt[name]; !ok && !exempted {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("these functions publish an apply_snapshot without re-sampling first: %v. "+
			"A section a lost partial update left unknown is re-sent from m.lastSnapshot and rolls the helper back (#9684)", missing)
	}
}

// TestCompileReSamplesUnderTheLockAndUnmarksWhatItReSampled9684 pins
// applyCompiledSnapshot. Compile builds its snapshot outside m.mu, so a partial
// update can run after the build sampled its sections. The build's older sample
// would then roll back a lost update and a landed one alike. So
// applyCompiledSnapshot must:
//   - re-sample both sections, marked or not, in a top-level statement under the
//     lock, before it computes the plan key or publishes;
//   - after the publish, unmark exactly what it re-sampled.
//
// The first leg drives the call Compile makes under the lock. It re-samples both
// sections when a partial update was sent after the build read the epoch, and
// otherwise only the marked ones, so the kernel is not sampled under m.mu for
// nothing. A fabric row keeps its plan half. The rest is structural, because
// without real BPF maps applyCompiledSnapshot fails before apply_snapshot (see
// TestCompileCommitsThePublishedGeneration9520).
func TestCompileReSamplesUnderTheLockAndUnmarksWhatItReSampled9684(t *testing.T) {
	for _, tc := range []struct {
		name         string
		marked       partialSections
		ranSince     bool
		otherPublish bool
		resampled    partialSections
	}{
		{"no partial update since the build and nothing marked", 0, false, false, 0},
		{"a partial update since the build", 0, true, false, partialNeighbors | partialFabrics},
		{"no partial update since the build but neighbors marked", partialNeighbors, false, false, partialNeighbors},
		// Codex #9684 r5: the mark Compile saw is gone by the time it takes the
		// lock, and no partial-update request was sent.
		{"a mark another publish re-sampled and cleared since the build", partialNeighbors, false, true,
			partialNeighbors | partialFabrics},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := withFreshKernel9684(&Manager{}, &partialRecorder9684{})
			m.partialOutcomeUnknown = tc.marked
			snap := staleSections9684(&ConfigSnapshot{Config: &config.Config{}})
			snap.Fabrics[0].ParentIfindex = 7
			snap.partialUpdateEpoch = m.partialUpdateEpoch.Load()
			if tc.ranSince {
				m.partialUpdateEpoch.Add(1)
			}
			if tc.otherPublish {
				// Another publish re-samples the marked section and, once it lands,
				// unmarks it. The helper now holds a newer sample than snap's.
				other := staleSections9684(&ConfigSnapshot{Config: &config.Config{}})
				m.resolvePartialOutcomesLocked(m.resampleUnresolvedSectionsLocked(other))
				if m.partialOutcomeUnknown != 0 {
					t.Fatal("premise: the other publish must leave nothing marked")
				}
			}
			if got := m.resampleForCompileLocked(snap); got != tc.resampled {
				t.Errorf("resampleForCompileLocked re-sampled %b, want %b", got, tc.resampled)
			}
			wantNeighbor, wantPeer := staleNeighbor9684.MAC, "unresolved"
			if tc.resampled&partialNeighbors != 0 {
				wantNeighbor = freshNeighbor9684.MAC
			}
			if tc.resampled&partialFabrics != 0 {
				wantPeer = freshFabric9684.PeerMAC
			}
			if got := neighborsCarried9684(snap.Neighbors); got != wantNeighbor {
				t.Errorf("the Compile snapshot carried neighbor MAC %s, want %s", got, wantNeighbor)
			}
			if got := fabricsCarried9684(snap.Fabrics); got != wantPeer {
				t.Errorf("the Compile snapshot carried fabric peer MAC %s, want %s", got, wantPeer)
			}
			if got := snap.Fabrics[0].ParentIfindex; got != 7 {
				t.Errorf("the Compile re-sample moved the fabric plan half: ParentIfindex = %d, want the build's 7", got)
			}
		})
	}

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "manager_compile.go", nil, 0)
	if err != nil {
		t.Fatalf("parse manager_compile.go: %v", err)
	}
	var fn *ast.FuncDecl
	for _, d := range f.Decls {
		if d, ok := d.(*ast.FuncDecl); ok && d.Name.Name == "applyCompiledSnapshot" {
			fn = d
		}
	}
	if fn == nil {
		t.Fatal("applyCompiledSnapshot not found in manager_compile.go")
	}
	resample := token.NoPos
	resampleName := ""
	for _, stmt := range fn.Body.List {
		if isResampleStmt9684(stmt) {
			resample = stmt.Pos()
			ast.Inspect(stmt, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok && resampleName == "" {
					resampleName = callName9684(call)
				}
				return resampleName == ""
			})
			break
		}
	}
	var planKey, publish token.Pos
	var resolves []*ast.CallExpr
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch callName9684(call) {
		case "snapshotBindingPlanKey":
			if planKey == token.NoPos {
				planKey = call.Pos()
			}
		case "publishSnapshotFailClosedLocked":
			if publish == token.NoPos {
				publish = call.Pos()
			}
		case "resolvePartialOutcomesLocked":
			resolves = append(resolves, call)
		}
		return true
	})
	if publish == token.NoPos || planKey == token.NoPos {
		t.Fatal("premise: applyCompiledSnapshot no longer computes a plan key and publishes through publishSnapshotFailClosedLocked")
	}
	if resample == token.NoPos {
		t.Fatal("applyCompiledSnapshot must re-sample in a top-level statement: it builds its snapshot outside m.mu")
	}
	if resampleName != "resampleForCompileLocked" {
		t.Errorf("applyCompiledSnapshot re-samples through %s, want resampleForCompileLocked: "+
			"re-sampling only the marked ones rolls back a partial update that landed after the build", resampleName)
	}
	if !(resample < planKey && resample < publish) {
		t.Fatal("applyCompiledSnapshot must re-sample before it computes the plan key and before it publishes")
	}
	if len(resolves) != 1 {
		t.Fatalf("applyCompiledSnapshot calls resolvePartialOutcomesLocked %d times, want 1", len(resolves))
	}
	if resolves[0].Pos() < publish {
		t.Fatal("applyCompiledSnapshot must unmark the sections after its publish lands, not before")
	}
	if len(resolves[0].Args) != 1 || gotypes.ExprString(resolves[0].Args[0]) != "resampled" {
		t.Fatal("applyCompiledSnapshot must unmark exactly the sections it re-sampled")
	}

	// Compile must read the epoch before its build samples the kernel, and stamp
	// that reading on the snapshot resampleForCompileLocked compares.
	var compile *ast.FuncDecl
	for _, d := range f.Decls {
		if d, ok := d.(*ast.FuncDecl); ok && d.Name.Name == "Compile" {
			compile = d
		}
	}
	if compile == nil {
		t.Fatal("Compile not found in manager_compile.go")
	}
	var epochRead, build token.Pos
	stamped := false
	ast.Inspect(compile.Body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CallExpr:
			if sel, ok := n.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Load" &&
				gotypes.ExprString(sel.X) == "m.partialUpdateEpoch" && epochRead == token.NoPos {
				epochRead = n.Pos()
			}
			if callName9684(n) == "buildSnapshotWithSchedulerStateAndNATCounters" && build == token.NoPos {
				build = n.Pos()
			}
		case *ast.AssignStmt:
			if len(n.Lhs) == 1 && gotypes.ExprString(n.Lhs[0]) == "snap.partialUpdateEpoch" {
				stamped = true
			}
		}
		return true
	})
	if build == token.NoPos {
		t.Fatal("premise: Compile no longer calls buildSnapshotWithSchedulerStateAndNATCounters")
	}
	if epochRead == token.NoPos || epochRead > build {
		t.Error("Compile must read partialUpdateEpoch before it builds the snapshot outside m.mu")
	}
	if !stamped {
		t.Error("Compile must stamp the epoch it read onto the snapshot (snap.partialUpdateEpoch)")
	}
}

// TestEveryPartialUpdateRequestAdvancesTheEpoch9684: resampleForCompileLocked
// trusts partialUpdateEpoch to move whenever a partial update may have changed
// what the helper holds, so every update_neighbors / update_fabrics request must
// advance it, whether its response landed or was lost, and an apply_snapshot
// must not.
func TestEveryPartialUpdateRequestAdvancesTheEpoch9684(t *testing.T) {
	path := republishPaths9684()[0]
	for _, outcome := range []struct {
		name  string
		reply error
	}{{"landed", nil}, {"lost", errLostResponse9520}} {
		for _, sec := range sections9684() {
			t.Run(outcome.name+"/"+sec.name, func(t *testing.T) {
				rec := &partialRecorder9684{verbReply: outcome.reply}
				m := path.newManager(t, rec)
				before := m.partialUpdateEpoch.Load()
				sec.update(m)
				if len(rec.verbs) == 0 {
					t.Fatal("premise: the update sent no request")
				}
				if got := m.partialUpdateEpoch.Load(); got != before+uint64(len(rec.verbs)) {
					t.Errorf("partialUpdateEpoch moved %d -> %d over %d partial update request(s)", before, got, len(rec.verbs))
				}
			})
		}
	}
	rec := &partialRecorder9684{}
	m := path.newManager(t, rec)
	before := m.partialUpdateEpoch.Load()
	if err := path.run(m); err != nil {
		t.Fatalf("%s: %v", path.name, err)
	}
	if len(rec.applies) == 0 {
		t.Fatal("premise: the republish sent no apply_snapshot")
	}
	if got := m.partialUpdateEpoch.Load(); got != before {
		t.Errorf("an apply_snapshot moved partialUpdateEpoch %d -> %d", before, got)
	}
}

// TestACompileEpochReadMidResampleStillReSamples9684: Compile reads
// partialUpdateEpoch outside m.mu, before its build. A read can land while a
// publish is still sampling a section under m.mu. That read must not match the
// epoch the publish leaves behind. Otherwise the Compile keeps its own kernel
// reads, which can be older than the sample the publish puts on the helper, and
// its publish rolls the helper back.
func TestACompileEpochReadMidResampleStillReSamples9684(t *testing.T) {
	for _, sec := range sections9684() {
		t.Run(sec.name, func(t *testing.T) {
			rec := &partialRecorder9684{}
			m := republishPaths9684()[0].newManager(t, rec)
			entered := make(chan struct{})
			release := make(chan struct{})
			var once sync.Once
			block := func() { once.Do(func() { close(entered); <-release }) }
			m.neighborSnapshotBuilder = func(*config.Config) []NeighborSnapshot {
				block()
				return []NeighborSnapshot{freshNeighbor9684}
			}
			m.fabricSnapshotBuilder = func(*config.Config) []FabricSnapshot {
				block()
				return []FabricSnapshot{freshFabric9684}
			}
			m.mu.Lock()
			cfg := m.lastSnapshot.Config
			m.mu.Unlock()

			published := staleSections9684(&ConfigSnapshot{Config: cfg})
			done := make(chan struct{})
			go func() {
				defer close(done)
				m.mu.Lock()
				defer m.mu.Unlock()
				m.resampleSectionsLocked(published, sec.mark)
			}()
			select {
			case <-entered:
			case <-time.After(10 * time.Second):
				t.Fatal("premise: the publish never sampled the section")
			}
			// The stamp of a Compile whose epoch read lands during that sample.
			compiled := staleSections9684(&ConfigSnapshot{Config: cfg, partialUpdateEpoch: m.partialUpdateEpoch.Load()})
			close(release)
			<-done

			m.mu.Lock()
			got := m.resampleForCompileLocked(compiled)
			m.mu.Unlock()
			if got&sec.mark == 0 {
				t.Errorf("a Compile whose epoch read landed during the %s sample did not re-sample it (re-sampled %b)",
					sec.name, got)
			}
			if carried := sec.carried(compiled); carried != sec.fresh {
				t.Errorf("that Compile publishes %s %q, want the kernel's %q", sec.name, carried, sec.fresh)
			}
		})
	}
}

// TestEveryFabricFieldIsClassifiedForTheResample9684: each FabricSnapshot field
// is either plan half, which a re-sample keeps, or re-sampled. A new field must
// be classified here, so it cannot land in either half by accident, and the
// classification must be what refreshFabricRowsKeepingPlan does.
func TestEveryFabricFieldIsClassifiedForTheResample9684(t *testing.T) {
	plan := map[string]bool{"Name": true, "ParentInterface": true, "ParentLinuxName": true,
		"ParentIfindex": true, "RXQueues": true, "ParentUnbindable": true}
	resampled := map[string]bool{"OverlayLinux": true, "OverlayIfindex": true, "PeerAddress": true,
		"LocalMAC": true, "PeerMAC": true, "Up": true}
	typ := reflect.TypeOf(FabricSnapshot{})
	for i := 0; i < typ.NumField(); i++ {
		if name := typ.Field(i).Name; plan[name] == resampled[name] {
			t.Errorf("FabricSnapshot.%s is not classified as plan half or re-sampled: decide which, "+
				"in refreshFabricRowsKeepingPlan and here", name)
		}
	}
	published := FabricSnapshot{Name: "fab0", ParentInterface: "a", ParentLinuxName: "a", ParentIfindex: 1,
		RXQueues: 1, OverlayLinux: "a", OverlayIfindex: 1, PeerAddress: "a", LocalMAC: "a", PeerMAC: "a"}
	fresh := FabricSnapshot{Name: "fab0", ParentInterface: "b", ParentLinuxName: "b", ParentIfindex: 2,
		RXQueues: 2, ParentUnbindable: true, OverlayLinux: "b", OverlayIfindex: 2, PeerAddress: "b",
		LocalMAC: "b", PeerMAC: "b", Up: true}
	got := reflect.ValueOf(refreshFabricRowsKeepingPlan([]FabricSnapshot{published}, []FabricSnapshot{fresh})[0])
	pub, frs := reflect.ValueOf(published), reflect.ValueOf(fresh)
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		want := frs.Field(i).Interface()
		if plan[name] {
			want = pub.Field(i).Interface()
		}
		if got.Field(i).Interface() != want {
			t.Errorf("refreshFabricRowsKeepingPlan: %s = %v, want %v", name, got.Field(i).Interface(), want)
		}
	}
}
