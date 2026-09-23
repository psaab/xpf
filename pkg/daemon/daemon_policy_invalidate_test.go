package daemon

import (
	"context"
	"errors"
	"github.com/cilium/ebpf"
	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	dpruntime "github.com/psaab/xpf/pkg/dataplane/runtime"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/feeds"
	"github.com/psaab/xpf/pkg/policymatch"
	"go/ast"
	"go/parser"
	"go/token"
	"golang.org/x/sync/semaphore"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// twoPolicyConfig builds a config with a single trust->untrust zone pair
// carrying the named permit policies plus the named global permit policies.
func twoPolicyConfig(zonePair []string, global []string) *config.Config {
	cfg := &config.Config{}
	if len(zonePair) > 0 {
		pols := make([]*config.Policy, 0, len(zonePair))
		for _, name := range zonePair {
			pols = append(pols, &config.Policy{Name: name, Action: config.PolicyPermit})
		}
		cfg.Security.Policies = []*config.ZonePairPolicies{
			{FromZone: "trust", ToZone: "untrust", Policies: pols},
		}
	}
	for _, name := range global {
		cfg.Security.GlobalPolicies = append(cfg.Security.GlobalPolicies,
			&config.Policy{Name: name, Action: config.PolicyPermit})
	}
	return cfg
}

func TestDeletedPolicyRuntimeIDs(t *testing.T) {
	// Three policies in one zone pair: p-first(id 0), p-web(id 1), p-ssh(id 2),
	// plus a global policy (id = 1*MaxRulesPerPolicy = 256, after the single
	// zone-pair set). p-first sits on the overloaded wire id 0.
	old := twoPolicyConfig([]string{"p-first", "p-web", "p-ssh"}, []string{"glob-a"})
	oldIDs := dpuserspace.PolicyIDsByStableKey(old)
	firstID := oldIDs["trust->untrust/p-first"]
	webID := oldIDs["trust->untrust/p-web"]
	sshID := oldIDs["trust->untrust/p-ssh"]
	globID := oldIDs["junos-global->junos-global/glob-a"]
	if firstID != 0 {
		t.Fatalf("precondition: first policy id = %d, want 0", firstID)
	}
	if webID == 0 || globID == 0 {
		t.Fatalf("precondition: web=%d glob=%d must be non-zero", webID, globID)
	}

	t.Run("nil old config yields nothing", func(t *testing.T) {
		if got := deletedPolicyRuntimeIDs(nil, old); got != nil {
			t.Fatalf("deletedPolicyRuntimeIDs(nil, ...) = %v, want nil", got)
		}
	})

	t.Run("deleted zone-pair policy (id>=1) is reported by its OLD id", func(t *testing.T) {
		// Delete p-web (id 1); keep p-first and p-ssh (p-ssh shifts numeric id).
		newCfg := twoPolicyConfig([]string{"p-first", "p-ssh"}, []string{"glob-a"})
		got := deletedPolicyRuntimeIDs(old, newCfg)
		if _, ok := got[webID]; !ok {
			t.Errorf("deleted set %v missing p-web old id %d", got, webID)
		}
		if _, ok := got[sshID]; ok {
			t.Errorf("deleted set %v must NOT contain surviving p-ssh id %d", got, sshID)
		}
		if _, ok := got[globID]; ok {
			t.Errorf("deleted set %v must NOT contain surviving global id %d", got, globID)
		}
	})

	t.Run("deleting the FIRST policy never puts overloaded id 0 in the set", func(t *testing.T) {
		// p-first (id 0) deleted, p-web/p-ssh kept. policy_id 0 is the overloaded
		// wire value carried by host-local/fabric/tunnel/pre-#3056 sessions, so it
		// must be excluded from the clear set even though p-first was deleted.
		newCfg := twoPolicyConfig([]string{"p-web", "p-ssh"}, []string{"glob-a"})
		got := deletedPolicyRuntimeIDs(old, newCfg)
		if _, ok := got[0]; ok {
			t.Fatalf("policy_id 0 must never enter the deleted set (overloaded wire value); got %v", got)
		}
	})

	t.Run("renaming the first policy never puts id 0 in the set", func(t *testing.T) {
		// A rename is delete(old-name)+add(new-name) by stable key; the deleted
		// old-name sits at id 0, which must still be excluded.
		newCfg := twoPolicyConfig([]string{"p-first-v2", "p-web", "p-ssh"}, []string{"glob-a"})
		got := deletedPolicyRuntimeIDs(old, newCfg)
		if _, ok := got[0]; ok {
			t.Fatalf("renaming the first policy wrongly put id 0 in the deleted set: %v", got)
		}
	})

	t.Run("modified policy (same zones+name) is NOT reported", func(t *testing.T) {
		// p-web keeps its name+zones but flips permit->deny. Its stable key is
		// unchanged, so it is a MODIFIED policy, not a deleted one — the deferred
		// #4234 policy-rematch half, out of scope for the deletion-clear.
		newCfg := twoPolicyConfig([]string{"p-first", "p-web", "p-ssh"}, []string{"glob-a"})
		newCfg.Security.Policies[0].Policies[1].Action = config.PolicyDeny
		if got := deletedPolicyRuntimeIDs(old, newCfg); len(got) != 0 {
			t.Fatalf("a modified (not deleted) policy triggered a clear set %v, want empty", got)
		}
	})

	t.Run("deleted global policy is reported", func(t *testing.T) {
		newCfg := twoPolicyConfig([]string{"p-first", "p-web", "p-ssh"}, nil)
		got := deletedPolicyRuntimeIDs(old, newCfg)
		if _, ok := got[globID]; !ok {
			t.Errorf("deleted set %v missing global glob-a id %d", got, globID)
		}
	})

	t.Run("identical config deletes nothing", func(t *testing.T) {
		if got := deletedPolicyRuntimeIDs(old, old); len(got) != 0 {
			t.Fatalf("identical old/new produced clear set %v, want empty", got)
		}
	})
}

// TestPolicySchedulerTransitionInvalidationDirection4343 pins the asymmetric
// scheduler transition contract: active->inactive clears sessions carrying
// the surviving policy's id, while inactive->active does not sweep that id.
// The latter is revalidated by the userspace generation fence because sessions
// admitted by a later permit carry that later policy's id.
func TestPolicySchedulerTransitionInvalidationDirection4343(t *testing.T) {
	oldCfg := twoPolicyConfig([]string{"p-first", "p-window"}, nil)
	oldCfg.Security.PolicyRematch = true
	oldCfg.Security.Policies[0].Policies[1].SchedulerName = "window"
	newCfg := twoPolicyConfig([]string{"p-first", "p-window"}, nil)
	newCfg.Security.PolicyRematch = true
	newCfg.Security.Policies[0].Policies[1].SchedulerName = "window"
	policyID := dpuserspace.PolicyIDsByStableKey(oldCfg)["trust->untrust/p-window"]
	if policyID == 0 {
		t.Fatalf("test policy must use a non-overloaded runtime id, got %d", policyID)
	}

	tightened := changedPolicyRuntimeIDs(
		oldCfg,
		newCfg,
		map[string]bool{"window": true},
		map[string]bool{"window": false},
	)
	if _, ok := tightened[policyID]; !ok {
		t.Fatalf("active->inactive scheduler transition omitted policy id %d: %v", policyID, tightened)
	}

	reopened := changedPolicyRuntimeIDs(
		oldCfg,
		newCfg,
		map[string]bool{"window": false},
		map[string]bool{"window": true},
	)
	if len(reopened) != 0 {
		t.Fatalf("inactive->active scheduler transition swept ids %v; generation revalidation owns this edge", reopened)
	}
}

// TestClearSessionsForDeletedPolicies is the RED-on-revert test: a session
// admitted under a policy that the commit DELETES (id >= 1) is invalidated,
// while a session under a surviving (or merely modified) policy keeps
// forwarding — and a session on the overloaded id 0 is never swept even though
// the first policy was deleted.
func TestClearSessionsForDeletedPolicies(t *testing.T) {
	old := twoPolicyConfig([]string{"p-first", "p-web", "p-ssh"}, nil)
	oldIDs := dpuserspace.PolicyIDsByStableKey(old)
	webID := oldIDs["trust->untrust/p-web"] // 1
	sshID := oldIDs["trust->untrust/p-ssh"] // 2

	// Delete p-first (id 0) AND p-web (id 1); keep p-ssh, modified permit->deny.
	// The clear is ACTIVE (deleted set = {1}) so this also proves the id-0 guard
	// holds while the sweep runs.
	newCfg := twoPolicyConfig([]string{"p-ssh"}, nil)
	newCfg.Security.Policies[0].Policies[0].Action = config.PolicyDeny

	webSess := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2},
		SrcPort: 40001, DstPort: 80, Protocol: 6,
	}
	sshSess := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2},
		SrcPort: 40002, DstPort: 22, Protocol: 6,
	}
	// Stand-in for a host-inbound / fabric / tunnel / pre-#3056 synced session:
	// carries the overloaded policy_id 0.
	hostLocalSess := dataplane.SessionKey{
		SrcIP: [4]byte{169, 254, 0, 1}, DstIP: [4]byte{169, 254, 0, 2},
		SrcPort: 0, DstPort: 179, Protocol: 6,
	}
	webSessV6 := dataplane.SessionKeyV6{
		SrcIP: [16]byte{0x20, 0x01, 15: 0x01}, DstIP: [16]byte{0x20, 0x01, 15: 0x02},
		SrcPort: 40003, DstPort: 80, Protocol: 6,
	}

	dp := &policyInvalTestDP{
		v4: map[dataplane.SessionKey]dataplane.SessionValue{
			webSess:       {State: dataplane.SessStateEstablished, PolicyID: webID},
			sshSess:       {State: dataplane.SessStateEstablished, PolicyID: sshID},
			hostLocalSess: {State: dataplane.SessStateEstablished, PolicyID: 0},
		},
		v6: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{
			webSessV6: {State: dataplane.SessStateEstablished, PolicyID: webID},
		},
	}

	d := &Daemon{}
	d.setDataplane(dp)
	d.clearSessionsForDeletedPolicies(old, newCfg)

	if _, ok := dp.v4[webSess]; ok {
		t.Errorf("session under DELETED policy p-web (id %d) survived the commit clear", webID)
	}
	if _, ok := dp.v6[webSessV6]; ok {
		t.Errorf("v6 session under DELETED policy p-web (id %d) survived the commit clear", webID)
	}
	if _, ok := dp.v4[sshSess]; !ok {
		t.Errorf("session under SURVIVING (modified) policy p-ssh (id %d) was wrongly cleared", sshID)
	}
	if _, ok := dp.v4[hostLocalSess]; !ok {
		t.Errorf("id-0 host-local session was swept when the first policy was deleted (overloaded wire value must be excluded)")
	}
}

// TestClearSessionsForDeletedPolicies_FirstPolicyIdZeroNotSwept pins the id-0
// guard directly: deleting the FIRST policy (policy_id 0) must NOT clear the
// host-local / fabric / peer-synced sessions that also carry policy_id 0. RED on
// revert: without the id-0 exclusion in deletedPolicyRuntimeIDs, deleting the
// first policy puts 0 in the set and mass-clears every id-0 session (a
// rolling-upgrade / host-local forwarding outage, amplified by delete-sync).
func TestClearSessionsForDeletedPolicies_FirstPolicyIdZeroNotSwept(t *testing.T) {
	old := twoPolicyConfig([]string{"p-first", "p-web"}, nil)
	// Delete the first policy (id 0). p-web survives.
	newCfg := twoPolicyConfig([]string{"p-web"}, nil)

	hostSess := dataplane.SessionKey{SrcIP: [4]byte{169, 254, 0, 1}, SrcPort: 0, DstPort: 179, Protocol: 6}
	fabricSess := dataplane.SessionKey{SrcIP: [4]byte{10, 99, 0, 1}, SrcPort: 5000, DstPort: 5001, Protocol: 17}
	syncedV6 := dataplane.SessionKeyV6{SrcIP: [16]byte{0xfe, 0x80, 15: 0x01}, SrcPort: 100, DstPort: 200, Protocol: 6}

	dp := &policyInvalTestDP{
		v4: map[dataplane.SessionKey]dataplane.SessionValue{
			hostSess:   {State: dataplane.SessStateEstablished, PolicyID: 0},
			fabricSess: {State: dataplane.SessStateEstablished, PolicyID: 0},
		},
		v6: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{
			syncedV6: {State: dataplane.SessStateEstablished, PolicyID: 0},
		},
	}
	d := &Daemon{}
	d.setDataplane(dp)
	d.clearSessionsForDeletedPolicies(old, newCfg)

	if _, ok := dp.v4[hostSess]; !ok {
		t.Errorf("host-inbound id-0 session cleared on first-policy delete")
	}
	if _, ok := dp.v4[fabricSess]; !ok {
		t.Errorf("fabric id-0 session cleared on first-policy delete")
	}
	if _, ok := dp.v6[syncedV6]; !ok {
		t.Errorf("v6 synced id-0 session cleared on first-policy delete")
	}
}

// TestClearSessionsForDeletedPolicies_RenameFirstPolicyNotSwept pins that
// renaming the first policy (delete old-name + add new-name at id 0) does not
// wipe id-0 sessions. RED on revert: without the guard, the rename puts 0 in the
// set, the sweep runs, and the id-0 session is cleared.
func TestClearSessionsForDeletedPolicies_RenameFirstPolicyNotSwept(t *testing.T) {
	old := twoPolicyConfig([]string{"p-first", "p-web"}, nil)
	newCfg := twoPolicyConfig([]string{"p-first-v2", "p-web"}, nil)

	hostSess := dataplane.SessionKey{SrcIP: [4]byte{169, 254, 0, 1}, SrcPort: 0, DstPort: 179, Protocol: 6}
	dp := &policyInvalTestDP{
		v4: map[dataplane.SessionKey]dataplane.SessionValue{
			hostSess: {State: dataplane.SessStateEstablished, PolicyID: 0},
		},
	}
	d := &Daemon{}
	d.setDataplane(dp)
	d.clearSessionsForDeletedPolicies(old, newCfg)

	if _, ok := dp.v4[hostSess]; !ok {
		t.Errorf("id-0 host-local session wiped when the first policy was RENAMED")
	}
}

func TestClearSessionsForDeletedPolicies_NoDeletionIsNoop(t *testing.T) {
	old := twoPolicyConfig([]string{"allow-web"}, nil)
	newCfg := twoPolicyConfig([]string{"allow-web"}, nil)
	webID := dpuserspace.PolicyIDsByStableKey(old)["trust->untrust/allow-web"]

	sess := dataplane.SessionKey{SrcPort: 1, Protocol: 6}
	dp := &policyInvalTestDP{
		v4: map[dataplane.SessionKey]dataplane.SessionValue{
			sess: {State: dataplane.SessStateEstablished, PolicyID: webID},
		},
	}
	d := &Daemon{}
	d.setDataplane(dp)
	d.clearSessionsForDeletedPolicies(old, newCfg)

	if _, ok := dp.v4[sess]; !ok {
		t.Fatalf("a commit with no policy deletion cleared a session")
	}
	if dp.iterateCalls != 0 {
		t.Fatalf("no-deletion commit scanned the session table (%d iterate calls); want a zero-cost no-op", dp.iterateCalls)
	}
}

// policyInvalTestDP is an in-memory RuntimeDataPlane whose session store backs
type policyInvalTestDP struct {
	dataplane.DataPlane // embedded nil — only the overridden methods are called

	v4           map[dataplane.SessionKey]dataplane.SessionValue
	v6           map[dataplane.SessionKeyV6]dataplane.SessionValueV6
	iterateCalls int
	renameWire   []dpuserspace.PolicyRenameAncestry
	renameRows   []dpuserspace.PolicySessionRebind
	iterErr      error
	// delErr, when non-nil, is returned by BatchDeleteSessions/V6 after the
	// configured prefix is removed. A zero prefix models a fully failed delete.
	delErr          error
	partialDeleteV4 int
	partialDeleteV6 int
	deletedV4       []dataplane.SessionKey
	deletedV6       []dataplane.SessionKeyV6
}

func (d *policyInvalTestDP) Start(context.Context) error { return nil }
func (d *policyInvalTestDP) Close() error                { return nil }
func (d *policyInvalTestDP) Teardown() error             { return nil }

func (d *policyInvalTestDP) ApplyConfig(context.Context, *config.Config) (*dataplane.ApplyResult, error) {
	return &dataplane.ApplyResult{}, nil
}
func (d *policyInvalTestDP) LastApplyResult() *dataplane.ApplyResult { return &dataplane.ApplyResult{} }
func (d *policyInvalTestDP) Link() dataplane.LinkController          { return noopLinkController{} }
func (d *policyInvalTestDP) HA() dataplane.HAController {
	return dataplane.NewDataPlaneHAController(nil)
}
func (d *policyInvalTestDP) Sessions() dataplane.SessionStore {
	return dataplane.NewDataPlaneSessionStore(d)
}
func (d *policyInvalTestDP) Telemetry() dataplane.Telemetry                  { return dataplane.TelemetryOf(nil) }
func (d *policyInvalTestDP) SessionDeltas() dpruntime.SessionDeltaSource     { return nil }
func (d *policyInvalTestDP) GetPersistentNAT() *dataplane.PersistentNATTable { return nil }

func (d *policyInvalTestDP) SetPolicyRenameAncestry(
	wire []dpuserspace.PolicyRenameAncestry,
	rows []dpuserspace.PolicySessionRebind,
) {
	d.renameWire = append([]dpuserspace.PolicyRenameAncestry(nil), wire...)
	d.renameRows = append([]dpuserspace.PolicySessionRebind(nil), rows...)
}

func (d *policyInvalTestDP) BatchIterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	d.iterateCalls++
	for k, v := range d.v4 {
		if !fn(k, v) {
			break
		}
	}
	return d.iterErr
}

func (d *policyInvalTestDP) BatchIterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	for k, v := range d.v6 {
		if !fn(k, v) {
			break
		}
	}
	return nil
}

func (d *policyInvalTestDP) GetSessionV4(key dataplane.SessionKey) (dataplane.SessionValue, error) {
	value, ok := d.v4[key]
	if !ok {
		return dataplane.SessionValue{}, ebpf.ErrKeyNotExist
	}
	return value, nil
}

func (d *policyInvalTestDP) GetSessionV6(key dataplane.SessionKeyV6) (dataplane.SessionValueV6, error) {
	value, ok := d.v6[key]
	if !ok {
		return dataplane.SessionValueV6{}, ebpf.ErrKeyNotExist
	}
	return value, nil
}

func (d *policyInvalTestDP) BatchDeleteSessions(keys []dataplane.SessionKey) (int, error) {
	n := 0
	for i, k := range keys {
		if d.delErr != nil && i >= d.partialDeleteV4 {
			return n, d.delErr
		}
		d.deletedV4 = append(d.deletedV4, k)
		if _, ok := d.v4[k]; ok {
			delete(d.v4, k)
			n++
		}
	}
	if d.delErr != nil {
		return n, d.delErr
	}
	return n, nil
}

func (d *policyInvalTestDP) BatchDeleteSessionsV6(keys []dataplane.SessionKeyV6) (int, error) {
	n := 0
	for i, k := range keys {
		if d.delErr != nil && i >= d.partialDeleteV6 {
			return n, d.delErr
		}
		d.deletedV6 = append(d.deletedV6, k)
		if _, ok := d.v6[k]; ok {
			delete(d.v6, k)
			n++
		}
	}
	if d.delErr != nil {
		return n, d.delErr
	}
	return n, nil
}

func (d *policyInvalTestDP) DeleteDNATEntry(dataplane.DNATKey) error     { return nil }
func (d *policyInvalTestDP) DeleteDNATEntryV6(dataplane.DNATKeyV6) error { return nil }

// deletedPolicyInvalFixture builds an old/new config pair that DELETES p-web
// (id 1) plus a fake DP whose v4 + v6 session tables each hold one session
// admitted by that deleted policy — the setup the #5578 error-propagation
// tests reuse. p-first (id 0) and p-ssh (id 2) survive so the clear set is the
// single non-overloaded deleted id {1}.
func deletedPolicyInvalFixture() (oldCfg, newCfg *config.Config, dp *policyInvalTestDP, webSess dataplane.SessionKey, webSessV6 dataplane.SessionKeyV6) {
	oldCfg = twoPolicyConfig([]string{"p-first", "p-web", "p-ssh"}, nil)
	newCfg = twoPolicyConfig([]string{"p-first", "p-ssh"}, nil)
	webID := dpuserspace.PolicyIDsByStableKey(oldCfg)["trust->untrust/p-web"]

	webSess = dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2},
		SrcPort: 40001, DstPort: 80, Protocol: 6,
	}
	webSessV6 = dataplane.SessionKeyV6{
		SrcIP: [16]byte{0x20, 0x01, 15: 0x01}, DstIP: [16]byte{0x20, 0x01, 15: 0x02},
		SrcPort: 40003, DstPort: 80, Protocol: 6,
	}
	dp = &policyInvalTestDP{
		v4: map[dataplane.SessionKey]dataplane.SessionValue{
			webSess: {State: dataplane.SessStateEstablished, PolicyID: webID},
		},
		v6: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{
			webSessV6: {State: dataplane.SessStateEstablished, PolicyID: webID},
		},
	}
	return oldCfg, newCfg, dp, webSess, webSessV6
}

// TestClearSessionsForPolicyIDsEnumerateErrorPropagates is the #5578
// RED-on-revert for a failed session-table ENUMERATE: a partial ForEachV4/V6
// iteration leaves unvisited sessions of the deleted policy in the live table.
// The helper must RETURN that error (wrapping the injected iterator error), not
// reduce it to a slog line. RED on revert: with the void/slog-only helper there
// is no return value to assert, so the compile fails / the error is lost.
func TestClearSessionsForPolicyIDsEnumerateErrorPropagates(t *testing.T) {
	oldCfg, newCfg, dp, _, _ := deletedPolicyInvalFixture()
	errBoom := errors.New("v4 iterator exploded")
	dp.iterErr = errBoom

	d := &Daemon{}
	d.setDataplane(dp)

	err := d.clearSessionsForDeletedPolicies(oldCfg, newCfg)
	if err == nil {
		t.Fatal("clearSessionsForDeletedPolicies swallowed a session-table enumerate error; " +
			"a partial invalidation must be RETURNED so the commit can surface the stale-authorization gap (#5578)")
	}
	if !errors.Is(err, errBoom) {
		t.Fatalf("returned error %v does not wrap the injected iterator error", err)
	}

	// The combined helper the commit/sync/rollback callers use must also
	// propagate it (errors.Join threads every wrapper's error through).
	if joined := d.clearSessionsForPolicyChanges(oldCfg, newCfg); !errors.Is(joined, errBoom) {
		t.Fatalf("clearSessionsForPolicyChanges dropped the enumerate error: %v", joined)
	}
}

// TestClearSessionsForPolicyIDsDeleteErrorPropagates is the #5578 RED-on-revert
// for a failed batch DELETE: the matched sessions of the deleted policy stay
// INSTALLED (stale authorization) yet the pre-fix helper reduced the failure to
// a slog.Warn. The helper must RETURN the error AND the sessions must remain in
// the table — proving the security gap (traffic the new policy should deny keeps
// forwarding) is now observable to the caller, not silently swallowed.
func TestClearSessionsForPolicyIDsDeleteErrorPropagates(t *testing.T) {
	oldCfg, newCfg, dp, webSess, webSessV6 := deletedPolicyInvalFixture()
	errBoom := errors.New("batch delete failed")
	dp.delErr = errBoom

	d := &Daemon{}
	d.setDataplane(dp)

	err := d.clearSessionsForDeletedPolicies(oldCfg, newCfg)
	if err == nil {
		t.Fatal("clearSessionsForDeletedPolicies swallowed a batch-delete failure; the matched " +
			"sessions stay installed under stale authorization and the commit must see the error (#5578)")
	}
	if !errors.Is(err, errBoom) {
		t.Fatalf("returned error %v does not wrap the injected delete error", err)
	}
	// The stale-authorization gap: the delete failed, so the sessions the new
	// policy should have revoked are still forwarding.
	if _, ok := dp.v4[webSess]; !ok {
		t.Error("precondition: v4 session should still be present after a failed delete (models stale authorization)")
	}
	if _, ok := dp.v6[webSessV6]; !ok {
		t.Error("precondition: v6 session should still be present after a failed delete (models stale authorization)")
	}
}

// TestDeleteInvalidatedSessionsErrorSyncsExactSet is the RED-on-revert cell
// for #10598 policy invalidation: a partially successful V4/V6 delete returns
// an error, but the HA queue receives only the keys actually deleted.
func TestDeleteInvalidatedSessionsErrorSyncsExactSet(t *testing.T) {
	_, _, store, firstV4, firstV6 := deletedPolicyInvalFixture()
	secondV4 := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 0, 3}, DstIP: [4]byte{10, 0, 0, 4},
		SrcPort: 40002, DstPort: 22, Protocol: 6,
	}
	secondV6 := dataplane.SessionKeyV6{
		SrcIP: [16]byte{0x20, 0x01, 15: 0x03}, DstIP: [16]byte{0x20, 0x01, 15: 0x04},
		SrcPort: 40004, DstPort: 22, Protocol: 6,
	}
	store.v4[secondV4] = dataplane.SessionValue{State: dataplane.SessStateEstablished}
	store.v6[secondV6] = dataplane.SessionValueV6{State: dataplane.SessStateEstablished}
	store.delErr = errors.New("partial policy delete")
	store.partialDeleteV4 = 1
	store.partialDeleteV6 = 1

	sender := cluster.NewSessionSync(":0", ":0", store)
	sender.SetConnectedForTesting(true)
	receiverStore := &policyInvalTestDP{
		v4: map[dataplane.SessionKey]dataplane.SessionValue{
			firstV4:  {State: dataplane.SessStateEstablished},
			secondV4: {State: dataplane.SessStateEstablished},
		},
		v6: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{
			firstV6:  {State: dataplane.SessStateEstablished},
			secondV6: {State: dataplane.SessStateEstablished},
		},
	}
	receiver := cluster.NewSessionSync(":0", ":0", receiverStore)

	d := &Daemon{
		cluster:     newClusterManager(true),
		sessionSync: sender,
	}
	d.setDataplane(store)
	err := d.deleteInvalidatedSessions(capturedSessions{
		targets: 1,
		v4:      []dataplane.SessionEntryV4{{Key: firstV4}, {Key: secondV4}},
		v6:      []dataplane.SessionEntryV6{{Key: firstV6}, {Key: secondV6}},
	}, dataplane.DeleteReasonPolicyDeleted, "partial exact test")
	if !errors.Is(err, store.delErr) {
		t.Fatalf("deleteInvalidatedSessions error = %v, want %v", err, store.delErr)
	}

	types, applyErr := sender.ApplyQueuedMessagesForTesting(receiver)
	if applyErr != nil {
		t.Fatalf("apply queued delete messages: %v", applyErr)
	}
	if len(types) != 2 || types[0] != "delete_v4" || types[1] != "delete_v6" {
		t.Fatalf("queued message types = %v, want [delete_v4 delete_v6]", types)
	}
	if len(receiverStore.deletedV4) != 1 || receiverStore.deletedV4[0] != firstV4 {
		t.Fatalf("queued v4 deletes = %+v, want [%+v]", receiverStore.deletedV4, firstV4)
	}
	if len(receiverStore.deletedV6) != 1 || receiverStore.deletedV6[0] != firstV6 {
		t.Fatalf("queued v6 deletes = %+v, want [%+v]", receiverStore.deletedV6, firstV6)
	}
	if _, ok := receiverStore.v4[secondV4]; !ok {
		t.Fatalf("queued v4 over-sync removed retained key %+v", secondV4)
	}
	if _, ok := receiverStore.v6[secondV6]; !ok {
		t.Fatalf("queued v6 over-sync removed retained key %+v", secondV6)
	}
}

// TestApplyAndSyncCommittedSurfacesInvalidationError proves the CALLER surfaces
// the propagated error (#5578): a successful config apply whose post-apply
// policy-session invalidation fails must return a non-nil commit error while
// still committing the config (mark-and-continue, mirroring the non-fatal
// applyErr path). RED on revert: dropping the errors.Join(applyErr, clearErr) in
// applyAndSyncCommitted (or reverting the helper to void) makes this return nil.
func TestApplyAndSyncCommittedSurfacesInvalidationError(t *testing.T) {
	oldActive, compiled, dp, _, _ := deletedPolicyInvalFixture()
	errBoom := errors.New("batch delete failed")
	dp.delErr = errBoom

	d := &Daemon{
		// Bypass the heavy reconcile: the apply "succeeds" so the post-apply
		// invalidation runs and its error is the only thing under test.
		applyBodyForTest: func(*config.Config) {},
		applyErrForTest:  nil,
	}
	d.setDataplane(dp) // #2114: publish through the cell

	// peerSyncNever: no cluster wiring needed; the peer push is orthogonal.
	got, err := d.applyAndSyncCommitted(oldActive, compiled, peerSyncNever)
	if err == nil {
		t.Fatal("applyAndSyncCommitted returned nil error despite a failed policy session " +
			"invalidation; the stale-authorization gap was swallowed (#5578)")
	}
	if !errors.Is(err, errBoom) {
		t.Fatalf("commit error %v does not carry the invalidation failure", err)
	}
	// Mark-and-continue: the config is still committed + active (returned),
	// mirroring how a non-fatal applyErr is surfaced alongside compiled.
	if got != compiled {
		t.Fatalf("applyAndSyncCommitted returned config %p, want the committed config %p "+
			"(a non-fatal invalidation error must not drop the commit)", got, compiled)
	}
}

// N3c: capture-level scheduler/feed stamping. The capture loop stamps
// each binding with policyInactiveFn(newSched) + feedOverlay; these cells pin
// the OBSERVED capture behavior (renamed iff active+resolving). Feed overlay
// honoring itself is pinned at unit level below (a populated feed Manager is
// covered by the feeds package + 5036/9588 tests, not rebuilt here).
func TestCaptureRenameStampingSchedulerAndFeed10592(t *testing.T) {
	captureWith := func(t *testing.T, sched *config.SchedulerConfig, feedName string, keepAlternate bool) *policyInvalidationCapture {
		t.Helper()
		oldCfg := policyRenameEvaluatorConfig("p-old", config.PolicyPermit)
		newCfg := policyRenameEvaluatorConfig("p-new", config.PolicyPermit)
		if sched != nil {
			oldCfg.Security.Policies[1].Policies[0].SchedulerName = sched.Name
			newCfg.Security.Policies[1].Policies[0].SchedulerName = sched.Name
			oldCfg.Schedulers = map[string]*config.SchedulerConfig{sched.Name: sched}
			newCfg.Schedulers = map[string]*config.SchedulerConfig{sched.Name: sched}
		}
		if feedName != "" {
			for _, cfg := range []*config.Config{oldCfg, newCfg} {
				cfg.Security.Policies[1].Policies[0].Match.SourceAddresses = []string{feedName}
			}
		}
		if !keepAlternate {
			// Isolate feed/scheduler semantics from alternate-permit fallback.
			for _, cfg := range []*config.Config{oldCfg, newCfg} {
				cfg.Security.Policies[1].Policies = cfg.Security.Policies[1].Policies[:1]
			}
		}
		oldID := dpuserspace.PolicyIDsByStableKey(oldCfg)["lan->wan/p-old"]
		key := dataplane.SessionKey{
			SrcIP: [4]byte{10, 0, 0, 10}, DstIP: [4]byte{10, 0, 0, 20},
			SrcPort: 1234, DstPort: 443, Protocol: 6,
		}
		dp := &policyInvalTestDP{
			v4: map[dataplane.SessionKey]dataplane.SessionValue{
				key: {
					State:       dataplane.SessStateEstablished,
					PolicyID:    oldID,
					IngressZone: config.StableZoneID("lan"),
					EgressZone:  config.StableZoneID("wan"),
				},
			},
			v6: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{},
		}
		d := &Daemon{}
		d.setDataplane(dp)
		d.armPolicyInvalidationPlanWithRename(oldCfg, newCfg, &pendingRenameApply{
			descriptors: []configstore.RenameDescriptor{
				policyRenameDescriptor("p-old", "p-new"),
			},
		})
		d.capturePolicyInvalidationLocked(newCfg)
		capture := d.policyInvalidationCapture
		if capture == nil {
			t.Fatal("rename apply did not produce a pre-publication capture")
		}
		return capture
	}
	t.Run("scheduler-active-retains", func(t *testing.T) {
		capture := captureWith(t,
			&config.SchedulerConfig{Name: "biz", Daily: true, AllDay: true}, "", true)
		if len(capture.renamed) != 1 {
			t.Fatalf("active-scheduler renamed rows = %d, want 1", len(capture.renamed))
		}
	})
	t.Run("scheduler-inactive-drops", func(t *testing.T) {
		capture := captureWith(t,
			&config.SchedulerConfig{Name: "biz", StartDate: "2000-01-01", StopDate: "2000-01-02"}, "", true)
		// The inactive renamed rule must not retain; retention via the
		// match-any alternate (no scheduler) is correct and expected.
		for _, row := range capture.renamed {
			if row.RuleID == "lan->wan/p-new" {
				t.Fatalf("inactive-scheduler renamed rule retained: %+v", row)
			}
		}
	})
	t.Run("feed-unresolved-drops", func(t *testing.T) {
		// Feed-backed name with a nil feed manager: overlay is nil, the name
		// cannot resolve, the row is not retained. (populated-Manager
		// plumbing is covered by feeds + 5036/9588 tests.)
		capture := captureWith(t, nil, "bad-actors", false)
		if len(capture.renamed) != 0 {
			t.Fatalf("unresolved-feed renamed rows = %d, want 0: %+v", len(capture.renamed), capture.renamed)
		}
	})
}

// TestCommitWindowArmApplySweepOrder10591 drives the real commit wrapper far
// enough to prove arm-before-apply plus sweep-deletes-row in one transaction:
// the plan is armed before the apply body, the body takes the pre-publication
// capture, and the post-apply sweep consumes the old-policy row before the
// wrapper returns. This is sibling commit-pipeline discipline (the POLICY
// invalidation sweep, p-web deleted), NOT the zone-rotation purge that
// terminates the Rust window cells (worker snapshot rotation, different
// plane) — it pins ordering, not window closure. The
// capture-at-publish-boundary placement itself is pinned
// by TestCaptureRunsBeforeTheDataplanePublish6948; the AST order guard below
// catches an arm, apply, or sweep moved behind the wrong boundary even if this
// seam is later simplified.
func TestCommitWindowArmApplySweepOrder10591(t *testing.T) {
	oldCfg, newCfg, oldID, _ := inheritedIDFixture6948(t)
	key := v4Key6948(1, 40001, 80)
	dp := &policyInvalTestDP{
		v4: map[dataplane.SessionKey]dataplane.SessionValue{
			key: {
				State:       dataplane.SessStateEstablished,
				PolicyID:    oldID,
				IngressZone: config.StableZoneID("lan"),
				EgressZone:  config.StableZoneID("wan"),
			},
		},
		v6: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{},
	}
	d := &Daemon{}
	d.setDataplane(dp)
	var phases []string
	d.applyBodyForTest = func(cfg *config.Config) {
		if d.policyInvalidationPlan == nil {
			t.Fatal("commit apply reached the publish body without an armed invalidation plan")
		}
		// R1: take the pre-publication capture through the ONE production
		// handoff (daemon_apply_dataplane.go:171). Without
		// this call the sweep below falls back to the legacy scan and the
		// plan/capture-consumption asserts prove nothing — deleting it must RED.
		d.captureAndStagePolicyRenameAncestry(cfg)
		phases = append(phases, "apply")
	}
	if _, err := d.applyAndSyncCommitted(oldCfg, newCfg, peerSyncNever); err != nil {
		t.Fatalf("applyAndSyncCommitted: %v", err)
	}
	if len(phases) != 1 || phases[0] != "apply" {
		t.Fatalf("commit apply phases = %v, want one real apply phase", phases)
	}
	if _, ok := dp.v4[key]; ok {
		t.Fatal("post-apply invalidation sweep left the old-policy row alive")
	}
	if d.policyInvalidationPlan != nil {
		t.Fatal("post-apply sweep left the invalidation plan armed: the apply body never took its capture")
	}
	if d.policyInvalidationCapture != nil {
		t.Fatal("post-apply sweep left the invalidation capture armed")
	}

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "daemon_apply_commit.go", nil, 0)
	if err != nil {
		t.Fatalf("parse daemon_apply_commit.go: %v", err)
	}
	var armAt, applyAt, sweepAt token.Pos
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "applyAndSyncCommitted" || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			switch sel.Sel.Name {
			case "armPolicyInvalidationPlanWithRename":
				armAt = call.Pos()
			case "applyConfigLockedForCommit":
				applyAt = call.Pos()
			case "reportSessionAuthorizationChanges":
				sweepAt = call.Pos()
			}
			return true
		})
	}
	if !armAt.IsValid() || !applyAt.IsValid() || !sweepAt.IsValid() {
		t.Fatalf("commit path must contain arm, apply, and sweep calls (arm=%v apply=%v sweep=%v)",
			armAt.IsValid(), applyAt.IsValid(), sweepAt.IsValid())
	}
	if !(armAt < applyAt && applyAt < sweepAt) {
		t.Fatalf("commit phases out of order: arm=%s apply=%s sweep=%s",
			fset.Position(armAt), fset.Position(applyAt), fset.Position(sweepAt))
	}
}

// N3c feed unit: the evaluator honors a hand-injected feed overlay
// (feed-backed name + overlay resolves) and denies without it. Capture-level
// stamping of the overlay is pinned by the scheduler matrix above (same loop).
func TestFeedOverlayRenameEvaluatorUnit10592(t *testing.T) {
	oldCfg := policyRenameEvaluatorConfig("p-old", config.PolicyPermit)
	newCfg := policyRenameEvaluatorConfig("p-new", config.PolicyPermit)
	for _, cfg := range []*config.Config{oldCfg, newCfg} {
		cfg.Security.Policies[1].Policies[0].Match.SourceAddresses = []string{"bad-actors"}
	}
	bindings, _, ok := expandPolicyRenameAncestry(
		oldCfg, newCfg, []configstore.RenameDescriptor{policyRenameDescriptor("p-old", "p-new")},
	)
	if !ok {
		t.Fatal("valid policy ancestry rejected")
	}
	oldID := dpuserspace.PolicyIDsByStableKey(oldCfg)["lan->wan/p-old"]
	binding := bindings[oldID]
	mkQuery := func() policymatch.Query {
		return policymatch.Query{
			FromZone: "lan", ToZone: "wan",
			SrcIP: net.ParseIP("203.0.113.7"), DstIP: net.ParseIP("10.0.0.20"),
			Protocol: "tcp", SrcPort: 40000, DstPort: 443,
		}
	}
	withOverlay := binding
	withOverlay.feedOverlay = map[string][]string{"bad-actors": {"203.0.113.0/24"}}
	if _, permitted := permittedRenameResult(newCfg, withOverlay, mkQuery()); !permitted {
		t.Fatal("feed-backed name with overlay was not retained")
	}
	if _, permitted := permittedRenameResult(newCfg, binding, mkQuery()); permitted {
		t.Fatal("feed-backed name without overlay was retained")
	}
}

func TestCapturePolicyInvalidationRetainsRenamedAndLeavesFirstPolicy10511(t *testing.T) {
	oldCfg := policyRenameEvaluatorConfig("p-old", config.PolicyPermit)
	newCfg := policyRenameEvaluatorConfig("p-new", config.PolicyPermit)
	oldID := dpuserspace.PolicyIDsByStableKey(oldCfg)["lan->wan/p-old"]
	renamedKey := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 0, 10}, DstIP: [4]byte{10, 0, 0, 20},
		SrcPort: 1234, DstPort: 443, Protocol: 6,
	}
	unboundKey := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 0, 11}, DstIP: [4]byte{10, 0, 0, 21},
		SrcPort: 1235, DstPort: 443, Protocol: 6,
	}
	dp := &policyInvalTestDP{
		v4: map[dataplane.SessionKey]dataplane.SessionValue{
			renamedKey: {
				State:       dataplane.SessStateEstablished,
				PolicyID:    oldID,
				IngressZone: config.StableZoneID("lan"),
				EgressZone:  config.StableZoneID("wan"),
			},
			unboundKey: {
				State:       dataplane.SessStateEstablished,
				PolicyID:    0,
				IngressZone: config.StableZoneID("lan"),
				EgressZone:  config.StableZoneID("wan"),
			},
		},
		v6: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{},
	}
	d := &Daemon{}
	d.setDataplane(dp)
	d.armPolicyInvalidationPlanWithRename(oldCfg, newCfg, &pendingRenameApply{
		descriptors: []configstore.RenameDescriptor{
			policyRenameDescriptor("p-old", "p-new"),
		},
	})
	d.capturePolicyInvalidationLocked(newCfg)
	capture := d.policyInvalidationCapture
	if capture == nil {
		t.Fatal("rename apply did not produce a pre-publication capture")
	}
	if len(capture.renamed) != 1 {
		t.Fatalf("renamed rows = %d, want one nonzero-policy rebind: %+v", len(capture.renamed), capture.renamed)
	}
	if capture.renamed[0].RuleID != "lan->wan/p-new" {
		t.Fatalf("capture rebound unexpected rule: %+v", capture.renamed[0])
	}
	if len(capture.deleted.v4) != 0 {
		t.Fatalf("permitted renamed row entered delete bucket: %+v", capture.deleted.v4)
	}
	if _, ok := dp.v4[unboundKey]; !ok {
		t.Fatal("id-0 unbound row was consumed during rename capture; Rust owns its rotation purge")
	}
}

// A renamed GRE row with discriminator zero cannot be re-identified: the BPF
// conntrack mirror omits the discriminator, so zero is both the valid
// non-tunnel class and an unidentifiable GRE row. The capture routes it to
// the delete bucket (never the renamed set) with PurgeTunnelVariants set, so
// the helper deletes every discriminator variant of the tuple rather than
// under-matching None and leaking the row — or aliasing it onto another GRE
// session. A non-GRE row in the same capture must not carry the flag.
func TestCaptureRoutesGreZeroRenameToWildcardDelete10511(t *testing.T) {
	oldCfg := policyRenameEvaluatorConfig("p-old", config.PolicyPermit)
	newCfg := policyRenameEvaluatorConfig("p-new", config.PolicyPermit)
	oldID := dpuserspace.PolicyIDsByStableKey(oldCfg)["lan->wan/p-old"]
	greKey := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 0, 10}, DstIP: [4]byte{10, 0, 0, 20},
		SrcPort: 0, DstPort: 0, Protocol: 47,
	}
	tcpKey := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 0, 11}, DstIP: [4]byte{10, 0, 0, 21},
		SrcPort: 1234, DstPort: 443, Protocol: 6,
	}
	dp := &policyInvalTestDP{
		v4: map[dataplane.SessionKey]dataplane.SessionValue{
			greKey: {
				State: dataplane.SessStateEstablished, PolicyID: oldID,
				IngressZone: config.StableZoneID("lan"), EgressZone: config.StableZoneID("wan"),
				TunnelDiscriminator: 0,
			},
			tcpKey: {
				State: dataplane.SessStateEstablished, PolicyID: oldID,
				IngressZone: config.StableZoneID("lan"), EgressZone: config.StableZoneID("wan"),
			},
		},
		v6: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{},
	}
	d := &Daemon{}
	d.setDataplane(dp)
	d.armPolicyInvalidationPlanWithRename(oldCfg, newCfg, &pendingRenameApply{
		descriptors: []configstore.RenameDescriptor{
			policyRenameDescriptor("p-old", "p-new"),
		},
	})
	d.capturePolicyInvalidationLocked(newCfg)
	capture := d.policyInvalidationCapture
	if capture == nil {
		t.Fatal("rename apply did not produce a pre-publication capture")
	}
	if len(capture.renamed) != 1 || capture.renamed[0].RuleID != "lan->wan/p-new" {
		t.Fatalf("TCP row was not retained as the one renamed rebind: %+v", capture.renamed)
	}
	if len(capture.deleted.v4) != 1 {
		t.Fatalf("GRE0 row did not land exactly once in the delete bucket: %+v", capture.deleted.v4)
	}
	entry := capture.deleted.v4[0]
	if entry.Key != greKey {
		t.Fatalf("delete bucket holds the wrong row: %+v", entry.Key)
	}
	if !entry.PurgeTunnelVariants {
		t.Fatal("GRE0 delete entry must set PurgeTunnelVariants for the helper wildcard delete")
	}
}

func TestPeerSyncRenameAncestryCaptureAndClearJointFixture10511(t *testing.T) {
	render := func(rule string, extensive bool) string {
		lines := []string{
			"set security zones security-zone other",
			"set security zones security-zone lan",
			"set security zones security-zone wan",
			"set security policies default-policy deny-all",
			"set security policies from-zone other to-zone wan policy p-seed match source-address any",
			"set security policies from-zone other to-zone wan policy p-seed match destination-address any",
			"set security policies from-zone other to-zone wan policy p-seed match application any",
			"set security policies from-zone other to-zone wan policy p-seed then deny",
			"set security policies from-zone lan to-zone wan policy " + rule + " match source-address any",
			"set security policies from-zone lan to-zone wan policy " + rule + " match destination-address any",
			"set security policies from-zone lan to-zone wan policy " + rule + " match application any",
			"set security policies from-zone lan to-zone wan policy " + rule + " then permit",
		}
		if extensive {
			lines = append(lines, "set security policies policy-rematch extensive")
		}
		return strings.Join(lines, "\n") + "\n"
	}
	canonical := func(rule string, extensive bool) string {
		raw := strings.TrimSuffix(render(rule, extensive), "\n")
		lines := strings.Split(raw, "\n")
		for i := range lines {
			lines[i] = strings.TrimPrefix(lines[i], "set ")
		}
		return renderSyncedConfigText(t, lines...)
	}
	store := newConfigStore(t, t.TempDir())
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, line := range strings.Split(strings.TrimSpace(render("p-old", false)), "\n") {
		line = strings.TrimPrefix(line, "set ")
		if err := store.SetFromInput(line); err != nil {
			t.Fatalf("SetFromInput(%q): %v", line, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("initial Commit: %v", err)
	}
	oldCfg := store.ActiveConfig()
	oldID := dpuserspace.PolicyIDsByStableKey(oldCfg)["lan->wan/p-old"]
	if oldID == 0 {
		t.Fatalf("fixture needs a nonzero renamed policy id, got %d", oldID)
	}
	renamedKey := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 0, 10}, DstIP: [4]byte{10, 0, 0, 20},
		SrcPort: 1234, DstPort: 443, Protocol: 6,
	}
	idZeroKey := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 0, 11}, DstIP: [4]byte{10, 0, 0, 21},
		SrcPort: 1235, DstPort: 443, Protocol: 6,
	}
	dp := &policyInvalTestDP{
		v4: map[dataplane.SessionKey]dataplane.SessionValue{
			renamedKey: {
				State: dataplane.SessStateEstablished, PolicyID: oldID,
				IngressZone: config.StableZoneID("lan"), EgressZone: config.StableZoneID("wan"),
			},
			idZeroKey: {
				State: dataplane.SessStateEstablished, PolicyID: 0,
				IngressZone: config.StableZoneID("lan"), EgressZone: config.StableZoneID("wan"),
			},
		},
		v6: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{},
	}
	d := &Daemon{store: store, applySem: semaphore.NewWeighted(1)}
	// The seam stands in for the full dataplane body, but the capture AND
	// the rename staging run through the shared production helper — never a
	// test-local re-implementation — so removing the staging from the helper
	// reds the assertions below. The helper's production callsite placement
	// (before ApplyConfig) is pinned structurally by
	// TestRenameStagingRunsBeforeDataplanePublish10511.
	d.applyBodyForTest = func(cfg *config.Config) {
		d.captureAndStagePolicyRenameAncestry(cfg)
	}
	d.setDataplane(dp)
	ancestry := []configstore.RenameDescriptor{policyRenameDescriptor("p-old", "p-new")}
	if _, err := d.syncAndApplyWithAncestry(context.Background(), canonical("p-new", true), nil, ancestry); err != nil {
		t.Fatalf("peer sync apply returned %v", err)
	}
	if len(dp.renameWire) != 1 {
		t.Fatalf("peer-sync capture emitted %d ancestry rows, want one: %#v", len(dp.renameWire), dp.renameWire)
	}
	if len(dp.renameRows) != 1 || dp.renameRows[0].RuleID != "lan->wan/p-new" {
		t.Fatalf("peer-sync capture did not deliver one permitted rebind: %#v", dp.renameRows)
	}
	if _, ok := dp.v4[renamedKey]; !ok {
		t.Fatal("renamed row was deleted instead of retained for Rust rotation")
	}
	if _, ok := dp.v4[idZeroKey]; !ok {
		t.Fatal("overloaded policy-id 0 row was consumed by the rename capture")
	}
	if d.policyInvalidationCapture != nil {
		t.Fatal("joint peer-sync path left its pre-publication capture armed after clear")
	}
}

// TestRenameStagingRunsBeforeDataplanePublish10511 pins the production
// callsite the HA joint fixture cannot reach through its apply seam: the real
// dataplane body must invoke the shared captureAndStagePolicyRenameAncestry
// helper before its ApplyConfig publish. The joint test proves the helper's
// LOGIC (capture + transfer) through the seam; this proves the real apply
// CALLS it at the #6948 placement. Moving the call after ApplyConfig — or
// deleting it — re-opens the positional-id race the capture exists to close,
// while the joint test alone would stay green.
func TestRenameStagingRunsBeforeDataplanePublish10511(t *testing.T) {
	const src = "daemon_apply_dataplane.go"
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, src, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", src, err)
	}
	var (
		stagingCalls int
		stagingPos   token.Pos
		stagingFunc  string
		publishPos   token.Pos
	)
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		var staged, published token.Pos
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			switch sel.Sel.Name {
			case "captureAndStagePolicyRenameAncestry":
				stagingCalls++
				staged = call.Pos()
			case "ApplyConfig":
				if staged.IsValid() && !published.IsValid() {
					published = call.Pos()
				}
			}
			return true
		})
		if staged.IsValid() {
			stagingPos, stagingFunc, publishPos = staged, fn.Name.Name, published
		}
	}
	if stagingCalls != 1 {
		t.Fatalf("want exactly one production captureAndStagePolicyRenameAncestry call, found %d", stagingCalls)
	}
	if !publishPos.IsValid() || publishPos <= stagingPos {
		t.Fatalf("%s: the rename staging call (%s) must precede the ApplyConfig publish in %s",
			src, fset.Position(stagingPos), stagingFunc)
	}
}

// TestCaptureRenameRetainsFeedBackedRowWithPopulatedFeed10623 closes the one
// unwired atom the #10592 review deferred: a feed-BACKED renamed row retained
// through arm + CapturePolicyInvalidationLocked with a POPULATED feed
// overlay. Adjacent atoms are pinned elsewhere (stamp loop, hand-injected
// overlay honoring, nil-overlay drop, SnapshotForBindings itself); this cell
// wires SnapshotForBindings output → binding.feedOverlay → Match end to end.
//
// The feed Manager is populated through its production path (Apply over an
// httptest feed server + poll-until-installed), not through the feeds
// package's private installPrefixes seam. No timing is asserted — the poll
// waits for installation, so the cell cannot flake on scheduling.
//
// RED: neutering the feedOverlay stamp (nil at the capture binding loop)
// drops the row (renamed == 0): without the overlay the feed-backed name
// cannot resolve, exactly the feed-unresolved shape.
func TestCaptureRenameRetainsFeedBackedRowWithPopulatedFeed10623(t *testing.T) {
	const feedBody = "203.0.113.0/24\n"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, feedBody)
	}))
	defer server.Close()

	const feedName = "bad-actors-feed"
	daCfg := &config.DynamicAddressConfig{
		FeedServers: map[string]*config.FeedServer{
			"srv": {Name: "srv", URL: server.URL, FeedName: feedName, UpdateInterval: 3600},
		},
		AddressBindings: map[string]*config.AddressBinding{
			"bad-actors": {Name: "bad-actors", FeedNames: []string{feedName}},
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr := feeds.New(func() error { return nil })
	// Feed fetch SSRF policy blocks loopback by default; allowlist the
	// httptest server exactly as the feeds package's own tests do.
	mgr.SetPrivateFeedAllowlist([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")})
	mgr.Apply(ctx, daCfg)
	defer mgr.StopAll()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if got := mgr.SnapshotForBindings(daCfg)["bad-actors"]; len(got) == 1 && got[0] == "203.0.113.0/24" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("feed overlay never installed: %v", mgr.SnapshotForBindings(daCfg))
		}
		time.Sleep(5 * time.Millisecond)
	}

	oldCfg := policyRenameEvaluatorConfig("p-old", config.PolicyPermit)
	newCfg := policyRenameEvaluatorConfig("p-new", config.PolicyPermit)
	for _, cfg := range []*config.Config{oldCfg, newCfg} {
		cfg.Security.Policies[1].Policies[0].Match.SourceAddresses = []string{"bad-actors"}
		cfg.Security.Policies[1].Policies = cfg.Security.Policies[1].Policies[:1]
		cfg.Security.DynamicAddress = *daCfg
	}
	// Session source inside the feed prefixes (203.0.113.0/24): with the
	// overlay the renamed rule's match permits and the row retains; without
	// it the name cannot resolve and the row drops.
	key := dataplane.SessionKey{
		SrcIP: [4]byte{203, 0, 113, 7}, DstIP: [4]byte{10, 0, 0, 20},
		SrcPort: 1234, DstPort: 443, Protocol: 6,
	}
	// Out-of-feed source (198.51.100.9 ∉ 203.0.113.0/24): the populated
	// overlay is present but CIDR membership fails, so this row must NOT
	// retain — pinning membership (not just overlay presence) load-bearing
	// at capture level.
	outKey := dataplane.SessionKey{
		SrcIP: [4]byte{198, 51, 100, 9}, DstIP: [4]byte{10, 0, 0, 20},
		SrcPort: 1235, DstPort: 443, Protocol: 6,
	}
	oldID := dpuserspace.PolicyIDsByStableKey(oldCfg)["lan->wan/p-old"]
	mkValue := func() dataplane.SessionValue {
		return dataplane.SessionValue{
			State:       dataplane.SessStateEstablished,
			PolicyID:    oldID,
			IngressZone: config.StableZoneID("lan"),
			EgressZone:  config.StableZoneID("wan"),
		}
	}
	dp := &policyInvalTestDP{
		v4: map[dataplane.SessionKey]dataplane.SessionValue{
			key:    mkValue(),
			outKey: mkValue(),
		},
		v6: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{},
	}
	d := &Daemon{}
	d.setDataplane(dp)
	d.feeds = mgr
	d.armPolicyInvalidationPlanWithRename(oldCfg, newCfg, &pendingRenameApply{
		descriptors: []configstore.RenameDescriptor{
			policyRenameDescriptor("p-old", "p-new"),
		},
	})
	d.capturePolicyInvalidationLocked(newCfg)
	capture := d.policyInvalidationCapture
	if capture == nil {
		t.Fatal("rename apply did not produce a pre-publication capture")
	}
	if len(capture.renamed) != 1 {
		t.Fatalf("populated-feed renamed rows = %d, want 1: %+v", len(capture.renamed), capture.renamed)
	}
	if capture.renamed[0].RuleID != "lan->wan/p-new" {
		t.Fatalf("renamed row rule = %q, want lan->wan/p-new", capture.renamed[0].RuleID)
	}
	if len(capture.deleted.v4) != 1 {
		t.Fatalf("out-of-feed row did not land exactly once in the delete bucket: %+v", capture.deleted.v4)
	}
	if entry := capture.deleted.v4[0]; entry.Key != outKey {
		t.Fatalf("delete bucket holds the wrong row: %+v, want %+v", entry.Key, outKey)
	}
}
