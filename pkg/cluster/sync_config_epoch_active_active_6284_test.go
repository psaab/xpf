package cluster

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #6284 historical coverage for the config-epoch guard.
//
// Config sync remains unidirectional: only the RG0 config-sync authority
// pushes config, so the authority's `configGenCounter` is the namespace the
// non-authority records in `lastAppliedConfigGen`. The #5274 guard therefore
// refuses an untagged authority epoch once the receiver has applied a newer
// config. #11055 extends that protection to the reverse direction with a
// tagged authority-relative epoch; its production stamp/install and handover
// behavior is exercised in sync_config_epoch_11055_test.go.
//
// These cells retain the original forward-direction check, pin the fail-open
// compatibility behavior for untagged epochs at an authority or tagged epochs
// at a non-authority during role disagreement, and verify that a converged
// non-authority stamps the applied authority generation without advancing its
// own send counter.

// TestActiveActiveConfigEpochDirectionalCoverage6284 retains the original
// #5274 forward-direction check, untagged handover compatibility case, and
// converged non-authority source assertion.
func TestActiveActiveConfigEpochDirectionalCoverage6284(t *testing.T) {
	// This legacy untagged stamp is not a real non-authority stamp after
	// #11055; role mismatch cases are intentionally fail-open during handover.
	const frozenEpoch = 3

	// --- PROTECTED direction (config-authority -> peer) ---
	// This receiver APPLIED a strictly-newer peer config, so its receive
	// high-water advanced to 10 (the same namespace the authority stamps in).
	// A session stamped with the older epoch 3 is a stale permit the newer
	// config may deny — it MUST be refused.
	dpApplied := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}}
	ssApplied := NewSessionSync(":0", "10.0.0.2:4785", dpApplied)
	ssApplied.IsPrimaryFn = func() bool { return false }
	ssApplied.recordAppliedConfigGen(10) // real receiver high-water advance
	if got := ssApplied.lastAppliedConfigGen.Load(); got != 10 {
		t.Fatalf("recordAppliedConfigGen(10): lastAppliedConfigGen = %d, want 10", got)
	}
	protectedKey := configEpochKeyV4(60001)
	installWithConfigEpochV4(ssApplied, protectedKey, frozenEpoch) // 3 < applied 10 -> REFUSE
	if _, ok := dpApplied.v4sessions[protectedKey]; ok {
		t.Fatal("config-authority->peer direction: a frozen-epoch(3) install must be REFUSED once this node applied a newer config(10) — the #5274 guard covers this direction")
	}
	if got := ssApplied.stats.SessionsStaleConfigIgnored.Load(); got != 1 {
		t.Fatalf("SessionsStaleConfigIgnored = %d, want 1 after the protected-direction reject", got)
	}

	// --- HANDOVER COMPATIBILITY: an untagged frame at the authority ---
	// A primary expects tagged reverse epochs. An untagged frame can come from
	// a peer that has not observed the local promotion yet, so it is admitted
	// rather than compared against this node's unrelated send namespace.
	dpAuth := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}}
	ssAuth := NewSessionSync(":0", "10.0.0.2:4785", dpAuth)
	ssAuth.IsPrimaryFn = func() bool { return true }
	ssAuth.configGenCounter.Store(100) // authority advanced its OWN send counter via local commits
	// lastAppliedConfigGen deliberately remains 0; authority compares only a
	// matching tagged reverse epoch against its local configGenCounter.
	inertKey := configEpochKeyV4(60002)
	installWithConfigEpochV4(ssAuth, inertKey, frozenEpoch)
	if _, ok := dpAuth.v4sessions[inertKey]; !ok {
		t.Fatal("authority falsely rejected an untagged frame during RG0 handover")
	}
	if got := ssAuth.stats.SessionsStaleConfigIgnored.Load(); got != 0 {
		t.Fatalf("SessionsStaleConfigIgnored = %d, want 0 for mismatched role tag", got)
	}

	// --- ROOT CAUSE AND FIXED STAMP: the authority apply namespace ---
	// A converged non-authority stamps the config generation it successfully
	// applied, with the source tag, but does not advance its own send counter.
	dpB := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{},
		v6sessions: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{},
	}
	ssB := NewSessionSync(":0", "10.0.0.2:4785", dpB)
	ssB.IsPrimaryFn = func() bool { return false }
	ssB.configGenCounter.Store(frozenEpoch) // frozen boot seed; this node never sends config
	setConfigEpochPeerTagCapability11055(ssB, true)
	ssB.recordRecvConfigGen(10)
	ssB.recordAppliedConfigGen(10) // applies the authority's config (real path)
	ssB.recordRecvConfigGen(11)
	ssB.recordAppliedConfigGen(11) // and its next commit
	if got := ssB.lastAppliedConfigGen.Load(); got != 11 {
		t.Fatalf("recordAppliedConfigGen advanced receive high-water to %d, want 11", got)
	}
	if got := ssB.configGenCounter.Load(); got != frozenEpoch {
		t.Fatalf("config apply must NOT advance the send-stamp counter: configGenCounter = %d, want frozen %d", got, frozenEpoch)
	}
	var ownV4 dataplane.SessionValue
	ssB.stampInstallGenV4(configEpochKeyV4(60003), &ownV4)
	if ownV4.ConfigEpoch != configEpochReverseTag|11 {
		t.Fatalf("converged non-authority v4 epoch = %#x, want tagged applied authority generation %#x", ownV4.ConfigEpoch, configEpochReverseTag|11)
	}
	var ownV6 dataplane.SessionValueV6
	ssB.stampInstallGenV6(configEpochKeyV6(60004), &ownV6)
	if ownV6.ConfigEpoch != configEpochReverseTag|11 {
		t.Fatalf("converged non-authority v6 epoch = %#x, want tagged applied authority generation %#x", ownV6.ConfigEpoch, configEpochReverseTag|11)
	}
}

// TestActiveActiveConfigEpochDirectionalCoverage6284V6 mirrors the protected
// authority-to-peer path and the untagged handover compatibility case on v6.
func TestActiveActiveConfigEpochDirectionalCoverage6284V6(t *testing.T) {
	const frozenEpoch = 3

	// PROTECTED: applied a newer config -> refuse the frozen-epoch install.
	dpApplied := &mockSweepDP{v6sessions: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{}}
	ssApplied := NewSessionSync(":0", "10.0.0.2:4785", dpApplied)
	ssApplied.IsPrimaryFn = func() bool { return false }
	ssApplied.recordAppliedConfigGen(10)
	protectedKey := configEpochKeyV6(60101)
	installWithConfigEpochV6(ssApplied, protectedKey, frozenEpoch)
	if _, ok := dpApplied.v6sessions[protectedKey]; ok {
		t.Fatal("config-authority->peer direction (v6): frozen-epoch(3) install must be REFUSED after applying config(10)")
	}
	if got := ssApplied.stats.SessionsStaleConfigIgnored.Load(); got != 1 {
		t.Fatalf("SessionsStaleConfigIgnored = %d, want 1 after the v6 protected-direction reject", got)
	}

	// HANDOVER COMPATIBILITY: the authority admits an untagged epoch because
	// the sender may not yet have observed the promotion.
	dpAuth := &mockSweepDP{v6sessions: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{}}
	ssAuth := NewSessionSync(":0", "10.0.0.2:4785", dpAuth)
	ssAuth.IsPrimaryFn = func() bool { return true }
	ssAuth.configGenCounter.Store(100)
	inertKey := configEpochKeyV6(60102)
	installWithConfigEpochV6(ssAuth, inertKey, frozenEpoch)
	if _, ok := dpAuth.v6sessions[inertKey]; !ok {
		t.Fatal("v6 authority falsely rejected an untagged frame during RG0 handover")
	}
	if got := ssAuth.stats.SessionsStaleConfigIgnored.Load(); got != 0 {
		t.Fatalf("SessionsStaleConfigIgnored = %d, want 0 for mismatched v6 role tag", got)
	}
}
