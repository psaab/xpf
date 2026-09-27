package cluster

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

func setConfigEpochPeerTagCapability11055(s *SessionSync, capable bool) {
	s.peerSnapshotProtocol.Store(1)
	var flags uint32
	if capable {
		flags = uint32(capFlagConfigEpochReverseTag)
	}
	s.peerCapabilityFlags.Store(flags)
}

func TestActiveActiveConfigEpochAuthorityGuard11055(t *testing.T) {
	const (
		staleAuthorityGen   = uint64(10)
		currentAuthorityGen = uint64(100)
	)

	// The non-authority's applied generation is in the authority's namespace.
	// It stamps that generation with the reverse-direction tag; its local send
	// counter remains unrelated and must not be used.
	sender := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	sender.IsPrimaryFn = func() bool { return false }
	setConfigEpochPeerTagCapability11055(sender, true)
	sender.configGenCounter.Store(3)
	sender.recordRecvConfigGen(staleAuthorityGen)
	sender.recordAppliedConfigGen(staleAuthorityGen)

	key4 := configEpochKeyV4(61001)
	val4 := dataplane.SessionValue{State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 2}
	sender.stampInstallGenV4(key4, &val4)
	if want := configEpochReverseTag | staleAuthorityGen; val4.ConfigEpoch != want {
		t.Fatalf("non-authority v4 ConfigEpoch = %#x, want tagged authority generation %#x", val4.ConfigEpoch, want)
	}
	if got := val4.Generation; got == 0 {
		t.Fatal("v4 stamp must retain the independent install generation")
	}

	key6 := configEpochKeyV6(61002)
	val6 := dataplane.SessionValueV6{State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 2}
	sender.stampInstallGenV6(key6, &val6)
	if want := configEpochReverseTag | staleAuthorityGen; val6.ConfigEpoch != want {
		t.Fatalf("non-authority v6 ConfigEpoch = %#x, want tagged authority generation %#x", val6.ConfigEpoch, want)
	}

	// The authority has committed a tighter config at generation 100. Both
	// reverse-direction families must reject the stale permits before they can
	// be installed for a later failover.
	dpAuthority := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{},
		v6sessions: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{},
	}
	authority := NewSessionSync(":0", "10.0.0.2:4785", dpAuthority)
	authority.IsPrimaryFn = func() bool { return true }
	setConfigEpochPeerTagCapability11055(authority, true)
	authority.configGenCounter.Store(currentAuthorityGen)
	if authority.installClusterSyncedV4(key4, val4) {
		t.Fatal("authority admitted v4 session stamped under config generation 10 after commit 100")
	}
	if authority.installClusterSyncedV6(key6, val6) {
		t.Fatal("authority admitted v6 session stamped under config generation 10 after commit 100")
	}
	// The would-be RG1 forwarding node has no stale row at this point. This
	// snapshot is before any session-owning RG ownership move, not a row
	// removed after promotion.
	if len(dpAuthority.v4sessions) != 0 || len(dpAuthority.v6sessions) != 0 {
		t.Fatal("stale reverse-direction sessions were installed before the owning RG moved")
	}
	if got := authority.stats.SessionsStaleConfigIgnored.Load(); got != 2 {
		t.Fatalf("SessionsStaleConfigIgnored = %d, want 2 for v4 and v6", got)
	}

	// Once the non-authority has applied the current authority generation, a
	// tagged equal-generation session is accepted. This is the converged state
	// after an RG0 handover; comparing it against the authority's send counter
	// must not create a false reject.
	sender.recordRecvConfigGen(currentAuthorityGen)
	sender.recordAppliedConfigGen(currentAuthorityGen)
	currentKey := configEpochKeyV4(61003)
	currentVal := dataplane.SessionValue{State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 2}
	sender.stampInstallGenV4(currentKey, &currentVal)
	if currentVal.ConfigEpoch != configEpochReverseTag|currentAuthorityGen {
		t.Fatalf("converged reverse stamp = %#x, want %#x", currentVal.ConfigEpoch, configEpochReverseTag|currentAuthorityGen)
	}
	if !authority.installClusterSyncedV4(currentKey, currentVal) {
		t.Fatal("authority falsely rejected a converged session stamped with its current config generation")
	}

	// During RG0 handover the peers can temporarily disagree about authority.
	// Their epochs are not comparable then, so a mismatched source tag disables
	// the guard rather than falsely rejecting a valid session.
	newAuthorityKey := configEpochKeyV4(61004)
	if !authority.installClusterSyncedV4(newAuthorityKey, dataplane.SessionValue{
		State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 2,
		ConfigEpoch: staleAuthorityGen, // old authority-role frame: untagged
	}) {
		t.Fatal("new authority falsely rejected an untagged frame across the RG0 handover")
	}

	nonAuthority := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{},
	})
	nonAuthority.IsPrimaryFn = func() bool { return false }
	nonAuthority.recordAppliedConfigGen(currentAuthorityGen)
	taggedOldRoleKey := configEpochKeyV4(61005)
	if !nonAuthority.installClusterSyncedV4(taggedOldRoleKey, dataplane.SessionValue{
		State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 2,
		ConfigEpoch: configEpochReverseTag | staleAuthorityGen,
	}) {
		t.Fatal("new non-authority falsely rejected a tagged frame across the RG0 handover")
	}
}

func TestActiveActiveConfigEpochStampRequiresConvergence11055(t *testing.T) {
	sender := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	sender.IsPrimaryFn = func() bool { return false }
	setConfigEpochPeerTagCapability11055(sender, true)
	sender.configGenCounter.Store(3)
	sender.recordAppliedConfigGen(10)
	if got := sender.stampConfigEpoch(); got != 0 {
		t.Fatalf("non-authority stamp with received/applied generations divergent = %#x, want disabled epoch 0", got)
	}
	sender.recordRecvConfigGen(10)
	if got, want := sender.stampConfigEpoch(), configEpochReverseTag|10; got != want {
		t.Fatalf("converged non-authority stamp = %#x, want %#x", got, want)
	}
}

func TestActiveActiveConfigEpochRequiresPeerCapability11055(t *testing.T) {
	if localCapabilityFlags&capFlagConfigEpochReverseTag == 0 {
		t.Fatal("this build does not advertise reverse ConfigEpoch tag support")
	}

	sender := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	sender.IsPrimaryFn = func() bool { return false }
	sender.configGenCounter.Store(3)
	sender.recordRecvConfigGen(10)
	sender.recordAppliedConfigGen(10)
	if got := sender.stampConfigEpoch(); got != 3 {
		t.Fatalf("unlearned-peer legacy stamp = %#x, want local send generation 3", got)
	}
	setConfigEpochPeerTagCapability11055(sender, false)
	if got := sender.stampConfigEpoch(); got != 3 {
		t.Fatalf("legacy-peer stamp = %#x, want local send generation 3", got)
	}
	setConfigEpochPeerTagCapability11055(sender, true)
	if got, want := sender.stampConfigEpoch(), configEpochReverseTag|10; got != want {
		t.Fatalf("capable-peer stamp = %#x, want %#x", got, want)
	}

	authority := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	authority.IsPrimaryFn = func() bool { return true }
	authority.configGenCounter.Store(100)
	taggedStale := configEpochReverseTag | 10
	if authority.configEpochStale(taggedStale) {
		t.Fatal("authority compared a tagged epoch before learning peer capabilities")
	}
	setConfigEpochPeerTagCapability11055(authority, false)
	if authority.configEpochStale(taggedStale) {
		t.Fatal("authority compared a tagged epoch from a legacy peer")
	}
	setConfigEpochPeerTagCapability11055(authority, true)
	if !authority.configEpochStale(taggedStale) {
		t.Fatal("authority failed to reject a stale tagged epoch from a capable peer")
	}
}

func TestActiveActiveConfigEpochDoesNotTagRetainedMarkAcrossHandover11055(t *testing.T) {
	localPrimary := true
	sender := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	sender.IsPrimaryFn = func() bool { return localPrimary }
	sender.configGenCounter.Store(5)
	// This applied mark belongs to the prior authority namespace. A new
	// authority has an independently seeded counter at 100 and has not pushed
	// a post-handover config yet.
	sender.lastRecvConfigGen.Store(90)
	sender.lastAppliedConfigGen.Store(90)
	setConfigEpochPeerTagCapability11055(sender, true)
	if got := sender.stampConfigEpoch(); got != 5 {
		t.Fatalf("old-role authority stamp = %d, want its local send generation 5", got)
	}

	localPrimary = false
	if got := sender.stampConfigEpoch(); got != 0 {
		t.Fatalf("retained pre-handover mark stamp = %#x, want disabled epoch 0", got)
	}

	newAuthority := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	newAuthority.IsPrimaryFn = func() bool { return true }
	newAuthority.configGenCounter.Store(100)
	setConfigEpochPeerTagCapability11055(newAuthority, true)
	if !newAuthority.configEpochStale(configEpochReverseTag | 90) {
		t.Fatal("test setup failed: comparing the retained old-namespace tag must show the false-reject hazard")
	}
	if newAuthority.configEpochStale(sender.stampConfigEpoch()) {
		t.Fatal("authority falsely rejected an untagged frame before it proved the new namespace")
	}

	// Only a generation received and applied after the role transition proves
	// that this sender now holds the current authority's namespace.
	sender.recordRecvConfigGen(101)
	sender.recordAppliedConfigGen(101)
	newAuthority.configGenCounter.Store(101)
	if got, want := sender.stampConfigEpoch(), configEpochReverseTag|101; got != want {
		t.Fatalf("post-handover stamp = %#x, want current-authority epoch %#x", got, want)
	}
	if newAuthority.configEpochStale(configEpochReverseTag | 101) {
		t.Fatal("authority falsely rejected a post-handover session at its current generation")
	}
}
