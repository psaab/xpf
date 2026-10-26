package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

type sessionTimeoutAuthority16880 struct {
	dataplane.RuntimeDataPlane
	applied *config.Config
}

func (a sessionTimeoutAuthority16880) PolicyReadConfig() *config.Config {
	return a.applied
}

func TestSessionTimeoutProfileSourceUsesCaptureAuthority16880(t *testing.T) {
	applied := &config.Config{}
	applied.Security.Flow.UDPSessionTimeout = 10
	source := sessionTimeoutAuthority16880{applied: applied}
	if got := policyInvalidationAppliedConfig(source); got != applied {
		t.Fatalf("applied timeout source = %p, want capture authority %p", got, applied)
	}
	if !hasSessionTimeoutCaptureAuthority(source) {
		t.Fatal("capture authority was not recognized for applied timeout profile seeding")
	}
}

func TestSessionSyncTimeoutProfileHandoffAppliesLatestCapture16880(t *testing.T) {
	oldCfg := &config.Config{}
	oldCfg.Security.Flow.UDPSessionTimeout = 60
	latestCfg := &config.Config{}
	latestCfg.Security.Flow.UDPSessionTimeout = 10
	d := &Daemon{}
	d.dpCell.Store(&dpSlot{v: sessionTimeoutAuthority16880{applied: oldCfg}})

	ss := cluster.NewSessionSync(":0", "10.0.0.2:4785", nil)
	d.seedActiveSessionSyncTimeoutProfile(ss)
	if got := ss.ReceiverSessionTimeoutProfileForTesting().UDPSessionSeconds; got != 60 {
		t.Fatalf("constructor seed UDP timeout = %ds, want 60s", got)
	}

	// Model an applied-snapshot callback between local seeding and publication.
	// With no live sessionSync yet, the callback can only update the handoff.
	d.updateSessionSyncTimeoutProfile(latestCfg)
	if !d.publishSessionSyncIfCurrent(0, ss) {
		t.Fatal("constructor object was not published for the current epoch")
	}
	if got := ss.ReceiverSessionTimeoutProfileForTesting().UDPSessionSeconds; got != 10 {
		t.Fatalf("published session sync retained stale %ds profile, want latest 10s", got)
	}
}

func TestReceiverSessionTimeoutProfileFromConfig16880(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Flow.UDPSessionTimeout = 10
	cfg.Security.Flow.ICMPSessionTimeout = 11
	cfg.Security.Flow.TCPSession = &config.TCPSessionConfig{
		EstablishedTimeout:             12,
		InitialTimeout:                 13,
		ClosingTimeout:                 14,
		TimeWaitTimeout:                15,
		TimeWaitStateSessionTimeout:    16,
		TimeWaitStateSessionAgeout:     true,
		TimeWaitStateApplyToHalfClosed: true,
		FinInvalidateSession:           true,
	}

	got := receiverSessionTimeoutProfileFromConfig(cfg)
	want := cluster.ReceiverSessionTimeoutProfile{
		UDPSessionSeconds:            10,
		ICMPSessionSeconds:           11,
		TCPEstablishedSeconds:        12,
		TCPOpeningSeconds:            13,
		TCPClosingSeconds:            14,
		TCPTimeWaitSeconds:           16,
		TCPTimeWaitSessionAgeout:     true,
		TCPTimeWaitApplyToHalfClosed: true,
		TCPFinInvalidateSession:      true,
	}
	if got != want {
		t.Fatalf("receiver timeout profile = %+v, want %+v", got, want)
	}
}
