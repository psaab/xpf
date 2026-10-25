package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
)

type sessionTimeoutAuthority16880 struct {
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
