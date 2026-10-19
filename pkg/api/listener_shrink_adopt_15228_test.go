package api

import (
	"context"
	"net"
	"testing"
)

// #15228 A44-02: shrinking [v4,v6] -> [v6] must adopt the surviving v6 leg.
// The positional code in the issue tried to bind v6 into slot 0 while slot 1
// still held it, failed, kept the dropped v4 leg and retired v6.
func TestReconcileShrinkAdoptsSurvivingLeg15228(t *testing.T) {
	if ln, err := net.Listen("tcp", "[::1]:0"); err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	} else {
		ln.Close()
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := []string{"127.0.0.1:0", "[::1]:0"}
	s := NewServer(Config{Addrs: req})
	s.SetTLSCertDirForTest(t.TempDir())
	if err := s.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { cancel(); s.Wait() }()
	bound := s.EffectiveHTTPAddrs()
	if len(bound) != 2 {
		t.Fatalf("bound=%v want 2", bound)
	}
	if err := s.ReconcileHTTPAddrs([]string{req[1]}); err != nil {
		t.Fatalf("shrink [v4,v6]->[v6] err=%v want nil", err)
	}
	got := s.EffectiveHTTPAddrs()
	if len(got) != 1 || got[0] != bound[1] {
		t.Fatalf("after shrink got=%v want [%s] (surviving v6)", got, bound[1])
	}
	assertHTTP200(t, "http://"+bound[1]+"/health")
	if !s.HTTPServing() {
		t.Fatal("HTTPServing false after shrink")
	}
	// Control: shrink to v4 only.
	if err := s.ReconcileHTTPAddrs(req); err != nil {
		t.Fatalf("regrow: %v", err)
	}
	if err := s.ReconcileHTTPAddrs([]string{req[0]}); err != nil {
		t.Fatalf("shrink to v4 err=%v", err)
	}
	got = s.EffectiveHTTPAddrs()
	if len(got) != 1 {
		t.Fatalf("after v4 shrink got=%v want 1", got)
	}
	assertHTTP200(t, "http://"+got[0]+"/health")
}
