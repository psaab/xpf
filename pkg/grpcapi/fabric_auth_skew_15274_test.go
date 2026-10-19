package grpcapi

import (
	"strings"
	"testing"
	"time"
)

// #15274 C03-03: the fabric-auth skew scan stores "no skew" for any
// present-but-unverifiable token after the global throttle, so a garbage
// token sent from the fabric segment erases a real measured skew from
// `show chassis cluster status` (FabricPeerClockSkew).
//
// Pre-fix, noteFabricAuthSkewForDigest's !ok arm unconditionally stores
// atNanos=0 / reported=false. Post-fix a !ok scan must NOT overwrite a
// measurement: only noteFabricAuthOK (a token that verifies normally)
// clears it. The existing #6708 throttle cell asserted the old clearing
// behaviour; that sub-assertion is folded to the new contract.

// TestGarbageTokenDoesNotEraseMeasuredSkew_15274 is the RED/GREEN cell:
// measure a real skew (150s, an exact auth-window multiple — the scan
// reports window multiples), let the throttle lapse, then present a
// garbage (unverifiable) token. The measured skew must survive.
func TestGarbageTokenDoesNotEraseMeasuredSkew_15274(t *testing.T) {
	key := skewTestKey()
	now := time.Unix(1785600000, 0)
	s := &Server{}

	clause := s.noteFabricAuthSkew([][]byte{key}, tokenAtOffset(t, key, now, 150*time.Second), now)
	if clause == "" {
		t.Fatal("setup: skewed token produced no clause; fixture is not skewed")
	}
	if skew, have := s.FabricPeerClockSkew(); !have || skew != 150 {
		t.Fatalf("setup: FabricPeerClockSkew = %d,%v, want 150,true", skew, have)
	}

	garbageAt := now.Add(fabricAuthSkewScanInterval + time.Second)
	if got := s.noteFabricAuthSkew([][]byte{key}, strings.Repeat("cd", 32), garbageAt); got != "" {
		t.Fatalf("garbage token produced a skew clause %q; an unverifiable token must not be labelled a clock problem", got)
	}
	if skew, have := s.FabricPeerClockSkew(); !have || skew != 150 {
		t.Fatalf("garbage token erased the measured skew: FabricPeerClockSkew = %d,%v, want 150,true", skew, have)
	}
	if got := s.fabricSkewClause(); !strings.Contains(got, "150s") {
		t.Fatalf("status clause after garbage token = %q, want it to still report the measured 150s skew", got)
	}

	// Control: a token that verifies normally still clears the
	// measurement (recovery), exactly as noteFabricAuthOK requires.
	s.noteFabricAuthOK()
	if _, have := s.FabricPeerClockSkew(); have {
		t.Fatal("noteFabricAuthOK must still clear the measured skew on recovery")
	}
}
