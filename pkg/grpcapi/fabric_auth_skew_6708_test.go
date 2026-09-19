package grpcapi

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/metadata"
)

// #6708: >30s of wall-clock skew between peers kills every fabric RPC with
// "invalid auth token" — permanently, since skew does not self-correct without
// NTP. Measured on the loss userspace cluster: 141s apart, NTPSynchronized=no
// on both nodes. The operator-visible symptom named SESSIONS ("fw0 has only 1
// established sessions"); the cause was the clock.
//
// The accept band is deliberately NOT widened — it is the replay horizon, and
// the allowlisted fabric RPCs include ClearSessions and cross-node failover.
// What is added is diagnosis, and its trustworthiness rests on one property:
// a skew is reported ONLY when the token verifies under an accepted key at some
// window. Only a key holder can produce that, so a forged token or a genuine
// PSK mismatch can neither plant a number in an operator's status output nor be
// mislabelled as a clock problem — which would be the same class of mistake
// #6708 is about.

const skewTestWindow = int64(fabricAuthWindowSeconds)

func skewTestKey() []byte { return []byte("shared-control-link-psk") }

// tokenAtOffset builds the token a peer whose clock is `offset` out would send.
func tokenAtOffset(t *testing.T, key []byte, now time.Time, offset time.Duration, method ...string) string {
	t.Helper()
	return fabricAuthTokenHex(key, now.Add(offset), method...)
}

// TestMeasureFabricAuthSkewOnlyReportsAnAuthenticatedWindow6708 is the truth
// table for the measurement itself.
func TestMeasureFabricAuthSkewOnlyReportsAnAuthenticatedWindow6708(t *testing.T) {
	// Pinned to a window boundary so an offset maps to an exact window count
	// and the expected values are not a function of when the suite runs.
	now := time.Unix(1785600000, 0)
	key := skewTestKey()

	cases := []struct {
		name     string
		token    string
		wantOK   bool
		wantSkew int64
		why      string
	}{
		{
			name:   "the_measured_141s_case",
			token:  tokenAtOffset(t, key, now, 141*time.Second),
			wantOK: true,
			// 141s lands in the window 4 ahead of ours (141/30 = 4.7, and the
			// boundary-pinned `now` puts it in window base+4).
			wantSkew: 4 * skewTestWindow,
			why:      "the skew actually observed on the loss userspace cluster",
		},
		{
			name:     "a_peer_behind_us_reports_a_negative_skew",
			token:    tokenAtOffset(t, key, now, -300*time.Second),
			wantOK:   true,
			wantSkew: -10 * skewTestWindow,
			why:      "direction must survive; an operator needs to know WHICH node to fix",
		},
		{
			name:   "a_wrong_key_is_NOT_a_clock_problem",
			token:  tokenAtOffset(t, []byte("a-different-psk"), now, 141*time.Second),
			wantOK: false,
			why: "reporting a skew here would tell an operator to fix NTP when the " +
				"real fault is a PSK mismatch — the same mislabelling #6708 is about",
		},
		{
			name:   "a_forged_token_is_NOT_a_clock_problem",
			token:  strings.Repeat("ab", 32),
			wantOK: false,
			why:    "an on-segment attacker must not be able to plant a number in status output",
		},
		{
			name:   "a_malformed_token_is_rejected_without_a_scan",
			token:  "not-hex",
			wantOK: false,
			why:    "hex/length are checked before any HMAC work",
		},
		{
			name:   "skew_beyond_the_scan_band_is_not_characterised",
			token:  tokenAtOffset(t, key, now, 3*time.Hour),
			wantOK: false,
			why:    "the band is bounded at ±2h on purpose; past that the number adds nothing",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			skew, ok := measureFabricAuthSkew([][]byte{key}, tc.token, now)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v — %s", ok, tc.wantOK, tc.why)
			}
			if ok && skew != tc.wantSkew {
				t.Fatalf("skew = %ds, want %ds — %s", skew, tc.wantSkew, tc.why)
			}
		})
	}
}

// TestSkewScanDoesNotWidenTheAcceptBand6708 is the security cell.
//
// The scan must be diagnosis ONLY. If adding it also admitted the RPC, #6708
// would have been "fixed" by multiplying the replay horizon of ClearSessions
// and cross-node failover by 240 — the outcome the PR explicitly refuses.
func TestSkewScanDoesNotWidenTheAcceptBand6708(t *testing.T) {
	key := skewTestKey()
	now := time.Now()
	for _, offset := range []time.Duration{
		141 * time.Second, -141 * time.Second, 30 * time.Minute,
	} {
		if verifyFabricAuthToken(key, tokenAtOffset(t, key, now, offset)) {
			t.Fatalf("a token %v out of window VERIFIED; the accept band was widened, "+
				"which multiplies the replay horizon of the allowlisted fabric RPCs "+
				"(ClearSessions, cross-node failover)", offset)
		}
	}
	// Positive control: the ±1 band still works, so the cell above is not
	// passing against a verifier that rejects everything.
	for _, offset := range []time.Duration{0, 25 * time.Second, -25 * time.Second} {
		if !verifyFabricAuthToken(key, tokenAtOffset(t, key, now, offset)) {
			t.Fatalf("a token %v out of window was REJECTED; the ±1 accept band "+
				"regressed and the cell above is vacuous", offset)
		}
	}
}

// TestRejectedSkewedTokenNamesTheClock6708 drives the real interceptor entry
// point and asserts the operator-facing text, because "the skew is recorded
// somewhere" is not the property — the property is that the message an operator
// reads names the clock.
func TestRejectedSkewedTokenNamesTheClock6708(t *testing.T) {
	key := skewTestKey()
	now := time.Now()

	cases := []struct {
		name       string
		token      string
		wantClock  bool
		wantStatus bool // a skew should be visible in `show chassis cluster status`
	}{
		{"skewed_peer_names_the_clock", tokenAtOffset(t, key, now, 141*time.Second, "/xpf.v1.BpfrxService/GetSessions"), true, true},
		{"wrong_psk_does_not_name_the_clock", tokenAtOffset(t, []byte("other-psk"), now, 0, "/xpf.v1.BpfrxService/GetSessions"), false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{}
			s.fabricAuthKeyFn = func() []byte { return key }
			ctx := metadata.NewIncomingContext(context.Background(),
				metadata.Pairs(fabricAuthMetadataKey, tc.token))

			err := s.checkFabricAuth(ctx, "/xpf.v1.BpfrxService/GetSessions")
			if err == nil {
				t.Fatal("checkFabricAuth admitted an out-of-band token")
			}
			named := strings.Contains(err.Error(), "the PSK is correct")
			if named != tc.wantClock {
				if tc.wantClock {
					t.Fatalf("rejection did not name the clock: %v\n"+
						"This is the whole defect: 'invalid auth token' sent an "+
						"engineer looking at sessions when the fault was NTP.", err)
				}
				t.Fatalf("a wrong-PSK rejection blamed the clock: %v\n"+
					"That sends an operator to fix NTP for an authentication fault "+
					"NTP cannot fix.", err)
			}
			if named && !strings.Contains(err.Error(), "NTP") {
				t.Fatalf("rejection names a skew but not the remedy: %v", err)
			}

			gotSkew, have := s.FabricPeerClockSkew()
			if have != tc.wantStatus {
				t.Fatalf("FabricPeerClockSkew present = %v, want %v", have, tc.wantStatus)
			}
			if tc.wantStatus && gotSkew <= 0 {
				t.Fatalf("recorded skew = %d, want a positive value for a peer AHEAD of us", gotSkew)
			}
		})
	}
}

// TestSkewScanIsThrottled6708 is the DoS cell.
//
// The scan runs on the reject path, which is the path an attacker controls by
// sending junk. Unthrottled, one garbage token costs up to 481 HMAC-SHA256
// computations — a ~500x amplification. The throttle is what makes adding a
// diagnostic to an attacker-reachable path safe.
func TestSkewScanIsThrottled6708(t *testing.T) {
	key := skewTestKey()
	now := time.Unix(1785600000, 0)
	s := &Server{}
	s.fabricAuthKeyFn = func() []byte { return key }

	scans := 0
	countingKeys := [][]byte{key}
	scan := func(at time.Time) string {
		scans++
		return s.noteFabricAuthSkew(countingKeys, tokenAtOffset(t, key, now, 141*time.Second), at)
	}

	first := scan(now)
	if first == "" {
		t.Fatal("the first scan produced no clause; the fixture is not skewed")
	}
	before := s.fabricSkew.lastScanNanos.Load()

	// A second call inside the interval must NOT re-scan...
	if got := s.noteFabricAuthSkew(countingKeys, strings.Repeat("cd", 32), now.Add(time.Second)); got != first {
		t.Fatalf("a throttled call re-scanned (clause changed to %q); an attacker "+
			"can drive this path at will and each scan costs ~481 HMACs", got)
	}
	if s.fabricSkew.lastScanNanos.Load() != before {
		t.Fatal("the throttle timestamp moved on a suppressed call, so the window " +
			"slides forward on attacker traffic and never closes")
	}
	// ...and the throttled answer must still be the LAST GOOD one, so an
	// operator's query does not depend on winning a race.
	if !strings.Contains(first, "the PSK is correct") {
		t.Fatalf("clause = %q, want it to name the clock", first)
	}

	// Past the interval it scans again. A token that is NOT skew-explained must
	// now CLEAR the state rather than leaving a stale number asserted.
	if got := scan(now.Add(fabricAuthSkewScanInterval + time.Second)); got != "" {
		_ = got
	}
	s.fabricSkew.lastScanNanos.Store(0)
	if got := s.noteFabricAuthSkew(countingKeys, strings.Repeat("cd", 32), now.Add(time.Minute)); got != "" {
		t.Fatalf("an unexplained token still reported a skew (%q); the status "+
			"surface would keep asserting a clock fault that no longer explains "+
			"anything", got)
	}
	if _, have := s.FabricPeerClockSkew(); have {
		t.Fatal("a scan that explained nothing left the previous measurement latched")
	}
	if scans == 0 {
		t.Fatal("no scan ran at all; this cell asserts nothing")
	}
}

// TestRecoveredFabricAuthClearsTheSkew6708: once tokens verify normally the
// clocks agree, so the status surface must stop reporting a skew and the
// one-shot warning must re-arm for the next episode.
func TestRecoveredFabricAuthClearsTheSkew6708(t *testing.T) {
	key := skewTestKey()
	now := time.Now()
	s := &Server{}
	s.fabricAuthKeyFn = func() []byte { return key }

	skewed := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs(fabricAuthMetadataKey, tokenAtOffset(t, key, now, 141*time.Second, "/m")))
	if err := s.checkFabricAuth(skewed, "/m"); err == nil {
		t.Fatal("skewed token was admitted")
	}
	if _, have := s.FabricPeerClockSkew(); !have {
		t.Fatal("no skew recorded from a skewed token; the rest of this cell is vacuous")
	}

	healthy := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs(fabricAuthMetadataKey, fabricAuthTokenHex(key, now, "/m")))
	if err := s.checkFabricAuth(healthy, "/m"); err != nil {
		t.Fatalf("an in-window token was rejected: %v", err)
	}
	if skew, have := s.FabricPeerClockSkew(); have {
		t.Fatalf("skew %ds still reported after authentication recovered; "+
			"`show chassis cluster status` would warn about a clock that is now fine", skew)
	}
}

// TestClusterStatusWarnsOnlyWhenSkewed6708 pins the show surface, including the
// silence half: a healthy cluster's status must be byte-identical to before.
func TestClusterStatusWarnsOnlyWhenSkewed6708(t *testing.T) {
	s := &Server{}
	var quiet strings.Builder
	s.appendFabricClockSkew(&quiet)
	if quiet.String() != "" {
		t.Fatalf("status appended %q with no measured skew; every healthy cluster "+
			"would carry a warning", quiet.String())
	}

	s.fabricSkew.skewSeconds.Store(141)
	s.fabricSkew.atNanos.Store(time.Now().UnixNano())
	var warned strings.Builder
	s.appendFabricClockSkew(&warned)
	out := warned.String()
	for _, want := range []string{"141s ahead of", "NTP", "failover are unaffected"} {
		if !strings.Contains(out, want) {
			t.Fatalf("status warning missing %q:\n%s", want, out)
		}
	}
}

// The skew clause must stay TRUE on every path that reaches it.
//
// #6708's scan proves the token verified under an accepted key at some window.
// That makes the PSK certainly correct, and the clock only PROBABLY skewed:
// producing the token requires the key, but PRESENTING it does not. Tokens ride
// every fabric RPC on the control link and are method-bound; this verifier has
// no nonce (same-method replay within the accepted window remains the bounded
// Residual 1), so a captured token replayed from outside the accept band but
// inside the scan band fails verification — correctly — and arrives here
// indistinguishable from a drifting clock.
//
// This test is the guard on the WORDING, because that is where the defect would
// be: an unhedged "peer wall clock is Ns behind ours" is a confident wrong
// diagnosis in the replay case, which is the same class of fault as the opaque
// "invalid auth token" #6708 removed. It is deliberately paired: the certain
// half must be asserted as fact, and the uncertain half must not be.
func TestSkewClauseDoesNotAssertSkewAsTheOnlyCause_6708(t *testing.T) {
	// A token from a window well outside the accept band — the shape both a
	// drifting peer and a replayed capture produce. Nothing at this layer can
	// distinguish them, which is the point.
	clause := fabricSkewClause(-2400)

	// CERTAIN half: this is the diagnostic that stops an operator
	// re-provisioning a key that was never wrong. It must be stated plainly.
	if !strings.Contains(clause, "the PSK is correct") {
		t.Errorf("clause does not state the one thing the scan PROVES — that the "+
			"key verified. That is the finding that ends the investigation: %q", clause)
	}
	// The measurement itself must survive; an operator needs the magnitude.
	if !strings.Contains(clause, "2400s") {
		t.Errorf("clause dropped the measured offset: %q", clause)
	}
	// UNCERTAIN half: the alternative cause must be named. Without this the
	// message asserts a clock skew that may not exist.
	if !strings.Contains(clause, "replayed") {
		t.Errorf("clause asserts clock skew without naming the replay alternative: %q\n\n"+
			"Producing this token needs the key; presenting it does not. A captured "+
			"token replayed inside the scan band lands here too, and the scan cannot "+
			"tell them apart — so an unhedged skew claim is a confident wrong "+
			"diagnosis.", clause)
	}
	// The remedy for the overwhelmingly common cause must still be present, or
	// hedging the diagnosis has cost the operator the action.
	if !strings.Contains(clause, "NTP") {
		t.Errorf("clause hedges the cause but drops the remedy: %q", clause)
	}

	// NON-VACUITY / direction: the sign must still be rendered, or the clause
	// could satisfy every assertion above while telling an operator to look at
	// the wrong node's clock.
	ahead := fabricSkewClause(2400)
	if !strings.Contains(ahead, "ahead of") || !strings.Contains(clause, "behind") {
		t.Errorf("clause lost the skew DIRECTION: behind=%q ahead=%q", clause, ahead)
	}
}
