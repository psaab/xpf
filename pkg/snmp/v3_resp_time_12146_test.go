// Copyright 2026 PSAAB. All rights reserved. This file is part of
// XPF. It is subject to the license terms in the LICENSE file found
// in the top-level directory of this distribution.

package snmp

import (
	"testing"
)

// withSteppedEngineTime injects a deterministic 1s tick on every engineTime()
// read: the first read returns base, and each subsequent read advances by 1.
// It restores the real clock after fn.
//
// The snmp package serves requests on a single serial goroutine and the tests
// do not run in parallel, so swapping the package var is safe (same rationale
// as the randRead seam).
func withSteppedEngineTime(t *testing.T, base int, fn func()) {
	t.Helper()
	saved := engineTimeNow
	calls := 0
	engineTimeNow = func(a *Agent) int {
		calls++
		return base + calls - 1
	}
	defer func() { engineTimeNow = saved }()
	fn()
}

// TestResponseAESIVMatchesCarriedTime12146 is the #12146 regression test.
//
// RFC 3826 §3.1.2.1 requires the AES-CFB IV to be
// boots(4) || time(4) || salt(8) where (boots, time) are the
// msgAuthoritativeEngineBoots/Time CARRIED in the message — a manager can only
// rebuild the IV from wire values. The response path read engineTime() TWICE
// per authPriv response (once for encryptAES128's IV inside encryptPDU, once
// for the USM stamp in buildV3Response). Crossing a 1s boundary between the
// two reads made the carried time = IV time + 1; the manager then built the
// wrong IV, CFB corrupted the first block, and the response was undecryptable.
//
// The stepped clock makes that rare race deterministic: IV from read #1 (T),
// header stamp from read #2 (T+1). The manager-side decoder
// (decodeV3AuthPrivResponse) decrypts with the CARRIED values only.
//
// fail-on-revert: reverting buildV3Response to two independent engineTime()
// reads fails this test (decrypt with carried T+1 yields garbage).
func TestResponseAESIVMatchesCarriedTime12146(t *testing.T) {
	a, _, _, privKey := newAuthPrivAgent(t, 7, 1000)
	reqFlags := byte(msgFlagAuth | msgFlagPriv)

	withSteppedEngineTime(t, 1000, func() {
		resp := a.buildV3Response(1, reqFlags, a.v3Users["puser"], nil, 42, errNoError, 0, nil)
		if resp == nil {
			t.Fatal("authPriv response must be built")
		}
		if !decodeV3AuthPrivResponse(t, resp, privKey) {
			t.Fatal("authPriv response MUST decrypt with its carried boots/time; " +
				"IV time != header time (engineTime stepped between reads)")
		}
	})
}

// TestResponseAESIVSteadyClock12146 guards the no-tick case: without a clock
// step the pinned-time response still round-trips (the fix must not regress
// the steady state).
func TestResponseAESIVSteadyClock12146(t *testing.T) {
	a, _, _, privKey := newAuthPrivAgent(t, 7, 1000)
	resp := a.buildV3Response(1, byte(msgFlagAuth|msgFlagPriv), a.v3Users["puser"], nil, 42, errNoError, 0, nil)
	if resp == nil {
		t.Fatal("authPriv response must be built")
	}
	if !decodeV3AuthPrivResponse(t, resp, privKey) {
		t.Fatal("authPriv response must decrypt with its carried boots/time on a steady clock")
	}
}
