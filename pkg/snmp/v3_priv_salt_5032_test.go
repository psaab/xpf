package snmp

import (
	"encoding/binary"
	"sync"
	"testing"
)

// #5032 — SNMPv3 privacy salt (msgPrivacyParameters) uniqueness.
//
// RFC 3826 §3.1.2.1/§3.3 (AES) and RFC 3414 §8.1.1.1 (DES) require the privacy
// salt to be UNIQUE per (engineBoots, key) so the derived cipher IV never
// repeats within an engine boot. The pre-#5032 code drew an INDEPENDENT random
// salt per message, which gives only birthday-bound uniqueness (a collision, and
// thus an IV reuse, becomes materially likely near 2^32 messages for the 64-bit
// salt). #5032 replaced that with a MONOTONIC 64-bit counter (Agent.nextPrivSalt)
// seeded once from crypto/rand and incremented atomically per encryption, so
// successive salts within an engine boot are guaranteed distinct.

// testPrivSalt returns a deterministic 8-byte privacy salt for building test
// SNMPv3 messages where the exact value is irrelevant (any conformant manager
// supplies a unique 8-octet msgPrivacyParameters; encrypt/decrypt only require
// the same salt on both ends). Shared by the priv-path tests in this package.
func testPrivSalt() []byte {
	return []byte{0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18}
}

// TestPrivSaltMonotonicUnique is the fail-on-revert guard for #5032. It asserts
// that N successive salts from a single agent are STRICTLY MONOTONIC (each is
// the previous value + 1) and all distinct. A monotonic counter satisfies this
// deterministically; an independent-random-draw implementation (the reverted
// behavior) fails the +1 check on the very first pair with overwhelming
// probability, so this test goes RED the instant the fix is reverted — it does
// not rely on a birthday collision to eventually appear.
func TestPrivSaltMonotonicUnique(t *testing.T) {
	a := &Agent{} // lazily seeds on first nextPrivSalt

	const N = 100000
	seen := make(map[uint64]struct{}, N)
	var prev uint64
	for i := 0; i < N; i++ {
		salt, err := a.nextPrivSalt()
		if err != nil {
			t.Fatalf("nextPrivSalt returned error at i=%d: %v", i, err)
		}
		if len(salt) != 8 {
			t.Fatalf("privacy salt must be 8 bytes, got %d at i=%d", len(salt), i)
		}
		v := binary.BigEndian.Uint64(salt)
		if _, dup := seen[v]; dup {
			t.Fatalf("privacy salt repeated at i=%d: %d (IV reuse — RFC 3826 §3.3 violated)", i, v)
		}
		seen[v] = struct{}{}
		if i > 0 && v != prev+1 {
			t.Fatalf("privacy salt not monotonic at i=%d: got %d, want %d "+
				"(reverted to independent random draws?)", i, v, prev+1)
		}
		prev = v
	}
}

// TestEncryptPDUDistinctSaltsPerMessage is the end-to-end fail-on-revert guard on
// the ACTUAL production path (buildV3Response → encryptPDU): encrypting the same
// scopedPDU under the same user N times must yield STRICTLY MONOTONIC privParams
// (each +1). Reverting encryptPDU to draw a fresh random salt per message breaks
// the +1 assertion immediately.
func TestEncryptPDUDistinctSaltsPerMessage(t *testing.T) {
	a, _, _, _ := newAuthPrivAgent(t, 5, 1000)
	user := a.v3Users["puser"]
	scoped := []byte("a scopedPDU whose bytes never change between calls")

	const N = 2000
	seen := make(map[uint64]struct{}, N)
	var prev uint64
	for i := 0; i < N; i++ {
		_, pp, err := a.encryptPDU(user, scoped, a.engineTime())
		if err != nil {
			t.Fatalf("encryptPDU error at i=%d: %v", i, err)
		}
		if len(pp) != 8 {
			t.Fatalf("privParams must be 8 bytes, got %d at i=%d", len(pp), i)
		}
		v := binary.BigEndian.Uint64(pp)
		if _, dup := seen[v]; dup {
			t.Fatalf("encryptPDU reused privParams at i=%d: %d (IV reuse)", i, v)
		}
		seen[v] = struct{}{}
		if i > 0 && v != prev+1 {
			t.Fatalf("encryptPDU privParams not monotonic at i=%d: got %d, want %d", i, v, prev+1)
		}
		prev = v
	}
}

// TestPrivSaltConcurrentUnique proves the counter is thread-safe: many goroutines
// allocating salts concurrently must never collide (the atomic increment
// guarantees global uniqueness even though per-goroutine order is interleaved).
// Run with -race to also catch a data race on the counter.
func TestPrivSaltConcurrentUnique(t *testing.T) {
	a := &Agent{}

	const goroutines, perG = 16, 5000
	all := make([][]uint64, goroutines)
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			vals := make([]uint64, perG)
			for i := 0; i < perG; i++ {
				salt, err := a.nextPrivSalt()
				if err != nil {
					// Cannot t.Fatal off the test goroutine; leave a sentinel and
					// let the aggregation below flag it (0 repeated == collision).
					vals[i] = 0
					continue
				}
				vals[i] = binary.BigEndian.Uint64(salt)
			}
			all[g] = vals
		}(g)
	}
	wg.Wait()

	seen := make(map[uint64]struct{}, goroutines*perG)
	for _, vals := range all {
		for _, v := range vals {
			if _, dup := seen[v]; dup {
				t.Fatalf("privacy salt collision under concurrency: %d "+
					"(atomic increment broken — IV reuse across concurrent encrypts)", v)
			}
			seen[v] = struct{}{}
		}
	}
	if len(seen) != goroutines*perG {
		t.Fatalf("expected %d distinct salts, got %d", goroutines*perG, len(seen))
	}
}
