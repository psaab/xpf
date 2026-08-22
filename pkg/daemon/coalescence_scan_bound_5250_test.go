// #5250 (A7-b1 F1): parseEthtoolCoalesce scanned `ethtool -c` output with a
// default bufio.Scanner — a 64 KiB line cap and no Err() check. A single
// over-long line silently ENDED the scan, so every field after it read as
// absent: the live/desired comparison then decided "mismatch" from a partial
// parse and rewrote coalescence on the NIC at every commit. The scanner now
// carries a 1 MiB line ceiling, and a scan error reports parsed=false so the
// caller takes its documented fail-safe (write blindly) instead of comparing
// against half-read values.
//
// FAIL-ON-REVERT: drop the scanner.Buffer call and the first test goes RED
// (rx/tx read 0 because the scan stopped at the long line). Drop the
// scanner.Err() check and the second goes RED (a truncated parse is reported
// as a successful one).
package daemon

import (
	"strings"
	"testing"
)

func TestParseEthtoolCoalesceLongLine_5250(t *testing.T) {
	// A driver line longer than the 64 KiB default cap, with the fields we
	// care about AFTER it.
	long := "sample-interval-comment: " + strings.Repeat("x", 200*1024)
	out := "Coalesce parameters for ge-0-0-1:\n" +
		"Adaptive RX: on  TX: on\n" +
		long + "\n" +
		"rx-usecs: 8\n" +
		"tx-usecs: 9\n"

	rx, tx, aRX, aTX, parsed := parseEthtoolCoalesce([]byte(out))
	if !parsed {
		t.Fatal("parsed = false, want true (the fields after the long line must still be read)")
	}
	if rx != 8 || tx != 9 {
		t.Fatalf("rx-usecs/tx-usecs = %d/%d, want 8/9 — the scan stopped at the over-long line and read a PARTIAL result", rx, tx)
	}
	if !aRX || !aTX {
		t.Fatalf("adaptive rx/tx = %v/%v, want true/true", aRX, aTX)
	}
}

func TestParseEthtoolCoalesceScanErrorFailsSafe_5250(t *testing.T) {
	// Past the 1 MiB ceiling the scan genuinely errors. The fail-safe is
	// parsed=false ("probe unparseable, write blindly"), NOT a confident
	// partial result the caller would compare against.
	huge := strings.Repeat("y", (1<<20)+16)
	out := "Coalesce parameters for ge-0-0-1:\n" +
		"Adaptive RX: on  TX: on\n" +
		"rx-usecs: 8\n" +
		huge + "\n" +
		"tx-usecs: 9\n"

	rx, tx, aRX, aTX, parsed := parseEthtoolCoalesce([]byte(out))
	if parsed {
		t.Fatalf("parsed = true (rx=%d tx=%d adaptive=%v/%v) on a scan error, want false — a truncated read must not be reported as a successful parse",
			rx, tx, aRX, aTX)
	}
	if rx != 0 || tx != 0 || aRX || aTX {
		t.Fatalf("scan-error return = (%d, %d, %v, %v), want all zero values", rx, tx, aRX, aTX)
	}
}
