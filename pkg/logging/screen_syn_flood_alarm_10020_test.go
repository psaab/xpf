package logging

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// TestScreenSynFloodAlarmLockstepWithRust_10020 is the #10020 cross-language
// contract: Rust userspace-dp/src/afxdp/event_emit.rs emits
// SCREEN_SYN_FLOOD_ALARM = 1 << 20 ("syn-flood-alarm", #3315 log-only alarm on
// the screen event frame); both Go consumers must decode it with the same bit
// and the display name "SYN flood alarm".
//
// The test parses the Rust source (like TestDefaultPolicySentinelLockstepWithRust)
// so a one-sided change on either side fails here — a hard-coded Go-only
// assertion would stay green if Rust drifted.
func TestScreenSynFloodAlarmLockstepWithRust_10020(t *testing.T) {
	// pkg/logging -> repo root is ../../
	src := filepath.Join("..", "..", "userspace-dp", "src", "afxdp", "event_emit.rs")
	body, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read %s: %v", src, err)
	}
	// const SCREEN_SYN_FLOOD_ALARM: u32 = 1 << 20;
	re := regexp.MustCompile(`(?m)const\s+SCREEN_SYN_FLOOD_ALARM\s*:\s*u32\s*=\s*1\s*<<\s*([0-9]+)\s*;`)
	m := re.FindSubmatch(body)
	if m == nil {
		t.Fatalf("could not find SCREEN_SYN_FLOOD_ALARM in %s", src)
	}
	shift, err := strconv.Atoi(string(m[1]))
	if err != nil {
		t.Fatalf("invalid SCREEN_SYN_FLOOD_ALARM shift %q: %v", string(m[1]), err)
	}
	if shift != 20 {
		t.Fatalf("Rust SCREEN_SYN_FLOOD_ALARM shift = %d, want 20", shift)
	}
	rustBit := uint32(1) << uint(shift)
	if !strings.Contains(string(body), `"syn-flood-alarm" => SCREEN_SYN_FLOOD_ALARM`) {
		t.Fatalf("%s must map \"syn-flood-alarm\" => SCREEN_SYN_FLOOD_ALARM", src)
	}

	// Both Go tables must carry the Rust bit with the display name.
	const wantName = "SYN flood alarm"
	if got := screenFlagNames[rustBit]; got != wantName {
		t.Errorf("logging screenFlagNames[1<<20] = %q, want %q (renders %q)",
			got, wantName, screenFlagName(rustBit))
	}
	if got := dataplane.ScreenFlagNames[rustBit]; got != wantName {
		t.Errorf("dataplane.ScreenFlagNames[1<<20] = %q, want %q", got, wantName)
	}
	if got := screenFlagName(rustBit); got != wantName {
		t.Errorf("screenFlagName(1<<20) = %q, want %q", got, wantName)
	}
	if len(screenFlagNames) != 21 {
		t.Errorf("len(screenFlagNames) = %d, want 21 (must cover alarm bit)", len(screenFlagNames))
	}
	if len(dataplane.ScreenFlagNames) != 21 {
		t.Errorf("len(dataplane.ScreenFlagNames) = %d, want 21 (must cover alarm bit)", len(dataplane.ScreenFlagNames))
	}
}
