package userspace

// #9412 LOCKSTEP, Go side. The golden UPDATE frame is produced by the Rust
// encoder (`test_encode_session_update_matches_the_shared_golden_9412`), and
// this decoder must read the close class out of those exact bytes. The two
// serde keys are read from the Rust source rather than restated here.
// Limit: Contains cannot tell WHICH struct in a file declares the key. That is
// the #7188 lockstep's bound too.

import (
	"encoding/binary"
	"encoding/hex"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestSessionUpdateGoldenFrameDecodes9412(t *testing.T) {
	raw, err := os.ReadFile("testdata/session_update_frame_9412.hex")
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	b, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatalf("golden is not hex: %v", err)
	}
	// Frame header: len u32 | type u8 | reserved [5:8] | seq u64 = 16 bytes.
	if len(b) < 16 {
		t.Fatalf("golden too short: %d bytes", len(b))
	}
	if b[4] != EventTypeSessionUpdate {
		t.Fatalf("golden frame type = %d, want EventTypeSessionUpdate (%d)", b[4], EventTypeSessionUpdate)
	}
	if n := binary.LittleEndian.Uint32(b[0:4]); int(n) != len(b)-16 {
		t.Fatalf("golden payload length %d does not match %d bytes after the header", n, len(b)-16)
	}
	d, ok := decodeSessionEvent(b[16:])
	if !ok {
		t.Fatal("decodeSessionEvent rejected the golden UPDATE payload")
	}
	if d.TCPCloseClass != 2 {
		t.Fatalf("#9412: golden UPDATE decoded TCPCloseClass=%d, want 2 (TIME_WAIT)", d.TCPCloseClass)
	}
	if d.SrcPort != 12345 || d.DstPort != 80 || d.RTFlowSessionID != 0x5EED {
		t.Fatalf("golden fields misread: src=%d dst=%d id=%#x", d.SrcPort, d.DstPort, d.RTFlowSessionID)
	}
}

func TestCloseClassWireKeyLockstepWithRust9412(t *testing.T) {
	const decl = `#[serde(rename = "tcp_close_class", default)]`
	for _, c := range []struct {
		rust string
		typ  reflect.Type
	}{
		{"../../../userspace-dp/src/protocol/binding.rs", reflect.TypeOf(SessionDeltaInfo{})},
		{"../../../userspace-dp/src/protocol/control.rs", reflect.TypeOf(SessionSyncRequest{})},
	} {
		src, err := os.ReadFile(c.rust)
		if err != nil {
			t.Fatalf("read %s: %v", c.rust, err)
		}
		if !strings.Contains(string(src), decl) {
			t.Fatalf("%s no longer declares %s: the Rust wire key moved", c.rust, decl)
		}
		f, ok := c.typ.FieldByName("TCPCloseClass")
		if !ok {
			t.Fatalf("%s has no TCPCloseClass field", c.typ.Name())
		}
		if tag := strings.Split(f.Tag.Get("json"), ",")[0]; tag != "tcp_close_class" {
			t.Fatalf("%s.TCPCloseClass json tag = %q, want the Rust key tcp_close_class", c.typ.Name(), tag)
		}
	}
}
