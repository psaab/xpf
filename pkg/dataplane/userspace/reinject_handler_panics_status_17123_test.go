package userspace

import (
	"encoding/json"
	"reflect"
	"testing"
)

// #17123: reinject handler panics are counted on REINJECT_HANDLER_PANICS —
// dropped, not quarantined — and must reach operators via ProcessStatus.
// A json-tag drift would silently read constant 0.
func TestReinjectHandlerPanicsDecodes17123(t *testing.T) {
	const payload = `{"reinject_handler_panics":13,"server_handler_panics":3}`
	var st ProcessStatus
	if err := json.Unmarshal([]byte(payload), &st); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if st.ReinjectHandlerPanics != 13 {
		t.Errorf("ReinjectHandlerPanics = %d, want 13", st.ReinjectHandlerPanics)
	}
	if st.ServerHandlerPanics != 3 {
		t.Fatalf("control: ServerHandlerPanics = %d, want 3", st.ServerHandlerPanics)
	}
	var old ProcessStatus
	if err := json.Unmarshal([]byte(`{"server_handler_panics":3}`), &old); err != nil {
		t.Fatalf("pre-#17123 payload failed to decode: %v", err)
	}
	if old.ReinjectHandlerPanics != 0 {
		t.Errorf("absent key decoded as %d, want 0", old.ReinjectHandlerPanics)
	}
	f, ok := reflect.TypeOf(ProcessStatus{}).FieldByName("ReinjectHandlerPanics")
	if !ok {
		t.Fatal("field not found")
	}
	if got := f.Tag.Get("json"); got != "reinject_handler_panics,omitempty" {
		t.Errorf("json tag = %q, want %q", got, "reinject_handler_panics,omitempty")
	}
}
