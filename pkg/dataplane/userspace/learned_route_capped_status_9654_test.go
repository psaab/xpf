package userspace

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestLearnedRouteImportCappedAbsenceIsUnknown9654: the wire field is a
// pointer so absence stays distinguishable from false. A helper that omits the
// key has no live worker or predates the field; it must decode as nil, never
// as a confident "not capped".
func TestLearnedRouteImportCappedAbsenceIsUnknown9654(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want *bool
	}{
		{"key absent (no live worker, or an older helper)", `{"pid":7}`, nil},
		{"explicit false", `{"learned_route_import_capped":false}`, boolPtr9654(false)},
		{"explicit true", `{"learned_route_import_capped":true}`, boolPtr9654(true)},
	} {
		var st ProcessStatus
		if err := json.Unmarshal([]byte(tc.raw), &st); err != nil {
			t.Fatalf("%s: unmarshal: %v", tc.name, err)
		}
		switch {
		case tc.want == nil && st.LearnedRouteImportCapped != nil:
			t.Errorf("%s: decoded %v, want nil (unknown)", tc.name, *st.LearnedRouteImportCapped)
		case tc.want != nil && st.LearnedRouteImportCapped == nil:
			t.Errorf("%s: decoded nil, want %v", tc.name, *tc.want)
		case tc.want != nil && *st.LearnedRouteImportCapped != *tc.want:
			t.Errorf("%s: decoded %v, want %v", tc.name, *st.LearnedRouteImportCapped, *tc.want)
		}
	}
	raw, err := json.Marshal(ProcessStatus{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "learned_route_import_capped") {
		t.Errorf("an unknown flag must be omitted on re-encode, got %s", raw)
	}
}

func boolPtr9654(v bool) *bool { return &v }
