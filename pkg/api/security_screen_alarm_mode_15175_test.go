package api

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

// #15175: REST GET /api/v1/security/screen must expose alarm_without_drop.
func TestScreenHandlerAlarmWithoutDrop15175(t *testing.T) {
	s := &Server{store: maximalScreenStore(t)}
	s.store.ActiveConfig().Security.Screen["max"].AlarmWithoutDrop = true
	rr := httptest.NewRecorder()
	s.screenHandler(rr, httptest.NewRequest("GET", "/api/v1/security/screen", nil))
	var resp struct {
		Success bool         `json:"success"`
		Data    []ScreenInfo `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, rr.Body.String())
	}
	for _, si := range resp.Data {
		if si.Name == "max" && !si.AlarmWithoutDrop {
			t.Fatalf("max must carry alarm_without_drop: %+v", si)
		}
		if si.Name == "max" {
			return
		}
	}
	t.Fatalf("max not found: %s", rr.Body.String())
}
