package configstore

import (
	"strings"
	"testing"
)

// #9503 on the operator commit channel: CheckText accepts `then loss-priority`
// on a three-color policer and carries the meter-only warning.
func TestCheckTextAcceptsThreeColorLossPriorityWithWarning9503(t *testing.T) {
	text := "firewall { three-color-policer pol-9503 { single-rate { committed-information-rate 1m; " +
		"committed-burst-size 15k; excess-burst-size 30k; } then { loss-priority high; } } }"
	cfg, err := CheckText(text, -1)
	if err != nil {
		t.Fatalf("CheckText refused a meter-only three-color policer: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, `three-color-policer "pol-9503"`) && strings.Contains(w, "meters only") {
			return
		}
	}
	t.Fatalf("no meter-only warning on the commit channel: %q", cfg.Warnings)
}
