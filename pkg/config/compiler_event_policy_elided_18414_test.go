package config

import (
	"reflect"
	"testing"
)

func TestEventPolicyThenChangeConfigurationElided18414(t *testing.T) {
	for _, tc := range []struct {
		name           string
		text           string
		want           []string
		wantPlantClass string
	}{
		{
			name: "issue deeply elided spelling",
			text: `event-options policy p { then change-configuration commands "set system host-name deeply-elided"; }`,
			want: []string{"set system host-name deeply-elided"},
		},
		{
			name: "single-line packed policy",
			text: `event-options { policy p { events ping_test_completed; then change-configuration commands "set system host-name packed"; } }`,
			want: []string{"set system host-name packed"},
		},
		{
			name: "already-supported braced control",
			text: `event-options { policy p { events ping_test_completed; then { change-configuration { commands "set system host-name braced"; } } } }`,
			want: []string{"set system host-name braced"},
		},
		{
			name: "packed action under braced then",
			text: `event-options { policy p { events ping_test_completed; then { change-configuration commands "set system host-name action-packed"; } } }`,
			want: []string{"set system host-name action-packed"},
		},
		{
			name: "packed then with braced action body",
			text: `event-options { policy p { events ping_test_completed; then change-configuration { commands "set system host-name body"; } } }`,
			want: []string{"set system host-name body"},
		},
		{
			name: "packed quoted command list",
			text: `event-options { policy p { events ping_test_completed; then change-configuration commands [ "set system host-name first" "delete system host-name" ]; } }`,
			want: []string{"set system host-name first", "delete system host-name"},
		},
		{
			name: "packed unquoted command",
			text: `event-options { policy p { events ping_test_completed; then change-configuration commands set system host-name unquoted; } }`,
			want: []string{"set system host-name unquoted"},
		},
		{
			name: "action with command block",
			text: `event-options { policy p { events ping_test_completed; then change-configuration { commands { "set system host-name block-a"; "set system host-name block-b"; } } } }`,
			want: []string{"set system host-name block-a", "set system host-name block-b"},
		},
		{
			name: "quoted command delimiter",
			text: `event-options { policy p { events ping_test_completed; then change-configuration commands "set system host-name \"semi;colon\""; } }`,
			want: []string{`set system host-name "semi;colon"`},
		},
		{
			name:           "packed then actions keep following statements",
			text:           `event-options { policy p { events ping_test_completed; then change-configuration commands "set system host-name first"; plant-class super-user; then change-configuration commands "delete system host-name"; } }`,
			want:           []string{"set system host-name first", "delete system host-name"},
			wantPlantClass: "super-user",
		},
		{
			name: "no command remains empty",
			text: `event-options { policy p { events ping_test_completed; then change-configuration; } }`,
			want: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(parseHierText(t, tc.text))
			if err != nil {
				t.Fatalf("strict compile: %v", err)
			}
			if len(cfg.EventOptions) != 1 {
				t.Fatalf("policies = %d, want 1", len(cfg.EventOptions))
			}
			if got := cfg.EventOptions[0].ThenCommands; !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ThenCommands = %q, want %q", got, tc.want)
			}
			if got := cfg.EventOptions[0].PlantClass; got != tc.wantPlantClass {
				t.Fatalf("PlantClass = %q, want %q", got, tc.wantPlantClass)
			}
		})
	}
}
