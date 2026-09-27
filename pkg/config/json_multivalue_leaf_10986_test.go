package config

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestFormatJSONMultiValueLeafElements_10986(t *testing.T) {
	tests := []struct {
		name string
		cfg  string
		want string
	}{
		{
			name: "bracketed multi-value leaf",
			cfg:  `system { name-server [ 8.8.8.8 8.8.4.4 ]; }`,
			want: `{"system":{"name-server":["8.8.8.8","8.8.4.4"]}}`,
		},
		{
			name: "repeated multi-value leaves accumulate elements",
			cfg:  `system { name-server [ 8.8.8.8 8.8.4.4 ]; name-server [ 1.1.1.1 1.0.0.1 ]; }`,
			want: `{"system":{"name-server":["8.8.8.8","8.8.4.4","1.1.1.1","1.0.0.1"]}}`,
		},
		{
			name: "quoted value stays grouped",
			cfg:  `system { host-name "my addr"; }`,
			want: `{"system":{"host-name":"my addr"}}`,
		},
		{
			name: "separate values stay distinct",
			cfg:  `system { host-name my addr; }`,
			want: `{"system":{"host-name":["my","addr"]}}`,
		},
		{
			name: "quoted element in a multi-value leaf stays grouped",
			cfg:  `interfaces { eth0 { unit 0 { family inet { address "my addr" 10.0.0.0/24; } } } }`,
			want: `{"interfaces":{"eth0":{"unit":{"0":{"family":{"inet":{"address":["my addr","10.0.0.0/24"]}}}}}}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree, parseErrors := NewParser(tt.cfg).Parse()
			if len(parseErrors) != 0 {
				t.Fatalf("parse: %v", parseErrors)
			}

			var got, want interface{}
			if err := json.Unmarshal([]byte(tree.FormatJSON()), &got); err != nil {
				t.Fatalf("FormatJSON produced invalid JSON: %v", err)
			}
			if err := json.Unmarshal([]byte(tt.want), &want); err != nil {
				t.Fatalf("invalid expected JSON: %v", err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("FormatJSON grouped leaf values incorrectly:\n got: %v\nwant: %v", got, want)
			}
		})
	}
}
