package config

import (
	"encoding/json"
	"reflect"
	"testing"
)

// TestFormatJSONRepeatedContainers_10976 guards against nodesToJSON replacing
// repeated container maps with only the last block. Junos merges these
// containers, while repeated leaves inside merged blocks remain ordered arrays.
func TestFormatJSONRepeatedContainers_10976(t *testing.T) {
	tests := []struct {
		name string
		cfg  string
		want string
	}{
		{
			name: "duplicate match blocks preserve all constraints",
			cfg: `security {
    policies {
        from-zone trust to-zone untrust {
            policy p {
                match { source-address any; destination-address any; application junos-http; }
                then { deny; }
                match { application junos-https; }
            }
        }
    }
}`,
			want: `{"security":{"policies":{"from-zone":{"trust to-zone untrust":{"policy":[{"p":{"match":{"source-address":"any","destination-address":"any","application":["junos-http","junos-https"]},"then":{"deny":true}}}]}}}}}`,
		},
		{
			name: "duplicate then blocks preserve all actions",
			cfg: `security {
    policies {
        from-zone trust to-zone untrust {
            policy p {
                match { source-address any; destination-address any; application any; }
                then { deny; }
                then { count; }
            }
        }
    }
}`,
			want: `{"security":{"policies":{"from-zone":{"trust to-zone untrust":{"policy":[{"p":{"match":{"source-address":"any","destination-address":"any","application":"any"},"then":{"deny":true,"count":true}}}]}}}}}`,
		},
		{
			name: "duplicate zone-pair contexts preserve both policies",
			cfg: `security {
    policies {
        from-zone trust to-zone untrust {
            policy block { match { source-address any; destination-address any; application any; } then { deny; } }
        }
        from-zone trust to-zone untrust {
            policy allow { match { source-address any; destination-address any; application any; } then { permit; } }
        }
    }
}`,
			want: `{"security":{"policies":{"from-zone":{"trust to-zone untrust":{"policy":[{"block":{"match":{"source-address":"any","destination-address":"any","application":"any"},"then":{"deny":true}}},{"allow":{"match":{"source-address":"any","destination-address":"any","application":"any"},"then":{"permit":true}}}]}}}}}`,
		},
		{
			name: "split security stanzas preserve zones and policies",
			cfg: `security { zones { security-zone trust; security-zone untrust; } }
security { policies { default-policy { deny-all; } } }`,
			want: `{"security":{"zones":{"security-zone":["trust","untrust"]},"policies":{"default-policy":{"deny-all":true}}}}`,
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
				t.Fatalf("invalid expected JSON in test: %v", err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("FormatJSON lost or changed repeated containers:\n got: %s\nwant: %s", mustJSON10976(t, got), mustJSON10976(t, want))
			}
		})
	}
}

func mustJSON10976(t *testing.T, v interface{}) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal JSON value: %v", err)
	}
	return string(b)
}
