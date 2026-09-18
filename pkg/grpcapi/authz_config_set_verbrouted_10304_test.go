package grpcapi

import (
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #10304: the gRPC Set gate normalised verb-led input differently from the
// handler, allowing an anchored deny-configuration bypass.
//
// Server.Set (server_config.go) routes by leading verb:
//   - "copy "/"rename " -> handleCopyRename (two REAL endpoints, F-029)
//   - "insert "        -> handleInsert
//   - "deactivate"/"activate" (Fields[0]) -> Deactivate/ActivateFromInput
//   - everything else  -> SetFromInput (bare path or "set ...")
//
// configMutationLineFor prepended "set " unless the input started with
// "set ", so "copy <denied> to <x>" was gated as the single path
// "copy <denied> to <x>" under verb "set". An anchored deny on the real
// endpoints never matched; the handler then executed the real two-path
// copy / deactivate. Unanchored substring denies caught the joined string
// incidentally, which hid the mechanism — same shape as #9938 F-029.
//
// The gate must route verbs identically to the handler: verb-led inputs the
// handler dispatches on are returned verbatim so AuthorizeConfigMutation
// adjudicates the REAL endpoints (both, for copy/rename).

func TestSetVerbLedInputsAreGatedOnRealEndpoints10304(t *testing.T) {
	cfg := cfgCfg9154(t, "^security policies p1$", "")
	denied := []struct {
		name  string
		input string
	}{
		{"deactivate denied", "deactivate security policies p1"},
		{"activate denied", "activate security policies p1"},
		{"copy denied to tmp", "copy security policies p1 to security policies ok"},
		{"copy tmp to denied", "copy security policies ok to security policies p1"},
		{"rename denied to tmp", "rename security policies p1 to security policies ok"},
		{"rename tmp to denied", "rename security policies ok to security policies p1"},
		{"insert denied", "insert security policies p1 before ok"},
	}
	for _, tc := range denied {
		t.Run(tc.name, func(t *testing.T) {
			if err := decideConfig9154(t, cfg, "Set", &pb.SetRequest{Input: tc.input}); err == nil {
				t.Errorf("%q was ALLOWED under an ANCHORED deny; the gate must evaluate "+
					"the handler-routed real endpoints (#10304)", tc.input)
			}
		})
	}
}

func TestSetVerbLedAllowedInputsStillPass10304(t *testing.T) {
	cfg := cfgCfg9154(t, "^security policies p1$", "")
	allowed := []struct {
		name  string
		input string
	}{
		{"deactivate allowed", "deactivate security policies ok"},
		{"activate allowed", "activate security policies ok"},
		{"copy allowed to allowed", "copy security policies ok to security policies alsook"},
		{"rename allowed to allowed", "rename security policies ok to security policies alsook"},
		{"insert allowed", "insert security policies ok before alsook"},
		{"bare set path allowed", "security policies ok description x"},
		{"prefixed set path allowed", "set security policies ok description x"},
	}
	for _, tc := range allowed {
		t.Run(tc.name, func(t *testing.T) {
			if err := decideConfig9154(t, cfg, "Set", &pb.SetRequest{Input: tc.input}); err != nil {
				t.Errorf("%q was DENIED with no endpoint denied: %v (#10304)", tc.input, err)
			}
		})
	}
}

func TestSetResolverKeepsHandlerRoutedVerbs10304(t *testing.T) {
	for _, in := range []string{
		"deactivate security policies p1",
		"activate security policies p1",
		"copy security policies p1 to security policies ok",
		"rename security policies p1 to security policies ok",
		"insert security policies p1 before ok",
	} {
		got := setLine9938(t, in)
		if got != in {
			t.Errorf("Set resolver mapped %q to %q; handler-routed verbs must reach the gate verbatim (#10304)", in, got)
		}
	}
}
