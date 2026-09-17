package main

import "testing"

// #4825: cmd/xpfd had arg-parsing tests (parseUpgradeArgs #4869, the #5322
// leftover-arg guards, gcProtectionForPublish #4876, buildUpgradeSystem #5286)
// but the TOP-LEVEL subcommand DISPATCH decision — which subcommand main()
// selects for a given argv — lived inline in main() reading os.Args and was
// never unit-testable (every branch calls os.Exit or a real side-effecting
// handler). classifyCommand is the extracted routing SSOT main() switches on;
// these tests pin the routing so a mis-route (e.g. a typo'd operational verb
// booting a second daemon, or upgrade routed to the wrong handler) is RED.

// TestClassifyCommand pins the top-level `xpfd` subcommand routing decision.
func TestClassifyCommand(t *testing.T) {
	tests := []struct {
		name string
		argv []string
		want xpfdCommand
	}{
		// argv[0] is the program name; the subcommand is argv[1].
		{"no args runs daemon", []string{"xpfd"}, cmdDaemon},
		{"nil argv runs daemon", nil, cmdDaemon},
		{"version", []string{"xpfd", "version"}, cmdVersion},
		{"protocol-versions", []string{"xpfd", "protocol-versions"}, cmdProtocolVersions},
		{"capability-check", []string{"xpfd", "--capability-check"}, cmdCapabilityCheck},
		{"cleanup", []string{"xpfd", "cleanup"}, cmdCleanup},
		{"cleanup with stray operand still routes to cleanup", []string{"xpfd", "cleanup", "oops"}, cmdCleanup},
		{"upgrade", []string{"xpfd", "upgrade"}, cmdUpgrade},
		{"upgrade rolling", []string{"xpfd", "upgrade", "--rolling"}, cmdUpgrade},
		{"upgrade kernel routes top-level to upgrade", []string{"xpfd", "upgrade", "kernel", "arm", "6.18.0"}, cmdUpgrade},
		{"seed-runtime", []string{"xpfd", "seed-runtime"}, cmdSeedRuntime},
		{"publish-generation", []string{"xpfd", "publish-generation"}, cmdPublishGeneration},
		{"verify-dataplane", []string{"xpfd", "verify-dataplane"}, cmdVerifyDataplane},
		{"check-config", []string{"xpfd", "check-config", "/etc/xpf/xpf.conf"}, cmdCheckConfig},
		{"unknown positional verb", []string{"xpfd", "show"}, cmdUnknown},
		{"unknown positional verb with args", []string{"xpfd", "request", "system", "reboot"}, cmdUnknown},
		{"leading-dash flag is daemon", []string{"xpfd", "--config", "/tmp/x.conf"}, cmdDaemon},
		{"single-dash flag is daemon", []string{"xpfd", "-debug"}, cmdDaemon},
		{"debug before cleanup stays daemon", []string{"xpfd", "--debug", "cleanup"}, cmdDaemon},
		{"config before version stays daemon", []string{"xpfd", "--config", "/tmp/xpf.conf", "version"}, cmdDaemon},
		{"no-dataplane before show stays daemon", []string{"xpfd", "--no-dataplane", "show", "system"}, cmdDaemon},
		{"terminator before cleanup stays daemon", []string{"xpfd", "--", "cleanup"}, cmdDaemon},
		{"empty first token is daemon", []string{"xpfd", ""}, cmdDaemon},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyCommand(tt.argv); got != tt.want {
				t.Fatalf("classifyCommand(%q) = %d, want %d", tt.argv, got, tt.want)
			}
		})
	}
}

// TestUpgradeArgsSelectKernel pins the second-level `xpfd upgrade` route:
// only a leading "kernel" operand selects the #1930 kernel channel; everything
// else (including the dash-less "rolling" typo) stays on the #1917 binary
// cut-over path. This decision was previously inline in runUpgradeSubcommand
// (untestable — the function calls os.Exit and builds a real runner).
func TestUpgradeArgsSelectKernel(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{"kernel arm", []string{"kernel", "arm", "6.18.0"}, true},
		{"kernel bare", []string{"kernel"}, true},
		{"empty is binary cut", nil, false},
		{"rolling flag is binary cut", []string{"--rolling"}, false},
		{"dashless rolling typo is binary cut", []string{"rolling"}, false},
		{"kernel not first is binary cut", []string{"--rolling", "kernel"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := upgradeArgsSelectKernel(tt.args); got != tt.want {
				t.Fatalf("upgradeArgsSelectKernel(%q) = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}
