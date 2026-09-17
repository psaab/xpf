package config

import "fmt"

// compileSections runs the P4 "section-compile dispatch" phase of config
// compilation — the ordered per-section dispatch extracted from
// compileExpanded as step 2 of the #4406 god-orchestrator decomposition
// (ps-review-011 / codex-173 #4).
//
// It iterates the root children in author order and routes each recognized
// top-level stanza to its already-extracted section compiler
// (compileSecurity / compileInterfaces / compileApplications /
// compileRoutingOptions / compileProtocols / compileRoutingInstances /
// compileFirewall / compileClassOfService / compileServices /
// compileForwardingOptions / compileSystem / compileSchedulers /
// compilePolicyOptions / compileChassis / compileEventOptions / compileSNMP /
// compileBridgeDomains), mutating the shared *Config in place. The first
// section compiler that fails wins the returned error slot; unrecognized
// stanzas are ignored here (they are gated in the P1 pre-walk).
//
// Behavior-preserving invariants (do NOT reorder relative to master): the
// iteration is over tree.Children in source order and dispatches to the SAME
// compilers in the SAME order as the inline switch it replaces — duplicate
// roots (e.g. two `security { }` blocks) still merge in author order, and the
// first compiler error is returned unchanged with its `<section>: %w` wrap.
// This phase runs AFTER the base *Config skeleton (P2) and the P3 warning
// append, and BEFORE the P5 cross-section derivations (the #4329 NodeID stamp
// and the fabric fixup), so tree must already be group-expanded and
// inactive-pruned and cfg must already carry its initialized maps. It is
// covered by the reusable golden-output gate in compile_golden_4406_test.go.
func compileSections(tree *ConfigTree, cfg *Config, opts compileOpts) error {
	for _, node := range tree.Children {
		switch node.Name() {
		case "security":
			if err := compileSecurity(node, &cfg.Security); err != nil {
				return fmt.Errorf("security: %w", err)
			}
		case "interfaces":
			if err := compileInterfaces(node, &cfg.Interfaces, opts, &cfg.Warnings); err != nil {
				return fmt.Errorf("interfaces: %w", err)
			}
		case "applications":
			if err := compileApplications(node, &cfg.Applications); err != nil {
				return fmt.Errorf("applications: %w", err)
			}
		case "routing-options":
			if err := compileRoutingOptions(node, &cfg.RoutingOptions); err != nil {
				return fmt.Errorf("routing-options: %w", err)
			}
		case "protocols":
			if err := compileProtocols(node, &cfg.Protocols); err != nil {
				return fmt.Errorf("protocols: %w", err)
			}
		case "routing-instances":
			if err := compileRoutingInstances(node, cfg); err != nil {
				return fmt.Errorf("routing-instances: %w", err)
			}
		case "firewall":
			if err := compileFirewall(node, &cfg.Firewall); err != nil {
				return fmt.Errorf("firewall: %w", err)
			}
		case "class-of-service":
			if err := compileClassOfService(node, cfg.ClassOfService, opts, &cfg.Warnings); err != nil {
				return fmt.Errorf("class-of-service: %w", err)
			}
		case "services":
			if err := compileServices(node, &cfg.Services); err != nil {
				return fmt.Errorf("services: %w", err)
			}
		case "forwarding-options":
			if err := compileForwardingOptionsWithOpts(node, &cfg.ForwardingOptions, opts, &cfg.Warnings); err != nil {
				return fmt.Errorf("forwarding-options: %w", err)
			}
		case "system":
			if err := compileSystem(node, &cfg.System, cfg, opts); err != nil {
				return fmt.Errorf("system: %w", err)
			}
		case "schedulers":
			if err := compileSchedulers(node, cfg); err != nil {
				return fmt.Errorf("schedulers: %w", err)
			}
		case "policy-options":
			if err := compilePolicyOptions(node, &cfg.PolicyOptions); err != nil {
				return fmt.Errorf("policy-options: %w", err)
			}
		case "chassis":
			if err := compileChassis(node, &cfg.Chassis); err != nil {
				return fmt.Errorf("chassis: %w", err)
			}
		case "event-options":
			if err := compileEventOptions(node, &cfg.EventOptions); err != nil {
				return fmt.Errorf("event-options: %w", err)
			}
		case "snmp":
			// Top-level snmp stanza (same format as system { snmp { ... } })
			if err := compileSNMP(node, &cfg.System, cfg, opts.lenientSNMPTrapGroup); err != nil {
				return fmt.Errorf("snmp: %w", err)
			}
		case "bridge-domains":
			if err := compileBridgeDomains(node, &cfg.BridgeDomains,
				opts.lenientBridgeDomainVlanID, &cfg.Warnings); err != nil {
				return fmt.Errorf("bridge-domains: %w", err)
			}
		}
	}
	return nil
}
