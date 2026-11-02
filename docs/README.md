# xpf documentation index

Start with the top-level [`../README.md`](../README.md) for getting
started (install/run via the `.deb`, an incus appliance image, or
KVM/QEMU/libvirt). This index points at the focused reference and design
docs.

## Getting started / operating

- [`install-images.md`](install-images.md) — appliance image bake,
  first-boot contract, credentials, upgrades, recovery.
- [`deploy-quickstart.md`](deploy-quickstart.md) — the positional naming
  contract and the YAML deployer (`scripts/deploy/xpf-deploy.py`),
  standalone + HA, incus + libvirt, SR-IOV/passthrough.
  ([`../examples/deploy/README.md`](../examples/deploy/README.md) is the
  full reference.)
- [`image-validation.md`](image-validation.md) — image validation runbook.

## Reference

- [`architecture.md`](architecture.md) — control plane + dataplane
  architecture, key design patterns, code layout.
- [`feature-coverage.md`](feature-coverage.md) — full feature matrix +
  userspace dataplane capability/admission boundary.
- [`network-topology.md`](network-topology.md) — test-VM and HA-cluster
  interface maps.
- [`test_env.md`](test_env.md) — test topology and validation steps.
- [`critical-patterns.md`](critical-patterns.md) — project-specific
  gotchas (byte order, struct alignment, BPF verifier, SR-IOV/XDP,
  interface management, HA timing).
- [`config-schema.md`](config-schema.md) — config-mode set/delete grammar
  and how to add a typed leaf.
- [`feature-gaps.md`](feature-gaps.md) / [`vsrx-gaps.md`](vsrx-gaps.md) —
  vSRX feature parity tracking.

## Dataplane (userspace AF_XDP)

- [`userspace-dataplane-architecture.md`](userspace-dataplane-architecture.md)
  — comprehensive AF_XDP dataplane architecture.
- [`userspace-debug-map.md`](userspace-debug-map.md) — active
  file/function map for forwarding and debugging.
- [`userspace-dataplane-gaps.md`](userspace-dataplane-gaps.md) — current
  capability/admission boundary.
- [`userspace-dnat-plan.md`](userspace-dnat-plan.md) — destination NAT
  implementation plan for the userspace dataplane.
- [`xdp-io-uring-userspace-dataplane.md`](xdp-io-uring-userspace-dataplane.md)
  — original userspace dataplane design.
- [`shared-umem-plan.md`](shared-umem-plan.md) — cross-NIC shared UMEM
  design.

## High availability

- [`sync-protocol.md`](sync-protocol.md) — cluster session-sync wire
  protocol and algorithms.
- [`session-sync-architecture.md`](session-sync-architecture.md) /
  [`session-sync-design.md`](session-sync-design.md) — session sync
  design.
- [`fabric-cross-chassis-fwd.md`](fabric-cross-chassis-fwd.md) — fabric
  link cross-chassis forwarding.
- [`in-place-upgrade.md`](in-place-upgrade.md) — in-service upgrade.
- [`userspace-ha-validation.md`](userspace-ha-validation.md) — HA
  failover validation procedures.
- `ha-cluster-userspace.conf` — the unified HA cluster config with
  `${node}` variable expansion (used by the loss userspace cluster).

## Performance & CoS

- [`userspace-perf-compare.md`](userspace-perf-compare.md) — throughput
  benchmarking methodology (bulk / elephant-flow regime).
- [`userspace-newflow-ceiling.md`](userspace-newflow-ceiling.md) —
  connection-rate (new flows/sec) harness and the per-site contention
  attribution that decides #2852 Phase-2. Measurement OWED.
- [`fairness-regimes.md`](fairness-regimes.md) — per-flow fairness
  regimes and CoV floors.
- [`cos-traffic-shaping.md`](cos-traffic-shaping.md) — class-of-service
  traffic shaping.
- [`optimizations.md`](optimizations.md) — performance profiling and
  optimization notes.

## Development & process

- [`development-workflow.md`](development-workflow.md) — plan → review →
  code → review → merge.
- [`engineering-style.md`](engineering-style.md) — coding/review
  discipline, hot-path rules, review severity.
- [`close-all-issues-plan.md`](close-all-issues-plan.md) — the active
  drive-to-zero plan for the open-issue backlog: triple hostile
  review (GPT-6.1 Sol, GLM-5.3, Kimi K3.1 Pro), parallel builds, and
  blocking loss/tcp/udp cluster gates for every merge.
- [`ci-gate-contract.md`](ci-gate-contract.md) — what ordinary CI runs and
  which packet-level gates remain manual.
- [`testing-procedures.md`](testing-procedures.md) /
  [`testing.md`](testing.md) — test categories and procedures.
- [`firewall-validation-harness-design.md`](firewall-validation-harness-design.md)
  — comprehensive dataplane firewall test & failure injection harness design.
- [`phases.md`](phases.md) — development phase history.
- [`bugs.md`](bugs.md) — bug tracker with root-cause analysis.

## CLI reference

- [`junos-cli-reference.md`](junos-cli-reference.md) — operational CLI
  reference.
- [`junos-config-display-reference.md`](junos-config-display-reference.md)
  — config display reference.
