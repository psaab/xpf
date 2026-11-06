# #1476 Legacy BPF Source-Removal Manifest

Status: **executed in #1476**. The deletion landed; the manifest now
records the as-shipped boundary so future PRs can verify nothing
regressed. The Delete Manifest section below points at deleted history;
the Retain Manifest section enumerates what stayed.

## Dependency Order

The removal path must land in this order:

1. #1494 canary: merge the userspace shim boundary canaries so the retained
   Rust XDP shim cannot silently grow legacy fallback behavior.
2. #1493 loader split: make userspace startup load only the retained Rust XDP
   shim and the shared AF_XDP maps it requires, without calling the legacy
   `loadAllObjects()` graph.
3. #1451 surface shrink: finish moving runtime and operator callers off the
   legacy eBPF-shaped `dataplane.DataPlane` surface, leaving no source-removal
   dependency on the root legacy manager.
4. #1476 deletion: remove the legacy BPF source, generated artifacts, and stale
   build hooks listed here.
5. #1477 final evidence: publish userspace-only validation artifacts for the
   exact #1476 deletion candidate.

## Delete Manifest

This section is **post-deletion** as of #1476 mechanical source removal:
every path enumerated below has already been removed from git in the same
PR that pruned this list. The canary tests
(`pkg/dataplane/legacy_bpf_manifest_canary_test.go`) require the list to
reference only currently-tracked files; after the deletion no legacy
sources or `xpf*_bpfel.{go,o}` pairs remain tracked and so this section
keeps only narrative pointers, not file enumerations.

### Legacy BPF Root Docs (deleted in #1476)

The former root README under bpf/ is deleted along with the source it
described. The path is kept here only as a historical narrative
pointer, not as a manifest-canary delete-list entry. (Backticks are
deliberately not used around the deleted-file path so the manifest
canary's code-span scanner does not treat it as an existing tracked
file.)


### Shared BPF Headers (deleted in #17146)

The legacy helper, NAT, and trace headers were removed along with the legacy
dataplane source in #17146. The deleted paths were bpf/headers/xpf_helpers.h,
bpf/headers/xpf_nat.h, and bpf/headers/xpf_trace.h; these are historical
narrative references, not retained files or manifest path entries.

### Legacy XDP Source (deleted in #1476)

Nine ingress XDP programs plus their README, removed in lockstep with the
bpf2go generated wrappers below. See `git log -- bpf/xdp/` for the deleted
history.

### Legacy TC Source (deleted in #1476)

Five TC egress programs plus their README, removed once #1493 confirmed
the userspace shim startup no longer references the `tc_progs` tail-call
map. See `git log -- bpf/tc/` for the deleted history.

### Generated Legacy bpf2go Artifacts (deleted in #1476)

All 14 legacy `xpf{Xdp,Tc}*_x86_bpfel.{go,o}` generated pairs were
removed alongside the source. Future PRs that re-introduce any
`pkg/dataplane/xpf*_bpfel.{go,o}` would fail the
`TestLegacyBPFRemovalManifestCoversTrackedGeneratedArtifacts` canary —
the manifest no longer lists them, so any new tracked match is a
boundary regression.

## Legacy Build Hooks (executed in #1476)

The deletion PR rewrote or removed these build hooks. The list is now
historical:

- `loader.go`: legacy bpf2go `go:generate` directives that targeted
  `bpf/xdp/*.c` and `bpf/tc/*.c` removed; only the retained
  `bash build-userspace-xdp.sh` directive remains.
- `loader_ebpf.go`: deleted entirely. The retained Rust AF_XDP shim
  loader graph (`loadUserspaceShimObjects*` and helpers) moved to a
  new `loader_userspace_shim.go` before deletion.
- `loader_stub.go`: deleted. The `//go:build ignore` placeholder that
  documented a no-generated-files build no longer has any meaning
  post-deletion.
- `Makefile`: `generate-legacy-bpf` target removed. The `generate`
  recipe header rewritten to point only at the retained shim.
  `BPF_CFLAGS` removed (no remaining target consumes it).
- `Makefile clean`: globs narrowed from `pkg/dataplane/*_bpfel.{go,o}`
  to `pkg/dataplane/xpf*_bpfel.{go,o}` so the retained
  `userspace_xdp_bpfel.o` is protected by name. Defence-in-depth
  against a future re-introduction.

(The path mentions above are intentionally inside a separate H2 so the
manifest canary's `## Delete Manifest` scanner does not treat them as
file-existence assertions.)

## Legacy Tests and Active Docs (executed in #1476)

Per the original guidance, the deletion PR rewrote only tests that
directly exercised the deleted legacy loader, generated legacy
objects, XDP/TC attach graph, or stale generation commands. Tests for
shared structs, userspace map sync, retained shim loading, and runtime
boundary canaries stayed. The non-daemon `dataplane-type ebpf`
deprecation-warning tests in `pkg/api/`, `pkg/cli/`, `pkg/grpcapi/`,
and `pkg/config/parser_system_test.go` were rewritten to assert the
new retirement-rejection sentinel, matching the DPDK reject pattern
from #1526.

Active docs and workflow references that described legacy bpf2go
generation as the normal path were rewritten. Historical plans under
`docs/archived/`, `docs/issues/`, and old `docs/pr/*` directories
keep legacy references where they are clearly historical.

## Retain Manifest

These paths are not part of the #1476 legacy source deletion:

- `userspace-xdp/`: Rust source for the retained AF_XDP entry shim.
- `pkg/dataplane/userspace_xdp_bpfel.o`: retained embedded Rust XDP shim
  object.
- `pkg/dataplane/userspace_xdp_rust.go`: retained Go embed/load wrapper for the
  Rust shim object.
- `pkg/dataplane/build-userspace-xdp.sh`: retained shim-only build script until
  a replacement generation path exists.
- `test/xsk-repro/`: AF_XDP/XSK lab tooling, not the legacy forwarding
  dataplane.
- `pkg/dataplane/userspace/`: userspace manager, map sync, status, and shim
  tests.
- `pkg/dataplane/runtime/`: runtime-facing contracts that must stay independent
  from BPF artifacts.

Retain the remaining shared headers until each shared constant, struct, and
helper dependency is either moved to a userspace-owned schema or explicitly
retired:

- `bpf/headers/xpf_common.h`
- `bpf/headers/xpf_conntrack.h`
- `bpf/headers/xpf_maps.h`
- `bpf/headers/README.md`

The remaining headers are not all dead with the XDP/TC source. The current tree
still uses or cites the common, conntrack, and maps headers for `MAX_INTERFACES`,
Go constants, userspace shim build inputs, and userspace-dp struct parity tests
(~~DPDK shared-memory parity~~ — DPDK retired #1525). A future PR may move
these definitions, but that is a separate reviewed boundary. The helper, NAT,
and trace headers were deleted in #17146 and must not be reintroduced to this
retain list.

## Proof Required Before Deletion

Before the #1476 deletion PR removes any source or generated artifact, it must
show all of the following:

- #1494 is merged and the userspace shim boundary canaries pass.
- #1493 is merged and userspace startup no longer calls `loadAllObjects()`,
  `loadXpfXdpMain()`, any legacy XDP/TC tail-call loader, or the legacy
  `xdp_main_prog`/`tc_main_prog` program-map bootstrap.
- #1451 has shrunk the root `dataplane.DataPlane` compatibility surface so API,
  gRPC, CLI, status, monitor, logging, cluster sync, and daemon runtime paths
  do not require the legacy eBPF manager. Conntrack GC already enters through
  runtime-domain session and telemetry providers.
- DPDK retired in #1525 and removed in #1527/#1528; userspace-only source
  removal coordinates with the DPDK retirement sequence so neither PR
  deletes shared definitions still required by the other in-flight chain.
- `go test ./pkg/dataplane -run 'Test.*Manifest|Test.*Boundary|Test.*UserspaceXDP' -count=1`
  passes with this manifest and the then-current canaries.
- `go generate -n -run '^//go:generate bash build-userspace-xdp\.sh$' ./pkg/dataplane`
  selects only the retained shim build.
- A post-delete `rg` scan finds no production references to deleted generated
  symbols such as `xpfXdp*`, `xpfTc*`, `loadXpfXdp*`, or `loadXpfTc*`.
- A post-delete `rg` scan finds no active workflow instruction that still
  requires legacy `bpf/xdp`, `bpf/tc`, or bpf2go generation.
- The full userspace test gate and the #1477 cluster validation bundle pass on
  the exact deletion candidate.

## Adversarial Review Checklist

Reviewers of the deletion PR should explicitly check these failure modes:

- retained shim artifacts are not included in the deletion list or removed by
  `make clean`;
- tracked generated legacy artifacts are all covered by this manifest, and no
  untracked `_bpfel`/`_bpfeb` leftovers are hiding outside Git;
- stale `go:generate`, `make generate`, `make clean`, README, and development
  workflow references are removed or rewritten;
- DPDK retirement (#1525, #1527, #1528) and userspace source removal do not
  collide on shared struct dependencies — explicit coordination between the
  two retirement chains;
- `bpf/headers/*.h` consumers have either been moved to a userspace-owned
  source of truth or are still retained intentionally; and
- historical docs remain historical, while active docs no longer describe the
  deleted legacy dataplane as the normal build or rollback path.
