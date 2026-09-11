CLANG ?= clang
GO ?= go
CARGO ?= $(HOME)/.cargo/bin/cargo
BINARY := xpfd
PREFIX ?= /usr/local

# Version info embedded at build time
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_TIME ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildTime=$(BUILD_TIME)

# eBPF compilation flags
.PHONY: all generate generate-userspace-xdp build-userspace-xdp build build-ctl build-userspace-dp build-userspace-dp-debug-log proto install clean test test-go test-rust test-race-dp audit-check test-connectivity test-wire-properties test-failover test-double-failover test-active-active test-stress-failover test-ha-crash test-chained-crash test-private-rg test-restart-connectivity test-harness-ledger-lib harness-compare harness-ledger-lint

all: generate build build-ctl

# Generate dataplane artifacts. After the #1476 source-removal phase of
# the #1373 eBPF retirement umbrella, the only generator step here is the
# retained Rust AF_XDP shim object embedded by userspace_xdp_rust.go.
generate:
	$(GO) generate ./pkg/dataplane/...

# Generate only the retained Rust userspace XDP shim object. The
# `generate` target above runs the same single directive; this alias
# stays for callers wired to the older name (e.g. build scripts that
# only need the shim and not full code-gen). Originally introduced as
# the #1473 source-removal canary that must not invoke legacy
# xdp_main/tc bpf2go (now permanently true post-#1476).
generate-userspace-xdp:
	$(GO) generate -run '^//go:generate bash build-userspace-xdp\.sh$$' ./pkg/dataplane

build-userspace-xdp: generate-userspace-xdp

# Build the daemon binary
build:
	CGO_ENABLED=0 $(GO) build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/xpfd

# Build the remote CLI client
build-ctl:
	CGO_ENABLED=0 $(GO) build -o cli ./cmd/cli

# #9726: build.rs re-records the linked libxdp/libbpf versions, and so relinks,
# when libxdp.a, libxdp.pc or libbpf.pc changes. Cargo compares only mtimes, so
# a replacement carrying an older mtime is missed. So every cargo run in
# build-userspace-dp, build-userspace-dp-debug-log and test-rust passes
# XPF_LINKED_LIBS_STAMP, those files' content hash from
# userspace-dp/build_support/linked-libs-stamp.sh, and build.rs re-runs when it
# changes. The script fails when it cannot resolve or read a file, and `&&`
# then fails the recipe line. A raw `cargo build` relies on mtimes alone.

# Build the userspace dataplane helper
build-userspace-dp:
	stamp=$$(sh userspace-dp/build_support/linked-libs-stamp.sh) && XPF_LINKED_LIBS_STAMP=$$stamp $(CARGO) build --manifest-path userspace-dp/Cargo.toml --release
	install -m 0755 userspace-dp/target/release/xpf-userspace-dp ./xpf-userspace-dp

# Manual build check for the diagnostic `debug-log` feature (#1678).
# The debug-log build is not the production target and is deliberately
# NOT wired into `all`/`build`/`test`, mirroring the opt-in
# `audit-check` precedent. There is no CI in this repo, so this is a
# developer convenience, not an automated gate: nothing runs it unless
# invoked. It exists so the feature build (which silently rotted until
# #1678 because nothing compiled it) can be revalidated with one
# command before a commit. Compile-only; does not install.
build-userspace-dp-debug-log:
	stamp=$$(sh userspace-dp/build_support/linked-libs-stamp.sh) && XPF_LINKED_LIBS_STAMP=$$stamp $(CARGO) build --manifest-path userspace-dp/Cargo.toml --release --features debug-log

# Generate protobuf/gRPC code
proto:
	protoc --proto_path=proto/xpf/v1 \
		--go_out=pkg/grpcapi/xpfv1 --go_opt=paths=source_relative \
		--go-grpc_out=pkg/grpcapi/xpfv1 --go-grpc_opt=paths=source_relative \
		proto/xpf/v1/xpf.proto

install: build build-ctl
	install -m 0755 $(BINARY) $(PREFIX)/sbin/$(BINARY)
	install -m 0755 cli $(PREFIX)/bin/cli

# The single pre-commit gate. `test` runs BOTH the Go suite AND the Rust
# userspace-dp cargo suite (#4006). The Rust AF_XDP dataplane is the only
# runtime forwarding path after the #1373/#1476 eBPF retirement, so a
# forwarding / CoS / NAT / session-correctness regression there must fail
# `make test`. Before #4006 this target ran only `go test ./...`, giving a
# false all-clear for the most critical code (a broken Rust dataplane test
# passed `make test` green). Each prerequisite recipe is a plain command,
# so a non-zero exit from either leg aborts the target (Make stops at the
# first failing prerequisite) — a Rust test failure now fails `make test`.
test: test-go test-rust
	@echo ""
	@echo "make test: NOT EXAMINED by this run — the XDP shim's behavioural"
	@echo "  coverage (pkg/dataplane/userspace/fragment_disposition_7494_test.go)"
	@echo "  SKIPS unprivileged. It is the ONLY behavioural coverage of the shim's"
	@echo "  control flow, and the #1864 verifier gate does not substitute: two"
	@echo "  distinct WRONG fixes both pass it. Run 'sudo make test-root' (#9052)."

# #9052 item 1: the root-capable aggregate. `test-shim-run` was a prerequisite
# of NOTHING — not of `test`, not of `selftest`, not of any ledger row — so the
# only behavioural coverage of the shim was reachable solely by someone
# remembering its name. That is the #7766 shape (a harness wired into no gate),
# and silence was the worst available option: a green `make test` looked
# identical whether the shim was covered or not.
#
# It is NOT a prerequisite of `test`, deliberately: `make test` must stay
# runnable unprivileged, and a target that fails without root would make the
# ordinary gate unusable. The remedy is the ANNOUNCEMENT above plus this named
# aggregate — the gate now says what it did not examine instead of implying it
# examined everything.
.PHONY: test-root
test-root: test-shim-run test-memlock-guards
	@echo "make test-root: the privilege-gated legs ran."
	@echo "  NOTE: some cells skip BECAUSE you are root (10 at last census)."
	@echo "  No single run examines every cell; see 'make go-skip-census'."

# #9337: the leg the 42 memlock-gated guards defer to.
#
# pkg/memlockcensus enumerates every test that goes inert without the privilege
# to create a BPF map and defers enforcement to "a privileged CI leg, gated on
# XPF_REQUIRE_MEMLOCK_GUARDS=1". THAT LEG DID NOT EXIST. `.github/` holds only
# `instructions/` — there is no CI in this repository at all — and nothing
# anywhere set the variable. 42 guards had been deferring to a name.
#
# CAP_BPF, not CAP_SYS_RESOURCE. Measured (#9337): with only the memlock rlimit
# raised, the census reported "memlock is available here — all 42 registered
# guards execute" and every guard then failed at `map create: operation not
# permitted`. A leg built to the old remedy text would have gone red with 42
# map-creation errors that look nothing like the defects the guards catch. The
# census now probes a trivial map create, so a run in that state is refused up
# front rather than mistaken for a regression.
#
# BY NAME, for the reason test-shim-run records: a `-run` predicate is a claim
# about names, and it fails silently in the only direction that matters — a
# guard whose name stops matching is not skipped-and-reported, it is invisible.
# Every registry row naming a `Test...` function must appear as a `=== RUN`
# line, and the package set is DERIVED from the registry rather than written
# down, so adding a guard in a new package cannot leave it unrun.
#
# TMPDIR is pinned to /tmp: several of these guards bind an AF_UNIX control
# socket under the temp dir, and a long TMPDIR pushes the path past the
# 108-byte sun_path limit — "bind: invalid argument", which reads like a
# dataplane defect and is not one.
.PHONY: test-memlock-guards
test-memlock-guards:
	@if [ "$$(id -u)" != "0" ]; then \
		echo "test-memlock-guards: needs CAP_BPF (BPF map creation). Re-run with sudo."; \
		echo "  CAP_SYS_RESOURCE alone is NOT enough — it raises the memlock rlimit,"; \
		echo "  so the guards stop skipping and start failing at map creation."; \
		exit 1; \
	fi
	@pkgs=$$(sed -n 's/.*File: "\([^"]*\)".*/\1/p' pkg/memlockcensus/registry.go \
		| xargs -n1 dirname | sort -u | sed 's#^#./#'); \
	if [ -z "$$pkgs" ]; then \
		echo "test-memlock-guards: derived NO packages from pkg/memlockcensus/registry.go."; \
		echo "  The row format changed and this target would have run nothing while"; \
		echo "  reporting success."; \
		exit 1; \
	fi; \
	echo "test-memlock-guards: packages $$pkgs"; \
	out=$$(TMPDIR=/tmp XPF_REQUIRE_MEMLOCK_GUARDS=1 $(GO) test -count=1 -v $$pkgs ./pkg/memlockcensus/ 2>&1); \
	status=$$?; \
	echo "$$out"; \
	missing=''; \
	for n in $$(sed -n 's/.*Test: "\(Test[A-Za-z0-9_]*\)".*/\1/p' pkg/memlockcensus/registry.go | sort -u); do \
		echo "$$out" | grep -q "^=== RUN   $$n$$" || missing="$$missing $$n"; \
	done; \
	if [ -n "$$missing" ]; then \
		echo "test-memlock-guards: these REGISTERED guards did not run:$$missing"; \
		echo "  A guard that cannot run is indistinguishable from a guard that passes."; \
		exit 1; \
	fi; \
	if [ $$status -ne 0 ]; then exit $$status; fi; \
	echo "test-memlock-guards: every registered guard executed."

# Go suite. Invocation preserved exactly from the pre-#4006 `test` target.
# #7494: behavioural coverage for the shim's own control flow, via
# BPF_PROG_TEST_RUN against the tracked object. Loading a BPF program needs
# privilege, so these cells SKIP under `make test-go` and only really run here.
# They exist because the #1864 verifier gate is a HEADROOM instrument, not a
# correctness one: two distinct WRONG implementations of the #7494 fragment fix
# both pass it, and nothing else in the tree can tell them apart.
test-shim-run:
	@if [ "$$(id -u)" != "0" ]; then \
		echo "test-shim-run: needs root (BPF program load). Re-run with sudo."; \
		exit 1; \
	fi
	# #7494/#6743-r2-N3: a `-run` predicate is a claim about the names of tests
	# that do not exist yet, and it fails SILENTLY in the only direction that
	# matters -- a cell whose name stops matching is not skipped-and-reported,
	# it is invisible. This target shipped with `TestFragment|TestNonFirstFragment`,
	# which does not match `TestV6...`, so it printed a clean 4/4 while the v6
	# cells never executed. A bare count cannot catch that either: the regex also
	# matches unrelated tests in this package (TestFilterSnapshotIsFragmentSerialized),
	# so the total is inflated by cells from other files. So the check is by NAME:
	# every `func Test...` in the file must appear as a `=== RUN` line.
	@out=$$(go test ./pkg/dataplane/userspace/ -run 'TestV6|TestFragment|TestNonFirstFragment' -v -count=1 2>&1); \
	status=$$?; \
	echo "$$out"; \
	missing=''; \
	for n in $$(grep -oE '^func Test[A-Za-z0-9_]+' pkg/dataplane/userspace/fragment_disposition_7494_test.go | sed 's/^func //'); do \
		echo "$$out" | grep -q "^=== RUN   $$n$$" || missing="$$missing $$n"; \
	done; \
	if [ -n "$$missing" ]; then \
		echo "test-shim-run: these cells exist but did NOT run:$$missing"; \
		echo "test-shim-run: the -run predicate has stopped matching them. Widen it or drop it."; \
		exit 1; \
	fi; \
	exit $$status

# #8231: opt-in machine-readable side channel for the Go gate legs. Empty by
# default, which keeps `make test-go` byte-identical to what it ran before.
GOTESTJSON ?=

test-go: test-race-dp
	# go vet gate, tree-wide (#9590): the tree is vet-clean, so any new
	# diagnostic in any package fails make test-go. It catches the #2224
	# atomic.Uint64-copy class wherever it reappears, not only in
	# pkg/flowexport. An exception must be a named, reasoned carve-out,
	# never a quiet re-narrowing of this scope.
	$(GO) vet ./...
	# #8231: truncate the side file ONCE per invocation, before the first leg.
	# The legs below APPEND (test-go has two), so without this a second
	# `make test-go GOTESTJSON=x` would attribute over the union of both runs —
	# a stale name from the previous run reads exactly like a current failure.
	# scripts/mutate.sh truncates per CELL for the same reason.
	@[ -z "$(GOTESTJSON)" ] || : > "$(GOTESTJSON)"
	# #8231: GOTESTJSON=<path> additionally APPENDS the `go test -json` event
	# stream to that file, so the mutation driver can attribute a KILLED verdict
	# to a NAME without bypassing this target and losing the vet and -race legs
	# it carries. Unset (the default) execs `go test ./...` unchanged — the
	# shared gate must not acquire a jq dependency or a new failure mode.
	bash ./scripts/go-test-json.sh "$(GOTESTJSON)" "$(GO)" ./...
	# #6626: pkg/refactoraudit MUST run uncached.
	#
	# Its hard gate (TestTouchedFileCrossedModularityThreshold) measures the
	# branch's own diff against its merge base by shelling out to
	# scripts/refactoring-audit-touched.sh. Neither the working tree nor that
	# script is a `go test` cache input, so a REAL threshold crossing changes
	# nothing the cache hashes and `./...` above returns "ok (cached)" — the
	# gate passes without running. Reproduced: a new 2004-LOC production file
	# (a genuine [REFACTOR] crossing, exactly the event this gate exists to
	# catch) returned "ok (cached)" and FAILED under -count=1.
	#
	# #6623 widened the window rather than creating it: under the old
	# byte-exact artifact compare the tracked artifact churned constantly and
	# busted the cache by accident, so a stale pass survived one commit instead
	# of many.
	#
	# Scoped to this package, not the whole suite: measured at ~10.7s uncached
	# against ~0.1s cached, which is noise on a suite that already runs
	# minutes, whereas -count=1 on ./... would forfeit caching everywhere.
	# Deliberately NOT narrowed further with -run: a name predicate silently
	# stops covering the next tree-reading test added here, which is the
	# #6743 r2-N3 lesson recorded in this package's own doc.go.
	bash ./scripts/go-test-json.sh "$(GOTESTJSON)" "$(GO)" -count=1 ./pkg/refactoraudit/

# #2114 scoped race gate: the dataplane-cell publication races
# (bootstrap-exit clear vs sampler/watcher/confirm-timer readers) and the
# A3 armed-gate registry races are only visible under -race — a plain
# `go test ./...` has no race teeth, and a full-repo -race run stays out
# of scope. The named patterns cover the daemon cell tests (incl. the
# #2116 NAT pool-alarm regressions and the forwarding-status adapter) and
# the pkg/dataplane armed-gate legs.
#
# #6743 r2-N3: the pkg/daemon pattern used to be just
# 'DataplaneCell|NATPoolAlarm|ForwardingStatus|BootstrapExit', which matched
# 19 of 1118 tests and EXCLUDED every test that runs a loop goroutine
# against a concurrently emptied cell — the event-stream binders, the
# capability probes, the escape binders. A -run filter is a NAME predicate
# over a PROPERTY-defined set, so widening it once is not the whole fix:
# pkg/daemon's TestRaceGateCoversTheConcurrencyBinders parses THIS recipe
# and fails if any test in the declared concurrency-binder files stops
# matching. Keep the `-run '<pattern>'` single-quoted spelling — that canary
# reads it.
#
# #6550: the pkg/cluster leg. Before it, NO make target ran ./pkg/cluster
# under -race at all, so the cluster Monitor's concurrent-map fatal (poll
# goroutine vs UpdateGroups) and the #7257 heartbeat start/stop race were
# not races CI had failed to catch — they were races CI had no path to
# observe. The selection is the two packages' race PROBES only (they are
# ~2s combined at -count=2); pkg/cluster's non-race tests stay on the
# plain `go test ./...` leg. Keep the `-run '<pattern>'` single-quoted
# spelling here too: pkg/cluster's TestRaceGateCoversTheClusterProbes6550
# parses this line, and pkg/daemon's canary reads the FIRST -run line in
# this recipe, so this leg must stay BELOW the pkg/daemon one.
test-race-dp:
	$(GO) test -race ./pkg/daemon/ -run 'DataplaneCell|NATPoolAlarm|ForwardingStatus|BootstrapExit|RuntimeDataplaneNeverBareRootManager|EventStreamFallbackLoop|RunUserspaceEventStream|LiveDataPlane_|GRPCShowBuffers_|SystemAction_|GRPCServer_|RESTServer_|ManagementProbe|ConsoleCLIProbeWiring|FullResync|ReconcilePassUsesOneDataplaneSnapshot|ReconcileBlackholeWrappersStillReloadPerCall' -count=2
	$(GO) test -race ./pkg/dataplane/ -run 'ArmedGate|PreArm|AllConcurrentSaveNoRace|StatusPathReadRacesCompileWrite|DetachXDPIsNotSelfSerializing' -count=2
	$(GO) test -race ./pkg/cluster/ -run 'DoesNotRaceUpdateGroups6550|DoesNotHoldMuAcrossManagerCallback6550|DoesNotRaceStopHeartbeat7257|HeartbeatStartSuperseded' -count=2

# Rust userspace-dp correctness suite (#4006). userspace-dp is a
# binary-only crate (no [lib] target), so its unit tests live in the bin
# and are reached via --bins; --tests adds any tests/ integration tests.
# Run in --release, matching build-userspace-dp so compiled artifacts are
# shared rather than rebuilt.
#
#   --bins --tests         select the correctness suite. Benches are
#                          deliberately excluded: criterion's harness
#                          (harness = false) rejects libtest's
#                          --test-threads flag, so running them here would
#                          break the run. #5190: benches are NOT run by any
#                          make target or CI job, and only two of them
#                          (prefix_set_lookup, runtime_view_refresh) even
#                          emit a failing verdict — the rest print numbers
#                          for a human and always exit 0. Do not treat a
#                          `cargo bench` exit status as a perf gate.
#   -- --test-threads=1    serialize the harness. Some dataplane socket
#                          tests can wedge in __skb_wait_for_more_packets
#                          when run concurrently; single-threaded execution
#                          avoids the intermittent hang. Runtime for the
#                          full suite is a few minutes (thousands of tests)
#                          — slower than the Go suite but a real gate.
#
# A non-zero cargo exit propagates: this is a plain recipe line, so Make
# fails the target on any command that exits non-zero (no `-` prefix / no
# `|| true` swallows the failure).
#
# #6610: a `cargo check --benches` leg runs FIRST. Benches are still never
# RUN here (criterion's harness = false rejects --test-threads, and the
# numbers are for a human), but they must at least COMPILE, and compiling
# them is what evaluates their `const _: () = assert!(...)` invariants.
# That distinction is the whole point: #6610 was a runtime `attempt to add
# with overflow` in benches/snat_allocator.rs that a compile-only check
# could NOT have caught, so the fix made the invariant it violated a CONST
# assert. A compile check now catches a reintroduction of that class,
# rather than only catching a bench that stopped compiling.
#
# Cheap: cold ~2.5 min (shared with the --release artifacts below only
# partially, since this is a dev-profile check), warm ~0s.
#
# #9499 member 1: a THIRD leg makes integer overflow an executed failure
# oracle. The --release leg is the only other leg that runs tests, and a
# release build has overflow-checks OFF, so a wrap was caught only when a
# test happened to assert the exact wrapped value. This leg runs the frame,
# NAT, session and checksum tests in the default test profile, where
# overflow checks and debug assertions are on. It is filtered rather than
# whole-suite because it is a second full build; widen the filter rather
# than dropping the leg.
#
# It is not decoration: with `parsed.seq.wrapping_add(seg_len)` in
# afxdp/frame/tcp.rs mutated to `parsed.seq + seg_len`, the --release leg
# stays green and this leg fails
# reject_rst_v4_for_syn_at_seq_max_wraps_ack_to_zero_9499 with "attempt to
# add with overflow" (docs/log/9499.md). Measured on a loaded host: ~3.5 min
# cold build, ~65 s run (2489 tests).
test-rust:
	stamp=$$(sh userspace-dp/build_support/linked-libs-stamp.sh) && XPF_LINKED_LIBS_STAMP=$$stamp $(CARGO) check --manifest-path userspace-dp/Cargo.toml --benches
	stamp=$$(sh userspace-dp/build_support/linked-libs-stamp.sh) && XPF_LINKED_LIBS_STAMP=$$stamp $(CARGO) test --manifest-path userspace-dp/Cargo.toml --release \
		--bins --tests -- --test-threads=1
	stamp=$$(sh userspace-dp/build_support/linked-libs-stamp.sh) && XPF_LINKED_LIBS_STAMP=$$stamp $(CARGO) test --manifest-path userspace-dp/Cargo.toml \
		--bins --tests -- --test-threads=1 frame nat session checksum

# Standalone convenience view of the refactoring-heatmap drift (#1661
# item 8). Regenerates scripts/refactoring-audit.sh output to a temp
# file and diffs it against the committed
# docs/refactoring-audit-current.txt, printing the exact drift and the
# one-line regenerate command.
#
# NOTHING IN `make test` FAILS ON WHAT THIS TARGET REPORTS (#7253). Global
# heatmap staleness stopped being a gate: it is a repo-GLOBAL property, so
# any file crossing 1500 or 2000 LOC anywhere flipped it for every author
# on the board, and #7235, #7252 and #7254 all regenerated it inside one
# hour — #7252 was already stale when it merged. The gate that remains is
# pkg/refactoraudit's TestTouchedFileCrossedModularityThreshold, which reds
# only the author who grew a file THEY TOUCHED past a threshold and is
# derived from that branch's own diff, so it cannot go stale. Converging
# the global artifact is `make audit-refresh`'s job, not a PR author's.
#
# This target's verdict MUST agree with the suite, or the two surfaces
# teach opposite lessons and both get ignored — which is how the artifact
# came to sit stale for 21 consecutive commits (#6617). So it exits 0 on
# every kind of staleness and reserves exit 1 for a MALFORMED artifact,
# which is a real defect the suite does still fail on:
#
#   no diff                       -> up to date, exit 0
#   LOC-only (same files+tiers)   -> ADVISORY refresh, exit 0
#   a file entered/left/retiered  -> STALE, exit 0 (run `make audit-refresh`)
#   malformed rows / dead generator -> ERROR, exit 1 (the suite fails too)
#
# For a machine-readable staleness predicate — a timer deciding whether to
# refresh — use `bash scripts/refactoring-audit-refresh.sh --check`, which
# exits 1 when the artifact is behind. That is a job's question, not a
# developer's.
#
# The full `diff -u` is printed either way, so a refresh is still one
# command away when you want the numbers current.
#
# Recipe notes: Make runs the recipe in one shell without `set -e`, so
# each step's failure is handled explicitly. `trap ... EXIT` guarantees
# the temp files are removed on every exit path. The awk projection
# drops the LOC column ($$2), leaving "tier path" — the canary's
# criterion — and sorts it so row order cannot affect the verdict.
# #6937 struct-heterogeneity drift. Standalone, like audit-check, and for
# the same reason: this is a repo-GLOBAL snapshot, so making it a gate
# would flip it for every author whenever any struct anywhere crossed a
# floor (see pkg/refactoraudit/doc.go on why global freshness stopped
# being a gate). The per-struct signal is reviewable in the artifact diff.
.PHONY: audit-structs
audit-structs:
	@tmp=$$(mktemp); trap 'rm -f "$$tmp"' EXIT; \
	bash scripts/refactoring-audit-structs.sh > "$$tmp" || { \
		echo "ERROR: scripts/refactoring-audit-structs.sh failed."; exit 1; }; \
	if [ ! -s "$$tmp" ]; then \
		echo "ERROR: generator produced no rows; refusing to report an empty audit."; \
		exit 1; \
	fi; \
	if diff -u docs/refactoring-audit-structs.txt "$$tmp"; then \
		echo "struct audit: up to date ($$(wc -l < "$$tmp") rows)"; \
	else \
		echo ""; \
		echo "struct audit is stale. Regenerate with:"; \
		echo "  bash scripts/refactoring-audit-structs.sh > docs/refactoring-audit-structs.txt"; \
	fi

.PHONY: audit-check
audit-check:
	@tmp=$$(mktemp); com=$$(mktemp); gen=$$(mktemp); \
	trap 'rm -f "$$tmp" "$$com" "$$gen"' EXIT; \
	bash scripts/refactoring-audit.sh > "$$tmp" || { \
		echo "ERROR: scripts/refactoring-audit.sh failed."; \
		exit 1; \
	}; \
	for f in docs/refactoring-audit-current.txt "$$tmp"; do \
		if awk 'NF == 0 { next } \
			NF != 3 { print "  " FILENAME ": want 3 fields, got " NF ": " $$0; bad = 1; next } \
			$$1 != "[REFACTOR]" && $$1 != "[WATCH]" { print "  " FILENAME ": bad tier " $$1 ": " $$0; bad = 1; next } \
			$$2 !~ /^[0-9]+$$/ { print "  " FILENAME ": non-numeric LOC " $$2 ": " $$0; bad = 1 } \
			{ rows++ } \
			END { if (rows == 0) { print "  " FILENAME ": zero rows"; bad = 1 } exit bad }' "$$f"; then :; else \
			echo "ERROR: $$f is malformed."; \
			echo "  Validated BEFORE the diff, and on BOTH the committed artifact and the"; \
			echo "  freshly generated one. Doing it after the diff let an identically"; \
			echo "  malformed pair pass as 'up to date', and checking only the committed"; \
			echo "  side let a broken generator through — while the Go parser rejected"; \
			echo "  each. This target must not report green on input the suite refuses."; \
			exit 1; \
		fi; \
	done; \
	if diff -u docs/refactoring-audit-current.txt "$$tmp"; then \
		echo "audit-check: refactoring-audit-current.txt is up to date"; \
		exit 0; \
	fi; \
	if awk 'NF != 3 { print "  malformed row (want 3 fields, got " NF "): " $$0; bad = 1 } \
		END { exit bad }' docs/refactoring-audit-current.txt; then :; else \
		echo "ERROR: docs/refactoring-audit-current.txt has malformed rows."; \
		echo "  The Go parser requires exactly 3 fields; this target used to project"; \
		echo "  \$$1,\$$3 and silently ignore extra ones, so a hand edit could pass here"; \
		echo "  and fail the test suite."; \
		exit 1; \
	fi; \
	awk '{print $$1, $$3}' docs/refactoring-audit-current.txt | LC_ALL=C sort > "$$com"; \
	awk '{print $$1, $$3}' "$$tmp" | LC_ALL=C sort > "$$gen"; \
	if cmp -s "$$com" "$$gen"; then \
		echo "audit-check: ADVISORY — same files, same tiers; only the LOC snapshot drifted."; \
		echo "  This target compares the (tier, path) projection SORTED, so it is blind to"; \
		echo "  LOC values and to row order BY DESIGN — that is what makes LOC advisory."; \
		echo "  No test fails on this. It is NOT a statement about the whole suite:"; \
		echo "  TestHeatmapArtifactWellFormed still checks each row's LOC against its"; \
		echo "  tier band and checks generator sort order, and can fail while this target is"; \
		echo "  green. Run 'go test ./pkg/refactoraudit/' for the authoritative answer."; \
		echo "  Refresh when convenient:"; \
		echo "    make audit-refresh"; \
		exit 0; \
	fi; \
	echo "audit-check: STALE — a file entered the audit, left it, or changed tier."; \
	echo "  This is NOT a failure and no test reds on it (#7253): the heatmap is a"; \
	echo "  repo-global snapshot that any unrelated file can invalidate, so keeping it"; \
	echo "  current is a job's work, not yours. Converge it with:"; \
	echo "    make audit-refresh"; \
	echo "  If one of the files above is one YOU grew past a threshold, the test that"; \
	echo "  says so is pkg/refactoraudit.TestTouchedFileCrossedModularityThreshold,"; \
	echo "  and regenerating this artifact will not silence it."; \
	exit 0

# Periodic heatmap refresh job (#7253). Regenerates
# docs/refactoring-audit-current.txt and COMMITS it, so global freshness
# converges without interrupting a PR author who did nothing wrong. Run it
# by hand, or wire it as a timer on a master checkout; add --push there
# (the docs-only maintenance carve-out from docs/engineering-style.md
# first principle #6, the same one /sync-history takes). Refuses to commit
# an empty heatmap, and commits only the artifact path even on a dirty
# tree. Self-tested hermetically by pkg/refactoraudit's
# TestRefreshJobConvergesTheGlobalArtifact — no repo state involved.
.PHONY: audit-refresh
audit-refresh:
	bash scripts/refactoring-audit-refresh.sh

# Upgrade/install docs canary (#2001). Fails if either of the two
# misleading upgrade-install doc phrasings reappears: "symlinks into the
# staging path" in the install-layout doc (the live sbin links resolve
# THROUGH versions/current after the #1964 seed, not into staging) or
# the phantom symbol `manifest.Managed` (the managed-binary SSOT is the
# unexported `managed` slice + All()/Names()/LockstepNames()). Standalone
# by design — same posture as audit-check; NOT a dependency of `test`.
.PHONY: docs-check
docs-check:
	bash scripts/docs/check-upgrade-docs.sh

# Single entry point for the day-0/image/dist/deploy self-tests (#4210 H-19).
# Before this, scripts/image/test-grow-root.sh, test_bake_sign_ordering.py,
# scripts/dist/selftest.sh, and scripts/deploy/test_xpf_deploy_*.py all passed
# but were reachable from NO target — a regression re-introducing
# sign-before-validate (#4017) or breaking the grow-root stamp discipline
# (#2047) merged green because nothing ran them. `make selftest` discovers and
# runs them all in one fast (<a few seconds), hermetic pass (no root, no incus,
# no cluster, no network); a leg whose external tool is missing SKIPs rather
# than fails. Standalone by design — same posture as audit-check / docs-check /
# test-deploy-lib (this repo has no CI; every gate is developer-invoked). It is
# the one command to run before touching image/day-0/dist/deploy tooling, and
# the single hook a future CI would call. The incus/QEMU image boot matrix
# (scripts/image/validate.py) and the loss-cluster smokes are NOT included —
# they need a hypervisor and have their own entry points.
.PHONY: selftest
selftest:
	sh scripts/run-selftests.sh

# Reachability census over the RUNNABLE HARNESSES, one layer above `make
# selftest` (#8302). `run-selftests.sh` carries three censuses and each exists
# because a test accumulated on disk that NOTHING ran; one layer up — the
# cluster/measurement harnesses — there was no census at all, and 28 of 41
# runnable harnesses were reached by nothing. 15 of those are GATES: the #4800
# new-flow ceiling (whose own doc opens "the code ships; the measurement is
# OWED"), the #905 mouse-latency matrix, #1827 FBF steering, #1922
# commit-confirmed rollback, #2261 DHCP lease failover, #7360 persistent-NAT
# failover, #1736 WireGuard interop, and the CoS/fairness sweeps.
#
# Every runnable harness must be INVOKED by a Makefile recipe — directly or
# transitively through another invoked harness — or declared in
# test/incus/HARNESSES.unreached with a one-line reason. That list is only
# allowed to SHRINK: the census fails if an entry becomes reached, or stops
# existing, or carries no reason.
#
# A mention in a comment, a similarly-named target, a `bash -n` lint, or a bare
# relative path in a lint list does NOT count as an invocation — all four are
# real shapes in this Makefile, and all four are mutation cells in
# test/incus/harness-census-selftest.sh. Hermetic: a pure file scan, <1 s.
# Also runs inside `make selftest`.
.PHONY: harness-census test-harness-census-lib
harness-census:
	sh scripts/harness-census.sh

# Self-test the census itself. This is a gate ABOUT gates, so its failure mode
# is invisible: a census whose matcher is broken reports a CLEAN BOARD, and
# every green run of a broken census looks exactly like a healthy one. Each
# defence is therefore asserted twice — a fixture that must score UNREACHED,
# and a MUTATION of the census that must make that same fixture flip. A
# mutation that does not flip is an ESCAPE and fails this target.
test-harness-census-lib:
	bash ./test/incus/harness-census-selftest.sh

# Bake the distributable appliance image (#1879 Path C): one
# offline-built bootable root disk (REVIEWED-PIN Ubuntu server cloudimg
# base — PINNED_BASE_RELEASE + PINNED_BASE_SHA256 in bake.py, not
# auto-latest; XPF_BASE_RELEASE overrides one run; linux-generic
# kernel >= 6.18, xpfd + cli + xpf-userspace-dp + day-0 config-drive
# loader), exported as a qcow2 for libvirt/KVM AND as an incus VM
# image (metadata tarball + the same qcow2). Includes the in-guest
# verify-dataplane validation gate. See docs/install-images.md.
.PHONY: image
image:
	python3 scripts/image/bake.py

# ── signed, hosted distribution (#1924) ───────────────────────────────────
# Hosting URL + signing key are CONFIG INPUTS, never hardcoded:
#   XPF_SIGN_SECKEY    path to the minisign image secret key (sign step)
#   XPF_GPG_KEY        OpenPGP key id that signs the apt Release
#   XPF_IMAGE_BASE_URL / XPF_APT_BASE_URL   publish destinations
#   XPF_PUBLISH_CMD    backend shim: $CMD <local-dir> <dest-base-url>
.PHONY: dist-sign dist-repo dist-publish dist-selftest

# Sign already-baked dist/ image artifacts (re-emit the per-version manifest
# signature). The bake also signs inline when XPF_SIGN_SECKEY is set; this is
# the standalone re-sign / rotation entry point.
dist-sign:
	@test -n "$(XPF_SIGN_SECKEY)" || { echo "set XPF_SIGN_SECKEY=<minisign seckey path>"; exit 1; }
	@for m in dist/xpf-*.SHA256SUMS; do \
	    [ -f "$$m" ] || { echo "no dist/xpf-*.SHA256SUMS (run 'make image' first)"; exit 1; }; \
	    python3 scripts/dist/sign.py sign-manifest --manifest "$$m" \
	        --seckey "$(XPF_SIGN_SECKEY)" \
	        $$(awk '{print "dist/" $$2}' "$$m"); \
	done

# Build the signed apt repo (flat default; XPF_APT_TOOL=reprepro to opt in).
dist-repo:
	XPF_GPG_KEY="$(XPF_GPG_KEY)" sh scripts/dist/build-apt-repo.sh

# Fail-closed publish: verifies every artifact is signed, then dispatches
# XPF_PUBLISH_CMD once per URL. Refuses to upload anything unsigned.
dist-publish:
	python3 scripts/dist/publish.py --channel $${XPF_CHANNEL:-stable}

# Self-contained roundtrip gate: throwaway key -> sign -> verify ->
# tamper-fails -> flat repo build -> install.sh dry-run. No real key, no host.
dist-selftest:
	sh scripts/dist/selftest.sh

clean:
	rm -f $(BINARY) cli xpf-userspace-dp
	# Narrowed glob (#1476): the retained Rust shim object lives at
	# pkg/dataplane/userspace_xdp_bpfel.o. Cleaning it would break
	# `make build` because userspace_xdp_rust.go uses //go:embed.
	# We restrict to the legacy bpf2go `xpf*` prefix even though
	# every matching file is gone after the #1476 deletion — the
	# pattern stays as defence-in-depth against accidental
	# re-introduction by a future PR.
	rm -f pkg/dataplane/xpf*_bpfel.go pkg/dataplane/xpf*_bpfeb.go
	rm -f pkg/dataplane/xpf*_bpfel.o pkg/dataplane/xpf*_bpfeb.o
	rm -rf userspace-dp/target

# Legacy standalone test environment management (single Incus VM/container).
# The standalone instance name defaults to xpf-fw; override it for an
# ad-hoc/renamed VM with `XPF_INSTANCE=<name> make test-deploy` (#2162). The
# env var flows through to setup.sh (INSTANCE_NAME=${XPF_INSTANCE:-xpf-fw}).
.PHONY: test-env-init test-vm standalone-test-vm test-ct test-deploy test-deploy-lib test-mutate-lib test-cluster-lock-lib test-target-services-lib test-cluster-env-lib test-iperf-throughput-lib test-cos-apply-lib test-mouse-elephant-lib test-fbf-steering-lib test-host-inbound-lib test-host-inbound test-host-inbound-failover test-persistent-nat-failover test-dhcp-lease-failover test-ssh test-destroy test-status test-start test-stop test-restart test-logs test-journal test-screen-probe-lib mouse-target-up mouse-target-status mouse-target-destroy

test-env-init:
	./test/incus/setup.sh init

test-vm:
	./test/incus/setup.sh create-vm

standalone-test-vm: test-vm

test-ct:
	./test/incus/setup.sh create-ct

test-deploy: build build-ctl
	./test/incus/setup.sh deploy

# Self-test the raw-deploy reconciliation + sha-verify helpers (#2162/#2176)
# against a mocked fake VM. No incus, no cluster, no network — pure bash logic.
test-deploy-lib:
	bash ./test/incus/deploy-lib-selftest.sh

# Self-test the mutation-harness scoring library (scripts/mutate-lib.sh).
# Hermetic: fixture logs only, no repo/compiler/cluster. The cell that matters
# is the REFUSAL one -- a single-language runner scores every cross-language
# mutation as an ESCAPE, because nothing it ran could have failed, and an
# escape is a claim that the code is untested. Also pins the three verdicts
# that are neither a kill nor an escape: a build break, a -race failure (which
# emits no `--- FAIL` line at all), and a full disk (which reds NAMED tests).
test-mutate-lib:
	bash ./scripts/mutate-selftest.sh
	bash ./scripts/go-test-json-selftest.sh
	bash ./scripts/no-git-stash-selftest.sh

# Self-test the #1875 shared-cluster lock cell (with-cluster.sh contention
# matrix) and the #4020 destructive-smoke lock preamble (every reboot/
# force-stop/failover smoke script routes through the lock, and the cell
# serializes/queues/re-enters correctly). Private lock path, mocked incus —
# no cluster, no network. Run this after touching the lock or smoke wiring.
test-cluster-lock-lib:
	bash ./test/incus/with-cluster-selftest.sh
	bash ./test/incus/cluster-cell-selftest.sh
	bash ./test/incus/cluster-build-identity-selftest.sh

# Self-test the #8040 target-service preflight. Every per-class harness
# (mouse-latency, fairness, CoS best-effort contention) needs live listeners
# on 5200-5211 and 6200-6211 at the VLAN-80 target; none could create one, and
# each checked only the single port it was about to use. So a run spent a
# build, a deploy and the shared cluster lock before discovering the target was
# unprovisioned, and named one missing port out of twenty-four.
# target-services.sh is now the one place that knows that contract; this gates
# its predicate (scoped, so an unrelated class does not block a two-port smoke)
# and its diagnosis (the whole grid, every missing port named). Hermetic —
# `incus` is stubbed, no cluster.
test-target-services-lib:
	bash ./test/incus/target-services-selftest.sh

# Self-test the #6440 CoS-apply CLI-transcript gate. `apply-cos-config.sh`
# drives the Junos CLI by piping a heredoc into it; that form is a REPL that
# prints "error: ..." for a failed command, continues, and still exits 0 — so
# the phase gates verify the CLI's own success markers instead of the session
# exit status. Hermetic: mocked incus, canned transcripts; no cluster, no VM.
# Run this after touching apply-cos-config.sh or cos-apply-lib.sh. The Go half
# of the marker contract lives in cmd/cli/cos_apply_markers_6440_test.go.
test-cos-apply-lib:
	bash ./test/incus/cos-apply-lib-selftest.sh
	go test -count=1 -run 6440 ./cmd/cli/

# Self-test the #7159 mouse-latency elephant lifecycle. The defect it guards is
# a CORRUPT MEASUREMENT rather than an error: the rep script stopped its
# elephant by killing the LOCAL incus-exec client, which leaves the remote
# 90 s iperf3 running, so an early-INVALID rep handed its load to the next one
# and a whole cell voided reporting cwnd-not-settled. Hermetic -- fake iperf3
# on PATH plus an unprivileged PID namespace for the stale-client controls; no
# incus, no cluster. Run it after touching test-mouse-latency.sh.
test-mouse-elephant-lib:
	bash ./test/incus/mouse-elephant-selftest.sh
	python3 -m unittest discover -s test/incus -p 'test_mouse_latency_shell_test.py'

# Self-test the #7796 FBF DSCP ip-rule apply leg. The defect this guards is
# INVISIBLE to a compile-side test: the pre-fix code built a well-formed
# netlink.Rule that every build-side assertion accepted, and the failure was
# entirely in what the KERNEL took — FRA_TOS is masked to IPTOS_TOS_MASK, so a
# DSCP shifted into a TOS byte was rejected with EINVAL from dscp 8 up and the
# whole commit failed.
#
# These cells SKIP without CAP_NET_ADMIN, which means `make test-go` does NOT
# exercise them. That is exactly the shape that lets an apply-leg regression sit
# green forever, so this target runs them under `unshare -rn` where they
# actually execute. It SKIPS as a whole (not fails) where user namespaces are
# unavailable, matching the other tool-gated legs.
# Single-sourced with the `make selftest` leg: both run the SAME script, so the
# target and the aggregate cannot drift into testing different things.
test-rule-dscp-lib:
	sh ./test/routing/selftest-rule-dscp_7796.sh

# Self-test the #6936 FBF two-upstream steering verdicts. The defect this
# guards is a NEGATIVE CELL THAT FAILS TO A HEALTHY VALUE: the main-table
# pollution check counted matches, so "no leak" and "the probe returned
# nothing" both scored 0 = PASS, and the cell certified an absence it had
# never looked for. The verdict is now TOTAL, and the selftest table carries
# the middle (probe-blind) row that is the only way to see the difference.
# Hermetic — no cluster. The Go half (every test/incus script that commits
# config through the piped CLI must use the #6440 marker gate) is
# cmd/cli/cos_apply_markers_6440_test.go.
test-fbf-steering-lib:
	bash ./test/incus/fbf-steering-selftest.sh
	go test -count=1 -run 6440 ./cmd/cli/

# Self-test the #6936 on-wire host-inbound verdicts. The defect class it
# guards is the one a probe CANNOT see: a probe never observes a deny, it
# observes SILENCE, and "the firewall dropped it" and "my prober never reached
# the firewall" are the same reading. So every DENY cell is scored against a
# positive control at the SAME address in the SAME run, and the selftest table
# carries the middle row (same expectation, same observation, only the control
# differs) that is the only way to tell those two apart. Hermetic — no
# cluster, no incus, no network. Run this after touching
# test-host-inbound.sh or host-inbound-lib.sh.
#
# The prober leg was `py_compile` — a SYNTAX check, which an unresolvable
# import, a renamed exception class or a changed output format all pass while
# failing later on the cluster. It now RUNS the prober: the OPEN/REFUSED/
# TIMEOUT/ERROR mapping (the discriminator the whole smoke rests on, and the one
# thing the shell lib structurally cannot see — it only ever sees the word the
# prober printed) and the positional output format that host-inbound-lib.sh
# awk-parses. Hermetic: loopback only, ~0.15s.
#
# cluster-cell-selftest.sh is included because the smoke's #1875 lock wiring is
# asserted there (its destructive-script detector picks up test-host-inbound.sh
# automatically since #6936), so this target stands alone rather than relying
# on whoever changes the smoke also remembering to run test-cluster-lock-lib.
test-host-inbound-lib:
	bash ./test/incus/host-inbound-selftest.sh
	python3 -m unittest discover -s test/incus -p 'host_inbound_probe_test.py'
	bash ./test/incus/cluster-cell-selftest.sh

# #7766: the #4555 shim/userspace IPv6 extension-header parity ACCEPTANCE
# harness. It mutates userspace-xdp/src/ipv6_ext_walk.rs — advance arithmetic,
# post-advance revalidation, the Fragment read length, MAX_EXT_HDRS — and
# requires the parity guards in tests_shim_ext_parity.rs to RED on every one,
# with two negative controls that must stay green.
#
# BEFORE THIS TARGET IT WAS RUN BY NOBODY: cited by three source comments as
# proof the guards fire, invoked only when a human typed the path. It had
# rotted accordingly — every mutation target still expected the pre-`unsafe {}`
# spelling of read_bytes, so the harness could not apply a single mutant. Note
# what rotted: not the assertions, which are correct, but the FIXTURES. An
# unrun guard does not decay toward wrongness, it decays toward
# INAPPLICABILITY, and running it is what keeps its targets matched to the code
# they mutate. That is the argument for this target, stronger than "nobody runs
# it".
#
# ~40 MINUTES ON AN IDLE BOX, and measured at 59+ when other gates are running
# — it rebuilds the shim once per mutant across ~20 rows, so it is entirely at
# the mercy of available CPU. If it seems to have hung, check for a running
# rustc before killing it. It is
# therefore in NO aggregate, deliberately. Folding it into `make selftest`
# (billed "fast hermetic") or a pre-push target would technically satisfy
# #7766 and practically undo it — a 40-minute leg does not get run, it gets the
# whole target avoided, costing everything else that target catches. Run it
# when ipv6_ext_walk.rs or the parity guards change.
test-shim-ext-parity-lib:
	bash ./test/mutation/shim-ext-parity-acceptance.sh

# #8136: the WHOLE test/incus Python suite. Before this, the only target that
# ran any of it passed a LITERAL filename as the discovery pattern, so 1 of 21
# files ran and the other 20 were executed by nothing — long enough for real
# drift to accumulate in them unnoticed.
#
# Two separate mechanisms made a file contribute ZERO tests while the run
# reported success, which is why harness_discovery_test.py exists alongside the
# widened pattern: a hyphenated filename is not an importable module name and is
# skipped without error, and a pytest-style module has no TestCase so nothing is
# collected from it. Widening the pattern alone would have left both live for
# the next file that lands.
#
# Hermetic: no cluster, no incus. The cases that invoke a real harness against a
# fake target set SKIP_TARGET_PRECHECK, since #8040's live target-service probe
# is inapplicable by construction there.
test-incus-lib:
	python3 -m unittest discover -s test/incus -p '*_test.py'

# The on-wire host-inbound smoke itself (#6936 — needs the loss userspace
# cluster). Reads the already-committed config, derives its probe targets from
# it, and commits NOTHING. `--with-failover` adds the HA leg, which moves RG1
# and RG2 to the peer and back under the #1875 lock.
test-host-inbound:
	./test/incus/test-host-inbound.sh

test-host-inbound-failover:
	./test/incus/test-host-inbound.sh --with-failover

# Self-test the shared cluster-env resolver (#5024): the HA/failover
# smoke scripts read $FW0/$FW1/$CLUSTER_LAN_HOST, which cluster-env.sh
# derives from each env's VM0/VM1/LAN_HOST and remote-qualifies with
# INCUS_REMOTE (including bare caller overrides). Hermetic — sources
# cluster-env.sh in an `env -i` subshell; no incus, cluster, or network.
# Run this after touching cluster-env.sh or a cluster *.env file.
test-cluster-env-lib:
	bash ./test/incus/cluster-env-selftest.sh

# Self-test the #6897 iperf3 throughput parse + verdict used by
# test-failover.sh. The defect it guards is a MISSING CELL, not a wrong
# number: the old inline parse matched only "Gbits", so a sub-Gbit run
# matched neither the pass nor the fail branch and the gate emitted nothing
# while still summarising "0 failed". Hermetic — sources the lib and feeds it
# literal [SUM] lines; no incus, cluster, network or iperf3.
# Run this after touching test-failover.sh's throughput cell.
# Self-test the #8302 harness result ledger: the adapter table that maps each
# tool's verdict vocabulary onto PASS/FAIL/VOID, the emitter's refusals, the
# band comparator, and the MUTATION cells over the comparator itself.
#
# The mutation leg is the one that matters. A comparator with a broken band is
# indistinguishable from a healthy one on every green run, and a loop is green
# almost always -- only a mutation can see it. Hermetic; no cluster, no lock.
# Census over `#[ignore]`d Rust cells (#8352). Every #[ignore] must carry a
# reason that DECLARES its kind -- `MEASUREMENT: ...` (stays ignored) or
# `#<issue>: ...` (comes back when that issue closes). With `gh` available it
# also asserts every named issue is still OPEN, so closing the issue reds this
# and whoever closed it must un-ignore the cell.
.PHONY: ignored-cell-census test-ignored-cell-census-lib go-skip-census test-go-skip-census-lib
ignored-cell-census:
	sh scripts/ignored-cell-census.sh --check-issues

# #9052 item 4: the census over Go test SKIPS — the missing sibling of the
# three that already exist (Rust `#[ignore]` above, shell harnesses in
# harness-census, python in run-selftests). `go test ./...` prints `ok` for a
# package whose cells all skipped: the summary line for "everything passed" and
# "nothing ran" is byte-identical, and no leg passes -v.
go-skip-census:
	sh scripts/go-skip-census.sh

test-go-skip-census-lib:
	bash ./test/incus/go-skip-census-selftest.sh

test-ignored-cell-census-lib:
	bash ./test/incus/ignored-cell-census-selftest.sh

test-harness-ledger-lib:
	@bash ./test/incus/harness-result-selftest.sh
	@bash ./test/incus/harness-ledger-mutation-selftest.sh
	@python3 -m unittest discover -s test/incus -p ledger_compare_test.py

# Compare the newest run of GATE against the band over the last K>=3 green runs
# at the same env. Exit 0 = within band / improved, 1 = regression or a FAIL
# row, 2 = VOID / NO-BASELINE (undetermined -- NOT a pass).
#   make harness-compare GATE=test-failover [ENV=loss-userspace-cluster]
harness-compare:
	@test -n "$(GATE)" || { echo "usage: make harness-compare GATE=<gate> [ENV=<env>]" >&2; exit 2; }
	@python3 ./test/incus/ledger_compare.py --gate $(GATE) $(if $(ENV),--env $(ENV),)

# Lint every row in the tracked ledger. FAILS on a zero-row ledger and names
# the first unparseable line, so a committed conflict marker is a red gate
# rather than silent corruption. Also runs as a leg of `make selftest`.
harness-ledger-lint:
	@python3 ./test/incus/ledger_compare.py --lint

test-iperf-throughput-lib:
	bash ./test/incus/iperf-throughput-selftest.sh

# Self-test the #8336 crafted-frame screen-probe analysis layer: the function
# that turns an armed-state flag plus two counter sample pairs into DROPPED /
# PASSED / VOID. The defect it guards is the one that produced the issue --
# two attempts at reproducing #8298 on the cluster came back with a flat
# aggregate counter and NO verdict, and a flat number with no verdict reads as
# "we found nothing" when the truth was "we measured nothing".
#
# So the load-bearing properties are TOTALITY (every input class yields exactly
# one verdict, including short argument lists) and ORDERING (a flat witness is
# VOID and must be decided BEFORE the subject, or a frame that never arrived
# reports as one that was permitted). Hermetic -- literal counter samples only;
# no incus, cluster, network or crafted frames.
test-screen-probe-lib:
	bash ./test/incus/screen-probe-selftest.sh

# #8259: provision the SECOND VLAN-80 target, so a mouse-latency verdict can be
# ATTRIBUTED.
#
# Mice and elephants both terminated on 172.16.80.200, so the loaded cell added
# the elephants' offered load to the host whose service time is inside every
# mouse sample — and #8467 made the gate return VOID-NOT-ATTRIBUTABLE rather
# than a PASS or FAIL it could not support. The blocker was never the check: the
# standing target is external lab hardware with no management path, and the
# firewall's WAN neighbour table held exactly two entries, so there was nowhere
# to move a flow to. `up` creates a third — an incus container on an SR-IOV VF
# tagged into VLAN 80, running target-services.sh's own grid (iperf3 5200-5211,
# echo 6200-6211, port 7).
#
# Idempotent, and touches NO existing instance: it creates and reconciles one
# container. It does not need the cluster lock for that reason, and does not
# take it — a `mouse-target-up` running beside somebody's smoke changes nothing
# the smoke reads.
mouse-target-up:
	bash ./test/incus/mouse-target-setup.sh up

mouse-target-status:
	bash ./test/incus/mouse-target-setup.sh status

mouse-target-destroy:
	bash ./test/incus/mouse-target-setup.sh destroy

# Self-test the #4800 new-flow-ceiling analysis layer: the function that
# turns two helper counter snapshots into "N new flows/sec, and here is
# which synchronization site saturated". Hermetic — synthetic snapshot
# pairs only; no incus, cluster, network or helper. Also builds and unit-
# tests the connection-rate generator, which lives outside the dataplane
# workspaces so `cargo test` at the root does not reach it.
# Run this after touching newflow_ceiling_analyze.py, newflow-gen, or the
# harness's node selection (#6962 — newflow-ceiling-lib.sh + its selftest).
# #9052 item 2: the cold-path-flooder crate was reached by NOTHING — no
# Makefile recipe, no run-selftests.sh line, and not declared in
# test/incus/HARNESSES.unreached either. It sits outside both cargo workspaces
# by design, there is no root Cargo.toml, and `make test-rust` pins
# --manifest-path userspace-dp/Cargo.toml, so 44 #[test] functions were
# unreachable by construction.
#
# The wiring pattern already existed one target below, for the sibling
# out-of-workspace crate newflow-gen, with the same "lives outside the
# workspaces" reasoning. It was simply never applied here.
.PHONY: test-cold-path-flooder
test-cold-path-flooder:
	cargo test --manifest-path test/incus/cold-path-flooder/Cargo.toml

test-newflow-ceiling-lib:
	cd test/incus && python3 -m unittest newflow_ceiling_analyze_test
	cargo test --release --manifest-path test/incus/newflow-gen/Cargo.toml
	bash -n ./test/incus/newflow-ceiling-harness.sh
	bash -n ./test/incus/newflow-ceiling-lib.sh
	bash ./test/incus/newflow-ceiling-selftest.sh

test-ssh:
	./test/incus/setup.sh ssh

test-destroy:
	./test/incus/setup.sh destroy

test-status:
	./test/incus/setup.sh status

test-start:
	./test/incus/setup.sh start

test-stop:
	./test/incus/setup.sh stop

test-restart:
	./test/incus/setup.sh restart

test-logs:
	./test/incus/setup.sh logs

test-journal:
	./test/incus/setup.sh journal

# Connectivity tests (standalone + cluster, VRF-aware)
MODE ?= all
PRIVATE_RG_MODE ?= $(if $(filter all,$(MODE)),full,$(MODE))
test-connectivity:
	BPFRX_CLUSTER_ENV=$(CLUSTER_ENV) ./test/incus/harness-result.sh run \
		--gate test-connectivity --adapter ha-smoke --env $(HARNESS_ENV) --cluster \
		-- ./test/incus/test-connectivity.sh $(MODE)

# On-wire properties test (PMTUD reflection + NPTv6 checksum neutrality)
test-wire-properties:
	./test/incus/harness-result.sh run \
		--gate test-wire-properties --adapter ha-smoke --env $(HARNESS_ENV) --hermetic \
		-- ./test/incus/test-wire-properties.sh

# Cluster failover test (iperf3 through reboot — requires cluster + iperf3 server)
test-failover:
	BPFRX_CLUSTER_ENV=$(CLUSTER_ENV) ./test/incus/harness-result.sh run \
		--gate test-failover --adapter ha-smoke --env $(HARNESS_ENV) --cluster \
		-- ./test/incus/test-failover.sh

# Double failover test (crash fw0 → fw1 takes over → fw0 rejoins → crash fw1 → fw0 takes over)
test-double-failover:
	BPFRX_CLUSTER_ENV=$(CLUSTER_ENV) ./test/incus/harness-result.sh run \
		--gate test-double-failover --adapter ha-smoke --env $(HARNESS_ENV) --cluster \
		-- ./test/incus/test-double-failover.sh

# Active/active per-RG failover test (iperf3 through RG split — requires cluster + iperf3 server)
test-active-active:
	BPFRX_CLUSTER_ENV=$(CLUSTER_ENV) ./test/incus/harness-result.sh run \
		--gate test-active-active --adapter ha-smoke --env $(HARNESS_ENV) --cluster \
		-- ./test/incus/test-active-active.sh

# Rapid failover stress test (repeated failover cycles — requires cluster + iperf3 server)
test-stress-failover:
	BPFRX_CLUSTER_ENV=$(CLUSTER_ENV) ./test/incus/harness-result.sh run \
		--gate test-stress-failover --adapter ha-smoke --env $(HARNESS_ENV) --cluster \
		-- ./test/incus/test-stress-failover.sh

# Hard-crash / hung-node HA test (force-stop + daemon stop + multi-cycle — requires cluster + iperf3 server)
test-ha-crash:
	BPFRX_CLUSTER_ENV=$(CLUSTER_ENV) ./test/incus/harness-result.sh run \
		--gate test-ha-crash --adapter ha-smoke --env $(HARNESS_ENV) --cluster \
		-- ./test/incus/test-ha-crash.sh

# #9729: persistent-NAT binding survives promotion (#7360). DESTRUCTIVE and
# self-locking: applies a persistent-NAT pool on the RG0 primary, reboots it,
# and restores interface-mode SNAT on exit.
test-persistent-nat-failover:
	BPFRX_CLUSTER_ENV=$(CLUSTER_ENV) ./test/incus/harness-result.sh run \
		--gate test-persistent-nat-failover --adapter ha-smoke --env $(HARNESS_ENV) --cluster \
		-- ./test/incus/persistent-nat-failover.sh

# #9729: a Kea lease survives a hard failover (#2261). DESTRUCTIVE and
# self-locking. Needs the lab DHCP fixture (dhcp-lease-synchronization plus a
# dhcp-local-server pool); without it the preflight refuses and the row is VOID.
test-dhcp-lease-failover:
	BPFRX_CLUSTER_ENV=$(CLUSTER_ENV) ./test/incus/harness-result.sh run \
		--gate test-dhcp-lease-failover --adapter ha-smoke --env $(HARNESS_ENV) --cluster \
		-- ./test/incus/dhcp-lease-failover.sh

# Chained hard-reset failover test (fw0 crash → fw1 crash → both rejoin — requires cluster + iperf3 server)
test-chained-crash:
	BPFRX_CLUSTER_ENV=$(CLUSTER_ENV) ./test/incus/harness-result.sh run \
		--gate test-chained-crash --adapter ha-smoke --env $(HARNESS_ENV) --cluster \
		-- ./test/incus/test-chained-crash.sh

# Private RG election test (enable/disable private-rg-election, verify VRRP behavior)
test-private-rg:
	BPFRX_CLUSTER_ENV=$(CLUSTER_ENV) ./test/incus/harness-result.sh run \
		--gate test-private-rg --adapter ha-smoke --env $(HARNESS_ENV) --cluster \
		-- ./test/incus/test-private-rg.sh $(PRIVATE_RG_MODE)

# Restart connectivity regression test (verify no transient loss during daemon restart — requires cluster + iperf3 server)
test-restart-connectivity:
	BPFRX_CLUSTER_ENV=$(CLUSTER_ENV) ./test/incus/harness-result.sh run \
		--gate test-restart-connectivity --adapter ha-smoke --env $(HARNESS_ENV) --cluster \
		-- ./test/incus/test-restart-connectivity.sh

# Canonical cluster HA test environment (isolated loss userspace cluster).
# Override CLUSTER_ENV= to use cluster-setup.sh local xpf-fw0/xpf-fw1 defaults.
NODE ?= all
ifeq ($(origin CLUSTER_ENV),undefined)
ifeq ($(origin BPFRX_CLUSTER_ENV),undefined)
CLUSTER_ENV := test/incus/loss-userspace-cluster.env
else
CLUSTER_ENV := $(BPFRX_CLUSTER_ENV)
endif

# Ledger `env` label for a gate run (test/results/ledger.d/). A band is only
# comparable WITHIN one env, so this label is what keeps runs on the loss
# userspace cluster from being compared against runs on the legacy local
# cluster. It is the env file's basename, or `local-cluster` when CLUSTER_ENV
# is empty (cluster-setup.sh's local xpf-fw0/xpf-fw1 defaults).
HARNESS_ENV := $(if $(CLUSTER_ENV),$(notdir $(basename $(CLUSTER_ENV))),local-cluster)
endif
LOSS_CLUSTER_ENV ?= test/incus/loss-cluster.env
CLUSTER_SETUP = BPFRX_CLUSTER_ENV=$(CLUSTER_ENV) ./test/incus/cluster-setup.sh
LOSS_CLUSTER_SETUP = BPFRX_CLUSTER_ENV=$(LOSS_CLUSTER_ENV) ./test/incus/cluster-setup.sh
.PHONY: cluster-init cluster-create cluster-deploy cluster-destroy cluster-status cluster-ssh cluster-logs cluster-start cluster-stop cluster-restart
.PHONY: userspace-cluster-init userspace-cluster-create userspace-cluster-deploy userspace-cluster-destroy userspace-cluster-status userspace-cluster-ssh userspace-cluster-logs userspace-cluster-start userspace-cluster-stop userspace-cluster-restart

cluster-init:
	$(CLUSTER_SETUP) init

cluster-create:
	$(CLUSTER_SETUP) create

cluster-deploy: build build-ctl
	$(CLUSTER_SETUP) deploy $(NODE)

cluster-destroy:
	$(CLUSTER_SETUP) destroy

cluster-status:
	$(CLUSTER_SETUP) status

cluster-ssh:
	$(CLUSTER_SETUP) ssh $(NODE)

cluster-logs:
	$(CLUSTER_SETUP) logs $(NODE)

cluster-start:
	$(CLUSTER_SETUP) start $(NODE)

cluster-stop:
	$(CLUSTER_SETUP) stop $(NODE)

cluster-restart:
	$(CLUSTER_SETUP) restart $(NODE)

userspace-cluster-init: cluster-init
userspace-cluster-create: cluster-create
userspace-cluster-deploy: cluster-deploy
userspace-cluster-destroy: cluster-destroy
userspace-cluster-status: cluster-status
userspace-cluster-ssh: cluster-ssh
userspace-cluster-logs: cluster-logs
userspace-cluster-start: cluster-start
userspace-cluster-stop: cluster-stop
userspace-cluster-restart: cluster-restart

# Legacy remote "loss" cluster using the older xpf-fw0/xpf-fw1 instance names.
.PHONY: loss-cluster-init loss-cluster-create loss-cluster-deploy loss-cluster-destroy loss-cluster-status loss-cluster-ssh loss-cluster-logs loss-cluster-start loss-cluster-stop loss-cluster-restart

loss-cluster-init:
	$(LOSS_CLUSTER_SETUP) init

loss-cluster-create:
	$(LOSS_CLUSTER_SETUP) create

loss-cluster-deploy: build build-ctl
	$(LOSS_CLUSTER_SETUP) deploy $(NODE)

loss-cluster-destroy:
	$(LOSS_CLUSTER_SETUP) destroy

loss-cluster-status:
	$(LOSS_CLUSTER_SETUP) status

loss-cluster-ssh:
	$(LOSS_CLUSTER_SETUP) ssh $(NODE)

loss-cluster-logs:
	$(LOSS_CLUSTER_SETUP) logs $(NODE)

loss-cluster-start:
	$(LOSS_CLUSTER_SETUP) start $(NODE)

loss-cluster-stop:
	$(LOSS_CLUSTER_SETUP) stop $(NODE)

loss-cluster-restart:
	$(LOSS_CLUSTER_SETUP) restart $(NODE)

# Build the xpf Debian package (#1917 increment A). Produces ../xpf_*.deb
# and ../xpf-appliance_*.deb relative to the source tree (dpkg's default
# parent-dir output), then copies them into dist-deb/ (a staging dir OUTSIDE
# the image publish root dist/ — see DEB_OUT below).
#
# The package build delegates to `make build build-ctl build-userspace-dp`
# (see debian/rules), so it picks up the embedded #1864 shim and the
# pinned cargo helper. The changelog version is rewritten from
# `git describe` here, normalized to a Debian-policy-valid native version
# (dashes -> dots; a `-` is illegal in a native package version).
# Debian native versions MUST start with a digit and exclude `-`. The
# project's git tags are non-numeric (e.g. userspace-forwarding-ok-*),
# so synthesize 0.0.<commit-count>+g<short-sha>[.dirty] — monotonic in
# commit count, carries the exact source sha, and is policy-valid.
DEB_GIT_COUNT ?= $(shell git rev-list --count HEAD 2>/dev/null || echo 0)
DEB_GIT_SHA   ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
DEB_GIT_DIRTY ?= $(shell git diff --quiet 2>/dev/null || echo .dirty)
DEB_VERSION ?= 0.0.$(DEB_GIT_COUNT)+g$(DEB_GIT_SHA)$(DEB_GIT_DIRTY)
# DEB_OUT is a build-STAGING dir and MUST live OUTSIDE the image publish root
# `dist/` (HB165 H-5): `make image` runs `make deb` and `make dist-publish`
# uploads the WHOLE `dist/` tree to the image URL, so a deb staged under
# `dist/` would ship unsigned. publish.py's default-deny sweep now REFUSES any
# stray file under `dist/`, so debs stage in the `dist-deb/` sibling instead.
DEB_OUT ?= $(CURDIR)/dist-deb

.PHONY: deb
deb:
	@echo "==> xpf .deb version: $(DEB_VERSION)"
	@# Run the whole build inside ONE shell with a trap so the changelog
	@# version is ALWAYS restored to the committed 0.0.0 and the parent-dir
	@# build byproducts are ALWAYS removed — even on SIGINT/SIGTERM or a
	@# failed dpkg-buildpackage. (A backup FILE under debian/ would be
	@# deleted by dpkg-buildpackage's own clean phase, so re-sed instead.)
	@# The build version is derived from git at build time, not committed;
	@# only the top changelog line's version token is rewritten so the rest
	@# of the entry/trailer stays dpkg-parseable. dpkg-buildpackage writes
	@# the .deb/.changes/.buildinfo to the PARENT dir (not configurable);
	@# we keep the canonical copies in dist-deb/ and scrub the parent so it
	@# never litters the tree above the source dir (a git worktree parent).
	@# Signal traps re-raise the caught signal after cleanup (trap - SIG;
	@# kill -SIG $$) so an interrupted build returns the SIGNAL exit status,
	@# not 0. A bare `trap cleanup INT TERM` with a cleanup that returns 0
	@# would mask Ctrl-C / CI-kill as success under dash (AGY r2). The EXIT
	@# trap covers normal completion + dpkg-buildpackage failure (set -e).
	set -e; \
	  cleanup() { \
	    sed -i "1s/^xpf ([^)]*)/xpf (0.0.0)/" debian/changelog; \
	    rm -f ../xpf_$(DEB_VERSION)_*.deb ../xpf-appliance_$(DEB_VERSION)_*.deb \
	          ../xpf_$(DEB_VERSION)_*.changes ../xpf_$(DEB_VERSION)_*.buildinfo; \
	  }; \
	  trap cleanup EXIT; \
	  trap 'cleanup; trap - INT; kill -INT $$$$' INT; \
	  trap 'cleanup; trap - TERM; kill -TERM $$$$' TERM; \
	  sed -i "1s/^xpf ([^)]*)/xpf ($(DEB_VERSION))/" debian/changelog; \
	  dpkg-buildpackage -us -uc -b --no-sign; \
	  mkdir -p $(DEB_OUT); \
	  cp ../xpf_$(DEB_VERSION)_*.deb ../xpf-appliance_$(DEB_VERSION)_*.deb $(DEB_OUT)/
	@echo "==> packages in $(DEB_OUT):"
	@ls -1 $(DEB_OUT)/*.deb
