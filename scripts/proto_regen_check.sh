#!/bin/sh
# proto_regen_check.sh (#16195): CI-only stale-.proto gate.
#
# Regenerates the Go stubs with PINNED tools into a scratch dir and
# fails if the checked-in stubs differ -- i.e. a .proto change without
# regeneration (or a hand-edited stub) is red independently of the
# hermetic header check in proto_header_check.py. This leg needs the
# network/toolchain, so it runs only in CI (`make proto-regen-check`,
# .github/workflows/test.yml proto job); never as a local prerequisite.
#
# Pins (keep in sync with proto/README.md):
#   protoc             v3.21.12  (release zip, no `go install` path exists)
#   protoc-gen-go      v1.36.11  (== go.mod google.golang.org/protobuf)
#   protoc-gen-go-grpc v1.6.1    (grpc/cmd/protoc-gen-go-grpc submodule)
# Plugins are `go install`ed at the pinned versions above (network in
# CI; module cache locally). Override PROTOC / PROTOC_GEN_GO /
# PROTOC_GEN_GO_GRPC to supply pre-pinned binaries (used by the
# hermetic self-test; CI installs fresh).
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

PROTOC_VERSION=3.21.12
SCRATCH=${TMPDIR:-/var/worktrees/.cache/tmpdir}/xpf-proto-regen.$$
mkdir -p "$SCRATCH/bin" "$SCRATCH/out"
trap 'rm -rf "$SCRATCH"' EXIT INT TERM

# --- protoc: use $PROTOC, else PATH protoc only if it is the pinned
# version, else download the pinned release zip (CI). Locally, a wrong
# ambient protoc is a hard failure, not a silent regen with it: that
# ambient-tool red is exactly what this pinned leg exists to avoid.
if [ -n "${PROTOC:-}" ]; then
	protoc_bin=$PROTOC
elif command -v protoc >/dev/null 2>&1 && [ "$(protoc --version)" = "libprotoc $PROTOC_VERSION" ]; then
	protoc_bin=$(command -v protoc)
else
	case "$(uname -s)-$(uname -m)" in
	Linux-x86_64) asset=protoc-$PROTOC_VERSION-linux-x86_64.zip ;;
	Linux-aarch64) asset=protoc-$PROTOC_VERSION-linux-aarch_64.zip ;;
	*) echo "proto-regen-check: no pinned protoc asset for $(uname -s)-$(uname -m); set PROTOC" >&2; exit 2 ;;
	esac
	if ! command -v curl >/dev/null 2>&1 || ! command -v unzip >/dev/null 2>&1; then
		echo "proto-regen-check: need curl+unzip to fetch pinned protoc, or set PROTOC" >&2
		exit 2
	fi
	curl -fsSL -o "$SCRATCH/protoc.zip" \
		"https://github.com/protocolbuffers/protobuf/releases/download/v$PROTOC_VERSION/$asset"
	unzip -q -o "$SCRATCH/protoc.zip" -d "$SCRATCH/protoc-dist"
	protoc_bin=$SCRATCH/protoc-dist/bin/protoc
fi
[ "$("$protoc_bin" --version)" = "libprotoc $PROTOC_VERSION" ] || {
	echo "proto-regen-check: protoc is $("$protoc_bin" --version), want libprotoc $PROTOC_VERSION" >&2
	exit 1
}

# --- plugins: use overrides, else `go install` the pinned versions.
if [ -n "${PROTOC_GEN_GO:-}" ]; then
	gen_go=$PROTOC_GEN_GO
else
	GOBIN=$SCRATCH/bin go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11
	gen_go=$SCRATCH/bin/protoc-gen-go
fi
if [ -n "${PROTOC_GEN_GO_GRPC:-}" ]; then
	gen_go_grpc=$PROTOC_GEN_GO_GRPC
else
	GOBIN=$SCRATCH/bin go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.1
	gen_go_grpc=$SCRATCH/bin/protoc-gen-go-grpc
fi
[ "$("$gen_go" --version)" = "protoc-gen-go v1.36.11" ] || {
	echo "proto-regen-check: protoc-gen-go is $("$gen_go" --version), want v1.36.11" >&2; exit 1; }
[ "$("$gen_go_grpc" --version)" = "protoc-gen-go-grpc 1.6.1" ] || {
	echo "proto-regen-check: protoc-gen-go-grpc is $("$gen_go_grpc" --version), want 1.6.1" >&2; exit 1; }

PATH="$SCRATCH/bin:$PATH" "$protoc_bin" --proto_path=proto/xpf/v1 \
	--plugin=protoc-gen-go="$gen_go" \
	--plugin=protoc-gen-go-grpc="$gen_go_grpc" \
	--go_out="$SCRATCH/out" --go_opt=paths=source_relative \
	--go-grpc_out="$SCRATCH/out" --go-grpc_opt=paths=source_relative \
	proto/xpf/v1/xpf.proto

status=0
for f in xpf.pb.go xpf_grpc.pb.go; do
	if ! diff -u "pkg/grpcapi/xpfv1/$f" "$SCRATCH/out/$f" >"$SCRATCH/$f.diff"; then
		echo "proto-regen-check: FAIL: pkg/grpcapi/xpfv1/$f is stale (diff vs pinned regen):" >&2
		cat "$SCRATCH/$f.diff" >&2
		status=1
	fi
done
[ "$status" -eq 0 ] && echo "proto-regen-check: OK (checked-in stubs == pinned regen)"
exit "$status"
