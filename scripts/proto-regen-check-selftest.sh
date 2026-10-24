#!/bin/sh
# proto-regen-check-selftest.sh (#16195): prove the CI regen-diff leg
# goes red on a .proto change without regeneration, independently of
# the hermetic header check (which cannot see an un-regenerated .proto
# whose stamps still match). Hermetic fixture tree; SKIPs (77) when the
# pinned protoc/plugins are not already installed -- it never installs.
set -u
SCRATCH=${TMPDIR:-/var/worktrees/.cache/tmpdir}/xpf-proto-regen-selftest.$$
trap 'rm -rf "$SCRATCH"' EXIT INT TERM
mkdir -p "$SCRATCH/fixture/scripts" "$SCRATCH/fixture/proto/xpf/v1" "$SCRATCH/fixture/pkg/grpcapi/xpfv1" || { echo "FATAL: cannot create scratch dir $SCRATCH (TMPDIR=${TMPDIR:-/var/worktrees/.cache/tmpdir})" >&2; exit 2; }

command -v protoc >/dev/null 2>&1 || { echo "SKIP: protoc not installed"; exit 77; }
[ "$(protoc --version)" = "libprotoc 3.21.12" ] || { echo "SKIP: protoc is $(protoc --version), want libprotoc 3.21.12"; exit 77; }
command -v protoc-gen-go >/dev/null 2>&1 || { echo "SKIP: protoc-gen-go not installed"; exit 77; }
[ "$(protoc-gen-go --version)" = "protoc-gen-go v1.36.11" ] || { echo "SKIP: protoc-gen-go is $(protoc-gen-go --version)"; exit 77; }
command -v protoc-gen-go-grpc >/dev/null 2>&1 || { echo "SKIP: protoc-gen-go-grpc not installed"; exit 77; }
[ "$(protoc-gen-go-grpc --version)" = "protoc-gen-go-grpc 1.6.1" ] || { echo "SKIP: protoc-gen-go-grpc is $(protoc-gen-go-grpc --version)"; exit 77; }

# shellcheck disable=SC1007  # `CDPATH= cd` clears CDPATH for this command only
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cp "$ROOT/scripts/proto_regen_check.sh" "$SCRATCH/fixture/scripts/"
cat > "$SCRATCH/fixture/proto/xpf/v1/xpf.proto" <<'EOF'
syntax = "proto3";
package xpf.v1;
option go_package = "github.com/psaab/xpf/pkg/grpcapi/xpfv1";
service S { rpc Ping(PingReq) returns (PingResp); }
message PingReq { string msg = 1; }
message PingResp { string msg = 1; }
EOF

cd "$SCRATCH/fixture" || exit 1
protoc --proto_path=proto/xpf/v1 \
	--go_out=pkg/grpcapi/xpfv1 --go_opt=paths=source_relative \
	--go-grpc_out=pkg/grpcapi/xpfv1 --go-grpc_opt=paths=source_relative \
	proto/xpf/v1/xpf.proto || { echo "FAIL: fixture generation failed"; exit 1; }

run_regen() {
	PROTOC=$(command -v protoc) PROTOC_GEN_GO=$(command -v protoc-gen-go) \
		PROTOC_GEN_GO_GRPC=$(command -v protoc-gen-go-grpc) \
		sh scripts/proto_regen_check.sh
}

if ! run_regen >"$SCRATCH/pass.log" 2>&1; then
	echo "FAIL: regen check red on freshly generated stubs"; cat "$SCRATCH/pass.log"; exit 1
fi
echo "PASS: freshly generated stubs are green"

# Stale .proto: edit the source, do NOT regenerate. The header stamps
# still match go.mod/README, so only this regen-diff leg can go red.
printf '\nmessage Extra { string x = 1; }\n' >> proto/xpf/v1/xpf.proto
if run_regen >"$SCRATCH/stale.log" 2>&1; then
	echo "FAIL: regen check green on .proto edited without regeneration"; exit 1
fi
grep -q "is stale" "$SCRATCH/stale.log" || { echo "FAIL: stale red gave no stale diagnostic"; cat "$SCRATCH/stale.log"; exit 1; }
echo "PASS: .proto without regeneration is red (independent stale leg)"

# Hand-edited stub is red too.
protoc --proto_path=proto/xpf/v1 \
	--go_out=pkg/grpcapi/xpfv1 --go_opt=paths=source_relative \
	--go-grpc_out=pkg/grpcapi/xpfv1 --go-grpc_opt=paths=source_relative \
	proto/xpf/v1/xpf.proto || exit 1
printf '\n// hand edit\n' >> pkg/grpcapi/xpfv1/xpf.pb.go
if run_regen >"$SCRATCH/hand.log" 2>&1; then
	echo "FAIL: regen check green on hand-edited stub"; exit 1
fi
echo "PASS: hand-edited stub is red"
echo "proto-regen-check-selftest: OK"
