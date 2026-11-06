#!/usr/bin/env bash
# Hermetic coverage for the Incus type check in vm-target-guard.sh (#18987).
# Uses a fake Incus client; valid VM cases also stub the guard's mutation tail.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/vm-target-guard.sh"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin"

cat >"$WORK/bin/incus" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
separator=
for arg in "$@"; do
	printf '%s%q' "$separator" "$arg" >>"${INCUS_CALLS:?}"
	separator=' '
done
printf '\n' >>"$INCUS_CALLS"
case "${1:-}" in
	list)
		case "${INCUS_CASE:?}" in
			vm)
				printf '%s\n' '[{"name":"other","type":"container"},{"name":"target","type":"virtual-machine"}]'
				;;
			container)
				printf '%s\n' '[{"name":"target","type":"container"}]'
				;;
			missing)
				printf '%s\n' '[{"name":"other","type":"virtual-machine"}]'
				;;
			empty)
				printf '%s\n' '[]'
				;;
			blank-output)
				;;
			garbage)
				printf '%s\n' '{not json'
				;;
			non-array)
				printf '%s\n' '{"name":"target","type":"virtual-machine"}'
				;;
			duplicate)
				printf '%s\n' '[{"name":"target","type":"virtual-machine"},{"name":"target","type":"container"}]'
				;;
			list-error)
				exit 42
				;;
			*)
				echo "unexpected fixture: ${INCUS_CASE}" >&2
				exit 43
				;;
		esac
		;;
	exec)
		if [[ "${4:-}" == cat && "${5:-}" == /proc/sys/kernel/random/boot_id ]]; then
			printf '%s\n' '01234567-89ab-cdef-0123-456789abcdef'
		fi
		;;
	file)
		;;
	*)
		echo "unexpected Incus command: $*" >&2
		exit 44
		;;
esac
STUB
chmod +x "$WORK/bin/incus"
PATH="$WORK/bin:$PATH"
export PATH

PASS=0
fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { PASS=$((PASS + 1)); echo "PASS: $*"; }

run_accept() {
	local scenario=$1 ref=$2 list_args=$3 calls="$WORK/calls" output rc first_call
	: >"$calls"
	set +e
	output=$(INCUS_CASE="$scenario" INCUS_CALLS="$calls" xpf_assert_vm_target "$ref" 2>&1)
	rc=$?
	set -e
	[[ $rc -eq 0 ]] || fail "expected accept for $ref (rc=$rc): $output"
	IFS= read -r first_call <"$calls"
	[[ "$first_call" == "list $list_args --format json" ]] \
		|| fail "wrong list arguments for $ref: $first_call"
	grep -q '^exec ' "$calls" || fail "accepted VM $ref did not reach stubbed exec tail"
	grep -q '^file push ' "$calls" || fail "accepted VM $ref did not reach stubbed file-push tail"
	ok "accepts $ref and selects the matching VM entry"
}

run_refuse() {
	local scenario=$1 ref=$2 expected=$3 calls="$WORK/calls" output rc
	: >"$calls"
	set +e
	output=$(INCUS_CASE="$scenario" INCUS_CALLS="$calls" xpf_assert_vm_target "$ref" 2>&1)
	rc=$?
	set -e
	[[ $rc -ne 0 ]] || fail "expected refusal for $ref ($scenario)"
	[[ "$output" == *"$expected"* ]] || fail "wrong refusal for $ref ($scenario): $output"
	[[ "$(wc -l <"$calls")" -eq 1 ]] || fail "refused $ref after a non-list Incus call: $(cat "$calls")"
	[[ "$(cat "$calls")" == list\ * ]] || fail "refusal for $ref did not stop at list: $(cat "$calls")"
	ok "refuses $ref for $scenario before exec/file mutations"
}

run_accept vm loss:target 'loss: target'
run_accept vm target target
run_refuse container loss:target "target type is 'container', not virtual-machine"
run_refuse missing loss:target "target type is '', not virtual-machine"
run_refuse empty loss:target "target type is '', not virtual-machine"
run_refuse blank-output loss:target "cannot decode Incus instance type for loss:target"
run_refuse garbage loss:target "cannot decode Incus instance type for loss:target"
run_refuse non-array loss:target "cannot decode Incus instance type for loss:target"
run_refuse duplicate loss:target "target type is '', not virtual-machine"
run_refuse list-error loss:target "cannot inspect target loss:target"

echo "ALL ${PASS} CASES PASS"
