#!/usr/bin/env bash
# Self-test for test/incus/deploy-lib.sh (#2162/#2176). Runs WITHOUT incus or a
# live VM by mocking `incus exec` / `incus file push` against a local fake-VM
# rootfs ($FAKE_VM), so the reconciliation + sha-verify logic is exercised
# end-to-end. No cluster, no lock, no network.
#
# Usage: ./test/incus/deploy-lib-selftest.sh   (rc 0 = all pass)

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Minimal info/warn/die the lib depends on. die exits non-zero (the whole point
# of the HARD-fail behavior), so tests that EXPECT a die run the call in a
# subshell and assert on the exit code.
info() { echo "  info: $*"; }
warn() { echo "  warn: $*" >&2; }
die()  { echo "  die: $*" >&2; exit 1; }

# shellcheck source=deploy-lib.sh
source "${SCRIPT_DIR}/deploy-lib.sh"

PASS=0
FAIL=0
ok()   { echo "PASS: $1"; PASS=$((PASS + 1)); }
bad()  { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }

# ── Fake VM + incus mock ──────────────────────────────────────────────
# FAKE_VM is a directory that stands in for the VM rootfs. The mock maps
# absolute remote paths under it. A small state file controls dynamic answers
# (MainPID, ExecStart path) the filesystem alone cannot express.
FAKE_VM=""
FAKE_MAINPID="0"
FAKE_EXECSTART="/usr/local/sbin/xpfd"
# #6493: verdict the fake `xpfd verify-dataplane` probe returns, and an ordered
# log of every incus call the lib made. The log is what lets a test assert what
# did NOT happen (no stop, no push to /usr/local/sbin) on the REJECT path — the
# ordering invariant the pre-flight exists to hold.
FAKE_VERIFY_RC=0
# A FILE, not an array: every call under test runs in a subshell (die() exits,
# so the rc has to be caught), and an array mutated in a subshell is discarded
# on return. A file survives, so "what did NOT happen" is still assertable
# after the abort.
FAKE_CALL_LOG=""

setup_fake_vm() {
	FAKE_VM=$(mktemp -d)
	FAKE_MAINPID="0"
	FAKE_EXECSTART="/usr/local/sbin/xpfd"
	FAKE_VERIFY_RC=0
	FAKE_CALL_LOG=$(mktemp)
	mkdir -p "$FAKE_VM/usr/local/sbin" "$FAKE_VM/etc/systemd/system"
}

# fake_calls_contain <extended-regex> — did any recorded incus call match?
fake_calls_contain() {
	[[ -n "$FAKE_CALL_LOG" ]] && grep -qE "$1" "$FAKE_CALL_LOG" 2>/dev/null
}

teardown_fake_vm() {
	[[ -n "$FAKE_VM" && -d "$FAKE_VM" ]] && rm -rf "$FAKE_VM"
	FAKE_VM=""
	[[ -n "$FAKE_CALL_LOG" ]] && rm -f "$FAKE_CALL_LOG"
	FAKE_CALL_LOG=""
}

# incus mock: supports `incus exec <inst> -- <cmd...>` and
# `incus file push <local> <inst>/<path> [--mode m]`. <inst> is ignored
# (single fake VM). All paths resolve under $FAKE_VM.
incus() {
	# Record BEFORE dispatch so a call that dies/returns non-zero is still in
	# the log (the REJECT path's assertions read it).
	[[ -n "$FAKE_CALL_LOG" ]] && printf '%s\n' "$*" >> "$FAKE_CALL_LOG"
	local verb="$1"; shift
	case "$verb" in
	exec)
		shift          # instance name
		[[ "$1" == "--" ]] && shift
		_fake_exec "$@"
		;;
	file)
		local sub="$1"; shift
		case "$sub" in
		push)
			local src="$1" dst="$2"
			# dst is "<inst>/usr/local/sbin/xpfd" — strip the inst prefix.
			local rel="${dst#*/}"          # drop up to first slash => path after inst
			local target="$FAKE_VM/$rel"
			mkdir -p "$(dirname "$target")"
			# Mirror `incus file push` over a dangling symlink: it fails.
			if [[ -L "$target" && ! -e "$target" ]]; then
				echo "Error: push through dangling symlink $target" >&2
				return 1
			fi
			cp -f "$src" "$target"
			;;
		*) echo "unsupported incus file $sub" >&2; return 2 ;;
		esac
		;;
	*) echo "unsupported incus verb $verb" >&2; return 2 ;;
	esac
}

# _fake_exec runs a remote command against the fake VM. It special-cases the
# few commands the lib issues; bash -c bodies are rewritten to operate under
# $FAKE_VM, and systemctl/sha256sum/test/rm/readlink are intercepted.
_fake_exec() {
	# Reconstruct argv. The lib calls:
	#   test -f <path>
	#   rm -f <path>
	#   bash -c '<script>'
	#   systemctl daemon-reload
	#   systemctl show -p ExecStart --value xpfd  (via bash -c "... sed ...")
	#   sha256sum <path>
	case "$1" in
	cli)
		# #6591: `cli -c "<command>"`. Every invocation is appended to
		# $CLI_LOG so a test can assert the ISSUED SEQUENCE (reset ->
		# transfer -> reset), and `show chassis cluster status` is answered
		# from $CLI_STATUS_QUEUE — one line-delimited response per read, the
		# last one repeating. That models the real failure: the first reads
		# after a deploy fail while the daemon settles, later ones succeed.
		shift
		[[ "$1" == "-c" ]] && shift
		local cmd="$1"
		printf '%s\n' "$cmd" >>"$CLI_LOG"
		if [[ "$cmd" == "show chassis cluster status" ]]; then
			_fake_cli_status
			return $?
		fi
		# request ... : succeed silently unless a test says otherwise.
		return "${CLI_REQUEST_RC:-0}"
		;;
	test)
		shift
		# test -f <path>  /  used by deploy_reconcile_stale_pin
		if [[ "$1" == "-f" ]]; then
			[[ -f "$FAKE_VM/${2#/}" ]]
			return $?
		fi
		return 2
		;;
	rm)
		shift
		[[ "$1" == "-f" ]] && shift
		rm -f "$FAKE_VM/${1#/}"
		return 0
		;;
	systemctl)
		shift
		case "$1" in
		daemon-reload) return 0 ;;
		show)
			# systemctl show -p ExecStart --value xpfd  => emit a
			# "{ path=... ; ... }" line; -p MainPID --value => the pid.
			if [[ "$*" == *ExecStart* ]]; then
				echo "{ path=$FAKE_EXECSTART ; argv[]=$FAKE_EXECSTART ; ... }"
			elif [[ "$*" == *MainPID* ]]; then
				echo "$FAKE_MAINPID"
			fi
			return 0
			;;
		esac
		return 0
		;;
	sha256sum)
		shift
		sha256sum "$FAKE_VM/${1#/}" 2>/dev/null | awk -v p="$1" '{print $1"  "p}'
		return ${PIPESTATUS[0]}
		;;
	bash)
		# bash -c '<script>' — run the script with a tiny shim layer that
		# redirects absolute paths into $FAKE_VM and emulates systemctl/sha256sum
		# for the running-verify body.
		shift
		[[ "$1" == "-c" ]] && shift
		local body="$1"
		_fake_remote_bash "$body"
		return $?
		;;
	esac
	return 0
}

# _fake_remote_bash interprets the specific bash -c bodies the lib sends.
_fake_remote_bash() {
	local body="$1"
	# #6493 pre-flight probe: the body execs `<staged> verify-dataplane`.
	# Answer with the configured verdict. Checked FIRST so the generic
	# fall-through `return 0` at the bottom can never launder a REJECT into a
	# pass (a mock that silently returns 0 for an unrecognized body inverts the
	# result of every REJECT test in this file).
	if [[ "$body" == *"verify-dataplane"* ]]; then
		return "$FAKE_VERIFY_RC"
	fi
	# deploy_verify_running_xpfd: effective ExecStart query (systemctl show
	# ExecStart | sed path=). Emit the modeled ExecStart through the same sed
	# the lib applies, so the extraction path is exercised end-to-end.
	if [[ "$body" == *"systemctl show -p ExecStart"* ]]; then
		echo "{ path=$FAKE_EXECSTART ; argv[]=$FAKE_EXECSTART ; ... }" \
			| sed -n 's/.*path=\([^ ;]*\).*/\1/p' | head -n1
		return 0
	fi
	# deploy_reconcile_stale_pin: rmdir-empty-dir guard
	if [[ "$body" == *"xpfd.service.d"* && "$body" == *rmdir* ]]; then
		local d="$FAKE_VM/etc/systemd/system/xpfd.service.d"
		[ -d "$d" ] && [ -z "$(ls -A "$d" 2>/dev/null)" ] && rmdir "$d"
		return 0
	fi
	# deploy_reconcile_stale_pin: other-ExecStart-override scan
	if [[ "$body" == *"grep -lE"* && "$body" == *ExecStart* ]]; then
		local d="$FAKE_VM/etc/systemd/system/xpfd.service.d"
		[ -d "$d" ] || return 0
		grep -lE "^[[:space:]]*ExecStart[[:space:]]*=" "$d"/*.conf 2>/dev/null || true
		return 0
	fi
	# deploy_reconcile_dangling_sbin: [ -L p ] && [ ! -e p ]
	if [[ "$body" == *"-L"* && "$body" == *"-e"* ]]; then
		# Extract the quoted path: ...'<path>'...
		local p
		p=$(sed -E "s/.*-L '([^']+)'.*/\1/" <<<"$body")
		local fp="$FAKE_VM/${p#/}"
		[ -L "$fp" ] && [ ! -e "$fp" ]
		return $?
	fi
	# deploy_verify_running_xpfd: MainPID + sha256sum /proc/PID/exe
	if [[ "$body" == *MainPID* && "$body" == *"/proc/"* ]]; then
		[[ "$FAKE_MAINPID" != "0" ]] || return 1
		# The "running exe" is the file the fake pid points at: we model it as
		# whatever currently lives at /usr/local/sbin/xpfd in the fake VM.
		sha256sum "$FAKE_VM/usr/local/sbin/xpfd" 2>/dev/null || return 1
		return 0
	fi
	return 0
}

# ── #6591 cli mock state ──────────────────────────────────────────────
# CLI_STATUS_RESPONSES is an array of status payloads consumed one per
# `show chassis cluster status`; the LAST entry repeats once exhausted.
# An empty string models an unreadable status (daemon still starting).
# The read index is FILE-BACKED, not a shell variable. `status=$(incus exec
# ...)` is a command substitution, i.e. a subshell, so a variable increment
# inside it is discarded — the counter would stick at 0 and every read would
# return the same response. That would have made the retry test below
# unfailable in one direction and permanently red in the other; it is exactly
# the kind of fixture defect that produces a confident wrong answer.
CLI_LOG=""
CLI_IDX_FILE=""
CLI_REQUEST_RC=0
declare -a CLI_STATUS_RESPONSES=()

_fake_cli_status() {
	local n=${#CLI_STATUS_RESPONSES[@]}
	(( n == 0 )) && return 1
	local i
	i=$(<"$CLI_IDX_FILE")
	printf '%s' "$(( i + 1 ))" >"$CLI_IDX_FILE"
	(( i >= n )) && i=$(( n - 1 ))
	local body="${CLI_STATUS_RESPONSES[$i]}"
	[[ -z "$body" ]] && return 1
	printf '%s\n' "$body"
}

reset_cli_mock() {
	CLI_LOG=$(mktemp)
	# $CLI_LOG records the command TEXT ONLY: incus() shifts the instance away
	# before _fake_exec sees it, so a reset issued to the peer is byte-identical
	# there to a duplicate reset issued to node0. $FAKE_CALL_LOG keeps the full
	# argv, so it is the only log that can answer WHICH NODE a command went to
	# -- which is the whole property under test in #7688.
	FAKE_CALL_LOG=$(mktemp)
	CLI_IDX_FILE=$(mktemp)
	printf '0' >"$CLI_IDX_FILE"
	CLI_REQUEST_RC=0
	CLI_STATUS_RESPONSES=()
	# No sleeping in the self-test; the retry COUNTS are what is under test.
	DEPLOY_REASSERT_READ_DELAY=0
	DEPLOY_REASSERT_VERIFY_DELAY=0
	DEPLOY_REASSERT_READ_TRIES=3
	DEPLOY_REASSERT_VERIFY_TRIES=3
}

# ── Fixtures ──────────────────────────────────────────────────────────
make_local_bin() { printf '%s' "$2" > "$1"; }   # path, content

# ── Tests ─────────────────────────────────────────────────────────────

test_verify_pushed_sha_match() {
	setup_fake_vm
	local lb; lb=$(mktemp); make_local_bin "$lb" "BINARY-A"
	cp "$lb" "$FAKE_VM/usr/local/sbin/xpfd"
	if ( deploy_verify_pushed_sha vm "$lb" /usr/local/sbin/xpfd xpfd ) >/dev/null 2>&1; then
		ok "verify_pushed_sha: matching sha passes"
	else
		bad "verify_pushed_sha: matching sha should pass"
	fi
	rm -f "$lb"; teardown_fake_vm
}

test_verify_pushed_sha_mismatch_hardfails() {
	setup_fake_vm
	local lb; lb=$(mktemp); make_local_bin "$lb" "BINARY-NEW"
	make_local_bin "$FAKE_VM/usr/local/sbin/xpfd" "BINARY-OLD"
	if ( deploy_verify_pushed_sha vm "$lb" /usr/local/sbin/xpfd xpfd ) >/dev/null 2>&1; then
		bad "verify_pushed_sha: mismatch MUST hard-fail (stale binary)"
	else
		ok "verify_pushed_sha: mismatch hard-fails (rc!=0)"
	fi
	rm -f "$lb"; teardown_fake_vm
}

test_verify_pushed_sha_absent_hardfails() {
	setup_fake_vm
	local lb; lb=$(mktemp); make_local_bin "$lb" "BINARY-A"
	# no file on VM
	if ( deploy_verify_pushed_sha vm "$lb" /usr/local/sbin/xpfd xpfd ) >/dev/null 2>&1; then
		bad "verify_pushed_sha: absent binary MUST hard-fail"
	else
		ok "verify_pushed_sha: absent binary hard-fails (empty readback)"
	fi
	rm -f "$lb"; teardown_fake_vm
}

test_reconcile_stale_pin_removes_managed() {
	setup_fake_vm
	mkdir -p "$FAKE_VM/etc/systemd/system/xpfd.service.d"
	printf '[Service]\nExecStart=\nExecStart=/usr/local/share/xpf/versions/v1/xpfd\n' \
		> "$FAKE_VM$DEPLOY_VERSION_DROPIN"
	if ( deploy_reconcile_stale_pin vm ) >/dev/null 2>&1; then :; else
		bad "reconcile_stale_pin: should succeed removing the managed pin"; teardown_fake_vm; return
	fi
	if [[ -f "$FAKE_VM$DEPLOY_VERSION_DROPIN" ]]; then
		bad "reconcile_stale_pin: managed pin still present after reconcile"
	elif [[ -d "$FAKE_VM/etc/systemd/system/xpfd.service.d" ]]; then
		bad "reconcile_stale_pin: empty drop-in dir not removed"
	else
		ok "reconcile_stale_pin: managed pin + empty dir removed"
	fi
	teardown_fake_vm
}

test_reconcile_stale_pin_no_pin_noop() {
	setup_fake_vm
	if ( deploy_reconcile_stale_pin vm ) >/dev/null 2>&1; then
		ok "reconcile_stale_pin: clean VM is a no-op (passes)"
	else
		bad "reconcile_stale_pin: clean VM should pass"
	fi
	teardown_fake_vm
}

test_reconcile_stale_pin_foreign_override_hardfails() {
	setup_fake_vm
	mkdir -p "$FAKE_VM/etc/systemd/system/xpfd.service.d"
	# A NON-managed ExecStart override (operator-authored) must HARD FAIL.
	printf '[Service]\nExecStart=\nExecStart=/opt/custom/xpfd\n' \
		> "$FAKE_VM/etc/systemd/system/xpfd.service.d/50-operator.conf"
	if ( deploy_reconcile_stale_pin vm ) >/dev/null 2>&1; then
		bad "reconcile_stale_pin: foreign ExecStart override MUST hard-fail"
	else
		ok "reconcile_stale_pin: foreign ExecStart override hard-fails"
	fi
	teardown_fake_vm
}

test_reconcile_dangling_sbin_removes() {
	setup_fake_vm
	# Dangling symlink into a removed versions dir.
	ln -s /usr/local/share/xpf/versions/current/xpfd "$FAKE_VM/usr/local/sbin/xpfd"
	if ( deploy_reconcile_dangling_sbin vm ) >/dev/null 2>&1; then :; else
		bad "reconcile_dangling_sbin: should succeed"; teardown_fake_vm; return
	fi
	if [[ -L "$FAKE_VM/usr/local/sbin/xpfd" ]]; then
		bad "reconcile_dangling_sbin: dangling symlink not removed"
	else
		ok "reconcile_dangling_sbin: dangling symlink removed (push can land a file)"
	fi
	# A subsequent push must now succeed (mock fails on dangling symlink).
	local lb; lb=$(mktemp); make_local_bin "$lb" "FRESH"
	if incus file push "$lb" "vm/usr/local/sbin/xpfd" --mode 0755 2>/dev/null; then
		ok "reconcile_dangling_sbin: push lands a regular file afterward"
	else
		bad "reconcile_dangling_sbin: push still fails after reconcile"
	fi
	rm -f "$lb"; teardown_fake_vm
}

test_reconcile_dangling_sbin_keeps_valid() {
	setup_fake_vm
	# A VALID symlink (target exists) is NOT removed.
	make_local_bin "$FAKE_VM/usr/local/sbin/.xpfd-real" "REAL"
	ln -s .xpfd-real "$FAKE_VM/usr/local/sbin/xpfd"
	( deploy_reconcile_dangling_sbin vm ) >/dev/null 2>&1
	if [[ -L "$FAKE_VM/usr/local/sbin/xpfd" ]]; then
		ok "reconcile_dangling_sbin: valid symlink preserved"
	else
		bad "reconcile_dangling_sbin: wrongly removed a VALID symlink"
	fi
	teardown_fake_vm
}

test_verify_running_match() {
	setup_fake_vm
	local lb; lb=$(mktemp); make_local_bin "$lb" "RUNNING-OK"
	cp "$lb" "$FAKE_VM/usr/local/sbin/xpfd"
	FAKE_MAINPID="4242"
	FAKE_EXECSTART="/usr/local/sbin/xpfd"
	if ( deploy_verify_running_xpfd vm "$lb" ) >/dev/null 2>&1; then
		ok "verify_running: running sha == pushed + base ExecStart passes"
	else
		bad "verify_running: matching run should pass"
	fi
	rm -f "$lb"; teardown_fake_vm
}

# #8302: the running-exe readback was EXTRACTED from deploy_verify_running_xpfd
# into deploy_running_xpfd_sha256 so the ledger emitter
# (test/incus/harness-result.sh) reuses the one readback rather than growing a
# second one free to disagree with it. The cells above exercise it through the
# wrapper; these two pin the extracted function's OWN contract, which the
# wrapper cannot express because it dies on both of these inputs.
test_running_sha_returns_the_live_sha() {
	setup_fake_vm
	local lb; lb=$(mktemp); make_local_bin "$lb" "RUNNING-OK"
	cp "$lb" "$FAKE_VM/usr/local/sbin/xpfd"
	FAKE_MAINPID="4242"
	local want got
	want=$(sha256sum "$lb" | awk '{print $1}')
	got=$(deploy_running_xpfd_sha256 vm 1)
	if [[ "$got" == "$want" ]]; then
		ok "running_sha: echoes the LIVE process image's sha256"
	else
		bad "running_sha: got '$got', want '$want'"
	fi
	rm -f "$lb"; teardown_fake_vm
}

test_running_sha_empty_instance_does_not_read_the_local_host() {
	setup_fake_vm
	# An empty instance name must NOT fall through to reading this machine's
	# own xpfd -- that would be a value indistinguishable from a healthy
	# readback, attributing a measurement to the wrong binary entirely.
	local got rc
	got=$(deploy_running_xpfd_sha256 "" 1); rc=$?
	if [[ $rc -ne 0 && -z "$got" ]]; then
		ok "running_sha: an empty instance name returns EMPTY rc!=0, never a local fallback"
	else
		bad "running_sha: empty instance gave rc=$rc out='$got'"
	fi
	teardown_fake_vm
}

test_verify_running_stale_pin_hardfails() {
	setup_fake_vm
	local lb; lb=$(mktemp); make_local_bin "$lb" "RUNNING-OK"
	cp "$lb" "$FAKE_VM/usr/local/sbin/xpfd"
	FAKE_MAINPID="4242"
	# ExecStart points at a versioned path => a pin survived => MUST hard-fail.
	FAKE_EXECSTART="/usr/local/share/xpf/versions/v1/xpfd"
	if ( deploy_verify_running_xpfd vm "$lb" ) >/dev/null 2>&1; then
		bad "verify_running: surviving version pin MUST hard-fail"
	else
		ok "verify_running: surviving version pin hard-fails (ExecStart != base)"
	fi
	rm -f "$lb"; teardown_fake_vm
}

test_verify_running_stale_binary_hardfails() {
	setup_fake_vm
	local lb; lb=$(mktemp); make_local_bin "$lb" "NEW-BUILD"
	# VM is running the OLD binary (different content) at the base path.
	make_local_bin "$FAKE_VM/usr/local/sbin/xpfd" "OLD-BUILD"
	FAKE_MAINPID="4242"
	FAKE_EXECSTART="/usr/local/sbin/xpfd"
	if ( deploy_verify_running_xpfd vm "$lb" ) >/dev/null 2>&1; then
		bad "verify_running: stale running binary MUST hard-fail"
	else
		ok "verify_running: stale running binary hard-fails (run sha != pushed)"
	fi
	rm -f "$lb"; teardown_fake_vm
}

# ── #1864 verify-dataplane pre-flight (#6493) ────────────────────────
# The gate the standalone deploy was missing. Three properties:
#   1. a REJECT hard-fails (rc != 0) AND touches nothing on the box — no
#      systemctl stop, no push into /usr/local/sbin. That is the whole point:
#      the old daemon keeps forwarding while the operator rebuilds.
#   2. a PASS returns 0 so the deploy proceeds.
#   3. the staged /tmp/xpfd.preflight is removed on BOTH paths.
# RED on revert: drop the die() and (1) flips; drop the cleanup call from
# either path and (3) flips; hoist the call below the stop in setup.sh and the
# ORDERING test below flips.

test_preflight_pass_proceeds() {
	setup_fake_vm
	local lb; lb=$(mktemp); make_local_bin "$lb" "GOOD-SHIM"
	FAKE_VERIFY_RC=0
	if ( deploy_verify_dataplane_preflight vm "$lb" ) >/dev/null 2>&1; then
		ok "preflight: verifier PASS lets the deploy proceed (rc 0)"
	else
		bad "preflight: verifier PASS must not abort the deploy"
	fi
	rm -f "$lb"; teardown_fake_vm
}

test_preflight_reject_hardfails() {
	setup_fake_vm
	local lb; lb=$(mktemp); make_local_bin "$lb" "BAD-SHIM"
	FAKE_VERIFY_RC=1
	if ( deploy_verify_dataplane_preflight vm "$lb" ) >/dev/null 2>&1; then
		bad "preflight: verifier REJECT MUST hard-fail (this is the #1864 mode)"
	else
		ok "preflight: verifier REJECT hard-fails (rc!=0, deploy aborts)"
	fi
	rm -f "$lb"; teardown_fake_vm
}

test_preflight_reject_touches_nothing() {
	setup_fake_vm
	local lb; lb=$(mktemp); make_local_bin "$lb" "BAD-SHIM"
	# The VM is running the OLD binary; a REJECT must leave it exactly there.
	make_local_bin "$FAKE_VM/usr/local/sbin/xpfd" "OLD-RUNNING"
	FAKE_VERIFY_RC=1
	# Subshell for the rc (die() exits); the call log is a file so it survives.
	local rc=0
	( deploy_verify_dataplane_preflight vm "$lb" ) >/dev/null 2>&1 || rc=$?
	if [[ $rc -eq 0 ]]; then
		bad "preflight: REJECT must not return 0"
		rm -f "$lb"; teardown_fake_vm; return
	fi
	if fake_calls_contain "systemctl stop"; then
		bad "preflight: REJECT stopped the daemon — the box was taken down to learn the binary is bad"
	elif fake_calls_contain "vm/usr/local/sbin/xpfd"; then
		bad "preflight: REJECT pushed into /usr/local/sbin — the bad binary replaced the good one"
	elif [[ "$(cat "$FAKE_VM/usr/local/sbin/xpfd")" != "OLD-RUNNING" ]]; then
		bad "preflight: REJECT overwrote the running binary"
	else
		ok "preflight: REJECT leaves the old daemon untouched (no stop, no sbin push)"
	fi
	rm -f "$lb"; teardown_fake_vm
}

test_preflight_cleans_up_on_pass() {
	setup_fake_vm
	local lb; lb=$(mktemp); make_local_bin "$lb" "GOOD-SHIM"
	FAKE_VERIFY_RC=0
	( deploy_verify_dataplane_preflight vm "$lb" ) >/dev/null 2>&1
	if [[ -e "$FAKE_VM/tmp/xpfd.preflight" ]]; then
		bad "preflight: staged candidate left behind after PASS"
	else
		ok "preflight: staged /tmp/xpfd.preflight removed after PASS"
	fi
	rm -f "$lb"; teardown_fake_vm
}

test_preflight_cleans_up_on_reject() {
	setup_fake_vm
	local lb; lb=$(mktemp); make_local_bin "$lb" "BAD-SHIM"
	FAKE_VERIFY_RC=1
	( deploy_verify_dataplane_preflight vm "$lb" ) >/dev/null 2>&1
	if [[ -e "$FAKE_VM/tmp/xpfd.preflight" ]]; then
		bad "preflight: staged candidate left behind after REJECT (poisons the next probe's diagnosis)"
	else
		ok "preflight: staged /tmp/xpfd.preflight removed after REJECT"
	fi
	rm -f "$lb"; teardown_fake_vm
}

# #9558: the two refusal arms must print DIFFERENT remediation. verify-dataplane
# exits 3 ONLY for the #1864 kernel-verifier reject; every other refusal (for
# example a live pinned-map ABI mismatch) exits 1, and "make generate" cannot fix
# it. A presence check alone would pass the pre-fix wrapper, which printed the
# #1864 text for BOTH, so the exit-1 cell asserts that remediation is ABSENT.
test_preflight_verifier_reject_prescribes_1864_remediation() {
	setup_fake_vm
	local lb; lb=$(mktemp); make_local_bin "$lb" "BAD-SHIM"
	FAKE_VERIFY_RC=3
	local out rc=0
	out=$( ( deploy_verify_dataplane_preflight vm "$lb" ) 2>&1 ) || rc=$?
	if [[ $rc -eq 0 ]]; then
		bad "preflight #9558: exit 3 (kernel-verifier REJECT) must hard-fail"
	elif [[ "$out" != *"#1864 failure mode"* || "$out" != *"make generate"* ]]; then
		bad "preflight #9558: exit 3 must print the #1864 make-generate remediation; got: $out"
	else
		ok "preflight #9558: exit 3 (kernel-verifier REJECT) prints the #1864 make-generate remediation"
	fi
	rm -f "$lb"; teardown_fake_vm
}

test_preflight_other_refusal_prescribes_no_make_generate() {
	setup_fake_vm
	local lb; lb=$(mktemp); make_local_bin "$lb" "PIN-ABI-MISMATCH"
	FAKE_VERIFY_RC=1
	local out rc=0
	out=$( ( deploy_verify_dataplane_preflight vm "$lb" ) 2>&1 ) || rc=$?
	if [[ $rc -eq 0 ]]; then
		bad "preflight #9558: exit 1 (non-verifier refusal) must hard-fail"
	elif [[ "$out" == *"make generate"* || "$out" == *"#1864 failure mode"* ]]; then
		bad "preflight #9558: exit 1 printed the #1864 make-generate remediation, which cannot fix a non-verifier refusal; got: $out"
	elif [[ "$out" != *"(exit 1)"* ]]; then
		bad "preflight #9558: an exit-1 refusal must name its exit status; got: $out"
	else
		ok "preflight #9558: exit 1 (non-verifier refusal) names its exit and prescribes no make generate"
	fi
	rm -f "$lb"; teardown_fake_vm
}

test_preflight_missing_local_binary_hardfails() {
	setup_fake_vm
	FAKE_VERIFY_RC=0
	# No local build at all: must fail loudly rather than push nothing and
	# "pass" a probe of a binary that does not exist.
	if ( deploy_verify_dataplane_preflight vm /nonexistent/xpfd ) >/dev/null 2>&1; then
		bad "preflight: absent local xpfd MUST hard-fail"
	else
		ok "preflight: absent local xpfd hard-fails before any remote work"
	fi
	teardown_fake_vm
}

# ── ORDERING: the call site position, not the function ───────────────
# The function can be perfect and the gate still useless if a caller runs it
# after `systemctl stop xpfd`. These read the real deploy scripts and assert the
# pre-flight call precedes every destructive step in the same function. Purely
# textual (no incus), and RED the moment either call is hoisted or removed.
# _first_line_matching <file> <grep-ere> -> line number of the first matching
# NON-COMMENT line, or empty.
#
# The comment filter is load-bearing, not tidiness: the pre-flight call sites
# are documented with prose that NAMES the destructive steps ("...runs before
# `systemctl stop xpfd`..."), so an unanchored sweep matches the explanation of
# the invariant instead of the code that breaks it — and reports the gate as
# mis-ordered while it is in fact correct. Caught by this very test on its
# first run.
_first_line_matching() {
	grep -nE "$2" "$1" 2>/dev/null \
		| awk -F: '{ line = $0; sub(/^[0-9]+:/, "", line); if (line !~ /^[[:space:]]*#/) { print $1; exit } }'
}

test_preflight_precedes_destructive_steps_standalone() {
	local f="${SCRIPT_DIR}/setup.sh"
	local pre stop push
	pre=$(_first_line_matching "$f" '^[[:space:]]*deploy_verify_dataplane_preflight ')
	stop=$(_first_line_matching "$f" 'systemctl stop xpfd')
	push=$(_first_line_matching "$f" 'incus file push .*/usr/local/sbin/xpfd')
	if [[ -z "$pre" ]]; then
		bad "ordering(setup.sh): no deploy_verify_dataplane_preflight call — the standalone deploy has NO verifier gate (#6493)"
	elif [[ -z "$stop" || -z "$push" ]]; then
		bad "ordering(setup.sh): could not locate the stop/push anchors — test is stale, fix the pattern"
	elif (( pre < stop && pre < push )); then
		ok "ordering(setup.sh): pre-flight at :$pre precedes stop(:$stop) and sbin push(:$push)"
	else
		bad "ordering(setup.sh): pre-flight at :$pre runs AFTER stop(:$stop)/push(:$push) — the box is already down when the gate fires"
	fi
}

test_preflight_precedes_destructive_steps_cluster() {
	local f="${SCRIPT_DIR}/cluster-setup.sh"
	local pre stop push
	pre=$(_first_line_matching "$f" '^[[:space:]]*deploy_verify_dataplane_preflight ')
	stop=$(_first_line_matching "$f" 'systemctl stop bpfrxd')
	push=$(_first_line_matching "$f" 'incus file push .*/usr/local/sbin/xpfd')
	if [[ -z "$pre" ]]; then
		bad "ordering(cluster-setup.sh): no deploy_verify_dataplane_preflight call — the #1869 gate was lost"
	elif [[ -z "$stop" || -z "$push" ]]; then
		bad "ordering(cluster-setup.sh): could not locate the stop/push anchors — test is stale, fix the pattern"
	elif (( pre < stop && pre < push )); then
		ok "ordering(cluster-setup.sh): pre-flight at :$pre precedes migration stop(:$stop) and sbin push(:$push)"
	else
		bad "ordering(cluster-setup.sh): pre-flight at :$pre runs AFTER stop(:$stop)/push(:$push)"
	fi
}

# ── Rolling-deploy node ordering (#4009) ─────────────────────────────
# Captured `cli -c "show chassis cluster status"` samples (FormatStatus,
# pkg/cluster/status.go). deploy_rolling_secondary_node must echo the RG0
# SECONDARY node index (upgrade it FIRST). RED-on-revert: the retired
# inline `grep "secondary:node0"` never matched these space-separated,
# lowercase rows, so a node0-secondary cluster wrongly resolved to
# node1-first — restarting the PRIMARY first → a spurious mid-deploy failover.

STATUS_NODE0_PRIMARY="Monitor Failure codes:
    CS  Cold Sync monitoring        FL  Fabric Connection monitoring

Cluster ID: 1
Node name: node0

Node    Priority  Status         Preempt  Manual   Monitor-failures

Redundancy group: 0 , Failover count: 0
node0   200       primary        no       no       None
  Takeover ready: yes
  Transfer ready: yes
node1   100       secondary      no       no       None
"

STATUS_NODE0_SECONDARY="Redundancy group: 0 , Failover count: 1
node0   100       secondary      no       no       None
node1   200       primary        no       no       None
"

# Active-active: node0 is SECONDARY for RG0 but PRIMARY for RG1. The decision
# must be scoped to RG0 (the mastership that steers the WAN path) → node0 first.
STATUS_MULTI_RG_NODE0_SEC_RG0="Redundancy group: 0 , Failover count: 1
node0   200       secondary      no       no       None
node1   100       primary        no       no       None

Redundancy group: 1 , Failover count: 2
node0   200       primary        no       no       None
node1   100       secondary      no       no       None
"

STATUS_SECONDARY_HOLD="Redundancy group: 0 , Failover count: 0
node0   100       secondary-hold no       no       None
node1   200       primary        no       no       None
"

STATUS_PEER_DOWN="Redundancy group: 0 , Failover count: 0
node0   200       primary        no       no       None
"

test_rolling_secondary_node0_primary() {
	local got; got=$(printf '%s' "$STATUS_NODE0_PRIMARY" | deploy_rolling_secondary_node)
	if [[ "$got" == 1 ]]; then
		ok "rolling: node0 primary -> upgrade node1 (secondary) first"
	else
		bad "rolling: node0 primary -> expected 1, got '$got'"
	fi
}

test_rolling_secondary_node0_secondary() {
	local got; got=$(printf '%s' "$STATUS_NODE0_SECONDARY" | deploy_rolling_secondary_node)
	if [[ "$got" == 0 ]]; then
		ok "rolling: node0 secondary -> upgrade node0 first (no spurious failover)"
	else
		bad "rolling: node0 secondary -> expected 0, got '$got' (retired secondary:node0 grep gives 1 -> restarts PRIMARY first)"
	fi
}

test_rolling_secondary_multi_rg_scoped_to_rg0() {
	local got; got=$(printf '%s' "$STATUS_MULTI_RG_NODE0_SEC_RG0" | deploy_rolling_secondary_node)
	if [[ "$got" == 0 ]]; then
		ok "rolling: multi-RG decision scoped to RG0 (node0 secondary in RG0)"
	else
		bad "rolling: multi-RG -> expected 0 (RG0), got '$got'"
	fi
}

test_rolling_secondary_hold_counts_as_secondary() {
	local got; got=$(printf '%s' "$STATUS_SECONDARY_HOLD" | deploy_rolling_secondary_node)
	if [[ "$got" == 0 ]]; then
		ok "rolling: node0 secondary-hold -> upgrade node0 first"
	else
		bad "rolling: secondary-hold -> expected 0, got '$got'"
	fi
}

test_rolling_secondary_peer_down_defaults() {
	local got; got=$(printf '%s' "$STATUS_PEER_DOWN" | deploy_rolling_secondary_node)
	if [[ "$got" == 1 ]]; then
		ok "rolling: node0 primary (peer down) -> default node1 first"
	else
		bad "rolling: peer-down -> expected 1, got '$got'"
	fi
}

test_rolling_secondary_empty_defaults() {
	local got; got=$(printf '' | deploy_rolling_secondary_node)
	if [[ "$got" == 1 ]]; then
		ok "rolling: empty/unparseable status -> default node1 first"
	else
		bad "rolling: empty -> expected 1, got '$got'"
	fi
}

test_rolling_rg_ids() {
	local got; got=$(printf '%s' "$STATUS_MULTI_RG_NODE0_SEC_RG0" | deploy_rolling_rg_ids | tr '\n' ' ')
	if [[ "$got" == "0 1 " ]]; then
		ok "rolling: rg-id extraction lists '0 1' for the post-deploy reassert"
	else
		bad "rolling: rg-ids -> expected '0 1 ', got '$got'"
	fi
}

# ── #6591 post-deploy reassert: fail-closed ──────────────────────────
# The pre-fix reassert read `show chassis cluster status`, and if the read
# failed it iterated ZERO redundancy groups, warned, and returned SUCCESS. The
# deploy then reported DEPLOY_RC=0 with the cluster left inverted relative to
# its configured priorities (node0 at priority 200 sitting secondary behind
# node1 at 100 — preempt=no means nothing corrects it), and the next HA smoke
# died in its own preflight where the natural first hypothesis is that the
# change under test broke HA. Measured twice on the shared gate.
#
# It also never verified the resulting role, so even a status read that
# SUCCEEDED could leave the cluster un-reasserted and still report success.

STATUS_BOTH_RG_NODE0_PRIMARY="Redundancy group: 0 , Failover count: 0
node0   200       primary        no       no       None
node1   100       secondary      no       no       None

Redundancy group: 1 , Failover count: 0
node0   200       primary        no       no       None
node1   100       secondary      no       no       None
"

# The state the lead actually observed after a deploy that reported success.
STATUS_INVERTED_RG0="Redundancy group: 0 , Failover count: 0
node0   200       secondary      no       no       None
node1   100       primary        no       no       None
"

# The partial case a per-RG loop can produce and a `grep node0.*primary`
# cannot see: RG0 reasserted, RG1 still inverted.
STATUS_RG0_OK_RG1_INVERTED="Redundancy group: 0 , Failover count: 0
node0   200       primary        no       no       None
node1   100       secondary      no       no       None

Redundancy group: 1 , Failover count: 0
node0   200       secondary      no       no       None
node1   100       primary        no       no       None
"

test_reassert_verifier_accepts_all_primary() {
	if printf '%s' "$STATUS_BOTH_RG_NODE0_PRIMARY" | deploy_reassert_node0_primary_ok; then
		ok "reassert verify: node0 primary for every RG -> accept"
	else
		bad "reassert verify: rejected a fully reasserted cluster"
	fi
}

test_reassert_verifier_rejects_inverted() {
	if printf '%s' "$STATUS_INVERTED_RG0" | deploy_reassert_node0_primary_ok; then
		bad "reassert verify: accepted node0=secondary/node1=primary — the exact state a deploy reported success on"
	else
		ok "reassert verify: inverted RG0 -> reject"
	fi
}

test_reassert_verifier_rejects_partial() {
	if printf '%s' "$STATUS_RG0_OK_RG1_INVERTED" | deploy_reassert_node0_primary_ok; then
		bad "reassert verify: accepted RG0-ok/RG1-inverted — the property is EVERY RG, which a per-line grep cannot express"
	else
		ok "reassert verify: partial reassert (RG1 inverted) -> reject"
	fi
}

test_reassert_verifier_rejects_empty() {
	# THE FAIL-OPEN CELL. An unreadable status must not read as "nothing to
	# check, therefore fine".
	if printf '%s' "" | deploy_reassert_node0_primary_ok; then
		bad "reassert verify: accepted an EMPTY status — an unreadable cluster status must FAIL, not pass vacuously (#6591)"
	else
		ok "reassert verify: empty/unreadable status -> reject"
	fi
}

test_reassert_dies_when_status_never_readable() {
	reset_cli_mock
	CLI_STATUS_RESPONSES=("")   # every read fails, for all retries
	local rc=0
	( deploy_reassert_primary_node0 "fake:vm0" ) >/dev/null 2>&1 || rc=$?
	if (( rc != 0 )); then
		ok "reassert: unreadable status -> DIES (rc=$rc), deploy cannot report success"
	else
		bad "reassert: unreadable status returned SUCCESS — this is the #6591 fail-open that cost two gate cycles"
	fi
}

test_reassert_retries_status_read_until_settled() {
	reset_cli_mock
	# Two failed reads (daemon still settling ~20s post-deploy), then good.
	CLI_STATUS_RESPONSES=("" "$STATUS_BOTH_RG_NODE0_PRIMARY" "$STATUS_BOTH_RG_NODE0_PRIMARY")
	local rc=0
	( deploy_reassert_primary_node0 "fake:vm0" ) >/dev/null 2>&1 || rc=$?
	if (( rc == 0 )); then
		ok "reassert: retries the status read across the post-deploy settle window"
	else
		bad "reassert: gave up on a transient unreadable status (rc=$rc) — the measured failure was a read that succeeded moments later"
	fi
}

test_reassert_dies_when_role_not_achieved() {
	reset_cli_mock
	# Status is readable throughout, but node0 never becomes primary: the
	# transfer was accepted and did not land. Only a verify can tell these
	# apart, which is why the exit code of the request is not the verdict.
	CLI_STATUS_RESPONSES=("$STATUS_INVERTED_RG0")
	local rc=0
	( deploy_reassert_primary_node0 "fake:vm0" ) >/dev/null 2>&1 || rc=$?
	if (( rc != 0 )); then
		ok "reassert: role not achieved -> DIES (rc=$rc) instead of handing the next smoke an inverted cluster"
	else
		bad "reassert: reported success while node0 stayed SECONDARY for RG0"
	fi
}

# #7962: the failure message must say WHICH failure this is. A gate that fails
# identically whether the helper is broken or whether nothing asked it to
# forward a packet carries no information, and its failures get read as HA
# regressions in whatever branch happened to deploy next.
test_reassert_failure_names_the_missing_precondition_7962() {
	reset_cli_mock
	CLI_STATUS_RESPONSES=("$STATUS_INVERTED_RG0")
	# No LAN host reachable, so liveness CANNOT be primed: the fallback is the
	# only mechanism and the diagnosis must say the precondition was absent.
	local out rc=0
	out=$( CLUSTER_LAN_HOST= IPERF_TARGET4= \
		deploy_reassert_primary_node0 "fake:vm0" 2>&1 ) || rc=$?
	if (( rc != 0 )) && printf '%s' "$out" | grep -q "precondition was absent"; then
		ok "reassert: unprimed failure names the ABSENT PRECONDITION, not an HA regression"
	else
		bad "reassert: unprimed failure did not distinguish 'nothing drove traffic' from 'the dataplane is broken' (rc=$rc)"
	fi
}

# The other half of the same split: when traffic WAS driven and the state still
# did not converge, the gate must say so affirmatively — that one IS a signal.
test_reassert_failure_names_a_real_signal_when_primed_7962() {
	reset_cli_mock
	CLI_STATUS_RESPONSES=("$STATUS_INVERTED_RG0")
	local out rc=0
	out=$( CLUSTER_LAN_HOST="fake:lan" IPERF_TARGET4="10.0.0.1" \
		deploy_reassert_primary_node0 "fake:vm0" 2>&1 ) || rc=$?
	if (( rc != 0 )) && printf '%s' "$out" | grep -q "REAL dataplane/HA signal"; then
		ok "reassert: primed failure is reported as a REAL signal"
	else
		bad "reassert: primed failure did not report itself as a real signal (rc=$rc)"
	fi
}

test_reassert_issues_reset_transfer_reset_per_rg() {
	reset_cli_mock
	CLI_STATUS_RESPONSES=("$STATUS_BOTH_RG_NODE0_PRIMARY")
	( deploy_reassert_primary_node0 "fake:vm0" ) >/dev/null 2>&1 || true

	# #6591: a TRANSFER must be issued per RG, not just a reset. A reset alone
	# clears the manual flag and never MOVES ownership, which was the original
	# report.
	local rg missing=""
	for rg in 0 1; do
		grep -qx "request chassis cluster failover redundancy-group $rg node 0" "$CLI_LOG" \
			|| missing="$missing rg$rg"
		grep -qx "request chassis cluster failover reset redundancy-group $rg" "$CLI_LOG" \
			|| missing="$missing rg${rg}-reset"
	done
	if [[ -n "$missing" ]]; then
		bad "reassert: missing transfer/reset for:$missing (#6591 -- a reset alone never moves ownership)"
		return
	fi

	# #7771: the pin-clearing reset must come AFTER a status read that FOLLOWS
	# the transfer. The transfer IS the pin; clearing it before the transfer
	# commits loses the RG to the natural election on a non-preempting cluster.
	#
	# Asserted as an ORDERING over the full log, deliberately NOT as a literal
	# sequence: the previous version of this cell pinned the exact byte string
	# `reset|transfer|reset` per RG, which is the RACE written down as the
	# expected answer. It also `grep -v`'d the status reads out of the log, so
	# it could not have expressed this property even if someone had thought to
	# ask -- it discarded the evidence first.
	local n_lines
	n_lines=$(wc -l <"$CLI_LOG")
	for rg in 0 1; do
		local xfer_ln clear_ln status_between
		xfer_ln=$(grep -nx "request chassis cluster failover redundancy-group $rg node 0" "$CLI_LOG" | tail -1 | cut -d: -f1)
		# The FIRST reset issued after the transfer is the one that matters. An
		# earlier draft of this cell took the LAST one (`tail -1`) and was
		# INSENSITIVE to the defect: restoring the race adds a reset right after
		# the transfer, but a later phase-3 reset still satisfies "the last reset
		# comes after a status read". Measured -- that mutation passed this cell
		# and was caught only by the #7688 reset-COUNT cell next door.
		clear_ln=$(awk -v n="$xfer_ln" 'NR>n && $0=="request chassis cluster failover reset redundancy-group '"$rg"'" {print NR; exit}' "$CLI_LOG")
		if [[ -z "$clear_ln" ]]; then
			bad "reassert rg$rg: no pin-clearing reset issued after the transfer at line $xfer_ln -- the pin is left set, which blocks the next election (#7688)"
			return
		fi
		status_between=$(sed -n "$((xfer_ln+1)),$((clear_ln-1))p" "$CLI_LOG" | grep -cx 'show chassis cluster status')
		if (( status_between < 1 )); then
			bad "reassert rg$rg: the FIRST reset after the transfer (line $clear_ln) has NO status read between it and the transfer (line $xfer_ln, of $n_lines). That is the #7771 race: the reset wins and the RG falls back to the natural election."
			return
		fi
	done
	ok "reassert: transfer per RG, and the pin is cleared only after a status read confirms it (#6591 + #7771)"
}

test_reassert_clears_the_peer_manual_pin() {
	reset_cli_mock
	CLI_STATUS_RESPONSES=("$STATUS_BOTH_RG_NODE0_PRIMARY")
	( deploy_reassert_primary_node0 "fake:vm0" "fake:vm1" ) >/dev/null 2>&1 || true
	# Assert on the INSTANCE-bearing log, not $CLI_LOG. Keyed on $CLI_LOG this
	# cell would stay green with the peer reset deleted, because node0 is reset
	# twice per RG anyway and the texts are identical.
	local peer node0
	peer=$(grep -c '^exec fake:vm1 -- cli -c request chassis cluster failover reset redundancy-group' "$FAKE_CALL_LOG" || true)
	node0=$(grep -c '^exec fake:vm0 -- cli -c request chassis cluster failover reset redundancy-group' "$FAKE_CALL_LOG" || true)
	if (( peer == 2 && node0 == 4 )); then
		ok "reassert: clears the PEER's manual pin once per RG (peer=$peer, node0=$node0)"
	else
		bad "reassert: peer resets=$peer (want 2, one per RG), node0 resets=$node0 (want 4).
ManualFailover is local, unsynced state: a pin left on node1 is invisible to
node0's CLI and blocks the election the transfer depends on (#7688)."
	fi
}

test_reassert_call_site_passes_the_peer() {
	# Bind the WIRING, not just the function. The peer is an OPTIONAL second
	# argument -- deliberately, so the other reassert cells can keep driving the
	# single-node form -- which means a call site that omits it silently gets
	# the pre-#7688 one-sided behaviour while every other test here still
	# passes. Only reading the production call site can catch that.
	local f="${SCRIPT_DIR}/cluster-setup.sh"
	local call
	call=$(grep '^[[:space:]]*deploy_reassert_primary_node0 ' "$f" | head -1)
	if [[ "$call" == *'VM0'*'VM1'* ]]; then
		ok "reassert: cluster-setup.sh call site passes BOTH nodes"
	else
		bad "reassert: cluster-setup.sh passes no peer instance, so the peer pin
is never cleared and the deploy still fails its primary reassert (#7688).
  got: $call"
	fi
}

test_reassert_transfer_rc_is_not_the_verdict() {
	reset_cli_mock
	# Every request returns non-zero, but the cluster ends up correct. The
	# verdict is the OBSERVED ROLE, so this must succeed — otherwise a noisy
	# but harmless CLI rc would fail an otherwise good deploy.
	CLI_REQUEST_RC=1
	CLI_STATUS_RESPONSES=("$STATUS_BOTH_RG_NODE0_PRIMARY")
	local rc=0
	( deploy_reassert_primary_node0 "fake:vm0" ) >/dev/null 2>&1 || rc=$?
	if (( rc == 0 )); then
		ok "reassert: a failing request rc with the correct end state still passes (role is the verdict)"
	else
		bad "reassert: failed on a request rc despite node0 being primary everywhere (rc=$rc)"
	fi
}

# The WIRING. Every test above drives deploy_reassert_primary_node0 directly,
# so all of them stay green if cluster-setup.sh stops calling it — which is the
# mutation that actually matters, because the function only ever runs from
# there. It is also asserted to run after BOTH deploy paths (rolling and
# rolling-deb), since a reassert wired into one of them leaves the other
# handing the next smoke an un-reasserted cluster.
test_reassert_is_wired_into_both_deploy_paths() {
	local f="${SCRIPT_DIR}/cluster-setup.sh"
	local lib call n
	lib=$(_first_line_matching "$f" '^[[:space:]]*deploy_reassert_primary_node0 ')
	n=$(grep -c '^[[:space:]]*reassert_primary_node0$' "$f" || true)
	if [[ -z "$lib" ]]; then
		bad "wiring: cluster-setup.sh never calls deploy_reassert_primary_node0 — the fail-closed reassert exists but nothing invokes it, so a deploy reasserts nothing and still reports success (#6591)"
		return
	fi
	if (( n < 2 )); then
		bad "wiring: reassert_primary_node0 is called $n time(s); expected both deploy paths (deploy_rolling and deploy_rolling_deb)"
		return
	fi
	ok "wiring: reassert routed through the lib at :$lib and called from $n deploy paths"
}

# ── #7368 ownership-vs-forwarding cross-reference ────────────────────
# test-failover.sh asserted primacy with a grep over `show chassis cluster
# status` — a field the node reports about ITSELF — and separately asserted
# that the same node carries sessions, which is a real measurement. The two
# were never compared.
#
# #6656 is what that costs: node0 reported primary for every RG with 1 session
# while node1 carried 33. The session assertion DID fail, but reported a
# session-count shortfall, so the run read as "the streams did not establish"
# — attributed to whatever change was under test — when the actual failure was
# that ownership and forwarding disagreed.
#
# So the property is not "add an oracle"; the oracle was already there. It is
# "decide WHICH failure this is, and say so distinctly".

test_ownership_verdict_ok() {
	local got; got=$(failover_ownership_verdict 25 24 4)
	if [[ "$got" == "ok" ]]; then
		ok "ownership: primary carries the traffic -> ok"
	else
		bad "ownership: healthy run -> expected 'ok', got '$got'"
	fi
}

test_ownership_verdict_diverged() {
	# The #6656 shape exactly.
	local got; got=$(failover_ownership_verdict 1 33 4)
	if [[ "$got" == "diverged" ]]; then
		ok "ownership: reported-primary carries 1, peer carries 33 -> diverged"
	else
		bad "ownership: the #6656 divergence -> expected 'diverged', got '$got' (it would be reported as a session-count shortfall and blamed on the change under test)"
	fi
}

test_ownership_verdict_nostream() {
	# Neither node carries traffic: a real establishment failure, and a
	# DIFFERENT bug with a different fix. Reporting it as a divergence would
	# be the same conflation in the other direction.
	local got; got=$(failover_ownership_verdict 0 0 4)
	if [[ "$got" == "nostream" ]]; then
		ok "ownership: neither node carries traffic -> nostream (not a divergence)"
	else
		bad "ownership: no traffic anywhere -> expected 'nostream', got '$got'"
	fi
}

test_ownership_verdict_boundary_is_inclusive() {
	# Exactly at the minimum is HEALTHY. An exclusive boundary would report a
	# cluster meeting the documented threshold as diverged.
	local got; got=$(failover_ownership_verdict 4 4 4)
	if [[ "$got" == "ok" ]]; then
		ok "ownership: primary exactly at MIN_SESSIONS -> ok (inclusive)"
	else
		bad "ownership: primary at the minimum -> expected 'ok', got '$got'"
	fi
}

test_ownership_verdict_peer_below_min_is_not_divergence() {
	# The peer carrying a FEW synced sessions while the primary carries none is
	# still an establishment failure — session sync means the peer legitimately
	# holds sessions, so "peer has some" cannot be the discriminator.
	local got; got=$(failover_ownership_verdict 0 2 4)
	if [[ "$got" == "nostream" ]]; then
		ok "ownership: peer below the minimum -> nostream, not diverged"
	else
		bad "ownership: peer with 2 sessions -> expected 'nostream', got '$got' (session sync means the peer always holds some; 'peer has any' is not a divergence signal)"
	fi
}

# The WIRING. Every cell above calls the verdict directly, so all of them stay
# green if test-failover.sh stops consulting it — and the script is the only
# caller. Also asserts the three failure paths carry DISTINCT exit codes: a
# gate that exits 2 for a precondition abort, a failover regression AND a
# divergence teaches people to re-run it instead of reading it.
test_failover_script_wires_the_crossref() {
	local f="${SCRIPT_DIR}/test-failover.sh"
	local missing=() code
	# CODE ONLY. A first version grepped the raw file and both wiring cells
	# stayed GREEN under mutation, because the names it searched for also
	# appear in the COMMENTS explaining them — the guard was reading its own
	# documentation. Strip whole-line comments before matching.
	code=$(grep -v '^[[:space:]]*#' "$f")
	grep -q 'failover_ownership_verdict' <<<"$code" || missing+=("failover_ownership_verdict call")
	grep -q 'deploy_reassert_node0_primary_ok' <<<"$code" || missing+=("per-RG primacy predicate")
	grep -q 'die_divergence' <<<"$code" || missing+=("die_divergence")
	grep -q 'exit 3' <<<"$code" || missing+=("distinct divergence exit code")
	grep -q 'source .*deploy-lib.sh' <<<"$code" || missing+=("deploy-lib.sh source")
	if (( ${#missing[@]} == 0 )); then
		ok "wiring: test-failover.sh sources the lib, uses the per-RG predicate, cross-references, and exits distinctly"
	else
		bad "wiring: test-failover.sh is missing: ${missing[*]} — the verdict is selftested but nothing calls it (#7368)"
	fi
}

# The primacy predicate must be SCOPED per redundancy group. The retired grep
# was `node0.*primary` over the whole status output: `secondary` does not
# contain `primary`, so that part was sound, but the match is not scoped to an
# RG — a cluster with node0 SECONDARY for RG0 and primary for RG1 satisfied it.
test_primacy_predicate_is_scoped_per_rg() {
	local mixed="Redundancy group: 0 , Failover count: 0
node0   200       secondary      no       no       None
node1   100       primary        no       no       None

Redundancy group: 1 , Failover count: 0
node0   200       primary        no       no       None
node1   100       secondary      no       no       None
"
	if printf '%s' "$mixed" | grep -q "node0.*primary"; then
		: # the retired grep DOES match this -- that is the point
	else
		bad "primacy: fixture no longer reproduces the retired grep's false accept"
		return
	fi
	if printf '%s' "$mixed" | deploy_reassert_node0_primary_ok; then
		bad "primacy: node0 is SECONDARY for RG0 and the predicate accepted it — the preflight would run a failover test against a cluster that is not in the asserted state (#7368)"
	else
		ok "primacy: node0 secondary for RG0 -> rejected (the retired whole-output grep accepted it)"
	fi
}

# ── #7368 (rejoin phase): the same unscoped shape, both roles ────────
# test_primacy_predicate_is_scoped_per_rg above covers the DEPLOY precondition.
# These cover test-failover.sh's post-reboot rejoin assertions, which kept the
# retired whole-output form after #7368 fixed the precondition.
#
# The rejoin check is an if/elif: `secondary` is tried first and `primary`
# second. So the mixed state does not merely slip past one assertion — it
# matches the FIRST branch and reports PASS, which makes the elif that names
# the auto-preempt regression unreachable in the exact case it was written for.
# The property is therefore two-sided: a mixed state must be rejected by BOTH
# roles, so the phase falls through to its failure branch.

STATUS_REJOIN_CLEAN="Redundancy group: 0 , Failover count: 1
node0   200       secondary      no       no       None
node1   100       primary        no       no       None

Redundancy group: 1 , Failover count: 1
node0   200       secondary      no       no       None
node1   100       primary        no       no       None
"

# node0 auto-preempted for RG1 only. The regression, on a subset of RGs.
STATUS_REJOIN_MIXED_PREEMPT="Redundancy group: 0 , Failover count: 1
node0   200       secondary      no       no       None
node1   100       primary        no       no       None

Redundancy group: 1 , Failover count: 1
node0   200       primary        no       no       None
node1   100       secondary      no       no       None
"

test_rejoin_predicate_rejects_mixed_preempt() {
	# Reproduce the retired grep's false accept first, so this cell cannot
	# quietly stop testing the thing it was written for.
	if printf '%s' "$STATUS_REJOIN_MIXED_PREEMPT" | grep -q "node0.*secondary"; then
		: # the retired grep matches -> old code took the PASS branch
	else
		bad "rejoin: fixture no longer reproduces the retired grep's false accept"
		return
	fi
	if printf '%s' "$STATUS_REJOIN_MIXED_PREEMPT" | deploy_node_role_every_rg_ok node0 secondary; then
		bad "rejoin: node0 is PRIMARY for RG1 and the secondary predicate accepted it — this is the auto-preempt regression reported as PASS (#7368 shape)"
		return
	fi
	# ...and the elif must not rescue it either, or a mixed state would be
	# reported as a clean full preempt instead of the partial state it is.
	if printf '%s' "$STATUS_REJOIN_MIXED_PREEMPT" | deploy_node_role_every_rg_ok node0 primary; then
		bad "rejoin: mixed state accepted as primary-for-every-RG; the phase would name the wrong failure"
		return
	fi
	ok "rejoin: RG1-only auto-preempt -> rejected by BOTH roles, so the phase fails"
}

test_rejoin_predicate_accepts_clean_rejoin() {
	if ! printf '%s' "$STATUS_REJOIN_CLEAN" | deploy_node_role_every_rg_ok node0 secondary; then
		bad "rejoin: rejected a correct no-auto-preempt rejoin (node0 secondary for every RG)"
		return
	fi
	if ! printf '%s' "$STATUS_REJOIN_CLEAN" | deploy_node_role_every_rg_ok node1 primary; then
		bad "rejoin: rejected node1 primary for every RG on a clean rejoin"
		return
	fi
	ok "rejoin: clean rejoin (node0 secondary / node1 primary for every RG) -> accept"
}

test_rejoin_predicate_names_full_preempt() {
	if printf '%s' "$STATUS_BOTH_RG_NODE0_PRIMARY" | deploy_node_role_every_rg_ok node0 secondary; then
		bad "rejoin: accepted a fully auto-preempted node0 as secondary"
		return
	fi
	if ! printf '%s' "$STATUS_BOTH_RG_NODE0_PRIMARY" | deploy_node_role_every_rg_ok node0 primary; then
		bad "rejoin: full auto-preempt not recognised as primary-for-every-RG, so the phase cannot name it"
		return
	fi
	ok "rejoin: full auto-preempt -> secondary rejects, primary accepts (the elif names it correctly)"
}

test_rejoin_predicate_rejects_empty() {
	# Fail-closed, same reason as #6591: an unreadable status is not "fine".
	if printf '%s' "" | deploy_node_role_every_rg_ok node0 secondary; then
		bad "rejoin: accepted an EMPTY status — an unreadable cluster status must FAIL, not pass vacuously"
	else
		ok "rejoin: empty/unreadable status -> reject"
	fi
}

test_rejoin_site_uses_the_scoped_predicate() {
	local f="$SCRIPT_DIR/test-failover.sh" code missing=()
	code=$(grep -v '^[[:space:]]*#' "$f")
	grep -q 'deploy_node_role_every_rg_ok node0 secondary' <<<"$code" || missing+=("scoped node0-secondary rejoin check")
	grep -q 'deploy_node_role_every_rg_ok node1 primary' <<<"$code" || missing+=("scoped node1-primary rejoin check")
	# The retired UNSCOPED form must not come back. The test that matters is
	# scoped-ness, not the substring: the failback loop legitimately writes
	# `grep -A1 "Redundancy group: $rg" | grep -q "node0.*primary"`, and an
	# earlier revision of this guard banned the substring outright and red on
	# exactly that shape. A control cell proved it, so the ban now fires only on
	# a role grep that is NOT scoped to a redundancy group on the same line.
	local unscoped
	unscoped=$(grep -E 'grep -q "node[01]\.\*(primary|secondary)"' <<<"$code" \
		| grep -v 'Redundancy group:' || true)
	[[ -z "$unscoped" ]] || missing+=("retired UNSCOPED role grep is back: ${unscoped//$'\n'/ ; }")
	if (( ${#missing[@]} == 0 )); then
		ok "rejoin: test-failover.sh uses the per-RG predicate for both roles and the unscoped greps are gone"
	else
		bad "rejoin: test-failover.sh wiring incomplete: ${missing[*]}"
	fi
}

# ── Run ───────────────────────────────────────────────────────────────
test_rolling_secondary_node0_primary
test_rolling_secondary_node0_secondary
test_rolling_secondary_multi_rg_scoped_to_rg0
test_rolling_secondary_hold_counts_as_secondary
test_rolling_secondary_peer_down_defaults
test_rolling_secondary_empty_defaults
test_rolling_rg_ids
test_verify_pushed_sha_match
test_verify_pushed_sha_mismatch_hardfails
test_verify_pushed_sha_absent_hardfails
test_reconcile_stale_pin_removes_managed
test_reconcile_stale_pin_no_pin_noop
test_reconcile_stale_pin_foreign_override_hardfails
test_reconcile_dangling_sbin_removes
test_reconcile_dangling_sbin_keeps_valid
test_verify_running_match
test_running_sha_returns_the_live_sha
test_running_sha_empty_instance_does_not_read_the_local_host
test_verify_running_stale_pin_hardfails
test_verify_running_stale_binary_hardfails
test_reassert_verifier_accepts_all_primary
test_reassert_verifier_rejects_inverted
test_reassert_verifier_rejects_partial
test_reassert_verifier_rejects_empty
test_reassert_dies_when_status_never_readable
test_reassert_retries_status_read_until_settled
test_reassert_dies_when_role_not_achieved
test_reassert_issues_reset_transfer_reset_per_rg
test_reassert_failure_names_the_missing_precondition_7962
test_reassert_failure_names_a_real_signal_when_primed_7962
test_reassert_transfer_rc_is_not_the_verdict
test_reassert_is_wired_into_both_deploy_paths
test_reassert_clears_the_peer_manual_pin
test_reassert_call_site_passes_the_peer
test_ownership_verdict_ok
test_ownership_verdict_diverged
test_ownership_verdict_nostream
test_ownership_verdict_boundary_is_inclusive
test_ownership_verdict_peer_below_min_is_not_divergence
test_failover_script_wires_the_crossref
test_primacy_predicate_is_scoped_per_rg
test_rejoin_predicate_rejects_mixed_preempt
test_rejoin_predicate_accepts_clean_rejoin
test_rejoin_predicate_names_full_preempt
test_rejoin_predicate_rejects_empty
test_rejoin_site_uses_the_scoped_predicate
test_preflight_pass_proceeds
test_preflight_reject_hardfails
test_preflight_reject_touches_nothing
test_preflight_cleans_up_on_pass
test_preflight_cleans_up_on_reject
test_preflight_verifier_reject_prescribes_1864_remediation
test_preflight_other_refusal_prescribes_no_make_generate
test_preflight_missing_local_binary_hardfails
test_preflight_precedes_destructive_steps_standalone
test_preflight_precedes_destructive_steps_cluster

echo "----------------------------------------"
echo "deploy-lib selftest: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
