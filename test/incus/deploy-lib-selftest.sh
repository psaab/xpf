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
FAKE_HELPER_PIDS=""
FAKE_EXECSTART="/usr/local/sbin/xpfd"
# #6493: verdict the fake `xpfd verify-dataplane` probe returns, and an ordered
# log of every incus call the lib made. The log is what lets a test assert what
# did NOT happen (no stop, no push to /usr/local/sbin) on the REJECT path — the
# ordering invariant the pre-flight exists to hold.
FAKE_VERIFY_RC=0
FAKE_UID=0
FAKE_HELPER_SYMLINK=0
FAKE_HELPER_LINK_UID=0
# A FILE, not an array: every call under test runs in a subshell (die() exits,
# so the rc has to be caught), and an array mutated in a subshell is discarded
# on return. A file survives, so "what did NOT happen" is still assertable
# after the abort.
FAKE_CALL_LOG=""
# #10026: verdict the fake `apt-get install` returns (0 = installed), and the
# file-backed mktemp sequence. The sequence MUST be file-backed (cf.
# CLI_IDX_FILE): _fake_exec runs in a command-substitution subshell, so a
# variable counter would stick at 0 and every slot would collide — the exact
# fixture defect that would blind the re-push regression cell.
# Rejecting an existing target models the Incus same-name re-push collision.
FAKE_REJECT_EXISTING=0
FAKE_MKTEMP_SEQ=""
# #18544: the fragment systemd has LOADED for each unit, one file per unit in
# this directory. Like FAKE_MKTEMP_SEQ it lives on disk, for the same subshell
# reason. It changes only on fake_systemd_boot and `systemctl daemon-reload`,
# never when a unit file is written or removed. That gap lets a cell catch a
# reconcile that edits the disk but forgets to reload. The directory exists
# only after a cell calls fake_systemd_boot, so other cells' daemon-reloads
# leave the fake VM tree untouched.
FAKE_SYSTEMD_DIR=""
FAKE_SYSTEMD_UNITS=(xpfd.service xpf-transit-closed.service xpf-input-closed.service)
# A remote path that the fake `rm`/`mv` reports as moved or removed but leaves
# in place. A removal that reports success says nothing about the unit systemd
# has loaded.
FAKE_REMOVE_NOOP_PATH=""
# "<unit>=<state>": systemd REJECTS that unit's packaged file and reports
# <state> (e.g. bad-setting, as for a directive the node's systemd does not
# know). It applies only while the packaged file is the loaded one.
FAKE_LOADSTATE_OVERRIDE=""
# When set to N, the Nth and every later `systemctl daemon-reload` fails
# (rc 1) and reloads nothing. The count lives in a file (subshells).
FAKE_RELOAD_FAIL_FROM=""

setup_fake_vm() {
	FAKE_VM=$(mktemp -d)
	FAKE_MAINPID="0"
	FAKE_HELPER_PIDS=""
	FAKE_EXECSTART="/usr/local/sbin/xpfd"
	FAKE_VERIFY_RC=0
	FAKE_UID=0
	FAKE_HELPER_SYMLINK=0
	FAKE_HELPER_LINK_UID=0
	FAKE_CALL_LOG=$(mktemp)
	FAKE_APT_RC=0
	FAKE_REJECT_EXISTING=0
	FAKE_MKTEMP_SEQ=$(mktemp)
	printf '0' > "$FAKE_MKTEMP_SEQ"
	FAKE_SYSTEMD_DIR="$FAKE_VM/run/fake-systemd"
	FAKE_REMOVE_NOOP_PATH=""
	FAKE_LOADSTATE_OVERRIDE=""
	FAKE_RELOAD_FAIL_FROM=""
	mkdir -p "$FAKE_VM/usr/local/sbin" "$FAKE_VM/etc/systemd/system" "$FAKE_VM/tmp"
}

# _fake_systemd_resolve <unit> prints the fragment systemd would load for
# <unit> from the fake disk right now, in unit search-path order: /etc, then
# /run/systemd/system and /usr/local/lib (both of which /etc outranks), then
# the package dirs. A symlink counts, as a mask or alias does for systemd. It
# prints nothing when no unit exists.
_fake_systemd_resolve() {
	local d
	for d in etc/systemd/system run/systemd/system usr/local/lib/systemd/system \
		usr/lib/systemd/system lib/systemd/system; do
		if [[ -e "$FAKE_VM/$d/$1" || -L "$FAKE_VM/$d/$1" ]]; then
			printf '/%s/%s\n' "$d" "$1"
			return 0
		fi
	done
}

# _fake_systemd_reload: re-read the disk for every modeled unit.
_fake_systemd_reload() {
	local u
	mkdir -p "$FAKE_SYSTEMD_DIR"
	for u in "${FAKE_SYSTEMD_UNITS[@]}"; do
		_fake_systemd_resolve "$u" >"$FAKE_SYSTEMD_DIR/$u.fragment"
	done
}

# fake_systemd_boot: systemd loads whatever units the fake disk holds now.
fake_systemd_boot() { _fake_systemd_reload; }

# fake_systemd_loaded <unit>: the fragment systemd currently has loaded.
fake_systemd_loaded() {
	cat "$FAKE_SYSTEMD_DIR/$1.fragment" 2>/dev/null
}

# fake_systemd_set_loaded <unit> <path>: model a stale load.
fake_systemd_set_loaded() {
	printf '%s\n' "$2" >"$FAKE_SYSTEMD_DIR/$1.fragment"
}

# _fake_systemd_loadstate <unit>: LoadState for the loaded fragment.
_fake_systemd_loadstate() {
	local frag
	frag=$(fake_systemd_loaded "$1")
	if [[ -z "$frag" ]]; then
		echo not-found
	elif [[ "$(readlink "$FAKE_VM$frag" 2>/dev/null)" == /dev/null ]]; then
		echo masked
	elif [[ "$FAKE_LOADSTATE_OVERRIDE" == "$1="* && ( "$frag" == /usr/lib/* || "$frag" == /lib/* ) ]]; then
		echo "${FAKE_LOADSTATE_OVERRIDE#*=}"
	else
		echo loaded
	fi
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
	FAKE_HELPER_PIDS=""
	FAKE_REJECT_EXISTING=0
	[[ -n "$FAKE_MKTEMP_SEQ" ]] && rm -f "$FAKE_MKTEMP_SEQ"
	FAKE_MKTEMP_SEQ=""
	FAKE_SYSTEMD_DIR=""
	FAKE_REMOVE_NOOP_PATH=""
	FAKE_LOADSTATE_OVERRIDE=""
	FAKE_RELOAD_FAIL_FROM=""
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
		# Like the real client, `incus exec` without -n reads its stdin (#9683).
		# Inside a `while read ... done <<<"$list"` loop that drains the rest of
		# the list, so the loop body runs once. Emulate it, or every cell here is
		# blind to a lib call that forgets -n. The drain never blocks: it reads
		# only input that is already there, and it leaves a terminal alone.
		local drain=1
		while [[ "$1" == -* && "$1" != "--" ]]; do
			[[ "$1" == "-n" || "$1" == "--disable-stdin" ]] && drain=0
			shift
		done
		shift          # instance name
		[[ "$1" == "--" ]] && shift
		if (( drain )) && [[ ! -t 0 ]]; then
			while read -r -t 0 _ && IFS= read -r _; do :; done
		fi
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
			# Incus rejects an existing fixed destination in the same way the
			# live validation did for a same-name re-push (#10026).
			if [[ "${FAKE_REJECT_EXISTING:-0}" == "1" && -e "$target" ]]; then
				echo "Error: target already exists $target" >&2
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
		# test -L <path>  /  deploy_reconcile_unit_shadow's mask guard
		if [[ "$1" == "-L" ]]; then
			[[ -L "$FAKE_VM/${2#/}" ]]
			return $?
		fi
		# test -e <path>  /  its free-/etc-path check before a restore
		if [[ "$1" == "-e" ]]; then
			[[ -e "$FAKE_VM/${2#/}" ]]
			return $?
		fi
		return 2
		;;
	rm)
		shift
		while [[ "${1:-}" == -* ]]; do shift; done
		local remote_path="${1:-}" rel
		[[ -n "$remote_path" && "$remote_path" == /* && "$remote_path" != "/" ]] || return 2
		# #18544: report success and remove nothing for the armed path.
		[[ -n "$FAKE_REMOVE_NOOP_PATH" && "$remote_path" == "$FAKE_REMOVE_NOOP_PATH" ]] && return 0
		rel="${remote_path#/}"
		rm -rf -- "$FAKE_VM/${rel:?}"
		return 0
		;;
	mv)
		# mv -f <src> <dst>, both VM paths (#18544 parks a unit file).
		shift
		[[ "${1:-}" == -f ]] && shift
		local mv_src="${1:-}" mv_dst="${2:-}"
		[[ "$mv_src" == /* && "$mv_dst" == /* ]] || return 2
		[[ -n "$FAKE_REMOVE_NOOP_PATH" && "$mv_src" == "$FAKE_REMOVE_NOOP_PATH" ]] && return 0
		mv -f "$FAKE_VM/${mv_src#/}" "$FAKE_VM/${mv_dst#/}"
		return $?
		;;
	mkdir)
		shift
		[[ "${1:-}" == -p ]] && shift
		[[ "${1:-}" == /* ]] || return 2
		mkdir -p "$FAKE_VM/${1#/}"
		return $?
		;;
	find)
		# find <dir> -mindepth 2 -maxdepth 2 -type l -name <unit>: the
		# install-link scan. Paths come back as VM paths.
		shift
		local find_dir="$1"
		shift
		[[ "$find_dir" == /* ]] || return 2
		[[ -d "$FAKE_VM$find_dir" ]] || return 1
		find "$FAKE_VM$find_dir" "$@" | sed "s|^$FAKE_VM||"
		return 0
		;;
	readlink)
		# readlink <path>: the literal link target, as on the VM.
		shift
		readlink "$FAKE_VM/${1#/}"
		return $?
		;;
	ln)
		# ln -sfn <target> <link>: the target is stored verbatim (a VM path);
		# only the link itself lives under $FAKE_VM.
		shift
		[[ "$1" == "-sfn" ]] || return 2
		local ln_target="$2" ln_link="$3"
		[[ "$ln_link" == /* ]] || return 2
		mkdir -p "$(dirname "$FAKE_VM/${ln_link#/}")"
		ln -sfn "$ln_target" "$FAKE_VM/${ln_link#/}"
		return $?
		;;
	mktemp)
		shift
		local make_dir=0 tmpl seq slot
		while [[ "${1:-}" == -* ]]; do
			[[ "$1" == "-d" ]] && make_dir=1
			shift
		done
		# mktemp <template> — replace the X-run with a file-backed sequence
		# so every call yields a distinct slot (the #10026 property).
		tmpl="${1:-/tmp/tmp.XXXXXXXXXX}"
		seq=$(cat "$FAKE_MKTEMP_SEQ" 2>/dev/null || echo 0)
		seq=$((seq + 1))
		printf '%s' "$seq" > "$FAKE_MKTEMP_SEQ"
		slot=$(sed -E "s/X+/$(printf '%06d' "$seq")/" <<<"$tmpl")
		if (( make_dir )); then
			mkdir -p "$FAKE_VM/${slot#/}"
		else
			mkdir -p "$FAKE_VM/$(dirname "${slot#/}")"
			: > "$FAKE_VM/${slot#/}"
		fi
		printf '%s\n' "$slot"
		return 0
		;;
	apt-get)
		# apt-get install -y --reinstall <slot> — the install step of
		# deploy_install_deb. Succeeds unless a test arms FAKE_APT_RC;
		# the call log records the exact slot installed.
		return "${FAKE_APT_RC:-0}"
		;;
	systemctl)
		shift
		case "$1" in
		daemon-reload)
			# #18544: reload re-reads the disk, but only once a cell has
			# booted the fake systemd (see FAKE_SYSTEMD_DIR).
			if [[ -n "$FAKE_RELOAD_FAIL_FROM" && -d "$FAKE_SYSTEMD_DIR" ]]; then
				local reload_n
				reload_n=$(( $(cat "$FAKE_SYSTEMD_DIR/reload.count" 2>/dev/null || echo 0) + 1 ))
				printf '%s' "$reload_n" >"$FAKE_SYSTEMD_DIR/reload.count"
				(( reload_n >= FAKE_RELOAD_FAIL_FROM )) && return 1
			fi
			if [[ -n "$FAKE_SYSTEMD_DIR" && -d "$FAKE_SYSTEMD_DIR" ]]; then
				_fake_systemd_reload
			fi
			return 0
			;;
		show)
			# systemctl show -p ExecStart --value xpfd  => emit a
			# "{ path=... ; ... }" line; -p MainPID --value => the pid;
			# -p FragmentPath/LoadState --value <unit> => the LOADED
			# fragment and its state (#18544); <unit> is the last arg.
			if [[ "$*" == *FragmentPath* ]]; then
				fake_systemd_loaded "${!#}"
			elif [[ "$*" == *LoadState* ]]; then
				[[ -d "$FAKE_SYSTEMD_DIR" ]] && _fake_systemd_loadstate "${!#}"
			elif [[ "$*" == *ExecStart* ]]; then
				echo "{ path=$FAKE_EXECSTART ; argv[]=$FAKE_EXECSTART ; ... }"
			elif [[ "$*" == *MainPID* ]]; then
				echo "$FAKE_MAINPID"
			fi
			return 0
			;;
		esac
		return 0
		;;
	stat)
		shift
		local stat_uid="$FAKE_UID" followed=0
		if [[ "$1" == "-L" ]]; then
			followed=1
			shift
		fi
		if [[ "$1" == "-c" && "$2" == "%u" && -n "$stat_uid" ]]; then
			if [[ "$FAKE_HELPER_SYMLINK" == "1" && $followed -eq 0 ]]; then
				stat_uid="$FAKE_HELPER_LINK_UID"
			fi
			printf '%s\n' "$stat_uid"
			return 0
		fi
		return 1
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
	# deploy_running_xpf_userspace_dp_sha256: exactly one helper PID is
	# required; a missing or duplicated helper must not fall back to disk.
	if [[ "$body" == *"pidof xpf-userspace-dp"* ]]; then
		local helper_pids="$FAKE_HELPER_PIDS"
		# Match the remote `set -- $pids; [ "$#" -eq 1 ]` guard.
		read -r -a helper_pid_array <<<"$helper_pids"
		(( ${#helper_pid_array[@]} == 1 )) || return 1
		sha256sum "$FAKE_VM/usr/local/sbin/xpf-userspace-dp" 2>/dev/null || return 1
		return 0
	fi
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
# #12658: optional function that ANSWERS a status read from what has been
# issued so far (it reads $CLI_LOG), for cells where ownership must move only
# in response to a command -- e.g. a transfer that lands only when re-sent. A
# fixed response queue cannot express that: it advances per read, not per
# command, so a reassert that never re-sent would converge all the same.
CLI_STATUS_FN=""

_fake_cli_status() {
	if [[ -n "$CLI_STATUS_FN" ]]; then
		"$CLI_STATUS_FN"
		return $?
	fi
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
	CLI_STATUS_FN=""
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

test_verify_pushed_uid_root_passes() {
	setup_fake_vm
	FAKE_UID=0
	if deploy_verify_pushed_uid vm /usr/local/sbin/xpf-userspace-dp xpf-userspace-dp >/dev/null 2>&1; then
		ok "verify_pushed_uid: root-owned helper passes"
	else
		bad "verify_pushed_uid: root-owned helper should pass"
	fi
	teardown_fake_vm
}

test_verify_pushed_uid_nonroot_hardfails() {
	setup_fake_vm
	FAKE_UID=1000
	if ( deploy_verify_pushed_uid vm /usr/local/sbin/xpf-userspace-dp xpf-userspace-dp ) >/dev/null 2>&1; then
		bad "verify_pushed_uid: non-root helper MUST hard-fail"
	else
		ok "verify_pushed_uid: non-root helper hard-fails"
	fi
	teardown_fake_vm
}
test_verify_pushed_uid_follows_symlink_hardfails() {
	setup_fake_vm
	FAKE_UID=1000
	FAKE_HELPER_SYMLINK=1
	FAKE_HELPER_LINK_UID=0
	if ( deploy_verify_pushed_uid vm /usr/local/sbin/xpf-userspace-dp xpf-userspace-dp ) >/dev/null 2>&1; then
		bad "verify_pushed_uid: must check a symlink target, not its root-owned link"
	else
		ok "verify_pushed_uid: follows helper symlink and rejects non-root target"
	fi
	teardown_fake_vm
}

test_verify_pushed_uid_empty_hardfails() {
	setup_fake_vm
	FAKE_UID=""
	if ( deploy_verify_pushed_uid vm /usr/local/sbin/xpf-userspace-dp xpf-userspace-dp ) >/dev/null 2>&1; then
		bad "verify_pushed_uid: empty readback MUST hard-fail"
	else
		ok "verify_pushed_uid: empty readback hard-fails"
	fi
	teardown_fake_vm
}

test_cluster_helper_raw_deploy_uses_root_ownership() {
	local f="$SCRIPT_DIR/cluster-setup.sh" body
	body=$(awk '/^deploy_vm\(\) \{/{f=1} f{print} f&&/^\}$/{exit}' "$f")
	if [[ -z "$body" ]]; then
		bad "cluster helper ownership wiring: could not extract deploy_vm"
		return
	fi
	if grep -Fq 'incus file push "$PROJECT_ROOT/xpf-userspace-dp" "${rinst}/usr/local/sbin/xpf-userspace-dp" --uid 0 --gid 0 --mode 0755' <<<"$body" &&
		grep -Fq 'deploy_verify_pushed_sha "$rinst" "$PROJECT_ROOT/xpf-userspace-dp" /usr/local/sbin/xpf-userspace-dp xpf-userspace-dp' <<<"$body" &&
		grep -Fq 'deploy_verify_pushed_uid "$rinst" /usr/local/sbin/xpf-userspace-dp xpf-userspace-dp' <<<"$body"; then
		ok "cluster helper ownership wiring: root-owned push keeps sha and uid verification"
	else
		bad "cluster helper ownership wiring: push must pin uid/gid 0 and verify both sha and uid"
	fi
}
test_standalone_helper_raw_deploy_uses_root_ownership() {
	local f="$SCRIPT_DIR/setup.sh" body
	body=$(awk '/^cmd_deploy\(\) \{/{f=1} f{print} f&&/^\}$/{exit}' "$f")
	if [[ -z "$body" ]]; then
		bad "standalone helper ownership wiring: could not extract cmd_deploy"
		return
	fi
	if grep -Fq 'incus file push "$PROJECT_ROOT/xpf-userspace-dp" "$INSTANCE_NAME/usr/local/sbin/xpf-userspace-dp" --uid 0 --gid 0 --mode 0755' <<<"$body" &&
		grep -Fq 'deploy_verify_pushed_sha "$INSTANCE_NAME" "$PROJECT_ROOT/xpf-userspace-dp" /usr/local/sbin/xpf-userspace-dp xpf-userspace-dp' <<<"$body" &&
		grep -Fq 'deploy_verify_pushed_uid "$INSTANCE_NAME" /usr/local/sbin/xpf-userspace-dp xpf-userspace-dp' <<<"$body"; then
		ok "standalone helper ownership wiring: root-owned push keeps sha and uid verification"
	else
		bad "standalone helper ownership wiring: push must pin uid/gid 0 and verify both sha and uid"
	fi
}

# #10026 regression: two installs of the same local filename must not reuse a
# fixed remote /tmp/<basename> destination. The fake Incus rejects overwrite,
# matching the live permission-denied collision from #9486 validation. The
# chosen remediation is disambiguation: each attempt gets a distinct remote
# directory, and both directories are cleaned after apt succeeds.
test_deb_repush_uses_distinct_remote_slots() {
	setup_fake_vm
	local deb slots slot_count stale=0
	deb=$(mktemp --suffix=.deb)
	make_local_bin "$deb" "DEB-BYTES"
	FAKE_REJECT_EXISTING=1
	if ! deploy_install_deb vm "$deb" >/dev/null 2>&1 ||
		! deploy_install_deb vm "$deb" >/dev/null 2>&1; then
		bad "deb re-push: same-name installs must use distinct remote slots"
		rm -f "$deb"; teardown_fake_vm
		return
	fi
	slots=$(grep -oE '/tmp/xpf-deb\.[0-9]+' "$FAKE_CALL_LOG" | sort -u)
	slot_count=$(printf '%s\n' "$slots" | sed '/^$/d' | wc -l)
	if (( slot_count != 2 )); then
		bad "deb re-push: expected two distinct remote slots, got $slot_count"
		rm -f "$deb"; teardown_fake_vm
		return
	fi
	for slot in $slots; do
		if [[ -e "$FAKE_VM/${slot#/}" ]]; then
			stale=1
		fi
		if ! grep -Fq "apt-get install -y --reinstall ${slot}/" "$FAKE_CALL_LOG"; then
			bad "deb re-push: apt did not install the deb from its pushed slot $slot"
			rm -f "$deb"; teardown_fake_vm
			return
		fi
	done
	if (( stale )); then
		bad "deb re-push: temporary remote slots were not cleaned"
	else
		ok "deb re-push: same-name installs use distinct cleaned remote slots"
	fi
	rm -f "$deb"; teardown_fake_vm
}

# The helper behavior test above is not enough if the deploy script stops
# calling it. Pin the production wiring and reject the retired fixed path.
# ── #18772/#18764: the deb deploy plan ─────────────────────────────────
test_deb_plan_orders_versions() {
	local bad_rows="" row deb run want got
	for row in "0.0.29582+gfcc612e43943 0.0.29579+g218c32023079 upgrade" \
		"0.0.29579+g218c32023079 0.0.29582+gfcc612e43943 downgrade" \
		"0.0.29582+gfcc612e43943 0.0.29582+gfcc612e43943 same" \
		"0.0.10 0.0.9 upgrade" \
		"0.0.9 - fresh"; do
		read -r deb run want <<<"$row"
		[[ "$run" == - ]] && run=""
		got=$(deploy_deb_plan "$deb" "$run")
		[[ "$got" == "$want" ]] || bad_rows+=" [$deb vs '$run': $got, want $want]"
	done
	if [[ -z "$bad_rows" ]]; then
		ok "deb plan: dpkg ordering gives upgrade, downgrade, same and fresh (numeric, not lexical)"
	else
		bad "deb plan: wrong verdicts:$bad_rows"
	fi
}

# _plan_action <running-version> <runs-deb 0|1> [allow]: deploy_deb_node_action
# for a deb of version 0.0.29580 against a mocked node. Prints
# "<rc>|<stdout>|<stderr>".
_plan_action() {
	local run="$1" same_bytes="$2" allow="${3:-}" out err rc d
	d=$(mktemp -d)
	: >"$d/xpf_0.0.29580+gaaaaaaaaaaaa_amd64.deb"
	(
		deploy_running_deb_version() { printf '%s\n' "$run"; }
		deploy_node_runs_deb() { [[ "$same_bytes" == 1 ]]; }
		if [[ -n "$allow" ]]; then export XPF_DEPLOY_ALLOW_DOWNGRADE="$allow"; else unset XPF_DEPLOY_ALLOW_DOWNGRADE; fi
		deploy_deb_node_action inst:vm "$d/xpf_0.0.29580+gaaaaaaaaaaaa_amd64.deb" >"$d/out" 2>"$d/err"
	)
	rc=$?
	printf '%s|%s|%s' "$rc" "$(<"$d/out")" "$(<"$d/err")"
	rm -rf "$d"
}

test_deb_node_action_upgrade_installs() {
	local got
	got=$(_plan_action 0.0.29570+gbbbbbbbbbbbb 0)
	if [[ "$got" == "0|install|" ]]; then
		ok "deb plan: an upgrade installs, with no downgrade flag"
	else
		bad "deb plan: an upgrade must print install (got $got)"
	fi
}

test_deb_node_action_downgrade_refused_without_optin() {
	local got allow fails=""
	# The opt-in is bound to the deb's exact version: a bare 1, a boolean, or
	# another version (a stale export from an earlier cell) authorizes nothing.
	for allow in "" true yes 0 1 0.0.29579+gaaaaaaaaaaaa 0.0.29580; do
		got=$(_plan_action 0.0.29590+gcccccccccccc 0 "$allow")
		[[ "${got%%|*}" == 1 && "$got" == *"xpf_0.0.29580+gaaaaaaaaaaaa is not newer than the running 0.0.29590+gcccccccccccc on inst:vm"* &&
			"$got" == *"scripts/next-deb-version.sh"* && "$got" == *"XPF_DEPLOY_ALLOW_DOWNGRADE=0.0.29580+gaaaaaaaaaaaa"* ]] ||
			fails+=" [allow='$allow': $got]"
		[[ "$got" == 1\|\|* ]] || fails+=" [allow='$allow': printed an action]"
	done
	if [[ -z "$fails" ]]; then
		ok "deb plan: a downgrade is refused up front, naming both versions and the fix, unless XPF_DEPLOY_ALLOW_DOWNGRADE is that deb's exact version"
	else
		bad "deb plan: a downgrade without the exact opt-in must be refused:$fails"
	fi
}

test_deb_node_action_downgrade_optin() {
	local got
	got=$(_plan_action 0.0.29590+gcccccccccccc 0 0.0.29580+gaaaaaaaaaaaa)
	if [[ "$got" == "0|install-downgrade|" ]]; then
		ok "deb plan: XPF_DEPLOY_ALLOW_DOWNGRADE=<that deb's version> turns a downgrade into install-downgrade"
	else
		bad "deb plan: the opted-in downgrade must print install-downgrade (got $got)"
	fi
}

test_deb_node_action_same_version() {
	local same diff
	same=$(_plan_action 0.0.29580+gaaaaaaaaaaaa 1)
	diff=$(_plan_action 0.0.29580+gaaaaaaaaaaaa 0 0.0.29580+gaaaaaaaaaaaa)
	if [[ "$same" == "0|skip-same|" && "${diff%%|*}" == 1 && "$diff" == *"not these bytes"* &&
		"$diff" == *"scripts/next-deb-version.sh"* ]]; then
		ok "deb plan: the same version byte for byte is skip-same; same version with other bytes is refused, even opted in"
	else
		bad "deb plan: same version must skip when identical and refuse otherwise (identical: $same; different: $diff)"
	fi
}

test_deb_node_runs_deb_compares_both_binaries() {
	local fails="" case_ expect
	# Each case: which binary differs (or is unreadable) on the node; "-" means none.
	for case_ in "- 0" "run-xpfd 1" "run-helper 1" "live-xpfd 1" "live-cli 1" "live-xpf-userspace-dp 1" "live-xpf-day0-config 1" "unread-cli 1"; do
		read -r _ck_odd expect <<<"$case_"
		(
			deploy_manifest_sha_from_deb() { echo "sha-$2"; }
			deploy_running_xpfd_sha256() { [[ "$_ck_odd" == run-xpfd ]] && echo other || echo sha-xpfd; }
			deploy_running_xpf_userspace_dp_sha256() { [[ "$_ck_odd" == run-helper ]] && echo other || echo sha-xpf-userspace-dp; }
			deploy_live_version_bin_sha256() {
				[[ "$_ck_odd" == "unread-$2" ]] && return 1
				[[ "$_ck_odd" == "live-$2" ]] && echo other || echo "sha-$2"
			}
			deploy_node_runs_deb inst:vm /dev/null
		)
		[[ "$?" == "$expect" ]] || fails+=" [$case_]"
	done
	if [[ -z "$fails" ]]; then
		ok "deb plan: byte identity needs the running xpfd and helper AND all four managed binaries in the live version dir; an unreadable one is not identical"
	else
		bad "deb plan: deploy_node_runs_deb verdicts wrong:$fails"
	fi
}

test_deb_running_version_reads_dpkg_state() {
	local fails="" row want got
	for row in "ii  0.0.29598+gabc|0.0.29598+gabc" "ii 0.0.29598+gabc|0.0.29598+gabc" "rc  0.0.29598+gabc|" "|" "iU  0.0.29598+gabc|!iU" "iF  0.0.29598+gabc|!iF" "un  0.0.1|"; do
		_ck_dpkg_state="${row%%|*}" want="${row#*|}"
		got=$(deploy_running_deb_state() { printf '%s' "$_ck_dpkg_state"; }; deploy_running_deb_version inst:vm)
		[[ "$got" == "$want" ]] || fails+=" ['$_ck_dpkg_state': '$got', want '$want']"
	done
	# A half-installed package is refused by the node action, naming the state.
	got=$(_plan_action '!iU' 0 2>&1)
	[[ "${got%%|*}" == 1 && "$got" == *"dpkg state iU"* ]] || fails+=" [half-installed not refused: $got]"
	if [[ -z "$fails" ]]; then
		ok "deb plan: only an installed (ii) package is a running version; rc/none is fresh, and a half-installed state is refused"
	else
		bad "deb plan: dpkg state handling wrong:$fails"
	fi
}

# _ck_floor_run <dir> <fn>: run a floor helper with incus mocked to execute its
# command locally against <dir> instead of /var/lib/xpf.
_ck_floor_run() {
	local d="$1" fn="$2"
	(
		incus() {
			[[ "$1" == exec ]] || return 0
			shift; while [[ "$1" != -- ]]; do shift; done; shift
			local -a argv=()
			local a
			for a in "$@"; do argv+=("${a//\/var\/lib\/xpf/$d}"); done
			"${argv[@]}"
		}
		warn() { :; }
		"$fn" inst:vm
	)
}

test_deb_floor_moved_aside_and_restored() {
	local d fails=""
	d=$(mktemp -d)
	# Failure path: the floor comes back.
	printf '0.0.29598+gold\n' >"$d/binary-floor"
	_ck_floor_run "$d" deploy_reset_binary_floor
	[[ ! -e "$d/binary-floor" && -e "$d/binary-floor.lab-downgrade-saved" ]] || fails+=" reset-did-not-move"
	_ck_floor_run "$d" deploy_restore_binary_floor
	[[ "$(cat "$d/binary-floor" 2>/dev/null)" == 0.0.29598+gold && ! -e "$d/binary-floor.lab-downgrade-saved" ]] || fails+=" restore-did-not-restore"
	# Committed path: the cut re-enrolled a new floor; the saved one is dropped.
	_ck_floor_run "$d" deploy_reset_binary_floor
	printf '0.0.29580+gnew\n' >"$d/binary-floor"
	_ck_floor_run "$d" deploy_drop_saved_binary_floor
	[[ "$(cat "$d/binary-floor")" == 0.0.29580+gnew && ! -e "$d/binary-floor.lab-downgrade-saved" ]] || fails+=" drop-lost-the-new-floor"
	# A failure AFTER re-enrollment keeps the re-enrolled floor.
	_ck_floor_run "$d" deploy_reset_binary_floor
	printf '0.0.29580+gnew\n' >"$d/binary-floor"
	_ck_floor_run "$d" deploy_restore_binary_floor
	[[ "$(cat "$d/binary-floor")" == 0.0.29580+gnew && ! -e "$d/binary-floor.lab-downgrade-saved" ]] || fails+=" restore-clobbered-a-reenrolled-floor"
	rm -rf "$d"
	if [[ -z "$fails" ]]; then
		ok "deb plan: the downgrade moves the floor aside, a failure restores it, a committed cut keeps the re-enrolled one"
	else
		bad "deb plan: anti-rollback floor handling wrong:$fails"
	fi
}

test_deb_preflight_refuses_before_any_change() {
	local d out rc
	d=$(mktemp -d)
	: >"$d/xpf_0.0.29580+gaaaaaaaaaaaa_amd64.deb"
	out=$(
		deploy_running_deb_version() { case "$1" in a:fw0) echo 0.0.29570+gbbbbbbbbbbbb ;; *) echo 0.0.29590+gcccccccccccc ;; esac; }
		deploy_node_runs_deb() { return 1; }
		incus() { echo "UNEXPECTED incus $*"; }
		unset XPF_DEPLOY_ALLOW_DOWNGRADE
		deploy_deb_preflight "$d/xpf_0.0.29580+gaaaaaaaaaaaa_amd64.deb" a:fw0 a:fw1 2>&1
	)
	rc=$?
	rm -rf "$d"
	if ((rc != 0)) && [[ "$out" == *"a:fw0 install"* && "$out" == *"not newer than the running 0.0.29590+gcccccccccccc on a:fw1"* &&
		"$out" != *UNEXPECTED* ]]; then
		ok "deb plan: the preflight refuses a cell when any node would downgrade, and touches no node"
	else
		bad "deb plan: preflight rc=$rc out=$out"
	fi
}

test_deb_install_downgrade_flag() {
	setup_fake_vm
	local deb plain allowed
	deb=$(mktemp --suffix=.deb)
	make_local_bin "$deb" "DEB-BYTES"
	deploy_install_deb vm "$deb" >/dev/null 2>&1
	plain=$(grep -c -- "--allow-downgrades" "$FAKE_CALL_LOG")
	deploy_install_deb vm "$deb" allow-downgrade >/dev/null 2>&1
	allowed=$(grep -c "apt-get install -y --reinstall --allow-downgrades /tmp/xpf-deb\." "$FAKE_CALL_LOG")
	if [[ "$plain" == 0 && "$allowed" == 1 ]]; then
		ok "deb plan: only the opted-in install passes --allow-downgrades to apt"
	else
		bad "deb plan: --allow-downgrades must appear only on the opted-in install (plain=$plain allowed=$allowed)"
	fi
	rm -f "$deb"; teardown_fake_vm
}

test_deb_plan_wiring() {
	local f="$SCRIPT_DIR/cluster-setup.sh" deploy vmdeb fails=""
	deploy=$(awk '/^cmd_deploy\(\) \{/{f=1} f{print} f&&/^\}$/{exit}' "$f")
	vmdeb=$(awk '/^deploy_vm_deb\(\) \{/{f=1} f{print} f&&/^\}$/{exit}' "$f")
	# The preflight runs before the manifest is invalidated (#18772: leave it untouched).
	awk '/deploy_deb_preflight/{p=NR} /deploy_manifest_invalidate "\$PROJECT_ROOT"/{i=NR} END{exit !(p && i && p < i)}' <<<"$deploy" ||
		fails+=" preflight-not-before-invalidate"
	# deploy_vm_deb decides before installing; only install-downgrade resets the floor and allows the downgrade.
	awk '/deploy_deb_node_action/{a=NR} /deploy_install_deb/{if(!i)i=NR} END{exit !(a && i && a < i)}' <<<"$vmdeb" ||
		fails+=" action-not-before-install"
	grep -Fq 'skip-same)' <<<"$vmdeb" || fails+=" no-skip-same"
	[[ "$(grep -c 'deploy_reset_binary_floor' <<<"$vmdeb")" == 1 && "$(grep -c 'allow-downgrade; then' <<<"$vmdeb")" == 1 ]] ||
		fails+=" floor-reset-or-allow-outside-the-branch"
	awk '/install-downgrade\)/{b=1} b&&/deploy_reset_binary_floor/{r=1} b&&/allow-downgrade; then/{a=1} b&&/deploy_restore_binary_floor/{x=1} b&&/;;/{exit} END{exit !(r && a && x)}' <<<"$vmdeb" ||
		fails+=" branch-incomplete"
	# The cut restores the floor on failure and drops the saved one on commit.
	grep -Fq '((floor_saved)) && deploy_restore_binary_floor "$rinst"' <<<"$vmdeb" &&
		grep -Fq '((floor_saved)) && deploy_drop_saved_binary_floor "$rinst"' <<<"$vmdeb" || fails+=" cut-floor-handling"
	if [[ -z "$fails" ]]; then
		ok "deb plan wiring: cmd_deploy preflights before invalidating; deploy_vm_deb acts on the plan, and only install-downgrade resets the floor"
	else
		bad "deb plan wiring:$fails"
	fi
}

test_deb_repush_wiring() {
	local f="$SCRIPT_DIR/cluster-setup.sh" code
	code=$(awk '/^deploy_vm_deb\(\)/,/^}/' "$f")
	if ! grep -Fq 'deploy_install_deb "$rinst" "$deb"' <<<"$code"; then
		bad "deb re-push wiring: deploy_vm_deb bypasses deploy_install_deb"
		return
	fi
	if grep -Fq 'incus file push "$deb"' <<<"$code"; then
		bad "deb re-push wiring: deploy_vm_deb still owns a fixed-name deb push"
		return
	fi
	ok "deb re-push wiring: deploy_vm_deb uses the unique-slot helper"
}

# ── #18544: raw-deploy unit shadows on the deb path ───────────────────
# The fixture models a node that was raw-deployed once and deb-deployed
# since. The raw push left a regular-file /etc copy (for xpfd, with the
# pre-#18213 KillMode), and the deb installed the packaged unit under
# /usr/lib. The raw `systemctl enable` pointed the install link at the /etc
# copy, and systemd loaded the /etc copy. That was the measured state of
# the lab nodes on 2026-10-30. The paths are LITERALS, not the lib's
# constants, so a wrong constant in the lib cannot bring its fixture along
# with it.
#
# unit_shadow_fixture <file|mask|alias|none> <packaged: 1|0>
#   (xpfd.service, wants link in multi-user.target.wants)
unit_shadow_fixture() {
	local kind="$1" packaged="$2"
	local etc="$FAKE_VM/etc/systemd/system"
	mkdir -p "$etc/multi-user.target.wants"
	case "$kind" in
		file) printf '[Service]\nExecStart=/usr/local/sbin/xpfd\nKillMode=control-group\n' >"$etc/xpfd.service" ;;
		mask) ln -s /dev/null "$etc/xpfd.service" ;;
		alias) ln -s /opt/stale/xpfd.service "$etc/xpfd.service" ;;
		none) ;;
	esac
	if [[ "$packaged" == 1 ]]; then
		mkdir -p "$FAKE_VM/usr/lib/systemd/system"
		printf '[Service]\nExecStartPre=/usr/local/sbin/xpfd verify-dataplane\nExecStart=/usr/local/sbin/xpfd\nKillMode=mixed\n' \
			>"$FAKE_VM/usr/lib/systemd/system/xpfd.service"
	fi
	ln -s /etc/systemd/system/xpfd.service "$etc/multi-user.target.wants/xpfd.service"
	fake_systemd_boot
}

# Any call that starts, stops, restarts or re-enables a unit. The reconcile
# runs while xpfd is live and forwarding, ahead of the controlled cut, so a
# single one of these is an uncontrolled restart.
UNIT_SHADOW_SERVICE_TOUCH='systemctl (start|stop|restart|try-restart|reload-or-restart|try-reload-or-restart|kill|enable|reenable|disable|mask|unmask|isolate)( |$)|--now'

# rc + stderr of one reconcile run, in a subshell because die() exits.
unit_shadow_run() {
	UNIT_SHADOW_RC=0
	UNIT_SHADOW_ERR=$( ( "$@" ) 2>&1 >/dev/null ) || UNIT_SHADOW_RC=$?
}

test_unit_shadow_removed_packaged_unit_governs_18544() {
	setup_fake_vm
	unit_shadow_fixture file 1
	local problems=() loaded link
	unit_shadow_run deploy_reconcile_unit_shadow vm xpfd.service
	loaded=$(fake_systemd_loaded xpfd.service)
	link=$(readlink "$FAKE_VM/etc/systemd/system/multi-user.target.wants/xpfd.service")
	(( UNIT_SHADOW_RC == 0 )) || problems+=("reconcile rc=$UNIT_SHADOW_RC")
	[[ -e "$FAKE_VM/etc/systemd/system/xpfd.service" ]] && problems+=("the /etc copy is still on disk")
	[[ -e "$FAKE_VM/var/lib/xpf-deploy-unit-shadow/xpfd.service" ]] && problems+=("the parked copy was not dropped")
	fake_calls_contain '^exec vm -- systemctl daemon-reload$' || problems+=("no daemon-reload was issued")
	[[ "$loaded" == /usr/lib/systemd/system/xpfd.service ]] ||
		problems+=("systemd has '${loaded:-nothing}' loaded, not the packaged unit")
	[[ "$link" == /usr/lib/systemd/system/xpfd.service ]] ||
		problems+=("wants link still -> '$link', not the packaged unit")
	grep -qx 'KillMode=mixed' "$FAKE_VM/usr/lib/systemd/system/xpfd.service" 2>/dev/null ||
		problems+=("the packaged unit was altered")
	# Idempotence: a second deploy against the reconciled node succeeds and
	# leaves it exactly as it was.
	unit_shadow_run deploy_reconcile_unit_shadow vm xpfd.service
	(( UNIT_SHADOW_RC == 0 )) || problems+=("second run rc=$UNIT_SHADOW_RC")
	[[ "$(fake_systemd_loaded xpfd.service)" == "$loaded" && -f "$FAKE_VM/usr/lib/systemd/system/xpfd.service" &&
		! -e "$FAKE_VM/etc/systemd/system/xpfd.service" &&
		"$(readlink "$FAKE_VM/etc/systemd/system/multi-user.target.wants/xpfd.service")" == "$link" ]] ||
		problems+=("second run changed the node")
	# Across BOTH runs: never start/stop/restart/re-enable the live daemon.
	fake_calls_contain "$UNIT_SHADOW_SERVICE_TOUCH" &&
		problems+=("touched the live service: $(grep -E "$UNIT_SHADOW_SERVICE_TOUCH" "$FAKE_CALL_LOG" | head -n1)")
	if (( ${#problems[@]} )); then
		bad "unit shadow (#18544): the packaged unit must govern after reconcile: ${problems[*]}"
	else
		ok "unit shadow (#18544): /etc copy removed, daemon-reloaded, packaged unit loaded, wants link re-pointed, no restart, idempotent"
	fi
	teardown_fake_vm
}

# The /etc copy was removed by an earlier run whose daemon-reload never ran:
# nothing is left on disk to find, yet systemd still has the stale unit
# loaded, and that unit governs the cut's stop.
test_unit_shadow_stale_load_without_file_reloads_18544() {
	setup_fake_vm
	unit_shadow_fixture none 1
	fake_systemd_set_loaded xpfd.service /etc/systemd/system/xpfd.service
	unit_shadow_run deploy_reconcile_unit_shadow vm xpfd.service
	if (( UNIT_SHADOW_RC == 0 )) && fake_calls_contain '^exec vm -- systemctl daemon-reload$' &&
		[[ "$(fake_systemd_loaded xpfd.service)" == /usr/lib/systemd/system/xpfd.service ]]; then
		ok "unit shadow (#18544): a /etc copy still LOADED with no file on disk is reloaded away"
	else
		bad "unit shadow (#18544): a /etc copy still loaded after its file was removed must be reloaded (rc=$UNIT_SHADOW_RC, loaded=$(fake_systemd_loaded xpfd.service))"
	fi
	teardown_fake_vm
}

# A /dev/null symlink at the /etc path is a mask (xpf-deploy.py's #7559 daemon
# hold). Removing it would unmask a deliberately held daemon.
test_unit_shadow_mask_symlink_left_alone_18544() {
	setup_fake_vm
	unit_shadow_fixture mask 1
	unit_shadow_run deploy_reconcile_unit_shadow vm xpfd.service
	if (( UNIT_SHADOW_RC == 0 )) &&
		[[ "$(readlink "$FAKE_VM/etc/systemd/system/xpfd.service")" == /dev/null ]] &&
		! fake_calls_contain '(rm|mv) .*/etc/systemd/system/xpfd\.service( |$)'; then
		ok "unit shadow (#18544): a mask symlink at the /etc path is left in place"
	else
		bad "unit shadow (#18544): a mask symlink must be left alone (rc=$UNIT_SHADOW_RC, link=$(readlink "$FAKE_VM/etc/systemd/system/xpfd.service"))"
	fi
	teardown_fake_vm
}

# Any other symlink at the /etc path is an alias this deploy did not write.
# It must not be removed, and it must not pass as "the packaged unit" when
# systemd loads it in place of the packaged file.
test_unit_shadow_alias_symlink_not_packaged_hardfails_18544() {
	setup_fake_vm
	unit_shadow_fixture alias 1
	unit_shadow_run deploy_reconcile_unit_shadow vm xpfd.service
	if (( UNIT_SHADOW_RC != 0 )) && [[ "$UNIT_SHADOW_ERR" == *"not the packaged"* ]] &&
		[[ "$(readlink "$FAKE_VM/etc/systemd/system/xpfd.service")" == /opt/stale/xpfd.service ]] &&
		! fake_calls_contain '(rm|mv) .*/etc/systemd/system/xpfd\.service( |$)'; then
		ok "unit shadow (#18544): an alias symlink that keeps governing hard-fails and is not removed"
	else
		bad "unit shadow (#18544): an alias symlink in place of the packaged unit must hard-fail, untouched (rc=$UNIT_SHADOW_RC, link=$(readlink "$FAKE_VM/etc/systemd/system/xpfd.service"))"
	fi
	teardown_fake_vm
}

# With no packaged unit to fall back to, removing the /etc copy would leave
# the node with no unit at all. The reconcile must refuse and keep it.
test_unit_shadow_kept_without_packaged_unit_18544() {
	setup_fake_vm
	unit_shadow_fixture file 0
	unit_shadow_run deploy_reconcile_unit_shadow vm xpfd.service
	if (( UNIT_SHADOW_RC != 0 )) && [[ -f "$FAKE_VM/etc/systemd/system/xpfd.service" ]] &&
		[[ "$UNIT_SHADOW_ERR" == *"refusing to remove"* ]] &&
		! fake_calls_contain '(rm|mv) .*/etc/systemd/system/xpfd\.service( |$)'; then
		ok "unit shadow (#18544): no packaged unit -> hard fail, /etc copy kept"
	else
		bad "unit shadow (#18544): with no packaged unit the /etc copy must be kept and the deploy refused (rc=$UNIT_SHADOW_RC, /etc copy present=$([[ -f "$FAKE_VM/etc/systemd/system/xpfd.service" ]] && echo yes || echo no))"
	fi
	teardown_fake_vm
}

# A move that reports success while the file stays. The verdict comes from
# the unit systemd LOADED, not from the move's exit status.
test_unit_shadow_surviving_removal_hardfails_18544() {
	setup_fake_vm
	unit_shadow_fixture file 1
	FAKE_REMOVE_NOOP_PATH=/etc/systemd/system/xpfd.service
	unit_shadow_run deploy_reconcile_unit_shadow vm xpfd.service
	if (( UNIT_SHADOW_RC != 0 )) && [[ "$UNIT_SHADOW_ERR" == *"not the packaged"* ]]; then
		ok "unit shadow (#18544): a /etc copy still loaded after removal + daemon-reload hard-fails"
	else
		bad "unit shadow (#18544): a /etc copy that survives removal must hard-fail on the LOADED unit (rc=$UNIT_SHADOW_RC)"
	fi
	teardown_fake_vm
}

# No unit anywhere, so systemd loaded nothing. The cut cannot be governed
# by the packaged unit; fail here, ahead of the cut.
test_unit_shadow_no_loaded_unit_hardfails_18544() {
	setup_fake_vm
	unit_shadow_fixture none 0
	unit_shadow_run deploy_reconcile_unit_shadow vm xpfd.service
	if (( UNIT_SHADOW_RC != 0 )) && [[ "$UNIT_SHADOW_ERR" == *"not loaded"* ]]; then
		ok "unit shadow (#18544): no loaded xpfd unit hard-fails"
	else
		bad "unit shadow (#18544): no loaded xpfd unit must hard-fail (rc=$UNIT_SHADOW_RC)"
	fi
	teardown_fake_vm
}

# The /etc copy outranked a runtime unit in /run/systemd/system. Removing it
# PROMOTES that unit over the packaged one. "A fragment exists and it is not
# /etc" would pass this; the positive check must refuse it and put the
# previous unit back, so the node is as it was before the deploy.
test_unit_shadow_promoted_runtime_unit_rolls_back_18544() {
	setup_fake_vm
	mkdir -p "$FAKE_VM/run/systemd/system"
	printf '[Service]\nExecStart=/usr/local/sbin/xpfd\n' >"$FAKE_VM/run/systemd/system/xpfd.service"
	unit_shadow_fixture file 1
	local problems=()
	unit_shadow_run deploy_reconcile_unit_shadow vm xpfd.service
	(( UNIT_SHADOW_RC != 0 )) || problems+=("reconcile passed (rc=0) with /run/systemd/system/xpfd.service loaded")
	[[ "$UNIT_SHADOW_ERR" == *"not the packaged"* ]] || problems+=("no 'not the packaged' diagnostic")
	grep -qx 'KillMode=control-group' "$FAKE_VM/etc/systemd/system/xpfd.service" 2>/dev/null ||
		problems+=("the previous /etc copy was not put back")
	[[ "$(fake_systemd_loaded xpfd.service)" == /etc/systemd/system/xpfd.service ]] ||
		problems+=("systemd has '$(fake_systemd_loaded xpfd.service)' loaded after the rollback")
	[[ "$(readlink "$FAKE_VM/etc/systemd/system/multi-user.target.wants/xpfd.service")" == /etc/systemd/system/xpfd.service ]] ||
		problems+=("the wants link was re-pointed despite the failed check")
	if (( ${#problems[@]} )); then
		bad "unit shadow (#18544): a promoted non-packaged unit must fail and roll back: ${problems[*]}"
	else
		ok "unit shadow (#18544): a promoted /run/systemd/system unit fails the positive check and the /etc copy is put back"
	fi
	teardown_fake_vm
}

# The packaged file is the fragment, but systemd rejects it (LoadState
# bad-setting, e.g. a directive the node's systemd does not know). The path
# alone would pass; LoadState must not.
test_unit_shadow_packaged_unit_rejected_rolls_back_18544() {
	setup_fake_vm
	unit_shadow_fixture file 1
	FAKE_LOADSTATE_OVERRIDE=xpfd.service=bad-setting
	unit_shadow_run deploy_reconcile_unit_shadow vm xpfd.service
	if (( UNIT_SHADOW_RC != 0 )) && [[ "$UNIT_SHADOW_ERR" == *"not loaded"* ]] &&
		grep -qx 'KillMode=control-group' "$FAKE_VM/etc/systemd/system/xpfd.service" 2>/dev/null &&
		[[ "$(fake_systemd_loaded xpfd.service)" == /etc/systemd/system/xpfd.service ]]; then
		ok "unit shadow (#18544): a packaged unit systemd rejects fails LoadState and the /etc copy is put back"
	else
		bad "unit shadow (#18544): a rejected packaged unit must fail on LoadState and roll back (rc=$UNIT_SHADOW_RC, loaded=$(fake_systemd_loaded xpfd.service))"
	fi
	teardown_fake_vm
}

# The raw deploy also pushes both boot barriers into /etc, shadowing their
# packaged copies. This uses the udp-node link shape: every install link
# (sysinit.target.wants for WantedBy=, systemd-networkd.service.requires and
# xpfd.service.requires for RequiredBy=) targets the /etc copy. After the
# reconcile, all three units load the packaged file. Every install link still
# exists, so enablement and RequiredBy= survive, and each one targets the
# packaged file.
test_unit_shadow_barrier_units_reconciled_18544() {
	setup_fake_vm
	local etc="$FAKE_VM/etc/systemd/system" u l problems=()
	local -a links=(
		multi-user.target.wants/xpfd.service
		sysinit.target.wants/xpf-transit-closed.service
		systemd-networkd.service.requires/xpf-transit-closed.service
		sysinit.target.wants/xpf-input-closed.service
		systemd-networkd.service.requires/xpf-input-closed.service
		xpfd.service.requires/xpf-input-closed.service
	)
	mkdir -p "$FAKE_VM/usr/lib/systemd/system"
	for u in xpfd.service xpf-transit-closed.service xpf-input-closed.service; do
		printf '[Unit]\nDescription=stale raw push of %s\n' "$u" >"$etc/$u"
		printf '[Unit]\nDescription=packaged %s\n' "$u" >"$FAKE_VM/usr/lib/systemd/system/$u"
	done
	for l in "${links[@]}"; do
		mkdir -p "$etc/$(dirname "$l")"
		ln -s "/etc/systemd/system/$(basename "$l")" "$etc/$l"
	done
	fake_systemd_boot
	unit_shadow_run deploy_reconcile_unit_shadows vm
	(( UNIT_SHADOW_RC == 0 )) || problems+=("rc=$UNIT_SHADOW_RC: $UNIT_SHADOW_ERR")
	for u in xpfd.service xpf-transit-closed.service xpf-input-closed.service; do
		[[ -e "$etc/$u" ]] && problems+=("$u: /etc copy still on disk")
		[[ "$(fake_systemd_loaded "$u")" == "/usr/lib/systemd/system/$u" ]] ||
			problems+=("$u: loaded '$(fake_systemd_loaded "$u")'")
	done
	for l in "${links[@]}"; do
		if [[ ! -L "$etc/$l" ]]; then
			problems+=("$l: install link gone (unit no longer enabled / RequiredBy= lost)")
		elif [[ "$(readlink "$etc/$l")" != "/usr/lib/systemd/system/$(basename "$l")" ]]; then
			problems+=("$l -> $(readlink "$etc/$l")")
		fi
	done
	fake_calls_contain "$UNIT_SHADOW_SERVICE_TOUCH" &&
		problems+=("touched a live unit: $(grep -E "$UNIT_SHADOW_SERVICE_TOUCH" "$FAKE_CALL_LOG" | head -n1)")
	if (( ${#problems[@]} )); then
		bad "unit shadow (#18544): xpfd + both boot barriers must load the packaged units with every install link kept: ${problems[*]}"
	else
		ok "unit shadow (#18544): xpfd + both boot barriers load the packaged units; all 6 install links kept and re-pointed; no unit touched"
	fi
	teardown_fake_vm
}

# An earlier run was interrupted after its move: the copy is parked, the /etc
# path is empty, and no reload ever ran. This run finds nothing to move
# (removed=0), and its check fails because a /run unit is promoted. It must
# still put the parked copy back and name it, not leave the node on an
# unverified unit with the copy stranded (seat H, round 2).
test_unit_shadow_interrupted_stash_restored_18544() {
	setup_fake_vm
	mkdir -p "$FAKE_VM/run/systemd/system" "$FAKE_VM/var/lib/xpf-deploy-unit-shadow"
	printf '[Service]\nExecStart=/usr/local/sbin/xpfd\n' >"$FAKE_VM/run/systemd/system/xpfd.service"
	unit_shadow_fixture none 1
	printf '[Service]\nExecStart=/usr/local/sbin/xpfd\nKillMode=control-group\n' \
		>"$FAKE_VM/var/lib/xpf-deploy-unit-shadow/xpfd.service"
	fake_systemd_set_loaded xpfd.service /etc/systemd/system/xpfd.service
	local problems=()
	unit_shadow_run deploy_reconcile_unit_shadow vm xpfd.service
	(( UNIT_SHADOW_RC != 0 )) || problems+=("reconcile passed with /run/systemd/system/xpfd.service loaded")
	[[ "$UNIT_SHADOW_ERR" == *"/var/lib/xpf-deploy-unit-shadow/xpfd.service"* ]] ||
		problems+=("the error does not name the parked copy")
	grep -qx 'KillMode=control-group' "$FAKE_VM/etc/systemd/system/xpfd.service" 2>/dev/null ||
		problems+=("the parked copy was not put back at /etc")
	[[ -e "$FAKE_VM/var/lib/xpf-deploy-unit-shadow/xpfd.service" ]] && problems+=("the parked copy is still stranded")
	[[ "$(fake_systemd_loaded xpfd.service)" == /etc/systemd/system/xpfd.service ]] ||
		problems+=("systemd has '$(fake_systemd_loaded xpfd.service)' loaded after the restore")
	if (( ${#problems[@]} )); then
		bad "unit shadow (#18544): a copy parked by an interrupted run must be restored on a failed check: ${problems[*]}"
	else
		ok "unit shadow (#18544): a copy parked by an interrupted earlier run is restored and named when the check fails"
	fi
	teardown_fake_vm
}

# The rollback's reload fails. The error must say so, not claim the node is
# "as it was" while systemd still has the unverified unit loaded.
test_unit_shadow_rollback_reload_failure_reported_18544() {
	setup_fake_vm
	mkdir -p "$FAKE_VM/run/systemd/system"
	printf '[Service]\nExecStart=/usr/local/sbin/xpfd\n' >"$FAKE_VM/run/systemd/system/xpfd.service"
	unit_shadow_fixture file 1
	FAKE_RELOAD_FAIL_FROM=2
	unit_shadow_run deploy_reconcile_unit_shadow vm xpfd.service
	if (( UNIT_SHADOW_RC != 0 )) && [[ "$UNIT_SHADOW_ERR" == *"daemon-reload FAILED"* ]] &&
		[[ "$UNIT_SHADOW_ERR" != *"as it was"* ]]; then
		ok "unit shadow (#18544): a failed rollback reload is reported, not claimed as a clean restore"
	else
		bad "unit shadow (#18544): a failed rollback reload must be reported truthfully (rc=$UNIT_SHADOW_RC, err=$UNIT_SHADOW_ERR)"
	fi
	teardown_fake_vm
}

# A deb pinned through XPF_DEPLOY_DEB_PATH can predate the boot barriers
# (#9852, #10751) and ship no packaged copy. On a raw-deployed node the /etc
# barrier copies are then the only ones. The barriers must be skipped with a
# warning, while xpfd, which is required, is still reconciled (seat G).
test_unit_shadow_unpackaged_barrier_skipped_18544() {
	setup_fake_vm
	unit_shadow_fixture file 1
	local etc="$FAKE_VM/etc/systemd/system" u problems=()
	for u in xpf-transit-closed.service xpf-input-closed.service; do
		printf '[Unit]\nDescription=raw push of %s\n' "$u" >"$etc/$u"
	done
	fake_systemd_boot
	unit_shadow_run deploy_reconcile_unit_shadows vm
	(( UNIT_SHADOW_RC == 0 )) || problems+=("rc=$UNIT_SHADOW_RC: $UNIT_SHADOW_ERR")
	for u in xpf-transit-closed.service xpf-input-closed.service; do
		[[ -f "$etc/$u" ]] || problems+=("$u: the only copy was removed")
		[[ "$UNIT_SHADOW_ERR" == *"No packaged $u"* ]] || problems+=("$u: no skip warning")
	done
	[[ "$(fake_systemd_loaded xpfd.service)" == /usr/lib/systemd/system/xpfd.service ]] ||
		problems+=("xpfd not reconciled: loaded '$(fake_systemd_loaded xpfd.service)'")
	if (( ${#problems[@]} )); then
		bad "unit shadow (#18544): unpackaged barriers must be skipped, xpfd still reconciled: ${problems[*]}"
	else
		ok "unit shadow (#18544): a deb with no packaged barriers skips them with a warning and still reconciles xpfd"
	fi
	teardown_fake_vm
}

# One unit in the loop fails its check. The wrapper must fail the deploy, not
# carry on to the cut with that unit unverified.
test_unit_shadow_loop_propagates_unit_failure_18544() {
	setup_fake_vm
	unit_shadow_fixture file 1
	local etc="$FAKE_VM/etc/systemd/system" u
	mkdir -p "$FAKE_VM/run/systemd/system"
	for u in xpf-transit-closed.service xpf-input-closed.service; do
		printf '[Unit]\nDescription=raw push of %s\n' "$u" >"$etc/$u"
		printf '[Unit]\nDescription=packaged %s\n' "$u" >"$FAKE_VM/usr/lib/systemd/system/$u"
	done
	printf '[Unit]\nDescription=runtime %s\n' xpf-transit-closed.service \
		>"$FAKE_VM/run/systemd/system/xpf-transit-closed.service"
	fake_systemd_boot
	unit_shadow_run deploy_reconcile_unit_shadows vm
	if (( UNIT_SHADOW_RC != 0 )) && [[ "$UNIT_SHADOW_ERR" == *"xpf-transit-closed.service"*"not the packaged"* ]]; then
		ok "unit shadow (#18544): one failing unit fails the whole reconcile"
	else
		bad "unit shadow (#18544): a failing unit in the loop must fail the deploy (rc=$UNIT_SHADOW_RC)"
	fi
	teardown_fake_vm
}

# A parked copy exists, but the /etc path is occupied (here by an alias). The
# restore must not overwrite what is there; it names both and fails.
test_unit_shadow_occupied_path_not_overwritten_18544() {
	setup_fake_vm
	unit_shadow_fixture alias 1
	mkdir -p "$FAKE_VM/var/lib/xpf-deploy-unit-shadow"
	printf '[Service]\nKillMode=control-group\n' >"$FAKE_VM/var/lib/xpf-deploy-unit-shadow/xpfd.service"
	unit_shadow_run deploy_reconcile_unit_shadow vm xpfd.service
	if (( UNIT_SHADOW_RC != 0 )) && [[ "$UNIT_SHADOW_ERR" == *"NOT restored"* ]] &&
		[[ "$(readlink "$FAKE_VM/etc/systemd/system/xpfd.service")" == /opt/stale/xpfd.service ]] &&
		[[ -f "$FAKE_VM/var/lib/xpf-deploy-unit-shadow/xpfd.service" ]]; then
		ok "unit shadow (#18544): a parked copy is never restored over an occupied /etc path"
	else
		bad "unit shadow (#18544): an occupied /etc path must not be overwritten by the restore (rc=$UNIT_SHADOW_RC)"
	fi
	teardown_fake_vm
}

# An interrupted run parked a barrier, and the deb deployed now predates the
# barriers. The parked copy is the unit's ONLY copy. It must go back to /etc,
# or the node boots without the transit barrier while its
# systemd-networkd.service.requires link still names it (both seats, round 3).
test_unit_shadow_unpackaged_barrier_stash_restored_18544() {
	setup_fake_vm
	unit_shadow_fixture file 1
	local etc="$FAKE_VM/etc/systemd/system" stash="$FAKE_VM/var/lib/xpf-deploy-unit-shadow" problems=()
	mkdir -p "$stash" "$etc/systemd-networkd.service.requires"
	printf '[Unit]\nDescription=raw push of transit barrier\n' >"$stash/xpf-transit-closed.service"
	ln -s /etc/systemd/system/xpf-transit-closed.service "$etc/systemd-networkd.service.requires/xpf-transit-closed.service"
	printf '[Unit]\nDescription=raw push of input barrier\n' >"$etc/xpf-input-closed.service"
	fake_systemd_boot
	unit_shadow_run deploy_reconcile_unit_shadows vm
	(( UNIT_SHADOW_RC == 0 )) || problems+=("rc=$UNIT_SHADOW_RC: $UNIT_SHADOW_ERR")
	grep -q 'raw push of transit barrier' "$etc/xpf-transit-closed.service" 2>/dev/null ||
		problems+=("the parked transit barrier was not put back at /etc")
	[[ -e "$stash/xpf-transit-closed.service" ]] && problems+=("the parked copy is still stranded")
	[[ "$UNIT_SHADOW_ERR" == *"Put the parked"*"xpf-transit-closed.service"* ]] ||
		problems+=("no warning naming the restore")
	[[ "$UNIT_SHADOW_ERR" == *"Leaving /etc/systemd/system/xpf-transit-closed.service as it is"* ]] &&
		problems+=("warned 'as it is' about a path that was empty")
	[[ "$(fake_systemd_loaded xpf-transit-closed.service)" == /etc/systemd/system/xpf-transit-closed.service ]] ||
		problems+=("transit barrier not loaded after the restore: '$(fake_systemd_loaded xpf-transit-closed.service)'")
	[[ -f "$etc/xpf-input-closed.service" ]] || problems+=("the input barrier's only copy was removed")
	if (( ${#problems[@]} )); then
		bad "unit shadow (#18544): a parked barrier must be restored when the deb ships none: ${problems[*]}"
	else
		ok "unit shadow (#18544): a barrier parked by an interrupted run is put back when the deployed deb ships no packaged copy"
	fi
	teardown_fake_vm
}

# The same, but the /etc path is occupied: the restore must not overwrite it,
# and the warning must name the parked copy rather than claim nothing is
# wrong.
test_unit_shadow_unpackaged_barrier_occupied_named_18544() {
	setup_fake_vm
	unit_shadow_fixture file 1
	local etc="$FAKE_VM/etc/systemd/system" stash="$FAKE_VM/var/lib/xpf-deploy-unit-shadow"
	mkdir -p "$stash"
	printf '[Unit]\nDescription=parked transit barrier\n' >"$stash/xpf-transit-closed.service"
	printf '[Unit]\nDescription=current transit barrier\n' >"$etc/xpf-transit-closed.service"
	fake_systemd_boot
	unit_shadow_run deploy_reconcile_unit_shadows vm
	if (( UNIT_SHADOW_RC == 0 )) &&
		grep -q 'current transit barrier' "$etc/xpf-transit-closed.service" 2>/dev/null &&
		[[ -f "$stash/xpf-transit-closed.service" ]] &&
		[[ "$UNIT_SHADOW_ERR" == *"/var/lib/xpf-deploy-unit-shadow/xpf-transit-closed.service"*"NOT restored"* ]]; then
		ok "unit shadow (#18544): with no packaged barrier, a parked copy is named and never restored over an occupied /etc path"
	else
		bad "unit shadow (#18544): an occupied barrier path must be kept and the parked copy named (rc=$UNIT_SHADOW_RC)"
	fi
	teardown_fake_vm
}

# The restore in the skip branch reloads; when that reload fails, the warning
# must say so rather than report a clean restore.
test_unit_shadow_unpackaged_barrier_reload_failure_reported_18544() {
	setup_fake_vm
	unit_shadow_fixture file 1
	local stash="$FAKE_VM/var/lib/xpf-deploy-unit-shadow"
	mkdir -p "$stash"
	printf '[Unit]\nDescription=raw push of transit barrier\n' >"$stash/xpf-transit-closed.service"
	fake_systemd_boot
	# Reload #1 is xpfd's own reconcile; #2 is the barrier restore.
	FAKE_RELOAD_FAIL_FROM=2
	unit_shadow_run deploy_reconcile_unit_shadows vm
	if (( UNIT_SHADOW_RC == 0 )) && [[ "$UNIT_SHADOW_ERR" == *"xpf-transit-closed.service, but daemon-reload FAILED"* ]] &&
		[[ "$UNIT_SHADOW_ERR" != *"xpf-transit-closed.service and reloaded"* ]]; then
		ok "unit shadow (#18544): a failed reload after a skip-branch restore is reported"
	else
		bad "unit shadow (#18544): a failed reload after a skip-branch restore must be reported (rc=$UNIT_SHADOW_RC)"
	fi
	teardown_fake_vm
}

# The helper is useless unless the deb path calls it, and the call's
# POSITION matters. After the deb install, the packaged units on disk are the
# ones being deployed. Before the `upgrade --rolling` cut, the cut's stop
# already runs under the packaged KillMode. The call is anchored at line end:
# a backgrounded `... &` call would race the cut.
test_unit_shadow_reconcile_wired_into_deb_deploy_18544() {
	local code n_install n_reconcile n_cut
	code=$(awk '/^deploy_vm_deb\(\)/,/^}/' "$SCRIPT_DIR/cluster-setup.sh")
	_body_line() {
		grep -nE "$1" <<<"$code" | grep -vE '^[0-9]+:[[:space:]]*#' | head -n1 | cut -d: -f1
	}
	# shellcheck disable=SC2016  # literal $rinst/$deb: matching source text
	n_install=$(_body_line '^[[:space:]]*deploy_install_deb "\$rinst" "\$deb"')
	# shellcheck disable=SC2016  # literal $rinst: matching source text
	n_reconcile=$(_body_line '^[[:space:]]*deploy_reconcile_unit_shadows "\$rinst"[[:space:]]*$')
	n_cut=$(_body_line 'xpfd upgrade --rolling')
	if [[ -z "$n_reconcile" ]]; then
		bad "unit shadow wiring (#18544): deploy_vm_deb never calls deploy_reconcile_unit_shadows as a plain foreground statement"
	elif [[ -z "$n_install" || -z "$n_cut" ]]; then
		bad "unit shadow wiring (#18544): could not locate the install/cut anchors in deploy_vm_deb; the test is stale, fix the pattern"
	elif (( n_install < n_reconcile && n_reconcile < n_cut )); then
		ok "unit shadow wiring (#18544): deploy_vm_deb reconciles after the deb install (:$n_install) and before the cut (:$n_cut)"
	else
		bad "unit shadow wiring (#18544): reconcile at :$n_reconcile must sit between the deb install (:$n_install) and the cut (:$n_cut)"
	fi
	unset -f _body_line
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

test_helper_running_sha_returns_live_sha() {
	setup_fake_vm
	local lb; lb=$(mktemp); make_local_bin "$lb" "HELPER-RUNNING-OK"
	cp "$lb" "$FAKE_VM/usr/local/sbin/xpf-userspace-dp"
	FAKE_HELPER_PIDS="4242"
	local want got
	want=$(sha256sum "$lb" | awk '{print $1}')
	got=$(deploy_running_xpf_userspace_dp_sha256 vm 1)
	if [[ "$got" == "$want" ]]; then
		ok "helper_running_sha: echoes the LIVE helper image sha256"
	else
		bad "helper_running_sha: got '$got', want '$want'"
	fi
	rm -f "$lb"; teardown_fake_vm
}

test_helper_running_sha_rejects_empty_instance() {
	setup_fake_vm
	local got rc
	got=$(deploy_running_xpf_userspace_dp_sha256 "" 1); rc=$?
	if [[ $rc -ne 0 && -z "$got" ]]; then
		ok "helper_running_sha: empty instance returns EMPTY rc!=0"
	else
		bad "helper_running_sha: empty instance gave rc=$rc out='$got'"
	fi
	teardown_fake_vm
}

test_helper_running_sha_rejects_absent_helper() {
	setup_fake_vm
	FAKE_HELPER_PIDS=""
	local got rc
	got=$(deploy_running_xpf_userspace_dp_sha256 vm 1); rc=$?
	if [[ $rc -ne 0 && -z "$got" ]]; then
		ok "helper_running_sha: absent helper returns EMPTY rc!=0"
	else
		bad "helper_running_sha: absent helper gave rc=$rc out='$got'"
	fi
	teardown_fake_vm
}

test_helper_running_sha_rejects_duplicate_helpers() {
	setup_fake_vm
	local lb; lb=$(mktemp); make_local_bin "$lb" "HELPER-DUPLICATE"
	cp "$lb" "$FAKE_VM/usr/local/sbin/xpf-userspace-dp"
	FAKE_HELPER_PIDS="4242 4343"
	local got rc
	got=$(deploy_running_xpf_userspace_dp_sha256 vm 1); rc=$?
	if [[ $rc -ne 0 && -z "$got" ]]; then
		ok "helper_running_sha: duplicate helper PIDs fail closed"
	else
		bad "helper_running_sha: duplicate PIDs gave rc=$rc out='$got'"
	fi
	rm -f "$lb"; teardown_fake_vm
}

test_helper_verify_stale_binary_hardfails() {
	setup_fake_vm
	local lb; lb=$(mktemp); make_local_bin "$lb" "HELPER-NEW-BUILD"
	make_local_bin "$FAKE_VM/usr/local/sbin/xpf-userspace-dp" "HELPER-OLD-BUILD"
	FAKE_HELPER_PIDS="4242"
	if ( deploy_verify_running_xpf_userspace_dp vm "$lb" ) >/dev/null 2>&1; then
		bad "helper_verify_running: stale helper MUST hard-fail"
	else
		ok "helper_verify_running: stale helper hard-fails"
	fi
	rm -f "$lb"; teardown_fake_vm
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

# #9558: exit 3 is the #1864 kernel-verifier reject; legacy other refusals
# (for example a live pinned-map ABI mismatch) exit 1, and "make generate"
# cannot fix those. A presence check alone would pass the pre-fix wrapper,
# which printed the #1864 text for BOTH, so the exit-1 cell asserts that
# remediation is absent. #17769 adds distinct code-4/5 remediation cells below.
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

test_preflight_low_headroom_prescribes_budget_remediation() {
	setup_fake_vm
	local lb; lb=$(mktemp); make_local_bin "$lb" "LOW-HEADROOM-SHIM"
	FAKE_VERIFY_RC=4
	local out rc=0
	out=$( ( deploy_verify_dataplane_preflight vm "$lb" ) 2>&1 ) || rc=$?
	if [[ $rc -eq 0 ]]; then
		bad "preflight #17769: exit 4 (LOW-HEADROOM) must hard-fail"
	elif [[ "$out" != *"(exit 4)"* || "$out" != *"LOW-HEADROOM"* ||
		"$out" != *"Free verifier headroom"* || "$out" != *"sufficient measured headroom"* ]]; then
		bad "preflight #17769: exit 4 must prescribe measured headroom remediation; got: $out"
	elif [[ "$out" == *"rebuilding the shim will not help"* || "$out" == *"stale pin cleared"* ]]; then
		bad "preflight #17769: exit 4 received the unrelated generic/pinned-map remediation; got: $out"
	else
		ok "preflight #17769: exit 4 refuses with low-headroom remediation, not stale-pin advice"
	fi
	rm -f "$lb"; teardown_fake_vm
}

test_preflight_unmeasured_headroom_prescribes_measurement_remediation() {
	setup_fake_vm
	local lb; lb=$(mktemp); make_local_bin "$lb" "UNMEASURED-HEADROOM-SHIM"
	FAKE_VERIFY_RC=5
	local out rc=0
	out=$( ( deploy_verify_dataplane_preflight vm "$lb" ) 2>&1 ) || rc=$?
	if [[ $rc -eq 0 ]]; then
		bad "preflight #17769: exit 5 (UNMEASURED-HEADROOM) must hard-fail"
	elif [[ "$out" != *"(exit 5)"* || "$out" != *"UNMEASURED-HEADROOM"* ||
		"$out" != *"processed-instruction count was unavailable"* ||
		"$out" != *"kernel that reports processed-instruction counts"* ]]; then
		bad "preflight #17769: exit 5 must prescribe restoring measurement; got: $out"
	elif [[ "$out" == *"LOW-HEADROOM:"* || "$out" == *"Free verifier headroom"* ||
		"$out" == *"rebuilding the shim will not help"* || "$out" == *"stale pin cleared"* ]]; then
		bad "preflight #17769: exit 5 was confused with measured low headroom or generic refusal; got: $out"
	else
		ok "preflight #17769: exit 5 refuses with measurement remediation, not low-headroom/stale-pin advice"
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

# #12659: on the real `cluster-setup.sh deploy` path, CLUSTER_LAN_HOST was
# never set (only LAN_HOST comes from the env file), so priming never ran and
# every deploy verified in the fallback regime. Reproduce that exact env
# shape: the deploy path must derive the remote-qualified CLUSTER_LAN_HOST
# (the cluster-env.sh LAN_HOST -> CLUSTER_LAN_HOST bridge, via cluster-setup's
# own r() remote qualification), and priming must then actually issue the ping
# on the derived ref. A bare-name or missing derivation would ping a
# nonexistent "local" instance on remote clusters, so the FULL argv ref is
# asserted, not just that some ping happened.
test_lan_host_bridge_derives_cluster_lan_host_12659() {
	reset_cli_mock
	local derived
	derived=$( LAN_HOST="cluster-userspace-host" INCUS_REMOTE="loss" \
		deploy_lan_host_ref ) || { bad "lan-host(12659): deploy_lan_host_ref failed with LAN_HOST+INCUS_REMOTE set"; return; }
	if [[ "$derived" != "loss:cluster-userspace-host" ]]; then
		bad "lan-host(12659): want loss:cluster-userspace-host, got '$derived'"
		return
	fi
	derived=$( CLUSTER_LAN_HOST="$derived" INCUS_REMOTE="loss" deploy_lan_host_ref )
	if [[ "$derived" != "loss:cluster-userspace-host" ]]; then
		bad "lan-host(12659): repeated resolution changed the qualified ref to '$derived'"
		return
	fi
	derived=$( LAN_HOST="cluster-lan-host" INCUS_REMOTE= \
		deploy_lan_host_ref ) || { bad "lan-host(12659): deploy_lan_host_ref failed with no remote"; return; }
	if [[ "$derived" != "cluster-lan-host" ]]; then
		bad "lan-host(12659): want cluster-lan-host (no remote), got '$derived'"
		return
	fi
	# Explicit operator override still wins, already-qualified included.
	derived=$( LAN_HOST="ignored" CLUSTER_LAN_HOST="mine:lan" INCUS_REMOTE="loss" \
		deploy_lan_host_ref ) || { bad "lan-host(12659): explicit CLUSTER_LAN_HOST override rejected"; return; }
	if [[ "$derived" != "mine:lan" ]]; then
		bad "lan-host(12659): explicit CLUSTER_LAN_HOST override lost: got '$derived'"
		return
	fi
	ok "lan-host(12659): deploy path derives remote-qualified CLUSTER_LAN_HOST from LAN_HOST and honors an explicit override"
}

# Mutant-killing priming cell: with ONLY the cluster-setup deploy env shape
# (LAN_HOST + INCUS_REMOTE + IPERF_TARGET4, CLUSTER_LAN_HOST unset), the
# reassert must take the PRIMED regime and issue the ping against the derived
# remote-qualified ref. If the derivation regresses to a bare name or drops
# out, the ping line below no longer matches and the regime flips to fallback.
test_reassert_primes_from_lan_host_without_cluster_lan_host_12659() {
	reset_cli_mock
	setup_fake_vm
	CLI_STATUS_RESPONSES=("$STATUS_BOTH_RG_NODE0_PRIMARY")
	local out rc=0
	out=$(
		unset CLUSTER_LAN_HOST
		export LAN_HOST="cluster-userspace-host" INCUS_REMOTE="loss" IPERF_TARGET4="172.16.80.200"
		CLUSTER_LAN_HOST=$(deploy_lan_host_ref)
		export CLUSTER_LAN_HOST
		DEPLOY_REASSERT_PRIME_COUNT=3 \
			deploy_reassert_primary_node0 "fake:vm0" "fake:vm1" 2>&1
	) || rc=$?
	if (( rc != 0 )) || ! printf '%s' "$out" | grep -q "primed regime"; then
		bad "reassert(12659): LAN_HOST-only deploy env did not reach the primed regime (rc=$rc)"
		return
	fi
	if ! grep -qF "exec loss:cluster-userspace-host -- ping -c 3" "$FAKE_CALL_LOG"; then
		bad "reassert(12659): priming ping was not issued on loss:cluster-userspace-host"
		return
	fi
	ok "reassert(12659): cluster-setup deploy env (LAN_HOST only) primes liveness on the remote-qualified LAN host"
	teardown_fake_vm
}

# The complement: when the LAN host genuinely cannot be named, priming must
# stay off (fallback), not guess. Empty LAN_HOST and empty CLUSTER_LAN_HOST
# must yield no ref and no ping.
test_lan_host_bridge_empty_stays_unprimed_12659() {
	reset_cli_mock
	local derived
	derived=$( LAN_HOST= CLUSTER_LAN_HOST= INCUS_REMOTE="loss" deploy_lan_host_ref )
	if [[ -n "$derived" ]]; then
		bad "lan-host(12659): empty LAN_HOST/CLUSTER_LAN_HOST yielded a phantom ref '$derived'"
		return
	fi
	ok "lan-host(12659): no LAN host name -> no ref, priming stays off (fallback), nothing is guessed"
}

# Wiring: cluster-setup.sh must export the derived ref before cmd_deploy's
# reassert runs. Deleting the derivation leaves the function defined but the
# deploy path unset again, so the assignment line in cluster-setup.sh is
# pinned, not just the lib helper.
test_lan_host_bridge_is_wired_into_cluster_setup_12659() {
	local f="${SCRIPT_DIR}/cluster-setup.sh"
	if grep -q 'CLUSTER_LAN_HOST="$(deploy_lan_host_ref)"' "$f"; then
		ok "wiring(12659): cluster-setup.sh derives CLUSTER_LAN_HOST from LAN_HOST via deploy_lan_host_ref"
	else
		bad "wiring(12659): cluster-setup.sh never derives CLUSTER_LAN_HOST — the deploy path still cannot prime liveness"
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
	# (-n )? keeps the count keyed on the CALL, not on its flag spelling; the
	# mock's stdin drain is what makes a missing -n visible here (#9683).
	peer=$(grep -cE '^exec (-n )?fake:vm1 -- cli -c request chassis cluster failover reset redundancy-group' "$FAKE_CALL_LOG" || true)
	node0=$(grep -cE '^exec (-n )?fake:vm0 -- cli -c request chassis cluster failover reset redundancy-group' "$FAKE_CALL_LOG" || true)
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

# ── #12658: a refused transfer is re-sent while the commit wait runs ──────
# Live shape: once RG1 lands on a freshly cut node0 that has not yet proven XSK
# liveness, node0 reads RG2 `userspace XSK liveness not proven` for ~2s and
# RequestPeerFailover REFUSES the RG2 transfer. The reassert sent it once and
# swallowed the refusal, so under preempt=no RG2 stayed on node1: 3 of 4
# rolling deploys on 2026-10-13 ended split-RG, with every LAN->WAN flow across
# the generic-XDP fabric at ~6 Gbps.
STATUS_THREE_RG_NODE0_PRIMARY="Redundancy group: 0 , Failover count: 0
node0   200       primary        no       no       None
node1   100       secondary      no       no       None

Redundancy group: 1 , Failover count: 0
node0   200       primary        no       no       None
node1   100       secondary      no       no       None

Redundancy group: 2 , Failover count: 0
node0   200       primary        no       no       None
node1   100       secondary      no       no       None
"

# The state those three deploys were left in.
STATUS_RG2_ON_NODE1="Redundancy group: 0 , Failover count: 0
node0   200       primary        no       no       None
node1   100       secondary      no       no       None

Redundancy group: 1 , Failover count: 0
node0   200       primary        no       no       None
node1   100       secondary      no       no       None

Redundancy group: 2 , Failover count: 0
node0   200       secondary      no       no       None
node1   100       primary        no       no       None
"

# Ownership of RG2 moves only once its transfer has been SENT TWICE.
_status_rg2_lands_on_second_send_12658() {
	local sends
	sends=$(grep -cx 'request chassis cluster failover redundancy-group 2 node 0' "$CLI_LOG" || true)
	if (( sends >= 2 )); then
		printf '%s\n' "$STATUS_THREE_RG_NODE0_PRIMARY"
	else
		printf '%s\n' "$STATUS_RG2_ON_NODE1"
	fi
}

_status_rg2_never_lands_12658() {
	printf '%s\n' "$STATUS_RG2_ON_NODE1"
}

# #7771 for a re-sent transfer: the LAST transfer for <rg> must be followed by
# a status read before the first pin-clearing reset after it. Echoes the
# offending position on failure.
_last_transfer_read_before_clear_12658() {
	local rg="$1" xfer_ln clear_ln between
	xfer_ln=$(grep -nx "request chassis cluster failover redundancy-group $rg node 0" "$CLI_LOG" | tail -1 | cut -d: -f1)
	if [[ -z "$xfer_ln" ]]; then
		echo "no transfer issued for rg$rg"
		return 1
	fi
	clear_ln=$(awk -v n="$xfer_ln" -v want="request chassis cluster failover reset redundancy-group $rg" \
		'NR > n && $0 == want { print NR; exit }' "$CLI_LOG")
	if [[ -z "$clear_ln" ]]; then
		echo "no pin-clearing reset after the last transfer (line $xfer_ln)"
		return 1
	fi
	between=$(sed -n "$((xfer_ln + 1)),$((clear_ln - 1))p" "$CLI_LOG" | grep -cx 'show chassis cluster status' || true)
	if (( between < 1 )); then
		echo "last transfer (line $xfer_ln) is followed by its pin reset (line $clear_ln) with no status read between"
		return 1
	fi
}

test_rgs_not_role_lists_only_unowned_groups_12658() {
	local split all partial
	split=$(printf '%s' "$STATUS_RG2_ON_NODE1" | deploy_node_rgs_not_role node0 primary | tr '\n' ' ')
	all=$(printf '%s' "$STATUS_THREE_RG_NODE0_PRIMARY" | deploy_node_rgs_not_role node0 primary | tr '\n' ' ')
	partial=$(printf '%s' "$STATUS_RG0_OK_RG1_INVERTED" | deploy_node_rgs_not_role node0 primary | tr '\n' ' ')
	if [[ "$split" == "2 " && -z "$all" && "$partial" == "1 " ]]; then
		ok "reassert: rgs-not-role lists exactly the groups node0 does not own (split='2', all-primary='', partial='1')"
	else
		bad "reassert: rgs-not-role -> split='$split' (want '2 '), all-primary='$all' (want ''), partial='$partial' (want '1 ')"
	fi
}

test_reassert_resends_a_refused_transfer_12658() {
	reset_cli_mock
	CLI_STATUS_FN=_status_rg2_lands_on_second_send_12658
	local rc=0 sends why
	( DEPLOY_REASSERT_TRANSFER_DELAY=0 \
		deploy_reassert_primary_node0 "fake:vm0" "fake:vm1" ) >/dev/null 2>&1 || rc=$?
	sends=$(grep -cx 'request chassis cluster failover redundancy-group 2 node 0' "$CLI_LOG" || true)
	if (( rc != 0 || sends < 2 )); then
		bad "reassert: node0 refused the first RG2 transfer and it was sent $sends time(s) (rc=$rc). A refused transfer that is never re-sent leaves RG2 on node1 under preempt=no: split-RG, LAN->WAN across the fabric (#12658)."
		return
	fi
	if ! why=$(_last_transfer_read_before_clear_12658 2); then
		bad "reassert: the RG2 re-send broke the #7771 ordering: $why"
		return
	fi
	ok "reassert: a refused RG2 transfer is re-sent until it lands (sends=$sends); its pin is cleared only after a status read (#12658 + #7771)"
}

test_reassert_resend_is_bounded_and_ordered_12658() {
	reset_cli_mock
	CLI_STATUS_FN=_status_rg2_never_lands_12658
	local rc=0 sends why
	( DEPLOY_REASSERT_TRANSFER_TRIES=4 DEPLOY_REASSERT_TRANSFER_DELAY=0 \
		deploy_reassert_primary_node0 "fake:vm0" ) >/dev/null 2>&1 || rc=$?
	sends=$(grep -cx 'request chassis cluster failover redundancy-group 2 node 0' "$CLI_LOG" || true)
	# One initial send, then one re-send per pass EXCEPT the last: 1 + (4 - 1).
	if (( rc == 0 || sends != 4 )); then
		bad "reassert: RG2 never lands -> want rc!=0 and exactly 4 sends (1 + 3 re-sends over 4 passes), got rc=$rc sends=$sends"
		return
	fi
	if ! why=$(_last_transfer_read_before_clear_12658 2); then
		bad "reassert: a re-send on the final pass reintroduces #7771: $why"
		return
	fi
	ok "reassert: an RG that never lands is re-sent a bounded number of times (sends=$sends), the reassert still dies, and the pin is cleared only after a status read"
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
# session-count shortfall, so the run read as "too few session entries"
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
	# Neither node reports session entries: the flow table is empty, a
	# DIFFERENT failure with a different fix. Reporting it as divergence would
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
	# The peer carrying a FEW synced session entries while the primary carries
	# none is still a session-count shortfall — session sync means the peer
	# legitimately holds entries, so "peer has some" cannot be the discriminator.
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

test_manifest_node_index_maps_configured_instances() {
	local fw0="custom-remote:primary-node-alpha"
	local fw1="custom-remote:secondary-node-beta"
	local got0 got1
	if got0=$(deploy_manifest_node_index "$fw0" "$fw0" "$fw1") &&
		got1=$(deploy_manifest_node_index "$fw1" "$fw0" "$fw1") &&
		[[ "$got0" == 0 && "$got1" == 1 ]] &&
		! deploy_manifest_node_index "unrecognized-custom-node" "$fw0" "$fw1" >/dev/null 2>&1; then
		ok "deploy manifest node mapping: configured names select stable slots and unknown names are refused"
	else
		bad "deploy manifest node mapping: configured names did not select stable slots or unknown name was accepted"
	fi
}

test_manifest_raw_records_verified_binary_hashes() {
	local fixture root manifest xpfd_sha0 xpfd_sha1 helper_sha0 helper_sha1
	local before after got0 got1 got_helper0 got_helper1 rc
	fixture=$(mktemp -d)
	root="$fixture/root"
	mkdir -p "$root"
	git -C "$root" init -q
	git -C "$root" config user.email t@t
	git -C "$root" config user.name t
	printf 'tracked build source\n' >"$root/source"
	git -C "$root" add source && git -C "$root" commit -qm init
	before=$(deploy_build_git_sha "$root")
	mkdir -p "$root/test/results/ledger.d"
	printf '{"run_id":"previous-row"}\n' >"$root/test/results/ledger.d/previous.json"
	after=$(deploy_build_git_sha "$root")
	manifest="$fixture/raw-manifest.json"

	printf 'raw xpfd build for fw0\n' >"$root/xpfd"
	printf 'raw cli build for fw0\n' >"$root/cli"
	printf 'raw helper build for fw0\n' >"$root/xpf-userspace-dp"
	xpfd_sha0=$(sha256sum "$root/xpfd" | awk '{print $1}')
	helper_sha0=$(sha256sum "$root/xpf-userspace-dp" | awk '{print $1}')
	if [[ "$before" != "$after" ]]; then
		bad "manifest git identity: an existing ledger row made the deploy look dirty"
	elif ! XPF_DEPLOY_MANIFEST="$manifest" deploy_write_manifest "$root" "" "$after" 0; then
		bad "raw deploy manifest: writer refused fw0's verified xpfd artifact"
	elif ! got0=$(XPF_DEPLOY_MANIFEST="$manifest" deploy_manifest_sha xpfd "$root" "$after" 0) ||
		[[ "$got0" != "$xpfd_sha0" ]]; then
		bad "raw deploy manifest: fw0 slot contains $got0, expected $xpfd_sha0"
	else
		ok "raw deploy manifest: first node deploy records its artifact in slot 0"
	fi

	printf 'raw xpfd rebuild for fw1 (different BUILD_TIME)\n' >"$root/xpfd"
	printf 'raw cli rebuild for fw1\n' >"$root/cli"
	printf 'raw helper rebuild for fw1\n' >"$root/xpf-userspace-dp"
	xpfd_sha1=$(sha256sum "$root/xpfd" | awk '{print $1}')
	helper_sha1=$(sha256sum "$root/xpf-userspace-dp" | awk '{print $1}')
	if [[ "$xpfd_sha0" == "$xpfd_sha1" || "$helper_sha0" == "$helper_sha1" ]]; then
		bad "rolling deploy fixture: per-node rebuilds must have different bytes"
	elif ! XPF_DEPLOY_MANIFEST="$manifest" deploy_write_manifest "$root" "" "$after" 1; then
		bad "raw deploy manifest: writer refused fw1's verified xpfd artifact"
	elif ! got0=$(XPF_DEPLOY_MANIFEST="$manifest" deploy_manifest_sha xpfd "$root" "$after" 0) ||
		[[ "$got0" != "$xpfd_sha0" ]]; then
		bad "rolling deploy manifest: fw1 deploy overwrote fw0 slot with $got0"
	elif ! got1=$(XPF_DEPLOY_MANIFEST="$manifest" deploy_manifest_sha xpfd "$root" "$after" 1) ||
		[[ "$got1" != "$xpfd_sha1" ]]; then
		bad "rolling deploy manifest: fw1 slot contains $got1, expected $xpfd_sha1"
	elif ! got_helper0=$(XPF_DEPLOY_MANIFEST="$manifest" deploy_manifest_sha xpf-userspace-dp "$root" "$after" 0) ||
		[[ "$got_helper0" != "$helper_sha0" ]]; then
		bad "rolling deploy manifest: fw0 helper slot contains $got_helper0, expected $helper_sha0"
	elif ! got_helper1=$(XPF_DEPLOY_MANIFEST="$manifest" deploy_manifest_sha xpf-userspace-dp "$root" "$after" 1) ||
		[[ "$got_helper1" != "$helper_sha1" ]]; then
		bad "rolling deploy manifest: fw1 helper slot contains $got_helper1, expected $helper_sha1"
	elif ! python3 - "$manifest" "$after" "$xpfd_sha0" "$xpfd_sha1" "$helper_sha0" "$helper_sha1" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
assert doc["schema"] == 2 and set(doc["nodes"]) == {"0", "1"}
for i, xpfd, helper in (("0", sys.argv[3], sys.argv[5]), ("1", sys.argv[4], sys.argv[6])):
    record = doc["nodes"][i]
    assert record["build_git_sha"] == sys.argv[2]
    assert record["mode"] == "raw" and record["deb"] is None
    assert record["binaries"]["xpfd"] == xpfd
    assert record["binaries"]["xpf-userspace-dp"] == helper
PY
	then
		bad "raw deploy manifest: rolling slots do not carry their respective shipped binaries"
	else
		ok "rolling raw deploy manifest: NODE=0 then NODE=1 preserves both distinct slots and helpers"
	fi
	if got0=$(XPF_DEPLOY_MANIFEST="$manifest" deploy_manifest_sha xpfd "$root" "different-checkout" 0); then
		bad "deploy manifest reader: accepted a manifest from a different checkout"
	else
		rc=$?
		if ((rc == 3)); then
			ok "deploy manifest reader: rejects a manifest from a different checkout"
		else
			bad "deploy manifest reader: stale checkout returned rc=$rc, expected 3"
		fi
	fi
	if XPF_DEPLOY_MANIFEST="$manifest" deploy_manifest_invalidate "$root" 1 &&
		[[ "$(XPF_DEPLOY_MANIFEST="$manifest" deploy_manifest_sha xpfd "$root" "$after" 0)" == "$xpfd_sha0" ]] &&
		! XPF_DEPLOY_MANIFEST="$manifest" deploy_manifest_sha xpfd "$root" "$after" 1; then
		ok "deploy manifest invalidation: clears the attempted node slot and preserves its peer"
	else
		bad "deploy manifest invalidation: node 1 failure did not preserve only node 0's slot"
	fi
	if XPF_DEPLOY_MANIFEST="$manifest" deploy_manifest_invalidate "$root" all &&
		[[ ! -e "$manifest" ]]; then
		ok "deploy manifest invalidation: all-node deploy clears the prior record"
	else
		bad "deploy manifest invalidation: all-node invalidation left stale provenance"
	fi
	rm -rf "$fixture"
}

test_manifest_deb_hashes_package_payload() {
	local fixture root pkg deb manifest packaged_sha local_sha got
	if ! command -v dpkg-deb >/dev/null 2>&1; then
		echo "  (skipped deploy manifest .deb extraction: dpkg-deb unavailable)"
		return
	fi
	fixture=$(mktemp -d)
	root="$fixture/root"
	pkg="$fixture/pkg"
	deb="$fixture/xpf_0.0.29580+gaaaaaaaaaaaa_amd64.deb"
	manifest="$fixture/deb-manifest.json"
	mkdir -p "$root" "$pkg/DEBIAN" "$pkg/usr/local/share/xpf/staged"
	chmod 0755 "$pkg/DEBIAN"
	git -C "$root" init -q
	git -C "$root" config user.email t@t
	git -C "$root" config user.name t
	printf 'tracked build source\n' >"$root/source"
	git -C "$root" add source && git -C "$root" commit -qm init
	printf 'local rebuild, not the package\n' >"$root/xpfd"
	printf 'packaged xpfd artifact\n' >"$pkg/usr/local/share/xpf/staged/xpfd"
	printf 'packaged cli artifact\n' >"$pkg/usr/local/share/xpf/staged/cli"
	printf 'packaged helper artifact\n' >"$pkg/usr/local/share/xpf/staged/xpf-userspace-dp"
	cat >"$pkg/DEBIAN/control" <<'CONTROL'
Package: xpf-fixture
Version: 1.0
Architecture: all
Maintainer: test <test@example.com>
Description: deploy manifest fixture
CONTROL
	if ! dpkg-deb --build "$pkg" "$deb" >/dev/null 2>&1; then
		bad "deb deploy manifest: could not build package fixture"
		rm -rf "$fixture"
		return
	fi
	packaged_sha=$(sha256sum "$pkg/usr/local/share/xpf/staged/xpfd" | awk '{print $1}')
	local_sha=$(sha256sum "$root/xpfd" | awk '{print $1}')
	got=$(deploy_manifest_sha_from_deb "$deb" xpfd || true)
	if [[ "$got" != "$packaged_sha" ]]; then
		bad "deb deploy manifest: extractor got $got, expected package payload $packaged_sha"
	elif [[ "$got" == "$local_sha" ]]; then
		bad "deb deploy manifest: package extractor incorrectly used local rebuild bytes"
	elif ! XPF_DEPLOY_MANIFEST="$manifest" deploy_write_manifest "$root" "$deb" "" 0; then
		bad "deb deploy manifest: writer refused package payload"
	elif ! got=$(XPF_DEPLOY_MANIFEST="$manifest" deploy_manifest_sha xpfd "$root" "" 0) || [[ "$got" != "$packaged_sha" ]]; then
		bad "deb deploy manifest: recorded $got, expected package payload $packaged_sha"
	elif ! python3 - "$manifest" "$(basename "$deb")" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
assert doc["schema"] == 2 and set(doc["nodes"]) == {"0"}
record = doc["nodes"]["0"]
assert record["mode"] == "deb" and record["deb"] == sys.argv[2]
assert record["deb_version"] == "0.0.29580+gaaaaaaaaaaaa", record.get("deb_version")
PY
	then
		bad "deb deploy manifest: mode, package basename or deb_version (#18772) missing"
	else
		ok "deb deploy manifest: attests payload bytes rather than a fresh local rebuild"
	fi
	rm -rf "$fixture"
}

test_manifest_write_wired_after_cluster_deploy() {
	local code invalidate first_deploy raw_call deb_call rebaseline=""
	local record trap_arm disarm
	code=$(awk '/^cmd_deploy\(\)/,/^}/' "$SCRIPT_DIR/cluster-setup.sh")
	invalidate=$(grep -n 'deploy_manifest_invalidate "$PROJECT_ROOT" "$target"' <<<"$code" | cut -d: -f1)
	first_deploy=$(grep -nE 'deploy_(vm|vm_deb|rolling|rolling_deb)( |;)' <<<"$code" |
		head -1 | cut -d: -f1)
	raw_call=$(grep -n 'deploy_write_manifest "$PROJECT_ROOT" "" "$deploy_git_sha" "$target"' <<<"$code" | cut -d: -f1)
	deb_call=$(grep -n 'deploy_write_manifest "$PROJECT_ROOT" "$attestation_deb" "$deploy_git_sha" "$target"' <<<"$code" | cut -d: -f1)
	record=$(grep -n 'deploy_manifest_record_failure "$PROJECT_ROOT" "$target"' <<<"$code" | cut -d: -f1)
	trap_arm=$(grep -n 'deploy_manifest_arm_failure_guard "$PROJECT_ROOT" "$target"' <<<"$code" | cut -d: -f1)
	disarm=$(grep -n '^[[:space:]]*trap - EXIT$' <<<"$code" | cut -d: -f1)
	rebaseline=$(grep -n '^[[:space:]]*xpf_cluster_rebaseline_build$' <<<"$code" | cut -d: -f1)
	# The EXIT trap covers every `set -e` abort / die between invalidation
	# and the manifest write (#16290); it must be armed after invalidate,
	# reference the refusal recorder, and be disarmed only after the write.
	record=(${record// / })
	if [[ -z "$invalidate" || -z "$first_deploy" || -z "$raw_call" ||
		-z "$deb_call" || -z "$rebaseline" || ${#record[@]} -lt 2 ||
		-z "$trap_arm" || -z "$disarm" ]] ||
		((invalidate >= trap_arm || trap_arm >= first_deploy ||
			record[0] >= first_deploy || raw_call >= disarm ||
			deb_call >= disarm || disarm >= rebaseline)); then
		bad "cluster deploy wiring: invalidate before push, record refusal on abort, and record both raw/.deb artifacts before re-baselining (#16290)"
	else
		ok "cluster deploy wiring: invalidates before deploy, traps refusal before manifest write, and records raw/.deb artifact before re-baselining"
	fi
}

# #16290 hermetic sequence: deploy A (manifest written) → re-stage refused
# (invalidate, cut aborts, no write) → manifest state must name the refusal
# while attesting NOTHING, and the next successful write must clear it.
# The deploy body is modelled with the real lib calls in cmd_deploy's order;
# the refusal is the `set -e` abort a `refuse-before-PREFLIGHT` exit causes.
test_manifest_refused_deploy_sequence_16290() {
	local fixture root manifest marker after xpfd_sha got reason
	fixture=$(mktemp -d)
	root="$fixture/root"
	mkdir -p "$root"
	git -C "$root" init -q
	git -C "$root" config user.email t@t
	git -C "$root" config user.name t
	printf 'tracked build source\n' >"$root/source"
	git -C "$root" add source && git -C "$root" commit -qm init
	after=$(deploy_build_git_sha "$root")
	manifest="$fixture/xpf-deploy-manifest.json"
	marker="$manifest.failed"
	printf 'raw xpfd build A\n' >"$root/xpfd"
	printf 'raw cli build A\n' >"$root/cli"
	printf 'raw helper build A\n' >"$root/xpf-userspace-dp"
	xpfd_sha=$(sha256sum "$root/xpfd" | awk '{print $1}')

	# Deploy A succeeds: manifest written, no failure marker.
	if ! XPF_DEPLOY_MANIFEST="$manifest" deploy_write_manifest "$root" "" "$after" all; then
		bad "#16290: fixture deploy A manifest write failed"
		rm -rf "$fixture"; return
	elif [[ -e "$marker" ]]; then
		bad "#16290: successful deploy A left a failed-deploy marker"
		rm -rf "$fixture"; return
	elif ! got=$(XPF_DEPLOY_MANIFEST="$manifest" deploy_manifest_sha xpfd "$root" "$after" 0) ||
		[[ "$got" != "$xpfd_sha" ]]; then
		bad "#16290: deploy A manifest does not attest build A"
		rm -rf "$fixture"; return
	else
		ok "#16290: deploy A writes its manifest with no failure marker (control)"
	fi

	# Refused re-deploy, in cmd_deploy's exact order: invalidate, then the
	# cut aborts (modelled), then record the refusal. The subshell mirrors
	# the EXIT-trap recorder without sourcing cluster-setup.sh (which would
	# enter the cluster lock / incus re-exec).
	(
		set -e
		XPF_DEPLOY_MANIFEST="$manifest" deploy_manifest_invalidate "$root" all
		# Cut refusal: `xpfd upgrade --rolling` exits nonzero pre-PREFLIGHT.
		false
	) 2>/dev/null
	XPF_DEPLOY_MANIFEST="$manifest" deploy_manifest_record_failure "$root" all \
		"attestation manifest absent because deploy deb rolling deploy failed (rc=1); re-stage under a DISTINCT version tag (refuse-before-PREFLIGHT)" || true
	if [[ -e "$manifest" ]]; then
		bad "#16290: refused deploy left a manifest behind (stale provenance revived)"
	elif ! reason=$(XPF_DEPLOY_MANIFEST="$manifest" deploy_manifest_failure_reason "$root") ||
		[[ "$reason" != *"deploy all failed"* ]] ||
		[[ "$reason" != *"refuse-before-PREFLIGHT"* ]]; then
		bad "#16290: refused deploy marker does not name the refusal: '$reason'"
	elif XPF_DEPLOY_MANIFEST="$manifest" deploy_manifest_sha xpfd "$root" "$after" 0 >/dev/null 2>&1; then
		bad "#16290: marker alone attested a binary (must fail closed)"
	else
		ok "#16290: invalidate→refused-cut leaves no manifest, a marker naming the refused deploy, and no attestation"
	fi

	# Single-node refusal preserves the peer slot AND records the failure;
	# the attempted slot must not attest.
	XPF_DEPLOY_MANIFEST="$manifest" deploy_write_manifest "$root" "" "$after" all >/dev/null
	XPF_DEPLOY_MANIFEST="$manifest" deploy_manifest_invalidate "$root" 1
	XPF_DEPLOY_MANIFEST="$manifest" deploy_manifest_record_failure "$root" 1 \
		"attestation manifest absent because deploy deb deploy of node 1 failed (rc=1)" || true
	if ! got=$(XPF_DEPLOY_MANIFEST="$manifest" deploy_manifest_sha xpfd "$root" "$after" 0) ||
		[[ "$got" != "$xpfd_sha" ]]; then
		bad "#16290: single-node refusal erased the peer (node 0) attestation"
	elif XPF_DEPLOY_MANIFEST="$manifest" deploy_manifest_sha xpfd "$root" "$after" 1 >/dev/null 2>&1; then
		bad "#16290: refused node 1 slot still attests the prior build"
	elif ! reason=$(XPF_DEPLOY_MANIFEST="$manifest" deploy_manifest_failure_reason "$root") ||
		[[ "$reason" != *"deploy 1 failed"* ]]; then
		bad "#16290: single-node refusal marker names the wrong target: '$reason'"
	else
		ok "#16290: single-node refusal preserves peer attestation, voids only the attempted slot, and names deploy 1"
	fi

	# The next successful deploy clears the marker atomically with its write.
	if ! XPF_DEPLOY_MANIFEST="$manifest" deploy_write_manifest "$root" "" "$after" all; then
		bad "#16290: recovery deploy manifest write failed"
	elif [[ -e "$marker" ]]; then
		bad "#16290: successful recovery deploy did not clear the refusal marker"
	elif XPF_DEPLOY_MANIFEST="$manifest" deploy_manifest_failure_reason "$root" >/dev/null 2>&1; then
		bad "#16290: refusal reason still readable after a successful deploy"
	else
		ok "#16290: a later successful deploy clears the refused-deploy marker"
	fi

	# A fresh attempt's invalidation also supersedes a stale marker, and an
	# empty/corrupt marker reads as no reason (never a false refusal).
	XPF_DEPLOY_MANIFEST="$manifest" deploy_manifest_record_failure "$root" all "stale refusal" || true
	XPF_DEPLOY_MANIFEST="$manifest" deploy_manifest_invalidate "$root" all
	if [[ -e "$marker" ]]; then
		bad "#16290: a new deploy attempt did not supersede the stale refusal marker"
	else
		ok "#16290: invalidation for a new attempt clears the stale refusal marker"
	fi
	printf 'target=bogus\n' >"$marker"
	if XPF_DEPLOY_MANIFEST="$manifest" deploy_manifest_failure_reason "$root" >/dev/null 2>&1; then
		bad "#16290: a marker without a reason was surfaced as a refusal"
	else
		ok "#16290: a marker without a reason fails closed (no fabricated refusal)"
	fi
	rm -rf "$fixture"
}

# #16290 fold (PR #16338): exercise the REAL EXIT-trap path, not a manual
# record_failure call. A child bash arms the guard exactly as cmd_deploy
# does (invalidate -> arm -> step -> failing command under `set -euo
# pipefail`, mirroring the refuse-before-PREFLIGHT abort), exits via the
# trap, and the parent asserts the marker the TRAP wrote: correct global
# target (a function-local target would die unbound under `set -u` and
# write nothing), the step label, and the real abort rc (7, not a
# clobbered 0/1). Two controls: a disarmed guard on an explicit-die path
# keeps the specific reason (trap must not overwrite it), and a guard
# disarmed + trap removed after success writes no marker. The child
# re-declares die after sourcing so this shell's die is not inherited
# semantics under test; only lib functions come from deploy-lib.sh.
test_manifest_failure_guard_trap_fires_16290() {
	local fixture root manifest marker child reason
	fixture=$(mktemp -d)
	root="$fixture/root"
	mkdir -p "$root"
	manifest="$fixture/xpf-deploy-manifest.json"
	marker="$manifest.failed"
	child="$fixture/guard-child.sh"
	cat >"$child" <<'CHILD'
#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$1"; ROOT="$2"; MANIFEST="$3"; MODE="$4"
export XPF_DEPLOY_MANIFEST="$MANIFEST"
info() { :; }
warn() { printf 'warn: %s\n' "$*" >&2; }
die() { echo "die: $*" >&2; exit 1; }
# shellcheck disable=SC1091
source "$SCRIPT_DIR/deploy-lib.sh"
# Simulate cmd_deploy: a function with a LOCAL target (the exact shape
# that broke when the trap referenced it), arm after invalidate, then
# abort the way the refused rolling cut does.
simulate_deploy() {
	local target="all"
	XPF_DEPLOY_MANIFEST="$MANIFEST" deploy_manifest_invalidate "$ROOT" "$target"
	deploy_manifest_arm_failure_guard "$ROOT" "$target"
	deploy_manifest_guard_step "deb rolling deploy"
	case "$MODE" in
	refused)
		# `xpfd upgrade --rolling` refuse-before-PREFLIGHT: nonzero, pre-cut.
		bash -c 'exit 7'
		;;
	explicit-die)
		deploy_manifest_record_failure "$ROOT" "$target" \
			"attestation manifest absent because deploy manifest write failed; no new build was attested" || true
		deploy_manifest_guard_disarm
		die "deploy completed but its executable attestation manifest could not be written"
		;;
	success)
		deploy_manifest_guard_disarm
		trap - EXIT
		return 0
		;;
	esac
}
simulate_deploy
CHILD

	# Case 1: refused cut -> the trap itself must write the marker.
	rm -f "$manifest" "$marker"
	if bash "$child" "$SCRIPT_DIR" "$root" "$manifest" refused 2>"$fixture/refused.log"; then
		bad "#16290 guard: refused child exited 0 (the abort was swallowed)"
	elif [[ -e "$manifest" ]]; then
		bad "#16290 guard: refused deploy left a manifest behind (stale provenance revived)"
	elif ! reason=$(XPF_DEPLOY_MANIFEST="$manifest" deploy_manifest_failure_reason "$root") ||
		[[ "$reason" != *"deploy all failed"* ]] ||
		[[ "$reason" != *"deb rolling deploy failed (rc=7)"* ]]; then
		bad "#16290 guard: trap marker missing/wrong (rc, step, or global target lost): '$reason'; child log: $(cat "$fixture/refused.log")"
	elif XPF_DEPLOY_MANIFEST="$manifest" deploy_manifest_sha xpfd "$root" "" 0 >/dev/null 2>&1; then
		bad "#16290 guard: trap marker attested a binary (must fail closed)"
	else
		ok "#16290 guard: real EXIT trap records the refused deploy (global target, step, rc=7) with no manifest"
	fi

	# Case 2: explicit die path -> specific reason survives, trap silent.
	rm -f "$marker"
	if bash "$child" "$SCRIPT_DIR" "$root" "$manifest" explicit-die 2>/dev/null; then
		bad "#16290 guard: explicit-die child exited 0"
	elif ! reason=$(XPF_DEPLOY_MANIFEST="$manifest" deploy_manifest_failure_reason "$root") ||
		[[ "$reason" != *"manifest write failed"* ]] ||
		[[ "$reason" == *"deb rolling deploy"* ]]; then
		bad "#16290 guard: trap overwrote the explicit die reason: '$reason'"
	else
		ok "#16290 guard: disarmed trap does not overwrite an explicit die-path reason"
	fi

	# Case 3: success (disarm + trap removed) -> no marker at all.
	rm -f "$marker"
	if ! bash "$child" "$SCRIPT_DIR" "$root" "$manifest" success 2>/dev/null; then
		bad "#16290 guard: success child exited nonzero"
	elif [[ -e "$marker" ]]; then
		bad "#16290 guard: successful deploy left a failure marker via the trap"
	else
		ok "#16290 guard: disarmed/removed trap writes no marker on success"
	fi
	rm -rf "$fixture"
}

test_cluster_deploy_gate_runs_in_one_ordered_wave() {
	local code wrapper runner
	code=$(awk '/^cluster-deploy-and-gate:/,/^$/' "$SCRIPT_DIR/../../Makefile")
	wrapper=$(grep -nF './test/incus/with-cluster.sh' <<<"$code" | cut -d: -f1)
	runner=$(grep -nF 'deploy_gate_wave "$$PWD" "$$1"' <<<"$code" | cut -d: -f1)
	if [[ -z "$wrapper" || -z "$runner" ]]; then
		bad "deploy/gate wave: deploy and smoke must use the fenced runner in one lock cell"
	else
		ok "deploy/gate wave: deploy and smoke use the SHA-fenced runner in one lock cell"
	fi
}

test_deploy_gate_wave_fences_checkout_sha() {
	local fixture root fake_make log
	fixture=$(mktemp -d)
	root="$fixture/root"
	mkdir -p "$root"
	git -C "$root" init -q
	git -C "$root" config user.email test@example.invalid
	git -C "$root" config user.name test
	printf 'deployed\n' >"$root/source"
	git -C "$root" add source && git -C "$root" commit -qm deployed || {
		bad "deploy/gate wave: failed to create temporary checkout"
		rm -rf "$fixture"
		return
	}
	fake_make="$fixture/fake-make"
	log="$fixture/gate-called"
	cat >"$fake_make" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == cluster-deploy && "${FAIL_DEPLOY:-0}" == 1 ]]; then
	exit 1
fi
if [[ "$1" == cluster-deploy && "${ADVANCE_CHECKOUT:-0}" == 1 ]]; then
	printf 'advanced\n' >>"$XPF_REPO_ROOT/source"
	git -C "$XPF_REPO_ROOT" add source
	git -C "$XPF_REPO_ROOT" commit -qm advanced
elif [[ "$1" != cluster-deploy ]]; then
	: >"$GATE_MARKER"
fi
SH
	chmod +x "$fake_make"
	if ! declare -F deploy_gate_wave >/dev/null; then
		bad "deploy/gate wave: SHA-fenced runner is unavailable"
		rm -rf "$fixture"
		return
	fi
	if XPF_REPO_ROOT="$root" GATE_MARKER="$log" \
		deploy_gate_wave "$root" test-gate "$fake_make" "$fake_make" cluster-deploy && [[ -e "$log" ]]; then
		ok "deploy/gate wave: unchanged checkout runs deploy then gate"
	else
		bad "deploy/gate wave: unchanged checkout did not run its gate"
	fi
	rm -f "$log"
	if XPF_REPO_ROOT="$root" GATE_MARKER="$log" ADVANCE_CHECKOUT=1 \
		deploy_gate_wave "$root" test-gate "$fake_make" "$fake_make" cluster-deploy >/dev/null 2>&1; then
		bad "deploy/gate wave: gate ran after checkout advanced past deployed SHA"
	elif [[ -e "$log" ]]; then
		bad "deploy/gate wave: advanced checkout reached the gate"
	else
		ok "deploy/gate wave: checkout advance after deploy aborts before gate"
	fi
	rm -f "$log"
	if XPF_REPO_ROOT="$root" GATE_MARKER="$log" FAIL_DEPLOY=1 \
		deploy_gate_wave "$root" test-gate "$fake_make" "$fake_make" cluster-deploy >/dev/null 2>&1; then
		bad "deploy/gate wave: gate ran after a failed deploy"
	elif [[ -e "$log" ]]; then
		bad "deploy/gate wave: failed deploy still reached the gate"
	else
		ok "deploy/gate wave: failed deploy aborts before gate"
	fi
	rm -rf "$fixture"
}


# #12203: committed regression cells for the scoped dual-active role reader.
DUAL_ACTIVE_CHAINED_CRASH="${DUAL_ACTIVE_CHAINED_CRASH:-$SCRIPT_DIR/test-chained-crash.sh}"
DUAL_ACTIVE_HA_CRASH="${DUAL_ACTIVE_HA_CRASH:-$SCRIPT_DIR/test-ha-crash.sh}"

dual_active_status() {
	local lid="$1" spec="$2" peer="${3:-}" pid=$((1 - $1))
	local tok rg role peer_role
	for tok in $spec; do
		rg=${tok%%=*}
		role=${tok#*=}
		printf 'Redundancy group: %s , Failover count: 1\n' "$rg"
		printf '%-6s %-8d %-14s %-8s %-8s %s\n' "node$lid" 200 "$role" no no None
		if [[ -n "$peer" ]]; then
			peer_role=$(tr ' ' '\n' <<<"$peer" | awk -F= -v r="$rg" '$1 == r { print $2 }')
			if [[ -n "$peer_role" ]]; then
				printf '%-6s %-8d %-14s %-8s %-8s %s\n' "node$pid" 100 "$peer_role" no no None
			fi
		fi
		printf '\n'
	done
}

dual_active_assert_row() {
	local smoke="$1" label="$2" rc0="$3" out0="$4" rc1="$5" out1="$6"
	local expected="$7" needle="$8" expected_fails="${9:-}" fn_src output sub_rc pass_count fail_count
	fn_src=$(awk '/^check_no_dual_active\(\) \{$/ { capture=1 } capture { print } capture && /^}$/ { exit }' "$smoke")
	if [[ -z "$fn_src" ]]; then
		bad "$label: could not extract check_no_dual_active from $smoke"
		return
	fi
	output=$(
		export FW0=fw0 FW1=fw1 RC0="$rc0" OUT0="$out0" RC1="$rc1" OUT1="$out1"
		PASS=0 FAIL=0
		incus() {
			case "$2" in
			fw0) printf '%s' "$OUT0"; return "$RC0" ;;
			fw1) printf '%s' "$OUT1"; return "$RC1" ;;
			esac
			return 99
		}
		pass() { PASS=$((PASS + 1)); printf '  PASS  %s\n' "$*"; }
		fail() { FAIL=$((FAIL + 1)); printf '  FAIL  %s\n' "$*"; }
		set -euo pipefail
		eval "$fn_src"
		check_no_dual_active "$label"
		printf 'RESULT pass=%d fail=%d CONTINUED\n' "$PASS" "$FAIL"
	)
	sub_rc=$?
	if [[ "$output" != *CONTINUED* ]]; then
		bad "$label: check aborted under set -e (rc=$sub_rc)"
		return
	fi
	if [[ "$output" =~ RESULT\ pass=([0-9]+)\ fail=([0-9]+)\ CONTINUED ]]; then
		pass_count=${BASH_REMATCH[1]}
		fail_count=${BASH_REMATCH[2]}
	else
		bad "$label: missing result marker"
		return
	fi
	if [[ "$expected" == PASS ]]; then
		if [[ "$pass_count" -gt 0 && "$fail_count" -eq 0 && "$output" == *"$needle"* ]]; then
			ok "$label: PASS as expected"
		else
			bad "$label: expected PASS only with '$needle'; got pass=$pass_count fail=$fail_count"
		fi
	elif [[ "$pass_count" -eq 0 && "$fail_count" -gt 0 && "$output" == *"$needle"* ]] &&
		{ [[ -z "$expected_fails" ]] || [[ "$fail_count" -eq "$expected_fails" ]]; }; then
		ok "$label: FAIL as expected"
	else
		bad "$label: expected FAIL only with '$needle'; got pass=$pass_count fail=$fail_count"
	fi
}

test_dual_active_scoped_reader() {
	local primary='Redundancy group: 0 , Failover count: 1
node0   200       primary        no       no       None
'
	local rg10='Redundancy group: 10 , Failover count: 1
node0   200       secondary      no       no       None
'
	local duplicate='Redundancy group: 1 , Failover count: 1
node0   200       primary        no       no       None
node0   200       secondary      no       no       None
'
	local missing_row='Redundancy group: 1 , Failover count: 1
node1   100       primary        no       no       None
'
	local got
	if got=$(printf '%s' "$primary" | deploy_node_rg_role node0 0) &&
		[[ "$got" == primary ]] &&
		! printf '%s' "" | deploy_node_rg_role node0 0 >/dev/null &&
		! printf '   \n' | deploy_node_rg_role node0 0 >/dev/null &&
		! printf '%s' 'Cluster not configured' | deploy_node_rg_role node0 0 >/dev/null &&
		! printf '%s' "$missing_row" | deploy_node_rg_role node0 1 >/dev/null &&
		! printf '%s' "$duplicate" | deploy_node_rg_role node0 1 >/dev/null &&
		! printf '%s' 'Redundancy group: 0 , Failover count: 1
node0   200
' | deploy_node_rg_role node0 0 >/dev/null &&
		! printf '%s' "$rg10" | deploy_node_rg_role node0 1 >/dev/null &&
		[[ $(printf '%s' "$rg10" | deploy_node_rg_role node0 10) == secondary ]]; then
		ok "dual-active scoped reader: exact node/RG role, empty/missing/duplicate fail, RG10 does not match RG1"
	else
		bad "dual-active scoped reader: exact node/RG role contract failed"
	fi
}

# #18523: `show chassis cluster status` prints Takeover/Transfer/Forwarding
# sub-lines under the LOCAL node's row, so on fw0 the node1 row sits four
# lines below the header. The HA smokes read every (node, RG) through
# deploy_node_rg_role; the control proves the `grep -A2` window they used
# misses exactly this row.
test_rg_role_reader_skips_local_sublines_18523() {
	local split='Redundancy group: 1 , Failover count: 1
node0  200      secondary-hold no       yes      None
  Takeover ready: yes
  Transfer ready: yes
  Forwarding: rg-active=inactive vrrp-master=none
node1  100      primary        no       no       None

Redundancy group: 2 , Failover count: 0
node0  200      primary        no       no       None
  Takeover ready: yes
  Transfer ready: yes
  Forwarding: rg-active=active vrrp-master=none
node1  100      secondary      no       no       None
'
	local old_window
	old_window=$(printf '%s' "$split" | grep -A2 "Redundancy group: 1" | grep node1 | awk '{print $3}' || true)
	if [[ $(printf '%s' "$split" | deploy_node_rg_role node1 1) == primary ]] &&
		[[ $(printf '%s' "$split" | deploy_node_rg_role node0 1) == secondary-hold ]] &&
		[[ $(printf '%s' "$split" | deploy_node_rg_role node1 2) == secondary ]] &&
		[[ -z "$old_window" ]]; then
		ok "RG role reader: peer row below local sub-lines is read; grep -A2 misses it (#18523)"
	else
		bad "RG role reader: peer row below local sub-lines (#18523) not read, or the grep -A2 control no longer misses it"
	fi
}

# #18523: each node's own `Forwarding: rg-active=` line is the forwarding
# authority. Missing, duplicated, wrong-RG and non-active/inactive lines fail
# (rc 1). A DIVERGENCE suffix, or any token besides rg-active=/vrrp-master=,
# is surfaced (rc 2, `<value> -- <suffix>`) so a caller comparing against a
# bare value FAILs and names it; the reader used to drop it.
test_rg_local_forwarding_reader_18523() {
	local fw1_view='Redundancy group: 1 , Failover count: 4
node1  100      primary        no       no       None
  Forwarding: rg-active=active vrrp-master=none
node0  200      secondary-hold no       yes      None

Redundancy group: 2 , Failover count: 3
node1  100      secondary      no       no       None
  Forwarding: rg-active=inactive vrrp-master=none
node0  200      primary        no       no       None
'
	local dup='Redundancy group: 1 , Failover count: 1
node0  200      primary        no       no       None
  Forwarding: rg-active=active vrrp-master=none
  Forwarding: rg-active=inactive vrrp-master=none
'
	local partial='Redundancy group: 1 , Failover count: 1
node0  200      secondary-hold no       yes      None
  Forwarding: rg-active=inactive vrrp-master=partial -- DIVERGENCE: VRRP master on only some member interfaces
node1  100      primary        no       no       None
'
	local nospace='Redundancy group: 2 , Failover count: 1
node0  200      primary        no       no       None
  Forwarding: rg-active=active vrrp-master=none --DIVERGENCE: this node is forwarding for a group it does not own
'
	local odd='Redundancy group: 1 , Failover count: 1
node0  200      primary        no       no       None
  Forwarding: rg-active=maybe vrrp-master=none
'
	local got rc missing=()
	got=$(printf '%s' "$fw1_view" | deploy_rg_local_forwarding 1) && [[ "$got" == active ]] || missing+=("fw1 RG1 active")
	got=$(printf '%s' "$fw1_view" | deploy_rg_local_forwarding 2) && [[ "$got" == inactive ]] || missing+=("fw1 RG2 inactive")
	printf '%s' "$fw1_view" | deploy_rg_local_forwarding 3 >/dev/null && missing+=("RG3 absent")
	printf '%s' "$dup" | deploy_rg_local_forwarding 1 >/dev/null && missing+=("duplicate")
	printf '%s' 'No VRRP groups configured' | deploy_rg_local_forwarding 1 >/dev/null && missing+=("no block")
	printf '%s' "$odd" | deploy_rg_local_forwarding 1 >/dev/null && missing+=("value not active/inactive")
	got=$(printf '%s' "$partial" | deploy_rg_local_forwarding 1)
	rc=$?
	[[ $rc -eq 2 && "$got" == 'inactive -- DIVERGENCE: VRRP master on only some member interfaces' ]] ||
		missing+=("DIVERGENCE suffix rc=$rc got='$got'")
	got=$(printf '%s' "$nospace" | deploy_rg_local_forwarding 2)
	rc=$?
	[[ $rc -eq 2 && "$got" == 'active -- DIVERGENCE: this node is forwarding for a group it does not own' ]] ||
		missing+=("unspaced suffix rc=$rc got='$got'")
	if ((${#missing[@]} == 0)); then
		ok "RG forwarding reader: exact-RG local rg-active; missing/duplicate/odd fail; DIVERGENCE suffix surfaced rc 2 (#18523)"
	else
		bad "RG forwarding reader (#18523): ${missing[*]}"
	fi
}

# aa_view <local-node-id> then, for RG1 and RG2 in order, three words:
# <local role> <local Forwarding value, or - for no line> <peer role>.
# Renders the FormatStatus shape: local row, Takeover/Transfer/Forwarding
# sub-lines, then the peer row.
aa_view() {
	local me="$1" peer=$((1 - $1)) rg=1
	shift
	while (($# >= 3)); do
		printf 'Redundancy group: %s , Failover count: 1\n' "$rg"
		printf 'node%s  100      %-14s no       no       None\n' "$me" "$1"
		printf '  Takeover ready: yes\n  Transfer ready: yes\n'
		[[ "$2" == - ]] || printf '  Forwarding: %s\n' "$2"
		printf 'node%s  200      %-14s no       no       None\n\n' "$peer" "$3"
		rg=$((rg + 1))
		shift 3
	done
}

# aa_split_row <label> <fw0-status> <fw1-status> <want-pass> <want-fail> <needle>
# drives the real deploy_active_active_split_verdict under
# `set -euo pipefail` and checks the exact PASS/FAIL counts and one needle.
aa_split_row() {
	local label="$1" s0="$2" s1="$3" want_pass="$4" want_fail="$5" needle="$6" out
	# shellcheck disable=SC2030,SC2031,SC2329 # mocks and counters scoped to this subshell
	out=$(
		PASS=0 FAIL=0
		pass() { PASS=$((PASS + 1)); printf '  PASS  %s\n' "$*"; }
		fail() { FAIL=$((FAIL + 1)); printf '  FAIL  %s\n' "$*"; }
		set -euo pipefail
		deploy_active_active_split_verdict "$s0" "$s1"
		printf 'RESULT pass=%d fail=%d CONTINUED\n' "$PASS" "$FAIL"
	)
	if [[ "$out" == *"RESULT pass=$want_pass fail=$want_fail CONTINUED"* && "$out" == *"$needle"* ]]; then
		ok "active-active split verdict: $label (#18523)"
	else
		bad "active-active split verdict: $label (#18523): want pass=$want_pass fail=$want_fail with '$needle'; got: $(tr '\n' '|' <<<"$out")"
	fi
}

# #18523: test-active-active.sh scores the RG split through this verdict.
# RG2 is read from BOTH views (fw1 claiming RG2 primary, or forwarding it,
# used to pass), and a DIVERGENCE suffix on any Forwarding line FAILs.
test_active_active_split_verdict_18523() {
	local a='rg-active=active vrrp-master=none' i='rg-active=inactive vrrp-master=none'
	local s0 s1
	s0=$(aa_view 0 secondary-hold "$i" primary primary "$a" secondary)
	s1=$(aa_view 1 primary "$a" secondary-hold secondary "$i" primary)
	aa_split_row "healthy split" "$s0" "$s1" 4 0 "RG2 (LAN) forwarding stayed on fw0"
	aa_split_row "old owner plain secondary" \
		"$(aa_view 0 secondary "$i" primary primary "$a" secondary)" "$s1" 4 0 "RG1 (WAN) moved to fw1"
	aa_split_row "fw1's own view does not hold RG1" \
		"$s0" "$(aa_view 1 secondary-hold "$a" secondary-hold secondary "$i" primary)" 3 1 \
		"RG1 did not move to fw1 (fw0 view: node0=secondary-hold node1=primary; fw1 view: node1=secondary-hold)"
	aa_split_row "fw1 also claims RG2 primary" \
		"$s0" "$(aa_view 1 primary "$a" secondary-hold primary "$i" primary)" 3 1 \
		"RG2 not owned by fw0 alone (fw0 view: node0=primary; fw1 view: node1=primary)"
	aa_split_row "fw1 also forwards RG2" \
		"$s0" "$(aa_view 1 primary "$a" secondary-hold secondary "$a" primary)" 3 1 \
		"RG2 (LAN) forwarding not on fw0 alone (fw0 rg-active=active, fw1 rg-active=active)"
	aa_split_row "DIVERGENCE on fw0 RG1" \
		"$(aa_view 0 secondary-hold 'rg-active=inactive vrrp-master=partial -- DIVERGENCE: VRRP master on only some member interfaces' primary primary "$a" secondary)" \
		"$s1" 3 1 "fw0 rg-active=inactive -- DIVERGENCE: VRRP master on only some member interfaces"
	aa_split_row "DIVERGENCE on fw1 RG2" \
		"$s0" "$(aa_view 1 primary "$a" secondary-hold secondary 'rg-active=inactive vrrp-master=none -- DIVERGENCE: this node owns the group but is not forwarding for it' primary)" \
		3 1 "fw1 rg-active=inactive -- DIVERGENCE"
	aa_split_row "RG1 did not move" \
		"$(aa_view 0 primary "$a" secondary primary "$a" secondary)" \
		"$(aa_view 1 secondary "$i" primary secondary "$i" primary)" 2 2 \
		"RG1 did not move to fw1 (fw0 view: node0=primary node1=secondary; fw1 view: node1=secondary)"
	aa_split_row "no Forwarding lines" \
		"$(aa_view 0 secondary-hold - primary primary - secondary)" \
		"$(aa_view 1 primary - secondary-hold secondary - primary)" 2 2 \
		"RG1 (WAN) forwarding not on fw1 alone (fw0 rg-active=missing, fw1 rg-active=missing)"
	aa_split_row "fw1 status empty" "$s0" "" 0 4 "fw1 view: node1=missing"
}

# ── #18523: restore_fw0_primary with a mocked incus and clock ──────────
# The mock keeps per-RG state in files (every `incus` call runs in a
# command-substitution subshell) and `sleep N` advances SECONDS instead of
# waiting. A granted yield makes fw1 read secondary-hold at once; fw0 reads
# primary RM_DELAY mocked seconds later. Each refused request answers with
# the barrier-fence error seen on integ7a.
RM_REFUSAL='error: demotion peer barrier failed: session sync barrier fenced seq=0'

rm_role() {
	local view="$1" rg="$2" own granted=0 at=0
	own=$(<"$RM_ST/own$rg")
	if [[ -s "$RM_ST/granted$rg" ]]; then
		granted=1
		at=$(<"$RM_ST/granted$rg")
	fi
	if [[ "$view" == 0 ]]; then
		if [[ "$own" == 0 ]] || ((granted && SECONDS >= at + RM_DELAY)); then
			echo primary
		else
			echo secondary
		fi
	elif [[ "$RM_FW1" == dual ]] || [[ "$own" == 1 && "$granted" == 0 ]]; then
		echo primary
	elif ((granted)); then
		echo secondary-hold
	else
		echo secondary
	fi
}

rm_status() {
	local me="$1" peer=$((1 - $1)) rg
	for rg in 0 1 2; do
		printf 'Redundancy group: %s , Failover count: 1\n' "$rg"
		printf 'node%s  100      %-14s no       no       None\n' "$me" "$(rm_role "$me" "$rg")"
		printf '  Takeover ready: yes\n  Transfer ready: yes\n'
		printf 'node%s  200      %-14s no       no       None\n\n' "$peer" "$(rm_role "$peer" "$rg")"
	done
}

rm_incus() {
	local inst="$2" cmd="${*: -1}" rg left
	printf '%s %s\n' "$inst" "$cmd" >>"$RM_ST/calls"
	case "$cmd" in
	"show chassis cluster status")
		if [[ "$inst" == fw0 ]]; then
			rm_status 0
		elif [[ "$RM_FW1" == unreadable ]]; then
			return 1
		else
			rm_status 1
		fi
		;;
	"request chassis cluster failover reset redundancy-group "*) ;;
	"request chassis cluster failover redundancy-group "*)
		rg=${cmd##* }
		left=$(<"$RM_ST/refuse")
		if ((left > 0)); then
			echo $((left - 1)) >"$RM_ST/refuse"
			echo "$RM_REFUSAL"
			return 1
		fi
		[[ -s "$RM_ST/granted$rg" ]] || echo "$SECONDS" >"$RM_ST/granted$rg"
		echo "Manual failover completed for redundancy group $rg"
		;;
	*) return 99 ;;
	esac
}

# rm_run <owner-at-start 0|1> <refusals> <delay> <fw1 normal|dual|unreadable>
#        [RESTORE_FW0_WAIT=<v>] [RESTORE_FW0_BUDGET=<v>]
# runs the real deploy_restore_fw0_primary and prints its verdicts plus
# `RESULT rc=<rc> pass=<n> fail=<n> yields=<n> CONTINUED`. Both knobs are
# unset unless passed, so a caller's environment cannot move a row.
rm_run() {
	local owner="$1" refuse="$2" delay="$3" fw1="$4" rg kv
	shift 4
	RM_ST=$(mktemp -d)
	for rg in 0 1 2; do echo "$owner" >"$RM_ST/own$rg"; done
	echo "$refuse" >"$RM_ST/refuse"
	: >"$RM_ST/calls"
	# shellcheck disable=SC2030,SC2031,SC2329 # mocks and counters scoped to this subshell
	(
		unset RESTORE_FW0_WAIT RESTORE_FW0_BUDGET
		for kv in "$@"; do
			case "$kv" in
			RESTORE_FW0_WAIT=*) export RESTORE_FW0_WAIT="${kv#*=}" ;;
			RESTORE_FW0_BUDGET=*) export RESTORE_FW0_BUDGET="${kv#*=}" ;;
			*) echo "rm_run: unknown setting $kv" ;;
			esac
		done
		export FW0=fw0 FW1=fw1 RM_DELAY="$delay" RM_FW1="$fw1"
		PASS=0 FAIL=0
		incus() { rm_incus "$@"; }
		sleep() { SECONDS=$((SECONDS + ${1%.*})); }
		pass() { PASS=$((PASS + 1)); printf '  PASS  %s\n' "$*"; }
		fail() { FAIL=$((FAIL + 1)); printf '  FAIL  %s\n' "$*"; }
		info() { printf '  info  %s\n' "$*"; }
		set -euo pipefail
		rc=0
		deploy_restore_fw0_primary t || rc=$?
		printf 'RESULT rc=%d pass=%d fail=%d yields=%d CONTINUED\n' "$rc" "$PASS" "$FAIL" \
			"$(grep -c 'request chassis cluster failover redundancy-group' "$RM_ST/calls" || true)"
	)
	rm -rf "$RM_ST"
}

# rm_row <label> <want RESULT prefix> <needle> <rm_run args...>
rm_row() {
	local label="$1" want="$2" needle="$3" out
	shift 3
	out=$(rm_run "$@")
	if [[ "$out" == *"RESULT $want"* && "$out" == *CONTINUED* && "$out" == *"$needle"* ]]; then
		ok "restore verdict: $label (#18523)"
	else
		bad "restore verdict: $label (#18523): want '$want' with '$needle'; got: $(tr '\n' '|' <<<"$out")"
	fi
}

# #18523: the restore verdict both HA smokes run. A completed restore FAILs
# on any refusal or over RESTORE_FW0_BUDGET (rc 0, the run continues); one
# that never completes FAILs with rc 1. fw0 counts as restored only when
# fw1's own view agrees, so a dual-primary RG and an unreadable fw1 are
# "not restored", never an abort.
test_restore_fw0_verdict_18523() {
	rm_row "already restored" "rc=0 pass=1 fail=0 yields=0" "t: fw0 already primary" 0 0 0 normal
	rm_row "prompt, no refusal" "rc=0 pass=1 fail=0 yields=3" "(3 request(s), 0 refused)" 1 0 0 normal
	rm_row "one refusal" "rc=0 pass=0 fail=1 yields=4" \
		"4 request(s), 1 refused; last refusal: RG0: $RM_REFUSAL)" 1 1 0 normal
	rm_row "three refusals" "rc=0 pass=0 fail=1 yields=6" "6 request(s), 3 refused" 1 3 0 normal
	rm_row "over budget, no refusal" "rc=0 pass=0 fail=1 yields=3" "(budget 30s; 3 request(s), 0 refused)" \
		1 0 12 normal
	rm_row "same restore, RESTORE_FW0_BUDGET=45" "rc=0 pass=1 fail=0 yields=3" "(3 request(s), 0 refused)" \
		1 0 12 normal RESTORE_FW0_BUDGET=45
	rm_row "RESTORE_FW0_BUDGET=abc falls back to 30" "rc=0 pass=0 fail=1" "budget 30s" \
		1 0 12 normal RESTORE_FW0_BUDGET=abc
	rm_row "refused until the deadline" "rc=1 pass=0 fail=1" \
		"could not restore fw0 as primary within 60s (last refusal: RG0: $RM_REFUSAL)" 1 20 0 normal
	rm_row "RESTORE_FW0_WAIT=abc falls back to 60" "rc=1 pass=0 fail=1" "within 60s" \
		1 20 0 normal RESTORE_FW0_WAIT=abc
	rm_row "dual-primary is not restored" "rc=1 pass=0 fail=1" "could not restore fw0 as primary" \
		0 0 0 dual
	rm_row "fw1 unreadable is not restored" "rc=1 pass=0 fail=1 yields=0" "could not restore fw0 as primary" \
		0 0 0 unreadable
}

# #18523: the healthy predicate at its edges: equal to the budget passes,
# one second over or one refusal fails.
test_restore_healthy_boundaries_18523() {
	if deploy_restore_healthy 0 30 0 && deploy_restore_healthy 30 30 0 &&
		! deploy_restore_healthy 31 30 0 && ! deploy_restore_healthy 0 30 1 &&
		! deploy_restore_healthy 31 30 2; then
		ok "restore healthy predicate: took<=budget and zero refusals (#18523)"
	else
		bad "restore healthy predicate (#18523): budget/refusal edges wrong"
	fi
}

# ha_smoke_pin_problems_18523 <dir> prints one problem per line for the
# HA smokes in <dir>: a missing file; a `grep -A<n>` window over
# "Redundancy group" in code (any spacing; it missed the peer row and
# aborted active-active); restore/fw0_is_primary not delegating to the
# shared, selftested deploy-lib.sh helpers; active-active not scoring the
# split through deploy_active_active_split_verdict.
ha_smoke_pin_problems_18523() {
	local dir="$1" f code fn
	for f in test-active-active.sh test-ha-crash.sh test-restart-connectivity.sh test-stress-failover.sh; do
		if [[ ! -r "$dir/$f" ]]; then
			echo "$f(missing)"
			continue
		fi
		code=$(grep -v '^[[:space:]]*#' "$dir/$f")
		if awk '/Redundancy group/ && /(-A[[:space:]]*[0-9]|--after-context)/ { hit = 1 } END { exit !hit }' <<<"$code"; then
			echo "$f(grep-A-window)"
		fi
	done
	for f in test-ha-crash.sh test-restart-connectivity.sh; do
		[[ -r "$dir/$f" ]] || continue
		if [[ $(grep -c '^restore_fw0_primary() {$' "$dir/$f") != 1 || $(grep -c '^fw0_is_primary() {$' "$dir/$f") != 1 ]]; then
			echo "$f(restore-defs-not-one)"
		fi
		fn=$(awk '/^restore_fw0_primary\(\) \{$/ { c = 1 } c { print } c && /^}$/ { exit }' "$dir/$f")
		# shellcheck disable=SC2016 # a literal harness line, not an expansion
		[[ "$fn" == *'deploy_restore_fw0_primary "$1"'* ]] || echo "$f(restore-not-shared)"
		fn=$(awk '/^fw0_is_primary\(\) \{$/ { c = 1 } c { print } c && /^}$/ { exit }' "$dir/$f")
		[[ "$fn" == *deploy_restore_fw0_owns_all* ]] || echo "$f(fw0_is_primary-not-shared)"
	done
	f=test-active-active.sh
	if [[ -r "$dir/$f" ]]; then
		code=$(grep -v '^[[:space:]]*#' "$dir/$f")
		# shellcheck disable=SC2016 # a literal harness line, not an expansion
		[[ "$code" == *'deploy_active_active_split_verdict "$fw0_status" "$fw1_status"'* ]] ||
			echo "$f(split-verdict-not-shared)"
	fi
}

# #18523: guard the HARNESS lines, not only the library. The real smokes
# must report no problem, and a fixture copy with a spaced `grep -A 2`, a
# single-quoted `grep -A2`, a local restore, and a deleted file must report
# each one (a matcher that finds nothing would otherwise pass a clean board).
test_ha_smoke_site_pins_18523() {
	local real fixture problems f missing=()
	real=$(ha_smoke_pin_problems_18523 "$SCRIPT_DIR")
	[[ -z "$real" ]] || missing+=("real smokes: $(tr '\n' ' ' <<<"$real")")
	fixture=$(mktemp -d)
	for f in test-active-active.sh test-ha-crash.sh test-restart-connectivity.sh test-stress-failover.sh; do
		cp "$SCRIPT_DIR/$f" "$fixture/$f"
	done
	# shellcheck disable=SC2016 # literal harness lines, not expansions
	printf '%s\n' 'r=$(grep -A 2 "Redundancy group: 1" <<<"$s" | grep node1 || true)' >>"$fixture/test-active-active.sh"
	# shellcheck disable=SC2016
	printf '%s\n' "r=\$(grep -A2 'Redundancy group: 1' <<<\"\$s\" || true)" >>"$fixture/test-restart-connectivity.sh"
	# shellcheck disable=SC2016 # a sed program, not an expansion
	sed -i 's/deploy_restore_fw0_primary "\$1"/local_restore "$1"/' "$fixture/test-ha-crash.sh"
	rm "$fixture/test-stress-failover.sh"
	problems=$(ha_smoke_pin_problems_18523 "$fixture")
	rm -rf "$fixture"
	for f in "test-active-active.sh(grep-A-window)" "test-restart-connectivity.sh(grep-A-window)" \
		"test-ha-crash.sh(restore-not-shared)" "test-stress-failover.sh(missing)"; do
		[[ "$problems" == *"$f"* ]] || missing+=("control not flagged: $f")
	done
	if ((${#missing[@]} == 0)); then
		ok "HA smoke pins: shared readers, restore and split verdict; controls flagged (#18523)"
	else
		bad "HA smoke pins (#18523): ${missing[*]}"
	fi
}

test_dual_active_committed_rows() {
	local allp='0=primary 1=primary 2=primary'
	local alls='0=secondary 1=secondary 2=secondary'
	local p0 p1 s0 s1 ok0 ok1
	p0=$(dual_active_status 0 "$allp")
	p1=$(dual_active_status 1 "$allp")
	s0=$(dual_active_status 0 "$alls" "$allp")
	s1=$(dual_active_status 1 "$alls" "$alls")
	ok0=$(dual_active_status 0 "$alls" "$allp")
	ok1=$(dual_active_status 1 "$allp" "$alls")
	for smoke in "$DUAL_ACTIVE_CHAINED_CRASH" "$DUAL_ACTIVE_HA_CRASH"; do
		local name
		name=$(basename "$smoke")
		dual_active_assert_row "$smoke" "$name row1 both-primary" 0 "$p0" 0 "$p1" FAIL "dual-active detected"
		dual_active_assert_row "$smoke" "$name row2 exactly-one" 0 "$s0" 0 "$ok1" PASS "no dual-active"
		dual_active_assert_row "$smoke" "$name row3 fw0-unreadable" 1 "" 0 "$ok1" FAIL "fw0 cluster status unreadable" 1
		dual_active_assert_row "$smoke" "$name row4 both-unreadable" 1 "" 1 "" FAIL "fw0 cluster status unreadable" 2
		dual_active_assert_row "$smoke" "$name row4 fw1 also read" 1 "" 1 "" FAIL "fw1 cluster status unreadable" 2
		dual_active_assert_row "$smoke" "$name row8 fw1-empty" 0 "$ok0" 0 "" FAIL "fw1 cluster status empty" 1
		dual_active_assert_row "$smoke" "$name row5 no-owner" 0 "$s0" 0 "$s1" FAIL "no primary detected"
		dual_active_assert_row "$smoke" "$name row16 whitespace-only" 0 "   " 0 "$ok1" FAIL "role unreadable"
		dual_active_assert_row "$smoke" "$name row17 duplicate-node-row" 0 "$(dual_active_status 0 '0=secondary 1=primary 1=primary 2=secondary')" 0 "$(dual_active_status 1 '0=primary 1=secondary 2=primary')" FAIL "RG1 role unreadable"
		dual_active_assert_row "$smoke" "$name row18 not-configured" 0 "Cluster not configured" 0 "$p1" FAIL "RG0 role unreadable"
		dual_active_assert_row "$smoke" "$name row19 missing-RG2" 0 "$(dual_active_status 0 '0=secondary 1=secondary')" 0 "$ok1" FAIL "RG2 role unreadable"
		dual_active_assert_row "$smoke" "$name row20 zero-RG-blocks" 0 "Status has no redundancy groups" 0 "$ok1" FAIL "RG0 role unreadable"
		dual_active_assert_row "$smoke" "$name row21 RG10" 0 "$(dual_active_status 0 '0=primary 1=primary 2=primary 10=primary')" 0 "$(dual_active_status 1 '0=secondary 1=secondary 2=secondary 10=secondary')" PASS "no dual-active"
		dual_active_assert_row "$smoke" "$name row24 fw0-rc1-nonempty" 1 "$ok0" 0 "$ok1" FAIL "fw0 cluster status unreadable" 1
		dual_active_assert_row "$smoke" "$name row25 fw1-rc1-nonempty" 0 "$ok0" 1 "$ok1" FAIL "fw1 cluster status unreadable" 1
	done
}

test_dual_active_retired_grep_counterfactual() {
	local fw0="Cluster not configured" fw1
	local old0 old1 rg
	fw1=$(dual_active_status 1 '0=primary 1=primary 2=primary')
	for rg in 0 1 2; do
		old0=$(printf '%s\n' "$fw0" | grep -A2 "Redundancy group: $rg" | grep node0 | grep -c primary || true)
		old1=$(printf '%s\n' "$fw1" | grep -A2 "Redundancy group: $rg" | grep node1 | grep -c primary || true)
		if [[ "$old0/$old1" != 0/1 ]]; then
			bad "dual-active retired-grep counterfactual: row18 fixture stopped producing vacuous 0/1 on RG$rg"
			return
		fi
	done
	dual_active_assert_row "$DUAL_ACTIVE_CHAINED_CRASH" "retired-grep counterfactual" 0 "$fw0" 0 "$fw1" FAIL "role unreadable"
}

test_dual_active_smoke_site_pins() {
	local chain ha chain_fn ha_fn missing=()
	chain=$(grep -v '^[[:space:]]*#' "$DUAL_ACTIVE_CHAINED_CRASH")
	ha=$(grep -v '^[[:space:]]*#' "$DUAL_ACTIVE_HA_CRASH")
	chain_fn=$(awk '/^check_no_dual_active\(\) \{$/ { capture=1 } capture { print } capture && /^}$/ { exit }' "$DUAL_ACTIVE_CHAINED_CRASH")
	ha_fn=$(awk '/^check_no_dual_active\(\) \{$/ { capture=1 } capture { print } capture && /^}$/ { exit }' "$DUAL_ACTIVE_HA_CRASH")
	for code in "$chain" "$ha"; do
		[[ "$code" == *'source "${SCRIPT_DIR}/deploy-lib.sh"'* ]] || missing+=("deploy-lib source")
		[[ "$code" == *'deploy_node_rg_role node0 "$rg"'* ]] || missing+=("node0 scoped reader")
		[[ "$code" == *'deploy_node_rg_role node1 "$rg"'* ]] || missing+=("node1 scoped reader")
	done
	[[ "$chain_fn" == "$ha_fn" ]] || missing+=("smoke check copies differ")
	[[ "$chain_fn" == *'return 0'* ]] || missing+=("explicit return 0")
	if grep -Eq '^[[:space:]]*return([[:space:]]+1)?[[:space:]]*$' <<<"$chain_fn"; then
		missing+=("bare/nonzero return")
	fi
	if (( ${#missing[@]} == 0 )); then
		ok "dual-active smoke pins: both smokes source the shared scoped reader and use byte-identical fail-closed checks"
	else
		bad "dual-active smoke pins: ${missing[*]}"
	fi
}
test_dual_active_scoped_reader
test_rg_role_reader_skips_local_sublines_18523
test_rg_local_forwarding_reader_18523
test_active_active_split_verdict_18523
test_restore_fw0_verdict_18523
test_restore_healthy_boundaries_18523
test_ha_smoke_site_pins_18523
test_dual_active_committed_rows
test_dual_active_retired_grep_counterfactual
test_dual_active_smoke_site_pins
if [[ "${DEPLOY_LIB_SELFTEST_DUAL_ACTIVE_ONLY:-0}" == 1 ]]; then
	echo "----------------------------------------"
	echo "deploy-lib selftest (dual-active cells): $PASS passed, $FAIL failed"
	[[ $FAIL -eq 0 ]]
	exit $?
fi
# ── #16308 prebuilt-deb selection: version, never mtime ──────────────
# The defect: `make cluster-deploy` rebuilt a stock deb (its .PHONY deb
# prereq), which then won `ls -t` selection in cluster-setup.sh and died
# in apt as a downgrade over the operator's prebuilt 99.0.x. These cells
# pin (a) the version-ordered selector, (b) the explicit-pin contract,
# and (c) the Makefile prepare-deb wiring (reuse vs rebuild), driven
# hermetically with a stubbed `dpkg-buildpackage` on PATH.
DEB_FIXTURE_DIR=""
setup_deb_fixture() {
	DEB_FIXTURE_DIR=$(mktemp -d)
}
teardown_deb_fixture() {
	[[ -n "$DEB_FIXTURE_DIR" ]] && rm -rf "$DEB_FIXTURE_DIR"
	DEB_FIXTURE_DIR=""
}
# mkdeb <name> <age-seconds-ago>
mkdeb() {
	local f="$DEB_FIXTURE_DIR/$1"
	: > "$f"
	touch -d "@$(( $(date +%s) - $2 ))" "$f"
}

test_deb_version_parses_filename() {
	local v
	v=$(deploy_deb_version "/x/dist-deb/xpf_99.0.16308+601c5462a991_amd64.deb") || { bad "deb version: 99 filename did not parse"; return; }
	[[ "$v" == "99.0.16308+601c5462a991" ]] && ok "deb version: parses xpf_<ver>_<arch>.deb" || bad "deb version: got '$v'"
	if deploy_deb_version "/x/xpf-appliance_1.2.3_amd64.deb" >/dev/null 2>&1; then
		bad "deb version: appliance meta must not parse as runtime deb"
	else
		ok "deb version: appliance meta rejected"
	fi
}

test_deb_newest_picks_highest_version_not_newest_mtime() {
	setup_deb_fixture
	# Stock deb is NEWEST on disk (the just-rebuilt shape); 99.0.x is older.
	mkdeb "xpf_99.0.16308+601c5462a991_amd64.deb" 3600
	mkdeb "xpf_0.0.23371+g30638bcad36b_amd64.deb" 0
	local got
	got=$(deploy_deb_newest "$DEB_FIXTURE_DIR") || { bad "deb newest: no selection"; teardown_deb_fixture; return; }
	[[ "$got" == *"xpf_99.0.16308"* ]] && ok "deb newest: highest version wins over newest mtime (#16308)" || bad "deb newest: picked $got (mtime regression)"
	teardown_deb_fixture
}

test_deb_newest_stock_only_and_empty() {
	setup_deb_fixture
	if deploy_deb_newest "$DEB_FIXTURE_DIR" >/dev/null 2>&1; then
		bad "deb newest: empty dir must fail"
	else
		ok "deb newest: empty dir fails closed"
	fi
	mkdeb "xpf_0.0.23371+g30638bcad36b_amd64.deb" 0
	local got
	got=$(deploy_deb_newest "$DEB_FIXTURE_DIR") || { bad "deb newest: stock-only no selection"; teardown_deb_fixture; return; }
	[[ "$got" == *"xpf_0.0.23371"* ]] && ok "deb newest: stock-only selects the stock deb" || bad "deb newest: stock-only picked $got"
	teardown_deb_fixture
}

test_deb_select_pin_wins_and_bad_pin_dies() {
	setup_deb_fixture
	mkdeb "xpf_99.0.16308+601c5462a991_amd64.deb" 3600
	mkdeb "xpf_0.0.23371+g30638bcad36b_amd64.deb" 0
	local got
	got=$(XPF_DEPLOY_DEB_PATH="xpf_0.0.23371+g30638bcad36b_amd64.deb" deploy_select_deb "$DEB_FIXTURE_DIR") || { bad "deb select: pin failed"; teardown_deb_fixture; return; }
	[[ "$got" == *"xpf_0.0.23371"* ]] && ok "deb select: explicit pin wins over higher version" || bad "deb select: pin picked $got"
	if ( XPF_DEPLOY_DEB_PATH="xpf_1.2.3_amd64.deb" deploy_select_deb "$DEB_FIXTURE_DIR" ) >/dev/null 2>&1; then
		bad "deb select: missing pin must die"
	else
		ok "deb select: missing pin dies (fail-closed)"
	fi
	teardown_deb_fixture
}

# Makefile wiring: drive `make prepare-deb` / `make -n cluster-deploy`
# against the REAL Makefile with DEB_OUT redirected to a fixture dir.
# The decision cells are decided by make's parse-time state (what exists
# in DEB_OUT, whether DEB_VERSION was explicit) and are asserted from
# `make -n` dry-run output, so no dpkg-buildpackage ever runs and the
# cells stay hermetic and fast.
MAKE_FIXTURE_OUT=""
setup_make_fixture() {
	MAKE_FIXTURE_OUT=$(mktemp -d)
}
teardown_make_fixture() {
	[[ -n "$MAKE_FIXTURE_OUT" ]] && rm -rf "$MAKE_FIXTURE_OUT"
	MAKE_FIXTURE_OUT=""
}
_make_n() { # extra make args...
	(cd "$SCRIPT_DIR/../.." && make --no-print-directory -n "$@" DEB_OUT="$MAKE_FIXTURE_OUT" 2>&1)
}

test_prepare_deb_reuses_prebuilt_99() {
	setup_make_fixture
	: > "$MAKE_FIXTURE_OUT/xpf_99.0.16308+601c5462a991_amd64.deb"
	local out rc
	out=$(_make_n prepare-deb); rc=$?
	if [[ $rc -eq 0 && "$out" == *'Reusing prebuilt deb'*99.0.16308* && "$out" != *"dpkg-buildpackage"* ]]; then
		ok "prepare-deb: prebuilt 99.0.x reused, no stock rebuild (#16308)"
	else
		bad "prepare-deb reuse: rc=$rc out=$out"
	fi
	# And the full deploy path must carry the reuse decision through.
	out=$(_make_n cluster-deploy); rc=$?
	if [[ $rc -eq 0 && "$out" == *'Reusing prebuilt deb'* && "$out" == *"cluster-setup.sh deploy"* && "$out" != *"dpkg-buildpackage"* ]]; then
		ok "cluster-deploy: prebuilt 99.0.x reused end-to-end (no stock rebuild)"
	else
		bad "cluster-deploy reuse: rc=$rc out=$out"
	fi
	teardown_make_fixture
}

test_prepare_deb_fresh_tree_builds_stock() {
	setup_make_fixture
	local out rc
	out=$(_make_n prepare-deb); rc=$?
	if [[ $rc -eq 0 && "$out" == *"dpkg-buildpackage"* ]]; then
		ok "prepare-deb: fresh tree builds stock deb"
	else
		bad "prepare-deb fresh: rc=$rc out=$out"
	fi
	out=$(_make_n cluster-deploy); rc=$?
	if [[ $rc -eq 0 && "$out" == *"dpkg-buildpackage"* && "$out" == *"cluster-setup.sh deploy"* ]]; then
		ok "cluster-deploy: fresh tree builds then deploys"
	else
		bad "cluster-deploy fresh: rc=$rc out=$out"
	fi
	teardown_make_fixture
}

test_prepare_deb_older_only_rebuilds() {
	setup_make_fixture
	: > "$MAKE_FIXTURE_OUT/xpf_0.0.1+gabc_amd64.deb"
	local out rc
	out=$(_make_n prepare-deb); rc=$?
	if [[ $rc -eq 0 && "$out" == *"is older than stock"* && "$out" == *"dpkg-buildpackage"* ]]; then
		ok "prepare-deb: older-only prebuilt rebuilds stock (not reused)"
	else
		bad "prepare-deb older-only: rc=$rc out=$out"
	fi
	teardown_make_fixture
}

test_prepare_deb_explicit_version_builds() {
	setup_make_fixture
	: > "$MAKE_FIXTURE_OUT/xpf_99.0.16308+601c5462a991_amd64.deb"
	local out rc
	out=$(_make_n prepare-deb DEB_VERSION=99.0.5+selftest); rc=$?
	if [[ $rc -eq 0 && "$out" == *"dpkg-buildpackage"* && "$out" != *"Reusing prebuilt deb"* ]]; then
		ok "prepare-deb: explicit DEB_VERSION builds (no reuse shortcut)"
	else
		bad "prepare-deb explicit: rc=$rc out=$out"
	fi
	out=$(_make_n cluster-deploy DEB_VERSION=99.0.5+selftest); rc=$?
	if [[ $rc -eq 0 && "$out" == *'XPF_DEPLOY_DEB_VERSION="99.0.5+selftest"'* ]]; then
		ok "cluster-deploy: explicit DEB_VERSION threaded to script selection"
	else
		bad "cluster-deploy explicit threading: rc=$rc out=$out"
	fi
	teardown_make_fixture
}

test_prepare_deb_fast_never_builds_deb() {
	setup_make_fixture
	local out rc
	out=$(_make_n cluster-deploy XPF_DEPLOY_FAST=1); rc=$?
	if [[ $rc -eq 0 && "$out" != *"dpkg-buildpackage"* && "$out" != *"prepare-deb"* && "$out" == *"cluster-setup.sh deploy"* ]]; then
		ok "cluster-deploy FAST: raw path, no deb build"
	else
		bad "cluster-deploy FAST: rc=$rc out=$out"
	fi
	teardown_make_fixture
}

test_cluster_setup_selects_by_version_wiring() {
	local setup="$SCRIPT_DIR/cluster-setup.sh" rolling="$SCRIPT_DIR/test-rolling-upgrade.sh" missing=()
	grep -q 'deploy_select_deb "$PROJECT_ROOT/dist-deb"' "$setup" || missing+=("cluster-setup deploy/attest selection")
	grep -q 'deploy_select_deb "$PROJECT_ROOT/dist-deb"' "$rolling" || missing+=("rolling-upgrade selection")
	grep -q 'XPF_DEPLOY_DEB_PATH' "$rolling" || missing+=("rolling-upgrade names its pin (fail-closed VOID)")
	if ! awk '/^test-rolling-upgrade:/,/^$/' "$SCRIPT_DIR/../../Makefile" | grep -q 'XPF_DEPLOY_DEB_PATH="$(CURDIR)/dist-deb/xpf_$(DEB_VERSION)_amd64.deb"'; then
		missing+=("Makefile test-rolling-upgrade does not pin the built candidate")
	fi
	if grep -Eq 'ls -t .*dist-deb/xpf_' "$setup" "$rolling"; then
		missing+=("retired ls -t dist-deb selection still present")
	fi
	if grep -Eq '^cluster-deploy:.*\bdeb\b' "$SCRIPT_DIR/../../Makefile" || grep -q 'CLUSTER_DEPLOY_PREREQS = deb' "$SCRIPT_DIR/../../Makefile"; then
		missing+=("Makefile still rebuilds via .PHONY deb prereq")
	fi
	grep -q 'prepare-deb' "$SCRIPT_DIR/../../Makefile" || missing+=("Makefile prepare-deb")
	if (( ${#missing[@]} == 0 )); then
		ok "wiring: cluster-setup selects by version; rolling pins its built candidate; Makefile uses prepare-deb (#16308)"
	else
		bad "wiring #16308: ${missing[*]}"
	fi
}

test_deb_select_version_wins_and_missing_dies() {
	setup_deb_fixture
	mkdeb "xpf_99.0.16308+601c5462a991_amd64.deb" 3600
	mkdeb "xpf_0.0.23371+g30638bcad36b_amd64.deb" 0
	local got
	got=$(XPF_DEPLOY_DEB_VERSION="0.0.23371+g30638bcad36b" deploy_select_deb "$DEB_FIXTURE_DIR") || { bad "deb select: version pin failed"; teardown_deb_fixture; return; }
	[[ "$got" == *"xpf_0.0.23371"* ]] && ok "deb select: explicit version wins over higher version" || bad "deb select: version pin picked $got"
	if ( XPF_DEPLOY_DEB_VERSION="1.2.3+missing" deploy_select_deb "$DEB_FIXTURE_DIR" ) >/dev/null 2>&1; then
		bad "deb select: missing explicit version must die"
	else
		ok "deb select: missing explicit version dies (fail-closed)"
	fi
	teardown_deb_fixture
}

# Fold (#16324 Opus): test-rolling-upgrade builds its candidate via the
# `deb` prerequisite, so its selection MUST be scoped to that candidate —
# highest-version fallback would attest a foreign prebuilt (e.g. a 99.0.x
# dropped in dist-deb/ by another tree) instead of the bits this gate
# just built. The Makefile pins XPF_DEPLOY_DEB_PATH per invocation.
test_rolling_upgrade_candidate_is_pinned_to_built_deb() {
	setup_make_fixture
	setup_deb_fixture
	# Foreign high-version deb present in the fixture DEB_OUT; the gate's
	# own candidate (stock version from the Makefile) must still be pinned.
	: > "$MAKE_FIXTURE_OUT/xpf_99.0.16308+601c5462a991_amd64.deb"
	local out rc pin
	out=$(_make_n test-rolling-upgrade); rc=$?
	pin=$(printf '%s\n' "$out" | grep -o 'XPF_DEPLOY_DEB_PATH="[^"]*"' | head -1 || true)
	if [[ $rc -eq 0 && "$out" == *"dpkg-buildpackage"* && -n "$pin" && "$pin" != *99.0.16308* && "$pin" == 'XPF_DEPLOY_DEB_PATH="/'*'/dist-deb/xpf_'* ]]; then
		ok "rolling-upgrade: Makefile pins candidate to the just-built deb, not the foreign 99.0.x"
	else
		bad "rolling-upgrade pin: rc=$rc pin='$pin' out=$(printf '%s' "$out" | tail -3)"
	fi
	# Fold 2 (3): a relative DEB_OUT must not change or double-prefix the
	# pin — the exported path is always the canonical absolute dist-deb/.
	local out_rel pin_rel
	out_rel=$(_make_n test-rolling-upgrade DEB_OUT=dist-deb); rc=$?
	pin_rel=$(printf '%s\n' "$out_rel" | grep -o 'XPF_DEPLOY_DEB_PATH="[^"]*"' | head -1 || true)
	if [[ "$pin_rel" == "$pin" && "$pin_rel" != *"dist-deb/dist-deb"* && "$pin_rel" != *'XPF_DEPLOY_DEB_PATH="dist-deb'* ]]; then
		ok "rolling-upgrade: relative DEB_OUT still exports the canonical absolute pin (no double-prefix)"
	else
		bad "rolling-upgrade relative DEB_OUT: pin='$pin' pin_rel='$pin_rel'"
	fi
	# Selector level: with that pin set, deploy_select_deb returns the
	# pinned stock deb even though a higher foreign deb sits beside it;
	# without the pin it would (wrongly, for this gate) pick the foreign one.
	local pinned_deb="xpf_0.0.23372+g9dff3bbd6ca8_amd64.deb"
	: > "$MAKE_FIXTURE_OUT/$pinned_deb"
	local got
	got=$(XPF_DEPLOY_DEB_PATH="$MAKE_FIXTURE_OUT/$pinned_deb" deploy_select_deb "$MAKE_FIXTURE_OUT") || { bad "rolling-upgrade: pinned select failed"; teardown_make_fixture; teardown_deb_fixture; return; }
	if [[ "$got" == *"$pinned_deb" ]]; then
		ok "rolling-upgrade: pinned selection returns the built candidate over the foreign 99.0.x"
	else
		bad "rolling-upgrade: pinned selection picked $got"
	fi
	# Fold 2 (1): PATH pin must WIN when a version pin is also set — an
	# ambient XPF_DEPLOY_DEB_VERSION must not override the per-invocation
	# candidate. (Pre-fix precedence picked the version pin's deb.)
	got=$(XPF_DEPLOY_DEB_PATH="$MAKE_FIXTURE_OUT/$pinned_deb" XPF_DEPLOY_DEB_VERSION="99.0.16308+601c5462a991" deploy_select_deb "$MAKE_FIXTURE_OUT") || { bad "rolling-upgrade: PATH+VERSION select failed"; teardown_make_fixture; teardown_deb_fixture; return; }
	if [[ "$got" == *"$pinned_deb" ]]; then
		ok "deb select: PATH pin wins over VERSION pin when both are set"
	else
		bad "deb select: PATH+VERSION picked $got (version pin overrode the candidate pin)"
	fi
	got=$(deploy_select_deb "$MAKE_FIXTURE_OUT") || got=""
	if [[ "$got" == *99.0.16308* ]]; then
		ok "rolling-upgrade: unpinned fallback would pick the foreign deb (pins are load-bearing)"
	else
		bad "rolling-upgrade: unpinned fallback picked '$got' — interaction cell is vacuous"
	fi
	# Missing pinned candidate dies rather than falling back (fail-closed).
	if ( XPF_DEPLOY_DEB_PATH="$MAKE_FIXTURE_OUT/xpf_0.0.99999+gmissing_amd64.deb" deploy_select_deb "$MAKE_FIXTURE_OUT" ) >/dev/null 2>&1; then
		bad "rolling-upgrade: missing pinned candidate must die, not fall back"
	else
		ok "rolling-upgrade: missing pinned candidate dies (no fallback to foreign deb)"
	fi
	teardown_make_fixture
	teardown_deb_fixture
}

# Fold 2 (2): the rolling script itself refuses to run unpinned — even
# with a usable package in dist-deb/ it must VOID before selecting.
# (Static pin: the script cannot be executed hermetically — it enters a
# destructive cluster cell on source — so the gate is asserted on the
# script text plus the selector behaviour above.)
test_rolling_upgrade_requires_pin_env() {
	local rolling="$SCRIPT_DIR/test-rolling-upgrade.sh" missing=()
	local gate_line select_line
	gate_line=$(grep -n 'XPF_DEPLOY_DEB_PATH unset' "$rolling" | head -1 | cut -d: -f1)
	select_line=$(grep -n 'deploy_select_deb' "$rolling" | head -1 | cut -d: -f1)
	[[ -n "$gate_line" ]] || missing+=("no unset-pin VOID gate")
	[[ -n "$select_line" ]] || missing+=("no deploy_select_deb call")
	if [[ -n "$gate_line" && -n "$select_line" ]] && (( gate_line >= select_line )); then
		missing+=("unset-pin gate does not precede selection")
	fi
	grep -q 'if \[\[ -z "${XPF_DEPLOY_DEB_PATH:-}" \]\]; then' "$rolling" || missing+=("gate is not an unset/empty check on XPF_DEPLOY_DEB_PATH")
	if (( ${#missing[@]} == 0 )); then
		ok "rolling-upgrade: unset pin VOIDs before any selection (fail-closed)"
	else
		bad "rolling-upgrade pin gate: ${missing[*]}"
	fi
}
# ── Run ───────────────────────────────────────────────────────────────
test_deb_version_parses_filename
test_deb_newest_picks_highest_version_not_newest_mtime
test_deb_newest_stock_only_and_empty
test_deb_select_pin_wins_and_bad_pin_dies
test_deb_select_version_wins_and_missing_dies
test_prepare_deb_reuses_prebuilt_99
test_prepare_deb_fresh_tree_builds_stock
test_prepare_deb_explicit_version_builds
test_prepare_deb_older_only_rebuilds
test_rolling_upgrade_candidate_is_pinned_to_built_deb
test_rolling_upgrade_requires_pin_env
test_prepare_deb_fast_never_builds_deb
test_cluster_setup_selects_by_version_wiring
test_rolling_secondary_node0_primary
test_rolling_secondary_node0_secondary
test_rolling_secondary_multi_rg_scoped_to_rg0
test_rolling_secondary_hold_counts_as_secondary
test_rolling_secondary_peer_down_defaults
test_rolling_secondary_empty_defaults
test_rolling_rg_ids
# ── #18724: lab cluster key substitution ───────────────────────────────
# A conf carrying DEPLOY_CLUSTER_KEY_TOKEN is pushed only after the token is
# replaced by the key from the host-side secret; nothing prints the key.
_ck_conf() { # dir -> path of a two-line conf carrying the token
	printf 'chassis { cluster {\n        authentication-key "%s";\n} }\n' "$DEPLOY_CLUSTER_KEY_TOKEN" >"$1/in.conf"
	printf '%s' "$1/in.conf"
}

test_cluster_key_render_substitutes_the_token() {
	local d key src out log expect
	d=$(mktemp -d); key="AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/AB="
	printf '%s\n' "$key" >"$d/k.key"; chmod 0600 "$d/k.key"
	src=$(_ck_conf "$d"); out="$d/out.conf"
	# umask 022 so the 0600 check is the function's own doing, not the caller's.
	log=$(umask 022 && deploy_render_cluster_conf "$src" "$d/k.key" "$out" 2>&1)
	printf 'chassis { cluster {\n        authentication-key "%s";\n} }\n' "$key" >"$d/expect"
	# cmp, not $(<): a dropped or added final newline must be visible.
	if [[ -f "$out" ]] && cmp -s "$out" "$d/expect" && [[ "$(stat -c %a "$out")" == 600 &&
		"$log" != *"$key"* ]]; then
		ok "cluster key: the token is replaced by the key, the output is 0600, and the key is never printed"
	else
		bad "cluster key: rendering must replace the token with the key in a 0600 file without printing it"
	fi
	rm -rf "$d"
}

test_cluster_key_render_is_byte_exact() {
	local d fails=""
	d=$(mktemp -d)
	printf '%s\n' "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/AB=" >"$d/k.key"; chmod 0600 "$d/k.key"
	# No token: no final newline, two trailing newlines, an embedded NUL.
	printf 'set system host-name x' >"$d/a.conf"
	printf 'a\n\n' >"$d/b.conf"
	printf 'a\0b\n' >"$d/c.conf"
	for f in a b c; do
		deploy_render_cluster_conf "$d/$f.conf" "" "$d/$f.out" >/dev/null 2>&1 && cmp -s "$d/$f.conf" "$d/$f.out" ||
			fails+=" no-token-$f"
	done
	# Token, no final newline: only the token changes.
	printf 'authentication-key "%s";' "$DEPLOY_CLUSTER_KEY_TOKEN" >"$d/t.conf"
	printf 'authentication-key "%s";' "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/AB=" >"$d/t.expect"
	deploy_render_cluster_conf "$d/t.conf" "$d/k.key" "$d/t.out" >/dev/null 2>&1 && cmp -s "$d/t.out" "$d/t.expect" ||
		fails+=" token-no-final-newline"
	if [[ -z "$fails" ]]; then
		ok "cluster key: rendering is byte-exact (final newlines and NULs kept; only the token changes)"
	else
		bad "cluster key: rendering must preserve every byte but the token:$fails"
	fi
	rm -rf "$d"
}

test_cluster_key_render_without_token_is_unchanged() {
	local d out
	d=$(mktemp -d); out="$d/out.conf"
	printf 'chassis { cluster { authentication-key "hand-keyed-0123456789"; } }\n' >"$d/in.conf"
	if deploy_render_cluster_conf "$d/in.conf" "" "$out" >/dev/null 2>&1 && cmp -s "$d/in.conf" "$out" &&
		[[ ! -e "$d/k.key" ]]; then
		ok "cluster key: a conf without the token is copied byte for byte and needs no key file"
	else
		bad "cluster key: a conf without the token must be pushed unchanged"
	fi
	rm -rf "$d"
}

test_cluster_key_render_refuses_without_key_file() {
	local d src
	d=$(mktemp -d); src=$(_ck_conf "$d")
	if deploy_render_cluster_conf "$src" "" "$d/out.conf" >/dev/null 2>&1 || [[ -e "$d/out.conf" ]]; then
		bad "cluster key: a token-carrying conf with no CLUSTER_AUTH_KEY_FILE must be refused"
	else
		ok "cluster key: a token-carrying conf with no key file named is refused and nothing is written"
	fi
	rm -rf "$d"
}

test_cluster_key_missing_file_is_refused_on_deploy() {
	local d src
	d=$(mktemp -d); src=$(_ck_conf "$d")
	if (unset XPF_CLUSTER_KEY_GENERATE; deploy_render_cluster_conf "$src" "$d/keys/new.key" "$d/out.conf") >/dev/null 2>&1 ||
		[[ -e "$d/keys/new.key" || -e "$d/out.conf" ]]; then
		bad "cluster key: a deploy with the key file missing must be refused and must generate nothing"
	else
		ok "cluster key: a deploy with the key file missing is refused, and nothing is generated or written"
	fi
	rm -rf "$d"
}

test_cluster_key_symlink_is_refused() {
	local d src fails=""
	d=$(mktemp -d); src=$(_ck_conf "$d"); mkdir -m 0700 "$d/keys"
	printf '%s\n' "Zm9vYmFyYmF6cXV4MDEyMzQ1Njc4OWFiY2RlZmdoaWo=" >"$d/real.key"; chmod 0600 "$d/real.key"
	ln -s "$d/real.key" "$d/keys/live.key"
	ln -s "$d/nowhere.key" "$d/keys/dangling.key"
	deploy_render_cluster_conf "$src" "$d/keys/live.key" "$d/o1" >/dev/null 2>&1 && fails+=" live-symlink"
	XPF_CLUSTER_KEY_GENERATE=1 deploy_render_cluster_conf "$src" "$d/keys/dangling.key" "$d/o2" >/dev/null 2>&1 && fails+=" dangling-symlink"
	[[ -e "$d/nowhere.key" ]] && fails+=" generated-through-symlink"
	if [[ -z "$fails" ]]; then
		ok "cluster key: a symlink at the key path is refused, live or dangling, even with generation enabled"
	else
		bad "cluster key: a symlinked key path must be refused:$fails"
	fi
	rm -rf "$d"
}

test_cluster_key_generation_refuses_an_unfixable_dir() {
	local d src
	d=$(mktemp -d); src=$(_ck_conf "$d")
	# A directory the generator cannot set to 0700 (one owned by someone else,
	# or on a read-only mount) must stop generation before a key is written.
	# Only the directory chmod fails; the file chmod still works, so the cell
	# sees whether generation stopped at the directory or carried on.
	if (chmod() { [[ "$1" == 0700 ]] && return 1; command chmod "$@"; }
		XPF_CLUSTER_KEY_GENERATE=1 deploy_render_cluster_conf "$src" "$d/keys/new.key" "$d/out.conf") >/dev/null 2>&1 ||
		[[ -n "$(ls -A "$d/keys" 2>/dev/null)" || -e "$d/out.conf" ]]; then
		bad "cluster key: a key dir that cannot be set to 0700 must refuse generation and write no key"
	else
		ok "cluster key: a key dir that cannot be set to 0700 refuses generation and writes no key"
	fi
	rm -rf "$d"
}

test_cluster_key_create_mints_the_key() {
	local body
	body=$(awk '/^cmd_create\(\) \{/{f=1} f{print} f&&/^\}$/{exit}' "$SCRIPT_DIR/cluster-setup.sh")
	# The mint must follow the create_vm loop (which dies on an existing VM).
	if grep -Fq 'deploy_ensure_cluster_key "$CLUSTER_AUTH_KEY_FILE" generate' <<<"$body" &&
		awk '/create_vm "\$idx"/{v=NR} /deploy_ensure_cluster_key/{k=NR} END{exit !(v && k > v)}' <<<"$body"; then
		ok "cluster key: only cluster-setup.sh create mints a key, after its VMs are newly created"
	else
		bad "cluster key: cmd_create must mint the key file after create_vm, with an explicit 'generate'"
	fi
}

test_cluster_key_generated_when_absent() {
	local d src key
	d=$(mktemp -d); src=$(_ck_conf "$d")
	if (umask 022 && XPF_CLUSTER_KEY_GENERATE=1 deploy_render_cluster_conf "$src" "$d/keys/new.key" "$d/out.conf") >/dev/null 2>&1; then
		key="$(<"$d/keys/new.key")"
		if [[ "$(stat -c %a "$d/keys/new.key")" == 600 && "$(stat -c %a "$d/keys")" == 700 &&
			-z "$(deploy_cluster_key_problem "$key")" && ${#key} -ge 40 &&
			"$(<"$d/out.conf")" == *"authentication-key \"$key\";"* ]]; then
			ok "cluster key: with XPF_CLUSTER_KEY_GENERATE=1 an absent key file is generated (0700 dir, 0600 file, openssl base64) and used"
		else
			bad "cluster key: a generated key must be 0600 in a 0700 dir, valid, and rendered in"
		fi
	else
		bad "cluster key: XPF_CLUSTER_KEY_GENERATE=1 must generate an absent key file"
	fi
	rm -rf "$d"
}

test_cluster_key_existing_file_is_never_rewritten() {
	local d src before after
	d=$(mktemp -d); src=$(_ck_conf "$d")
	printf 'Zm9vYmFyYmF6cXV4MDEyMzQ1Njc4OWFiY2RlZmdoaWo=\n' >"$d/k.key"; chmod 0600 "$d/k.key"
	before=$(sha256sum "$d/k.key")
	deploy_render_cluster_conf "$src" "$d/k.key" "$d/out.conf" >/dev/null 2>&1
	deploy_render_cluster_conf "$src" "$d/k.key" "$d/out2.conf" >/dev/null 2>&1
	after=$(sha256sum "$d/k.key")
	if [[ "$before" == "$after" ]] && cmp -s "$d/out.conf" "$d/out2.conf"; then
		ok "cluster key: an existing key file (the key the live cluster runs) is never rewritten"
	else
		bad "cluster key: an existing key file must be used as is, never regenerated"
	fi
	rm -rf "$d"
}

test_cluster_key_refuses_unusable_keys() {
	local d src k bad_keys=0 cases=('short' 'xpf-lab-ha-psk-cluster-22-CHANGE-ME' 'has"a-double-quote-0123456789' 'has a space 0123456789abcdef')
	d=$(mktemp -d); src=$(_ck_conf "$d")
	for k in "${cases[@]}"; do
		printf '%s\n' "$k" >"$d/k.key"; chmod 0600 "$d/k.key"; rm -f "$d/out.conf"
		if deploy_render_cluster_conf "$src" "$d/k.key" "$d/out.conf" >/dev/null 2>&1 || [[ -e "$d/out.conf" ]]; then
			bad_keys=$((bad_keys + 1))
		fi
	done
	if ((bad_keys == 0)); then
		ok "cluster key: a short, placeholder, quote- or space-carrying key is refused and nothing is written"
	else
		bad "cluster key: $bad_keys unusable key(s) were rendered into a conf"
	fi
	rm -rf "$d"
}

test_cluster_key_deploy_pushes_only_the_rendered_conf() {
	local body
	body=$(awk '/^deploy_vm\(\) \{/{f=1} f{print} f&&/^\}$/{exit}' "$SCRIPT_DIR/cluster-setup.sh")
	if grep -Fq 'deploy_push_cluster_conf "$CLUSTER_CONF" "${CLUSTER_AUTH_KEY_FILE:-}" "$rinst" /etc/xpf/xpf.conf' <<<"$body" &&
		! grep -Eq 'incus file push[^#]*"\$CLUSTER_CONF"' <<<"$body"; then
		ok "cluster key: deploy_vm pushes the conf only through deploy_push_cluster_conf, never \$CLUSTER_CONF itself"
	else
		bad "cluster key: deploy_vm must push \$CLUSTER_CONF through deploy_push_cluster_conf only"
	fi
}

# _ck_push <dir> <mode>: run deploy_push_cluster_conf against a mock incus
# with TMPDIR=<dir>/tmp. mode "ok" records the push; "TERM"/"INT"/"HUP"
# signals the push subshell mid-push, the shape of an operator's ^C or a
# killed session. Prints the exit status.
_ck_push() {
	local d="$1" mode="$2" src
	src=$(_ck_conf "$d")
	(
		incus() {
			printf '%s\n' "$*" >"$d/args"
			cp "${@: -2:1}" "$d/pushed"
			[[ "$mode" == ok ]] || kill -s "$mode" "$BASHPID"
		}
		TMPDIR="$d/tmp" deploy_push_cluster_conf "$src" "$d/k.key" "inst:vm" /etc/xpf/xpf.conf
	) >/dev/null 2>&1
	printf '%s' "$?"
}

test_cluster_key_push_renders_and_cleans_up() {
	local d key rc
	d=$(mktemp -d); mkdir "$d/tmp"; key="AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/AB="
	printf '%s\n' "$key" >"$d/k.key"; chmod 0600 "$d/k.key"
	rc=$(_ck_push "$d" ok)
	if [[ "$rc" == 0 && "$(<"$d/args")" == "file push --mode 0600 --uid 0 --gid 0 $d/tmp/"*"/xpf.conf inst:vm/etc/xpf/xpf.conf" &&
		"$(<"$d/pushed")" == *"authentication-key \"$key\";"* && -z "$(ls -A "$d/tmp")" ]]; then
		ok "cluster key: deploy_push_cluster_conf pushes the rendered conf at 0600 root:root and leaves nothing in TMPDIR"
	else
		bad "cluster key: deploy_push_cluster_conf must push the rendered conf at 0600 and remove its temp dir (rc=$rc)"
	fi
	rm -rf "$d"
}

test_cluster_key_push_cleans_up_on_a_signal() {
	local d sig rc left=""
	d=$(mktemp -d); mkdir "$d/tmp"
	printf '%s\n' "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/AB=" >"$d/k.key"; chmod 0600 "$d/k.key"
	for sig in TERM INT HUP; do
		rc=$(_ck_push "$d" "$sig")
		# The push was reached (the rendered copy existed) and the subshell
		# died by the signal, yet the copy is gone.
		if [[ ! -s "$d/pushed" || "$rc" == 0 || -n "$(ls -A "$d/tmp")" ]]; then
			left+=" $sig(rc=$rc)"
		fi
		rm -f "$d/pushed"; rm -rf "$d/tmp"/*
	done
	if [[ -z "$left" ]]; then
		ok "cluster key: a TERM, INT or HUP during the push still removes the rendered copy from TMPDIR"
	else
		bad "cluster key: a signal during the push must not leave the rendered copy behind:$left"
	fi
	rm -rf "$d"
}

test_cluster_key_refuses_open_permissions() {
	local d src fails=""
	d=$(mktemp -d); src=$(_ck_conf "$d"); mkdir -m 0700 "$d/keys"
	printf '%s\n' "Zm9vYmFyYmF6cXV4MDEyMzQ1Njc4OWFiY2RlZmdoaWo=" >"$d/keys/k.key"
	chmod 0644 "$d/keys/k.key"
	if deploy_render_cluster_conf "$src" "$d/keys/k.key" "$d/out.conf" >/dev/null 2>&1 || [[ -e "$d/out.conf" ]]; then
		fails+=" 0644-file"
	fi
	chmod 0600 "$d/keys/k.key"; chmod 0755 "$d/keys"
	if deploy_render_cluster_conf "$src" "$d/keys/k.key" "$d/out.conf" >/dev/null 2>&1 || [[ -e "$d/out.conf" ]]; then
		fails+=" 0755-dir"
	fi
	# Positive control: the same key at 0600 in a 0700 dir renders.
	chmod 0700 "$d/keys"
	deploy_render_cluster_conf "$src" "$d/keys/k.key" "$d/out.conf" >/dev/null 2>&1 || fails+=" 0600/0700-control"
	if [[ -z "$fails" ]]; then
		ok "cluster key: a key file with group/other bits, or in such a dir, is refused; 0600 in 0700 renders"
	else
		bad "cluster key: open key-file permissions must be refused:$fails"
	fi
	rm -rf "$d"
}

test_cluster_key_each_env_names_its_own_key_file() {
	local env cluster file seen="" problems="" n=0
	for env in "$SCRIPT_DIR"/*-userspace-cluster.env; do
		cluster="$(basename "$env" -userspace-cluster.env)"
		file="$(sed -n 's/^CLUSTER_AUTH_KEY_FILE="\(.*\)"$/\1/p' "$env")"
		n=$((n + 1))
		[[ "$(basename "$file")" == "$cluster.key" ]] || problems+=" $cluster->${file:-unset}"
		[[ " $seen " == *" $file "* ]] && problems+=" $cluster(shared)"
		seen+=" $file"
	done
	if ((n >= 3)) && [[ -z "$problems" ]]; then
		ok "cluster key: each of the $n userspace cluster envs names its own <cluster>.key"
	else
		bad "cluster key: every userspace cluster env must name its own key file ($n envs):$problems"
	fi
}

# The two legacy confs no userspace env selects keep their published
# CHANGE-ME placeholder: tokenising them would re-key those regression
# clusters mid-way through their next rolling raw deploy. They may carry ONLY
# a placeholder, never a real key. Every other docs/ha-cluster*.conf must
# carry the token, and the cell fails on anything else rather than skipping.
CK_PLACEHOLDER_EXEMPT_CONFS=(ha-cluster.conf ha-cluster-loss.conf)

test_cluster_key_lab_confs_carry_only_the_token() {
	local root conf env base keyline value n=0 tokenised=0 problems=""
	root="$(cd "$SCRIPT_DIR/../.." && pwd)"
	for conf in "$root"/docs/ha-cluster*.conf; do
		n=$((n + 1))
		base="$(basename "$conf")"
		if [[ " ${CK_PLACEHOLDER_EXEMPT_CONFS[*]} " == *" $base "* ]]; then
			while IFS= read -r keyline; do
				value="${keyline#*\"}"; value="${value%%\"*}"
				[[ "${value,,}" == *change-me* || "${value,,}" == *example-only* ]] ||
					problems+=" $base(non-placeholder key)"
			done < <(grep -E '^\s*(additional-)?authentication-key\s' "$conf")
			continue
		fi
		if ! grep -Fq "$DEPLOY_CLUSTER_KEY_TOKEN" "$conf"; then
			problems+=" $base(no token)"
			continue
		fi
		tokenised=$((tokenised + 1))
		# Every authentication-key line in a tokenised conf is the token.
		while IFS= read -r keyline; do
			[[ "$keyline" == *"\"$DEPLOY_CLUSTER_KEY_TOKEN\""* ]] || problems+=" $base(literal key)"
		done < <(grep -E '^\s*(additional-)?authentication-key\s' "$conf")
		# ...and some cluster env file both selects it and names a key file.
		for env in "$SCRIPT_DIR"/*cluster.env; do
			grep -Eq "^CLUSTER_CONF=\"(\\\$\\{PROJECT_ROOT\\}/)?docs/$base\"" "$env" &&
				grep -Eq '^CLUSTER_AUTH_KEY_FILE="/[^"]+"' "$env" && continue 2
		done
		problems+=" $base(no env names a key file)"
	done
	if ((tokenised >= 3 && n == tokenised + ${#CK_PLACEHOLDER_EXEMPT_CONFS[@]})) && [[ -z "$problems" ]]; then
		ok "cluster key: $tokenised lab confs carry only the token with a key file named, and the ${#CK_PLACEHOLDER_EXEMPT_CONFS[@]} legacy confs only a placeholder"
	else
		bad "cluster key: docs/ha-cluster*.conf ($n, $tokenised tokenised):${problems:- missing confs}"
	fi
}

test_verify_pushed_sha_match
test_verify_pushed_sha_mismatch_hardfails
test_verify_pushed_sha_absent_hardfails
test_verify_pushed_uid_root_passes
test_verify_pushed_uid_nonroot_hardfails
test_verify_pushed_uid_follows_symlink_hardfails
test_verify_pushed_uid_empty_hardfails
test_cluster_helper_raw_deploy_uses_root_ownership
test_standalone_helper_raw_deploy_uses_root_ownership
test_deb_repush_uses_distinct_remote_slots
test_deb_repush_wiring
test_deb_plan_orders_versions
test_deb_node_action_upgrade_installs
test_deb_node_action_downgrade_refused_without_optin
test_deb_node_action_downgrade_optin
test_deb_node_action_same_version
test_deb_node_runs_deb_compares_both_binaries
test_deb_running_version_reads_dpkg_state
test_deb_floor_moved_aside_and_restored
test_deb_preflight_refuses_before_any_change
test_deb_install_downgrade_flag
test_deb_plan_wiring
test_unit_shadow_removed_packaged_unit_governs_18544
test_unit_shadow_stale_load_without_file_reloads_18544
test_unit_shadow_mask_symlink_left_alone_18544
test_unit_shadow_alias_symlink_not_packaged_hardfails_18544
test_unit_shadow_kept_without_packaged_unit_18544
test_unit_shadow_surviving_removal_hardfails_18544
test_unit_shadow_no_loaded_unit_hardfails_18544
test_unit_shadow_promoted_runtime_unit_rolls_back_18544
test_unit_shadow_packaged_unit_rejected_rolls_back_18544
test_unit_shadow_barrier_units_reconciled_18544
test_unit_shadow_interrupted_stash_restored_18544
test_unit_shadow_rollback_reload_failure_reported_18544
test_unit_shadow_unpackaged_barrier_skipped_18544
test_unit_shadow_loop_propagates_unit_failure_18544
test_unit_shadow_occupied_path_not_overwritten_18544
test_unit_shadow_unpackaged_barrier_stash_restored_18544
test_unit_shadow_unpackaged_barrier_occupied_named_18544
test_unit_shadow_unpackaged_barrier_reload_failure_reported_18544
test_unit_shadow_reconcile_wired_into_deb_deploy_18544
test_manifest_node_index_maps_configured_instances
test_manifest_raw_records_verified_binary_hashes
test_manifest_deb_hashes_package_payload
test_manifest_write_wired_after_cluster_deploy
test_manifest_refused_deploy_sequence_16290
test_manifest_failure_guard_trap_fires_16290
test_cluster_deploy_gate_runs_in_one_ordered_wave
test_deploy_gate_wave_fences_checkout_sha
test_reconcile_stale_pin_removes_managed
test_reconcile_stale_pin_no_pin_noop
test_reconcile_stale_pin_foreign_override_hardfails
test_reconcile_dangling_sbin_removes
test_reconcile_dangling_sbin_keeps_valid
test_verify_running_match
test_running_sha_returns_the_live_sha
test_running_sha_empty_instance_does_not_read_the_local_host
test_helper_running_sha_returns_live_sha
test_helper_running_sha_rejects_empty_instance
test_helper_running_sha_rejects_absent_helper
test_helper_running_sha_rejects_duplicate_helpers
test_helper_verify_stale_binary_hardfails
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
test_lan_host_bridge_derives_cluster_lan_host_12659
test_reassert_primes_from_lan_host_without_cluster_lan_host_12659
test_lan_host_bridge_empty_stays_unprimed_12659
test_lan_host_bridge_is_wired_into_cluster_setup_12659
test_reassert_transfer_rc_is_not_the_verdict
test_rgs_not_role_lists_only_unowned_groups_12658
test_reassert_resends_a_refused_transfer_12658
test_reassert_resend_is_bounded_and_ordered_12658
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
test_preflight_low_headroom_prescribes_budget_remediation
test_preflight_unmeasured_headroom_prescribes_measurement_remediation
test_preflight_precedes_destructive_steps_standalone
test_preflight_precedes_destructive_steps_cluster

test_cluster_key_render_substitutes_the_token
test_cluster_key_render_is_byte_exact
test_cluster_key_render_without_token_is_unchanged
test_cluster_key_render_refuses_without_key_file
test_cluster_key_missing_file_is_refused_on_deploy
test_cluster_key_symlink_is_refused
test_cluster_key_generation_refuses_an_unfixable_dir
test_cluster_key_create_mints_the_key
test_cluster_key_generated_when_absent
test_cluster_key_existing_file_is_never_rewritten
test_cluster_key_refuses_unusable_keys
test_cluster_key_deploy_pushes_only_the_rendered_conf
test_cluster_key_push_renders_and_cleans_up
test_cluster_key_push_cleans_up_on_a_signal
test_cluster_key_refuses_open_permissions
test_cluster_key_each_env_names_its_own_key_file
test_cluster_key_lab_confs_carry_only_the_token
echo "----------------------------------------"
echo "deploy-lib selftest: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
