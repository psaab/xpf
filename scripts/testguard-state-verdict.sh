# shellcheck shell=sh
# scripts/testguard-state-verdict.sh -- sourced (POSIX sh) by every reader of
# the production-state verdict that testguard-run.sh records in
# $XPF_TESTGUARD_STATE_VERDICT: go-test-json.sh, go-test-watch.sh and
# ci_affected_go_tests.sh (#19090).
#
# testguard-run.sh appends exactly one line per run: clean, state-changed,
# not-run (it stopped before the command started) or interrupted (the command
# started and the post-run check never completed). This reader FAILS CLOSED
# (Codex on 37c57fe8ac): only an explicit completed verdict reads as clean.
#
# testguard_state_verdict FILE prints one word:
#   clean          at least one line, and every line is clean or not-run;
#   state-changed  some line is state-changed;
#   incomplete     anything else: no file, an unreadable or empty file, an
#                  interrupted line, or a line this reader does not know.
#
# Readers pass /proc/self/fd/N for a descriptor they opened BEFORE the run,
# so a child that replaced the pathname (a /dev/null symlink) changes nothing
# they read.
testguard_state_verdict() {
	_tsv_any=0
	_tsv_bad=0
	_tsv_changed=0
	# Set before the loop: under `set -u` a first read that fails (a
	# directory, an I/O error) leaves it unset, and the `-n` test below would
	# abort the caller's command substitution with an empty verdict.
	_tsv_line=
	if [ ! -r "$1" ]; then
		echo incomplete
		return 0
	fi
	while IFS= read -r _tsv_line || [ -n "$_tsv_line" ]; do
		_tsv_any=1
		case $_tsv_line in
		clean | not-run) ;;
		state-changed) _tsv_changed=1 ;;
		*) _tsv_bad=1 ;;
		esac
	done <"$1" 2>/dev/null
	if [ "$_tsv_changed" = 1 ]; then
		echo state-changed
	elif [ "$_tsv_bad" = 1 ] || [ "$_tsv_any" = 0 ]; then
		echo incomplete
	else
		echo clean
	fi
}
