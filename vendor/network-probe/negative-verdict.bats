#!/usr/bin/env bats
# Reject false security passes from outages, fail-open agents and unrelated drops.
setup() {
	source "$BATS_TEST_DIRNAME/probe.sh"
	events="$BATS_TEST_TMPDIR/events.txt"
	cat >"$events" <<'LOG'
Sun, 25 Oct 2026 20:00:00 GMT:ip address dropped: 93.184.215.14
Sun, 25 Oct 2026 20:00:00 GMT:endpoint called ip address:port 93.184.215.14:443, domain: , pid: 1234, process: curl, status:
LOG
}

@test "accept exact denied curl destination with live agent" {
	run negative_verdict 7 93.184.215.14 1234 active "$events"
	[ "$status" -eq 0 ]
	[ "$output" = CONFIRMED_BLOCK ]
}

@test "reject a successful connection despite old drop evidence" {
	run negative_verdict 0 93.184.215.14 1234 active "$events"
	[ "$status" -eq 1 ]
}

@test "reject generic DNS failure" {
	run negative_verdict 6 93.184.215.14 1234 active "$events"
	[ "$status" -eq 1 ]
}

@test "reject curl failure when hardener is inactive" {
	run negative_verdict 7 93.184.215.14 1234 failed "$events"
	[ "$status" -eq 1 ]
}

@test "reject a drop for another address" {
	run negative_verdict 7 93.184.215.15 1234 active "$events"
	[ "$status" -eq 1 ]
}

@test "reject another process at the same destination" {
	run negative_verdict 7 93.184.215.14 9999 active "$events"
	[ "$status" -eq 1 ]
}

@test "reject missing local drop even when curl failed" {
	sed '/ip address dropped:/d' "$events" >"$events.tmp"
	mv "$events.tmp" "$events"
	run negative_verdict 7 93.184.215.14 1234 active "$events"
	[ "$status" -eq 1 ]
}

@test "reject malformed destination rather than interpret it as a pattern" {
	run negative_verdict 7 '.*' 1234 active "$events"
	[ "$status" -eq 1 ]
}

@test "accept agent versions without a trailing status field" {
	sed 's/, status:$//' "$events" >"$events.tmp"
	mv "$events.tmp" "$events"
	run negative_verdict 7 93.184.215.14 1234 active "$events"
	[ "$status" -eq 0 ]
}

@test "refuse the claimed pre-hardener baseline when agent is already active" {
	export RUNNER_TEMP="$BATS_TEST_TMPDIR"
	systemctl() { return 0; }
	snapshot() { echo 'incorrectly took a baseline'; }
	run prepare
	[ "$status" -eq 1 ]
	[[ "$output" == *'agent already running'* ]]
	[[ "$output" != *'incorrectly took a baseline'* ]]
}

@test "record the real control address before denied-domain substitution" {
	export RUNNER_TEMP="$BATS_TEST_TMPDIR"
	mkdir -p "$(probe_dir)"
	timeout() {
		shift
		"$@"
	}
	getent() { printf '93.184.215.14 STREAM example.com\n93.184.215.14 DGRAM\n'; }
	run prepare_negative_address
	[ "$status" -eq 0 ]
	[ "$(cat "$(probe_dir)/negative-address.txt")" = 93.184.215.14 ]
}

@test "refuse a pre-hardener sinkhole address" {
	export RUNNER_TEMP="$BATS_TEST_TMPDIR"
	mkdir -p "$(probe_dir)"
	timeout() {
		shift
		"$@"
	}
	getent() { printf '54.185.253.63 STREAM example.com\n'; }
	run prepare_negative_address
	[ "$status" -eq 1 ]
	[ ! -e "$(probe_dir)/negative-address.txt" ]
}

@test "refuse failed pre-hardener resolution" {
	export RUNNER_TEMP="$BATS_TEST_TMPDIR"
	mkdir -p "$(probe_dir)"
	timeout() { return 124; }
	run prepare_negative_address
	[ "$status" -eq 1 ]
	[ ! -e "$(probe_dir)/negative-address.txt" ]
}

@test "use saved address and preserve exact fresh process evidence requirement" {
	export RUNNER_TEMP="$BATS_TEST_TMPDIR"
	mkdir -p "$(probe_dir)"
	printf '93.184.215.14\n' >"$(probe_dir)/negative-address.txt"
	: >"$events"
	getent() {
		printf 'unexpected DNS lookup\n' >&2
		return 1
	}
	curl() {
		printf '%s\n' "$@" >"$(probe_dir)/curl-arguments.txt"
		printf 'Sun, 25 Oct 2026 20:00:00 GMT:ip address dropped: 93.184.215.14\n' >>"$events"
		printf 'Sun, 25 Oct 2026 20:00:00 GMT:endpoint called ip address:port 93.184.215.14:443, domain: , pid: %s, process: curl, status: \n' "$BASHPID" >>"$events"
		return 7
	}
	agent_events() { cat "$events"; }
	sleep() { :; }
	systemctl() { printf 'active\n'; }
	run negative
	[ "$status" -eq 0 ]
	[[ "$output" == *'verdict=CONFIRMED_BLOCK'* ]]
	grep -Fxq 'example.com:443:93.184.215.14' "$(probe_dir)/curl-arguments.txt"
}

@test "missing saved control address never launches a request" {
	export RUNNER_TEMP="$BATS_TEST_TMPDIR"
	mkdir -p "$(probe_dir)"
	curl() { touch "$(probe_dir)/unexpected-request"; }
	run negative
	[ "$status" -eq 1 ]
	[ ! -e "$(probe_dir)/unexpected-request" ]
}

@test "DNS denial and sinkhole curl failure alone never confirm local enforcement" {
	printf 'Sun, 25 Oct 2026 20:35:02 GMT:domain not allowed: example.com.\n' >"$events"
	run negative_verdict 7 54.185.253.63 3424 active "$events"
	[ "$status" -eq 1 ]
	[ "$output" = UNCONFIRMED ]
}

@test "API read accepts HTTP 200 and retains transport receipt without response body" {
	export RUNNER_TEMP="$BATS_TEST_TMPDIR"
	mkdir -p "$(probe_dir)"
	curl() {
		printf '%s\n' "$@" >"$(probe_dir)/api-arguments.txt"
		printf 'http_code=200\nremote_ip=140.82.116.5\nremote_port=443\n'
	}
	run api_read
	[ "$status" -eq 0 ]
	grep -Fxq 'curl_rc=0' "$(probe_dir)/api.txt"
	grep -Fxq '/dev/null' "$(probe_dir)/api-arguments.txt"
	grep -Fxq 'https://api.github.com/repos/TurboCoder13/lgtm-ci-consumer-fixture' "$(probe_dir)/api-arguments.txt"
}

@test "API read preserves HTTP 403 failure distinct from transport failure" {
	export RUNNER_TEMP="$BATS_TEST_TMPDIR"
	mkdir -p "$(probe_dir)"
	curl() {
		printf 'http_code=403\nremote_ip=140.82.116.5\nremote_port=443\n'
		return 22
	}
	run api_read
	[ "$status" -eq 22 ]
	grep -Fxq 'http_code=403' "$(probe_dir)/api.txt"
	grep -Fxq 'curl_rc=22' "$(probe_dir)/api.txt"
}

@test "API read preserves connection refusal as curl 7" {
	export RUNNER_TEMP="$BATS_TEST_TMPDIR"
	mkdir -p "$(probe_dir)"
	curl() {
		printf 'http_code=000\nremote_ip=\nremote_port=0\n'
		return 7
	}
	run api_read
	[ "$status" -eq 7 ]
	grep -Fxq 'curl_rc=7' "$(probe_dir)/api.txt"
}

@test "API read rejects HTTP redirect even if curl reports success" {
	export RUNNER_TEMP="$BATS_TEST_TMPDIR"
	mkdir -p "$(probe_dir)"
	curl() { printf 'http_code=301\nremote_ip=140.82.116.5\nremote_port=443\n'; }
	run api_read
	[ "$status" -eq 1 ]
}
