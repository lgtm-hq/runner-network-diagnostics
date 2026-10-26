#!/usr/bin/env bash
# Fixture-owned diagnostics for lgtm-hq/lgtm-ci#1203; never change network policy.
set -euo pipefail

probe_dir() {
	printf '%s/ci1203' "${RUNNER_TEMP:?RUNNER_TEMP is required}"
}

agent_events() {
	sudo -n cat /home/agent/agent.log 2>/dev/null |
		grep -E 'domain resolved:|ip address dropped:|endpoint called ip address:port|domain not allowed:|Initialized|Reverted changes|Error resolving' || true
}

snapshot() {
	local stage="$1" out
	out="$(probe_dir)/${stage}.txt"
	{
		date -u -Is
		printf 'stage=%s sha=%s run=%s attempt=%s arch=%s image=%s version=%s\n' \
			"$stage" "$GITHUB_SHA" "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT" \
			"$RUNNER_ARCH" "${ImageOS:-unknown}" "${ImageVersion:-unknown}"
		printf 'region=unknown (external Set up job receipt required)\n'
		sha256sum "${BASH_SOURCE[0]}"
		uname -a
		readlink -f /etc/resolv.conf
		stat -Lc '%d:%i %n' /etc/resolv.conf
		cat /etc/resolv.conf
		timeout 10 resolvectl status || true
		timeout 10 resolvectl statistics || true
		findmnt -T /etc/resolv.conf -o TARGET,SOURCE,FSTYPE || true
		grep -E '^hosts:' /etc/nsswitch.conf || true
		grep -E '(^|[[:space:]])(api\.)?github\.com([[:space:]]|$)' /etc/hosts || true
		local file
		for file in /etc/systemd/resolved.conf /etc/systemd/resolved.conf.d/*.conf \
			/run/systemd/resolve/resolv.conf /run/systemd/resolve/stub-resolv.conf; do
			if [[ -f "$file" ]]; then
				printf '\nFILE %s\n' "$file"
				grep -E '^([[:space:]]*(DNS|FallbackDNS|Domains|DNSStubListener|DNSOverTLS|DNSSEC)=|nameserver |search )' "$file" || true
			fi
		done
		sudo -n ss -lunpt || true
		ip route show
		local unit
		for unit in systemd-resolved egress-dns-resolver egress-outbound-proxy hosted-compute-agent agent; do
			printf 'UNIT %s\n' "$unit"
			systemctl show "$unit" -p LoadState -p ActiveState -p ExecMainPID || true
		done
		sudo -n sha256sum /home/agent/agent 2>/dev/null || true
		sudo -n iptables-save || true
		sudo -n ip6tables-save || true
		# Native nftables rules may not appear in the iptables compatibility view.
		printf 'NATIVE_NFTABLES_BEGIN\n'
		sudo -n timeout 10 nft list ruleset || true
		printf 'NATIVE_NFTABLES_END\n'
		if sudo -n grep -Fxq Initialized /home/agent/agent.status 2>/dev/null; then
			printf 'agent-status=Initialized\n'
		else
			printf 'agent-status=unavailable\n'
		fi
		agent_events
	} >"$out" 2>&1
	cat "$out"
}

prepare_negative_address() {
	local out address
	out="$(probe_dir)"
	# Resolve before the hardener substitutes its denied-domain sinkhole.
	address="$(timeout 10 getent ahostsv4 example.com | awk 'NR == 1 { print $1 }')" || true
	if [[ ! "$address" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] ||
		[[ "$address" == 54.185.253.63 ]]; then
		printf 'UNCONFIRMED: no usable pre-hardener control address\n' >&2
		return 1
	fi
	printf '%s\n' "$address" >"$out/negative-address.txt"
}

prepare() {
	local out helper
	out="$(probe_dir)"
	helper="$(dirname "${BASH_SOURCE[0]}")"
	mkdir -p "$out"
	# This is the FIRST action's runs.pre, ahead of the hardener's runs.pre.
	# Refuse a false baseline if pre-hook order or runner state differs.
	if systemctl is-active --quiet agent.service; then
		printf 'UNCONFIRMED: agent already running before baseline\n' >&2
		return 1
	fi
	snapshot before
	prepare_negative_address
	"${PROBE_NODE:-node}" "$helper/capture.cjs" start "$out"
	date -u -Is >"$out/prepared.marker"
	printf 'PRE_HARDENER_READY\n'
}

# A generic curl failure is NOT an enforcement pass. Require fresh evidence
# that the exact curl process and selected destination were locally rejected.
negative_verdict() {
	local result="$1" address="$2" pid="$3" active="$4" events="$5"
	if [[ "$address" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] &&
		[[ "$pid" =~ ^[0-9]+$ ]] && [[ "$active" == active ]] &&
		[[ "$result" == 7 || "$result" == 28 ]] &&
		grep -Fqx "ip address dropped: $address" <(sed -E 's/^.*GMT://' "$events") &&
		grep -F "endpoint called ip address:port $address:443, domain: " "$events" |
		grep -Eq "pid: $pid, process: curl(,|$)"; then
		printf 'CONFIRMED_BLOCK\n'
	else
		printf 'UNCONFIRMED\n'
		return 1
	fi
}

negative() {
	local out address before pid result=0 active verdict
	out="$(probe_dir)"
	# Use the pre-hardener address: denied-domain DNS returns a sinkhole whose
	# connection events are intentionally omitted by agent v0.17.0.
	# The control still runs after checkout/roundtrip and requires exact evidence.
	address="$(cat "$out/negative-address.txt")" || true
	if [[ ! "$address" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] ||
		[[ "$address" == 54.185.253.63 ]]; then
		printf 'UNCONFIRMED: missing usable pre-hardener control address\n' >"$out/negative.txt"
		cat "$out/negative.txt"
		return 1
	fi
	before="$(agent_events | wc -l)"
	curl --noproxy '*' --connect-timeout 5 --max-time 10 --retry 0 \
		--resolve "example.com:443:$address" --silent --show-error \
		--output /dev/null --write-out '%{json}\n' https://example.com/ \
		>"$out/negative-curl.txt" 2>"$out/negative-curl-stderr.txt" &
	pid="$!"
	wait "$pid" || result="$?"
	# Allow the agent's event writer to flush, without retrying the request.
	sleep 3
	agent_events | tail -n "+$((before + 1))" >"$out/negative-agent.txt"
	active="$(systemctl is-active agent.service)" || true
	verdict="$(negative_verdict "$result" "$address" "$pid" "$active" "$out/negative-agent.txt")" || true
	printf 'verdict=%s curl_rc=%s address=%s pid=%s agent=%s\n' \
		"$verdict" "$result" "$address" "$pid" "$active" | tee "$out/negative.txt"
	[[ "$verdict" == CONFIRMED_BLOCK ]]
}

# Public read only, no token, no body retained, no retry. HTTP errors remain
# distinct from connection failures in the curl receipt and process exit code.
api_read() {
	local out result=0
	out="$(probe_dir)"
	curl --noproxy '*' --connect-timeout 5 --max-time 10 --retry 0 \
		--fail --silent --show-error --output /dev/null \
		--write-out 'http_code=%{http_code}\nremote_ip=%{remote_ip}\nremote_port=%{remote_port}\n' \
		https://api.github.com/repos/TurboCoder13/lgtm-ci-consumer-fixture \
		>"$out/api.txt" 2>"$out/api-stderr.txt" || result="$?"
	printf 'curl_rc=%s\n' "$result" >>"$out/api.txt"
	cat "$out/api.txt"
	if [[ "$result" != 0 ]]; then
		return "$result"
	fi
	grep -Fxq http_code=200 "$out/api.txt"
}

payload() {
	printf '%s %s %s\n' "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT" "$RUNNER_ARCH" >"$(probe_dir)/payload.txt"
}

roundtrip() {
	cmp "$(probe_dir)/payload.txt" "$RUNNER_TEMP/ci1203-roundtrip/payload.txt"
	printf 'ROUNDTRIP_OK\n' | tee "$(probe_dir)/roundtrip.txt"
}

finish() {
	local out host resolver
	out="$(probe_dir)"
	# Freeze before active comparisons so they cannot contaminate the capture.
	"${PROBE_NODE:-node}" "$(dirname "${BASH_SOURCE[0]}")/capture.cjs" freeze "$out" || true
	snapshot final
	# Label these as active measurements: they can alter cache state.
	{
		printf 'ACTIVE_DNS_COMPARISONS_BEGIN\n'
		for host in github.com api.github.com; do
			timeout 10 getent ahostsv4 "$host" || true
			timeout 10 resolvectl query "$host" || true
			if command -v dig >/dev/null; then
				for resolver in 127.0.0.1 127.0.0.53 127.0.0.100; do
					dig +time=2 +tries=1 "@$resolver" "$host" A || true
				done
			fi
		done
		printf 'ACTIVE_DNS_COMPARISONS_END\n'
	} >"$out/active-dns.txt" 2>&1
	cat "$out/active-dns.txt"
	# Snapshots and console output survive failed artifact publication.
	[[ ! -f "$out/dns-wire.txt" ]] || cat "$out/dns-wire.txt"
	"${PROBE_NODE:-node}" "$(dirname "${BASH_SOURCE[0]}")/capture.cjs" verify "$out" || true
	(cd "$out" && sha256sum ./*.txt >SHA256SUMS)
	cat "$out/SHA256SUMS"
	printf 'TERMINAL_STEP_REACHED (external API confirmation still required)\n'
	grep -Fxq COMPLETE_DNS_EVIDENCE "$out/completeness.txt"
}

main() {
	case "${PROBE_MODE:-}" in
	prepare) prepare ;;
	confirm) test -s "$(probe_dir)/prepared.marker" ;;
	snapshot) snapshot hardened ;;
	payload) payload ;;
	roundtrip) roundtrip ;;
	api) api_read ;;
	negative) negative ;;
	finish) finish ;;
	*)
		printf 'Unknown PROBE_MODE\n' >&2
		return 2
		;;
	esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
	main "$@"
fi
