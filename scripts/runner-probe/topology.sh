#!/usr/bin/env bash
# Read-only screening/topology. Never alter DNS, firewall, or services.
set -euo pipefail
stage="${1:?stage required}"
case "$stage" in before | snapshot | finish) ;; *) exit 2 ;; esac
out="${RUNNER_TEMP:?}/ci1203"
mkdir -p "$out"
if [[ "$stage" == before ]]; then
	# Compute location only: never query IMDS identity or tokens.
	region="$(curl --noproxy '*' --connect-timeout 1 --max-time 3 --retry 0 \
		--fail --silent -H Metadata:true \
		'http://169.254.169.254/metadata/instance/compute/location?api-version=2021-02-01&format=text')" || region=unknown
	if [[ ! "$region" =~ ^[a-z][a-z0-9]+$ ]]; then region=unknown; fi
	printf '%s\n' "$region" >"$out/region.txt"
	readlink -f /etc/resolv.conf >"$out/resolver-target.txt" || printf 'unknown\n' >"$out/resolver-target.txt"
	for component in resolver proxy; do
		unit="egress-dns-resolver"
		if [[ "$component" == proxy ]]; then unit=egress-outbound-proxy; fi
		unit_state="$(timeout 3 systemctl show "$unit" --value -p ActiveState)" || unit_state=unknown
		printf '%s\n' "${unit_state:-unknown}" >"$out/$component-unit.txt"
	done
	if sockets="$(sudo -n timeout 3 ss -lnut)"; then
		if [[ "$sockets" == *127.0.0.100:53* ]]; then listener=present; else listener=absent; fi
	else listener=unknown; fi
	printf '%s\n' "$listener" >"$out/listener.txt"
fi
{
	date -u -Is
	printf 'stage=%s\n' "$stage"
	for command in status dns domain default-route dnsovertls dnssec; do
		printf '\nRESOLVECTL %s\n' "$command"
		sudo -n timeout 5 resolvectl "$command" || true
	done
	printf '\nEFFECTIVE RESOLVED CONFIG (DNS fields only)\n'
	timeout 5 systemd-analyze cat-config systemd/resolved.conf 2>/dev/null |
		grep -E '^# /|^[[:space:]]*(DNS|FallbackDNS|Domains|DNSStubListener|DNSOverTLS|DNSSEC)=' || true
	for file in /etc/systemd/network/* /run/systemd/network/*; do
		if [[ -f "$file" ]]; then
			printf '\nNETWORK FILE %s\n' "$file"
			sudo -n timeout 3 grep -E '^[[:space:]]*(DNS|Domains|DNSDefaultRoute|UseDNS|UseDomains)=' "$file" || true
		fi
	done
	for unit in systemd-resolved egress-dns-resolver egress-outbound-proxy hosted-compute-agent agent; do
		printf '\nUNIT %s\n' "$unit"
		timeout 3 systemctl show "$unit" -p ActiveState -p LoadState -p ExecMainPID -p FragmentPath -p DropInPaths || true
	done
	# Config contents under /opt/hca are deliberately never read.
	printf '\nRESOLVER FILE\n'
	readlink -f /etc/resolv.conf || true
	stat -Lc '%d:%i %n' /etc/resolv.conf || true
	cat /etc/resolv.conf || true
} >"$out/topology-$stage.txt" 2>&1
cat "$out/topology-$stage.txt"
