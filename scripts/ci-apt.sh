#!/bin/sh
# CI only: install packages with apt-get, giving up on a hung mirror
# after a few minutes and trying again, instead of waiting until the job
# times out (a hung auditd install once held linux-live for 30 minutes).
#   scripts/ci-apt.sh PACKAGE...
set -u
opts="-o Acquire::Retries=3 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 -o DPkg::Lock::Timeout=60"
try() {
	n=1
	while :; do
		sudo timeout 300 "$@" && return 0
		[ "$n" -ge 3 ] && { echo "ci-apt: $* failed $n times" >&2; return 1; }
		echo "ci-apt: $* failed or timed out (attempt $n); retrying" >&2
		n=$((n + 1))
		sleep 10
	done
}
if [ ! -e /tmp/ci-apt-updated ]; then
	try apt-get $opts update -qq || exit 1
	touch /tmp/ci-apt-updated
fi
try env DEBIAN_FRONTEND=noninteractive apt-get $opts install -y -qq "$@"
