#!/bin/sh
# ci-status.sh runs blackbox status in CI (usage: ci-status.sh BLACKBOX [ARGS]).
# Exit 4 (needs attention) is accepted in one case only: the kernel itself
# counted lost audit records (auditctl -s "lost"), the only problem is the
# gap that left in the audit serials, and status said so. A runner under
# load (apt installing packages) can overflow the audit backlog; Blackbox
# reporting that loss is correct, not a failure. Anything else fails.
out=$(sudo "$@" 2>&1)
rc=$?
printf '%s\n' "$out"
[ "$rc" -eq 4 ] || exit "$rc"
lost=$(sudo auditctl -s | awk '$1 == "lost" { print $2 }')
attention=$(printf '%s\n' "$out" | sed -n 's/.*needs attention: //p' | sed 's/; /\n/g' | sort -u)
if [ "${lost:-0}" -gt 0 ] && [ "$attention" = "the saved original logs are incomplete" ] &&
	printf '%s\n' "$out" | grep -q "LOGS INCOMPLETE:  audit serials"; then
	echo "::notice title=audit records lost on the runner::the kernel lost $lost audit records; status reported the gap, as it should"
	exit 0
fi
echo "::error title=blackbox status::exit $rc (kernel lost count: ${lost:-unknown}; needs attention: $attention)"
exit "$rc"
