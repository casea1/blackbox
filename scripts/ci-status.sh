#!/bin/sh
# ci-status.sh runs blackbox status in CI (usage: ci-status.sh BLACKBOX [ARGS]).
# Exit 4 (needs attention) is accepted in one case only: every line status
# flags (its upper-case labels) is a gap in the audit log's serials. A CI
# runner loses audit records while auditd is installed, restarted or under
# load (apt installing packages), sometimes without the kernel counting
# them; Blackbox reporting the gap is correct, not a failure. Anything
# else status flags fails the step.
out=$(sudo "$@" 2>&1)
rc=$?
printf '%s\n' "$out"
[ "$rc" -eq 4 ] || exit "$rc"
flagged=$(printf '%s\n' "$out" | grep -E '^  [A-Z][A-Z ]*[A-Z]:' || true)
other=$(printf '%s\n' "$flagged" | grep -v '^  LOGS INCOMPLETE:  audit serials ' | grep . || true)
lost=$(sudo auditctl -s 2>/dev/null | awk '$1 == "lost" { print $2 }')
if [ -n "$flagged" ] && [ -z "$other" ]; then
	echo "::notice title=audit gap on the runner::status reported a gap in the runner's audit log, as it should (kernel lost count: ${lost:-unknown})"
	exit 0
fi
echo "::error title=blackbox status::exit $rc; flagged: $(printf '%s' "$other" | tr '\n' ' ')"
exit "$rc"
