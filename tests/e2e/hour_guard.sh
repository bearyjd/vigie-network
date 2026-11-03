# Sourced by run_e2e.sh. Promotion needs two distinct server-received UTC hours
# (processor.py PROMOTE_MIN_HOURS), so a collect stage that straddles an hour boundary promotes
# the rolling-MAC phones and the "hidden by default" assertion fails.

# hour_guard_wait_s EPOCH BUDGET_S -> seconds to sleep so [now, now+BUDGET_S] stays in one hour.
hour_guard_wait_s() {
	local remaining=$((3600 - $1 % 3600))
	if ((remaining >= $2)); then
		echo 0
	else
		echo $((remaining + 1))
	fi
}
