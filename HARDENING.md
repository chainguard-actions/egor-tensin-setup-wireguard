<!-- markdownlint-disable -->

# Hardening Report: egor-tensin--setup-wireguard/v1.2.2

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **egor-tensin--setup-wireguard/v1.2.2** was hardened automatically. 1 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Rule (b) violation: The shell variable `$allowed_ips` holds the value of `inputs.allowed_ips` (set via `ARG_ALLOWED_IPS: ${{ inputs.allowed_ips }}` in the env block and then assigned with `allowed_ips="$ARG_ALLOWED_IPS"`). It is expanded **unquoted** in a `for` loop: `for i in ${allowed_ips//,/ }; do sudo ip route replace "$i" dev "$ifname"; done`. An attacker-controlled value containing shell metacharacters (`;`, `|`, `&`, glob characters, whitespace) will be parsed by the shell before word-splitting, enabling command injection. The fix is to quote the expansion: `for i in "${allowed_ips//,/ }"` or use a safer splitting approach.

Locations:

- `action.yml:138`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection

**Notes:**

Fixed the script-injection vulnerability at action.yml line 138. Replaced the unsafe unquoted `for i in ${allowed_ips//,/ }` loop with a safe `while IFS= read -d "$delim" -r allowed_ip` loop using process substitution and a comma delimiter. This prevents shell metacharacters in the user-controlled `allowed_ips` input from being interpreted as shell commands. The fix uses the same safe splitting pattern already present in the script for the `ips` variable.

