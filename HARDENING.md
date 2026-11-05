<!-- markdownlint-disable -->

# Hardening Report: egor-tensin--setup-wireguard/v1.2.3

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **egor-tensin--setup-wireguard/v1.2.3** was hardened automatically. 1 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (b), unquoted shell expansion of untrusted data. The offending line is `for i in ${allowed_ips//,/ }; do sudo ip route replace "$i" dev "$ifname"; done`. `allowed_ips` comes from inputs.allowed_ips (via ARG_ALLOWED_IPS) and is expanded without double quotes. That leaves the value open to word splitting and glob expansion, so wildcard characters or extra whitespace in the input can change the arguments passed to `ip route`. The fix is to split it safely, for example `IFS=, read -r -a routes <<< "$allowed_ips"; for i in "${routes[@]}"; do ...; done`.

Locations:

- `action.yml:175`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection

**Notes:**

Replaced the unquoted `for i in ${allowed_ips//,/ }` loop in action.yml. allowed_ips now goes into an array (commas are swapped for spaces, then `read -r -d '' -a ... || true`), which is guarded against empty input. The loop expands that array quoted, in a nounset-safe form. Upstream split on commas and whitespace, and the new code does too, but without glob expansion.

