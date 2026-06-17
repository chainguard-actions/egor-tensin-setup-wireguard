<!-- markdownlint-disable -->

# Hardening Report: egor-tensin--setup-wireguard/v1.1.0

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `1`

Action **egor-tensin--setup-wireguard/v1.1.0** was hardened automatically. 7 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): Six `${{ inputs.* }}` expressions are directly interpolated inside the `run:` shell script in action.yml. Although each value is wrapped in single quotes (e.g. `readonly endpoint='${{ inputs.endpoint }}'`), GitHub Actions performs expression substitution *before* the shell parses the script. An attacker-controlled input containing a single quote (`'`) can break out of the single-quoted string and inject arbitrary shell commands. All six input values are affected: `inputs.endpoint`, `inputs.endpoint_public_key`, `inputs.ips`, `inputs.allowed_ips`, `inputs.private_key`, and `inputs.preshared_key`. The fix is to pass these values via `env:` variables and reference them as `"$VAR"` in the shell script, never using `${{ }}` directly inside a `run:` block.

Locations:

- `action.yml:30`
- `action.yml:31`
- `action.yml:32`
- `action.yml:33`
- `action.yml:34`
- `action.yml:35`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.endpoint }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:30`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.endpoint_public_key }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:31`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.ips }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:32`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.allowed_ips }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:33`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.private_key }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:34`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.preshared_key }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:35`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection, static-inline-injection

**Notes:**

Moved all six ${{ inputs.* }} expressions (endpoint, endpoint_public_key, ips, allowed_ips, private_key, preshared_key) from the run: block to an env: block on the step in action.yml. The shell script now reads these values from environment variables ($INPUT_ENDPOINT, $INPUT_ENDPOINT_PUBLIC_KEY, $INPUT_IPS, $INPUT_ALLOWED_IPS, $INPUT_PRIVATE_KEY, $INPUT_PRESHARED_KEY) using double-quoted references, eliminating the shell injection risk from attacker-controlled inputs containing single quotes or other shell metacharacters.

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Fixed the unquoted shell variable expansion in the `for` loop at line 130 of action.yml. Replaced `for i in ${allowed_ips//,/ }; do sudo ip route replace "$i" dev "$ifname"; done` with a safe `while IFS= read -d "$delim" -r route_ip` loop using process substitution (`< <( printf -- "%s$delim\0" "$allowed_ips" )`). This matches the safe iteration pattern already used in the same script for the `$ips` variable, and prevents word splitting and glob expansion on the workflow-controllable `allowed_ips` input.

