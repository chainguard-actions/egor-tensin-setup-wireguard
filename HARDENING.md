<!-- markdownlint-disable -->

# Hardening Report: egor-tensin--setup-wireguard/v1.2.0

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `1`

Action **egor-tensin--setup-wireguard/v1.2.0** was hardened automatically. 8 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): All seven `inputs.*` values are interpolated directly via `${{ ... }}` expressions inside the `run:` shell script. Although each expression is wrapped in single quotes in the shell source (e.g. `readonly endpoint='${{ inputs.endpoint }}'`), GitHub Actions performs YAML template substitution *before* the shell parses the script. An attacker-controlled input value containing a single quote (e.g. `x' ; id ; echo '`) can break out of the quoting context and execute arbitrary shell commands on the runner. Affected lines: `readonly endpoint='${{ inputs.endpoint }}'` (line 32), `readonly endpoint_public_key='${{ inputs.endpoint_public_key }}'` (line 33), `readonly ips='${{ inputs.ips }}'` (line 34), `readonly allowed_ips='${{ inputs.allowed_ips }}'` (line 35), `readonly private_key='${{ inputs.private_key }}'` (line 36), `readonly preshared_key='${{ inputs.preshared_key }}'` (line 37), `readonly keepalive='${{ inputs.keepalive }}'` (line 38). Fix: pass all inputs via `env:` variables and reference them as `"$VAR"` in the shell script, never interpolating `${{ ... }}` directly inside a `run:` block.

Locations:

- `action.yml:32`
- `action.yml:33`
- `action.yml:34`
- `action.yml:35`
- `action.yml:36`
- `action.yml:37`
- `action.yml:38`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.endpoint }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:33`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.endpoint_public_key }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:34`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.ips }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:35`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.allowed_ips }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:36`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.private_key }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:37`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.preshared_key }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:38`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.keepalive }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:39`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection, static-inline-injection

**Notes:**

Fixed all 8 findings (1 script-injection + 7 static-inline-injection) in action.yml. Moved all seven ${{ inputs.* }} expressions (endpoint, endpoint_public_key, ips, allowed_ips, private_key, preshared_key, keepalive) from the run: shell script into an env: block on the step. Updated the shell script to reference these values as double-quoted environment variables ($INPUT_ENDPOINT, $INPUT_ENDPOINT_PUBLIC_KEY, $INPUT_IPS, $INPUT_ALLOWED_IPS, $INPUT_PRIVATE_KEY, $INPUT_PRESHARED_KEY, $INPUT_KEEPALIVE) instead of using single-quoted ${{ ... }} template expressions. This prevents attacker-controlled input values from breaking out of the shell quoting context.

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Fixed the script injection vulnerability at action.yml line 148. The unquoted `${allowed_ips//,/ }` expansion in the `for` loop was replaced with a safe array-based approach: `IFS=',' read -ra _allowed_ips_arr <<< "$allowed_ips"` followed by `for i in "${_allowed_ips_arr[@]}"; do ...`. This prevents shell word-splitting and glob expansion on the attacker-controlled `allowed_ips` input value, while preserving the correct behavior of iterating over each comma-separated IP/netmask.

