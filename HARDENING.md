<!-- markdownlint-disable -->

# Hardening Report: egor-tensin--setup-wireguard/v1.2.1

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **egor-tensin--setup-wireguard/v1.2.1** was hardened automatically. 8 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): All seven `inputs.*` values are interpolated directly via `${{ ... }}` expressions inside the `run:` shell script. GitHub Actions performs this template substitution before the shell ever parses the script, so single-quote wrapping (e.g., `readonly endpoint='${{ inputs.endpoint }}'`) does NOT prevent injection. An attacker-controlled input containing a single quote — for example `foo' ; malicious_command ; echo '` — breaks out of the shell quoting and achieves arbitrary command execution on the runner. All inputs are affected: `inputs.endpoint`, `inputs.endpoint_public_key`, `inputs.ips`, `inputs.allowed_ips`, `inputs.private_key`, `inputs.preshared_key`, and `inputs.keepalive`. The fix is to pass each input through an `env:` block and reference it as a quoted shell variable (e.g., `"$ENDPOINT"`) inside the `run:` script, never using `${{ ... }}` directly in a shell command string.

Locations:

- `action.yml:31`
- `action.yml:32`
- `action.yml:33`
- `action.yml:34`
- `action.yml:35`
- `action.yml:36`
- `action.yml:37`

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

Moved all seven ${{ inputs.* }} expressions (endpoint, endpoint_public_key, ips, allowed_ips, private_key, preshared_key, keepalive) from direct interpolation inside the run: shell script to an env: block on the step. The shell script now references them as properly double-quoted environment variables ($INPUT_ENDPOINT, $INPUT_ENDPOINT_PUBLIC_KEY, etc.), preventing shell injection attacks where attacker-controlled input values containing single quotes or other shell metacharacters could break out of the original single-quote wrapping and execute arbitrary commands.

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Fixed the unquoted shell variable expansion in the `via_wg_tools()` function at line 148 of action.yml. Replaced `for i in ${allowed_ips//,/ }` (unquoted, subject to glob expansion and word-splitting) with a safe array-based approach: `IFS=, read -ra ips_arr <<< "$allowed_ips"` followed by `for i in "${ips_arr[@]}"`. This splits on commas safely into an array and iterates with proper quoting, preventing attacker-controlled input from injecting shell metacharacters.

