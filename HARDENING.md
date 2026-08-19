<!-- markdownlint-disable -->

# Hardening Report: egor-tensin--setup-wireguard/v1.2.0

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **egor-tensin--setup-wireguard/v1.2.0** was hardened automatically. 11 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): The action.yml run: block directly interpolates ${{ inputs.* }} expressions inside shell command strings. The template substitution occurs before the shell parses the script, so a single-quote character in any input value (e.g., inputs.endpoint, inputs.private_key, etc.) breaks out of the surrounding single-quote context and allows arbitrary shell command injection. Offending lines include:
  readonly endpoint='${{ inputs.endpoint }}'
  readonly endpoint_public_key='${{ inputs.endpoint_public_key }}'
  readonly ips='${{ inputs.ips }}'
  readonly allowed_ips='${{ inputs.allowed_ips }}'
  readonly private_key='${{ inputs.private_key }}'
  readonly preshared_key='${{ inputs.preshared_key }}'
  readonly keepalive='${{ inputs.keepalive }}'

Locations:

- `action.yml:27`
- `action.yml:28`
- `action.yml:29`
- `action.yml:30`
- `action.yml:31`
- `action.yml:32`
- `action.yml:33`

### script-injection (severity: high)

Sub-rule (a): The test workflow run: block directly interpolates ${{ secrets.ENDPOINT_PRIVATE_IP }} inside a shell command string: `run: ping -W 10 -c 5 -- '${{ secrets.ENDPOINT_PRIVATE_IP }}'`. Any expression interpolated directly into a run: block is a script-injection risk regardless of the context it reads from.

Locations:

- `.github/workflows/test.yml:35`

### unpinned-uses (severity: high)

The workflow uses actions/checkout@v2, which is a mutable tag reference rather than a pinned 40-character commit SHA. This is vulnerable to supply-chain attacks if the tag is moved or the upstream repository is compromised. It should be pinned to a full SHA, e.g. actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v2.

Locations:

- `.github/workflows/test.yml:21`

### missing-permissions (severity: medium)

The workflow file has no top-level `permissions:` key and the single job also has no `permissions:` key. Without explicit permissions, the workflow inherits the repository's default token permissions (which may be write-all), granting broader access than necessary.

Locations:

- `.github/workflows/test.yml:1`

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

**Fixes applied:** script-injection, static-inline-injection, unpinned-uses, missing-permissions

**Notes:**

Fixed all findings:
1. action.yml: Moved all 7 ${{ inputs.* }} expressions (endpoint, endpoint_public_key, ips, allowed_ips, private_key, preshared_key, keepalive) from the run: shell block into a step-level env: map. Shell script now references them as double-quoted environment variables (e.g., "$INPUT_ENDPOINT"), eliminating template injection.
2. test.yml: Moved ${{ secrets.ENDPOINT_PRIVATE_IP }} in the ping step to an env: block, referencing it as "$ENDPOINT_PRIVATE_IP" in the shell command.
3. test.yml: Pinned actions/checkout@v2 to full SHA ee0669bd1cc54295c223e0bb666b733df41de1c5 # v2.
4. test.yml: Added top-level permissions: {} to enforce least-privilege token access.

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Fixed the unquoted variable expansion in the `via_wg_tools()` function's for loop at line 143 of action.yml. Changed `for i in ${allowed_ips//,/ }` to `for i in "${allowed_ips//,/ }"`. The quoted form prevents glob expansion (e.g., `*`, `?`, `[...]`) of attacker-controlled values from the `allowed_ips` input, while still allowing the intended word-splitting on spaces to iterate over the comma-separated list of netmasks.

