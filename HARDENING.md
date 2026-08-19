<!-- markdownlint-disable -->

# Hardening Report: egor-tensin--setup-wireguard/v1.1.0

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **egor-tensin--setup-wireguard/v1.1.0** was hardened automatically. 9 finding(s) were identified and resolved across 3 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): The `run:` block in action.yml directly interpolates `${{ inputs.* }}` expressions inside single-quoted shell strings (e.g., `readonly endpoint='${{ inputs.endpoint }}'`). GitHub Actions performs `${{ }}` template substitution at the YAML level before the shell ever executes the script. An attacker can break out of the single-quoted string by supplying a value containing a single quote `'`, enabling arbitrary shell command injection. All six input values are interpolated this way: `inputs.endpoint`, `inputs.endpoint_public_key`, `inputs.ips`, `inputs.allowed_ips`, `inputs.private_key`, and `inputs.preshared_key`. The fix is to pass inputs via `env:` variables and reference them as `"$VAR"` in the shell script, never interpolating `${{ }}` directly inside a `run:` block.

Locations:

- `action.yml:26`

### unpinned-uses (severity: high)

The workflow file `.github/workflows/test.yml` references `actions/checkout@v2`, which uses a mutable version tag rather than a pinned 40-character commit SHA. A supply-chain attacker could move the `v2` tag to a malicious commit. It should be pinned to a full SHA, e.g. `actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4`.

Locations:

- `.github/workflows/test.yml:20`

### missing-permissions (severity: medium)

The workflow file `.github/workflows/test.yml` has no top-level `permissions:` key and the `test` job also has no `permissions:` key. Without explicit permissions, the workflow inherits the repository's default token permissions (which may be `write-all` on older repositories). A minimal `permissions:` block (e.g., `permissions: {}` or only the scopes actually needed) should be added at the top level or on every job.

Locations:

- `.github/workflows/test.yml:1`

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

**Fixes applied:** script-injection, static-inline-injection, unpinned-uses, missing-permissions

**Notes:**

1. action.yml: Moved all six ${{ inputs.* }} template expressions (endpoint, endpoint_public_key, ips, allowed_ips, private_key, preshared_key) from inline single-quoted shell strings into an env: map on the step. The shell script now reads them as plain environment variables ("$INPUT_ENDPOINT", etc.), eliminating the shell injection risk.
2. .github/workflows/test.yml: Pinned actions/checkout@v2 to its full commit SHA (0717577d45739eb3c851188b29f50ed6c0b2194e) with a # v2 comment.
3. .github/workflows/test.yml: Added top-level `permissions: {}` to restrict the GITHUB_TOKEN to no permissions by default.

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Fixed the script-injection finding in .github/workflows/test.yml at the 'Check endpoint' step. Moved `${{ secrets.ENDPOINT_PRIVATE_IP }}` from the `run:` shell string into an `env:` block as `ENDPOINT_PRIVATE_IP`, and updated the shell command to reference it as the quoted variable `"$ENDPOINT_PRIVATE_IP"`. This prevents the value from flowing through YAML template substitution before the shell sees it.

### Iteration 3

**Fixes applied:** script-injection

**Notes:**

Fixed the script injection vulnerability at line 131 of action.yml. The unquoted `for i in ${allowed_ips//,/ }` construct was replaced with a safe `while IFS= read -d "$delim_r" -r route_ip` loop using `printf -- "%s$delim_r\0" "$allowed_ips"` as input. This matches the same safe pattern already used elsewhere in the script for processing comma-separated IP lists, and ensures all variable expansions are properly quoted, preventing shell metacharacter injection from attacker-controlled `allowed_ips` input.

