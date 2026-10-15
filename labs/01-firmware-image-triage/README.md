# Session 01: Firmware Image Triage

**Duration:** ~30 min  
**Tools:** `file`, `xxd`, `binwalk`, `dd`, `tar`, `strings`, `rg`

## Objective

Analyze [`gateway-update.bin`](gateway-update.bin), a synthetic embedded Linux firmware image. Recover its filesystem, reconstruct its startup behavior, and identify security weaknesses.

## Tasks

1. **Inspect:** Identify the firmware header, payload type, and exact offset (hex and decimal). Explain why `file` does not recognize the embedded archive directly.
2. **Extract:** Manually carve the payload using `dd`, verify its format, and recover the filesystem.
3. **Trace:** Inspect configuration and init scripts. Reconstruct the command the startup script would execute.
4. **Audit:** Identify two distinct security weaknesses and record short identifiers for each.

## Submit & check

1. From this directory, run `cp submission.example.json submission.json` and fill in your findings.
2. Commit `submission.json` to a branch in your fork and open a pull request against this repository's `main` branch.
3. Open the PR's **Checks** tab and inspect **Validate firmware submissions** for per-field `PASS` / `FAIL` results.

Validation accepts equivalent numeric representations and common formatting differences. No validation key is needed to submit a PR.

## Rules

- No automatic firmware extraction.
- Do not execute extracted binaries or scripts.
- Do not modify the original firmware image.
