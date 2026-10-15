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

1. **Fork** this repository and enable **Actions** in your fork (one-time setup).
2. Copy `submission.example.json` to `submission.json` and fill in your findings.
3. Commit and push `submission.json` to your fork (the default branch is fine).
4. Open your fork's **Actions** tab → **Validate firmware submissions** to see per-field `PASS` / `FAIL` results.

No pull request or validation key is required. The validator accepts equivalent numeric representations and common formatting differences.

## Rules

- No automatic firmware extraction.
- Do not execute extracted binaries or scripts.
- Do not modify the original firmware image.
