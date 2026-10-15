# Session 01: Firmware Image Triage

**Duration:** ~30 min
**Tools:** `file`, `xxd`, `binwalk`, `dd`, `tar`, `strings`, `rg`

## Objective

Analyze [`gateway-update.bin`](gateway-update.bin), a synthetic embedded Linux firmware image. Recover its filesystem, reconstruct its startup behavior, and identify security weaknesses.

## Tasks

1. **Inspect:** Identify the firmware header, payload type, and exact offset (hex and decimal). Explain why `file` does not recognize the embedded archive directly.
2. **Extract:** Manually carve the payload using `dd`, verify its format, and recover the filesystem.
3. **Trace:** Inspect configuration and init scripts. Reconstruct the command the startup script would execute.
4. **Audit:** Identify two distinct security weaknesses. For each, provide evidence, realistic impact, and a remediation.

## Submission

Complete [`submission.example.json`](submission.example.json) and save it as `submission.json`.

Include the extracted payload's SHA-256 fingerprint and your findings.

## Rules

- No automatic firmware extraction.
- Do not execute extracted binaries or scripts.
- Do not modify the original firmware image.
