# Firmware RE Labs

A collection of focused, reproducible investigation sessions covering embedded firmware reverse engineering and security testing.

Each session tackles a concrete technical problem, such as unpacking firmware images, reconstructing boot behavior, analyzing binaries, interpreting hardware captures, or identifying security weaknesses.

These are hands-on investigations, not a course or a series of guided tutorials. The emphasis is on examining artifacts, following the evidence, and documenting defensible technical findings.

## The format

Sessions are designed to take approximately 30 minutes, assuming familiarity with Linux and basic C programming.

Each session provides an objective, the necessary artifacts, minimal context, setup instructions, and investigation tasks. The analysis is left to the investigator, with solutions kept separate.

The expected outcome is a reproducible investigation, demonstrated through concrete technical findings and automatically checked submissions where supported.

## Labs

| Session | Focus | Duration |
| --- | --- | --- |
| [01: Firmware Image Triage](labs/01-firmware-image-triage/) | Firmware extraction, startup analysis, security triage | ~30 min |

See each session's README for submission and validation instructions.

## Repository layout

- `labs/` contains the sessions and their associated artifacts.
- [`docs/methodology.md`](docs/methodology.md) documents the structure, validation criteria, and scope of the sessions.
- [`docs/tools.md`](docs/tools.md) provides technical notes and references for tools used in the investigations.

Specialized hardware is only required when explicitly stated in a session's prerequisites.
