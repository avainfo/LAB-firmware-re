# Methodology

Each session focuses on a specific aspect of firmware reverse engineering or embedded security, from firmware extraction and binary analysis to boot process investigation, hardware interfaces, and vulnerability identification.

The format is deliberately investigation-driven rather than instructional. Each session defines a bounded technical problem and leaves room to inspect the evidence, test hypotheses, and reach independently verifiable conclusions.

## Session structure

Each session includes:

- A clearly defined technical objective and expected deliverables.
- Only the context needed to begin the investigation.
- The required artifacts, tools, and setup instructions.
- Practical investigation tasks and specific questions to answer.
- Findings to report, including supporting commands, observations, and relevant limitations.

Solutions are kept in separate files. They document the investigative steps, distinguish observed facts from interpretations, and explain how the conclusions can be verified.

## Validation

Before publishing a session, I verify that:

- All required artifacts are provided or can be generated from the repository.
- Setup instructions work in a clean environment with the stated dependencies.
- The exercise does not reveal its solution in advance.
- The intended behavior is reproducible.
- The solution explains how the findings can be independently verified.
- Any requirements involving root access, specific architectures, or additional hardware are explicitly documented.

## Scope and safety

Sessions are generally designed to take around 30 minutes, but the priority is a complete and meaningful investigation rather than a strict time limit.

Investigations use synthetic artifacts, deliberately vulnerable samples, or hardware that can be tested with proper authorization. Testing systems or devices without permission is outside the scope of this repository.
