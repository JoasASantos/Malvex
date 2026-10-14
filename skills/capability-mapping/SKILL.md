---
name: capability-mapping
description: Use when Malvex needs to convert validated functions and artifacts into capabilities and MITRE ATT&CK mappings.
---

# Skill: capability-mapping

Vector: capability-mapping | agent: decompilation | platforms: windows, linux, macos

## Objective

Convert low-level functions into behavioral capabilities and align them to ATT&CK where justified.

## Checklist

- execution
- persistence
- discovery
- credential access
- collection
- defense evasion
- command and control
- exfiltration
- impact

## Procedure

1. Group renamed functions into capability clusters.
2. Map only evidence-backed behavior to ATT&CK.
3. Keep a clear separation between observed capability and inferred operator intent.

## Proof

Capability mappings need supporting functions, xrefs, APIs, artifacts, and a confidence note.
