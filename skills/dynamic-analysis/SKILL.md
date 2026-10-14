---
name: dynamic-analysis
description: Use when Malvex needs runtime observation of process, filesystem, registry or service, IPC, memory, or host-discovery behavior.
---

# Skill: dynamic-analysis

Vector: dynamic-analysis | agent: dynamic-analysis | platforms: windows, linux, macos

## Objective

Observe what the sample does when it runs.

## Checklist

- process creation and tree
- file, registry, service, task, named-pipe, mutex activity
- DLL/shared library loading
- memory allocations and permission changes
- IPC, environment, user, host, and network discovery

## Procedure

1. Launch in a controlled environment.
2. Capture process, file-system, service, task, IPC, and persistence events.
3. Correlate behavior with the static functions believed to drive it.
4. Distinguish attempted from successful behavior.

## Proof

Dynamic findings should reference the observed event source, timestamp, process, and proving artifact.
