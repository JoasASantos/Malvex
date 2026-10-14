---
name: debugging
description: Use when Malvex needs debugger-backed runtime evidence such as breakpoints, arguments, registers, threads, heap state, or decrypted configuration.
---

# Skill: debugging

Vector: debugging | agent: dynamic-analysis | platforms: windows, linux, macos

## Objective

Define or execute the debugger strategy needed to expose behavior blocked by static analysis.

## Checklist

- breakpoints at entrypoint and key routines
- registers, stack, heap, mappings, threads, exceptions
- child processes
- decrypted strings and runtime-resolved APIs
- unpacking and decrypted config
- flow across modules

## Procedure

1. Break on the entrypoint or post-unpack pivot.
2. Place secondary breakpoints on API resolution, string decode, persistence, C2, and credential routines.
3. Capture arguments and decoded outputs.
4. Persist debugger artifacts to the session.

## Guardrail

If the current host cannot debug the target natively, emit the exact host-specific debugging recipe.
