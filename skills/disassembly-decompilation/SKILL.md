---
name: disassembly-decompilation
description: Use when Malvex must reconstruct execution flow, identify critical functions, and rename behavior from disassembly or pseudocode.
---

# Skill: disassembly-decompilation

Vector: disassembly-decompilation | agent: decompilation | platforms: windows, linux, macos

## Objective

Recover execution flow and rename important functions by behavior.

## Checklist

- identify main function and execution path
- call graph, CFG, cross-references
- critical functions and arguments
- structures, globals, objects, classes, vtables
- important loops, comparisons, state machines, error handling
- indirect calls, dynamic API resolution, syscalls
- dead code and anti-disassembly patterns

## Procedure

1. Identify the real starting logic, not only the PE/ELF/Mach-O entrypoint stub.
2. Walk the call graph into credential, persistence, network, discovery, and anti-analysis behavior.
3. Rename functions when strings, APIs, xrefs, or algorithm structure justify the name.
4. Annotate unresolved functions with confidence notes instead of fake certainty.

## Proof

A rename such as `enumerate_browser_profiles` needs supporting APIs, strings, xrefs, data structures, or runtime corroboration.
