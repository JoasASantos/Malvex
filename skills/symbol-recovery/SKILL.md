---
name: symbol-recovery
description: Use when Malvex needs to recover meaningful function and variable names from stripped malware binaries through behavioral analysis and pattern matching.
---

# Skill: symbol-recovery

Vector: `symbol-recovery` | agent: decompilation | platforms: windows, linux, macos
ATT&CK: T1027.002 (Software Packing)

## Objective

Recover meaningful function and variable names from stripped binaries through behavioral
analysis, API usage patterns, string references, error messages, and library identification.

## Checklist

- RTTI / typeinfo structures (C++ binaries)
- Debug strings, error messages, log format strings
- PDB path remnants
- Go/Rust symbol tables (often partially retained)
- API call patterns suggesting function purpose
- Exception handler registration naming

## Procedure

1. **Residual symbols**: scan for RTTI structures, Go pclntab, Rust panic strings, Objective-C
   class/method lists, Swift reflection metadata.
2. **Debug artifacts**: extract PDB paths, assert messages, log format strings that leak
   function/module names.
3. **Behavioral naming**: for stripped functions, infer purpose from API calls, string refs,
   parameter patterns. Name functions by their primary capability (e.g., `decrypt_config`,
   `send_beacon`, `inject_process`).
4. **Library function identification**: apply FLIRT/pattern matching to identify standard
   library functions (CRT, STL, libc) and remove them from the analysis surface.
5. **Cross-reference naming**: propagate names through call chains — a function called only
   by `send_beacon` that formats HTTP headers becomes `format_c2_request`.
6. Apply recovered names to improve decompiler output readability.

## Proof

Each renamed function justified by converging evidence (API calls + string refs + call
context), not by LLM guessing. Names must be supported by observable behavior.

## Evidence out

- locus: function address, original auto-name, new name
- detail: evidence supporting the name (APIs called, strings referenced, caller context)
- confidence: high when multiple evidence types converge
- follow-up: `disassembly-decompilation` for deeper function analysis

## Guardrail

LLM output is a lead, not proof. Rename only when behavior evidence supports the name.
