---
name: anti-analysis
description: Use when Malvex must focus on anti-debug, anti-VM, timing, exception, or self-modifying protections that block inspection.
---

# Skill: anti-analysis

Vector: anti-analysis | agent: deobfuscation | platforms: windows, linux, macos

## Objective

Document analysis-specific friction mechanisms.

## Checklist

- IsDebuggerPresent-style checks, PEB checks
- timing differences
- hardware, CPU, RAM, disk-size checks
- VM and sandbox artifacts
- analysis-tool detection
- debug registers, exception tricks
- control-flow obfuscation and self-modifying code

## Procedure

1. Enumerate the checks.
2. Identify what code they hide or alter.
3. Suggest the minimum bypass needed for deeper analysis.

## Proof

Anti-analysis claims require the exact predicate or mutation path.
