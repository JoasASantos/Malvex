---
name: defense-evasion
description: Use when Malvex needs to analyze sandbox, VM, or debugger detection, obfuscation, cleanup, or masquerading behavior.
---

# Skill: defense-evasion

Vector: defense-evasion | agent: deobfuscation | platforms: windows, linux, macos

## Objective

Map how the sample avoids security controls and analysis visibility.

## Checklist

- sandbox, VM, debugger, timing, environment and security-product checks
- process checks, anti-debugging, anti-disassembly, anti-VM
- API and string obfuscation
- living-off-the-land behavior
- log manipulation, cleanup, self-deletion, masquerading, signed-binary abuse

## Procedure

1. Identify the evasive predicates and the code they guard.
2. Determine whether they are cosmetic, gating, or destructive.
3. Note what artifact disappears or changes if evasion succeeds.

## Proof

Defense-evasion findings need the actual check or cleanup path, not just suspicious strings.
