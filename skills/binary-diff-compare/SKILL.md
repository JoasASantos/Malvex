---
name: binary-diff-compare
description: Use when Malvex needs to compare malware variants, patches or versions at the binary level to identify behavioral differences and evolution.
---

# Skill: binary-diff-compare

Vector: `binary-diff-compare` | agent: static-core | platforms: windows, linux, macos
ATT&CK: T1027.005 (Indicator Removal from Tools)

## Objective

Compare malware variants, versions or related samples at the binary level to identify
behavioral differences, code evolution, added/removed capabilities, and shared lineage.

## Checklist

- Function-level diffing (matched/added/removed/modified functions)
- Basic block and instruction-level changes
- String and constant differences
- Import/export table changes
- Section layout and entropy differences

## Procedure

1. **Function matching**: use BinDiff, Diaphora, or radare2 diffing to match functions
   between two samples. Identify matched (identical), modified, added, and removed functions.
2. **Change analysis**: for modified functions, identify specific instruction changes —
   new API calls, changed constants, altered control flow.
3. **String comparison**: diff extracted string sets to identify new C2 servers, changed
   campaign IDs, updated encryption keys, or removed debug strings.
4. **Import evolution**: compare import tables to identify new capabilities added or
   removed between variants.
5. **Metadata comparison**: compare compile timestamps, PDB paths, resource versions,
   Rich header toolchain IDs.
6. Emit variant comparison report: similarity score, key differences, capability delta.

## Proof

Function-level match report with specific instruction-level changes documented for
modified functions, correlated with behavioral impact assessment.

## Evidence out

- locus: changed function addresses in both samples
- detail: similarity score, specific changes, capability impact
- confidence: high for exact function matches; medium for heuristic matching
- follow-up: `malware-lineage` for family tree analysis

## Guardrail

LLM output is a lead, not proof. Binary diffing requires tool output, not visual comparison.
