---
name: data-structure-recovery
description: Use when Malvex needs to recover internal data structures, vtables, class hierarchies and configuration formats used by malware.
---

# Skill: data-structure-recovery

Vector: `data-structure-recovery` | agent: decompilation | platforms: windows, linux, macos
ATT&CK: T1027 (Obfuscated Files)

## Objective

Recover internal data structures, vtables, class hierarchies, linked lists, configuration
record formats, and protocol message structures used by the malware.

## Checklist

- Structure field access patterns from decompiled code
- Vtable layouts and virtual function dispatch
- Allocation size from malloc/HeapAlloc calls
- Serialization/deserialization routines
- Network protocol message structures

## Procedure

1. **Allocation analysis**: trace malloc/HeapAlloc/new calls, extract sizes, correlate with
   subsequent field access patterns to reconstruct structure layouts.
2. **Field access patterns**: from decompiled code, identify base+offset access patterns.
   Group accesses by base pointer to reconstruct field layouts with types.
3. **Vtable recovery**: identify contiguous function pointer arrays in data sections,
   trace virtual calls through vtable+offset patterns.
4. **Protocol structures**: for C2 communication, identify serialization/deserialization
   routines that pack/unpack structured data — these reveal message formats.
5. **Config structures**: identify configuration record layouts used for bot settings,
   C2 addresses, encryption keys, campaign IDs.
6. Apply recovered types to decompiler output for improved pseudocode readability.

## Proof

Recovered structure with field layout confirmed by multiple access sites, allocation size
matching field count, and improved decompiler output using the applied type.

## Evidence out

- locus: structure definition, vtable address, allocation sites
- detail: field layout (offset, size, type, name), usage context
- confidence: high when multiple access sites converge; medium on single-site inference
- follow-up: `config-extraction` for config structures, `c2-protocol-analysis` for protocol types

## Guardrail

LLM output is a lead, not proof. Every field offset must trace to a real access pattern.
