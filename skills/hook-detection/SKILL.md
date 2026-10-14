---
name: hook-detection
description: Use when Malvex needs to analyze hooking techniques used by malware including IAT hooks, inline hooks, SSDT hooks, VMT hooks and API monitoring bypass.
---

# Skill: hook-detection

Vector: `hook-detection` | agent: dynamic-analysis | platforms: windows, linux, macos
ATT&CK: T1056 (Input Capture), T1179 (Hooking), T1562.001 (Disable or Modify Tools)

## Objective

Analyze hooking techniques used by malware — IAT patching, inline detours, EAT hooks,
syscall hooks, VMT replacement — and EDR unhooking techniques used to bypass monitoring.

## Checklist

- IAT hook detection (modified import addresses)
- Inline hooks (JMP/CALL patches at function prologues)
- EAT hooks (modified export addresses)
- VMT/vtable hooks (replaced virtual function pointers)
- SSDT hooks (kernel-level syscall interception)
- EDR unhooking (ntdll remapping, direct syscalls)

## Procedure

1. **IAT integrity**: compare import table entries against on-disk DLL export addresses.
   Mismatches indicate IAT hooking for API interception.
2. **Inline hook scan**: check function prologues for JMP/CALL patches (E9/FF 25 patterns)
   that redirect execution. Compare against clean module copies.
3. **EAT modification**: check if export address table entries point outside the module's
   code section — indicates EAT hooking for DLL proxying.
4. **VMT analysis**: for C++ objects, verify vtable entries point to the correct module.
5. **Unhooking detection**: identify ntdll remapping (read clean copy from disk/KnownDlls),
   direct syscall stubs, or VirtualProtect + memcpy patterns restoring original bytes.
6. **Purpose classification**: categorize hooks by purpose — keylogging, API monitoring
   bypass, credential interception, man-in-the-browser.

## Proof

Hook location, original bytes, patched bytes, and hook destination with purpose classification.
For unhooking, the remapping source and restored functions documented.

## Evidence out

- locus: hooked function address, hook type, destination
- detail: original vs patched bytes, hook purpose, target module
- confidence: high — byte comparison is deterministic
- follow-up: `anti-analysis` for EDR evasion context, `credential-data-access` for keylogging

## Guardrail

LLM output is a lead, not proof. Hook detection requires byte-level comparison.
