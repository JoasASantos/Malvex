---
name: process-injection
description: Use when Malvex needs to analyze process injection techniques including classic DLL injection, process hollowing, APC injection, syscall-based injection and modern evasion variants.
---

# Skill: process-injection

Vector: `process-injection` | agent: dynamic-analysis | platforms: windows, linux
ATT&CK: T1055 (Process Injection) and sub-techniques

## Objective

Identify and classify process injection techniques used by malware — from classic DLL
injection to modern syscall-based evasion techniques.

## Checklist

- Classic remote thread injection (VirtualAllocEx + WriteProcessMemory + CreateRemoteThread)
- Process hollowing (T1055.012) — create suspended, unmap, write, resume
- APC injection (T1055.004) — QueueUserAPC to suspended thread
- Early bird injection — APC before main thread initialization
- Reflective DLL injection — manual mapping without LoadLibrary
- Module stomping — overwriting legitimate DLL in memory
- Direct/indirect syscalls for injection APIs
- Thread hijacking — GetContext/SetContext/ResumeThread
- Process doppelganging — TxF transacted file + section mapping
- Process ghosting — delete-pending file + section mapping

## Procedure

1. **API pattern identification**: identify injection API sequences in import table or
   dynamic resolution — OpenProcess + VirtualAllocEx + WriteProcessMemory + CreateRemoteThread.
2. **Technique classification**: match API sequence to specific technique variant.
3. **Target selection**: identify how the target process is chosen — process enumeration,
   hardcoded process name, parent-child relationship.
4. **Payload analysis**: identify what is being injected — shellcode, DLL path, PE image.
5. **Evasion layers**: check for direct syscalls, API unhooking, indirect syscalls,
   module stomping that complicate detection.
6. **Runtime verification**: if platform matches, observe injection behavior via debugger
   or Frida hooks on NtWriteVirtualMemory/NtCreateThreadEx.

## Proof

Complete injection chain documented: target selection → memory allocation → payload write →
execution trigger, with specific API calls or syscalls at each stage.

## Evidence out

- locus: injection routine address, target process selection, payload source
- detail: technique name, API sequence, evasion layers, payload type
- confidence: high when full chain traced; medium on partial API sequence
- follow-up: `syscall-surface-map` for direct syscall usage, `anti-analysis` for evasion

## Guardrail

LLM output is a lead, not proof. Injection chains must be traced through code, not assumed.
