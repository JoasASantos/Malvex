---
name: bootkit-rootkit
description: Use when Malvex needs to analyze bootkits and rootkits including MBR/VBR/UEFI persistence, kernel hooks, DKOM, driver loading and boot process subversion.
---

# Skill: bootkit-rootkit

Vector: `bootkit-rootkit` | agent: static-core, memory-analysis | platforms: windows, linux
ATT&CK: T1542 (Pre-OS Boot), T1014 (Rootkit), T1068 (Exploitation for Privilege Escalation)

## Objective

Analyze bootkits (MBR/VBR/UEFI persistence) and rootkits (kernel hooks, DKOM, filter
drivers, hypervisor-based) for boot process subversion and stealth mechanisms.

## Checklist

- MBR/VBR modification (overwrite, chain-load)
- UEFI firmware implants (DXE drivers, boot services hooks, ESP manipulation)
- Kernel driver loading (signed driver abuse, vulnerable driver exploitation — BYOVD)
- DKOM (Direct Kernel Object Manipulation — process/thread/driver hiding)
- SSDT/IDT hooking for syscall interception
- Minifilter/callback registration for filesystem/registry/process hiding
- Hypervisor-based rootkits (hardware virtualization abuse)

## Procedure

1. **Boot sector analysis**: dump and disassemble MBR (sector 0) and VBR (volume boot
   record). Compare against known-clean versions. Identify chain-loading to malicious code.
2. **UEFI analysis**: examine EFI System Partition for unauthorized DXE drivers, modified
   boot manager, or firmware implants. Check Secure Boot state.
3. **Driver analysis**: for kernel drivers (.sys), identify loaded driver registration,
   IRP dispatch table, callbacks (PsSetCreateProcessNotifyRoutine, ObRegisterCallbacks,
   CmRegisterCallbackEx), minifilter altitude registration.
4. **BYOVD detection**: identify loading of known vulnerable signed drivers (e.g.,
   RTCore64.sys, DBUtil, procexp) used for kernel read/write primitives.
5. **DKOM techniques**: identify direct manipulation of kernel structures — EPROCESS
   linked list unlinking, TOKEN privilege modification, driver object hiding.
6. **Stealth assessment**: categorize hiding capabilities — process hiding, file hiding,
   registry key hiding, network connection hiding, driver hiding.

## Proof

Specific kernel manipulation technique identified with affected structures, hook
addresses, and hiding mechanisms documented.

## Evidence out

- locus: boot sector/driver entry point, hook addresses, DKOM targets
- detail: technique, affected kernel structures, hiding scope, persistence method
- confidence: high when kernel structures analyzed; medium on static analysis alone
- follow-up: `memory-forensics` for runtime kernel analysis, `persistence-analysis` for boot persistence

## Guardrail

LLM output is a lead, not proof. Kernel structure analysis requires memory dumps or driver disassembly.
