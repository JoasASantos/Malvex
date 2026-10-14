---
name: syscall-surface-map
description: Use when Malvex needs to map direct and indirect syscall usage in malware to identify EDR evasion, anti-hooking techniques and low-level OS interaction.
---

# Skill: syscall-surface-map

Vector: `syscall-surface-map` | agent: static-core | platforms: windows, linux, macos
ATT&CK: T1106 (Native API), T1562.001 (Disable or Modify Tools)

## Objective

Map direct syscall usage (int 0x80, syscall, svc, sysenter), indirect syscall stubs, and
Nt/Zw API calls. In malware, direct syscalls indicate EDR/hooking evasion techniques.

## Checklist

- Direct syscall instructions (syscall/sysenter/int 0x80/svc)
- Syscall number tables (SSN resolution)
- Indirect syscall trampolines (jumping into ntdll code sections)
- Nt/Zw API calls bypassing Win32 layer
- System call number resolution techniques (Hell's Gate, Halo's Gate, Tartarus' Gate)

## Procedure

1. **Direct syscall scan**: search for `0F 05` (syscall), `0F 34` (sysenter), `CD 80`
   (int 0x80), `D4 00 00 01` (svc #1 ARM64) instructions outside ntdll.
2. **SSN resolution**: identify syscall number assignment patterns — static tables,
   runtime resolution from ntdll export parsing (Hell's Gate), neighboring export sorting
   (Halo's Gate), or exception-based resolution (Tartarus' Gate).
3. **Indirect syscalls**: identify `jmp` or `call` into ntdll `.text` section after
   setting up registers — the trampoline pattern that avoids direct syscall detection.
4. **Nt API mapping**: for each resolved syscall number or Nt* call, map to the
   corresponding capability (NtAllocateVirtualMemory → memory allocation,
   NtCreateThreadEx → thread creation, NtWriteVirtualMemory → process injection).
5. **Platform comparison**: on Linux, map syscall numbers to capability (sys_ptrace,
   sys_memfd_create, sys_process_vm_writev). On macOS, map Mach traps.
6. Emit syscall inventory with capability mapping and evasion technique classification.

## Proof

Syscall instruction at identified address with resolved syscall number mapping to a
specific OS function, confirmed by register setup pattern in the calling code.

## Evidence out

- locus: syscall instruction address, SSN resolution routine
- detail: syscall number, mapped OS function, evasion technique, capability
- confidence: high when SSN confirmed; medium on pattern-based inference
- follow-up: `anti-analysis` for evasion context, `process-injection` for injection syscalls

## Guardrail

LLM output is a lead, not proof. Syscall numbers vary by OS version — confirm the target version.
