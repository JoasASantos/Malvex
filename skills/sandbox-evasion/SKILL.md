---
name: sandbox-evasion
description: Use when Malvex needs to analyze sandbox and analysis environment evasion techniques including VM detection, timing checks, user interaction requirements and environment fingerprinting.
---

# Skill: sandbox-evasion

Vector: `sandbox-evasion` | agent: static-core, deobfuscation | platforms: windows, linux, macos
ATT&CK: T1497 (Virtualization/Sandbox Evasion), T1480 (Execution Guardrails)

## Objective

Analyze sandbox evasion and execution guardrails — VM/sandbox detection, timing-based
evasion, user interaction requirements, environment fingerprinting, and geofencing.

## Checklist

- VM detection (CPUID, registry keys, MAC addresses, device names, files)
- Sandbox detection (process names, DLLs, usernames, computer names)
- Timing checks (RDTSC, GetTickCount, NtQueryPerformanceCounter, sleep acceleration)
- User interaction requirements (mouse movement, click count, window interaction)
- Environment fingerprinting (domain-joined, installed software, language, timezone)
- Geofencing (IP geolocation, keyboard layout, system locale)
- Hardware fingerprinting (CPU cores, RAM size, disk size, GPU)

## Procedure

1. **VM detection**: identify checks for VMware (vmtoolsd, vmhgfs, VBOX MAC prefix),
   VirtualBox (VBoxService, VBoxGuest), Hyper-V, KVM, Xen via registry, files, devices,
   CPUID leaf, WMI queries (Win32_ComputerSystem.Model).
2. **Sandbox detection**: identify checks for analysis tool processes (procmon, wireshark,
   x64dbg, ida), known sandbox usernames/computer names, loaded DLLs (sbiedll, dbghelp).
3. **Timing evasion**: identify RDTSC-based timing, extended sleep calls (Sleep > 5min),
   sleep acceleration detection, NtDelayExecution with large intervals.
4. **Interaction checks**: identify GetCursorPos polling, click counting, GetForegroundWindow
   monitoring, dialog box interaction requirements.
5. **Guardrails**: identify execution conditions — domain name check, specific hostname,
   installed software requirements, language/locale checks, IP geolocation.
6. **Bypass assessment**: for each check, document the specific values compared and suggest
   sandbox configuration to bypass the evasion.

## Proof

Each evasion technique identified with specific API calls, comparison values, and branch
conditions that gate execution.

## Evidence out

- locus: evasion check routine, comparison values, branch target
- detail: technique, checked values, gate condition, bypass method
- confidence: high when comparison values extracted
- follow-up: `anti-analysis` for broader evasion context

## Guardrail

LLM output is a lead, not proof. Evasion checks must be traced to specific comparisons.
