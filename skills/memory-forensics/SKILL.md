---
name: memory-forensics
description: Use when Malvex needs to perform memory forensics analysis including process memory dumps, injected code detection, rootkit artifacts and volatile evidence recovery.
---

# Skill: memory-forensics

Vector: `memory-forensics` | agent: memory-analysis | platforms: windows, linux, macos
ATT&CK: T1055 (Process Injection), T1014 (Rootkit)

## Objective

Perform memory forensics — process enumeration from memory, injected code detection,
rootkit artifact identification, volatile credential recovery, network connection
reconstruction, and memory-resident malware analysis.

## Checklist

- Process listing (cross-reference multiple methods to detect hiding)
- DLL/module listing per process (detect unlinked/injected modules)
- VAD analysis (RWX regions, private executable memory, unbacked sections)
- Kernel object analysis (SSDT hooks, callback tables, driver objects)
- Network connections from memory (sockets, connection table)
- Registry hives from memory
- Credential extraction (LSASS, cached hashes)
- Command history (cmd, PowerShell console history)

## Procedure

1. **Image acquisition**: verify memory image integrity — profile identification,
   KDBG/DTB location, OS version detection.
2. **Process analysis**: `volatility3` pslist/psscan/psxview cross-reference to identify
   hidden processes (DKOM, unlinking from ActiveProcessLinks).
3. **Injection detection**: scan for RWX VADs (malfind), unlinked modules (ldrmodules),
   hollowed processes (comparing on-disk vs in-memory PE headers).
4. **Code extraction**: dump injected/suspicious code regions for disassembly and further
   analysis. Identify shellcode, reflectively loaded DLLs, config data.
5. **Kernel analysis**: check SSDT for hooks, enumerate driver objects, scan for
   callback registrations that indicate rootkit activity.
6. **Volatile evidence**: extract network connections (netscan), open handles (handles),
   command history (cmdscan/consoles), clipboard content.

## Proof

Memory artifacts with process context, injection evidence (RWX VADs, unlinked modules),
and extracted code verified in disassembler.

## Evidence out

- locus: process PID, memory region base/size, kernel address
- detail: artifact type, content hash, injection technique, hiding method
- confidence: high for structural analysis; medium for behavioral inference
- follow-up: `process-memory-analysis` for per-process depth, `bootkit-rootkit` for kernel

## Guardrail

LLM output is a lead, not proof. Memory forensics artifacts must come from tool output.
