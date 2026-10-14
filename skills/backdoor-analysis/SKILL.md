---
name: backdoor-analysis
description: Use when Malvex needs to analyze backdoor and RAT capabilities including remote shell, file management, surveillance, plugin architecture and command dispatch.
---

# Skill: backdoor-analysis

Vector: `backdoor-analysis` | agent: static-core, dynamic-analysis | platforms: windows, linux, macos
ATT&CK: T1059 (Command and Scripting), T1219 (Remote Access Software), T1113 (Screen Capture)

## Objective

Analyze backdoor and RAT capabilities — command dispatch tables, remote shell, file
management, surveillance features, plugin loading, and operator interaction protocols.

## Checklist

- Command dispatch table (command ID → handler mapping)
- Remote shell (cmd.exe/bash/sh spawning, pipe redirection)
- File operations (upload, download, list, delete, search)
- Surveillance (screenshot, webcam, microphone, keylogger)
- System info collection (OS, hardware, network, installed software)
- Plugin/module architecture (dynamic capability loading)
- Self-management (update, uninstall, sleep, migrate)

## Procedure

1. **Command dispatch**: identify the main command handler — typically a switch/case or
   function pointer table mapping command IDs to handler functions.
2. **Capability enumeration**: for each command handler, classify the capability — remote
   shell, file ops, surveillance, system info, persistence management.
3. **Shell access**: identify reverse/bind shell implementation — process creation with
   redirected stdin/stdout/stderr, pipe/socket plumbing.
4. **File management**: identify upload/download protocols, directory listing, file
   search with pattern matching.
5. **Surveillance**: identify screenshot (BitBlt/CGWindowListCreateImage), webcam
   (DirectShow/AVFoundation), audio (waveIn/AVAudioEngine), keylogger hooks.
6. **Plugin system**: identify dynamic module loading — DLL/SO loading, reflective loading,
   memory-only modules, plugin protocol/API.

## Proof

Complete capability matrix with command IDs mapped to handler functions. Each capability
documented with specific API calls and implementation details.

## Evidence out

- locus: command dispatch table, handler function addresses
- detail: command ID, capability, implementation method, APIs used
- confidence: high when dispatch table fully mapped
- follow-up: `c2-protocol-analysis` for communication protocol, `process-injection` for migration

## Guardrail

LLM output is a lead, not proof. Every capability must be traced to specific handler code.
