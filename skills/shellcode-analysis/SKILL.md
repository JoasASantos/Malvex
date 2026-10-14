---
name: shellcode-analysis
description: Use when Malvex needs to analyze shellcode including decoder stubs, position-independent code patterns, syscall sequences, egg hunters and staged payloads.
---

# Skill: shellcode-analysis

Vector: `shellcode-analysis` | agent: decompilation, deobfuscation | platforms: windows, linux, macos
ATT&CK: T1059.006 (Command and Scripting Interpreter), T1620 (Reflective Code Loading)

## Objective

Analyze shellcode payloads — decoder stubs, PIC patterns, API resolution (PEB walking),
syscall sequences, egg hunters, staged loaders, and payload delivery mechanisms.

## Checklist

- Position-independent code (PIC) patterns
- PEB walking for kernel32/ntdll base resolution
- API hashing and resolution (ROR13, CRC32, djb2)
- Decoder stubs (XOR, SUB, NOT, multi-byte key)
- Egg hunters (scanning memory for marker)
- Staged vs stageless payload architecture
- Syscall stubs (direct syscall shellcode)
- Encoder identification (Shikata Ga Nai, XOR, Alpha)

## Procedure

1. **Format identification**: determine shellcode architecture (x86, x64, ARM), endianness,
   and entry convention. Check for NOP sleds, alignment padding.
2. **Decoder analysis**: identify encoding scheme — single-byte XOR, multi-byte XOR key,
   SUB/ADD/NOT cascades, polymorphic decoders (Shikata Ga Nai FNSTENV-based).
3. **PEB resolution**: identify TEB/PEB access patterns (`fs:[0x30]` x86, `gs:[0x60]` x64)
   for kernel32 base resolution via InMemoryOrderModuleList.
4. **API hashing**: identify hash computation over export names, extract hash values, resolve
   against known hash databases (ROR13 → `LoadLibraryA` = 0x0726774C).
5. **Payload behavior**: after decoding and API resolution, trace the actual payload — reverse
   shell, bind shell, download-and-execute, meterpreter stager.
6. **Egg hunter**: identify memory scanning loops looking for a marker tag, used to locate
   larger second-stage payload in memory.

## Proof

Decoded shellcode with API resolution chain documented, payload behavior classified,
and C2/callback information extracted.

## Evidence out

- locus: shellcode offset, decoder stub, PEB walk routine, API hash table
- detail: encoding scheme, key, resolved APIs, payload type, C2 callback
- confidence: high when fully decoded and traced
- follow-up: `c2-protocol-analysis` for callback protocol, `process-injection` for delivery

## Guardrail

LLM output is a lead, not proof. Shellcode must be decoded and traced, not pattern-matched.
