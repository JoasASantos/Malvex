---
name: emulation-unpacking
description: Use when Malvex needs to use emulation-based unpacking to recover the original payload from packed or protected malware samples.
---

# Skill: emulation-unpacking

Vector: `emulation-unpacking` | agent: deobfuscation | platforms: windows, linux, macos
ATT&CK: T1027.002 (Software Packing), T1140 (Deobfuscate/Decode)

## Objective

Use emulation-based approaches (Unicorn, Qiling, speakeasy) to unpack protected malware
without executing it natively, recovering the original payload for analysis.

## Checklist

- Emulator selection based on target architecture and platform
- Memory snapshot at OEP (original entry point)
- Import table reconstruction
- Multi-layer unpacking (nested packers)
- Anti-emulation detection and bypass

## Procedure

1. **Packer identification**: from `entropy-packer-detect`, determine packer type and
   expected unpacking behavior (single-layer UPX vs multi-layer custom).
2. **Emulator setup**: configure Unicorn/Qiling/speakeasy for target architecture (x86,
   x64, ARM) with appropriate OS environment simulation.
3. **Execution monitoring**: trace memory writes to identify unpacking writes — large
   contiguous writes to executable sections indicate payload decompression.
4. **OEP detection**: identify the original entry point transition — typically a tail jump
   from the unpacker stub to the unpacked code. Set breakpoint and dump.
5. **Memory dump**: at OEP, dump the unpacked image from memory. Fix PE headers, section
   alignments, and entry point.
6. **Import reconstruction**: rebuild the import table using Scylla, ImpRec, or manual
   IAT scanning — the unpacked binary needs valid imports for analysis.
7. **Validation**: verify unpacked sample loads in disassembler with valid code at EP.

## Proof

Unpacked binary with valid PE/ELF structure, correct entry point, reconstructed imports,
and lower entropy sections containing analyzable code.

## Evidence out

- locus: OEP address, unpacker stub location, dump parameters
- detail: packer identified, layers unpacked, import count, resulting file hash
- confidence: high when clean dump verified in disassembler
- follow-up: full pipeline restart on unpacked sample

## Guardrail

LLM output is a lead, not proof. Unpacked samples must be verified in a disassembler.
