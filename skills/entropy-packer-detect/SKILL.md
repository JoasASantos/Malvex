---
name: entropy-packer-detect
description: Use when Malvex needs to identify packing, encryption and shielding layers via per-section entropy analysis and vendor signature matching.
---

# Skill: entropy-packer-detect

Vector: `entropy-packer-detect` | agent: triage | platforms: windows, linux, macos
ATT&CK: T1027.002 (Software Packing), T1027 (Obfuscated Files)

## Objective

Identify packing, encryption and shielding layers through per-section entropy analysis and
vendor/tool signatures. This is a first-pass triage step that tells downstream agents which
protection layers must be handled before deep analysis.

## Checklist

- Per-section Shannon entropy (flag >= 7.9 as packed/encrypted)
- Section name signatures (.vmp0/.vmp1, .upx, .aspack, .themida, .nsp)
- YARA vendor signature matches (UPX, VMProtect, Themida, ASPack, MPRESS, Enigma, Obsidium)
- Overlay/appended data entropy
- Entry point section entropy vs code section norms

## Procedure

1. **Per-section entropy**: compute Shannon entropy for each section. Flag sections at 7.9–8.0
   as encrypted/packed. Normal code sections sit at 5.5–6.5; data sections vary.
2. **Section name tell-tales**: `.vmp0`/`.vmp1` (VMProtect), `.upx0`/`.upx1` (UPX packed),
   `.aspack` (ASPack), `.themida` (Themida), `__packed` (custom). ELF: unusual segment names.
3. **YARA signature scan**: run packer/protector rule sets against the binary. Common hits:
   UPX magic `UPX!`, VMProtect markers, Themida section headers, MPRESS signatures.
4. **Entry point analysis**: if EP sits inside a high-entropy section or outside `.text`,
   strong packer indicator. Compare EP section entropy to overall code entropy.
5. **Overlay scan**: `binwalk` or manual check for appended data beyond section table bounds.
   High-entropy overlay = potential packed/encrypted payload.
6. Emit shielding inventory: layer name, affected sections, entropy values, signature hits,
   and recommended unpacking approach for each layer.

## Proof

Section at entropy >= 7.9 and/or positive packer YARA match, correlated with entry point
location and section naming anomalies.

## Evidence out

- locus: section name, offset, size
- detail: entropy value, matched signature, identified packer/version
- confidence: high on signature + entropy convergence; medium on entropy alone
- follow-up: `packing-obfuscation` for unpacking, `emulation-unpacking` for runtime unpack

## Guardrail

LLM output is a lead, not proof. High entropy alone does not prove packing — compressed
resources and media sections can show similar values. Correlate with other indicators.
