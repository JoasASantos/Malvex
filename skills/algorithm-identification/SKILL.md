---
name: algorithm-identification
description: Use when Malvex needs to fingerprint cryptographic, hashing and compression algorithms from constants and code shape to identify weak or custom crypto in malware.
---

# Skill: algorithm-identification

Vector: `algorithm-identification` | agent: static-core | platforms: windows, linux, macos
ATT&CK: T1573 (Encrypted Channel), T1027 (Obfuscated Files)

## Objective

Fingerprint cryptographic, hashing and compression algorithms in use — AES, DES, RC4,
ChaCha20, SHA-1/256, MD5, RSA, custom XOR, zlib — from their constants and code shape.
Flag weak/obsolete primitives and custom implementations.

## Checklist

- Constant-table signatures (S-box, round constants, init vectors)
- Code shape (round loops, Feistel networks, KSA/PRGA, quarter-rounds)
- Mode of operation (ECB, CBC, CTR, GCM)
- Key/IV provenance (hardcoded, derived, config-resident)
- Custom/modified algorithms (XOR cascades, rolling keys, non-standard block sizes)

## Procedure

1. **Constant scan**: match algorithm signatures via YARA crypto rules or manual search —
   Rijndael S-box/Te/Td → AES; DES SP-boxes/PC1/PC2 → DES; SHA-256 init `6A09E667…` → SHA-256;
   MD5 sine table → MD5; `"expand 32-byte k"` → ChaCha20; CRC32 poly → zlib; large odd
   moduli/`65537` → RSA. RC4 has no constants — identify by code shape only.
2. **Code-shape confirmation**: decompile candidate routines. Confirm AES round loop (10/12/14),
   DES 16-round Feistel, RC4 256-byte KSA+PRGA, ChaCha20 quarter-round rotations (16/12/8/7),
   SHA compression Ch/Maj/Σ, RSA modexp.
3. **Mode detection**: trace data flow around block calls — ECB (no chaining/IV), CBC
   (XOR-with-previous), CTR/GCM (counter/tag). ECB is a finding by itself.
4. **Key/IV source**: xrefs to key arguments — hardcoded key = extractable;
   config-resident key = C2-delivered; zero/fixed IV = mode weakness.
5. **Custom crypto**: identify non-standard XOR cascades, rolling single-byte keys, modified
   RC4 variants, custom Feistel networks. These are common in commodity malware.
6. Emit algorithm inventory: routine → primitive → mode → key source → weakness flag.

## Proof

Each crypto routine named to a primitive+mode with converging evidence (constant match +
code shape). Every weak use flagged. Custom algorithms described with structure.

## Evidence out

- locus: crypto routine address + constant table location
- detail: primitive, mode, key/IV provenance, weakness verdict
- confidence: high when constants + code shape converge; medium on code shape alone
- follow-up: `hardcoded-crypto-blobs` for embedded keys, `c2-protocol-analysis` for
  C2-delivered keys, `config-extraction` for config-resident crypto parameters

## Guardrail

LLM output is a lead, not proof. Constant matches need code-shape confirmation.
A recognized constant without a calling crypto routine may be a false positive.
