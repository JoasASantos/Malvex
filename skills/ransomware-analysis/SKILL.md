---
name: ransomware-analysis
description: Use when Malvex needs to analyze ransomware samples including encryption implementation, key management, ransom note generation, payment infrastructure and recovery potential.
---

# Skill: ransomware-analysis

Vector: `ransomware-analysis` | agent: static-core, dynamic-analysis | platforms: windows, linux, macos
ATT&CK: T1486 (Data Encrypted for Impact), T1490 (Inhibit System Recovery)

## Objective

Analyze ransomware encryption implementation, key management, ransom note patterns, file
targeting, shadow copy deletion, payment infrastructure, and recovery potential.

## Checklist

- Encryption algorithm identification (AES, ChaCha20, RSA hybrid)
- Key generation and management (per-file keys, master key, key wrapping)
- File targeting (extension whitelist/blacklist, directory exclusion)
- Ransom note content and template analysis
- Shadow copy / backup deletion mechanisms
- Payment infrastructure (Tor sites, wallet addresses, contact emails)
- Recovery potential (key material in memory, weak RNG, implementation bugs)
- Anti-recovery measures (MBR overwrite, secure delete, MFT encryption)

## Procedure

1. **Encryption identification**: identify the crypto primitives via `algorithm-identification`.
   Common: AES-CBC/CTR + RSA for key wrapping, ChaCha20 + Curve25519, Salsa20.
2. **Key management**: trace key generation — per-file symmetric key generated, encrypted
   with embedded RSA public key, appended to encrypted file. Identify if master key or
   per-file keys, key derivation method, RNG quality.
3. **File targeting**: extract file extension lists (target or skip), directory exclusions
   (Windows, Program Files, system dirs), filename patterns.
4. **Ransom note**: extract note template, payment instructions, Tor URLs, wallet addresses,
   victim ID generation, timer/deadline mechanisms.
5. **Recovery inhibition**: identify shadow copy deletion (vssadmin, wmic, PowerShell),
   backup catalog wiping, boot config changes (bcdedit), safe mode manipulation.
6. **Recovery assessment**: check for weak RNG (time-seeded, predictable), key material
   left in memory, implementation bugs (reused IVs, ECB mode), incomplete encryption
   (only first N bytes encrypted).

## Proof

Encryption algorithm confirmed with key management chain documented. File targeting rules
extracted. Recovery potential assessed with specific technical basis.

## Evidence out

- locus: encryption routine address, key generation, note template location
- detail: algorithm, key management scheme, file targeting rules, payment infrastructure
- confidence: varies — high for crypto identification, medium for recovery assessment
- follow-up: `algorithm-identification` for crypto details, `ioc-extraction` for payment IOCs

## Guardrail

LLM output is a lead, not proof. Crypto implementation analysis requires code-level verification.
Recovery claims must cite specific implementation weaknesses with evidence.
