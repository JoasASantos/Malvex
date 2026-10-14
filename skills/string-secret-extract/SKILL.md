---
name: string-secret-extract
description: Use when Malvex needs to extract and classify strings including stack strings, encrypted strings and obfuscated secrets from malware samples.
---

# Skill: string-secret-extract

Vector: `string-secret-extract` | agent: static-core | platforms: windows, linux, macos
ATT&CK: T1140 (Deobfuscate/Decode), T1027.001 (Binary Padding)

## Objective

Extract and classify all string material including plaintext, stack-constructed strings,
XOR-encrypted strings, base64-encoded data, and obfuscated secrets. Strings are the
fastest route to IOCs, C2 infrastructure, and capability identification.

## Checklist

- Plaintext ASCII/Unicode strings (min length 4)
- Stack strings (character-by-character construction)
- FLOSS-extracted obfuscated strings
- Base64/hex-encoded data in string table
- Encrypted strings with identified decryption routine
- URL/IP/domain/path/registry key patterns in extracted strings

## Procedure

1. **Plaintext extraction**: `strings` + `floss` for static string extraction. Classify by
   type: URLs, IPs, domains, file paths, registry keys, mutex names, user agents, error
   messages, API names.
2. **Stack strings**: `floss` with stack string mode, or manual identification of
   `mov byte [rbp-XX], immediate` sequences building strings character by character.
3. **Encrypted strings**: identify string decryption routines (XOR loops, RC4 decrypt, custom
   decoders), extract key, and batch-decrypt all encrypted string references.
4. **Base64/encoding**: decode base64, hex, ROT13, and custom encoding found in string data.
5. **Secret classification**: flag API keys, tokens, wallet addresses, webhook URLs,
   credentials, PDB paths, campaign IDs, build paths.
6. **IOC extraction**: feed classified strings to `ioc-extraction` for indicator generation.

## Proof

Extracted string with source (plaintext/stack/decrypted), location, and classification.
Decrypted strings must show the decryption routine and key used.

## Evidence out

- locus: string address/offset, extraction method
- detail: string content, classification, decryption key if applicable
- confidence: high for plaintext; high for decrypted with confirmed routine
- follow-up: `ioc-extraction` for indicators, `c2-protocol-analysis` for C2 strings

## Guardrail

LLM output is a lead, not proof. Never fabricate string content — extract and verify.
