---
name: hardcoded-crypto-blobs
description: Use when Malvex needs to identify and extract hardcoded keys, certificates, tokens and secret material embedded in malware binaries.
---

# Skill: hardcoded-crypto-blobs

Vector: `hardcoded-crypto-blobs` | agent: static-core | platforms: windows, linux, macos
ATT&CK: T1552.004 (Private Keys), T1588.004 (Digital Certificates)

## Objective

Identify and extract certificates, keys, tokens and secret material compiled as constant
blobs in data sections. In malware, these reveal C2 certificate pinning, embedded encryption
keys, hardcoded API tokens, and operator infrastructure.

## Checklist

- Base64 blobs >= 80 chars in .rdata/.rodata/.data sections
- ASN.1/DER sequences (0x30 0x82) indicating X.509 certs or RSA keys
- PEM headers ("-----BEGIN") in string table
- High-entropy blobs referenced by crypto import/init functions
- Wallet addresses, API keys, OAuth tokens

## Procedure

1. Scan data sections for base64 runs >= 80 chars and DER `30 82` headers.
2. For each hit, check xrefs — a blob referenced by a crypto routine (key import, cert
   parse, verify) is live secret material. Unreferenced blobs may be dead code.
3. Decode and classify: X.509 certificate (extract CN, issuer, validity), RSA/EC key
   (public vs private), PKCS#7, JWT, AES key (high-entropy 16/32-byte blob).
4. Extract infrastructure indicators from certs: CN/SAN domains, issuer chain, serial
   numbers. These feed threat-intel for C2 infrastructure mapping.
5. Identify hardcoded API keys, Discord webhooks, Telegram bot tokens, wallet addresses.
6. Emit inventory: type, decoded length, SHA-256, consumer function, infrastructure value.

## Proof

Data-section blob with xref from crypto routine, decoding to cert/key/token with
extractable infrastructure indicators (domains, IPs, wallet addresses).

## Evidence out

- locus: blob address in data section + referencing crypto call
- detail: blob type, decoded content summary, SHA-256, infrastructure indicators
- confidence: high when decode succeeds and xref confirms usage
- follow-up: `c2-protocol-analysis` for C2 cert pinning, `ioc-extraction` for indicators

## Guardrail

LLM output is a lead, not proof. Decode and hash every blob. Never fabricate cert fields.
