---
name: code-signing-analysis
description: Use when Malvex needs to analyze digital signatures, Authenticode, codesign validation and certificate chains on malware samples.
---

# Skill: code-signing-analysis

Vector: `code-signing-analysis` | agent: triage | platforms: windows, linux, macos
ATT&CK: T1553.002 (Code Signing), T1588.003 (Code Signing Certificates)

## Objective

Analyze digital signatures on malware samples — Authenticode (PE), codesign (Mach-O),
GPG (ELF packages). Identify stolen/fraudulent certs, expired signatures, timestamping,
and certificate chain anomalies used for legitimacy.

## Checklist

- Signature presence and validity
- Certificate chain (issuer, subject CN, serial, validity period)
- Countersignature/timestamp
- Revocation status (CRL/OCSP)
- Known stolen/abused certificate databases
- Catalog-signed vs embedded signature

## Procedure

1. **Signature check**: `osslsigncode verify` (PE), `codesign -dvvv` (Mach-O), `rpm -K` (RPM).
2. **Certificate extraction**: extract signer cert, issuer chain, serial numbers.
3. **Validity analysis**: check expiry, revocation status, timestamp countersignature.
4. **Anomaly detection**: self-signed certs on "legitimate" software, known stolen cert serials,
   test/development certificates used in production, mismatched CN vs publisher.
5. **Infrastructure mapping**: extract cert metadata for threat-intel — organization name,
   email, serial numbers cross-reference with known malware campaigns.
6. Emit signature assessment: valid/invalid/absent, cert chain, anomalies, infrastructure value.

## Proof

Certificate chain extracted with serial numbers, validity dates, and issuer information.
Anomalies documented with specific evidence (revoked serial, mismatched CN).

## Evidence out

- locus: signature location in binary, certificate serial number
- detail: signer CN, issuer chain, validity, revocation status, anomalies
- confidence: high — signature verification is deterministic
- follow-up: `threat-intelligence` for cert-based campaign correlation

## Guardrail

LLM output is a lead, not proof. Signature verification must use tools, not inference.
