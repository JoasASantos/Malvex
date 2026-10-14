---
name: c2-protocol-analysis
description: Use when Malvex needs to deeply analyze C2 communication protocols including beacon patterns, protocol fingerprinting, DGA algorithms, encryption and channel multiplexing.
---

# Skill: c2-protocol-analysis

Vector: `c2-protocol-analysis` | agent: dynamic-analysis, threat-intel | platforms: windows, linux, macos
ATT&CK: T1071 (Application Layer Protocol), T1568 (Dynamic Resolution), T1573 (Encrypted Channel)

## Objective

Deep analysis of C2 communication protocols beyond surface-level network indicators —
beacon interval/jitter analysis, protocol structure, DGA algorithms, encryption layers,
channel multiplexing, and fallback infrastructure.

## Checklist

- Beacon interval and jitter calculation
- Protocol structure (HTTP headers, custom binary, DNS tunneling, ICMP)
- DGA (Domain Generation Algorithm) reverse engineering
- Encryption/encoding of C2 traffic (custom XOR, AES, RSA key exchange)
- Command structure (tasking format, response format)
- Fallback channels (multiple C2, Tor, dead drops, social media)
- Protocol fingerprinting (JA3/JA3S, HTTP header order, User-Agent)

## Procedure

1. **Protocol identification**: determine transport (HTTP/HTTPS, DNS, ICMP, raw TCP/UDP,
   WebSocket, named pipe) and application layer format (JSON, binary struct, base64).
2. **Beacon analysis**: extract sleep time, jitter percentage, and calculate expected
   beacon pattern for network detection signatures.
3. **DGA reverse engineering**: identify domain generation routine — extract seed, algorithm
   (time-based, hash-based, wordlist), TLD selection, daily/hourly rotation.
4. **Encryption analysis**: identify C2 traffic encryption — key exchange protocol,
   session key derivation, per-message encryption, integrity checks.
5. **Command parsing**: reverse engineer the tasking protocol — command IDs, parameter
   serialization, response format, error handling.
6. **Infrastructure mapping**: extract all C2 endpoints (primary, fallback), proxy
   configuration, Tor usage, domain fronting, CDN abuse.

## Proof

C2 protocol documented with message format, encryption scheme, beacon parameters, and
generated domains (if DGA) verified against real infrastructure.

## Evidence out

- locus: C2 communication routine, DGA function, encryption routine
- detail: protocol structure, beacon params, DGA algorithm, encryption scheme, endpoints
- confidence: high when protocol fully reversed; medium on partial analysis
- follow-up: `command-and-control` for C2 config, `ioc-extraction` for network IOCs

## Guardrail

LLM output is a lead, not proof. DGA must be verified by generating domains and checking resolution.
