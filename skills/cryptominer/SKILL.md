---
name: cryptominer
description: Use when Malvex needs to analyze cryptomining malware including mining pool connections, algorithm identification, resource management and wallet address extraction.
---

# Skill: cryptominer

Vector: `cryptominer` | agent: static-core, dynamic-analysis | platforms: windows, linux, macos
ATT&CK: T1496 (Resource Hijacking)

## Objective

Analyze cryptomining malware — mining algorithm identification, pool connections, wallet
address extraction, resource throttling, persistence, and evasion techniques.

## Checklist

- Mining algorithm (RandomX/Monero, Ethash, CryptoNight, KawPow)
- Pool connection strings (stratum+tcp://, pool addresses, ports)
- Wallet addresses (Monero, Bitcoin, Ethereum)
- CPU/GPU resource management (thread count, throttling, idle detection)
- Process hiding (process name masquerading, rootkit)
- Persistence mechanism
- Competitor miner killing

## Procedure

1. **Algorithm identification**: identify the mining algorithm from constants, function
   patterns, or library signatures (XMRig, PhoenixMiner, T-Rex, custom).
2. **Pool extraction**: extract mining pool addresses from strings, config files, or
   hardcoded values. Identify primary and fallback pools.
3. **Wallet extraction**: extract destination wallet addresses for attribution and
   financial impact assessment.
4. **Resource management**: identify thread count configuration, CPU affinity settings,
   idle detection (GetLastInputInfo), throttling to avoid detection.
5. **Stealth**: identify process name masquerading (svchost.exe, system), CPU usage
   monitoring avoidance, task manager detection.
6. **Competitor killing**: identify routines that scan for and kill other miners
   (process name lists, mutex checking, port scanning for stratum).

## Proof

Mining algorithm confirmed, pool and wallet extracted, resource management strategy
documented with specific techniques.

## Evidence out

- locus: mining routine, pool connection, wallet string
- detail: algorithm, pool addresses, wallet addresses, resource config, stealth methods
- confidence: high when pool/wallet extracted
- follow-up: `ioc-extraction` for wallet/pool IOCs, `persistence-analysis` for persistence

## Guardrail

LLM output is a lead, not proof. Wallet addresses and pool connections must be extracted, not guessed.
