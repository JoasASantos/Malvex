---
name: network-forensics
description: Use when Malvex needs to perform network traffic analysis and forensics including PCAP analysis, protocol reconstruction, C2 traffic identification and exfiltration detection.
---

# Skill: network-forensics

Vector: `network-forensics` | agent: dynamic-analysis | platforms: windows, linux, macos
ATT&CK: T1071 (Application Layer Protocol), T1048 (Exfiltration Over Alternative Protocol)

## Objective

Analyze network traffic captures — protocol reconstruction, C2 traffic identification,
exfiltration detection, DNS analysis, TLS fingerprinting, and network-based IOC extraction.

## Checklist

- PCAP/PCAPNG analysis and protocol statistics
- HTTP/HTTPS request/response reconstruction
- DNS query analysis (DGA detection, DNS tunneling, DNS-over-HTTPS)
- TLS fingerprinting (JA3/JA3S, certificate analysis)
- C2 beacon pattern detection (interval, jitter, data size)
- Data exfiltration detection (large uploads, encoding, chunking)
- Protocol anomalies (non-standard ports, tunneling, covert channels)

## Procedure

1. **Traffic overview**: load PCAP in tshark/Zeek, generate protocol statistics,
   connection summary, and top talkers.
2. **DNS analysis**: extract all DNS queries, identify DGA patterns (high entropy domains,
   rapid NXDOMAIN responses), DNS tunneling (long subdomain labels, TXT record abuse).
3. **HTTP reconstruction**: extract HTTP requests with full headers, URLs, POST bodies,
   response content. Identify beaconing patterns (regular intervals, consistent size).
4. **TLS analysis**: extract JA3/JA3S fingerprints, server certificates (CN, SAN, issuer,
   serial), identify known malware TLS fingerprints.
5. **C2 identification**: correlate beacon timing, response patterns, and protocol
   structure to identify C2 communication channels.
6. **Exfiltration detection**: identify large data transfers, encoded/encrypted uploads,
   unusual protocols for data transfer (ICMP, DNS TXT).

## Proof

C2 traffic identified with beacon parameters, protocol structure, and extracted IOCs.
Exfiltration channels documented with volume and encoding method.

## Evidence out

- locus: packet timestamps, connection tuples, DNS queries
- detail: C2 endpoints, beacon params, JA3 fingerprints, exfil volume
- confidence: high when traffic pattern confirmed
- follow-up: `c2-protocol-analysis` for protocol depth, `ioc-extraction` for network IOCs

## Guardrail

LLM output is a lead, not proof. Network analysis must be based on actual traffic captures.
