---
name: apt-tooling
description: Use when Malvex needs to analyze APT-grade custom implants, living-off-the-land techniques, staged operations and infrastructure fingerprinting.
---

# Skill: apt-tooling

Vector: `apt-tooling` | agent: threat-intel, static-core | platforms: windows, linux, macos
ATT&CK: T1588 (Obtain Capabilities), T1587 (Develop Capabilities)

## Objective

Analyze APT-grade malware characteristics — custom implants vs modified open-source tools,
LOTL (Living-off-the-Land) technique chains, staged operations, operational security
measures, and infrastructure fingerprinting for attribution.

## Checklist

- Custom vs commodity tooling identification
- Open-source tool modifications (Cobalt Strike, Metasploit, Sliver, Mythic, Havoc)
- LOTL technique chains (LOLBins, LOLDrivers, LOLScripts)
- Operational security measures (timestomping, log clearing, anti-forensics)
- Build environment indicators (compiler, timestamps, paths, language artifacts)
- Infrastructure fingerprinting (SSL certs, HTTP headers, hosting patterns)
- Code reuse across campaigns (shared libraries, crypto implementations)

## Procedure

1. **Tooling classification**: determine if the sample is custom-developed, modified
   open-source, or commodity malware. Check for known framework signatures (Cobalt Strike
   beacon config, Metasploit staged patterns, Sliver implant markers).
2. **Modification analysis**: for modified tools, identify what was changed — custom
   communication protocol, additional capabilities, obfuscation layers, signature evasion.
3. **LOTL analysis**: identify chains of legitimate tool abuse — certutil download →
   PowerShell decode → rundll32 execute → scheduled task persistence.
4. **OPSEC measures**: identify anti-forensics — timestomping (SetFileTime), log clearing
   (wevtutil), artifact cleanup, secure deletion, anti-debugging.
5. **Build forensics**: extract compiler version, build timestamps, PDB paths, embedded
   language strings (non-English strings indicate developer nationality).
6. **Infrastructure correlation**: extract infrastructure indicators for cross-campaign
   comparison — SSL cert patterns, HTTP header signatures, C2 framework markers.

## Proof

Classification justified with specific evidence. Modified tool identified with exact
changes documented. OPSEC measures catalogued with techniques.

## Evidence out

- locus: framework signatures, modification points, LOTL chain, build artifacts
- detail: tooling classification, modifications, OPSEC techniques, build forensics
- confidence: varies — high for known framework matches, medium for custom tooling
- follow-up: `malware-lineage` for cross-campaign comparison, `threat-intelligence` for attribution

## Guardrail

LLM output is a lead, not proof. Similarity is not attribution. Build artifacts and
language strings are indicators, not proof of developer nationality.
