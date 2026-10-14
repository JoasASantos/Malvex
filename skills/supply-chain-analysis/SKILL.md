---
name: supply-chain-analysis
description: Use when Malvex needs to analyze supply chain compromise indicators including dependency confusion, typosquatting, build pipeline compromise and trojanized updates.
---

# Skill: supply-chain-analysis

Vector: `supply-chain-analysis` | agent: static-core, threat-intel | platforms: windows, linux, macos
ATT&CK: T1195 (Supply Chain Compromise), T1199 (Trusted Relationship)

## Objective

Analyze supply chain compromise indicators — trojanized legitimate software, dependency
confusion attacks, typosquatting packages, build pipeline compromise, and update mechanism
hijacking.

## Checklist

- Trojanized legitimate software (valid signature + malicious code)
- Modified open-source packages (added backdoor in build scripts)
- Dependency confusion (private package name collision with public registry)
- Typosquatting packages (near-miss package names)
- Build system compromise (modified CI/CD, injected build steps)
- Update mechanism hijacking (MITM, DNS hijack, compromised update server)
- Code signing anomalies (valid but unexpected signer, test certificates)

## Procedure

1. **Legitimacy assessment**: compare against known-good version — binary diff, hash
   comparison, signature verification, version string analysis.
2. **Modification identification**: identify added/modified code compared to legitimate
   version — new functions, modified entry points, injected DLLs, altered build scripts.
3. **Build chain analysis**: examine build metadata — compiler version, build paths,
   timestamps, Rich header differences from known-good builds.
4. **Package analysis**: for script-based packages (npm, pip, gem), examine install hooks
   (setup.py install, postinstall scripts) for malicious payload execution.
5. **Update mechanism**: analyze update checking — URL validation, certificate pinning,
   signature verification of downloaded updates.
6. **Timeline**: establish when compromise occurred based on build timestamps, file
   modification times, and distribution timeline.

## Proof

Specific modifications identified compared to legitimate version, with compromise
vector determined and timeline established.

## Evidence out

- locus: modified code, injected components, build metadata differences
- detail: compromise type, modifications, timeline, affected versions
- confidence: high when diff against known-good confirmed
- follow-up: `code-signing-analysis` for signature anomalies, `threat-intelligence` for campaign

## Guardrail

LLM output is a lead, not proof. Always compare against known-good baseline.
