---
name: threat-intelligence
description: Use when Malvex needs family, variant, overlap, and historical evolution analysis without over-claiming attribution.
---

# Skill: threat-intelligence

Vector: threat-intelligence | agent: threat-intel | platforms: windows, linux, macos

## Objective

Place the sample in technical context without overclaiming attribution.

## Checklist

- family and variants
- similar samples
- code reuse, infrastructure overlap, config overlap
- campaign relationships
- compilation, PDB, certificate, and TTP similarities

## Procedure

1. Compare structural and behavioral fingerprints.
2. State what matched and what did not.
3. Keep attribution claims narrower than similarity claims.

## Guardrail

Technical overlap is not enough for actor attribution.
