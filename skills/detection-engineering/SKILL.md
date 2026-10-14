---
name: detection-engineering
description: Use when Malvex needs to turn validated findings into YARA, Sigma, EDR, network, memory, or behavioral detections.
---

# Skill: detection-engineering

Vector: detection-engineering | agent: detection-engineering | platforms: windows, linux, macos

## Objective

Turn the analysis into detections, not just narrative.

## Checklist

- YARA
- Sigma
- EDR behavioral logic
- DNS, HTTP, TLS, memory, file-system, registry, process indicators
- behavioral sequences

## Procedure

1. Prefer unique structural or behavioral combinations over single weak atoms.
2. Separate high-confidence signatures from hunting ideas.
3. Document expected false-positive pressure.

## Proof

Every detection should cite the exact artifact or behavioral sequence it matches.
