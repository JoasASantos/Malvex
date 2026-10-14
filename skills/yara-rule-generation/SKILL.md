---
name: yara-rule-generation
description: Use when Malvex needs to generate YARA rules based on analysis findings for malware detection, family classification and threat hunting.
---

# Skill: yara-rule-generation

Vector: `yara-rule-generation` | agent: detection-engineering | platforms: windows, linux, macos
ATT&CK: Detection Engineering

## Objective

Generate YARA rules based on analysis findings — unique byte patterns, string signatures,
structural indicators, and behavioral markers for malware detection, family classification,
and proactive threat hunting.

## Checklist

- Unique code sequences (packer stubs, crypto routines, custom algorithms)
- Distinctive strings (C2 patterns, PDB paths, error messages, mutex names)
- Structural indicators (section names, resource types, import combinations)
- Byte patterns at specific offsets (PE header anomalies, magic values)
- Condition logic (file size, entropy, import hash, section count)
- False positive testing against goodware corpus

## Procedure

1. **Signature selection**: from analysis findings, identify the most distinctive and stable
   indicators — prefer code patterns over strings (harder to change).
2. **Pattern extraction**: extract hex byte patterns for unique code sequences. Use
   wildcards (`??`) for variable bytes (addresses, offsets) and jumps (`[4-8]`) for
   variable-length gaps.
3. **String signatures**: extract distinctive strings with appropriate modifiers (ascii,
   wide, nocase, fullword). Prefer strings that are unique to the malware family.
4. **Condition construction**: combine patterns with file metadata conditions — filesize,
   section entropy, import count, PE header fields.
5. **Rule quality**: ensure rules have sufficient specificity (multiple conditions),
   reasonable performance (avoid expensive patterns), and clear metadata (author, date,
   description, reference, hash).
6. **Validation**: test rules against the sample (must match) and known-good files
   (must not match). Compile with `yara -w` to check syntax.

## Proof

YARA rule that compiles cleanly, matches the analyzed sample, and does not match a
standard goodware corpus. Each condition cites the analysis finding it captures.

## Evidence out

- locus: YARA rule source
- detail: matched patterns, condition rationale, tested sample hash
- confidence: high when validated against sample and goodware
- follow-up: `detection-engineering` for broader detection strategy

## Guardrail

LLM output is a lead, not proof. Every rule must compile and match the sample.
