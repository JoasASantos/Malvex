# Skills

Each folder under `skills/` contains a `SKILL.md` for one malware-analysis domain.

These are not generic “think about malware” prompts. They are analyst operating procedures with explicit evidence requirements.

## Global rules

- hypothesis -> evidence -> verification -> confidence
- LLM output != evidence
- rename functions when behavior is supported by xrefs, APIs, strings, or runtime traces
- if the target is packed, unpacking is part of the job
- if a runtime claim is made, it must reference an observed trace, dump, hook, log, or packet artifact

## Recommended output fields

- exact locus: RVA, VA, offset, symbol, section, or PID/base address
- evidence kind: header, import, string, xref, pseudocode, disassembly, debugger trace, memory dump, file artifact, packet capture
- confidence and unresolved gaps
